"""Invariant tests for cab_of_one.runtime.hookio (PreToolUse boundary). No files are written."""

from __future__ import annotations

import io
import json
import sys
import unittest
from typing import Any
from unittest import mock

from cab_of_one.runtime import hookio
from cab_of_one.runtime.hookio import Decision

SECRET = "sk-FICTIONAL-SECRET-0123456789"


def event(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "session_id": "sess-0001",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "simtenant --state s.json list users"},
        "tool_use_id": "toolu_0001",
        "cwd": "/work/contoso-ops",
        "permission_mode": "default",
    }
    base.update(overrides)
    return base


def run(handler: Any, raw: str | bytes) -> tuple[int, str, str]:
    stdin: io.IOBase = io.BytesIO(raw) if isinstance(raw, bytes) else io.StringIO(raw)
    out, err = io.StringIO(), io.StringIO()
    code = hookio.run_hook(handler, stdin=stdin, stdout=out, stderr=err, exit_process=False)
    return code, out.getvalue(), err.getvalue()


def allow_all(_data: dict[str, Any]) -> Decision:
    return Decision.allow()


def deny_all(_data: dict[str, Any]) -> Decision:
    return Decision.deny("No open change. Start one with /change.")


class HookIOTests(unittest.TestCase):
    def one_json(self, out: str) -> dict[str, Any]:
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, "stdout must carry exactly one JSON line")
        self.assertTrue(out.endswith("\n"))
        obj = json.loads(lines[0])
        self.assertIsInstance(obj, dict)
        return obj

    def assert_blocked(self, code: int, out: str, err: str) -> dict[str, Any]:
        self.assertEqual(code, hookio.EXIT_BLOCK)
        obj = self.one_json(out)
        specific = obj["hookSpecificOutput"]
        self.assertEqual(specific["hookEventName"], "PreToolUse")
        self.assertEqual(specific["permissionDecision"], "deny")
        self.assertTrue(specific["permissionDecisionReason"])
        self.assertTrue(err.strip(), "a blocked call must explain itself on stderr")
        return obj

    def assert_no_leak(self, out: str, err: str, *needles: str) -> None:
        for needle in needles:
            self.assertNotIn(needle, out)
            self.assertNotIn(needle, err)

    # ----------------------------------------------------------------- allow and deny

    def test_allow_exits_zero_with_one_json_and_no_forced_allow(self) -> None:
        code, out, err = run(allow_all, json.dumps(event()))
        self.assertEqual(code, hookio.EXIT_ALLOW)
        obj = self.one_json(out)
        decision = obj.get("hookSpecificOutput", {}).get("permissionDecision")
        self.assertIsNone(decision, "allow must defer to normal permissions, not force allow")
        self.assertEqual(err, "")

    def test_deny_exits_two_with_reason_on_stderr_and_stdout(self) -> None:
        code, out, err = run(deny_all, json.dumps(event()))
        obj = self.assert_blocked(code, out, err)
        reason = obj["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("No open change. Start one with /change.", reason)
        self.assertIn("No open change. Start one with /change.", err)

    def test_read_is_not_auto_allowed(self) -> None:
        seen: list[str] = []

        def handler(data: dict[str, Any]) -> Decision:
            seen.append(data["tool_name"])
            return Decision.deny("policy unreadable")

        raw = json.dumps(event(tool_name="Read", tool_input={"file_path": "/work/a.txt"}))
        self.assert_blocked(*run(handler, raw))
        self.assertEqual(seen, ["Read"])

    def test_handler_receives_parsed_object(self) -> None:
        received: list[dict[str, Any]] = []

        def handler(data: dict[str, Any]) -> Decision:
            received.append(data)
            return Decision.allow()

        payload = event(tool_input={"command": "echo é中"})
        code, _out, _err = run(handler, json.dumps(payload).encode("utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(received, [payload])

    def test_deny_reason_is_single_line_and_bounded(self) -> None:
        def handler(_data: dict[str, Any]) -> Decision:
            return Decision.deny("line one\nline two\r\n\x1b[31mred\x00" + "x" * 5000)

        code, out, err = run(handler, json.dumps(event()))
        obj = self.assert_blocked(code, out, err)
        reason = obj["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertNotRegex(reason, r"[\x00-\x1f]")
        self.assertLessEqual(len(reason), hookio.MAX_REASON_CHARS + 32)
        self.assertEqual(len(err.splitlines()), 1)

    # ----------------------------------------------------------------- malformed input

    def test_malformed_inputs_block_without_echoing_input(self) -> None:
        cases: dict[str, str | bytes] = {
            "truncated": '{"hook_event_name": "PreToolUse", "tool_name": "' + SECRET,
            "garbage": "not json " + SECRET,
            "empty": "",
            "array": json.dumps([SECRET]),
            "string": json.dumps(SECRET),
            "number": "42",
            "nan": '{"hook_event_name": "PreToolUse", "tool_name": "Bash", "x": NaN}',
            "duplicate": (
                '{"hook_event_name": "PreToolUse", "tool_name": "Bash",'
                ' "tool_name": "' + SECRET + '"}'
            ),
            "not-utf8": b'{"tool_name": "\xff\xfe' + SECRET.encode() + b'"}',
            "bom": "﻿" + json.dumps(event()),
        }
        for label, raw in cases.items():
            calls: list[object] = []

            def handler(data: dict[str, Any], calls: list[object] = calls) -> Decision:
                calls.append(data)
                return Decision.allow()

            with self.subTest(case=label):
                code, out, err = run(handler, raw)
                self.assert_blocked(code, out, err)
                self.assert_no_leak(out, err, SECRET)
                self.assertEqual(calls, [], "handler must not run on malformed input")

    def test_non_pretooluse_events_are_blocked(self) -> None:
        for name in ("PostToolUse", "Stop", "SessionStart", "", None):
            with self.subTest(event=name):
                payload = event(hook_event_name=name)
                self.assert_blocked(*run(allow_all, json.dumps(payload)))
        missing = event()
        del missing["hook_event_name"]
        self.assert_blocked(*run(allow_all, json.dumps(missing)))

    def test_missing_or_bad_tool_name_is_blocked(self) -> None:
        for value in ("", 7, None, ["Bash"]):
            with self.subTest(tool_name=value):
                self.assert_blocked(*run(allow_all, json.dumps(event(tool_name=value))))

    def test_oversized_input_is_blocked(self) -> None:
        raw = json.dumps(event(tool_input={"content": "a" * 500}))
        with mock.patch.object(hookio, "MAX_INPUT_BYTES", 100):
            self.assert_blocked(*run(allow_all, raw))

    # ----------------------------------------------------------------- handler faults

    def test_handler_exception_blocks_with_type_only(self) -> None:
        def handler(data: dict[str, Any]) -> Decision:
            raise ValueError(f"cannot parse {data['tool_input']['command']} {SECRET}")

        raw = json.dumps(event(tool_input={"command": "Set-Thing -Password " + SECRET}))
        code, out, err = run(handler, raw)
        self.assert_blocked(code, out, err)
        self.assert_no_leak(out, err, SECRET, "Set-Thing", "cannot parse")
        self.assertIn("ValueError", err)

    def test_handler_system_exit_and_interrupt_still_block(self) -> None:
        for exc in (SystemExit(0), KeyboardInterrupt(), GeneratorExit()):

            def handler(_data: dict[str, Any], exc: BaseException = exc) -> Decision:
                raise exc

            with self.subTest(exc=type(exc).__name__):
                self.assert_blocked(*run(handler, json.dumps(event())))

    def test_wrong_return_types_block(self) -> None:
        bad_results: list[object] = [
            None,
            True,
            0,
            "allow",
            {"permissionDecision": "allow"},
            ("allow",),
            Decision,
        ]
        for result in bad_results:

            def handler(_data: dict[str, Any], result: object = result) -> Decision:
                return result  # type: ignore[return-value]

            with self.subTest(result=repr(result)):
                self.assert_blocked(*run(handler, json.dumps(event())))

    def test_tampered_decision_fields_block(self) -> None:
        tampered = Decision.allow()
        object.__setattr__(tampered, "allowed", 1)
        self.assert_blocked(*run(lambda _d: tampered, json.dumps(event())))

        empty_deny = Decision.deny("x")
        object.__setattr__(empty_deny, "reason", "  \n ")
        self.assert_blocked(*run(lambda _d: empty_deny, json.dumps(event())))

    def test_handler_prints_are_discarded(self) -> None:
        def handler(_data: dict[str, Any]) -> Decision:
            print("debug", SECRET)
            print("debug", SECRET, file=sys.stderr)
            return Decision.allow()

        code, out, err = run(handler, json.dumps(event()))
        self.assertEqual(code, 0)
        self.one_json(out)
        self.assert_no_leak(out, err, SECRET)

    def test_unwritable_stdout_blocks(self) -> None:
        class Broken(io.StringIO):
            def write(self, _s: str) -> int:
                raise BrokenPipeError

        err = io.StringIO()
        code = hookio.run_hook(
            allow_all,
            stdin=io.StringIO(json.dumps(event())),
            stdout=Broken(),
            stderr=err,
            exit_process=False,
        )
        self.assertEqual(code, hookio.EXIT_BLOCK)
        self.assertTrue(err.getvalue().strip())

    # ----------------------------------------------------------------- process exit

    def test_default_raises_system_exit_with_code(self) -> None:
        for handler, expected in ((allow_all, 0), (deny_all, 2)):
            with self.subTest(expected=expected):
                with self.assertRaises(SystemExit) as caught:
                    hookio.run_hook(
                        handler,
                        stdin=io.StringIO(json.dumps(event())),
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_binary_stdout_is_supported(self) -> None:
        out = io.BytesIO()
        code = hookio.run_hook(
            deny_all,
            stdin=io.BytesIO(json.dumps(event()).encode()),
            stdout=out,  # type: ignore[arg-type]
            stderr=io.StringIO(),
            exit_process=False,
        )
        self.assertEqual(code, 2)
        lines = out.getvalue().decode("ascii").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["hookSpecificOutput"]["permissionDecision"], "deny")

    # ----------------------------------------------------------------- Decision

    def test_decision_constructor_validates(self) -> None:
        with self.assertRaises(ValueError):
            Decision.deny("")
        with self.assertRaises(ValueError):
            Decision.deny(" \n\t ")
        with self.assertRaises(TypeError):
            Decision("yes")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            Decision(False, None)  # type: ignore[arg-type]
        self.assertTrue(Decision.allow().allowed)
        self.assertFalse(Decision.deny("why").allowed)


if __name__ == "__main__":
    unittest.main()
