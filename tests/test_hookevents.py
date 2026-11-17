"""Tests for cab_of_one.runtime.hookevents (S5 C0). Injected streams only; no files."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import unittest
from typing import Any
from unittest import mock

from cab_of_one.runtime import hookevents
from cab_of_one.runtime.hookevents import EventError, read_event, recognize
from cab_of_one.runtime.ledger import redact_value
from cab_of_one.runtime.schema import canonical_json

SECRET = "sk-FICTIONAL-SECRET-0123456789"
EXPECTED = frozenset({"PostToolUse", "PostToolUseFailure"})


def measured_response(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "stdout": "",
        "stderr": "",
        "interrupted": False,
        "isImage": False,
        "noOutputExpected": False,
    }
    base.update(overrides)
    return base


def post(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "session_id": "5e2b41ed-28d8-4bbd-aa16-f6c9a90088c4",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "simtenant --state s.json disable user/u1"},
        "tool_use_id": "toolu_012oUKpwCp5sLvg4B1kdtNyn",
        "cwd": "/work/contoso-ops",
        "tool_response": measured_response(),
    }
    base.update(overrides)
    return base


def failure(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "session_id": "6241ac13-e01c-436b-bf54-755193937b55",
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "simtenant --state s.json disable user/u1"},
        "tool_use_id": "toolu_01HfJo2w8pcSNmNQZRqBE5pe",
        "cwd": "/work/contoso-ops",
        "error": "Exit code 7\nsome stderr",
        "is_interrupt": False,
    }
    base.update(overrides)
    return base


class Endless:
    """A stream that never ends; counts the bytes handed out."""

    def __init__(self) -> None:
        self.given = 0

    def read(self, n: int = -1) -> bytes:
        assert n > 0
        self.given += n
        return b" " * n


class ReadEventTests(unittest.TestCase):
    def read(self, raw: bytes | str) -> dict[str, Any]:
        stream = io.BytesIO(raw) if isinstance(raw, bytes) else io.StringIO(raw)
        return read_event(stream, EXPECTED)

    def code(self, raw: bytes | str) -> str:
        with self.assertRaises(EventError) as ctx:
            self.read(raw)
        return ctx.exception.code

    def test_valid_bytes_and_text(self) -> None:
        raw = json.dumps(post())
        self.assertEqual(self.read(raw.encode())["tool_name"], "Bash")
        self.assertEqual(self.read(raw)["hook_event_name"], "PostToolUse")

    def test_strictness(self) -> None:
        self.assertEqual(
            self.code(b'{"hook_event_name":"PostToolUse","a":1,"a":2}'), "duplicate_key"
        )
        self.assertEqual(self.code(b'{"hook_event_name":"PostToolUse","a":NaN}'), "non_finite")
        self.assertEqual(self.code(b'{"hook_event_name":"PostToolUse","a":Infinity}'), "non_finite")
        self.assertEqual(self.code(b"[1]"), "not_object")
        self.assertEqual(self.code(b"\xff\xfe"), "encoding")
        self.assertEqual(self.code(b"{"), "syntax")
        self.assertEqual(self.code(b""), "empty")
        self.assertEqual(self.code('﻿{"hook_event_name":"PostToolUse"}'.encode()), "bom")

    def test_event_name_must_be_expected(self) -> None:
        self.assertEqual(self.code(json.dumps(post(hook_event_name="PreToolUse"))), "event_name")
        listed = json.dumps(post(hook_event_name=["PostToolUse"]))
        self.assertEqual(self.code(listed), "event_name")
        data = post()
        del data["hook_event_name"]
        self.assertEqual(self.code(json.dumps(data)), "event_name")

    def test_bounded_read(self) -> None:
        stream = Endless()
        with mock.patch.object(hookevents, "MAX_EVENT_BYTES", 1000):
            with self.assertRaises(EventError) as ctx:
                read_event(stream, EXPECTED)
        self.assertEqual(ctx.exception.code, "too_large")
        self.assertEqual(stream.given, 1001)

    def test_read_error_is_fixed_code(self) -> None:
        class Broken:
            def read(self, _n: int) -> bytes:
                raise OSError(SECRET)

        with self.assertRaises(EventError) as ctx:
            read_event(Broken(), EXPECTED)
        self.assertEqual(ctx.exception.code, "unreadable")
        self.assertNotIn(SECRET, str(ctx.exception))


class IdentityTests(unittest.TestCase):
    def test_main(self) -> None:
        who = hookevents.identity(post())
        self.assertTrue(who.is_main)
        self.assertFalse(who.is_subagent)
        self.assertEqual(who.tool_use_id, "toolu_012oUKpwCp5sLvg4B1kdtNyn")

    def test_agent_id_key_is_never_main(self) -> None:
        for value in ("agent-1", "", None, 7):
            who = hookevents.identity(post(agent_id=value))
            self.assertTrue(who.is_subagent)
            self.assertFalse(who.is_main)

    def test_malformed_identity_is_not_main(self) -> None:
        for field, value in (
            ("session_id", "bad id"),
            ("session_id", 5),
            ("session_id", ""),
            ("tool_name", "Ba\x00sh"),
            ("tool_name", ""),
            ("tool_name", "x" * 257),
            ("tool_name", None),
        ):
            with self.subTest(field=field, value=value):
                who = hookevents.identity(post(**{field: value}))
                self.assertFalse(who.is_main)
        missing = post()
        del missing["session_id"]
        self.assertFalse(hookevents.identity(missing).is_main)

    def test_malformed_tool_use_id_is_none(self) -> None:
        for value in ("bad id", "", 3, "x" * 129):
            self.assertIsNone(hookevents.identity(post(tool_use_id=value)).tool_use_id)


class RecognizeTests(unittest.TestCase):
    def test_measured_success_is_ok(self) -> None:
        result = recognize(post())
        self.assertEqual((result.source, result.outcome, result.exit), ("post", "ok", None))
        self.assertEqual(result.shape, "bash_success")
        self.assertRegex(result.response_sha256 or "", r"^[0-9a-f]{64}$")

    def test_each_deviation_is_unknown(self) -> None:
        cases: list[Any] = []
        for key in hookevents.BASH_SUCCESS_KEYS:
            missing = measured_response()
            del missing[key]
            cases.append(missing)
        cases += [
            measured_response(exit_code=0),
            measured_response(interrupted=True),
            measured_response(interrupted="false"),
            measured_response(interrupted=0),
            measured_response(isImage=None),
            measured_response(noOutputExpected="no"),
            measured_response(stdout=1),
            measured_response(stderr=None),
            [measured_response()],
            "Success",
            None,
            {},
        ]
        for response in cases:
            with self.subTest(response=response):
                result = recognize(post(tool_response=response))
                self.assertEqual(result.outcome, "unknown")
        absent = post()
        del absent["tool_response"]
        result = recognize(absent)
        self.assertEqual(result.outcome, "unknown")
        self.assertIsNone(result.response_sha256)

    def test_stdout_content_is_never_inspected(self) -> None:
        for text in ("Success", "FAILED", "error: denied", "Exit code 1", ""):
            for stream in ("stdout", "stderr"):
                with self.subTest(text=text, stream=stream):
                    result = recognize(post(tool_response=measured_response(**{stream: text})))
                    self.assertEqual(result.outcome, "ok")

    def test_non_bash_post_is_unknown(self) -> None:
        for tool in ("mcp__tenant__disable_user", "Write", "PowerShell", "bash"):
            with self.subTest(tool=tool):
                self.assertEqual(recognize(post(tool_name=tool)).outcome, "unknown")

    def test_failure_exit_code(self) -> None:
        result = recognize(failure())
        self.assertEqual((result.source, result.outcome, result.exit), ("failure", "failed", 7))
        self.assertIsNone(result.response_sha256)
        for error, expected in (
            ("Exit code 7", 7),
            ("Exit code 0", 0),
            ("Exit code 255\n", 255),
            ("Exit code 256", None),
            ("Exit code 1000", None),
            ("exit code 7", None),
            (" Exit code 7", None),
            ("Exit code 7 ", None),
            ("Exit code 7\r\nmore", None),
            ("Exit code -1", None),
            ("Exit code ٧", None),
            ("Command failed", None),
            ("", None),
            (7, None),
            (None, None),
        ):
            with self.subTest(error=error):
                self.assertEqual(recognize(failure(error=error)).exit, expected)
                self.assertEqual(recognize(failure(error=error)).outcome, "failed")

    def test_failure_interrupt(self) -> None:
        self.assertEqual(recognize(failure(is_interrupt=True)).outcome, "unknown")
        # Only the boolean True is an interrupt; the string is evaluated, not trusted.
        self.assertEqual(recognize(failure(is_interrupt="true")).outcome, "failed")
        self.assertEqual(recognize(failure(is_interrupt=1)).outcome, "failed")

    def test_other_events_refused(self) -> None:
        for name in ("PreToolUse", "Stop", None):
            with self.assertRaises(EventError):
                recognize(post(hook_event_name=name))

    def test_response_hash_is_of_redacted_value(self) -> None:
        response = measured_response(stdout=f"token={SECRET}")
        result = recognize(post(tool_response=response))
        expected = hashlib.sha256(
            canonical_json(redact_value(response)).encode("ascii")
        ).hexdigest()
        self.assertEqual(result.response_sha256, expected)
        other = measured_response(stdout="token=sk-FICTIONAL-OTHER-9876543210")
        self.assertEqual(recognize(post(tool_response=other)).response_sha256, expected)

    def test_secret_not_in_result_text(self) -> None:
        data = post(
            tool_input={"command": f"simtenant --client-secret {SECRET} disable user/u1"},
            tool_response=measured_response(stdout=SECRET),
        )
        result = recognize(data)
        self.assertNotIn(SECRET, repr(result))
        self.assertNotIn(SECRET, str(result))
        self.assertEqual(result.tool_input, data["tool_input"])  # raw, for the HMAC only

    def test_non_dict_input_is_none(self) -> None:
        self.assertIsNone(recognize(post(tool_input="x")).tool_input)

    def test_input_not_mutated(self) -> None:
        data = post(tool_response=measured_response(stdout=SECRET))
        before = copy.deepcopy(data)
        recognize(data)
        self.assertEqual(data, before)


if __name__ == "__main__":
    unittest.main()
