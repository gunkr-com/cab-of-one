"""S5 C-main: audit hooks (Post/Failure, Subagent, Session) over the real Store.

Fixture: ``test_cli.CabProject`` (A's ``test_guard.Project`` plus the pinned entries).
Fictional Contoso data under <repo>/.local/test-tmp only; HOME is never read or set.
Hook events are synthetic dictionaries shaped like the measured events (contract
section 5); nothing here is an L2 measurement of Claude Code.

    python3 -m unittest discover -s tests -p test_audithook.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from typing import Any
from unittest import mock

from cab_of_one.runtime import audithook, fsutil, guard, hookevents, hookio, schema, selfaudit
from cab_of_one.runtime.state import Store
from cab_of_one.setup import profile, render
from test_cli import BASH_OK, TARGET, CabProject, secret_free, set_value
from test_guard import (
    CHANGE_ID,
    MCP_INPUT,
    MCP_WRITE,
    OPERATOR,
    REVIEW_SESSION,
    REVIEWER,
    SLUG,
    child_env,
)
from test_profile import encode, user
from test_render import build_source

PASS_BLOCK = 'Review done.\n```json\n{"verdict": "PASS", "findings": []}\n```\n'


def review_event(name: str, **changes: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "hook_event_name": name,
        "session_id": REVIEW_SESSION,
        "agent_id": REVIEWER,
        "agent_type": "safety-reviewer",
    }
    ev.update(changes)
    return ev


class HookCase(unittest.TestCase):
    def setUp(self) -> None:
        self.p = CabProject(self)
        self.p.targets = (TARGET,)

    def reserved(self, command: str | None = None) -> dict[str, Any]:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        ev = p.bash(command or set_value("u-1007", "Sales"))
        self.assertTrue(p.decide(ev).allowed)
        return ev

    def post_rows(self) -> list[dict[str, Any]]:
        return self.p.rows("post")


# --------------------------------------------------------------------------- settlement


class SettlementTests(HookCase):
    def test_measured_bash_shape_settles_ok(self) -> None:
        ev = self.reserved()
        self.assertEqual(self.p.audit("post", self.p.post(ev)), (0, ""))
        unit = self.p.doc()["units"][0]
        self.assertEqual((unit["outcome"], unit["verify"]), ("ok", None))
        self.assertEqual(unit["receipt"]["source"], "post")
        self.assertEqual(unit["receipt"]["response_sha256"], hookevents.response_sha256(BASH_OK))
        self.assertFalse(self.p.inflight_exists())
        row = self.post_rows()[-1]
        self.assertEqual(
            (row["decision"], row["outcome"], row["source"]), ("settled", "ok", "post")
        )
        self.assertEqual(self.p.doc()["state"], "executing")  # ok is never a verify PASS

    def test_shape_deviations_are_unknown_and_halt(self) -> None:
        cases = {
            "extra exit_code": dict(BASH_OK, exit_code=0),
            "interrupted": dict(BASH_OK, interrupted=True),
            "string bool": dict(BASH_OK, isImage="false"),
            "list": [BASH_OK],
            "missing key": {k: v for k, v in BASH_OK.items() if k != "stderr"},
        }
        for label, response in cases.items():
            with self.subTest(label):
                self.p = CabProject(self)
                ev = self.reserved()
                self.p.audit("post", self.p.post(ev, response))
                doc = self.p.doc()
                self.assertEqual(doc["units"][0]["outcome"], "unknown")
                self.assertEqual(doc["halted"]["code"], "write_unknown")

    def test_missing_response_is_unknown(self) -> None:
        ev = self.reserved()
        post = self.p.post(ev)
        del post["tool_response"]
        self.p.audit("post", post)
        self.assertEqual(self.p.doc()["units"][0]["outcome"], "unknown")

    def test_failure_exit_code_and_interrupt(self) -> None:
        for error, interrupt, outcome, exit_code, halt in (
            ("Exit code 7\nfixture stderr", False, "failed", 7, "write_failed"),
            ("Exit code 999", False, "failed", None, "write_failed"),
            ("Exit code 7", True, "unknown", 7, "write_unknown"),
            ("Exit code 7", "true", "failed", 7, "write_failed"),
        ):
            with self.subTest(error=error, interrupt=interrupt):
                self.p = CabProject(self)
                ev = self.reserved()
                self.p.audit("fail", self.p.failure(ev, error, is_interrupt=interrupt))
                unit = self.p.doc()["units"][0]
                self.assertEqual(unit["outcome"], outcome)
                self.assertEqual(unit["receipt"]["exit"], exit_code)
                self.assertEqual(self.p.doc()["halted"]["code"], halt)

    def test_mcp_post_is_unknown(self) -> None:
        p = self.p
        step = {"id": "m1", "tool": MCP_WRITE, "input_sha256": schema.input_sha256(MCP_INPUT),
                "targets": [TARGET]}  # fmt: skip
        p.prepare("normal", targets=(TARGET,), steps=[step])
        ev = p.event(MCP_WRITE, dict(MCP_INPUT))
        self.assertTrue(p.decide(ev).allowed)
        p.audit("post", p.post(ev, {"content": [{"type": "text", "text": "done"}]}))
        doc = p.doc()
        self.assertEqual((doc["units"][0]["outcome"], doc["halted"]["code"]),
                         ("unknown", "write_unknown"))  # fmt: skip

    def test_replay_and_conflict(self) -> None:
        p = self.p
        ev = self.reserved()
        p.audit("post", p.post(ev))
        before = p.state_bytes()
        p.audit("post", p.post(ev))
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(self.post_rows()[-1]["decision"], "replay")
        p.audit("fail", p.failure(ev))
        doc = p.doc()
        self.assertEqual(doc["halted"]["code"], "result_conflict")
        self.assertEqual(doc["units"][0]["outcome"], "unknown")
        self.assertEqual(self.post_rows()[-1]["reason_code"], "result_conflict")

    def test_secret_only_difference_keeps_the_reservation(self) -> None:
        p = self.p
        command = set_value("u-1007", "Sales") + " --note CONTOSO-SECRET-4821"
        p.prepare("normal", targets=(TARGET,),
                  steps=[{"id": "s1", "command": command, "targets": [TARGET]}])  # fmt: skip
        ev = p.bash(command)
        self.assertTrue(p.decide(ev).allowed)
        other = p.post(ev, tool_input={"command": command.replace("4821", "9999")})
        p.audit("post", other)
        doc = p.doc()
        self.assertEqual(doc["halted"]["code"], "settle_mismatch")
        self.assertIsNotNone(doc["inflight"])
        self.assertTrue(p.inflight_exists())


# --------------------------------------------------------------------------- edge rows


class EdgeRowTests(HookCase):
    def test_unbound_keeps_the_reservation(self) -> None:
        p = self.p
        ev = self.reserved()
        before = p.state_bytes()
        post = p.post(ev)
        del post["tool_use_id"]
        p.audit("post", post)
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(self.post_rows()[-1]["decision"], "unbound")
        post["tool_use_id"] = "bad id with spaces"
        p.audit("post", post)
        self.assertEqual(p.state_bytes(), before)

    def test_unreadable_event(self) -> None:
        p = self.p
        self.reserved()
        before = p.state_bytes()
        for text in ("{broken", '{"hook_event_name": "PostToolUse", "a": 1, "a": 2}', ""):
            self.assertEqual(p.audit("post", text), (0, ""))
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual({r["decision"] for r in self.post_rows()}, {"unreadable"})

    def test_unguarded_write_without_a_change(self) -> None:
        p = self.p
        ev = p.bash(set_value("u-1007", "Sales"))
        p.audit("post", p.post(ev))
        row = self.post_rows()[-1]
        self.assertEqual((row["decision"], row["change_id"]), ("unguarded_no_change", None))
        self.assertFalse((p.project / ".cab" / "state" / "active.json").exists())

    def test_unknown_token_with_an_active_change_halts(self) -> None:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        ev = p.bash(set_value("u-1007", "Sales"))  # never passed the guard
        p.audit("post", p.post(ev))
        self.assertEqual(p.doc()["halted"]["code"], "unguarded_write")

    def test_not_admin_and_fixed_cli_calls_are_not_settled(self) -> None:
        p = self.p
        ev = self.reserved()
        p.audit("post", p.post(ev))
        before = p.state_bytes()
        rows = len(self.post_rows())
        read = p.event("Read", {"file_path": str(p.project / "notes.txt")})
        p.audit("post", p.post(read, {"type": "text"}))
        cab = p.bash(".claude/hooks/cab/cab status")
        self.assertTrue(p.decide(cab).allowed)
        p.audit("post", p.post(cab))
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(len(self.post_rows()), rows)

    def test_store_failure_is_an_error_row_and_keeps_the_reservation(self) -> None:
        p = self.p
        ev = self.reserved()
        with mock.patch.object(Store, "settle", side_effect=fsutil.LockTimeout("busy")):
            p.audit("post", p.post(ev))
        row = self.post_rows()[-1]
        self.assertEqual((row["decision"], row["reason_code"]), ("error", "lock_timeout"))
        self.assertTrue(p.inflight_exists())

    def test_runtime_unavailable_is_silent_and_changes_nothing(self) -> None:
        p = self.p
        ev = self.reserved()
        before = p.state_bytes()
        p.env = {"CLAUDE_PROJECT_DIR": str(p.home)}
        self.assertEqual(p.audit("post", p.post(ev)), (0, ""))
        self.assertEqual(p.state_bytes(), before)


# --------------------------------------------------------------------------- interview evidence


class AskUserTests(HookCase):
    def ask(self) -> dict[str, Any]:
        ev = self.p.event("AskUserQuestion", {"questions": [{"question": "Which mailboxes?"}]})
        return self.p.post(ev, {"answers": {"Which mailboxes?": "ANSWERSENTINELq1"}})

    def test_question_is_recorded_without_its_answer(self) -> None:
        p = self.p
        p.store().new_change(CHANGE_ID, SLUG, OPERATOR)
        p.audit("post", self.ask())
        rows = p.rows("intake")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(
            (row["source"], row["reason_code"], row["outcome"], row["change_id"]),
            ("askuser", "answers_unmeasured", "unknown", CHANGE_ID),
        )
        self.assertIn("Which mailboxes?", row["command_redacted"])
        self.assertNotIn(b"ANSWERSENTINELq1", p.ledger_bytes())
        self.assertEqual(p.doc()["units"], [])

    def test_no_change_no_intake_row(self) -> None:
        self.p.audit("post", self.ask())
        self.assertEqual(self.p.rows("intake"), [])


# --------------------------------------------------------------------------- E14


class SecretTests(HookCase):
    def test_e14_secret_appears_nowhere(self) -> None:
        """real guard, real hooks, real subprocess probes (SimClock)."""
        p = self.p
        secret = "CONTOSO-SECRET-4821"
        command = set_value("u-1007", "Sales") + f" --note {secret}"
        p.prepare("normal", targets=(TARGET,),
                  steps=[{"id": "s1", "command": command, "targets": [TARGET]}])  # fmt: skip
        ev = p.bash(command)
        self.assertTrue(p.decide(ev).allowed)
        p.audit("post", p.post(ev, dict(BASH_OK, stdout=f"token={secret}")))
        code, verify_out, verify_err = p.cab("verify", CHANGE_ID)
        # a recorded verdict (PASS or FAIL), not a refusal: the evidence below must exist
        self.assertIn(code, (0, 10), verify_out + verify_err)
        self.assertEqual(p.doc()["units"][0]["verify_ref"]["line"], 1)
        _, status_out, _ = p.cab("status", CHANGE_ID)
        _, stop = p.stop()
        verify_json = (p.folder / "verify.json").read_bytes()
        secret_free(self, secret, p.ledger_bytes(), p.state_bytes(), verify_json,
                    verify_out, verify_err, status_out, json.dumps(stop))  # fmt: skip


# --------------------------------------------------------------------------- review


class ReviewTests(HookCase):
    def snapshotted(self) -> None:
        self.p.prepare("normal", targets=(TARGET,), review=None, approve=False)

    def test_start_and_pass_record_the_review(self) -> None:
        p = self.snapshotted() or self.p
        p.audit("substart", review_event("SubagentStart"))
        start = p.doc()["review_start"]
        self.assertEqual((start["agent_id"], start["session_id"]), (REVIEWER, REVIEW_SESSION))
        p.audit("substop", review_event("SubagentStop", last_assistant_message=PASS_BLOCK))
        doc = p.doc()
        self.assertEqual(doc["state"], "reviewed")
        review = json.loads((p.folder / "review.json").read_text())
        self.assertEqual((review["verdict"], review["session_id"]), ("PASS", REVIEW_SESSION))

    def test_unreadable_handback_is_block_never_pass(self) -> None:
        cases = {
            "missing": None,
            "no fence": '{"verdict": "PASS", "findings": []}',
            "trailing text": PASS_BLOCK + "Actually, one more thing.",
            "two blocks": PASS_BLOCK + PASS_BLOCK,
            "extra key": '```json\n{"verdict": "PASS", "findings": [], "x": 1}\n```',
            "duplicate key": (
                '```json\n{"verdict": "BLOCK", "verdict": "PASS", "findings": []}\n```'
            ),
        }
        for label, message in cases.items():
            with self.subTest(label):
                self.p = CabProject(self)
                p = self.snapshotted() or self.p
                p.audit("substart", review_event("SubagentStart"))
                stop = review_event("SubagentStop")
                if message is not None:
                    stop["last_assistant_message"] = message
                p.audit("substop", stop)
                doc = p.doc()
                self.assertEqual(doc["state"], "planned")
                review = json.loads((p.folder / "review.json").read_text())
                self.assertEqual(review["verdict"], "BLOCK")
                self.assertEqual(review["findings"][0]["code"], "review_unreadable")

    def test_stop_from_another_session_changes_nothing(self) -> None:
        p = self.snapshotted() or self.p
        p.audit("substart", review_event("SubagentStart"))
        before = p.state_bytes()
        p.audit("substop", review_event("SubagentStop", session_id="sess-other-02",
                                        last_assistant_message=PASS_BLOCK))  # fmt: skip
        self.assertEqual(p.state_bytes(), before)
        row = p.rows("subagent_stop")[-1]
        self.assertEqual((row["decision"], row["reason_code"]), ("error", "review_session"))

    def test_other_agents_have_no_authority(self) -> None:
        p = self.snapshotted() or self.p
        before = p.state_bytes()
        for name in ("SubagentStart", "SubagentStop"):
            p.audit("substart" if name == "SubagentStart" else "substop",
                    review_event(name, agent_type="impact-analyst",
                                 last_assistant_message=PASS_BLOCK))  # fmt: skip
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual({r["decision"] for r in p.rows("subagent_start")}, {"logged"})

    def test_reviewer_without_session_is_refused(self) -> None:
        p = self.snapshotted() or self.p
        before = p.state_bytes()
        ev = review_event("SubagentStart")
        del ev["session_id"]
        p.audit("substart", ev)
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(p.rows("subagent_start")[-1]["reason_code"], "identity_invalid")

    def test_parse_review_message(self) -> None:
        ok = audithook.parse_review_message(
            "x\n```json\n"
            '{"verdict": "PASS_WITH_CONDITIONS", "findings": [{"code": "B7", "detail": "d"}]}'
            "\n```\n  \n"
        )
        self.assertEqual(ok, ("PASS_WITH_CONDITIONS", [{"code": "B7", "detail": "d"}]))
        refusals = {
            "review_missing": 3,
            "review_block_count": "```json\n{}\n```\n```\n",
            "review_block_shape": "x```json\n{}\n```",
            "review_json_invalid": '```json\n{"verdict": NaN}\n```',
            "review_keys": '```json\n{"verdict": "PASS"}\n```',
            "review_verdict": '```json\n{"verdict": "OK", "findings": []}\n```',
            "review_findings": '```json\n{"verdict": "PASS", "findings": [{"code": "B1"}]}\n```',
            "review_too_large": "x" * (audithook.MAX_REVIEW_MESSAGE_BYTES + 1),
        }
        for code, message in refusals.items():
            with self.subTest(code):
                self.assertEqual(audithook.parse_review_message(message), code)


# --------------------------------------------------------------------------- session


def start_event(**changes: Any) -> dict[str, Any]:
    ev = {"hook_event_name": "SessionStart", "session_id": "sess-main-01", "source": "startup"}
    ev.update(changes)
    return ev


ADMIN_MARK = "WARNING (setup profile): the agent identity is admin."
BYPASS_MARK = "WARNING (setup profile): this project was set up for bypass permissions mode"
UNMEASURED_MARK = "are UNMEASURED; nothing is assumed and nothing is granted"
SELFTEST_PASS = "Guard self test (synthetic fixture, not a live check): pass"


class SessionTests(HookCase):
    def test_start_selftest_passes_in_an_isolated_fixture(self) -> None:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        active = (p.project / ".cab" / "state" / "active.json").read_bytes()
        state = p.change_doc()
        code, out = p.audit("start", start_event())
        self.assertEqual(code, 0)
        payload = json.loads(out)
        context = payload["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Guard self test (synthetic fixture, not a live check): pass", context)
        self.assertNotIn("systemMessage", payload)
        row = p.rows(audithook.SESSION_START_EVENT)[-1]
        self.assertEqual((row["decision"], row["session_id"]), ("selftest_pass", "sess-main-01"))
        self.assertEqual((p.project / ".cab" / "state" / "active.json").read_bytes(), active)
        self.assertEqual(p.change_doc(), state)
        leftovers = os.listdir(p.project / ".cab" / "state" / "selftest")
        self.assertEqual(leftovers, [])
        evidence = selfaudit.load_session_evidence(
            str(p.project), start_events=audithook.START_EVENTS
        )
        self.assertIn("sess-main-01", evidence.session_ids)

    def test_selftest_requires_the_exact_no_change_denial(self) -> None:
        p = self.p
        cases = {
            "not_denied": hookio.Decision.allow(),
            "unexpected_denial": hookio.Decision.deny(guard.message("internal_error")),
        }
        for code, decision in cases.items():
            with self.subTest(code):
                result = audithook.run_guard_selftest(
                    p.roots, clock=p.clock, decide=lambda *a, d=decision, **k: d
                )
                self.assertEqual((result.ok, result.code), (False, code))
        failing = lambda roots, clock: audithook.SelfTest(False, "not_denied")  # noqa: E731
        _, out = p.audit("start", start_event(), selftest=failing)
        payload = json.loads(out)
        self.assertIn("FAILED [not_denied]", payload["systemMessage"])
        self.assertEqual(p.rows(audithook.SESSION_START_EVENT)[-1]["decision"], "selftest_fail")

    def test_start_without_runtime_warns(self) -> None:
        p = self.p
        p.env = {"CLAUDE_PROJECT_DIR": str(p.home)}
        _, out = p.audit("start", start_event())
        self.assertIn("could not load the project runtime", json.loads(out)["systemMessage"])

    def test_start_without_profile_metadata_warns_unmeasured(self) -> None:
        # The S5 fixture installs no metadata: an unmeasured warning, never silence.
        p = self.p
        _, out = p.audit("start", start_event())
        context = json.loads(out)["hookSpecificOutput"]["additionalContext"]
        self.assertIn(f"{audithook.SESSION_PROFILE_PATH} is missing", context)
        self.assertIn(UNMEASURED_MARK, context)
        self.assertNotIn(ADMIN_MARK, context)
        self.assertNotIn(BYPASS_MARK, context)

    def test_end_logs_reason_and_handoff(self) -> None:
        p = self.p
        ev = self.reserved()
        p.audit("post", p.post(ev))
        before = p.state_bytes()
        p.audit("end", {"hook_event_name": "SessionEnd", "session_id": "sess-main-01",
                        "reason": "logout"})  # fmt: skip
        row = p.rows("session_end")[-1]
        self.assertEqual((row["reason_code"], row["decision"]), ("logout", "handoff_due"))
        self.assertEqual(p.state_bytes(), before)


# --------------------------------------------------------------------------- setup metadata


class SessionProfileTests(HookCase):
    """SessionStart warnings from ``.claude/hooks/cab/session-profile.json``.

    In-process cases call ``audithook.main`` from the source package; the synthetic guard
    self test runs in its own fixture either way and is never a live check. The subprocess
    case runs the installed ``audit.py`` with the pinned package copy, not the source tree.
    """

    def meta(self) -> Any:
        return self.p.entry.parent / "session-profile.json"

    def clear(self) -> None:
        path = self.meta()
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()

    def start(self, **kw: Any) -> tuple[str, dict[str, Any]]:
        code, out = self.p.audit("start", start_event(), **kw)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        return payload["hookSpecificOutput"]["additionalContext"], payload

    def test_real_profile_combinations(self) -> None:
        """admin/read-only x manual/bypass-guarded/auto, rendered from real profiles."""
        p = self.p
        source = build_source(p.tmp / "render-source")
        before = p.state_bytes()
        for ident, mode in (
            ("read-only", "manual"),
            ("read-only", "bypass-guarded"),
            ("admin", "manual"),
            ("admin", "bypass-guarded"),
            ("admin", "auto"),
            ("read-only", "auto"),
        ):
            with self.subTest(identity=ident, mode=mode):
                prof = profile.load_profile(
                    encode(user(identity__agent_identity=ident, session__permission_mode=mode))
                )
                data = render.render_bundle(prof, source)[render.SESSION_PROFILE_PATH]
                self.clear()
                self.meta().write_bytes(data)
                context, payload = self.start()
                self.assertEqual(ADMIN_MARK in context, ident == "admin")
                self.assertEqual(BYPASS_MARK in context, mode == "bypass-guarded")
                self.assertNotIn(UNMEASURED_MARK, context)
                self.assertIn(SELFTEST_PASS, context)
                self.assertNotIn("systemMessage", payload)  # the self test result decides it
                row = p.rows(audithook.SESSION_START_EVENT)[-1]
                self.assertEqual(row["decision"], "selftest_pass")
                self.assertNotIn("Contoso", data.decode("ascii"))  # booleans only
        self.assertEqual(p.state_bytes(), before)

    def test_missing_corrupt_or_unsafe_metadata_is_unmeasured_never_silent(self) -> None:
        p = self.p
        good = audithook.session_profile_bytes(admin_identity=True, bypass_guarded=True)
        outside = p.tmp / "outside-profile.json"
        outside.write_bytes(good)

        def put(data: bytes) -> None:
            self.meta().write_bytes(data)

        cases: dict[str, tuple[Any, str]] = {
            "missing": (lambda: None, "is missing"),
            "empty object": (lambda: put(b"{}\n"), "is not exactly"),
            "int not bool": (
                lambda: put(good.replace(b"true", b"1")), "is not exactly",
            ),
            "string not bool": (
                lambda: put(good.replace(b"true", b'"true"')), "is not exactly",
            ),
            "extra profile string": (
                lambda: put(b'{"admin_identity": false, "bypass_guarded": false, '
                            b'"org": "Contoso"}\n'),
                "is not exactly",
            ),
            "non-canonical bytes": (
                lambda: put(b'{"admin_identity":true,"bypass_guarded":true}\n'), "is not exactly",
            ),
            "not json": (lambda: put(b"\xff\xfe"), "is not exactly"),
            "oversized": (lambda: put(b" " * 5000), "is not a plain single-link file"),
            "symlink": (lambda: os.symlink(outside, self.meta()), "is not a plain"),
            "hard link": (lambda: os.link(outside, self.meta()), "is not a plain"),
            "folder": (lambda: self.meta().mkdir(), "is not a plain"),
        }  # fmt: skip
        before = p.state_bytes()
        for label, (make, problem) in cases.items():
            with self.subTest(label):
                self.clear()
                make()
                context, payload = self.start()
                self.assertIn(f"{audithook.SESSION_PROFILE_PATH} {problem}", context)
                self.assertIn(UNMEASURED_MARK, context)
                # a link to a "true/true" file is not read as true, nor as "no warning"
                self.assertNotIn(ADMIN_MARK, context)
                self.assertNotIn(BYPASS_MARK, context)
                self.assertIn(SELFTEST_PASS, context)
                self.assertNotIn("systemMessage", payload)
                self.assertEqual(p.rows(audithook.SESSION_START_EVENT)[-1]["decision"],
                                 "selftest_pass")  # fmt: skip
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(outside.read_bytes(), good)

    def test_warnings_never_change_the_self_test_result(self) -> None:
        self.meta().write_bytes(
            audithook.session_profile_bytes(admin_identity=True, bypass_guarded=False)
        )
        failing = lambda roots, clock: audithook.SelfTest(False, "not_denied")  # noqa: E731
        context, payload = self.start(selftest=failing)
        self.assertIn("FAIL [not_denied]", context)
        self.assertIn(ADMIN_MARK, context)
        self.assertIn("FAILED [not_denied]", payload["systemMessage"])
        self.assertEqual(self.p.rows(audithook.SESSION_START_EVENT)[-1]["decision"],
                         "selftest_fail")  # fmt: skip

    def test_parse_is_exact(self) -> None:
        for admin in (False, True):
            for bypass in (False, True):
                data = audithook.session_profile_bytes(admin_identity=admin, bypass_guarded=bypass)
                self.assertEqual(audithook.parse_session_profile(data), (admin, bypass))
        self.assertEqual(
            audithook.session_profile_bytes(admin_identity=True, bypass_guarded=False),
            b'{\n  "admin_identity": true,\n  "bypass_guarded": false\n}\n',
        )
        good = audithook.session_profile_bytes(admin_identity=False, bypass_guarded=False)
        for bad in (
            good.decode(), good + b"\n", good.rstrip(b"\n"), b"\xef\xbb\xbf" + good,
            b'{\n  "admin_identity": false,\n  "admin_identity": false,\n'
            b'  "bypass_guarded": false\n}\n',
            b'{\n  "admin_identity": null,\n  "bypass_guarded": false\n}\n',
            b"[]\n",
        ):  # fmt: skip
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audithook.parse_session_profile(bad)
        one: Any = 1
        with self.assertRaises(TypeError):
            audithook.session_profile_bytes(admin_identity=one, bypass_guarded=False)

    def test_installed_audit_entry_warns(self) -> None:
        """real subprocess: the installed audit.py and its pinned package (not the source
        tree); the self test inside is still synthetic."""
        p = self.p
        p.install()

        def run() -> dict[str, Any]:
            proc = subprocess.run(
                [sys.executable, p.audit_entry, "start"],
                input=json.dumps(start_event()).encode(), cwd=str(p.project),
                env=dict(child_env(str(p.project)), HOME=str(p.home)),
                capture_output=True, timeout=60, check=False,
            )  # fmt: skip
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout.decode("ascii"))

        self.meta().write_bytes(
            audithook.session_profile_bytes(admin_identity=True, bypass_guarded=True)
        )
        context = run()["hookSpecificOutput"]["additionalContext"]
        self.assertIn(ADMIN_MARK, context)
        self.assertIn(BYPASS_MARK, context)
        self.assertIn("synthetic fixture, not a live check", context)
        self.clear()
        target = p.tmp / "linked-profile.json"
        target.write_bytes(
            audithook.session_profile_bytes(admin_identity=False, bypass_guarded=False)
        )
        os.symlink(target, self.meta())
        context = run()["hookSpecificOutput"]["additionalContext"]
        self.assertIn(UNMEASURED_MARK, context)
        self.assertIn("is not a plain single-link file", context)


# --------------------------------------------------------------------------- shim


class ShimTests(HookCase):
    def test_audit_shim_import_failure_settles_nothing(self) -> None:
        """real subprocess: the generated audit.py with a broken pinned package."""
        p = self.p
        ev = self.reserved()
        p.install(broken=True)
        before = p.state_bytes()
        proc = subprocess.run(
            [sys.executable, p.audit_entry, "post"], input=json.dumps(p.post(ev)).encode(),
            cwd=str(p.project), env=dict(child_env(str(p.project)), HOME=str(p.home)),
            capture_output=True,
            timeout=60, check=False,
        )  # fmt: skip
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"could not start", proc.stderr)
        self.assertNotIn(b"Traceback", proc.stderr)
        self.assertEqual(p.state_bytes(), before)
        self.assertTrue(p.inflight_exists())


if __name__ == "__main__":
    unittest.main()
