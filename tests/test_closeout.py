"""S5 C-main: the Stop hook (contract section 4.3) over the real Store and obligations.

Fixture: ``test_cli.CabProject`` under <repo>/.local/test-tmp; fictional Contoso data.
The Stop JSON form and the display of ``systemMessage`` are UNMEASURED until L2; these
tests check what the hook prints, not how Claude Code shows it.

    python3 -m unittest discover -s tests -p test_closeout.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from typing import Any

from cab_of_one.runtime import closeout, obligations, schema
from test_cli import TARGET, CabProject, set_value
from test_guard import CHANGE_ID, child_env

CLI = ".claude/hooks/cab/cab"


def stop_event(active: Any = False, **changes: Any) -> dict[str, Any]:
    ev = {"hook_event_name": "Stop", "session_id": "sess-main-01", "stop_hook_active": active}
    ev.update(changes)
    return ev


class StopCase(unittest.TestCase):
    def setUp(self) -> None:
        self.p = CabProject(self)
        self.p.targets = (TARGET,)

    def written(self, outcome: str | None = "ok") -> dict[str, Any]:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        ev = p.bash(set_value("u-1007", "Sales"))
        self.assertTrue(p.decide(ev).allowed)
        if outcome is not None:
            p.settle(ev, outcome)
        return ev

    def blocked(self, event: dict[str, Any] | None = None) -> str:
        code, out = self.p.stop(event)
        self.assertEqual(code, 0)
        self.assertIsNotNone(out)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertEqual(out["decision"], "block")
        return out["reason"]


class StopMatrixTests(StopCase):
    def test_nothing_owed_prints_nothing(self) -> None:
        self.assertEqual(self.p.stop(), (0, None))
        self.p.prepare("normal", targets=(TARGET,))
        self.assertEqual(self.p.stop(), (0, None))

    def test_exact_escape_only(self) -> None:
        p = self.p
        self.written(outcome=None)
        self.assertEqual(p.stop(stop_event(True)), (0, None))
        self.assertEqual(p.rows("stop")[-1]["decision"], "pass_active")
        for value in ("true", 1, None):
            with self.subTest(value=value):
                self.assertIn("never returned a result", self.blocked(stop_event(value)))

    def test_inflight_blocks(self) -> None:
        self.written(outcome=None)
        reason = self.blocked()
        self.assertEqual(
            reason,
            f"{CHANGE_ID}: a write never returned a result. Stop writing; a person must run "
            f"cab resume {CHANGE_ID} in their own terminal.",
        )
        self.assertEqual(self.p.rows("stop")[-1]["reason_code"], "inflight")

    def test_unverified_write_blocks(self) -> None:
        self.written()
        reason = self.blocked()
        self.assertIn(f"{CHANGE_ID} has 1 writes with no verification after them", reason)
        self.assertIn(f"Run {CLI} verify {CHANGE_ID}.", reason)

    def test_halted_blocks_and_offers_failed_close_only_when_possible(self) -> None:
        p = self.p
        self.written(outcome="failed")
        reason = self.blocked()
        self.assertIn("is halted [write_failed]", reason)
        self.assertNotIn("end it as failed", reason)  # verify debt first
        p.verify(1, "FAIL")
        reason = self.blocked()
        self.assertIn(f"or end it as failed: {CLI} close {CHANGE_ID}", reason)

    def test_committed_unmeasured_is_reported_not_blocked(self) -> None:
        p = self.p
        self.written()
        p.verify(1, "UNMEASURED")
        code, out = p.stop()
        self.assertEqual(code, 0)
        self.assertEqual(set(out), {"systemMessage"})
        text = out["systemMessage"]
        self.assertIn("is not verified (0 FAIL, 1 UNMEASURED); it is not closed", text)
        self.assertIn("simtenant/simtenant.py", text)  # the exact command a person runs
        for word in ("PASS", "done", "succeeded"):
            self.assertNotIn(word, text)
        self.assertEqual(p.rows("stop")[-1]["decision"], "report")
        p.close()
        self.assertEqual(p.doc()["state"], "open-unverified")
        self.assertIn("systemMessage", p.stop()[1])

    def test_unfinished_close_blocks(self) -> None:
        p = self.p
        self.written()
        p.verify(1, "FAIL")
        p.close()
        self.assertEqual(p.stop(), (0, None))  # pointer cleared: nothing owed
        p.write(".cab/state/active.json",
                schema.canonical_bytes({"schema": 1, "change_id": CHANGE_ID}))  # fmt: skip
        reason = self.blocked()
        self.assertIn("close did not finish", reason)

    def test_invalid_state_or_evidence_blocks(self) -> None:
        p = self.p
        self.written()
        p.verify(1, "PASS")
        verify = p.folder / "verify.json"
        verify.write_bytes(verify.read_bytes().replace(b'"PASS"', b'"FAIL"', 1))
        self.assertEqual(self.blocked(), closeout.STATE_INVALID_TEXT)
        self.assertEqual(p.rows("stop")[-1]["reason_code"], "state_invalid")
        state = p.project / ".cab" / "state" / "changes" / f"{CHANGE_ID}.json"
        state.write_bytes(b"{")
        self.assertEqual(self.blocked(), closeout.STATE_INVALID_TEXT)

    def test_unreadable_event_and_roots_block(self) -> None:
        p = self.p
        self.assertEqual(self.blocked("{broken"), closeout.UNREADABLE_TEXT)
        self.assertEqual(self.blocked(json.dumps({"hook_event_name": "PostToolUse"})),
                         closeout.UNREADABLE_TEXT)  # fmt: skip
        code, out = p.stop(env={"CLAUDE_PROJECT_DIR": str(p.home)})
        self.assertEqual(out, {"decision": "block", "reason": closeout.STATE_INVALID_TEXT})

    def test_texts_match_obligations(self) -> None:
        self.written()
        view = self.p.store().load()
        expected = obligations.stop_message(obligations.evaluate(view, {})).text
        self.assertEqual(self.blocked(), expected)


class ShimFallbackTests(StopCase):
    def run_shim(self, event: Any) -> subprocess.CompletedProcess[bytes]:
        p = self.p
        data = event if isinstance(event, bytes) else json.dumps(event).encode()
        env = dict(child_env(str(p.project)), HOME=str(p.home))
        return subprocess.run(
            [sys.executable, p.closeout_entry], input=data, cwd=str(p.project),
            env=env, capture_output=True, timeout=60, check=False,
        )  # fmt: skip

    def test_broken_package_blocks_unless_exact_escape(self) -> None:
        """real subprocess: the generated closeout.py with a broken pinned package."""
        self.p.install(broken=True)
        proc = self.run_shim(stop_event(True))
        self.assertEqual((proc.returncode, proc.stdout), (0, b""))
        for event in (stop_event(False), stop_event("true"), b"{broken"):
            with self.subTest(event=event):
                proc = self.run_shim(event)
                self.assertEqual(proc.returncode, 0)
                out = json.loads(proc.stdout.decode())
                self.assertEqual(out["decision"], "block")
                self.assertIn("closeout could not start", out["reason"])

    def test_installed_shim_runs_the_real_hook(self) -> None:
        """real subprocess: the generated closeout.py with the pinned package."""
        self.p.install()
        self.written(outcome=None)
        proc = self.run_shim(stop_event(False))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.decode())
        self.assertIn("never returned a result", out["reason"])


if __name__ == "__main__":
    unittest.main()
