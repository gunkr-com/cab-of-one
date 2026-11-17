"""S6 self-audit (E7): sessions outside the harness and sessions where hooks did not run.

Everything lives under <repo>/.local/test-tmp: a fixture transcripts root (passed as
``projects_root``), fixture project folders (the registry) and their ledgers, written with
the real S4 ``Ledger``. The user's real transcripts, HOME and registry are never read.
The SessionStart event name below is a fixture value; S5 supplies the real one.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import selfaudit  # noqa: E402
from cab_of_one.runtime.ledger import Ledger  # noqa: E402
from cab_of_one.runtime.paths import Roots  # noqa: E402
from cab_of_one.runtime.selfaudit import (  # noqa: E402
    CATEGORY_HOOKS_MISSING,
    CATEGORY_INDETERMINATE,
    CATEGORY_OUTSIDE,
    SessionEvidence,
    audit_projects,
    ledger_metrics,
    load_session_evidence,
)

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC).timestamp()
HOUR = 3600.0
DAY = 86400.0
START = ("session_start",)  # fixture SessionStart event name (S5 owns the real one)
POLICY = {"classifier": {"trusted_simtenant_scripts": ["simtenant/simtenant.py"]}}
SIM = "python3 simtenant/simtenant.py --state tenant/state.json"
WRITE = f"{SIM} delete users u-1007"
READ = f"{SIM} get users u-1007"
SECRET = "ContosoSENTINELsecret0042"


def sid(n: int) -> str:
    return f"0b6c1d2e-2222-4a4a-9b9b-{n:012d}"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def call_record(session: str, cwd: str, tid: str, name: str, inp: object, ts: float, **extra):
    rec = {
        "type": "assistant",
        "sessionId": session,
        "cwd": cwd,
        "timestamp": iso(ts),
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": tid, "name": name, "input": inp}],
        },
    }
    rec.update(extra)
    return rec


def bash(session: str, cwd: str, tid: str, command: str, ts: float = NOW - HOUR, **extra):
    return call_record(session, cwd, tid, "Bash", {"command": command}, ts, **extra)


def jsonl(records) -> bytes:
    return b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in records)


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="selfaudit-", dir=TMP_ROOT)).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "claude-projects"
        self.root.mkdir()
        self.project = self.tmp / "contoso-ops"
        self.project.mkdir()
        self.scratch = self.tmp / "scratch"
        self.scratch.mkdir()
        self.home = self.tmp / "home"
        self.home.mkdir()

    # transcripts ---------------------------------------------------------
    def transcript(self, session: str, records, *, agent: str | None = None,
                   mtime: float = NOW - HOUR, folder: str = "-fixture") -> Path:  # fmt: skip
        if agent is None:
            path = self.root / folder / f"{session}.jsonl"
        else:
            path = self.root / folder / session / "subagents" / f"agent-{agent}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(jsonl(records))
        os.utime(path, (mtime, mtime))
        return path

    # ledger ---------------------------------------------------------------
    def ledger(self, *starts: str, clock: float = NOW - 2 * HOUR) -> Ledger:
        roots = Roots(str(self.project), str(self.home / ".local" / "state" / "cab-of-one"))
        led = Ledger(roots, clock=lambda: clock)
        for s in starts:
            led.append("session_start", session_id=s)
        return led

    def evidence(self) -> dict[str, SessionEvidence]:
        return {str(self.project): load_session_evidence(str(self.project), start_events=START)}

    def audit(self, **kw):
        kw.setdefault("registry", [str(self.project)])
        kw.setdefault("evidence", self.evidence())
        kw.setdefault("policy", POLICY)
        kw.setdefault("now", NOW)
        return audit_projects(str(self.root), **kw)

    def tree(self) -> dict[str, tuple[str, int]]:
        out = {}
        for base, _dirs, files in os.walk(self.tmp):
            for name in files:
                p = os.path.join(base, name)
                st = os.lstat(p)
                with open(p, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                out[p] = (digest, st.st_mtime_ns)
        return out


class E7Tests(Fixture):
    def test_a_write_from_another_folder_is_outside_the_harness(self) -> None:
        self.ledger()
        s = sid(1)
        self.transcript(s, [
            bash(s, str(self.scratch), "toolu_a1", WRITE),
            bash(s, str(self.scratch), "toolu_a2", f"{SIM} purge users u-1008"),
        ])  # fmt: skip
        report = self.audit()
        self.assertEqual((report.outside, report.hooks_missing), (1, 0))
        f = report.findings[0]
        self.assertEqual((f.session_id, f.category, f.writes), (s, CATEGORY_OUTSIDE, 2))
        self.assertEqual(f.label, "outside the harness")
        self.assertEqual(f.cwds, (str(self.scratch),))
        self.assertIn("cwd_not_registered", f.reasons)
        text = "\n".join(report.lines())
        self.assertIn("outside the harness", text)
        self.assertIn(s, text)
        self.assertIn("2 writes", text)
        self.assertFalse(report.clean)

    def test_b_registered_project_without_session_start_is_hooks_did_not_run(self) -> None:
        other = sid(99)
        self.ledger(other)  # a SessionStart exists, but for another session
        s = sid(2)
        self.transcript(s, [bash(s, str(self.project), "toolu_b1", WRITE)])
        report = self.audit()
        self.assertEqual((report.hooks_missing, report.outside), (1, 0))
        f = report.findings[0]
        self.assertEqual((f.session_id, f.category, f.writes), (s, CATEGORY_HOOKS_MISSING, 1))
        self.assertEqual(f.label, "hooks did not run")
        self.assertEqual(f.projects, (str(self.project),))
        self.assertIn("no_session_start", f.reasons)
        self.assertIn("hooks did not run", "\n".join(report.lines()))

    def test_no_ledger_at_all_is_measured_absence(self) -> None:
        s = sid(3)
        self.transcript(s, [bash(s, str(self.project), "toolu_c1", WRITE)])
        report = self.audit()
        self.assertEqual(report.hooks_missing, 1)
        self.assertEqual(report.status, "ok")

    def test_session_with_session_start_is_inside(self) -> None:
        s = sid(4)
        self.ledger(s)
        self.transcript(s, [bash(s, str(self.project), "toolu_d1", WRITE)])
        report = self.audit()
        self.assertEqual((report.sessions, report.with_admin_writes, report.inside), (1, 1, 1))
        self.assertEqual(report.findings, ())
        self.assertTrue(report.clean)
        self.assertEqual(report.status, "ok")
        self.assertIn("1 inside the harness", report.summary())

    def test_reads_and_not_admin_calls_are_not_admin_writes(self) -> None:
        s = sid(5)
        self.transcript(s, [
            bash(s, str(self.scratch), "toolu_e1", READ),
            bash(s, str(self.project), "toolu_e2", READ),
            bash(s, str(self.scratch), "toolu_e3", "ls -la"),
            call_record(s, str(self.scratch), "toolu_e4", "Read", {"file_path": "/x"},
                        NOW - HOUR),
        ])  # fmt: skip
        report = self.audit()
        # Outside a registered root a relative trusted script is not trusted (Policy.s3_for),
        # so the first call is unknown-admin there; the project-root read and the rest are not.
        self.assertEqual(report.outside, 1)
        self.assertEqual(report.findings[0].writes, 1)
        self.assertEqual(report.findings[0].write_codes, {"write_unknown_bash": 1})

    def test_only_reads_inside_is_a_session_without_admin_writes(self) -> None:
        s = sid(6)
        self.transcript(s, [bash(s, str(self.project), "toolu_f1", READ)])
        report = self.audit()
        self.assertEqual((report.sessions, report.with_admin_writes), (1, 0))
        self.assertEqual(report.findings, ())

    def test_subfolder_of_a_registered_project_is_outside(self) -> None:
        sub = self.project / "scripts"
        sub.mkdir()
        s = sid(7)
        self.ledger(s)
        self.transcript(s, [bash(s, str(sub), "toolu_g1", WRITE)])
        report = self.audit()
        self.assertEqual(report.outside, 1)
        self.assertIn("cwd_under_registered", report.findings[0].reasons)

    def test_subagent_transcript_writes_are_found_and_deduplicated(self) -> None:
        s = sid(8)
        self.ledger()
        rec = bash(s, str(self.scratch), "toolu_h1", WRITE, agentId="a12", isSidechain=True)
        self.transcript(s, [rec])  # older layout: sidechain copy in the main file
        self.transcript(s, [rec], agent="a12")
        report = self.audit()
        f = report.findings[0]
        self.assertEqual((f.category, f.writes, f.subagent_writes), (CATEGORY_OUTSIDE, 1, 1))
        self.assertEqual(report.counts.get("duplicate_across_files"), 1)

    def test_scripts_named_by_transcripts_are_never_opened(self) -> None:
        # The script exists and is harmless; reading it would make the call not-admin.
        (self.scratch / "tidy.sh").write_text("echo tidy\n")
        s = sid(9)
        self.transcript(s, [bash(s, str(self.scratch), "toolu_i1", "bash tidy.sh")])
        report = self.audit()
        self.assertEqual(report.outside, 1)
        self.assertEqual(report.findings[0].write_codes, {"write_unknown_bash": 1})

    def test_unlisted_built_in_tools_count_conservatively_and_are_labelled(self) -> None:
        s = sid(10)
        self.transcript(s, [call_record(s, str(self.scratch), "toolu_j1", "TodoWrite",
                                        {"todos": []}, NOW - HOUR)])  # fmt: skip
        report = self.audit()
        self.assertEqual(report.findings[0].write_codes, {"write_unlisted_tool": 1})
        self.assertEqual(report.findings[0].tools, {"TodoWrite": 1})
        listed = {"classifier": {"not_admin_tools": [
            "Read", "Grep", "Glob", "Write", "Edit", "AskUserQuestion", "TodoWrite"]}}  # fmt: skip
        report = self.audit(policy=listed)
        self.assertEqual((report.with_admin_writes, report.findings), (0, ()))

    def test_reports_never_contain_commands_inputs_or_secrets(self) -> None:
        s = sid(11)
        command = f"{WRITE} --password {SECRET}"
        self.transcript(s, [
            bash(s, str(self.scratch), "toolu_k1", command),
            call_record(s, str(self.scratch), "toolu_k2", "mcp__contoso__set_user",
                        {"client_secret": SECRET}, NOW - HOUR),
        ])  # fmt: skip
        report = self.audit()
        blob = json.dumps(report.to_dict()) + "\n".join(report.lines())
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("simtenant", blob)
        self.assertNotIn("delete", blob)
        self.assertEqual(report.findings[0].write_codes,
                         {"write_unknown_bash": 1, "write_mcp": 1})  # fmt: skip

    def test_audit_is_read_only(self) -> None:
        s = sid(12)
        self.ledger(s)
        self.transcript(s, [bash(s, str(self.project), "toolu_l1", WRITE)])
        evidence = self.evidence()
        before = self.tree()
        self.audit(evidence=evidence)
        ledger_metrics(str(self.project), now=NOW)
        self.assertEqual(self.tree(), before)


class IndeterminateTests(Fixture):
    def test_registered_project_without_supplied_evidence_is_not_inside(self) -> None:
        s = sid(20)
        self.transcript(s, [bash(s, str(self.project), "toolu_m1", WRITE)])
        report = self.audit(evidence={})
        self.assertEqual(report.indeterminate, 1)
        self.assertEqual(report.findings[0].category, CATEGORY_INDETERMINATE)
        self.assertIn("evidence_not_supplied", report.findings[0].reasons)
        self.assertEqual(report.status, "indeterminate")

    def test_damaged_ledger_cannot_prove_absence_but_valid_rows_prove_presence(self) -> None:
        s_seen, s_unseen = sid(21), sid(22)
        self.ledger(s_seen)
        ledger_file = next((self.project / "audit" / "ledger").glob("*.jsonl"))
        with open(ledger_file, "ab") as fh:
            fh.write(b'{"v":1,"event":"session_st')  # truncated tail
        ev = load_session_evidence(str(self.project), start_events=START)
        self.assertEqual(ev.status, "indeterminate")
        self.assertIn("ledger_truncated", ev.reasons)
        self.transcript(s_seen, [bash(s_seen, str(self.project), "toolu_n1", WRITE)])
        self.transcript(s_unseen, [bash(s_unseen, str(self.project), "toolu_n2", WRITE)])
        report = self.audit(evidence={str(self.project): ev})
        self.assertEqual((report.inside, report.indeterminate, report.hooks_missing), (1, 1, 0))
        self.assertIn("evidence_indeterminate", report.findings[0].reasons)

    def test_damaged_transcript_without_writes_is_indeterminate_not_clean(self) -> None:
        s = sid(23)
        path = self.transcript(s, [bash(s, str(self.scratch), "toolu_o1", "ls")])
        with open(path, "ab") as fh:
            fh.write(b'{"type": "assistant", "message": {"content": [')
        os.utime(path, (NOW - HOUR, NOW - HOUR))
        report = self.audit()
        self.assertEqual(report.indeterminate, 1)
        self.assertIn("truncated_line", report.findings[0].reasons)
        self.assertEqual(report.status, "indeterminate")
        self.assertFalse(report.clean)

    def test_write_without_any_cwd_is_indeterminate(self) -> None:
        s = sid(24)
        rec = bash(s, str(self.scratch), "toolu_p1", WRITE)
        del rec["cwd"]
        self.transcript(s, [rec])
        report = self.audit()
        self.assertEqual(report.indeterminate, 1)
        self.assertIn("write_cwd_unknown", report.findings[0].reasons)

    def test_unusable_policy_is_an_error_not_a_flood_of_writes(self) -> None:
        report = self.audit(policy={"adapters": {"enabled": ["no-such-adapter"]}})
        self.assertEqual((report.status, report.error), ("error", "policy_unusable"))

    def test_bad_root_and_arguments_are_errors(self) -> None:
        self.assertEqual(audit_projects(str(self.tmp / "nope"), registry=[], evidence={},
                                        now=NOW).error, "root_missing")  # fmt: skip
        self.assertEqual(self.audit(days=0).error, "days_invalid")
        self.assertEqual(self.audit(now=float("nan")).error, "now_invalid")
        report = self.audit(registry=["relative/path", str(self.project)])
        self.assertEqual(report.counts.get("registry_entry_invalid"), 1)

    def test_symlinked_transcript_makes_the_scan_incomplete(self) -> None:
        target = self.tmp / "elsewhere.jsonl"
        target.write_bytes(jsonl([bash(sid(25), str(self.scratch), "toolu_q1", WRITE)]))
        folder = self.root / "-fixture"
        folder.mkdir()
        try:
            os.symlink(target, folder / f"{sid(25)}.jsonl")
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")
        report = self.audit()
        self.assertEqual(report.sessions, 0)
        self.assertEqual(report.status, "indeterminate")
        self.assertEqual(report.counts.get("symlink_skipped"), 1)


class WindowTests(Fixture):
    def test_old_files_and_old_sessions_are_outside_the_window(self) -> None:
        old, recent_file_old_records, fresh = sid(30), sid(31), sid(32)
        self.transcript(old, [bash(old, str(self.scratch), "toolu_r1", WRITE, NOW - 30 * DAY)],
                        mtime=NOW - 30 * DAY)  # fmt: skip
        self.transcript(recent_file_old_records,
                        [bash(recent_file_old_records, str(self.scratch), "toolu_r2", WRITE,
                              NOW - 20 * DAY)], mtime=NOW - HOUR)  # fmt: skip
        self.transcript(fresh, [bash(fresh, str(self.scratch), "toolu_r3", WRITE)])
        report = self.audit(days=14)
        self.assertEqual(report.sessions, 1)
        self.assertEqual(report.findings[0].session_id, fresh)
        self.assertEqual(report.counts.get("files_before_window"), 1)
        self.assertEqual(report.counts.get("sessions_before_window"), 1)
        self.assertTrue(report.summary().startswith("14d: 1 sessions"))
        wide = self.audit(days=60)
        self.assertEqual(wide.sessions, 3)


class EvidenceAndMetricsTests(Fixture):
    def test_start_events_are_required(self) -> None:
        self.ledger(sid(40))
        for bad in ((), ("bad event!",), None):
            with self.subTest(bad=bad):
                ev = load_session_evidence(str(self.project), start_events=bad)
                self.assertEqual(ev.status, "indeterminate")
                self.assertEqual(ev.reasons, ("start_events_invalid",))
        ev = load_session_evidence(str(self.project), start_events=START)
        self.assertEqual((ev.status, ev.session_ids), ("ok", frozenset({sid(40)})))

    def test_symlinked_ledger_folder_is_not_evidence(self) -> None:
        real = self.tmp / "real-ledger"
        real.mkdir()
        (self.project / "audit").mkdir()
        try:
            os.symlink(real, self.project / "audit" / "ledger")
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")
        ev = load_session_evidence(str(self.project), start_events=START)
        self.assertEqual((ev.status, ev.reasons), ("indeterminate", ("ledger_dir_unsafe",)))

    def test_metrics_are_minimal_counts_from_valid_rows(self) -> None:
        led = self.ledger(sid(41))
        led.append("pre", session_id=sid(41), decision="deny", reason_code="no_open_change",
                   tool="Bash", command=f"{WRITE} --password {SECRET}")  # fmt: skip
        led.append("pre", session_id=sid(41), decision="allow", reason_code="read", tool="Bash")
        led.append("settle", change_id="CHG-0001", tool_use_id="toolu_x", outcome="ok")
        m = ledger_metrics(str(self.project), now=NOW)
        self.assertEqual(m.status, "ok")
        self.assertEqual(m.rows, 4)
        self.assertEqual(m.events, {"session_start": 1, "pre": 2, "settle": 1})
        self.assertEqual(m.pre_decisions, {"deny": 1, "allow": 1})
        self.assertEqual(m.deny_reasons, {"no_open_change": 1})
        self.assertEqual(m.settle_outcomes, {"ok": 1})
        self.assertEqual(m.chain, "not_implemented")
        self.assertNotIn(SECRET, json.dumps(m.to_dict()))
        self.assertEqual(ledger_metrics(str(self.project), now=NOW + 30 * DAY).rows, 0)

    def test_metrics_report_damage(self) -> None:
        self.ledger(sid(42))
        ledger_file = next((self.project / "audit" / "ledger").glob("*.jsonl"))
        with open(ledger_file, "ab") as fh:
            fh.write(b"{broken}\n")
        m = ledger_metrics(str(self.project), now=NOW)
        self.assertEqual(m.status, "indeterminate")
        self.assertEqual(m.problems.get("ledger_malformed"), 1)
        self.assertEqual(ledger_metrics(str(self.project), days=0).error, "days_invalid")

    def test_labels_cover_every_category(self) -> None:
        for cat in (selfaudit.CATEGORY_NO_WRITES, selfaudit.CATEGORY_INSIDE, CATEGORY_OUTSIDE,
                    CATEGORY_HOOKS_MISSING, CATEGORY_INDETERMINATE):  # fmt: skip
            self.assertIn(cat, selfaudit.LABELS)


if __name__ == "__main__":
    unittest.main()
