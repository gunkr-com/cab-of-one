"""S5 C-main: the ``cab`` runtime CLI over the real Store (A) and runners (B).

Fixture: ``test_guard.Project`` (A's shared fixture) under <repo>/.local/test-tmp, with a
fixture home; HOME is never read or set and the real approval registry is never touched.
All data is fictional Contoso data. Approvals created through the Store directly are
fixture data, not human authorisation; the TTY cases use injected fake terminals and
never touch the real terminal.

Execution labels (S5_CONTRACT_ACCEPTANCE item 3):
- "real subprocess + SimClock": probes run the real simtenant script through B's
  ``SubprocessRunner``; ``SimClock`` only replaces retry sleeps (time-independent cases).
- "Store only": no process is started.

    python3 -m unittest discover -s tests -p test_cli.py
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import types
import unittest
from collections.abc import Mapping, Sequence
from typing import Any
from unittest import mock

from cab_of_one.runtime import audithook, cli, closeout, config_lock, probes, terminal
from cab_of_one.runtime.probes import SubprocessRunner
from cab_of_one.setup import manifest as setup_manifest
from test_guard import (
    APPROVER,
    CHANGE_ID,
    ROOT,
    SIMTENANT_SCRIPT,
    SLUG,
    TENANT,
    Project,
    child_env,
    leaks,
    read_argv,
    sim,
    toml_str,
)

HOOKS = ROOT / "templates" / "core" / "hooks"
TARGET = "users/u-1007"
BASH_OK = {
    "stdout": "",
    "stderr": "",
    "interrupted": False,
    "isImage": False,
    "noOutputExpected": False,
}
INTAKE_TOML = """\
purpose = "Fictional Contoso fixture change"
in_scope = "users/u-1007 (fixture list)"
out_of_scope = "every other fictional user"
timing = "any time"
known_dependents = "none known"
success_criteria = "department reads the planned value"
"""


class SimClock:
    """Probe clock: epoch ``now`` aligned with the Store's FakeClock; sleeps are recorded,
    not slept (no elapsed-time claim)."""

    def __init__(self, epoch: float) -> None:
        self.epoch = epoch
        self.t = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.epoch + self.t

    def monotonic(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


class FakeTTY(io.StringIO):
    """A stream that claims to be a terminal (paired with an injected TerminalOS)."""

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


def tty_os(uid: int = 501, euid: int = 501) -> terminal.TerminalOS:
    return terminal.TerminalOS(
        isatty=lambda fd: True,
        getuid=lambda: uid,
        geteuid=lambda: euid,
        username=lambda u: APPROVER["os_user"],
    )


def verify_block(target: str, value: str) -> str:
    argv = read_argv(target)
    return (
        "\n".join(
            [
                "",
                "[[verify]]",
                f"target = {toml_str(target)}",
                "argv = [" + ", ".join(toml_str(a) for a in argv) + "]",
                'expect = "active"',
                "",
                "[[verify.check]]",
                'pointer = "/object/department"',
                'op = "eq"',
                f"value_json = {toml_str(json.dumps(value))}",
            ]
        )
        + "\n"
    )


def set_value(obj_id: str, value: str, *extra: str) -> str:
    return sim(
        f"set users {obj_id} --field department --value {value}" + "".join(" " + e for e in extra)
    )


class CabProject(Project):
    """Project plus the pinned cab/audit/closeout entries and [[verify]] probes."""

    def __init__(self, case: unittest.TestCase, **kw: Any) -> None:
        super().__init__(case, **kw)
        for name in ("cab", "audit.py", "closeout.py"):
            shutil.copyfile(HOOKS / name, self.entry.parent / name)
        self.cab_entry = str(self.entry.parent / "cab")
        self.audit_entry = str(self.entry.parent / "audit.py")
        self.closeout_entry = str(self.entry.parent / "closeout.py")
        self.values: dict[str, str] = {}
        self.probe_clock = SimClock(self.clock.now)
        self.env = {"CLAUDE_PROJECT_DIR": str(self.project)}

    def write_plan(self, tier: str, steps: Sequence[Mapping[str, Any]] = (), tenant: str = TENANT):
        super().write_plan(tier, steps, tenant)
        rel = f"{self.change_rel}/change.toml"
        text = self.read(rel).decode("utf-8")
        text += "".join(verify_block(t, self.values.get(t, "Sales")) for t in self.targets)
        self.write(rel, text)

    # ------------------------------------------------------------ CLI

    def deps(self, **kw: Any) -> cli.Deps:
        base = {
            "clock": self.clock,
            "probe_clock": self.probe_clock,
            "runner": SubprocessRunner(),
            "git_lookup": lambda project: APPROVER["git_user"],
            "cwd": lambda: str(self.project),
        }
        base.update(kw)
        return cli.Deps(**base)

    def cab(
        self,
        *argv: str,
        stdin: Any = None,
        stdout: Any = None,
        env: Mapping[str, str] | None = None,
        entry: str | None = None,
        **deps: Any,
    ) -> tuple[int, str, str]:
        out = stdout if stdout is not None else io.StringIO()
        err = io.StringIO()
        code = cli.main(
            list(argv),
            entry=entry or self.cab_entry,
            env={} if env is None else env,
            home=str(self.home),
            stdin=stdin if stdin is not None else io.StringIO(""),
            stdout=out,
            stderr=err,
            deps=self.deps(**deps),
        )
        return code, out.getvalue(), err.getvalue()

    # ------------------------------------------------------------ hooks

    def audit(self, mode: str, event: Any, **kw: Any) -> tuple[int, str]:
        out = io.StringIO()
        text = event if isinstance(event, str) else json.dumps(event)
        code = audithook.main(
            self.audit_entry, mode, stdin=io.StringIO(text), stdout=out, env=self.env,
            home=str(self.home), clock=self.clock, **kw,
        )  # fmt: skip
        return code, out.getvalue()

    def stop(self, event: Any = None, **kw: Any) -> tuple[int, dict[str, Any] | None]:
        if event is None:
            event = {"hook_event_name": "Stop", "session_id": "sess-main-01",
                     "stop_hook_active": False}  # fmt: skip
        out = io.StringIO()
        text = event if isinstance(event, str) else json.dumps(event)
        code = closeout.main(
            self.closeout_entry, stdin=io.StringIO(text), stdout=out,
            env=kw.pop("env", self.env), home=str(self.home), clock=self.clock, **kw,
        )  # fmt: skip
        value = out.getvalue()
        lines = value.splitlines()
        assert len(lines) <= 1, "Stop prints at most one JSON line"
        return code, (json.loads(lines[0]) if lines else None)

    def post(self, pre: Mapping[str, Any], response: Any = None, **changes: Any) -> dict:
        ev = {k: v for k, v in pre.items() if k != "hook_event_name"}
        ev["hook_event_name"] = "PostToolUse"
        ev["tool_response"] = dict(BASH_OK) if response is None else response
        ev.update(changes)
        return ev

    def failure(self, pre: Mapping[str, Any], error: Any = "Exit code 7", **changes: Any) -> dict:
        ev = {k: v for k, v in pre.items() if k != "hook_event_name"}
        ev.update(hook_event_name="PostToolUseFailure", error=error, is_interrupt=False)
        ev.update(changes)
        return ev

    def run_write(self, command_args: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        """real subprocess: the tenant write itself (bounded)."""
        return subprocess.run(
            [sys.executable, "-I", str(self.project / "simtenant" / "simtenant.py"),
             "--state", TENANT, *command_args],
            cwd=str(self.project), capture_output=True, timeout=60, check=False,
        )  # fmt: skip

    def guarded_write(self, command: str, args: Sequence[str]) -> dict[str, Any]:
        """Pre (real guard) -> real write -> Post (real audit hook). Returns the Pre event."""
        ev = self.bash(command)
        decision = self.decide(ev)
        self.case.assertTrue(decision.allowed, decision.reason)
        proc = self.run_write(args)
        self.case.assertEqual(proc.returncode, 0)
        response = dict(BASH_OK, stdout=proc.stdout.decode("utf-8"))
        code, out = self.audit("post", self.post(ev, response))
        self.case.assertEqual((code, out), (0, ""))
        return ev

    def rows(self, event: str) -> list[dict[str, Any]]:
        return [r for r in self.ledger_rows() if r.get("event") == event]


class CliCase(unittest.TestCase):
    def setUp(self) -> None:
        self.p = CabProject(self)
        self.p.targets = (TARGET,)


# --------------------------------------------------------------------------- roots and usage


class RootsAndUsageTests(CliCase):
    def test_entry_not_installed_exits_3(self) -> None:
        code, out, err = self.p.cab("status", entry=str(SIMTENANT_SCRIPT))
        self.assertEqual((code, out), (cli.EXIT_REFUSED, ""))
        self.assertIn("cab: roots:", err)

    def test_project_dir_must_match_only_when_set(self) -> None:
        self.assertEqual(self.p.cab("status")[0], 0)  # a person's terminal: no variable
        self.assertEqual(self.p.cab("status", env=self.p.env)[0], 0)
        code, _, err = self.p.cab("status", env={"CLAUDE_PROJECT_DIR": str(self.p.home)})
        self.assertEqual(code, cli.EXIT_REFUSED)
        self.assertIn("roots", err)

    def test_usage_errors_never_echo_input(self) -> None:
        secret = "CliDashSENTINELw5"
        for argv in ([], ["bogus", secret], ["close", secret], ["new", "CHG-1", secret]):
            code, out, err = self.p.cab(*argv)
            self.assertEqual(code, cli.EXIT_USAGE, argv)
            self.assertNotIn(secret, out + err)
            self.assertNotIn("Traceback", err)

    def test_setup_is_not_part_of_the_installed_runtime(self) -> None:
        code, _, err = self.p.cab("setup", "apply")
        self.assertEqual(code, cli.EXIT_REFUSED)
        self.assertIn("setup_unavailable", err)

    def test_source_setup_dispatch_is_lazy(self) -> None:
        err = io.StringIO()
        missing = ModuleNotFoundError("fixture", name="cab_of_one.setup.cli")
        with mock.patch.object(importlib, "import_module", side_effect=missing):
            code = cli.source_main(["setup", "x"], source_root="/src", entry="/x", stderr=err)
        self.assertEqual(code, cli.EXIT_REFUSED)
        self.assertIn("setup_unavailable", err.getvalue())
        calls: list[Any] = []
        fake = types.SimpleNamespace(main=lambda argv, source_root: calls.append(
            (argv, source_root)) or 7)  # fmt: skip
        with mock.patch.object(importlib, "import_module", return_value=fake):
            code = cli.source_main(["setup", "plan"], source_root="/src", entry="/x")
        self.assertEqual((code, calls), (7, [(["plan"], "/src")]))

    def test_internal_errors_are_fixed_codes(self) -> None:
        def boom(*a: Any, **k: Any) -> Any:
            raise RuntimeError("SecretSENTINELboom")

        code, _, err = self.p.cab("status", resolve=boom)
        self.assertEqual(code, cli.EXIT_REFUSED)
        broken = mock.Mock(side_effect=RuntimeError("SecretSENTINELx"))
        with mock.patch.dict(cli.COMMANDS, {"status": broken}):
            code, _, err = self.p.cab("status")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertNotIn("SENTINEL", err)
        self.assertNotIn("Traceback", err)


# --------------------------------------------------------------------------- planning


class PlanningTests(CliCase):
    def open_change(self, tier: str = "normal") -> None:
        p = self.p
        self.assertEqual(p.cab("new", CHANGE_ID, SLUG)[0], 0)
        p.write_plan(tier)
        p.write("work/intake.toml", INTAKE_TOML)

    def test_new_intake_plan_check_snapshot(self) -> None:
        """real subprocess + SimClock for the snapshot probe."""
        p = self.p
        self.open_change()
        code, out, _ = p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")
        self.assertEqual(code, 0)
        self.assertIn("source=fixture", out)
        intake = (p.folder / "intake.md").read_text()
        self.assertIn("- Source: fixture (not answers given by a person)", intake)
        rows = p.rows("intake")
        self.assertEqual([(r["source"], r["change_id"]) for r in rows], [("fixture", CHANGE_ID)])
        code, out, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual(code, 0, err)
        self.assertIn("fixture 1", out)
        doc = p.doc()
        self.assertEqual((doc["state"], doc["tier"]), ("planned", "normal"))
        p.plan_hash = doc["plan_hash"]
        code, out, err = p.cab("snapshot", CHANGE_ID)
        self.assertEqual(code, 0, out + err)
        self.assertIn("snapshot complete", out)
        data = (p.folder / "snapshot.json").read_bytes()
        snap = json.loads(data)
        self.assertEqual(snap["targets"][TARGET]["status"], "active")
        self.assertEqual(p.doc()["snapshot_sha"], hashlib.sha256(data).hexdigest())  # real Store
        self.assertEqual(p.probe_clock.sleeps, [])
        code, out, _ = p.cab("status", CHANGE_ID)
        self.assertEqual(code, 0)
        self.assertIn("state: planned", out)

    def test_intake_refusals(self) -> None:
        p = self.p
        self.open_change()
        p.write("work/extra.toml", INTAKE_TOML + 'note = "x"\n')
        self.assertEqual(p.cab("intake", CHANGE_ID, "--from-file", "work/extra.toml")[0], 2)
        p.write("work/num.toml", INTAKE_TOML.replace('timing = "any time"', "timing = 3"))
        self.assertEqual(p.cab("intake", CHANGE_ID, "--from-file", "work/num.toml")[0], 2)
        outside = p.tmp / "outside.toml"
        outside.write_text(INTAKE_TOML)
        self.assertEqual(p.cab("intake", CHANGE_ID, "--from-file", str(outside))[0], 3)
        self.assertEqual(p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")[0], 0)
        code, _, err = p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")
        self.assertEqual(code, cli.EXIT_REFUSED)
        self.assertIn("intake_exists", err)

    def test_plan_check_refusals(self) -> None:
        p = self.p
        self.open_change()
        # no intake.md
        code, _, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "intake_missing" in err), (2, True))
        # intake.md by hand, but no interview evidence in the ledger
        p.write(f"{p.change_rel}/intake.md", "".join(f"{label} x\n" for _, label in
                                                     cli.INTAKE_FIELDS))  # fmt: skip
        code, _, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "interview_missing" in err), (2, True))
        # a broken ledger line is not evidence of anything
        p.store().ledger.append("intake", change_id=CHANGE_ID, source="fixture")
        ledger_file = p.ledger_files()[0]
        with open(ledger_file, "ab") as fh:
            fh.write(b"{broken\n")
        code, _, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "ledger_unreadable" in err), (5, True))

    def refuse_interview(self) -> None:
        """plan check refuses with interview_missing and changes no state (Store only)."""
        p = self.p
        before = p.state_bytes()
        code, out, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "interview_missing" in err), (cli.EXIT_USAGE, True), out + err)
        self.assertNotIn("planned", out)
        self.assertEqual(p.state_bytes(), before)
        doc = p.doc()
        self.assertEqual(doc["state"], "draft")
        self.assertFalse(doc["tier"])

    def test_plan_check_counts_only_completed_fixture_intake(self) -> None:
        """Questions-only, timeout, unknown, malformed and other-change rows are not
        completed interview evidence; the fixture written by cab intake is (Store only)."""
        p = self.p
        self.open_change()
        p.write(f"{p.change_rel}/intake.md", "".join(f"{label} x\n" for _, label in
                                                     cli.INTAKE_FIELDS))  # fmt: skip
        book = p.store().ledger
        rejected: list[tuple[str, dict[str, Any]]] = [
            ("askuser questions only", dict(
                session_id="sess-main-01", tool_use_id="toolu_ask01", change_id=CHANGE_ID,
                source="askuser", reason_code="answers_unmeasured", outcome="unknown",
            )),
            ("askuser timeout", dict(
                session_id="sess-main-01", change_id=CHANGE_ID, source="askuser",
                reason_code="timeout", outcome="unknown",
            )),
            ("unknown source", dict(
                change_id=CHANGE_ID, source="interview", reason_code="fixture_file",
                actor=cli.AGENT_ACTOR,
            )),
            ("no source", dict(
                change_id=CHANGE_ID, reason_code="fixture_file", actor=cli.AGENT_ACTOR,
            )),
            ("fixture without reason", dict(
                change_id=CHANGE_ID, source="fixture", actor=cli.AGENT_ACTOR,
            )),
            ("fixture by another actor", dict(
                change_id=CHANGE_ID, source="fixture", reason_code="fixture_file",
                actor="someone",
            )),
            ("fixture with an outcome", dict(
                change_id=CHANGE_ID, outcome="ok", **cli.FIXTURE_INTAKE_ROW,
            )),
            ("fixture with a tool call", dict(
                change_id=CHANGE_ID, tool_use_id="toolu_ask02", **cli.FIXTURE_INTAKE_ROW,
            )),
            ("fixture for another change", dict(
                change_id="CHG-0999", **cli.FIXTURE_INTAKE_ROW,
            )),
            ("fixture with no change", dict(**cli.FIXTURE_INTAKE_ROW)),
        ]  # fmt: skip
        self.refuse_interview()
        for label, fields in rejected:
            with self.subTest(row=label):
                book.append("intake", **fields)
                self.refuse_interview()
        # The real fixture path still passes; the rejected rows are reported, not counted.
        (p.folder / "intake.md").unlink()
        code, _, err = p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")
        self.assertEqual(code, 0, err)
        code, out, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual(code, 0, err)
        self.assertIn("interview evidence: fixture 1 (", out)
        # same change only: the other-change and no-change rows are not listed either
        self.assertIn(f"not counted: {len(rejected) - 2} other intake rows", out)
        self.assertEqual(p.doc()["state"], "planned")

    def test_completed_fixture_row_still_needs_intake_md(self) -> None:
        p = self.p
        self.open_change()
        p.store().ledger.append("intake", change_id=CHANGE_ID, **cli.FIXTURE_INTAKE_ROW)
        before = p.state_bytes()
        code, _, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "intake_missing" in err), (cli.EXIT_USAGE, True))
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(p.doc()["state"], "draft")

    def test_completed_intake_is_exact(self) -> None:
        """Row shapes the ledger API cannot write (types, versions) also fail closed."""
        row = json.loads(
            self.p.store().ledger.row("intake", change_id=CHANGE_ID, **cli.FIXTURE_INTAKE_ROW)
        )
        self.assertTrue(cli.completed_intake(row, CHANGE_ID))
        self.assertFalse(cli.completed_intake(row, "CHG-0999"))
        broken: list[tuple[str, Any]] = [
            ("v", True), ("v", 2), ("v", "1"), ("event", "post"), ("ts", 0),
            ("source", "Fixture"), ("source", None), ("source", 1),
            ("reason_code", "answers_unmeasured"), ("actor", "cab-cli "), ("change_id", None),
        ]  # fmt: skip
        for key, value in broken:
            with self.subTest(key=key, value=value):
                self.assertFalse(cli.completed_intake(dict(row, **{key: value}), CHANGE_ID))
        for key in row:
            with self.subTest(missing=key):
                self.assertFalse(
                    cli.completed_intake({k: v for k, v in row.items() if k != key}, CHANGE_ID)
                )
        self.assertFalse(cli.completed_intake(dict(row, outcome="unknown"), CHANGE_ID))
        # strict per source: the fixture row never carries the terminal file hash
        self.assertIsNone(cli.intake_row_source(dict(row, response_sha256="a" * 64), CHANGE_ID))

    def test_terminal_intake_row_is_exact(self) -> None:
        """The terminal row shape (Store only): fixed source, reason and actor, and a
        lowercase sha256; anything else, including a person-looking actor, fails closed."""
        row = json.loads(
            self.p.store().ledger.row(
                "intake", change_id=CHANGE_ID, response_sha256="a" * 64, **cli.TERMINAL_INTAKE_ROW
            )
        )
        self.assertEqual(
            {k: row[k] for k in ("source", "reason_code", "actor")},
            {"source": "terminal", "reason_code": "terminal_answers", "actor": "cab-cli-terminal"},
        )
        self.assertNotEqual(cli.TERMINAL_INTAKE_ROW["actor"], cli.FIXTURE_INTAKE_ROW["actor"])
        self.assertEqual(cli.intake_row_source(row, CHANGE_ID), "terminal")
        self.assertTrue(cli.completed_intake(row, CHANGE_ID))
        self.assertIsNone(cli.intake_row_source(row, "CHG-0999"))
        broken: list[tuple[str, Any]] = [
            ("source", "fixture"), ("source", "askuser"), ("source", "Terminal"),
            ("reason_code", "fixture_file"), ("reason_code", "answers_unmeasured"),
            ("actor", cli.AGENT_ACTOR), ("actor", "contoso-operator"), ("actor", None),
            ("response_sha256", "A" * 64), ("response_sha256", "a" * 63),
            ("response_sha256", None), ("response_sha256", 0), ("v", True), ("ts", 0),
            ("event", "post"),
        ]  # fmt: skip
        for key, value in broken:
            with self.subTest(key=key, value=value):
                self.assertIsNone(cli.intake_row_source(dict(row, **{key: value}), CHANGE_ID))
        for key in row:
            with self.subTest(missing=key):
                self.assertIsNone(
                    cli.intake_row_source({k: v for k, v in row.items() if k != key}, CHANGE_ID)
                )
        for extra in ({"outcome": "ok"}, {"tool_use_id": "toolu_x1"}, {"session_id": "sess-1"}):
            with self.subTest(extra=extra):
                self.assertIsNone(cli.intake_row_source(dict(row, **extra), CHANGE_ID))

    def test_plan_check_needs_the_row_of_the_same_source_as_intake_md(self) -> None:
        """Rows count only for an intake.md whose single Source line names the same
        source, and a terminal row only for the exact intake.md bytes (Store only)."""
        p = self.p
        self.open_change()
        body = "".join(f"{label} x\n" for _, label in cli.INTAKE_FIELDS)
        book = p.store().ledger
        rel = f"{p.change_rel}/intake.md"

        def digest(text: str) -> str:
            return hashlib.sha256(text.encode("utf-8")).hexdigest()

        terminal_md = body + cli.TERMINAL_SOURCE_LINE + "\n"
        fixture_md = body + cli.FIXTURE_SOURCE_LINE + "\n"
        # Rows accumulate. The fixture-source file comes first: fixture rows are not bound
        # to file bytes (the unchanged fixture route), so it must not meet a fixture row.
        cases = [
            ("fixture file, terminal row with its hash", fixture_md,
             dict(cli.TERMINAL_INTAKE_ROW, response_sha256=digest(fixture_md))),
            ("terminal file, fixture row", terminal_md, dict(cli.FIXTURE_INTAKE_ROW)),
            ("terminal file, terminal row for other bytes", terminal_md,
             dict(cli.TERMINAL_INTAKE_ROW, response_sha256=digest(terminal_md + "x"))),
            ("two source lines", terminal_md + cli.FIXTURE_SOURCE_LINE + "\n",
             dict(cli.FIXTURE_INTAKE_ROW)),
            ("edited source line", body + cli.TERMINAL_SOURCE_LINE + " (edited)\n",
             dict(cli.TERMINAL_INTAKE_ROW,
                  response_sha256=digest(body + cli.TERMINAL_SOURCE_LINE + " (edited)\n"))),
        ]  # fmt: skip
        for label, text, fields in cases:
            with self.subTest(case=label):
                p.write(rel, text)
                book.append("intake", change_id=CHANGE_ID, **fields)
                self.refuse_interview()

    def test_plan_check_requires_one_read_probe_per_target(self) -> None:
        p = self.p
        self.open_change()
        p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")
        rel = f"{p.change_rel}/change.toml"
        original = p.read(rel)
        # no [[verify]] at all
        p.write(rel, original.split(b"\n[[verify]]")[0] + b"\n")
        code, _, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "verify_missing" in err), (2, True))
        # a write disguised as the probe
        write_probe = original.replace(b'"get", "users", "u-1007"', b'"purge", "users", "u-1007"')
        self.assertNotEqual(write_probe, original)
        p.write(rel, write_probe)
        code, out, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual((code, "probe_invalid" in err), (2, True))
        self.assertEqual(p.doc()["state"], "draft")

    def test_plan_check_warns_on_unsupported_runner(self) -> None:
        p = self.p
        self.open_change()
        p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")
        unsupported = probes.Unmeasured("runner_unsupported", "pwsh -Command Get-X", ())
        with mock.patch.object(probes, "validate", return_value=unsupported):
            code, out, _ = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual(code, 0)
        self.assertIn("writes will be refused at snapshot", out)

    def test_tier_is_read_only(self) -> None:
        p = self.p
        self.open_change("critical")
        before = p.state_bytes()
        code, out, _ = p.cab("tier", CHANGE_ID)
        self.assertEqual(code, 0)
        self.assertIn("computed tier critical", out)
        self.assertEqual(p.state_bytes(), before)


# --------------------------------------------------------------------------- person-only commands


class HumanTests(CliCase):
    def reviewed(self) -> None:
        self.p.prepare("normal", targets=(TARGET,), approve=False)

    def test_not_a_tty_refuses_before_the_summary(self) -> None:
        self.reviewed()
        p = self.p
        before = p.state_bytes()
        code, out, err = p.cab("approve", CHANGE_ID, stdin=io.StringIO(CHANGE_ID + "\n"))
        self.assertEqual((code, out), (3, ""))
        # one line, fixed code and fixed text, like every other CLI error
        self.assertEqual(err, f"cab: not_a_tty: {terminal.MESSAGES['not_a_tty']}\n")
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(p.doc()["state"], "reviewed")

    def test_tty_matrix(self) -> None:
        self.reviewed()
        p = self.p
        before = p.state_bytes()
        cases = (
            ("uid differs", tty_os(501, 0), CHANGE_ID + "\n", 3, "uid_mismatch"),
            ("wrong id", tty_os(), "CHG-0002\n", 1, "mismatch"),
            ("crlf", tty_os(), CHANGE_ID + "\r\n", 1, "mismatch"),
            ("no newline", tty_os(), CHANGE_ID, 1, "mismatch"),
            ("too long", tty_os(), CHANGE_ID + "x" * 80 + "\n", 1, "mismatch"),
        )
        for label, osx, typed, expected, refusal in cases:
            with self.subTest(label):
                code, _, err = p.cab("approve", CHANGE_ID, stdin=FakeTTY(typed),
                                     stdout=FakeTTY(), terminal_os=osx)  # fmt: skip
                self.assertEqual(code, expected)
                self.assertEqual(err, f"cab: {refusal}: {terminal.MESSAGES[refusal]}\n")
                self.assertNotIn("x" * 80, err)  # typed input is never echoed
                self.assertEqual(p.state_bytes(), before)

    def test_approve_confirmed_commits_with_cas(self) -> None:
        self.reviewed()
        p = self.p
        out = FakeTTY()
        code, _, err = p.cab("approve", CHANGE_ID, stdin=FakeTTY(CHANGE_ID + "\n"), stdout=out,
                             terminal_os=tty_os())  # fmt: skip
        self.assertEqual(code, 0, err)
        self.assertIn("snapshot complete at", out.getvalue())
        self.assertEqual(p.doc()["state"], "approved")
        nonce = p.doc()["approval_nonce"]
        self.assertNotIn(nonce, out.getvalue())

    def test_approve_stale_summary_is_conflict(self) -> None:
        self.reviewed()
        p = self.p

        def meanwhile(project: str) -> str:
            p.snapshot()  # a fresh snapshot changes seq and clears the review
            return APPROVER["git_user"]

        code, _, _ = p.cab(
            "approve",
            CHANGE_ID,
            stdin=FakeTTY(CHANGE_ID + "\n"),
            stdout=FakeTTY(),
            terminal_os=tty_os(),
            git_lookup=meanwhile,
        )
        self.assertEqual(code, cli.EXIT_CONFLICT)
        self.assertEqual(p.doc()["state"], "planned")

    def test_resume_with_stale_seq_is_conflict_and_fresh_resume_works(self) -> None:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        ev = p.bash(set_value("u-1007", "Sales"))
        self.assertTrue(p.decide(ev).allowed)
        p.settle(ev, "failed")
        self.assertEqual(p.doc()["state"], "halted")

        def meanwhile(project: str) -> str:
            p.verify(1, "FAIL")  # seq moves on while the person reads the summary
            return ""

        code, _, _ = p.cab(
            "resume",
            CHANGE_ID,
            stdin=FakeTTY(CHANGE_ID + "\n"),
            stdout=FakeTTY(),
            terminal_os=tty_os(),
            git_lookup=meanwhile,
        )
        self.assertEqual(code, cli.EXIT_CONFLICT)
        self.assertEqual(p.doc()["state"], "halted")
        code, _, err = p.cab("resume", CHANGE_ID, stdin=FakeTTY(CHANGE_ID + "\n"),
                             stdout=FakeTTY(), terminal_os=tty_os())  # fmt: skip
        self.assertEqual(code, 0, err)
        doc = p.doc()
        self.assertEqual(doc["state"], "executing")
        self.assertEqual(doc["units"][0]["verify"], "FAIL")  # nothing reset

    def test_resume_in_flight_needs_the_explicit_flag_and_warns(self) -> None:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        self.assertTrue(p.decide(p.bash(set_value("u-1007", "Sales"))).allowed)
        code, _, err = p.cab("resume", CHANGE_ID, stdin=FakeTTY(CHANGE_ID + "\n"),
                             stdout=FakeTTY(), terminal_os=tty_os())  # fmt: skip
        self.assertEqual((code, "inflight_needs_clear" in err), (3, True))
        out = FakeTTY()
        code, _, _ = p.cab("resume", CHANGE_ID, "--clear-inflight",
                           stdin=FakeTTY(CHANGE_ID + "\n"), stdout=out,
                           terminal_os=tty_os())  # fmt: skip
        self.assertEqual(code, 0)
        self.assertIn("make sure that old call has stopped", out.getvalue())
        unit = p.doc()["units"][0]
        self.assertEqual((unit["outcome"], unit["receipt"]["source"]), ("unknown", "resume"))


# --------------------------------------------------------------------------- close and status


class CloseStatusTests(CliCase):
    def executed(self, verdict: str | None) -> dict[str, Any]:
        p = self.p
        p.prepare("normal", targets=(TARGET,))
        ev = p.bash(set_value("u-1007", "Sales"))
        self.assertTrue(p.decide(ev).allowed)
        p.settle(ev, "ok")
        if verdict is not None:
            p.verify(1, verdict)
        return ev

    def test_close_exit_codes(self) -> None:
        for verdict, expected, state in (
            ("PASS", 0, "closed"),
            ("FAIL", 10, "failed"),
            ("UNMEASURED", 11, "open-unverified"),
        ):
            with self.subTest(verdict):
                self.p = CabProject(self)
                self.p.targets = (TARGET,)
                self.executed(verdict)
                code, out, _ = self.p.cab("close", CHANGE_ID)
                self.assertEqual(code, expected)
                self.assertEqual(self.p.change_doc()["state"], state)
                if state != "closed":
                    self.assertIn("not closed", out)

    def test_close_with_unverified_writes_is_refused(self) -> None:
        self.executed(None)
        code, _, err = self.p.cab("close", CHANGE_ID)
        self.assertEqual((code, "unverified_units" in err), (3, True))

    def test_status_shows_only_selected_fields(self) -> None:
        ev = self.executed("UNMEASURED")
        doc = self.p.doc()
        code, out, _ = self.p.cab("status")
        self.assertEqual(code, 0)
        self.assertIn("owed:", out)
        unit = doc["units"][0]
        hidden = [unit["call"]["salt"], unit["call"]["input_hmac"], doc["approval_nonce"],
                  ev["tool_use_id"]]  # fmt: skip
        for value in hidden:
            self.assertNotIn(value, out)


# --------------------------------------------------------------------------- end to end


class EndToEndTests(CliCase):
    def test_e5_lie_write_fails_and_is_never_closed(self) -> None:
        """E5: real guard, real subprocess write (--lie), real audit/Stop hooks, real
        subprocess probes with SimClock retry sleeps, real Store close."""
        p = self.p
        p.values[TARGET] = "E5Value"
        args = ("set", "users", "u-1007", "--field", "department", "--value", "E5Value", "--lie")
        command = set_value("u-1007", "E5Value", "--lie")
        p.prepare("normal", targets=(TARGET,),
                  steps=[{"id": "s1", "command": command, "targets": [TARGET]}])  # fmt: skip
        before = (p.project / TENANT).read_bytes()
        p.guarded_write(command, args[0:])
        self.assertEqual((p.project / TENANT).read_bytes(), before)  # the write lied
        unit = p.doc()["units"][0]
        self.assertEqual((unit["outcome"], unit["verify"]), ("ok", None))
        _, out = p.stop()
        self.assertEqual(out["decision"], "block")
        self.assertIn("1 writes with no verification", out["reason"])
        code, text, _ = p.cab("verify", CHANGE_ID)
        self.assertEqual(code, 10, text)
        self.assertEqual(p.probe_clock.sleeps, [2, 5, 10, 20, 40])
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "verify_failed"))
        _, out = p.stop()
        self.assertEqual(out["decision"], "block")
        self.assertIn(f".claude/hooks/cab/cab close {CHANGE_ID}", out["reason"])
        code, text, _ = p.cab("close", CHANGE_ID)
        self.assertEqual(code, 10)
        final = p.change_doc()
        self.assertEqual(final["state"], "failed")
        self.assertIsNone(p.store().load().active)
        self.assertNotIn("closed (", text)
        self.assertEqual(p.stop(), (0, None))

    def test_e11_canary_end_to_end(self) -> None:
        """E11/RD A29: real guard, real subprocess writes and probes (SimClock)."""
        p = self.p
        targets = ("users/u-1007", "users/u-1015")
        p.values = {t: "E11Value" for t in targets}
        p.prepare("critical", targets=targets)
        first = set_value("u-1007", "E11Value")
        p.guarded_write(first, ("set", "users", "u-1007", "--field", "department",
                                "--value", "E11Value"))  # fmt: skip
        second = p.bash(set_value("u-1015", "E11Value"))
        decision = p.decide(second)
        self.assertFalse(decision.allowed)
        self.assertIn("[canary_awaiting]", decision.reason)
        code, text, _ = p.cab("verify", CHANGE_ID)
        self.assertEqual(code, 0, text)
        self.assertEqual(p.doc()["canary"], "passed")
        p.guarded_write(
            set_value("u-1015", "E11Value"),
            ("set", "users", "u-1015", "--field", "department", "--value", "E11Value"),
        )
        self.assertEqual(p.stop()[1]["decision"], "block")  # unit 2 has no verify yet
        self.assertEqual(p.cab("verify", CHANGE_ID)[0], 0)
        self.assertEqual(p.stop(), (0, None))
        code, text, _ = p.cab("close", CHANGE_ID)
        self.assertEqual(code, 0, text)
        final = p.change_doc()
        self.assertEqual(final["state"], "closed")
        evidence = p.store().verify_evidence(final)  # the Store's own integrity check
        self.assertEqual({n: r["verdict"] for n, r in evidence.items()}, {1: "PASS", 2: "PASS"})


# --------------------------------------------------------------------------- S6 slots


class S6SlotTests(CliCase):
    def test_doctor_never_reports_unmeasured_sources_as_verified(self) -> None:
        p = self.p
        config = p.tmp / "fixture-config"  # fixture CLAUDE_CONFIG_DIR; real settings unread
        config.mkdir()
        code, out, _ = p.cab("doctor", "--json", env={"CLAUDE_CONFIG_DIR": str(config)})
        payload = json.loads(out)
        self.assertNotEqual(code, 0)
        self.assertNotEqual(payload["doctor"]["overall"], "PASS")
        self.assertTrue(any("managed" in s for s in payload["unmeasured_sources"]))
        code, out, _ = p.cab("doctor", env={"CLAUDE_CONFIG_DIR": str(config)})
        self.assertIn("not the effective settings", out)

    def test_audit_uses_the_start_event_constant(self) -> None:
        p = self.p
        config = p.tmp / "fixture-config"
        (config / "projects").mkdir(parents=True)
        code, out, err = p.cab("audit", "--json", env={"CLAUDE_CONFIG_DIR": str(config)})
        self.assertIn(code, (0, 1, 2), err)
        report = json.loads(out)
        self.assertIn(report["status"], ("ok", "indeterminate", "error"))
        self.assertEqual(audithook.START_EVENTS, ("session_start",))


OWNED_HOOKS = tuple(
    ".claude/hooks/cab/" + name for name in ("guard.py", "audit.py", "closeout.py", "cab")
)


class DoctorManifestTests(CliCase):
    """``cab doctor`` with the project's real ``.cab/manifest.json``.

    Fixture data only: the manifest is built with the pinned S9 API (``setup.manifest``),
    user settings come from a fixture ``CLAUDE_CONFIG_DIR``; no real account, user
    configuration or tenant command is used. Managed, command-line, version and mod
    sources stay unmeasured, so the overall result is never PASS here.
    """

    def setUp(self) -> None:
        super().setUp()
        self.config = self.p.tmp / "fixture-config"
        self.config.mkdir()
        self.env = {"CLAUDE_CONFIG_DIR": str(self.config)}
        self.manifest = self.p.project / config_lock.MANIFEST_REL

    def digest(self, rel: str) -> str:
        return hashlib.sha256(self.p.read(rel)).hexdigest()

    def write_manifest(self, files: Mapping[str, str] | None = None) -> bytes:
        if files is None:
            files = {rel: self.digest(rel) for rel in OWNED_HOOKS}
        record = setup_manifest.Manifest(
            generator_version="0.1.0", profile_sha256="a" * 64, files=dict(files)
        )
        data = setup_manifest.dump_manifest(record)
        self.p.write(config_lock.MANIFEST_REL, data)
        return data

    def clear_manifest(self) -> None:
        if self.manifest.is_symlink() or self.manifest.is_file():
            self.manifest.unlink()
        elif self.manifest.is_dir():
            self.manifest.rmdir()

    def doctor(self) -> tuple[int, dict[str, Any]]:
        code, out, err = self.p.cab("doctor", "--json", env=self.env)
        self.assertNotIn("Traceback", err)
        return code, json.loads(out)

    @staticmethod
    def manifest_issues(payload: Mapping[str, Any]) -> set[tuple[str, str, str | None]]:
        return {
            (i["status"], i["code"], i["subject"])
            for i in payload["doctor"]["issues"]
            if i["check"] == "manifest"
        }

    def test_intact_manifest_hashes_are_checked(self) -> None:
        self.write_manifest()
        code, payload = self.doctor()
        self.assertEqual(self.manifest_issues(payload), {("PASS", "manifest_ok", None)})
        self.assertNotEqual(code, cli.EXIT_OK)  # managed/version/mods stay unmeasured
        self.assertNotEqual(payload["doctor"]["overall"], "PASS")
        self.assertTrue(any("manifest" in s for s in payload["unmeasured_sources"]))
        # the deny floor is the pinned lock's own (it includes the snapshot rule)
        missing = {i["subject"] for i in payload["doctor"]["issues"] if i["code"] == "deny_missing"}
        self.assertEqual(missing, set(config_lock.FLOOR_DENY))  # no settings file here
        self.assertIn("Edit(./changes/*/snapshot.json)", missing)

    def test_modified_missing_and_unsafe_owned_files_fail(self) -> None:
        p = self.p
        p.write(".claude/agents/recorder.md", "---\nname: recorder\ntools: Read\n---\n")
        files = {rel: self.digest(rel) for rel in (*OWNED_HOOKS, ".claude/agents/recorder.md")}
        files[".claude/agents/verifier.md"] = "b" * 64  # listed, never written
        self.write_manifest(files)
        p.write(".claude/hooks/cab/audit.py", p.read(".claude/hooks/cab/audit.py") + b"# x\n")
        os.link(p.project / ".claude/agents/recorder.md", p.tmp / "recorder-second-name.md")
        real = p.tmp / "closeout-real.py"
        (p.project / ".claude/hooks/cab/closeout.py").rename(real)
        os.symlink(real, p.project / ".claude/hooks/cab/closeout.py")
        before = p.state_bytes()
        code, payload = self.doctor()
        self.assertEqual(
            self.manifest_issues(payload),
            {
                ("FAIL", "manifest_mismatch", ".claude/hooks/cab/audit.py"),
                ("FAIL", "manifest_file_missing", ".claude/agents/verifier.md"),
                ("FAIL", "manifest_file_unsafe", ".claude/agents/recorder.md"),
                ("FAIL", "manifest_file_unsafe", ".claude/hooks/cab/closeout.py"),
            },
        )
        self.assertEqual((code, payload["doctor"]["overall"]), (cli.EXIT_MISMATCH, "FAIL"))
        self.assertEqual(p.state_bytes(), before)  # doctor only reads

    def test_unusable_manifest_is_never_an_empty_pass(self) -> None:
        p = self.p
        good = self.write_manifest()
        outside = p.tmp / "outside-manifest.json"
        outside.write_bytes(good)
        empty = setup_manifest.dump_manifest(
            setup_manifest.Manifest(generator_version="0.1.0", profile_sha256="a" * 64)
        )
        cases: dict[str, tuple[Any, str]] = {
            "absent": (lambda: None, "manifest_absent"),
            "not json": (lambda: p.write(config_lock.MANIFEST_REL, b"{"), "manifest_corrupt"),
            "wrong schema": (
                lambda: p.write(config_lock.MANIFEST_REL, good.replace(b'"schema": 1',
                                                                       b'"schema": 2')),
                "manifest_corrupt",
            ),
            "no files": (lambda: p.write(config_lock.MANIFEST_REL, empty), "manifest_empty"),
            "symlink": (lambda: os.symlink(outside, self.manifest), "manifest_unsafe"),
            "hard link": (lambda: os.link(outside, self.manifest), "manifest_unsafe"),
            "folder": (lambda: self.manifest.mkdir(), "manifest_unsafe"),
            "oversized": (
                lambda: p.write(config_lock.MANIFEST_REL,
                                b" " * (config_lock.MAX_FILE_BYTES + 1)),
                "manifest_unsafe",
            ),
        }  # fmt: skip
        before = p.state_bytes()
        for label, (make, problem) in cases.items():
            with self.subTest(label):
                self.clear_manifest()
                make()
                code, payload = self.doctor()
                found = self.manifest_issues(payload)
                status = cli.MANIFEST_PROBLEMS[problem][0]
                self.assertIn((status, problem, config_lock.MANIFEST_REL), found)
                self.assertIn(("UNKNOWN", "manifest_unmeasured", None), found)
                self.assertNotIn(("PASS", "manifest_ok", None), found)
                self.assertEqual(payload["doctor"]["overall"], "FAIL")
                self.assertEqual(code, cli.EXIT_MISMATCH)
        self.assertEqual(p.state_bytes(), before)
        self.assertEqual(outside.read_bytes(), good)

    def test_installed_cab_doctor_reads_the_real_manifest(self) -> None:
        """real subprocess: the installed cab entry with its pinned package (fixture
        CLAUDE_CONFIG_DIR and HOME; nothing from the real user configuration)."""
        p = self.p
        p.install()
        pinned = ".claude/hooks/cab/cab_of_one/runtime/cli.py"
        self.write_manifest({rel: self.digest(rel) for rel in (*OWNED_HOOKS, pinned)})
        env = dict(child_env(str(p.project)), HOME=str(p.home), CLAUDE_CONFIG_DIR=str(self.config))

        def run() -> tuple[int, dict[str, Any]]:
            proc = subprocess.run(
                [sys.executable, p.cab_entry, "doctor", "--json"], cwd=str(p.project),
                env=env, capture_output=True, timeout=60, check=False,
            )  # fmt: skip
            self.assertNotIn(b"Traceback", proc.stderr)
            return proc.returncode, json.loads(proc.stdout.decode("ascii"))

        code, payload = run()
        self.assertEqual(self.manifest_issues(payload), {("PASS", "manifest_ok", None)})
        self.assertNotEqual(code, 0)
        p.write(".claude/hooks/cab/guard.py", p.read(".claude/hooks/cab/guard.py") + b"# x\n")
        code, payload = run()
        self.assertIn(
            ("FAIL", "manifest_mismatch", ".claude/hooks/cab/guard.py"),
            self.manifest_issues(payload),
        )
        self.assertEqual(code, cli.EXIT_MISMATCH)
        (p.project / ".claude/hooks/cab/cab_of_one/setup/manifest.py").unlink()
        code, payload = run()
        found = self.manifest_issues(payload)
        self.assertIn(("UNKNOWN", "manifest_reader_unavailable", config_lock.MANIFEST_REL), found)
        self.assertNotIn(("PASS", "manifest_ok", None), found)
        self.assertNotEqual(code, 0)


# --------------------------------------------------------------------------- pinned wrapper


class WrapperTests(CliCase):
    def test_pinned_cab_wrapper_runs_from_the_project(self) -> None:
        """real subprocess: the generated cab entry imports only its pinned package."""
        p = self.p
        p.install()
        env = child_env(str(p.project))
        env["HOME"] = str(p.home)
        proc = subprocess.run(
            [sys.executable, p.cab_entry, "status"], cwd=str(p.project), env=env,
            capture_output=True, timeout=60, check=False,
        )  # fmt: skip
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.decode().strip(), "no active change")

    def test_broken_package_fails_with_a_fixed_message(self) -> None:
        p = self.p
        p.install(broken=True)
        proc = subprocess.run(
            [sys.executable, p.cab_entry, "status"], cwd=str(p.project),
            env=dict(child_env(str(p.project)), HOME=str(p.home)), capture_output=True,
            timeout=60, check=False,
        )  # fmt: skip
        self.assertEqual(proc.returncode, 5)
        self.assertNotIn(b"Traceback", proc.stderr)

    def test_source_script_refuses_runtime_commands(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "cab"), "status"], cwd=str(self.p.tmp),
            env=dict(child_env(str(self.p.project)), HOME=str(self.p.home)),
            capture_output=True, timeout=60, check=False,
        )  # fmt: skip
        self.assertEqual(proc.returncode, cli.EXIT_REFUSED)
        self.assertIn(b"roots", proc.stderr)


def secret_free(case: unittest.TestCase, secret: str, *blobs: str | bytes) -> None:
    for blob in blobs:
        text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
        case.assertEqual(leaks(secret, text), [])


__all__ = [
    "BASH_OK",
    "CabProject",
    "CliCase",
    "FakeTTY",
    "SimClock",
    "TARGET",
    "secret_free",
    "set_value",
    "tty_os",
]

if __name__ == "__main__":
    unittest.main()
