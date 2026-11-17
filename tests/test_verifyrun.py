"""S5 B: run_verify / run_snapshot over a fake Store with the declared §2.2 API.

Fictional Contoso data only. Temporary files live only under <project>/.local/test-tmp/.
No network and no real tenant. Most cases use a fake Store (A's Store had not landed when
they were written); its exceptions are the real ``state.Conflict`` / ``state.NotAllowed``
and its change document now has the real shape (``id``). ``RealStoreTests`` run the same
code over the real ``state.Store`` so that a fake/real contract gap cannot hide again.

Clock and execution labels (S5_CONTRACT_ACCEPTANCE item 3) are kept separate:

- "Tenant API + FakeClock": ``TenantRunner`` runs the real simtenant code in-process
  through ``simtenant.run(argv, clock=...)`` with the same FakeClock that drives the retry
  sleeps. This is deterministic delay logic, not a subprocess and not elapsed-time evidence.
- "real subprocess + FakeClock": ``SubprocessRunner`` starts the real script; FakeClock
  only replaces the retry sleeps. Used where wall time cannot matter (--lie, purge).
- "real subprocess + real clock": a short real propagation delay with real sleeps and a
  bounded wall time.

    python3 -m unittest discover -s tests -p test_verifyrun.py
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections import namedtuple
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "simtenant" / "simtenant.py"
SEED = ROOT / "simtenant" / "seed" / "contoso.json"
TMP_ROOT = ROOT / ".local" / "test-tmp"
sys.path.insert(0, str(ROOT / "src"))

from cab_of_one.runtime import ledger, probes, schema, state, verifyrun  # noqa: E402
from cab_of_one.runtime.probes import RunResult, SubprocessRunner, SystemClock  # noqa: E402
from cab_of_one.runtime.verifyrun import FAIL, PASS, UNMEASURED  # noqa: E402
from test_cli import TARGET, CabProject, set_value  # noqa: E402 - the real A Store fixture
from test_guard import CHANGE_ID  # noqa: E402


def _load_simtenant():
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("simtenant_for_verifyrun_tests", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


st = _load_simtenant()

CID = "CHG-0007"
PH = "a" * 64
STATE_REL = "tenant/state.json"
SCRIPT_REL = "simtenant/simtenant.py"
USER = "users/u-1042"
MBX = "mailboxes/mbx-1042"
MBX7 = "mailboxes/mbx-1007"
GONE = "users/u-1142"
M365 = "mguser/u-1042"
EVIDENCE_KEYS = {"started_at", "finished_at", "schedule", "results"}
RESULT_KEYS = {"verdict", "attempts", "reason", "human_command", "last", "checked"}
OBS_KEYS = {
    "status",
    "observed_at",
    "argv",
    "exit",
    "object",
    "object_sha256",
    "reason",
    "human_command",
}

View = namedtuple("View", "active change")


@dataclass(frozen=True)
class Check:
    pointer: str
    op: str
    value_json: str


@dataclass(frozen=True)
class VerifySpec:
    target: str
    argv: tuple
    expect: str
    checks: tuple = ()


@dataclass(frozen=True)
class Plan:
    tenant: str
    verify: tuple = ()


def get_argv(target):
    resource, obj_id = target.split("/")
    return ("python3", SCRIPT_REL, "--state", STATE_REL, "get", resource, obj_id)


SPECS = {
    USER: VerifySpec(
        USER, get_argv(USER), "active", (Check("/object/department", "eq", '"Sales"'),)
    ),
    MBX: VerifySpec(
        MBX, get_argv(MBX), "active", (Check("/object/forwarding_smtp_address", "eq", "null"),)
    ),
    MBX7: VerifySpec(
        MBX7, get_argv(MBX7), "active", (Check("/object/forwarding_smtp_address", "eq", "null"),)
    ),
    GONE: VerifySpec(GONE, get_argv(GONE), "absent", ()),
    M365: VerifySpec(
        M365,
        ("pwsh", "-NoProfile", "-Command", "Get-MgUser -UserId u-1042"),
        "active",
        (Check("/id", "eq", '"u-1042"'),),
    ),
}


class Policy:
    """The fields of ``schema.Policy`` that verifyrun reads (``extra_patterns`` included)."""

    def __init__(self, retry_seconds=(2, 5, 10, 20, 40), extra_patterns=()):
        self.retry_seconds = retry_seconds
        self.extra_patterns = tuple(extra_patterns)

    def s3_for(self, inside):
        return {
            "classifier": {
                "trusted_simtenant_scripts": [SCRIPT_REL],
                "trusted_simtenant_commands": ["simtenant"],
            }
        }


class FakeClock:
    def __init__(self, start=None):
        self.epoch = time.time() if start is None else start
        self.t = 0.0
        self.sleeps = []

    def now(self):
        return self.epoch + self.t

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def advance(self, s):
        self.t += s


class TenantRunner:
    """Tenant API + FakeClock: real simtenant code in-process (``simtenant.run`` with an
    injected clock). Not a subprocess."""

    def __init__(self, clock, before=None):
        self.clock = clock
        self.before = before
        self.calls = 0

    def run(self, vector, *, cwd, timeout, max_stdout):
        self.calls += 1
        if self.before is not None:
            self.before(self.calls)
        args = list(vector[3:])
        i = args.index("--state")
        args[i + 1] = os.path.join(cwd, args[i + 1])
        code, payload = st.run(args, clock=self.clock.now)
        return RunResult(code, (json.dumps(payload, sort_keys=True) + "\n").encode(), None)


class Counting:
    def __init__(self, inner, before=None):
        self.inner = inner
        self.before = before
        self.calls = 0

    def run(self, vector, **kw):
        self.calls += 1
        if self.before is not None:
            self.before(self.calls)
        return self.inner.run(vector, **kw)


def unit(n, targets, outcome="ok", verify=None):
    return {"n": n, "targets": list(targets), "outcome": outcome, "verify": verify}


def make_doc(units, state_name="executing", seq=7, inflight=None, **extra):
    # The real change document (state.Store.new_change) names its change "id"; an earlier
    # version of this fake used "change_id", which hid the mismatch with the real Store.
    doc = {
        "id": CID,
        "state": state_name,
        "seq": seq,
        "plan_hash": PH,
        "inflight": inflight,
        "halted": None,
        "units": units,
        "review_start": None,
        "review_sha": None,
        "ack_review_sha": None,
        "approval_nonce": None,
    }
    doc.update(extra)
    return doc


class FakeStore:
    """Declared API only: load, load_plan, record_verify, record_snapshot (§2.2)."""

    def __init__(self, doc, plan, targets):
        self.doc = doc
        self.plan = plan
        self.targets = tuple(targets)
        self.current_hash = PH
        self.records = []
        self.snapshots = []
        self.record_calls = 0
        self.violations = []
        self.after_record = None

    def load(self):
        return View(self.doc["id"], copy.deepcopy(self.doc))

    def load_plan(self, change_id):
        return self.plan, self.targets, self.current_hash

    def _check(self, cond, what):
        if not cond:
            self.violations.append(what)

    def record_verify(self, change_id, unit_n, results, expect_seq, expect_plan_hash, *, evidence):
        self.record_calls += 1
        d = self.doc
        if d["seq"] != expect_seq:
            raise state.Conflict("seq")
        if expect_plan_hash != d["plan_hash"] or expect_plan_hash != self.current_hash:
            raise state.Conflict("plan_hash")
        if d["state"] not in ("executing", "halted", "open-unverified"):
            raise state.NotAllowed("state")
        u = next(x for x in d["units"] if x["n"] == unit_n)
        self._check(u["outcome"] is not None, "unsettled unit")
        self._check(set(evidence) == EVIDENCE_KEYS, "evidence keys")
        self._check(set(results) == set(u["targets"]) == set(evidence["results"]), "targets")
        for t, r in evidence["results"].items():
            self._check(set(r) == RESULT_KEYS, "result keys")
            self._check(results[t] == r["verdict"], "verdict copy")
            if r["last"] is not None:
                self._check(set(r["last"]) == OBS_KEYS, "last keys")
                self._check(r["last"]["object"] is None, "last has no object")
        verdict = verifyrun.aggregate(list(results.values()))
        self.records.append(
            {"unit": unit_n, "seq_before": d["seq"], "verdict": verdict, "evidence": evidence}
        )
        u["verify"] = verdict
        if verdict == FAIL and d["state"] != "halted":
            d["state"], d["halted"] = "halted", {"code": "verify_failed"}
        d["seq"] += 1
        new_seq = d["seq"]
        if self.after_record is not None:
            self.after_record(self)  # e.g. a settlement landing after this commit
        return new_seq

    def record_snapshot(self, change_id, values, expect_plan_hash, actor):
        if expect_plan_hash != self.current_hash:
            raise state.Conflict("plan_hash")
        self._check(set(values) == set(self.targets), "snapshot targets")
        for v in values.values():
            self._check(set(v) == OBS_KEYS, "snapshot keys")
        self.snapshots.append(values)
        d = self.doc
        for key in verifyrun.REVIEW_FIELDS:
            d[key] = None
        d["state"] = "planned"
        d["seq"] += 1
        return d["seq"]


class Case(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="verifyrun-", dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "simtenant").mkdir()
        shutil.copyfile(SCRIPT, self.root / SCRIPT_REL)
        (self.root / "tenant").mkdir()
        self.state = self.root / STATE_REL
        self.roots = SimpleNamespace(project=str(self.root))
        patcher = mock.patch.object(probes, "state_file_safe", self._state_safe)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _state_safe(roots, scope):
        path = os.path.join(roots.project, scope)
        return not os.path.islink(path) and os.path.isfile(path)

    def reset(self, clock=None):
        st.Tenant(self.state, clock=clock).reset(SEED)

    def store(self, units, targets, specs=None, **doc):
        specs = [SPECS[t] for t in targets] if specs is None else specs
        return FakeStore(make_doc(units, **doc), Plan(STATE_REL, tuple(specs)), targets)

    def sim(self, *args):
        """real subprocess: one simtenant invocation (test setup only, bounded)."""
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(self.root / SCRIPT_REL), "--state", STATE_REL, *args],
            cwd=self.root,
            capture_output=True,
            timeout=60,
            check=False,
        )
        return proc.returncode, json.loads(proc.stdout)

    def verify(self, store, runner, clock, policy=None):
        report = verifyrun.run_verify(
            store, self.roots, CID, runner=runner, clock=clock, policy=policy or Policy()
        )
        self.assertEqual(store.violations, [])
        return report


# ----------------------------------------------------------------- E5 / E6 cores


class RetryTests(Case):
    def test_lie_real_subprocess_fails_after_full_schedule(self):
        """real subprocess + FakeClock: --lie reports success, re-reads never converge."""
        self.reset()
        code, payload = self.sim(
            "set",
            "mailboxes",
            "mbx-1042",
            "--field",
            "forwarding_smtp_address",
            "--value",
            "null",
            "--lie",
        )
        self.assertEqual(code, 0)
        self.assertIs(payload["ok"], True)
        before = self.state.read_bytes()
        store = self.store([unit(1, [MBX])], [MBX])
        clock = FakeClock()
        runner = Counting(SubprocessRunner())
        report = self.verify(store, runner, clock)
        self.assertEqual(report.exit, verifyrun.EXIT_FAIL)
        self.assertEqual(clock.sleeps, [2, 5, 10, 20, 40])
        result = report.results[MBX]
        self.assertEqual(
            (result.verdict, result.attempts, result.reason), (FAIL, 6, "not_converged")
        )
        self.assertEqual(runner.calls, 6)
        self.assertEqual(result.last["status"], "active")
        self.assertEqual(set(result.checked), {"/object/forwarding_smtp_address"})
        self.assertNotEqual(result.checked["/object/forwarding_smtp_address"], "null")
        self.assertEqual(self.state.read_bytes(), before)  # probes never write
        self.assertEqual([r["verdict"] for r in store.records], [FAIL])
        self.assertEqual(store.doc["state"], "halted")
        self.assertEqual(report.committed, (1,))

    def test_delay_12_passes_on_attempt_4(self):
        """Tenant API + FakeClock (deterministic delay logic, not a subprocess)."""
        clock = FakeClock()
        self.reset(clock.now)
        st.Tenant(self.state, clock=clock.now).write(
            "set", "users", "u-1042", field="department", value="Sales", delay_seconds=12
        )
        store = self.store([unit(1, [USER])], [USER])
        runner = TenantRunner(clock)
        report = self.verify(store, runner, clock)
        self.assertEqual(report.exit, verifyrun.EXIT_OK)
        self.assertEqual((report.results[USER].verdict, report.results[USER].attempts), (PASS, 4))
        self.assertEqual(clock.sleeps, [2, 5, 10])
        self.assertEqual(runner.calls, 4)
        self.assertEqual(report.verdict, PASS)

    def test_delay_100_fails_and_halts(self):
        """Tenant API + FakeClock."""
        clock = FakeClock()
        self.reset(clock.now)
        st.Tenant(self.state, clock=clock.now).write(
            "set", "users", "u-1042", field="department", value="Sales", delay_seconds=100
        )
        store = self.store([unit(1, [USER])], [USER], canary="awaiting")
        report = self.verify(store, TenantRunner(clock), clock)
        self.assertEqual(report.exit, verifyrun.EXIT_FAIL)
        self.assertEqual((report.results[USER].verdict, report.results[USER].attempts), (FAIL, 6))
        self.assertEqual(clock.sleeps, [2, 5, 10, 20, 40])
        self.assertEqual(store.doc["halted"], {"code": "verify_failed"})

    def test_real_subprocess_short_propagation_delay(self):
        """real subprocess + real clock: a 3 s replication delay, real sleeps, bounded wall."""
        self.reset()
        code, _ = self.sim(
            "set",
            "users",
            "u-1042",
            "--field",
            "department",
            "--value",
            "Sales",
            "--delay-seconds",
            "3",
        )
        self.assertEqual(code, 0)
        store = self.store([unit(1, [USER])], [USER])
        start = time.monotonic()
        report = self.verify(store, SubprocessRunner(), SystemClock(), Policy((1, 1, 1, 1, 2)))
        elapsed = time.monotonic() - start
        self.assertEqual(report.exit, verifyrun.EXIT_OK)
        self.assertEqual(report.results[USER].verdict, PASS)
        self.assertGreaterEqual(report.results[USER].attempts, 2)
        self.assertLess(elapsed, 30.0)

    def test_purge_dry_run_expect_absent_passes(self):
        """real subprocess + FakeClock: purge ignores --dry-run, so absent is observed."""
        self.reset()
        code, payload = self.sim("purge", "users", "u-1142", "--dry-run")
        self.assertEqual((code, payload.get("fault")), (0, "dry_run_ignored"))
        store = self.store([unit(1, [GONE])], [GONE])
        clock = FakeClock()
        report = self.verify(store, SubprocessRunner(), clock)
        self.assertEqual(report.exit, verifyrun.EXIT_OK)
        result = report.results[GONE]
        got = (result.verdict, result.attempts, result.last["status"])
        self.assertEqual(got, (PASS, 1, "absent"))
        self.assertEqual(clock.sleeps, [])

    def test_budget_exhaustion_is_unmeasured_not_fail(self):
        """Tenant API + FakeClock: each probe costs 20 s of clock; budget runs out first."""
        clock = FakeClock()
        self.reset(clock.now)
        store = self.store([unit(1, [USER])], [USER])  # department never becomes Sales
        runner = TenantRunner(clock, before=lambda n: clock.advance(20))
        report = self.verify(store, runner, clock)
        result = report.results[USER]
        self.assertEqual((result.verdict, result.reason), (UNMEASURED, "time_budget"))
        self.assertEqual(report.exit, verifyrun.EXIT_UNMEASURED)
        self.assertNotIn(FAIL, [r["verdict"] for r in store.records])
        self.assertLess(clock.monotonic(), verifyrun.TOTAL_BUDGET + probes.RUN_TIMEOUT + 20)


# ----------------------------------------------------------------- refusals and safety


class SafetyTests(Case):
    def test_unsupported_probes_are_unmeasured_with_zero_runner_calls(self):
        self.reset()
        write = VerifySpec(
            USER,
            (
                "python3",
                SCRIPT_REL,
                "--state",
                STATE_REL,
                "set",
                "users",
                "u-1042",
                "--field",
                "department",
                "--value",
                "Sales",
            ),
            "active",
            (Check("/object/department", "eq", '"Sales"'),),
        )
        wrong_target = VerifySpec(USER, get_argv("users/u-1007"), "active", SPECS[USER].checks)
        other_scope = VerifySpec(
            USER,
            ("python3", SCRIPT_REL, "--state", "tenant/other.json", "get", "users", "u-1042"),
            "active",
            SPECS[USER].checks,
        )
        bare = VerifySpec(USER, ("simtenant", *get_argv(USER)[2:]), "active", SPECS[USER].checks)
        cases = [
            ("m365", M365, [SPECS[M365]], "runner_unsupported"),
            ("write probe", USER, [write], "probe_not_read"),
            ("wrong target", USER, [wrong_target], "probe_target_mismatch"),
            ("other scope", USER, [other_scope], "scope_mismatch"),
            ("bare command", USER, [bare], "runner_unsupported"),
            ("no probe", USER, [], "no_runner"),
        ]
        for name, target, specs, reason in cases:
            with self.subTest(name=name):
                store = self.store([unit(1, [target])], [target], specs=specs)
                runner = Counting(SubprocessRunner())
                report = self.verify(store, runner, FakeClock())
                self.assertEqual(runner.calls, 0)
                result = report.results[target]
                self.assertEqual((result.verdict, result.reason), (UNMEASURED, reason))
                self.assertEqual(result.attempts, 0)
                self.assertIsNone(result.last)
                if specs:
                    self.assertEqual(result.human_command, shlex.join(specs[0].argv))
                self.assertEqual(report.exit, verifyrun.EXIT_UNMEASURED)
                self.assertEqual([r["verdict"] for r in store.records], [UNMEASURED])

    def test_output_flood_through_trusted_path_is_unmeasured(self):
        """real subprocess: the trusted script path holds a flooder."""
        self.reset()
        (self.root / SCRIPT_REL).write_text(
            "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n", encoding="utf-8"
        )
        store = self.store([unit(1, [USER])], [USER])
        start = time.monotonic()
        report = self.verify(store, SubprocessRunner(), FakeClock(), Policy(()))
        self.assertLess(time.monotonic() - start, 15.0)
        result = report.results[USER]
        self.assertEqual((result.verdict, result.reason), (UNMEASURED, "output_too_large"))
        self.assertEqual(report.exit, verifyrun.EXIT_UNMEASURED)

    def test_script_swapped_between_attempts_stops_running(self):
        """Tenant API + FakeClock: the script is replaced during attempt 1."""
        clock = FakeClock()
        self.reset(clock.now)

        def swap(n):
            if n == 1:
                fresh = self.root / "simtenant" / "fresh.py"
                shutil.copyfile(SCRIPT, fresh)
                os.replace(fresh, self.root / SCRIPT_REL)

        runner = TenantRunner(clock, before=swap)
        store = self.store([unit(1, [USER])], [USER])
        report = self.verify(store, runner, clock)
        self.assertEqual(runner.calls, 1)
        result = report.results[USER]
        got = (result.verdict, result.reason, result.attempts)
        self.assertEqual(got, (UNMEASURED, "script_changed", 1))
        self.assertEqual(clock.sleeps, [2])

    def test_noncanonical_values_never_pass(self):
        """Tenant API + FakeClock: account_enabled is a bool; expecting 1 never matches."""
        clock = FakeClock()
        self.reset(clock.now)
        enabled = (Check("/object/account_enabled", "eq", "1"),)
        spec = VerifySpec(USER, get_argv(USER), "active", enabled)
        store = self.store([unit(1, [USER])], [USER], specs=[spec])
        report = self.verify(store, TenantRunner(clock), clock, Policy(()))
        self.assertEqual(report.results[USER].verdict, FAIL)

    def test_soft_deleted_is_not_active(self):
        """Tenant API + FakeClock."""
        clock = FakeClock()
        self.reset(clock.now)
        st.Tenant(self.state, clock=clock.now).write("delete", "users", "u-1042")
        finance = (Check("/object/department", "eq", '"Finance"'),)
        active = VerifySpec(USER, get_argv(USER), "active", finance)
        deleted = VerifySpec(USER, get_argv(USER), "soft_deleted", ())
        for spec, want in ((active, FAIL), (deleted, PASS)):
            with self.subTest(expect=spec.expect):
                store = self.store([unit(1, [USER])], [USER], specs=[spec])
                report = self.verify(store, TenantRunner(clock), clock, Policy(()))
                self.assertEqual(report.results[USER].verdict, want)

    def test_redactor_missing_fails_closed(self):
        self.reset()

        def missing():
            raise probes.RedactionUnavailable("none")

        store = self.store([unit(1, [USER])], [USER])
        runner = Counting(SubprocessRunner())
        with mock.patch.object(probes, "_resolve_redactor", missing):
            report = self.verify(store, runner, FakeClock())
        self.assertEqual(report.exit, verifyrun.EXIT_ERROR)
        self.assertEqual(report.code, "redaction_unavailable")
        self.assertEqual((runner.calls, store.record_calls), (0, 0))

    def test_policy_without_extra_patterns_fails_closed(self):
        """A policy object that cannot say its redaction patterns runs nothing (exit 5)."""
        self.reset()
        runner = Counting(SubprocessRunner())
        for name, value in (("missing", None), ("a string", "x"), ("not strings", (1,))):
            with self.subTest(policy=name):
                policy = SimpleNamespace(retry_seconds=(), s3_for=Policy().s3_for)
                if value is not None:
                    policy.extra_patterns = value
                store = self.store([unit(1, [USER])], [USER])
                report = self.verify(store, runner, FakeClock(), policy)
                self.assertEqual((report.exit, report.code), (5, "redaction_unavailable"))
                self.assertEqual(store.record_calls, 0)
                snap = self.store([], [USER], state_name="planned")
                report = verifyrun.run_snapshot(
                    snap, self.roots, CID, runner=runner, clock=FakeClock(), policy=policy
                )
                self.assertEqual((report.exit, report.code), (5, "redaction_unavailable"))
                self.assertEqual(snap.snapshots, [])
        self.assertEqual(runner.calls, 0)

    def test_policy_patterns_redact_verify_evidence(self):
        """Tenant API + FakeClock: a value matching a policy pattern is redacted in the
        evidence, and the object digest is of the redacted object, not of the raw one."""
        clock = FakeClock()
        self.reset(clock.now)
        st.Tenant(self.state, clock=clock.now).write(
            "set", "users", "u-1042", field="department", value="Sales"
        )
        policy = Policy((), extra_patterns=("Sales",))
        store = self.store([unit(1, [USER])], [USER])
        report = self.verify(store, TenantRunner(clock), clock, policy)
        self.assertEqual(report.exit, verifyrun.EXIT_OK)  # compared on the raw response
        result = report.results[USER]
        self.assertNotIn("Sales", result.checked["/object/department"])
        args = ["--state", str(self.state), "get", "users", "u-1042"]
        _, payload = st.run(args, clock=clock.now)
        raw = payload["object"]
        redacted = schema.canonical_json(ledger.redact_value(raw, ("Sales",)))
        self.assertEqual(
            result.last["object_sha256"], hashlib.sha256(redacted.encode("ascii")).hexdigest()
        )
        self.assertNotEqual(result.last["object_sha256"], probes.public_sha256(raw))
        evidence = json.dumps(store.records[0]["evidence"])
        self.assertNotIn("Sales", evidence)


# ----------------------------------------------------------------- CAS chain and selection


class ChainTests(Case):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.reset(self.clock.now)

    def test_every_settled_unverified_unit_is_verified_in_order(self):
        units = [
            unit(1, [MBX7], verify=PASS),  # already PASS: not selected
            unit(2, [MBX7], outcome="failed"),
            unit(3, [M365], outcome="unknown", verify=UNMEASURED),
            unit(4, [MBX7, USER]),
            unit(5, [USER], outcome=None),  # not settled
        ]
        finance = (Check("/object/department", "eq", '"Finance"'),)
        specs = [SPECS[MBX7], SPECS[M365], VerifySpec(USER, get_argv(USER), "active", finance)]
        store = FakeStore(make_doc(units), Plan(STATE_REL, tuple(specs)), [MBX7, M365, USER])
        runner = TenantRunner(self.clock)
        report = self.verify(store, runner, self.clock, Policy(()))
        self.assertEqual([r["unit"] for r in store.records], [2, 3, 4])
        self.assertEqual([r["seq_before"] for r in store.records], [7, 8, 9])
        self.assertEqual(report.seq, 10)
        self.assertEqual(report.committed, (2, 3, 4))
        self.assertEqual(runner.calls, 2)  # each runnable target measured once; M365 never
        self.assertEqual(set(store.records[0]["evidence"]["results"]), {MBX7})
        self.assertEqual(set(store.records[2]["evidence"]["results"]), {MBX7, USER})
        verdicts = {r["unit"]: r["verdict"] for r in store.records}
        self.assertEqual(verdicts, {2: PASS, 3: UNMEASURED, 4: PASS})
        self.assertEqual(report.exit, verifyrun.EXIT_UNMEASURED)

    def test_settle_between_unit_commits_keeps_first(self):
        units = [unit(1, [MBX7]), unit(2, [MBX7])]
        store = self.store(units, [MBX7])

        def settle(s):
            if s.record_calls == 1:
                s.doc["seq"] += 1  # a late settlement lands between the two commits

        store.after_record = settle
        report = self.verify(store, TenantRunner(self.clock), self.clock, Policy(()))
        self.assertEqual((report.exit, report.code), (verifyrun.EXIT_CONFLICT, "seq"))
        self.assertEqual(report.committed, (1,))
        self.assertEqual(report.not_committed, (2,))
        self.assertEqual(report.seq, 8)
        self.assertEqual(len(store.records), 1)

    def test_seq_moved_during_probes_commits_nothing(self):
        store = self.store([unit(1, [MBX7])], [MBX7])

        def bump(n):
            store.doc["seq"] += 1

        report = self.verify(store, TenantRunner(self.clock, before=bump), self.clock, Policy(()))
        self.assertEqual(report.exit, verifyrun.EXIT_CONFLICT)
        self.assertEqual((report.committed, store.records), ((), []))

    def test_plan_edit_mid_run_conflicts_with_nothing_appended(self):
        store = self.store([unit(1, [MBX7])], [MBX7])

        def edit(n):
            store.current_hash = "b" * 64

        report = self.verify(store, TenantRunner(self.clock, before=edit), self.clock, Policy(()))
        self.assertEqual((report.exit, report.code), (verifyrun.EXIT_CONFLICT, "plan_changed"))
        self.assertEqual((store.record_calls, store.records), (0, []))
        self.assertEqual(report.not_committed, (1,))

    def test_preconditions(self):
        runner = Counting(TenantRunner(self.clock))
        held = {"token": "t"}
        cases = [
            ("inflight", make_doc([unit(1, [MBX7])], inflight=held), 3, "write_in_flight"),
            ("planned", make_doc([unit(1, [MBX7])], state_name="planned"), 3, "state"),
            ("closed", make_doc([unit(1, [MBX7])], state_name="closed"), 3, "state"),
            ("nothing", make_doc([unit(1, [MBX7], verify=PASS)]), 3, "nothing_to_verify"),
            ("plan hash", make_doc([unit(1, [MBX7])], plan_hash="c" * 64), 4, "plan_changed"),
        ]
        for name, doc, exit_code, code in cases:
            with self.subTest(name=name):
                store = FakeStore(doc, Plan(STATE_REL, (SPECS[MBX7],)), [MBX7])
                report = self.verify(store, runner, self.clock)
                self.assertEqual((report.exit, report.code), (exit_code, code))
                self.assertEqual(store.record_calls, 0)
        self.assertEqual(runner.calls, 0)
        self.assertEqual(report.recorded_plan_hash, "c" * 64)

        other = FakeStore(make_doc([unit(1, [MBX7])]), Plan(STATE_REL, (SPECS[MBX7],)), [MBX7])
        report = verifyrun.run_verify(
            other, self.roots, "CHG-0008", runner=runner, clock=self.clock, policy=Policy()
        )
        self.assertEqual((report.exit, report.code), (3, "not_active"))
        bad = FakeStore(make_doc([unit(1, [MBX7])]), Plan(STATE_REL, (SPECS[MBX7],)), [MBX7])
        report = self.verify(bad, runner, self.clock, Policy((1,) * 11))
        self.assertEqual((report.exit, report.code), (3, "policy_invalid"))

    def test_lines_never_claim_success_for_fail(self):
        store = self.store([unit(1, [MBX])], [MBX])  # seed forwarding is not null
        report = self.verify(store, TenantRunner(self.clock), self.clock, Policy(()))
        text = "\n".join(verifyrun.verify_lines(report))
        self.assertIn("FAIL", text)
        self.assertIn("not verified", text)
        self.assertIn(shlex.join(get_argv(MBX)), text)
        self.assertNotIn("all selected units PASS", text)


# ----------------------------------------------------------------- snapshot


class SnapshotTests(Case):
    def setUp(self):
        super().setUp()
        self.reset()

    def snapshot(self, store, runner, clock=None):
        report = verifyrun.run_snapshot(
            store, self.roots, CID, runner=runner, clock=clock or FakeClock(), policy=Policy()
        )
        self.assertEqual(store.violations, [])
        return report

    def test_m365_target_makes_snapshot_incomplete(self):
        """real subprocess for the simtenant target; M365 is never run."""
        store = self.store(
            [], [USER, M365], state_name="approved", review_sha="d" * 64, approval_nonce="n"
        )
        runner = Counting(SubprocessRunner())
        report = self.snapshot(store, runner)
        self.assertEqual(report.exit, verifyrun.EXIT_UNMEASURED)
        self.assertEqual(report.code, "snapshot_incomplete")
        self.assertFalse(report.complete)
        self.assertEqual(runner.calls, 1)
        self.assertEqual(
            report.unmeasured, ((M365, "runner_unsupported", shlex.join(SPECS[M365].argv)),)
        )
        user = report.values[USER]
        self.assertEqual(set(user), OBS_KEYS)
        self.assertEqual(user["status"], "active")
        self.assertEqual(user["object"]["id"], "u-1042")
        self.assertEqual(user["object_sha256"], probes.public_sha256(user["object"]))
        self.assertTrue(report.review_invalidated)
        self.assertEqual(store.doc["state"], "planned")
        self.assertIsNone(store.doc["approval_nonce"])
        self.assertEqual(report.seq, 8)
        self.assertIn("a person must run", "\n".join(verifyrun.snapshot_lines(report)))

    def test_complete_snapshot(self):
        """real subprocess."""
        store = self.store([], [USER, GONE], state_name="planned")
        report = self.snapshot(store, SubprocessRunner())
        self.assertEqual((report.exit, report.complete), (verifyrun.EXIT_OK, True))
        self.assertFalse(report.review_invalidated)
        self.assertEqual(report.values[GONE]["status"], "active")  # u-1142 not yet purged

    def test_target_without_probe_is_no_runner(self):
        store = self.store([], [USER, MBX], specs=[SPECS[USER]], state_name="planned")
        report = self.snapshot(store, SubprocessRunner())
        self.assertEqual(report.exit, verifyrun.EXIT_UNMEASURED)
        self.assertEqual(report.unmeasured[0][:2], (MBX, "no_runner"))

    def test_snapshot_refusals_record_nothing(self):
        runner = Counting(SubprocessRunner())
        cases = [
            ("executing", {"state_name": "executing"}, 3, "state"),
            ("inflight", {"state_name": "planned", "inflight": {"t": 1}}, 3, "write_in_flight"),
            ("plan hash", {"state_name": "planned", "plan_hash": "e" * 64}, 4, "plan_changed"),
        ]
        for name, doc_kw, exit_code, code in cases:
            with self.subTest(name=name):
                store = self.store([], [USER], **doc_kw)
                report = self.snapshot(store, runner)
                self.assertEqual((report.exit, report.code), (exit_code, code))
                self.assertEqual(store.snapshots, [])
        self.assertEqual(runner.calls, 0)

    def test_plan_edit_during_snapshot_records_nothing(self):
        store = self.store([], [USER], state_name="planned")

        def edit(n):
            store.current_hash = "f" * 64

        report = self.snapshot(store, Counting(SubprocessRunner(), before=edit))
        self.assertEqual((report.exit, report.code), (verifyrun.EXIT_CONFLICT, "plan_changed"))
        self.assertEqual(store.snapshots, [])


# ----------------------------------------------------------------- the real A Store

SECRET = "CONTOSO-SECRET-4821"  # matches the fixture policy's extra pattern (test_guard)


class RealStoreTests(unittest.TestCase):
    """run_snapshot / run_verify over the real ``state.Store`` (``test_cli.CabProject`` over
    ``test_guard.Project``), real subprocess probes; ``SimClock`` only replaces retry sleeps.

    Regression for the fake/real contract mismatch (the real change document names its
    change ``id``; the fake used ``change_id``, so every real run was ``not_active``) and for
    evidence redaction with the policy's ``extra_patterns``, which the real Store checks.
    """

    def setUp(self):
        self.p = CabProject(self)
        self.p.targets = (TARGET,)
        self.policy, _ = self.p.runtime()
        self.assertTrue(self.policy.extra_patterns)

    def run_snapshot(self, cid=CHANGE_ID):
        return verifyrun.run_snapshot(
            self.p.store(), self.p.roots, cid, runner=SubprocessRunner(),
            clock=self.p.probe_clock, policy=self.policy, actor="cab-cli",
        )  # fmt: skip

    def run_verify(self, cid=CHANGE_ID):
        return verifyrun.run_verify(
            self.p.store(), self.p.roots, cid, runner=SubprocessRunner(),
            clock=self.p.probe_clock, policy=self.policy,
        )  # fmt: skip

    def tenant(self, *args):
        """real subprocess: one simtenant call on the fixture tenant (setup or read-back)."""
        proc = self.p.run_write(args)
        self.assertEqual(proc.returncode, 0)
        return json.loads(proc.stdout)

    def planned(self):
        self.p.prepare("normal", targets=(TARGET,), snapshot=False, review=None)
        self.assertEqual(self.p.doc()["state"], "planned")

    def written(self, value):
        """A real guarded write of ``value`` (real guard, real tenant write, Store settle)."""
        p = self.p
        p.values[TARGET] = value
        p.prepare("normal", targets=(TARGET,))
        ev = p.bash(set_value("u-1007", value))
        self.assertTrue(p.decide(ev).allowed)
        self.tenant("set", "users", "u-1007", "--field", "department", "--value", value)
        p.settle(ev, "ok")

    def test_snapshot_is_recorded_by_the_real_store(self):
        p = self.p
        self.planned()
        report = self.run_snapshot()
        self.assertEqual((report.exit, report.code, report.complete), (0, None, True))
        data = (p.folder / "snapshot.json").read_bytes()
        self.assertEqual(p.doc()["snapshot_sha"], hashlib.sha256(data).hexdigest())
        snap = schema.parse_snapshot(data)
        self.assertEqual(snap["targets"][TARGET]["object"]["id"], "u-1007")
        self.assertEqual(report.seq, p.doc()["seq"])

    def test_verify_is_recorded_by_the_real_store(self):
        p = self.p
        self.written("Sales")
        report = self.run_verify()
        self.assertEqual((report.exit, report.code, report.committed), (0, None, (1,)))
        doc = p.doc()
        self.assertEqual(doc["units"][0]["verify"], PASS)
        records = p.store().verify_evidence(doc)  # the Store's own integrity check
        self.assertEqual(records[1]["results"][TARGET]["verdict"], PASS)
        self.assertEqual(p.probe_clock.sleeps, [])

    def test_other_or_no_change_is_refused_and_records_nothing(self):
        p = self.p
        report = self.run_verify()
        self.assertEqual((report.exit, report.code), (3, "no_open_change"))
        self.written("Sales")
        before = p.state_bytes()
        for run in (self.run_verify, self.run_snapshot):
            with self.subTest(run=run.__name__):
                report = run("CHG-0002")
                self.assertEqual((report.exit, report.code), (3, "not_active"))
        self.assertEqual(p.state_bytes(), before)
        self.assertFalse((p.folder / "verify.json").exists())

    def test_policy_pattern_never_reaches_snapshot_evidence(self):
        """The real Store refuses an unredacted object or a digest of one; the snapshot is
        recorded only because verifyrun redacts with the policy patterns."""
        p = self.p
        self.tenant("set", "users", "u-1007", "--field", "department", "--value", SECRET)
        self.planned()
        report = self.run_snapshot()
        self.assertEqual((report.exit, report.code), (0, None))
        data = (p.folder / "snapshot.json").read_bytes()
        self.assertNotIn(SECRET.encode(), data)
        obs = json.loads(data)["targets"][TARGET]
        raw = self.tenant("get", "users", "u-1007")["object"]
        self.assertEqual(raw["department"], SECRET)
        self.assertNotEqual(obs["object_sha256"], probes.public_sha256(raw))
        shown = schema.canonical_json(obs["object"]).encode("ascii")
        self.assertEqual(obs["object_sha256"], hashlib.sha256(shown).hexdigest())

    def test_policy_pattern_never_reaches_verify_evidence(self):
        p = self.p
        self.written(SECRET)
        report = self.run_verify()
        self.assertEqual((report.exit, report.committed), (0, (1,)))
        data = (p.folder / "verify.json").read_bytes()
        self.assertNotIn(SECRET.encode(), data)
        self.assertNotIn(SECRET, "\n".join(verifyrun.verify_lines(report)))
        result = p.store().verify_evidence(p.doc())[1]["results"][TARGET]
        raw = self.tenant("get", "users", "u-1007")["object"]
        public = schema.canonical_json(ledger.redact_value(raw, self.policy.extra_patterns))
        self.assertEqual(
            result["last"]["object_sha256"], hashlib.sha256(public.encode("ascii")).hexdigest()
        )
        self.assertNotEqual(result["last"]["object_sha256"], probes.public_sha256(raw))


if __name__ == "__main__":
    unittest.main()
