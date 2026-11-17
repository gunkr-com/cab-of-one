"""S5 B: probe validation, per-attempt recheck, bounded subprocess runner, observe, compare.

Fictional Contoso data only. Temporary files live only under <project>/.local/test-tmp/.
No network and no real tenant.

Two kinds of execution are kept apart and labelled in each test:

- "fake runner": an in-memory ``Runner`` returning fixed bytes (no process is started);
- "real subprocess": ``probes.SubprocessRunner`` starting a real child process (the
  project's simtenant script or a small fixture script) with real wall-clock limits.

Integration seams (see .local/S5_B_REPORT.md): ``probes.state_file_safe`` is patched with
a local stand-in until A's ``paths.state_file_safe`` lands, and the redactor is the
project's ``redact_value`` (some cases patch ``probes.redact`` to prove the plumbing).

    python3 -m unittest discover -s tests -p test_probes.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "simtenant" / "simtenant.py"
SEED = ROOT / "simtenant" / "seed" / "contoso.json"
TMP_ROOT = ROOT / ".local" / "test-tmp"
sys.path.insert(0, str(ROOT / "src"))

from cab_of_one.runtime import probes, schema  # noqa: E402
from cab_of_one.runtime.probes import (  # noqa: E402
    MATCH,
    MISMATCH,
    UNMEASURABLE,
    ExecSpec,
    RunResult,
    SubprocessRunner,
    Unmeasured,
)


def _load_simtenant():
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("simtenant_for_probe_tests", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


st = _load_simtenant()

TARGET = "users/u-1042"
STATE_REL = "tenant/state.json"
SCRIPT_REL = "simtenant/simtenant.py"
PROBE = ("python3", SCRIPT_REL, "--state", STATE_REL, "get", "users", "u-1042")
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


# ----------------------------------------------------------------- fakes with the declared API


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


class Policy:
    def __init__(self, scripts=(SCRIPT_REL,), commands=("simtenant",), retry_seconds=None):
        self.scripts = scripts
        self.commands = commands
        if retry_seconds is not None:
            self.retry_seconds = retry_seconds

    def s3_for(self, inside):
        return {
            "classifier": {
                "trusted_simtenant_scripts": list(self.scripts),
                "trusted_simtenant_commands": list(self.commands),
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


class FakeRunner:
    """fake runner: returns fixed results, starts no process."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def run(self, vector, *, cwd, timeout, max_stdout):
        self.calls.append((tuple(vector), cwd, timeout, max_stdout))
        item = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        return item


def local_state_file_safe(roots, scope):
    """Stand-in for paths.state_file_safe: an existing regular file inside the project
    reached without any symlink."""
    project = os.path.realpath(roots.project)
    cur = roots.project
    for part in scope.split("/"):
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return False
    real = os.path.realpath(os.path.join(roots.project, scope))
    inside = real != project and os.path.commonpath([project, real]) == project
    return inside and os.path.isfile(real)


def line(payload):
    return (json.dumps(payload, sort_keys=True) + "\n").encode()


class ProjectCase(unittest.TestCase):
    """A throwaway project with a copied simtenant script and a seeded tenant."""

    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="probes-", dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "simtenant").mkdir()
        shutil.copyfile(SCRIPT, self.root / SCRIPT_REL)
        (self.root / "tenant").mkdir()
        self.state = self.root / STATE_REL
        st.Tenant(self.state).reset(SEED)
        self.roots = SimpleNamespace(project=str(self.root))
        self.plan = Plan(tenant=STATE_REL)
        self.policy = Policy()
        patcher = mock.patch.object(probes, "state_file_safe", local_state_file_safe)
        patcher.start()
        self.addCleanup(patcher.stop)

    def spec(self, argv=PROBE, target=TARGET, expect="active", checks=None):
        if checks is None:
            dept = Check("/object/department", "eq", '"Finance"')
            checks = (dept,) if expect == "active" else ()
        return VerifySpec(target, tuple(argv), expect, tuple(checks))

    def exec_spec(self, **kw):
        ex = probes.validate(self.spec(**kw), self.plan, self.policy, self.roots)
        self.assertIsInstance(ex, ExecSpec)
        return ex

    def tool(self, name, body):
        path = self.root / "tools" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return str(path)


# ----------------------------------------------------------------- validate


class ValidateTests(ProjectCase):
    def test_accepts_literal_trusted_get_and_builds_isolated_vector(self):
        ex = self.exec_spec()
        real = os.path.realpath(self.root / SCRIPT_REL)
        self.assertEqual(
            ex.vector,
            (sys.executable, "-I", real, "--state", STATE_REL, "get", "users", "u-1042"),
        )
        stt = os.lstat(real)
        self.assertEqual(ex.script_id, (stt.st_dev, stt.st_ino))
        self.assertEqual(ex.scope, STATE_REL)
        self.assertEqual(ex.target, TARGET)
        self.assertEqual(ex.human_command, shlex.join(PROBE))
        self.assertEqual(ex.human_command, shlex.join(ex.display_argv))

    def test_accepts_exec_form_and_dot_slash(self):
        for first in (SCRIPT_REL, "./" + SCRIPT_REL):
            with self.subTest(first=first):
                argv = (first, "--state", STATE_REL, "get", "users", "u-1042")
                ex = self.exec_spec(argv=argv)
                self.assertEqual(ex.vector[3:], argv[1:])

    def test_refusals_are_unmeasured_with_exact_command(self):
        def p(*tail, script=SCRIPT_REL, state=STATE_REL):
            return ("python3", script, "--state", state, *tail)

        get = ("get", "users", "u-1042")
        cases = [
            (
                "write",
                p("set", "users", "u-1042", "--field", "department", "--value", "x"),
                "probe_not_read",
            ),
            ("purge", p("purge", "users", "u-1042"), "probe_not_read"),
            ("get with --lie", p(*get, "--lie"), "probe_not_read"),
            ("list", p("list", "users"), "probe_target_mismatch"),
            ("other target", p("get", "users", "u-1007"), "probe_target_mismatch"),
            (
                "pwsh",
                ("pwsh", "-NoProfile", "-Command", "Get-MgUser -UserId u-1042"),
                "runner_unsupported",
            ),
            ("az", ("az", "group", "show", "--name", "rg-contoso"), "runner_unsupported"),
            (
                "graph",
                ("curl", "-sS", "https://graph.microsoft.com/v1.0/users"),
                "runner_unsupported",
            ),
            ("bare command", ("simtenant", "--state", STATE_REL, *get), "runner_unsupported"),
            ("other state", p(*get, state="tenant/other.json"), "scope_mismatch"),
            ("escaping state", p(*get, state="../state.json"), "scope_mismatch"),
            ("absolute state", p(*get, state=str(self.state)), "scope_mismatch"),
            ("untrusted script", p(*get, script="tools/simtenant.py"), "probe_not_read"),
            ("python -c", ("python3", "-c", "print(1)"), "probe_not_read"),
            ("empty", (), "probe_invalid"),
            ("control char", ("python3", SCRIPT_REL + "\n"), "probe_invalid"),
        ]
        for name, argv, reason in cases:
            with self.subTest(name=name):
                out = probes.validate(self.spec(argv=argv), self.plan, self.policy, self.roots)
                self.assertIsInstance(out, Unmeasured)
                self.assertEqual(out.reason, reason)
                self.assertTrue(out.human_command)
                self.assertEqual(out.human_command, shlex.join(out.display_argv))
                plain = not any(a.startswith("/") for a in argv)  # a redactor may mask paths
                if argv and plain and reason != "probe_invalid":
                    self.assertEqual(out.human_command, shlex.join(argv))

    def test_symlinked_state_is_scope_unsafe(self):
        real = self.root / "tenant" / "real.json"
        os.replace(self.state, real)
        os.symlink(real, self.state)
        out = probes.validate(self.spec(), self.plan, self.policy, self.roots)
        self.assertIsInstance(out, Unmeasured)
        self.assertEqual(out.reason, "scope_unsafe")

    def test_symlinked_script_is_refused(self):
        real = self.root / "simtenant" / "real.py"
        os.replace(self.root / SCRIPT_REL, real)
        os.symlink(real, self.root / SCRIPT_REL)
        out = probes.validate(self.spec(), self.plan, self.policy, self.roots)
        self.assertEqual(out.reason, "script_unsafe")

    def test_hardlinked_script_is_refused(self):
        try:
            os.link(self.root / SCRIPT_REL, self.root / "simtenant" / "twin.py")
        except OSError:
            self.skipTest("hard links are not supported on this filesystem")
        out = probes.validate(self.spec(), self.plan, self.policy, self.roots)
        self.assertEqual(out.reason, "script_unsafe")

    def test_script_in_protected_folder_is_refused(self):
        (self.root / ".cab").mkdir()
        shutil.copyfile(SCRIPT, self.root / ".cab" / "simtenant.py")
        self.policy = Policy(scripts=(".cab/simtenant.py",))
        argv = ("python3", ".cab/simtenant.py", "--state", STATE_REL, "get", "users", "u-1042")
        out = probes.validate(self.spec(argv=argv), self.plan, self.policy, self.roots)
        self.assertEqual(out.reason, "script_unsafe")

    def test_unusable_policy_runs_nothing(self):
        class Broken:
            def s3_for(self, inside):
                raise RuntimeError("boom")

        out = probes.validate(self.spec(), self.plan, Broken(), self.roots)
        self.assertEqual(out.reason, "policy_invalid")


# ----------------------------------------------------------------- recheck


class RecheckTests(ProjectCase):
    def test_unchanged_passes(self):
        ex = self.exec_spec()
        self.assertIsNone(probes.recheck(ex, self.roots))

    def test_replaced_script_is_script_changed_and_never_runs(self):
        ex = self.exec_spec()
        fresh = self.root / "simtenant" / "fresh.py"
        shutil.copyfile(SCRIPT, fresh)
        os.replace(fresh, self.root / SCRIPT_REL)  # same bytes, new inode
        self.assertEqual(probes.recheck(ex, self.roots), "script_changed")
        runner = FakeRunner(RunResult(0, b"{}\n", None))
        obs, resp = probes.observe(ex, runner, FakeClock(), self.roots, with_object=False)
        self.assertEqual(runner.calls, [])
        self.assertIsNone(resp)
        self.assertEqual(obs["status"], "unmeasured")
        self.assertEqual(obs["reason"], "script_changed")
        self.assertEqual(set(obs), OBS_KEYS)

    def test_in_place_edit_is_script_changed(self):
        ex = self.exec_spec()
        with open(self.root / SCRIPT_REL, "a", encoding="utf-8") as fh:
            fh.write("\n# edited\n")
        self.assertEqual(probes.recheck(ex, self.roots), "script_changed")

    def test_state_swapped_for_symlink_is_scope_unsafe(self):
        ex = self.exec_spec()
        outside = Path(tempfile.mkdtemp(prefix="outside-", dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, outside, True)
        os.replace(self.state, outside / "state.json")
        os.symlink(outside / "state.json", self.state)
        self.assertEqual(probes.recheck(ex, self.roots), "scope_unsafe")
        runner = FakeRunner(RunResult(0, b"{}\n", None))
        obs, _ = probes.observe(ex, runner, FakeClock(), self.roots, with_object=False)
        self.assertEqual((obs["reason"], runner.calls), ("scope_unsafe", []))


# ----------------------------------------------------------------- observe (fake runner)


class ObserveTests(ProjectCase):
    def get_payload(self, resource="users", obj_id="u-1042"):
        return st.run(["--state", str(self.state), "get", resource, obj_id])

    def observe(self, result, with_object=False, **kw):
        ex = self.exec_spec(**kw)
        runner = FakeRunner(result)
        return probes.observe(ex, runner, FakeClock(), self.roots, with_object=with_object)

    def test_active_observation_shape(self):
        code, payload = self.get_payload()
        obs, resp = self.observe(RunResult(code, line(payload), None))
        self.assertEqual(set(obs), OBS_KEYS)
        self.assertEqual(obs["status"], "active")
        self.assertEqual(obs["exit"], 0)
        self.assertIsNone(obs["object"])  # verify variant carries no object
        expected_sha = hashlib.sha256(
            schema.canonical_json(probes.redact(payload["object"])).encode("ascii")
        ).hexdigest()
        self.assertEqual(obs["object_sha256"], expected_sha)
        self.assertIsNone(obs["reason"])
        self.assertEqual(obs["argv"], list(PROBE))
        self.assertEqual(resp, payload)

    def test_snapshot_variant_carries_redacted_object(self):
        code, payload = self.get_payload()
        obs, _ = self.observe(RunResult(code, line(payload), None), with_object=True)
        self.assertEqual(obs["object"], probes.redact(payload["object"]))

    def test_soft_deleted_and_absent(self):
        st.Tenant(self.state).write("delete", "users", "u-1042")
        code, payload = self.get_payload()
        obs, _ = self.observe(RunResult(code, line(payload), None))
        self.assertEqual(obs["status"], "soft_deleted")
        code, payload = self.get_payload(obj_id="u-9999")
        self.assertEqual(code, 3)
        obs, resp = self.observe(
            RunResult(code, line(payload), None),
            argv=("python3", SCRIPT_REL, "--state", STATE_REL, "get", "users", "u-9999"),
            target="users/u-9999",
            expect="absent",
        )
        self.assertEqual((obs["status"], obs["exit"], obs["object_sha256"]), ("absent", 3, None))
        absent = self.spec(target="users/u-9999", expect="absent")
        self.assertEqual(probes.compare(absent, obs, resp)[0], MATCH)

    def test_unexpected_responses(self):
        code, payload = self.get_payload()
        _, missing = self.get_payload(obj_id="u-9999")

        def edit(**kw):
            out = json.loads(json.dumps(payload))
            out.update(kw)
            return out

        bad_obj = json.loads(json.dumps(payload))
        bad_obj["object"]["id"] = "u-1007"
        cases = [
            ("ok is 1, not true", RunResult(0, line(edit(ok=1)), None)),
            ("verb list", RunResult(0, line(edit(verb="list")), None)),
            ("other id", RunResult(0, line(edit(id="u-1007")), None)),
            ("other resource", RunResult(0, line(edit(resource="groups")), None)),
            ("purged status", RunResult(0, line(edit(status="purged")), None)),
            ("object id differs", RunResult(0, line(bad_obj), None)),
            ("not_found for another id", RunResult(3, line(missing), None)),
            ("exit 2", RunResult(2, line(payload), None)),
            ("exit 3 with ok payload", RunResult(3, line(payload), None)),
            ("signal (no exit)", RunResult(None, line(payload), None)),
        ]
        for name, result in cases:
            with self.subTest(name=name):
                obs, resp = self.observe(result)
                self.assertEqual(obs["status"], "unmeasured")
                self.assertEqual(obs["reason"], "unexpected_response")
                self.assertIsNone(resp)

    def test_output_shape(self):
        good = line(self.get_payload()[1]).rstrip(b"\n")
        cases = {
            "NaN": b'{"ok": NaN}\n',
            "Infinity": b'{"ok": Infinity}\n',
            "-Infinity": b'{"ok": -Infinity}\n',
            "overflow float": b'{"ok": 1e400}\n',
            "duplicate key": b'{"ok": true, "ok": true}\n',
            "two lines": good + b"\n" + good + b"\n",
            "empty": b"",
            "blank line": b"\n",
            "array": b"[]\n",
            "trailing text": good + b" x\n",
            "CRLF": good + b"\r\n",
            "invalid utf-8": b'{"ok": "\xff"}\n',
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                obs, resp = self.observe(RunResult(0, data, None))
                self.assertEqual((obs["status"], obs["reason"]), ("unmeasured", "output_shape"))
                self.assertIsNone(resp)

    def test_runner_errors_are_unmeasured(self):
        for error in ("timeout", "output_too_large", "spawn_error"):
            with self.subTest(error=error):
                obs, _ = self.observe(RunResult(None, None, error))
                got = (obs["status"], obs["reason"], obs["exit"])
                self.assertEqual(got, ("unmeasured", error, None))
        obs, _ = self.observe(RunResult(None, None, "weird"))
        self.assertEqual(obs["reason"], "spawn_error")


# ----------------------------------------------------------------- compare


class CompareTests(unittest.TestCase):
    ACTIVE = {"status": "active"}

    def run_check(self, response, op, pointer, value_json, status="active", expect="active"):
        spec = VerifySpec("users/u-1", (), expect, (Check(pointer, op, value_json),))
        return probes.compare(spec, {"status": status}, response)

    def test_canonical_types_are_distinct(self):
        resp = {"object": {"b": True, "i": 1, "f": 1.0, "s": "true", "n": None}}
        cases = [
            ("/object/b", "true", MATCH),
            ("/object/b", "1", MISMATCH),
            ("/object/i", "1", MATCH),
            ("/object/i", "1.0", MISMATCH),
            ("/object/f", "1", MISMATCH),
            ("/object/f", "1.0", MATCH),
            ("/object/s", "true", MISMATCH),
            ("/object/s", '"true"', MATCH),
            ("/object/n", "null", MATCH),
        ]
        for pointer, value, want in cases:
            with self.subTest(pointer=pointer, value=value):
                self.assertEqual(self.run_check(resp, "eq", pointer, value)[0], want)
        self.assertEqual(self.run_check(resp, "ne", "/object/i", "1.0")[0], MATCH)
        self.assertEqual(self.run_check(resp, "ne", "/object/i", "1")[0], MISMATCH)

    def test_membership(self):
        resp = {"object": {"members": ["u-1", 2, True], "name": "x"}}
        self.assertEqual(self.run_check(resp, "contains", "/object/members", '"u-1"')[0], MATCH)
        self.assertEqual(self.run_check(resp, "contains", "/object/members", "1")[0], MISMATCH)
        self.assertEqual(self.run_check(resp, "not_contains", "/object/members", '"u-9"')[0], MATCH)
        self.assertEqual(self.run_check(resp, "not_contains", "/object/members", "2")[0], MISMATCH)
        out = self.run_check(resp, "contains", "/object/name", '"x"')
        self.assertEqual(out[:2], (UNMEASURABLE, "not_a_list"))

    def test_pointer_rules(self):
        resp = {"object": {"a/b": 1, "m~n": 2, "list": ["x", "y"]}}
        self.assertEqual(self.run_check(resp, "eq", "/object/a~1b", "1")[0], MATCH)
        self.assertEqual(self.run_check(resp, "eq", "/object/m~0n", "2")[0], MATCH)
        self.assertEqual(self.run_check(resp, "eq", "/object/list/1", '"y"')[0], MATCH)
        for pointer in ("/object/list/01", "/object/list/2", "/object/nope", "/object/a~1b/x"):
            with self.subTest(pointer=pointer):
                got = self.run_check(resp, "eq", pointer, "1")
                self.assertEqual(got, (UNMEASURABLE, "path_missing", {pointer: None}))
        for pointer in ("object/a", "/object/x~2", "/" + "/".join(["a"] * 9)):
            with self.subTest(pointer=pointer):
                got = self.run_check(resp, "eq", pointer, "1")[:2]
                self.assertEqual(got, (UNMEASURABLE, "check_invalid"))

    def test_invalid_checks_and_expectations(self):
        resp = {"object": {"a": 1}}
        self.assertEqual(self.run_check(resp, "gt", "/object/a", "1")[1], "check_invalid")
        self.assertEqual(self.run_check(resp, "eq", "/object/a", "NaN")[1], "check_invalid")
        self.assertEqual(self.run_check(resp, "eq", "/object/a", "{bad")[1], "check_invalid")
        invalid = (UNMEASURABLE, "check_invalid")
        no_checks = VerifySpec("users/u-1", (), "active", ())
        self.assertEqual(probes.compare(no_checks, self.ACTIVE, resp)[:2], invalid)
        absent_with = VerifySpec("users/u-1", (), "absent", (Check("/a", "eq", "1"),))
        self.assertEqual(probes.compare(absent_with, {"status": "absent"}, resp)[:2], invalid)
        bogus = VerifySpec("users/u-1", (), "purged", ())
        self.assertEqual(probes.compare(bogus, self.ACTIVE, resp)[1], "check_invalid")

    def test_status_comes_first(self):
        resp = {"object": {"a": 1}}
        got = self.run_check(resp, "eq", "/object/a", "1", status="soft_deleted")
        self.assertEqual(got[0], MISMATCH)
        self.assertEqual(
            self.run_check(resp, "eq", "/object/a", "1", status="active", expect="soft_deleted")[0],
            MISMATCH,
        )
        out = probes.compare(
            VerifySpec("users/u-1", (), "active", (Check("/object/a", "eq", "1"),)),
            {"status": "unmeasured", "reason": "timeout"},
            None,
        )
        self.assertEqual(out, (UNMEASURABLE, "timeout", {}))

    def test_checked_is_redacted_canonical_and_bounded(self):
        resp = {"object": {"d": {"z": 1, "a": [True]}, "big": "x" * 2000}}
        _, _, checked = self.run_check(resp, "eq", "/object/d", '{"a":[true],"z":1}')
        want = schema.canonical_json(probes.redact(resp["object"]["d"]))
        self.assertEqual(checked["/object/d"], want)
        _, _, checked = self.run_check(resp, "ne", "/object/big", '""')
        self.assertIsNone(checked["/object/big"])


# ----------------------------------------------------------------- redaction plumbing


def _stub_redact(value):
    if isinstance(value, str):
        return value.replace("SECRET", "[R]")
    if isinstance(value, list):
        return [_stub_redact(v) for v in value]
    if isinstance(value, dict):
        return {k: _stub_redact(v) for k, v in value.items()}
    return value


class RedactionTests(ProjectCase):
    def test_every_public_value_passes_the_redactor(self):
        with mock.patch.object(probes, "redact", _stub_redact):
            shown, human = probes.display_command(["tool", "--token", "abcSECRETxyz"])
            self.assertNotIn("SECRET", human)
            self.assertNotIn("SECRET", json.dumps(shown))
            payload = st.run(["--state", str(self.state), "get", "users", "u-1042"])[1]
            payload["object"]["job_title"] = "SECRET-title"
            ex = self.exec_spec()
            obs, resp = probes.observe(
                ex,
                FakeRunner(RunResult(0, line(payload), None)),
                FakeClock(),
                self.roots,
                with_object=True,
            )
            self.assertNotIn("SECRET", json.dumps(obs))
            self.assertEqual(
                obs["object_sha256"],
                hashlib.sha256(
                    schema.canonical_json(_stub_redact(payload["object"])).encode("ascii")
                ).hexdigest(),
            )
            spec = self.spec(checks=(Check("/object/job_title", "ne", '"x"'),))
            outcome, _, checked = probes.compare(spec, obs, resp)
            self.assertEqual(outcome, MATCH)
            self.assertNotIn("SECRET", json.dumps(checked))

    def test_missing_redactor_fails_closed(self):
        def missing():
            raise probes.RedactionUnavailable("none")

        with mock.patch.object(probes, "_resolve_redactor", missing):
            with self.assertRaises(probes.RedactionUnavailable):
                probes.display_command(["x"])
            with self.assertRaises(probes.RedactionUnavailable):
                probes.validate(self.spec(), self.plan, self.policy, self.roots)


# ----------------------------------------------------------------- real subprocess


class SubprocessRunnerTests(ProjectCase):
    """real subprocess: every case starts a real child with real wall-clock limits."""

    def run_vec(self, vector, timeout=5.0, max_stdout=probes.MAX_STDOUT):
        start = time.monotonic()
        result = SubprocessRunner().run(
            vector, cwd=str(self.root), timeout=timeout, max_stdout=max_stdout
        )
        return result, time.monotonic() - start

    def test_real_simtenant_get(self):
        ex = self.exec_spec()
        result, _ = self.run_vec(ex.vector)
        self.assertEqual((result.exit, result.error), (0, None))
        self.assertEqual(result.stdout.count(b"\n"), 1)
        runner = SubprocessRunner()
        obs, resp = probes.observe(ex, runner, FakeClock(), self.roots, with_object=False)
        self.assertEqual(obs["status"], "active")
        self.assertEqual(probes.compare(self.spec(), obs, resp)[0], MATCH)

    def test_output_flood_is_killed_while_collected(self):
        path = self.tool("flood.py", "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n")
        result, elapsed = self.run_vec([sys.executable, "-I", path], timeout=20.0)
        self.assertEqual(
            (result.exit, result.stdout, result.error), (None, None, "output_too_large")
        )
        self.assertLess(elapsed, 15.0)

    def test_hang_times_out(self):
        path = self.tool("hang.py", "import time\ntime.sleep(60)\n")
        result, elapsed = self.run_vec([sys.executable, "-I", path], timeout=0.5)
        self.assertEqual(result.error, "timeout")
        self.assertLess(elapsed, 8.0)

    def test_process_group_is_killed(self):
        pid_file = self.root / "tools" / "grandchild.pid"
        path = self.tool(
            "spawner.py",
            "import subprocess, sys\n"
            "p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])\n"
            "open(sys.argv[1], 'w').write(str(p.pid))\n"
            "print('partial', flush=True)\n",
        )
        result, elapsed = self.run_vec([sys.executable, "-I", path, str(pid_file)], timeout=2.0)
        self.assertEqual(result.error, "timeout")  # the grandchild kept the pipe open
        self.assertLess(elapsed, 10.0)
        pid = int(pid_file.read_text())
        deadline = time.monotonic() + 5.0
        alive = True
        while alive and time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
                time.sleep(0.05)
            except (ProcessLookupError, PermissionError):
                alive = False
        self.assertFalse(alive, "grandchild survived the process-group kill")

    def test_spawn_error(self):
        result, _ = self.run_vec([str(self.root / "missing-binary")])
        self.assertEqual(result.error, "spawn_error")

    def test_environment_and_stdin_are_not_inherited(self):
        path = self.tool(
            "env.py",
            "import json, os, sys\n"
            "print(json.dumps({'keys': sorted(os.environ), 'path': os.environ.get('PATH'),"
            " 'stdin': len(sys.stdin.read())}))\n",
        )
        with mock.patch.dict(os.environ, {"CAB_TEST_SECRET": "s3cr3t", "PYTHONPATH": "/x"}):
            result, _ = self.run_vec([sys.executable, "-I", path])
        data = json.loads(result.stdout)
        self.assertNotIn("CAB_TEST_SECRET", data["keys"])
        self.assertNotIn("PYTHONPATH", data["keys"])
        self.assertNotIn("HOME", data["keys"])
        self.assertEqual(data["path"], os.defpath)
        self.assertEqual(data["stdin"], 0)

    def test_exit_code_passthrough(self):
        path = self.tool("exit7.py", "import sys\nprint('{}')\nsys.exit(7)\n")
        result, _ = self.run_vec([sys.executable, "-I", path])
        self.assertEqual((result.exit, result.error), (7, None))


if __name__ == "__main__":
    unittest.main()
