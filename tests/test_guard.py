"""S4 guard end to end (E1, E2, E3, E9, E10, E11, E14) and the shared S4/S5 test fixture.

S5 changes to the fixture: snapshots are strict observations taken before review (a fresh
snapshot clears review and approval), results are ``Receipt``s, verification carries an
evidence record, and ``resume`` passes the sequence the person saw.

Every file lives under <repo>/.local/test-tmp. The approval registry lives in a fixture home
inside that folder and is passed explicitly (``resolve_roots(..., home)``); HOME is never
read or set and the real registry is never touched. Policy, catalogue and plan documents
are fictional Contoso data that the real strict schema accepts. Approvals created here are
fixture data, not human authorisation.

Other S4 test modules import the helpers below (``Project``, ``S4Case`` ...).
"""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"
TEMPLATE = ROOT / "templates" / "core" / "hooks" / "guard.py"
PACKAGE = ROOT / "src" / "cab_of_one"
SIMTENANT_SCRIPT = ROOT / "simtenant" / "simtenant.py"

from cab_of_one.runtime import fsutil, guard, hookio, ledger, paths, schema  # noqa: E402
from cab_of_one.runtime.planhash import PLAN_FILES, plan_hash  # noqa: E402
from cab_of_one.runtime.state import Receipt, Store, StoreError, unverified_units  # noqa: E402


def _load_simtenant() -> Any:
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # no __pycache__ next to the module
    try:
        spec = importlib.util.spec_from_file_location("simtenant_for_s4_tests", SIMTENANT_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


SIMTENANT = _load_simtenant()

# --------------------------------------------------------------------------- fixture data

T0 = 1_800_000_000.0  # 2027-01-15T08:00:00Z
TTL_HOURS = 4
TENANT = "tenant/state.json"
SIM = "python3 simtenant/simtenant.py"
CHANGE_ID = "CHG-0001"
SLUG = "contoso-fixture"
CHANGE_DIR = f"changes/{CHANGE_ID}-{SLUG}"
OPERATOR = "contoso-operator"
REVIEWER = "agent-safety-01"
# Parent session of the reviewer: SubagentStart/Stop carry the main session's ID.
REVIEW_SESSION = "sess-main-01"
APPROVER = {"os_user": "contoso-approver", "git_user": "Contoso Approver"}
CRITICAL_TARGETS = (
    "users/u-1007",
    "users/u-1015",
    "users/u-1023",
    "users/u-1031",
    "users/u-1042",
)
STANDARD_TARGETS = ("users/u-1007", "users/u-1015", "users/u-1023")
MCP_WRITE = "mcp__contosoadmin__set_user"
MCP_READ = "mcp__contoso__get_user"
MCP_INPUT = {"user_id": "u-1007", "department": "Sales"}

POLICY_TOML = """\
schema = 1

[harness]
approval_ttl_hours = 4
one_active_change = true

[adapters]
enabled = ["simtenant"]

[tiers]
critical_patterns = []

[execution]
canary_tiers = ["critical"]
halt_on_failure = true

[surfaces]
mcp_write_servers = ["contosoadmin"]

[classifier]
trusted_simtenant_scripts = ["simtenant/simtenant.py"]
mcp_read_tools = ["mcp__contoso__get_user"]

[redaction]
extra_patterns = ["CONTOSO-SECRET-[0-9]{4}"]
"""

CATALOG_TOML = """\
schema = 1

[[entry]]
id = "contoso-user-department"
enabled = true
adapter = "simtenant"
command_pattern = "simtenant set users * --field department --value *"
target_scope = ["users/u-1007", "users/u-1015"]
state_scope = "tenant/state.json"
description = "Fictional Contoso department update"
"""

# tier -> (irreversible, reversible, has_dependents)
TIER_ANSWERS = {
    "critical": (True, False, False),
    "normal": (False, True, True),
    "standard": (False, True, False),
}

# Fictional secrets. Every value is unique so that any 8-character window of it is a leak.
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTRU5USU5FTCJ9.U0VOVElORUxzaWduYXR1cmU"
SECRET_CASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "authorization header",
        "az rest --url https://graph.microsoft.com/v1.0/me "
        '--headers "Authorization: Bearer AuthHdrSENTINELtok8"',
        ("AuthHdrSENTINELtok8",),
    ),
    ("bearer", "az rest --headers Bearer BearerOnlySENTINELq6", ("BearerOnlySENTINELq6",)),
    ("jwt", f"az account show --query {JWT}", (JWT,)),
    ("client_secret=", "az ad sp create client_secret=CsEqSENTINELk2", ("CsEqSENTINELk2",)),
    (
        "--client-secret",
        "az login --service-principal --client-secret CliDashSENTINELw5",
        ("CliDashSENTINELw5",),
    ),
    ("-ClientSecret", "az ad app update -ClientSecret CliSecSENTINELv3", ("CliSecSENTINELv3",)),
    ("--password=", "az ad user update --password=PwEqSENTINELm4", ("PwEqSENTINELm4",)),
    ("-Password", "az ad user update -Password PwSpSENTINELn5", ("PwSpSENTINELn5",)),
    (
        "az login -p",
        "az login -u svc@contoso.example -p AzLoginSENTINELp9",
        ("AzLoginSENTINELp9",),
    ),
    (
        "account key",
        'az storage blob list --connection-string "DefaultEndpointsProtocol=https;'
        'AccountName=contoso;AccountKey=AcctKeySENTINELs2==;EndpointSuffix=core.windows.net"',
        ("AcctKeySENTINELs2",),
    ),
    (
        "connection string password",
        'az sql db show --cs "Server=tcp:contoso.example;Password=ConnPwSENTINELr1;"',
        ("ConnPwSENTINELr1",),
    ),
    (
        "shared access key",
        'az servicebus x --cs "Endpoint=sb://contoso.example/;SharedAccessKeyName=root;'
        'SharedAccessKey=SasKeySENTINELt3="',
        ("SasKeySENTINELt3",),
    ),
    (
        "sas signature",
        "az storage x --url 'https://contoso.blob.core.windows.net/c/x?sv=2024-01-01"
        "&sig=SasSigSENTINELu4%3D&se=2027'",
        ("SasSigSENTINELu4",),
    ),
    ("aws key id", "az x --aws AKIAQZXSENTINELWKJVR", ("AKIAQZXSENTINELWKJVR",)),
    ("aws secret", "az x AWS_SECRET_ACCESS_KEY=AwsSecSENTINELx7abc", ("AwsSecSENTINELx7abc",)),
    (
        "pem",
        'az x --key "-----BEGIN PRIVATE KEY-----\nPemFullSENTINELbody0\n-----END PRIVATE KEY-----"',
        ("PemFullSENTINELbody0",),
    ),
    (
        "truncated pem",
        'az x --key "-----BEGIN EC PRIVATE KEY-----\nPemCutSENTINELbody1"',
        ("PemCutSENTINELbody1",),
    ),
    (
        "url credentials",
        "az x --url https://svc-admin:UrlPwSENTINELq7@contoso.example/api",
        ("UrlPwSENTINELq7",),
    ),
    ("token=", "az x token=TokEqSENTINELy8", ("TokEqSENTINELy8",)),
    ("policy extra pattern", "az x --note CONTOSO-SECRET-4821", ("CONTOSO-SECRET-4821",)),
)


def toml_str(value: str) -> str:
    """A TOML basic string (JSON string syntax is a subset TOML accepts)."""
    return json.dumps(value)


def toml_bool(value: bool) -> str:
    return "true" if value else "false"


def change_toml(
    cid: str, tier: str, steps: Sequence[Mapping[str, Any]] = (), tenant: str = TENANT
) -> str:
    irreversible, reversible, dependents = TIER_ANSWERS[tier]
    lines = [
        "schema = 1",
        f"id = {toml_str(cid)}",
        f"irreversible = {toml_bool(irreversible)}",
        'title = "Fictional Contoso fixture change"',
        "",
        "[answers]",
        f"reversible = {toml_bool(reversible)}",
        f"has_dependents = {toml_bool(dependents)}",
        "targets_enumerated = true",
        "",
        "[scope]",
        f"tenant = {toml_str(tenant)}",
    ]
    for step in steps:
        lines += ["", "[[steps]]"]
        for key, value in step.items():
            if isinstance(value, list | tuple):
                lines.append(f"{key} = [{', '.join(toml_str(v) for v in value)}]")
            else:
                lines.append(f"{key} = {toml_str(value)}")
    return "\n".join(lines) + "\n"


def targets_csv(targets: Sequence[str]) -> str:
    return "target\n" + "".join(t + "\n" for t in targets)


def sim(args: str, state: str = TENANT) -> str:
    return f"{SIM} --state {state} {args}"


def purge(obj_id: str, state: str = TENANT) -> str:
    return sim(f"purge users {obj_id}", state)


def set_department(obj_id: str, value: str = "Sales") -> str:
    return sim(f"set users {obj_id} --field department --value {value}")


RESPONSE_SHA = "e" * 64  # fixture stand-in for sha256 of a redacted Post response


def read_argv(target: str) -> list[str]:
    kind, obj_id = target.split("/", 1)
    return ["python3", "simtenant/simtenant.py", "--state", TENANT, "get", kind, obj_id]


def observation(
    target: str, at: float, status: str = "active", *, with_object: bool = True
) -> dict[str, Any]:
    """A strict fixture observation (snapshot variant unless ``with_object`` is False)."""
    argv = read_argv(target)
    obj = {"id": target.split("/", 1)[1], "department": "Sales", "fixture": "Contoso"}
    present = status in ("active", "soft_deleted")
    return {
        "status": status,
        "observed_at": schema.utc_text(at),
        "argv": argv,
        "exit": None if status == "unmeasured" else (3 if status == "absent" else 0),
        "object": obj if (present and with_object) else None,
        "object_sha256": sha256_text(schema.canonical_json(obj)) if present else None,
        "reason": "runner_unsupported" if status == "unmeasured" else None,
        "human_command": shlex.join(argv),
    }


def verify_result(target: str, verdict: str, at: float) -> dict[str, Any]:
    """One fixture ``results[target]`` entry of a verify evidence record."""
    argv = read_argv(target)
    if verdict == "UNMEASURED":
        return {
            "verdict": verdict, "attempts": 0, "reason": "runner_unsupported",
            "human_command": shlex.join(argv), "last": None, "checked": {},
        }  # fmt: skip
    return {
        "verdict": verdict,
        "attempts": 1 if verdict == "PASS" else 6,
        "reason": None if verdict == "PASS" else "not_converged",
        "human_command": shlex.join(argv),
        "last": observation(target, at, with_object=False),
        "checked": {"/object/department": '"Sales"' if verdict == "PASS" else '"Finance"'},
    }


def code_of(decision: hookio.Decision) -> str | None:
    """Reason code of a deny (the text between the last brackets), None for no objection."""
    if decision.allowed:
        return None
    reason = decision.reason
    start = reason.rfind("[")
    if start < 0 or not reason.endswith("]"):
        return reason
    return reason[start + 1 : -1]


def leaks(secret: str, blob: str, window: int = 8) -> list[str]:
    """Every window of ``secret`` that appears in ``blob`` (empty list: no leak)."""
    if len(secret) <= window:
        return [secret] if secret in blob else []
    return [secret[i : i + window] for i in range(len(secret) - window + 1)
            if secret[i : i + window] in blob]  # fmt: skip


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def child_env(project_dir: str) -> dict[str, str]:
    """Environment for hook children: inherited, minus PYTHON* and with the project dir."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("PYTHON") and k != "CLAUDE_PROJECT_DIR"
    }
    env["CLAUDE_PROJECT_DIR"] = project_dir
    return env


GUARD_DRIVER = """\
import os
import sys
import time

sys.dont_write_bytecode = True
hooks, entry, home, clock, barrier = sys.argv[1:6]
sys.path.insert(0, hooks)
from cab_of_one.runtime import guard, hookio, paths

if barrier != "-":
    deadline = time.monotonic() + 20.0
    while not os.path.exists(barrier):
        if time.monotonic() > deadline:
            raise SystemExit(3)
        time.sleep(0.002)
fixed = float(clock)


def handler(data):
    # Same as guard.main, but the registry home is explicit (HOME is never used).
    try:
        roots = paths.resolve_roots(entry, os.environ, home)
    except Exception:
        roots = None
    return guard.decide(data, roots, clock=lambda: fixed)


hookio.run_hook(handler)
"""

LEDGER_DRIVER = """\
import os
import sys
import time

sys.dont_write_bytecode = True
hooks, project, state_home, worker, count, timeout, clock, barrier = sys.argv[1:9]
sys.path.insert(0, hooks)
from cab_of_one.runtime.ledger import Ledger, LedgerError
from cab_of_one.runtime.paths import Roots

if barrier != "-":
    deadline = time.monotonic() + 20.0
    while not os.path.exists(barrier):
        if time.monotonic() > deadline:
            raise SystemExit(3)
        time.sleep(0.002)
fixed = float(clock)
book = Ledger(Roots(project, state_home), clock=lambda: fixed, lock_timeout=float(timeout))
try:
    for i in range(int(count)):
        book.append("state", action="concurrency", actor="worker-" + worker, seq=i + 1)
except LedgerError as exc:
    sys.stdout.write(exc.code + "\\n")
    raise SystemExit(4)
sys.stdout.write("ok\\n")
"""


class FakeClock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Project:
    """A generated-layout project under .local/test-tmp, with a fixture registry home."""

    def __init__(
        self,
        case: unittest.TestCase,
        *,
        policy: str = POLICY_TOML,
        catalog: str = CATALOG_TOML,
    ) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.case = case
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s4-", dir=TMP_ROOT)))
        case.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = self.tmp / "proj"
        self.home = self.tmp / "home"
        self.home.mkdir()
        for rel in (
            "policy",
            ".cab/state",
            ".claude/hooks/cab",
            "changes",
            "tenant",
            "simtenant",
            "scripts",
            "work",
        ):
            (self.project / rel).mkdir(parents=True, exist_ok=True)
        self.write("policy/policy.toml", policy)
        self.write("policy/standard-changes.toml", catalog)
        shutil.copyfile(SIMTENANT_SCRIPT, self.project / "simtenant" / "simtenant.py")
        self.write("scripts/bulk.py", "print('fictional Contoso batch')\n")
        self.write("notes.txt", "fixture notes\n")
        self.entry = self.project / ".claude" / "hooks" / "cab" / "guard.py"
        shutil.copyfile(TEMPLATE, self.entry)
        self.roots = paths.resolve_roots(
            str(self.entry), {"CLAUDE_PROJECT_DIR": str(self.project)}, str(self.home)
        )
        self.clock = FakeClock(T0)
        self._ids = 0
        self.change_id = CHANGE_ID
        self.change_rel = CHANGE_DIR
        self.folder = self.project / CHANGE_DIR
        self.targets: tuple[str, ...] = ()
        self.plan_hash: str | None = None
        self.review_sha: str | None = None
        self.record: dict[str, Any] | None = None
        code, _ = SIMTENANT.run(["--state", str(self.project / TENANT), "reset"], clock=lambda: T0)
        case.assertEqual(code, 0, "simtenant fixture reset failed")

    # ---------------------------------------------------------------- files

    def path(self, rel: str) -> Path:
        return self.project / rel

    def write(self, rel: str, data: str | bytes) -> None:
        target = self.project / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))

    def read(self, rel: str) -> bytes:
        return (self.project / rel).read_bytes()

    def symlink(self, target: Path | str, link: Path | str) -> None:
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.case.skipTest(f"symlinks unsupported here: {type(exc).__name__}")

    def hardlink(self, source: Path | str, link: Path | str) -> None:
        try:
            os.link(source, link)
        except OSError as exc:
            self.case.skipTest(f"hard links unsupported here: {type(exc).__name__}")

    # ---------------------------------------------------------------- runtime objects

    def runtime(self) -> tuple[schema.Policy, tuple[dict[str, Any], ...]]:
        return guard.load_runtime(self.roots)

    def store(
        self, *, ledger_timeout: float = 2.0, lock_timeout: float = 3.0, ext_timeout: float = 1.0
    ) -> Store:
        policy, catalog = self.runtime()
        book = ledger.Ledger(
            self.roots,
            extra_patterns=policy.extra_patterns,
            clock=self.clock,
            lock_timeout=ledger_timeout,
        )
        return Store(
            self.roots,
            policy,
            catalog,
            ledger=book,
            clock=self.clock,
            lock_timeout=lock_timeout,
            ext_timeout=ext_timeout,
        )

    # ---------------------------------------------------------------- events

    def new_id(self) -> str:
        self._ids += 1
        return f"toolu_fixture_{self._ids:04d}"

    def event(
        self,
        tool: str,
        tool_input: dict[str, Any],
        *,
        cwd: str | None = None,
        tool_use_id: str | None = None,
        extra: Mapping[str, Any] | None = None,
        omit: Sequence[str] = (),
    ) -> dict[str, Any]:
        ev: dict[str, Any] = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-main-01",
            "transcript_path": str(self.tmp / "transcript.jsonl"),
            "cwd": cwd if cwd is not None else str(self.project),
            "permission_mode": "default",
            "tool_name": tool,
            "tool_input": tool_input,
            "tool_use_id": tool_use_id or self.new_id(),
        }
        ev.update(extra or {})
        for key in omit:
            ev.pop(key, None)
        return ev

    def bash(self, command: str, **kw: Any) -> dict[str, Any]:
        return self.event("Bash", {"command": command}, **kw)

    def decide(self, ev: Mapping[str, Any], **kw: Any) -> hookio.Decision:
        return guard.decide(ev, self.roots, clock=self.clock, **kw)

    # ---------------------------------------------------------------- change lifecycle

    def write_plan(
        self, tier: str, steps: Sequence[Mapping[str, Any]] = (), tenant: str = TENANT
    ) -> None:
        toml = change_toml(self.change_id, tier, steps, tenant)
        self.write(f"{self.change_rel}/change.toml", toml)
        self.write(f"{self.change_rel}/plan.md", "# Fictional Contoso change\n\nFixture plan.\n")
        self.write(f"{self.change_rel}/targets.csv", targets_csv(self.targets))

    def prepare(
        self,
        tier: str,
        *,
        targets: Sequence[str] | None = None,
        steps: Sequence[Mapping[str, Any]] = (),
        review: str | None = "PASS",
        ack: bool = False,
        snapshot: bool = True,
        approve: bool = True,
        tenant: str = TENANT,
    ) -> None:
        """Open CHG-0001 and take it as far as the arguments say (fixture data only).

        S5 order: the complete snapshot comes first, because review and approval require
        it and a fresh snapshot clears them. A review therefore needs ``snapshot=True``.
        """
        if targets is None:
            targets = CRITICAL_TARGETS if tier == "critical" else STANDARD_TARGETS
        self.targets = tuple(targets)
        store = self.store()
        store.new_change(self.change_id, SLUG, OPERATOR)
        self.write_plan(tier, steps, tenant)
        self.plan_hash = plan_hash(self.folder)
        store.mark_planned(self.change_id, tier, self.plan_hash, OPERATOR)
        self.review_sha = None
        if snapshot:
            self.snapshot(store)
        reviewed = tier != "standard" and review is not None and snapshot
        if reviewed:
            self.review(review, store, ack=ack)
        self.record = None
        if reviewed and approve:
            self.approve(store)

    def review(self, verdict: str = "PASS", store: Store | None = None, ack: bool = False) -> str:
        store = store or self.store()
        store.begin_review(self.change_id, REVIEWER, session_id=REVIEW_SESSION)
        self.review_sha = store.finish_review(self.change_id, REVIEWER, REVIEW_SESSION, verdict, [])
        if ack:
            store.ack(self.change_id, self.review_sha, OPERATOR)
        return self.review_sha

    def observations(self, statuses: Mapping[str, str] | None = None) -> dict[str, Any]:
        statuses = statuses or {}
        return {t: observation(t, self.clock.now, statuses.get(t, "active")) for t in self.targets}

    def snapshot(self, store: Store | None = None, values: Mapping[str, Any] | None = None) -> int:
        store = store or self.store()
        values = self.observations() if values is None else values
        return store.record_snapshot(self.change_id, values, self.plan_hash, OPERATOR)

    def approve(self, store: Store | None = None) -> dict[str, Any]:
        store = store or self.store()
        seq = store.load().change["seq"]
        self.record = store.approve(self.change_id, seq, self.plan_hash, self.review_sha, APPROVER)
        return self.record

    def replan(self, tier: str) -> None:
        self.plan_hash = plan_hash(self.folder)
        self.store().mark_planned(self.change_id, tier, self.plan_hash, OPERATOR)

    def doc(self) -> dict[str, Any]:
        view = self.store().load()
        assert view.change is not None
        return view.change

    def change_doc(self) -> dict[str, Any]:
        """The change state by ID, also after close cleared the active pointer."""
        return self.store()._read_change(self.change_id)

    def fingerprint(self, ev: Mapping[str, Any]) -> str:
        policy, _ = self.runtime()
        return ledger.fingerprint(ev["tool_name"], ev["tool_input"], policy.extra_patterns)

    def receipt(self, ev: Mapping[str, Any], outcome: str = "ok", **changes: Any) -> Receipt:
        """The Receipt a Post (ok/unknown) or Failure (failed) hook would build."""
        source = "failure" if outcome == "failed" else "post"
        fields: dict[str, Any] = {
            "tool_use_id": ev["tool_use_id"],
            "session_id": ev.get("session_id"),
            "tool_name": ev["tool_name"],
            "tool_input": ev["tool_input"],
            "fingerprint": self.fingerprint(ev),
            "source": source,
            "outcome": outcome,
            "exit": 1 if source == "failure" else None,
            "response_sha256": RESPONSE_SHA if source == "post" else None,
        }
        fields.update(changes)
        return Receipt(**fields)

    def settle(self, ev: Mapping[str, Any], outcome: str = "ok", **changes: Any) -> int:
        return self.store().settle(self.receipt(ev, outcome, **changes))

    def evidence(self, results: Mapping[str, str]) -> dict[str, Any]:
        at = self.clock.now
        return {
            "started_at": schema.utc_text(at),
            "finished_at": schema.utc_text(at),
            "schedule": [],
            "results": {t: verify_result(t, v, at) for t, v in results.items()},
        }

    def verify(
        self, unit: int, value: str = "PASS", results: Mapping[str, str] | None = None
    ) -> int:
        doc = self.doc()
        if results is None:
            results = {t: value for t in doc["units"][unit - 1]["targets"]}
        return self.store().record_verify(
            self.change_id, unit, results, doc["seq"], self.plan_hash,
            evidence=self.evidence(results),
        )  # fmt: skip

    def resume(self, clear_inflight: bool = False, expect_seq: int | None = None) -> int:
        seq = self.doc()["seq"] if expect_seq is None else expect_seq
        return self.store().resume(
            self.change_id, OPERATOR, expect_seq=seq, clear_inflight=clear_inflight
        )

    def close(self, expect_seq: int | None = None) -> Any:
        seq = self.doc()["seq"] if expect_seq is None else expect_seq
        return self.store().close(self.change_id, OPERATOR, seq, self.plan_hash)

    def inflight_exists(self) -> bool:
        return os.path.lexists(self.roots.inflight_file)

    # ---------------------------------------------------------------- ledger

    def ledger_files(self) -> list[Path]:
        folder = Path(self.roots.ledger_dir)
        return sorted(folder.glob("*.jsonl")) if folder.is_dir() else []

    def ledger_bytes(self) -> bytes:
        return b"".join(f.read_bytes() for f in self.ledger_files())

    def ledger_rows(self) -> list[dict[str, Any]]:
        return ledger.read_jsonl_strict(self.ledger_bytes())

    def state_bytes(self) -> bytes:
        folder = self.project / ".cab" / "state"
        return b"".join(f.read_bytes() for f in sorted(folder.rglob("*")) if f.is_file())

    # ---------------------------------------------------------------- hook processes

    def install(self, *, broken: bool = False) -> None:
        """Copy the package next to the pinned entry, as setup would (or a broken one)."""
        target = self.entry.parent / "cab_of_one"
        if broken:
            target.mkdir()
            (target / "__init__.py").write_text(
                "raise ImportError('fixture: broken guard package')\n"
            )
        else:
            shutil.copytree(PACKAGE, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    def driver(self, name: str, text: str) -> str:
        folder = self.tmp / "bin"
        folder.mkdir(exist_ok=True)
        path = folder / name
        if not path.exists():
            path.write_text(text)
        return str(path)

    def guard_argv(self, *, clock: float = T0, barrier: str = "-") -> list[str]:
        return [
            sys.executable,
            "-I",
            "-B",
            self.driver("guard_driver.py", GUARD_DRIVER),
            str(self.entry.parent),
            str(self.entry),
            str(self.home),
            repr(clock),
            barrier,
        ]

    def ledger_argv(
        self, worker: int, count: int, *, timeout: float = 20.0, barrier: str = "-"
    ) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-B",
            self.driver("ledger_driver.py", LEDGER_DRIVER),
            str(self.entry.parent),
            str(self.project),
            self.roots.state_home,
            str(worker),
            str(count),
            repr(timeout),
            repr(T0),
            barrier,
        ]

    def run(
        self, argv: Sequence[str], event: Mapping[str, Any] | None = None, *, project_dir=None
    ) -> subprocess.CompletedProcess[bytes]:
        data = json.dumps(event).encode("utf-8") if event is not None else b""
        return subprocess.run(
            list(argv),
            input=data,
            capture_output=True,
            timeout=60,
            env=child_env(project_dir or str(self.project)),
            cwd=str(self.project),
            check=False,
        )


def hook_json(proc: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    lines = proc.stdout.decode("ascii").splitlines()
    if len(lines) != 1:
        raise AssertionError(f"expected one stdout line, got {len(lines)}")
    return json.loads(lines[0])


class S4Case(unittest.TestCase):
    """Base class: a fresh fixture project per test."""

    def setUp(self) -> None:
        self.p = Project(self)

    def assertAllowed(self, decision: hookio.Decision) -> None:
        self.assertTrue(decision.allowed, decision.reason)

    def assertDenied(self, decision: hookio.Decision, *codes: str) -> None:
        self.assertFalse(decision.allowed, "expected a deny")
        self.assertIn(code_of(decision), codes, decision.reason)

    def assertNoLeak(self, secret: str, blob: str) -> None:
        self.assertEqual(leaks(secret, blob), [], "secret material leaked")

    def last_row(self) -> dict[str, Any]:
        rows = self.p.ledger_rows()
        self.assertTrue(rows, "no ledger row")
        return rows[-1]


# =========================================================================== fixture sanity


class FixtureTests(S4Case):
    def test_fixture_documents_pass_the_real_strict_schema(self) -> None:
        policy, catalog = self.p.runtime()
        self.assertEqual(policy.ttl_hours, TTL_HOURS)
        self.assertIn("critical", policy.canary_tiers)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(self.p.roots.state_home.startswith(str(TMP_ROOT)))
        self.p.prepare("critical")
        doc = self.p.doc()
        self.assertEqual((doc["state"], doc["tier"]), ("approved", "critical"))
        self.assertTrue(os.path.isfile(self.p.roots.approvals_file))

    def test_baseline_first_single_canary_unit_is_allowed(self) -> None:
        self.p.prepare("critical")
        ev = self.p.bash(purge("u-1007"))
        self.assertAllowed(self.p.decide(ev))
        doc = self.p.doc()
        self.assertEqual(doc["state"], "executing")
        self.assertEqual(doc["inflight"]["token"], ev["tool_use_id"])
        self.assertEqual(doc["units"][0]["targets"], ["users/u-1007"])
        self.assertTrue(doc["units"][0]["canary"])
        row = self.last_row()
        self.assertEqual((row["decision"], row["reason_code"]), ("allow", "write_reserved"))
        self.assertEqual(row["tool_use_id"], ev["tool_use_id"])


# =========================================================================== E1


class E1ApprovalRequiredTests(S4Case):
    def test_critical_write_with_pass_review_and_no_approval_is_denied(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        self.assertEqual(p.doc()["state"], "reviewed")
        tenant_before = p.read(TENANT)
        ev = p.bash(purge("u-1007"))
        decision = p.decide(ev)
        self.assertDenied(decision, "approval_missing")
        self.assertIn("critical tier requires approval", decision.reason)
        row = self.last_row()
        self.assertEqual(
            (row["event"], row["decision"], row["reason_code"], row["tool_use_id"]),
            ("pre", "deny", "approval_missing", ev["tool_use_id"]),
        )
        self.assertEqual((row["change_id"], row["tier"]), (CHANGE_ID, "critical"))
        doc = p.doc()
        self.assertEqual(doc["units"], [])
        self.assertIsNone(doc["inflight"])
        self.assertFalse(p.inflight_exists())
        self.assertEqual(p.read(TENANT), tenant_before)

    def test_hook_process_exits_2_with_deny_json_and_durable_row(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        p.install()
        tenant_before = p.read(TENANT)
        rows_before = len(p.ledger_rows())
        proc = p.run(p.guard_argv(), p.bash(purge("u-1007")))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        out = hook_json(proc)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("critical tier requires approval", out["permissionDecisionReason"])
        self.assertIn("[approval_missing]", proc.stderr.decode())
        rows = p.ledger_rows()
        self.assertEqual(len(rows), rows_before + 1)
        self.assertEqual(rows[-1]["reason_code"], "approval_missing")
        self.assertFalse(p.inflight_exists())
        self.assertEqual(p.read(TENANT), tenant_before)


# =========================================================================== E2


class E2PlanApprovalTests(S4Case):
    def test_each_plan_file_changed_after_approval_is_refused(self) -> None:
        p = self.p
        p.prepare("critical")
        edits = {
            "change.toml": (b"Fictional", b"fictional"),
            "plan.md": (b"Fixture plan.", b"Fixture plan!"),
            "targets.csv": (b"users/u-1042", b"users/u-1043"),
        }
        self.assertEqual(set(edits), set(PLAN_FILES))
        for name, (old, new) in edits.items():
            with self.subTest(file=name):
                rel = f"{CHANGE_DIR}/{name}"
                original = p.read(rel)
                p.write(rel, original.replace(old, new, 1))
                self.assertDenied(p.decide(p.bash(purge("u-1007"))), "plan_changed")
                p.write(rel, original)
        self.assertEqual(p.doc()["units"], [])
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))

    def test_review_whose_plan_changed_between_start_and_end_never_approves(self) -> None:
        p = self.p
        p.prepare("critical", review=None)
        store = p.store()
        store.begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        rel = f"{CHANGE_DIR}/plan.md"
        original = p.read(rel)
        p.write(rel, original + b"edited during review\n")
        sha = store.finish_review(CHANGE_ID, REVIEWER, REVIEW_SESSION, "PASS", [])
        p.write(rel, original)
        self.assertEqual(p.doc()["state"], "planned")
        seq = p.doc()["seq"]
        with self.assertRaises(StoreError) as caught:
            store.approve(CHANGE_ID, seq, p.plan_hash, sha, APPROVER)
        self.assertEqual(getattr(caught.exception, "code", None), "state")
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_missing")

    def test_expired_approval(self) -> None:
        p = self.p
        p.prepare("critical")
        p.clock.advance(TTL_HOURS * 3600)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_expired")
        p.clock.advance(1)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_expired")

    def test_approval_just_before_expiry_still_counts(self) -> None:
        p = self.p
        p.prepare("critical")
        p.clock.advance(TTL_HOURS * 3600 - 1)
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))

    def test_approval_from_the_future_is_refused(self) -> None:
        p = self.p
        p.prepare("critical")
        p.clock.now = T0 - 60
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid")

    def test_registry_and_local_record_must_agree(self) -> None:
        cases = ("later forged line", "registry missing", "registry truncated", "reformatted")
        for label in cases:
            with self.subTest(case=label):
                p = Project(self)
                p.prepare("critical")
                registry = Path(p.roots.approvals_file)
                local = p.folder / "approval.json"
                if label == "later forged line":
                    forged = dict(p.record)
                    forged["nonce"] = "0" * 32
                    with registry.open("ab") as handle:
                        handle.write(schema.canonical_bytes(forged))
                elif label == "registry missing":
                    registry.unlink()
                elif label == "registry truncated":
                    with registry.open("ab") as handle:
                        handle.write(b'{"schema":1,"change_id":"CHG-0001"')
                else:
                    local.write_text(json.dumps(p.record, indent=2) + "\n")
                self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid")
                self.assertFalse(p.inflight_exists())

    def test_missing_or_linked_local_approval(self) -> None:
        p = self.p
        p.prepare("critical")
        local = p.folder / "approval.json"
        data = local.read_bytes()
        local.unlink()
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_missing")
        outside = p.tmp / "approval-copy.json"
        outside.write_bytes(data)
        p.symlink(outside, local)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid")

    def test_symlinked_registry_folder_is_refused(self) -> None:
        p = self.p
        p.prepare("critical")
        real = p.tmp / "registry-real"
        shutil.move(p.roots.state_home, real)
        p.symlink(real, p.roots.state_home)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid")

    def test_approval_longer_than_policy_ttl_is_refused(self) -> None:
        p = self.p
        p.prepare("critical")
        shorter = POLICY_TOML.replace("approval_ttl_hours = 4", "approval_ttl_hours = 1")
        p.write("policy/policy.toml", shorter)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid")

    def test_forged_long_lived_record_is_refused_even_when_both_copies_match(self) -> None:
        p = self.p
        p.prepare("critical")
        forged = dict(p.record)
        forged["expires_at"] = schema.utc_text(T0 + 30 * 3600)
        line = schema.canonical_bytes(forged)
        with open(p.roots.approvals_file, "ab") as handle:
            handle.write(line)
        (p.folder / "approval.json").write_bytes(line)
        p.clock.advance(5 * 3600)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid", "approval_expired")

    def test_scope_crossing_is_refused(self) -> None:
        p = self.p
        p.prepare("critical")
        absolute = shlex.quote(str(p.path(TENANT)))
        for label, command in (
            ("other file", purge("u-1007", "other/state.json")),
            ("absolute path", purge("u-1007", absolute)),
            ("parent hop", purge("u-1007", "tenant/../tenant/state.json")),
            ("second leaf", purge("u-1007") + " && " + purge("u-1015", "other/state.json")),
        ):
            with self.subTest(case=label):
                self.assertDenied(p.decide(p.bash(command)), "scope_mismatch")
        self.assertEqual(p.doc()["units"], [])

    def test_unsafe_tenant_state_paths_are_refused(self) -> None:
        for label in ("symlinked file", "symlinked folder", "hard link"):
            with self.subTest(case=label):
                p = Project(self)
                p.prepare("critical")
                state_file = p.path(TENANT)
                if label == "symlinked file":
                    real = p.tmp / "outside-state.json"
                    shutil.move(state_file, real)
                    p.symlink(real, state_file)
                    codes: tuple[str, ...] = ("scope_unsafe",)
                elif label == "symlinked folder":
                    real = p.tmp / "tenant-real"
                    shutil.move(p.path("tenant"), real)
                    p.symlink(real, p.path("tenant"))
                    codes = ("scope_unsafe",)
                else:
                    p.hardlink(state_file, p.tmp / "state-alias.json")
                    codes = ("scope_unsafe", "protected_path")
                self.assertDenied(p.decide(p.bash(purge("u-1007"))), *codes)
                self.assertFalse(p.inflight_exists())

    def test_target_outside_targets_csv(self) -> None:
        p = self.p
        p.prepare("critical")
        self.assertDenied(p.decide(p.bash(purge("u-1050"))), "target_outside")

    def test_symlinked_state_or_change_folder_fails_closed(self) -> None:
        p = self.p
        p.prepare("critical")
        changes = p.project / ".cab" / "state" / "changes"
        real = p.tmp / "state-changes-real"
        shutil.move(changes, real)
        p.symlink(real, changes)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_invalid")

        q = Project(self)
        q.prepare("critical")
        real = q.tmp / "change-folder-real"
        shutil.move(q.folder, real)
        q.symlink(real, q.folder)
        self.assertDenied(q.decide(q.bash(purge("u-1007"))), "plan_invalid")


class E2TierAndSnapshotTests(S4Case):
    def test_standard_catalogue_write_with_snapshot_is_allowed(self) -> None:
        self.p.prepare("standard")
        self.assertEqual(self.p.doc()["state"], "planned")
        self.assertAllowed(self.p.decide(self.p.bash(set_department("u-1007"))))

    def test_standard_write_without_plan_bound_snapshot_is_refused(self) -> None:
        self.p.prepare("standard", snapshot=False)
        self.assertDenied(self.p.decide(self.p.bash(set_department("u-1007"))), "snapshot_invalid")

    def test_every_tier_needs_a_snapshot(self) -> None:
        # S5: review and approval need the snapshot first, so a reviewed change always
        # had one; removing the committed file is refused at write time for every tier.
        for tier, command in (
            ("standard", set_department("u-1007")),
            ("normal", set_department("u-1023")),
            ("critical", purge("u-1007")),
        ):
            with self.subTest(tier=tier):
                p = Project(self)
                p.prepare(tier)
                path = p.folder / "snapshot.json"
                data = path.read_bytes()
                path.unlink()
                self.assertDenied(p.decide(p.bash(command)), "snapshot_invalid")
                path.write_bytes(data)
                self.assertAllowed(p.decide(p.bash(command)))

    def test_review_needs_a_snapshot_first(self) -> None:
        p = self.p
        p.prepare("critical", snapshot=False, review=None, approve=False)
        with self.assertRaises(StoreError) as caught:
            p.store().begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        self.assertEqual(getattr(caught.exception, "code", None), "snapshot_invalid")

    def test_replan_drops_the_snapshot(self) -> None:
        p = self.p
        p.prepare("standard")
        p.write(f"{CHANGE_DIR}/plan.md", "# Fictional Contoso change\n\nRevised.\n")
        p.replan("standard")
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "snapshot_invalid")

    def test_tampered_snapshot_is_refused(self) -> None:
        p = self.p
        p.prepare("standard")
        path = p.folder / "snapshot.json"
        doc = json.loads(path.read_bytes())
        doc["targets"]["users/u-1007"] = {"fixture": "forged"}
        path.write_bytes(schema.canonical_bytes(doc))
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "snapshot_invalid")

    def test_no_count_based_or_catalogue_shortcut(self) -> None:
        p = self.p
        p.prepare("standard")
        # one target, but the command is outside the catalogue -> normal
        self.assertDenied(p.decide(p.bash(set_department("u-1023"))), "tier_floor")
        # one target, but a core critical pattern -> critical
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "tier_floor")

    def test_normal_tier_requires_approval(self) -> None:
        p = self.p
        p.prepare("normal", approve=False)
        decision = p.decide(p.bash(set_department("u-1023")))
        self.assertDenied(decision, "approval_missing")
        self.assertIn("normal tier requires approval", decision.reason)

    def test_pass_with_conditions_needs_an_acknowledgement(self) -> None:
        p = self.p
        p.prepare("normal", review="PASS_WITH_CONDITIONS", approve=False)
        with self.assertRaises(StoreError) as caught:
            p.approve()
        self.assertEqual(getattr(caught.exception, "code", None), "review_invalid")
        q = Project(self)
        q.prepare("normal", review="PASS_WITH_CONDITIONS", ack=True)
        self.assertAllowed(q.decide(q.bash(set_department("u-1023"))))

    def test_blocked_review_never_approves(self) -> None:
        p = self.p
        p.prepare("critical", review="BLOCK", approve=False)
        self.assertEqual(p.doc()["state"], "planned")
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_missing")


BULK_ONE = "python3 scripts/bulk.py --batch one"
BULK_TWO = "python3 scripts/bulk.py --batch two"
BULK_DUP = "python3 scripts/bulk.py --batch dup"
BULK_DYNAMIC = "python3 scripts/bulk.py --batch $CONTOSO_BATCH"
BULK_NESTED = "sh -c 'python3 scripts/bulk.py --batch $CONTOSO_BATCH'"
BULK_PROTECTED = "python3 scripts/bulk.py --batch one > policy/policy.toml"
BOUND_STEPS = (
    {"id": "bulk-one", "command": BULK_ONE, "targets": ["users/u-1007"]},
    {"id": "bulk-two", "command": BULK_TWO, "targets": ["users/u-1015", "users/u-1023"]},
    {"id": "bulk-dynamic", "command": BULK_DYNAMIC, "targets": ["users/u-1031"]},
    {"id": "bulk-dup-a", "command": BULK_DUP, "targets": ["users/u-1031"]},
    {"id": "bulk-dup-b", "command": BULK_DUP, "targets": ["users/u-1042"]},
    {"id": "bulk-nested", "command": BULK_NESTED, "targets": ["users/u-1042"]},
    {"id": "bulk-protected", "command": BULK_PROTECTED, "targets": ["users/u-1042"]},
)


class E2BindingTests(S4Case):
    def test_opaque_write_without_a_bound_step_is_refused(self) -> None:
        self.p.prepare("critical", steps=BOUND_STEPS)
        for command in (
            "python3 scripts/bulk.py --batch three",
            purge("u-1007") + " && " + BULK_ONE,  # complete targets plus an opaque leaf
        ):
            with self.subTest(command=command):
                self.assertDenied(self.p.decide(self.p.bash(command)), "binding_missing")

    def test_dynamic_or_ambiguous_steps_gain_no_trust(self) -> None:
        p = self.p
        p.prepare("critical", steps=BOUND_STEPS)
        self.assertDenied(p.decide(p.bash(BULK_DYNAMIC)), "binding_dynamic")
        self.assertDenied(p.decide(p.bash(BULK_NESTED)), "binding_dynamic")
        self.assertDenied(p.decide(p.bash(BULK_DUP)), "binding_ambiguous")
        self.assertDenied(p.decide(p.bash(BULK_PROTECTED)), "protected_path")
        self.assertEqual(p.doc()["executed_steps"], [])

    def test_bound_step_runs_once(self) -> None:
        p = self.p
        p.prepare("critical", steps=BOUND_STEPS)
        first = p.bash(BULK_ONE)
        self.assertAllowed(p.decide(first))
        doc = p.doc()
        self.assertEqual(doc["executed_steps"], ["bulk-one"])
        self.assertEqual(doc["units"][0]["step"], "bulk-one")
        self.assertEqual(doc["units"][0]["targets"], ["users/u-1007"])
        p.settle(first, "ok")
        p.verify(1, "PASS")
        self.assertDenied(p.decide(p.bash(BULK_ONE)), "step_used")

    def test_used_step_stays_used_after_failure_and_resume(self) -> None:
        p = self.p
        p.prepare("critical", steps=BOUND_STEPS)
        first = p.bash(BULK_ONE)
        self.assertAllowed(p.decide(first))
        p.settle(first, "failed")
        p.resume()
        self.assertEqual(p.doc()["executed_steps"], ["bulk-one"])
        self.assertDenied(p.decide(p.bash(BULK_ONE)), "step_used")

    def test_mcp_write_binds_tool_and_canonical_input_hash(self) -> None:
        p = self.p
        step = {
            "id": "mcp-set",
            "tool": MCP_WRITE,
            "input_sha256": schema.input_sha256(MCP_INPUT),
            "targets": ["users/u-1007"],
        }
        p.prepare("normal", steps=[step])
        other = dict(MCP_INPUT, department="Finance")
        self.assertDenied(p.decide(p.event(MCP_WRITE, other)), "binding_missing")
        self.assertDenied(
            p.decide(p.event(MCP_WRITE, dict(MCP_INPUT), cwd=str(p.path("work")))),
            "cwd_not_project",
        )
        self.assertAllowed(p.decide(p.event(MCP_WRITE, dict(MCP_INPUT))))
        self.assertEqual(p.doc()["units"][0]["targets"], ["users/u-1007"])


# =========================================================================== E3


APPROVAL_COMMANDS = (
    "cab approve CHG-0001",
    "scripts/cab approve CHG-0001",
    "python3 -m cab_of_one approve CHG-0001",
    "bash -c 'cab ack CHG-0001'",
    "sh -c \"bash -c 'cab approve CHG-0001'\"",
    "echo $(cab resume CHG-0001)",
    "env CONTOSO=1 cab approve CHG-0001",
    "script -q /dev/null cab approve CHG-0001",
    'python3 -c \'import pty; pty.spawn(["cab", "approve", "CHG-0001"])\'',
    "expect -c 'spawn cab approve CHG-0001; interact'",
    "unbuffer cab resume CHG-0001",
    "ca''b approve CHG-0001",
    "CAB APPROVE CHG-0001",
    "cab setup apply",
    "cab setup uninstall",
)

PROTECTED_COMMANDS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("echo x >> audit/ledger/2027-01.jsonl", "", ("protected_path",)),
    ("echo x | tee -a audit/ledger/2027-01.jsonl", "", ("protected_path",)),
    (f"cp notes.txt {CHANGE_DIR}/approval.json", "", ("protected_path",)),
    (f"cp work/approval.json {CHANGE_DIR}/", "", ("protected_path",)),
    ("cp notes.txt policy", "", ("protected_path",)),
    ("mv notes.txt .claude/settings.json", "", ("protected_path",)),
    (f"mv {CHANGE_DIR}/review.json work/", "", ("protected_path",)),
    (f"rm -f {CHANGE_DIR}/review.json", "", ("protected_path",)),
    ("rm -rf .cab", "", ("protected_path",)),
    (f"cd {CHANGE_DIR} && echo x > approval.json", "", ("protected_path",)),
    ("bash <<'EOF'\necho x > policy/policy.toml\nEOF", "", ("protected_path",)),
    ("cat <<EOF\n$(rm -f policy/policy.toml)\nEOF", "", ("protected_path",)),
    ("find . -delete", "", ("protected_path",)),
    ("git checkout -- policy/policy.toml", "", ("protected_path",)),
    ("git clean -fdx", "", ("protected_path",)),
    ("trap 'rm -f policy/policy.toml' EXIT", "", ("protected_path",)),
    ("curl -opolicy/policy.toml https://example.com", "", ("protected_path",)),
    ("wget -Opolicy/policy.toml https://example.com", "", ("protected_path",)),
    ("curl -sSopolicy/policy.toml https://example.com", "", ("protected_path",)),
    ("curl --output policy/x https://example.com", "", ("protected_path",)),
    ("curl -O https://example.com/approval.json", CHANGE_DIR, ("protected_path",)),
    ("sed -i -f work/s.sed .claude/settings.json", "", ("protected_path",)),
    ("touch .cab/state/inflight", "", ("protected_path",)),
    ("chmod 600 audit/ledger", "", ("protected_path",)),
    ("dd if=notes.txt of=policy/policy.toml", "", ("protected_path",)),
    ("sort -o policy/policy.toml notes.txt", "", ("protected_path",)),
    ("printf x > .cab/manifest.json", "", ("protected_path",)),
    ("ln -sf notes.txt policy/policy.toml", "", ("protected_path",)),
    (f"echo x >| {CHANGE_DIR}/snapshot.json", "", ("protected_path",)),
    ("echo x > Changes/CHG-0001-contoso-fixture/Approval.json", "", ("protected_path",)),
    ("echo x > work/../policy/policy.toml", "", ("protected_path",)),
    ("echo x > ../policy/policy.toml", "work", ("protected_path",)),
    ('echo x > "$F"', "", ("opaque_write",)),
    ("ls | xargs rm", "", ("opaque_write",)),
    ("xargs -I{} rm {}", "", ("opaque_write",)),
    ('cd "$D" && echo x > approval.json', "", ("opaque_write",)),
    ("python3 -c \"open('policy/policy.toml', 'w').write('x')\"", "", ("opaque_script",)),
    ("node -e \"require('fs').writeFileSync('audit/ledger/x', '')\"", "", ("opaque_script",)),
    ("bash scripts/missing.sh", "", ("opaque_script",)),
)

SAFE_COMMANDS = (
    "echo hi > notes.txt",
    "echo x > work/out.txt",
    "cp notes.txt work/copy.txt",
    f"sed -i 's/Contoso/Fabrikam/' {CHANGE_DIR}/plan.md",
    "cat policy/policy.toml",
    "cat .cab/state/active.json",
    f"cd {CHANGE_DIR}; echo x > plan.md",
    "grep -r approval changes",
    "ls -la audit",
)
# A literal trap callback is safe for the shellscan step only (test_shellscan keeps that
# expectation). Frozen S3 classifies every trap as unknown-admin write, so the guard sends
# it to the change gate: see E3ProtectedTests.test_literal_trap_still_needs_the_admin_gate.
TRAP_LITERAL = "trap 'echo bye' EXIT"


class E3ProtectedTests(S4Case):
    def setUp(self) -> None:
        super().setUp()
        self.p.prepare("critical", review=None, snapshot=False, approve=False)
        self.p.write("work/approval.json", "{}\n")
        self.p.write("work/s.sed", "s/a/b/\n")

    def test_human_only_cab_commands_are_refused_with_a_row(self) -> None:
        for command in APPROVAL_COMMANDS:
            with self.subTest(command=command):
                ev = self.p.bash(command)
                self.assertDenied(self.p.decide(ev), "approval_cmd")
                row = self.last_row()
                self.assertEqual(
                    (row["decision"], row["reason_code"], row["tool_use_id"]),
                    ("deny", "approval_cmd", ev["tool_use_id"]),
                )

    def test_authority_writes_through_bash_are_refused(self) -> None:
        for command, cwd, codes in PROTECTED_COMMANDS:
            with self.subTest(command=command):
                cwd_path = str(self.p.path(cwd)) if cwd else None
                ev = self.p.bash(command, cwd=cwd_path)
                decision = self.p.decide(ev)
                self.assertDenied(decision, *codes)
                row = self.last_row()
                self.assertEqual((row["decision"], row["tool_use_id"]), ("deny", ev["tool_use_id"]))
                self.assertEqual(row["reason_code"], code_of(decision))

    def test_authority_writes_through_file_tools_are_refused(self) -> None:
        p = self.p
        folder = p.folder
        (folder / "real.md").write_text("x\n")
        p.write(f"{CHANGE_DIR}/approval.json", "{}\n")
        p.symlink(folder / "approval.json", p.path("work/plan-link.md"))
        p.symlink(folder, p.path("work/change-link"))
        p.hardlink(folder / "approval.json", p.path("work/approval-alias.json"))
        registry = os.path.join(p.roots.state_home, "approvals.jsonl")
        cases = (
            ("Write", "file_path", str(folder / "approval.json")),
            ("Edit", "file_path", str(folder / "review.json")),
            ("MultiEdit", "file_path", str(p.path("policy/policy.toml"))),
            ("NotebookEdit", "notebook_path", str(p.path(".claude/notes.ipynb"))),
            ("Write", "file_path", str(p.path("work/plan-link.md"))),
            ("Write", "file_path", str(p.path("work/change-link/verify.json"))),
            ("Write", "file_path", str(p.path("work/approval-alias.json"))),
            ("Write", "file_path", str(p.path("Changes/CHG-0001-contoso-fixture/Approval.json"))),
            ("Write", "file_path", str(p.path(".cab/state/active.json"))),
            ("Write", "file_path", str(p.path("audit/ledger/2027-01.jsonl"))),
            ("Write", "file_path", "policy/policy.toml"),
            ("Write", "file_path", registry),
        )
        for tool, key, path in cases:
            with self.subTest(tool=tool, path=path):
                ev = p.event(tool, {key: path, "content": "x"})
                self.assertDenied(p.decide(ev), "protected_path")
                self.assertEqual(self.last_row()["reason_code"], "protected_path")

    def test_relative_file_tool_path_without_cwd_is_refused(self) -> None:
        ev = self.p.event("Write", {"file_path": "policy/policy.toml"}, omit=("cwd",))
        self.assertDenied(self.p.decide(ev), "event_invalid")

    def test_literal_safe_operations_stay_allowed(self) -> None:
        for command in SAFE_COMMANDS:
            with self.subTest(command=command):
                self.assertAllowed(self.p.decide(self.p.bash(command)))
        for tool, path in (
            ("Write", self.p.path("notes.md")),
            ("Edit", self.p.folder / "plan.md"),
            ("Write", self.p.folder / "change.toml"),
        ):
            with self.subTest(tool=tool, path=str(path)):
                self.assertAllowed(self.p.decide(self.p.event(tool, {"file_path": str(path)})))
        self.assertAllowed(
            self.p.decide(self.p.event("Read", {"file_path": str(self.p.folder / "approval.json")}))
        )

    def test_long_literal_argument_does_not_crash_the_guard(self) -> None:
        # A literal word longer than one path component (255 bytes) is ordinary text, e.g. a
        # test filter or a JSON value. It must be judged, not turned into internal_error.
        long_word = "contoso" * 40
        decision = self.p.decide(self.p.bash(f"pytest -k {long_word}"))
        self.assertAllowed(decision)

    def test_literal_operand_below_a_regular_file_is_judged(self) -> None:
        # notes.txt is a regular file, so notes.txt/child cannot exist (ENOTDIR): not protected
        self.assertAllowed(self.p.decide(self.p.bash("pytest notes.txt/child")))

    def test_unexpected_lstat_error_fails_closed(self) -> None:
        p = self.p
        real_lstat = os.lstat
        probe = str(p.path("work/out.json"))

        def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if os.fspath(path) == probe:
                raise OSError(errno.EACCES, "fixture: permission denied")
            return real_lstat(path, *args, **kwargs)

        ev = p.event("Write", {"file_path": probe, "content": "x"})
        with mock.patch.object(paths.os, "lstat", lstat):
            decision = p.decide(ev)
        self.assertFalse(decision.allowed, "an unreadable path must not count as absent")
        self.assertFalse(p.inflight_exists())

    def test_literal_trap_still_needs_the_admin_gate(self) -> None:
        p = self.p
        ev = p.bash(TRAP_LITERAL)
        decision = p.decide(ev)
        self.assertDenied(decision, "approval_missing")
        row = self.last_row()
        self.assertEqual(
            (row["decision"], row["reason_code"], row["tool_use_id"]),
            ("deny", "approval_missing", ev["tool_use_id"]),
        )
        doc = p.doc()
        self.assertEqual((doc["units"], doc["inflight"]), ([], None))
        self.assertFalse(p.inflight_exists())


# =========================================================================== E9


class E9SubagentTests(S4Case):
    def setUp(self) -> None:
        super().setUp()
        self.p.prepare("critical", review=None, snapshot=False, approve=False)

    def sub(self, agent_type: str | None = "runbook-author", agent_id: Any = "agent-0001"):
        extra: dict[str, Any] = {"agent_id": agent_id}
        if agent_type is not None:
            extra["agent_type"] = agent_type
        return extra

    def test_subagent_tenant_write_is_refused(self) -> None:
        p = self.p
        for ev in (
            p.bash(purge("u-1007"), extra=self.sub()),
            p.event(MCP_WRITE, dict(MCP_INPUT), extra=self.sub()),
            p.event(
                "NotebookEdit",
                {"notebook_path": str(p.path("work/x.ipynb"))},
                extra=self.sub("verifier"),
            ),  # fmt: skip
        ):
            with self.subTest(tool=ev["tool_name"]):
                self.assertDenied(p.decide(ev), "subagent_write", "subagent_path")
        self.assertEqual(p.doc()["units"], [])

    def test_role_local_files_only(self) -> None:
        p = self.p
        other = p.path("changes/CHG-0002-other")
        other.mkdir()
        allowed = (
            ("runbook-author", p.folder / "change.toml"),
            ("runbook-author", p.folder / "plan.md"),
            ("recorder", p.folder / "record.md"),
        )
        for role, path in allowed:
            with self.subTest(role=role, path=path.name):
                ev = p.event("Write", {"file_path": str(path)}, extra=self.sub(role))
                self.assertAllowed(p.decide(ev))
        denied = (
            ("runbook-author", p.folder / "targets.csv", "subagent_path"),
            ("runbook-author", other / "change.toml", "subagent_path"),
            ("runbook-author", p.path("notes.md"), "subagent_path"),
            ("runbook-author", p.folder / "approval.json", "protected_path"),
            ("recorder", p.folder / "plan.md", "subagent_path"),
            ("verifier", p.folder / "plan.md", "subagent_path"),
        )
        for role, path, code in denied:
            with self.subTest(role=role, path=str(path)):
                ev = p.event("Edit", {"file_path": str(path)}, extra=self.sub(role))
                self.assertDenied(p.decide(ev), code)

    def test_malformed_agent_id_is_never_the_main_session(self) -> None:
        p = self.p
        for agent_id in ("", None, 42, "bad id with spaces", "x" * 200):
            with self.subTest(agent_id=agent_id):
                ev = p.event(
                    "Write",
                    {"file_path": str(p.folder / "change.toml")},
                    extra=self.sub("runbook-author", agent_id),
                )
                self.assertDenied(p.decide(ev), "subagent_path")
                ev = p.bash(purge("u-1007"), extra=self.sub("runbook-author", agent_id))
                self.assertDenied(p.decide(ev), "subagent_write")

    def test_agent_type_alone_is_a_main_custom_agent(self) -> None:
        p = self.p
        extra = {"agent_type": "runbook-author"}
        ev = p.event("Write", {"file_path": str(p.path("notes.md"))}, extra=extra)
        self.assertAllowed(p.decide(ev))
        # the main path reaches the change gate, not the subagent refusal
        self.assertDenied(p.decide(p.bash(purge("u-1007"), extra=extra)), "approval_missing")

    def test_subagent_bash_is_strictly_read_only(self) -> None:
        p = self.p
        allowed = (
            "cat notes.txt",
            "cat notes.txt 2>/dev/null",
            "ls work | wc -l",
            "grep -r Contoso changes > /dev/null",
            sim("list users"),
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertAllowed(p.decide(p.bash(command, extra=self.sub())))
        denied = (
            ("cat notes.txt > work/out.txt", ("subagent_bash",)),
            ("echo x >> notes.txt", ("subagent_bash",)),
            (sim("list users") + " > work/users.json", ("subagent_bash",)),
            ("bash -c 'cat notes.txt'", ("subagent_bash",)),
            ("/bin/cat notes.txt", ("subagent_bash",)),
            ("CONTOSO=1 cat notes.txt", ("subagent_bash",)),
            # frozen S3 classifies a here-document as unknown-admin write before S4's
            # read-only Bash branch, so the exact refusal is subagent_write
            ("cat <<EOF\nx\nEOF", ("subagent_write",)),
            ("cp notes.txt work/copy.txt", ("subagent_bash",)),
            ("find . -name '*.md'", ("subagent_bash",)),
            ("python3 -c 'print(1)'", ("subagent_bash", "subagent_write")),
        )
        for command, codes in denied:
            with self.subTest(command=command):
                self.assertDenied(p.decide(p.bash(command, extra=self.sub())), *codes)
        self.assertEqual(p.doc()["units"], [])
        self.assertFalse(p.inflight_exists())

    def test_subagent_reads_are_recorded_as_subagent(self) -> None:
        p = self.p
        ev = p.bash(sim("get users u-1007"), extra=self.sub("verifier", "agent-verify-01"))
        self.assertAllowed(p.decide(ev))
        row = self.last_row()
        self.assertEqual(
            (row["agent"], row["decision"], row["reason_code"]), ("subagent", "allow", "read")
        )
        self.assertEqual(row["agent_type"], "verifier")
        ev = p.event(MCP_READ, {"user_id": "u-1007"}, extra=self.sub("verifier"))
        self.assertAllowed(p.decide(ev))
        self.assertEqual(self.last_row()["agent"], "subagent")
        ev = p.bash(sim("get users u-1007"), extra=self.sub("verifier"), omit=("session_id",))
        self.assertDenied(p.decide(ev), "event_invalid")


# =========================================================================== E10


BROKEN_POLICIES = {
    "toml syntax": POLICY_TOML + "[harness\n",
    "duplicate key": POLICY_TOML.replace("schema = 1\n", "schema = 1\nschema = 1\n", 1),
    "unknown table": POLICY_TOML + "\n[mystery]\nvalue = 1\n",
    "unknown key": POLICY_TOML.replace(
        "one_active_change = true", "one_active_change = true\nmystery = 1"
    ),
    "schema 2": POLICY_TOML.replace("schema = 1", "schema = 2", 1),
    "ttl bool": POLICY_TOML.replace("approval_ttl_hours = 4", "approval_ttl_hours = true"),
    "ttl 0": POLICY_TOML.replace("approval_ttl_hours = 4", "approval_ttl_hours = 0"),
    "ttl 25": POLICY_TOML.replace("approval_ttl_hours = 4", "approval_ttl_hours = 25"),
    "ttl float": POLICY_TOML.replace("approval_ttl_hours = 4", "approval_ttl_hours = 4.0"),
    "canary without critical": POLICY_TOML.replace(
        'canary_tiers = ["critical"]', 'canary_tiers = ["normal"]'
    ),
    "halt_on_failure false": POLICY_TOML.replace(
        "halt_on_failure = true", "halt_on_failure = false"
    ),
    "one_active_change false": POLICY_TOML.replace(
        "one_active_change = true", "one_active_change = false"
    ),
    "nan": POLICY_TOML + "\n[verify]\nretry_seconds = [nan]\n",
    "redaction matches everything": POLICY_TOML.replace(
        'extra_patterns = ["CONTOSO-SECRET-[0-9]{4}"]', 'extra_patterns = [".*"]'
    ),
    "shell in subagent allow list": (
        POLICY_TOML + '\n[guard]\nsubagent_bash_allow = ["cat", "bash"]\n'
    ),
}

BROKEN_CATALOGS = {
    "missing state_scope": CATALOG_TOML.replace('state_scope = "tenant/state.json"\n', ""),
    "dot state_scope": CATALOG_TOML.replace(
        'state_scope = "tenant/state.json"', 'state_scope = "./tenant/state.json"'
    ),
    "pattern state_scope": CATALOG_TOML.replace(
        'state_scope = "tenant/state.json"', 'state_scope = "tenant/*.json"'
    ),
    "unknown entry key": CATALOG_TOML + 'owner = "contoso"\n',
    "enabled string": CATALOG_TOML.replace("enabled = true", 'enabled = "yes"'),
    "schema missing": CATALOG_TOML.replace("schema = 1\n", "", 1),
}


class E10FailClosedTests(S4Case):
    def fail_path_events(self) -> list[tuple[dict[str, Any], bool]]:
        p = self.p
        notes = str(p.path("notes.txt"))
        return [
            (p.event("Read", {"file_path": notes}), True),
            (p.event("Grep", {"pattern": "Contoso", "path": str(p.project)}), True),
            (p.event("Glob", {"pattern": "**/*.md"}), True),
            (p.bash("echo hi"), False),
            (p.bash(purge("u-1007")), False),
            (p.event("Write", {"file_path": str(p.path("notes.md"))}), False),
            (p.event("Edit", {"file_path": notes}), False),
            (p.event(MCP_READ, {"user_id": "u-1007"}), False),
            (p.event(MCP_WRITE, dict(MCP_INPUT)), False),
        ]

    def check_fail_path(self, roots: paths.Roots | None) -> None:
        for ev, allowed in self.fail_path_events():
            with self.subTest(tool=ev["tool_name"]):
                decision = guard.decide(ev, roots, clock=self.p.clock)
                if allowed:
                    self.assertAllowed(decision)
                else:
                    self.assertDenied(decision, "policy_invalid")

    def test_broken_policy_allows_only_read_grep_glob(self) -> None:
        for label, text in BROKEN_POLICIES.items():
            with self.subTest(policy=label):
                self.p.write("policy/policy.toml", text)
                self.check_fail_path(self.p.roots)
        self.p.write("policy/policy.toml", POLICY_TOML)
        self.assertAllowed(self.p.decide(self.p.bash("echo hi")))

    def test_broken_catalogue_allows_only_read_grep_glob(self) -> None:
        for label, text in BROKEN_CATALOGS.items():
            with self.subTest(catalog=label):
                self.p.write("policy/standard-changes.toml", text)
                self.check_fail_path(self.p.roots)

    def test_unresolved_layout_allows_only_read_grep_glob(self) -> None:
        self.check_fail_path(None)

    def test_hardlinked_policy_file_is_a_bad_layout(self) -> None:
        self.p.hardlink(self.p.path("policy/policy.toml"), self.p.tmp / "policy-alias.toml")
        self.check_fail_path(self.p.roots)

    def test_classifier_exception_or_bad_result_fails_closed(self) -> None:
        def boom(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("fixture classifier failure")

        def nonsense(*_args: Any, **_kwargs: Any) -> Any:
            return {"kind": "not-admin"}

        for classify in (boom, nonsense):
            with self.subTest(classify=classify.__name__):
                decision = self.p.decide(self.p.bash("echo hi"), classify=classify)
                self.assertDenied(decision, "internal_error")

    def test_handler_exception_exits_2(self) -> None:
        roots = self.p.roots

        def handler(data: dict[str, Any]) -> hookio.Decision:
            raise RuntimeError("fixture handler failure")

        for fn in (handler, lambda data: guard.decide(data, roots, classify=None)):
            out, err = io.StringIO(), io.StringIO()
            code = hookio.run_hook(
                fn,
                stdin=io.StringIO(json.dumps(self.p.bash("echo hi"))),
                stdout=out,
                stderr=err,
                exit_process=False,
            )
            self.assertEqual(code, 2)
            payload = json.loads(out.getvalue())["hookSpecificOutput"]
            self.assertEqual(payload["permissionDecision"], "deny")

    def test_template_import_failure_blocks(self) -> None:
        p = self.p
        p.install(broken=True)
        argv = [sys.executable, "-I", "-B", str(p.entry)]
        proc = p.run(argv, p.event("Read", {"file_path": str(p.path("notes.txt"))}))
        self.assertEqual(proc.returncode, 2)
        out = hook_json(proc)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("could not start", proc.stderr.decode())

    def test_template_with_mismatched_project_dir(self) -> None:
        p = self.p
        p.install()
        argv = [sys.executable, "-I", "-B", str(p.entry)]
        other = str(p.tmp)
        read_event = p.event("Read", {"file_path": str(p.path("notes.txt"))})
        read = p.run(argv, read_event, project_dir=other)
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertEqual(hook_json(read), {})
        bash = p.run(argv, p.bash("echo hi"), project_dir=other)
        self.assertEqual(bash.returncode, 2)
        self.assertIn("[policy_invalid]", bash.stderr.decode())
        # correct project: a Read needs no registry access, so the real HOME is never used
        ok = p.run(argv, read_event)
        self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_corrupt_state_blocks_writes(self) -> None:
        p = self.p
        p.prepare("critical")
        path = p.project / ".cab" / "state" / "changes" / f"{CHANGE_ID}.json"
        original = path.read_bytes()
        path.write_bytes(original.replace(b'{"ack_review_sha":', b'{"seq":1,"ack_review_sha":', 1))
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_invalid")
        self.assertAllowed(p.decide(p.event("Read", {"file_path": str(p.path("notes.txt"))})))
        path.write_bytes(original)
        fsutil.reserve(p.roots.inflight_file, "toolu_orphan")
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_invalid")


# =========================================================================== E11


class E11CanaryTests(S4Case):
    def test_canary_sequence(self) -> None:
        p = self.p
        p.prepare("critical", steps=BOUND_STEPS)
        compound = purge("u-1007") + " && " + purge("u-1015")
        self.assertDenied(p.decide(p.bash(compound)), "canary_first_unit")
        self.assertDenied(p.decide(p.bash(BULK_TWO)), "canary_first_unit")
        doc = p.doc()
        self.assertEqual((doc["units"], doc["executed_steps"]), ([], []))

        first = p.bash(purge("u-1007"))
        self.assertAllowed(p.decide(first))
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "inflight")
        p.settle(first, "ok")
        doc = p.doc()
        self.assertEqual((doc["canary"], doc["canary_unit"]), ("awaiting", 1))
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "canary_awaiting")
        p.verify(1, "UNMEASURED")
        self.assertEqual(p.doc()["canary"], "awaiting")
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "canary_awaiting")
        p.verify(1, "PASS")
        self.assertEqual(p.doc()["canary"], "passed")

        second = p.bash(purge("u-1015"))
        self.assertAllowed(p.decide(second))
        p.settle(second, "ok")
        third = p.bash(purge("u-1023"))
        self.assertAllowed(p.decide(third))
        p.settle(third, "failed")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "write_failed"))
        unit = doc["units"][2]
        self.assertEqual((unit["targets"], unit["outcome"], unit["verify"]),
                         (["users/u-1023"], "failed", None))  # fmt: skip
        self.assertDenied(p.decide(p.bash(purge("u-1031"))), "halted")
        self.assertEqual([u["n"] for u in unverified_units(doc)], [2, 3])

        p.resume()
        fourth = p.bash(purge("u-1031"))
        self.assertAllowed(p.decide(fourth))
        p.settle(fourth, "ok")
        doc = p.doc()
        self.assertEqual([u["n"] for u in unverified_units(doc)], [2, 3, 4])
        reuse = p.bash(purge("u-1042"), tool_use_id=first["tool_use_id"])
        self.assertDenied(p.decide(reuse), "duplicate_id")

    def test_failed_verify_of_canary_halts_and_never_counts_as_pass(self) -> None:
        p = self.p
        p.prepare("critical")
        first = p.bash(purge("u-1007"))
        self.assertAllowed(p.decide(first))
        p.settle(first, "ok")
        p.verify(1, "FAIL")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "verify_failed"))
        # _gate checks the awaiting canary (step 7) before the halt (step 8)
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "canary_awaiting")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "verify_failed"))
        self.assertEqual((len(doc["units"]), doc["inflight"]), (1, None))
        self.assertFalse(p.inflight_exists())
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])
        p.resume()
        self.assertEqual(p.doc()["canary"], "awaiting")
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "canary_awaiting")
        self.assertEqual([u["n"] for u in unverified_units(p.doc())], [1])

    def test_failed_or_unknown_first_unit_may_have_written(self) -> None:
        for outcome in ("failed", "unknown"):
            with self.subTest(outcome=outcome):
                p = Project(self)
                p.prepare("critical")
                first = p.bash(purge("u-1007"))
                self.assertAllowed(p.decide(first))
                p.settle(first, outcome)
                doc = p.doc()
                self.assertEqual(doc["state"], "halted")
                self.assertEqual(doc["canary"], "awaiting")
                self.assertEqual(doc["units"][0]["targets"], ["users/u-1007"])
                p.resume()
                self.assertDenied(p.decide(p.bash(purge("u-1015"))), "canary_awaiting")
                self.assertEqual([u["n"] for u in unverified_units(p.doc())], [1])

    def test_mismatched_result_halts_and_keeps_the_reservation(self) -> None:
        p = self.p
        p.prepare("critical")
        first = p.bash(purge("u-1007"))
        self.assertAllowed(p.decide(first))
        with self.assertRaises(StoreError) as caught:
            p.settle(first, "ok", fingerprint="0" * 64)
        self.assertEqual(getattr(caught.exception, "code", None), "settle_mismatch")
        doc = p.doc()
        self.assertEqual(doc["state"], "halted")
        self.assertEqual(doc["inflight"]["token"], first["tool_use_id"])
        self.assertTrue(p.inflight_exists())
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "halted")
        with self.assertRaises(StoreError):
            p.resume()  # a reservation needs an explicit human clear
        p.resume(clear_inflight=True)
        doc = p.doc()
        self.assertEqual((doc["units"][0]["outcome"], doc["canary"]), ("unknown", "awaiting"))
        self.assertFalse(p.inflight_exists())

    def test_missing_result_is_never_released_by_time(self) -> None:
        p = self.p
        p.prepare("critical")
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))
        p.clock.advance(3 * 3600)
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "inflight")
        self.assertTrue(p.inflight_exists())

    def test_replan_cannot_erase_executed_obligations(self) -> None:
        p = self.p
        p.prepare("critical")
        first = p.bash(purge("u-1007"))
        self.assertAllowed(p.decide(first))
        p.settle(first, "failed")
        p.resume()
        store = p.store()
        for action in (
            lambda: store.mark_planned(CHANGE_ID, "critical", p.plan_hash, OPERATOR),
            lambda: store.begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION),
            lambda: store.record_snapshot(CHANGE_ID, {}, p.plan_hash, OPERATOR),
        ):
            with self.assertRaises(StoreError):
                action()
        doc = p.doc()
        self.assertEqual(len(doc["units"]), 1)
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])


# =========================================================================== E14


class E14RedactionTests(S4Case):
    def test_known_secret_kinds_never_reach_the_ledger_or_the_reason(self) -> None:
        p = self.p
        policy, _ = p.runtime()
        for label, command, values in SECRET_CASES:
            with self.subTest(case=label):
                decision = p.decide(p.bash(command))
                self.assertFalse(decision.allowed)
                for value in values:
                    self.assertNoLeak(value, decision.reason)
        data = p.ledger_bytes()
        rows = ledger.read_jsonl_strict(data)
        self.assertEqual(len(rows), len(SECRET_CASES), "every deny needs one durable row")
        text = data.decode("ascii")
        for (label, command, values), row in zip(SECRET_CASES, rows, strict=True):
            with self.subTest(case=label):
                for value in values:
                    self.assertNoLeak(value, text)
                self.assertNotIn(sha256_text(command), text)
                redacted = ledger.redact(command, policy.extra_patterns)
                self.assertEqual(row["command_sha256"], sha256_text(redacted))
                self.assertNotIn("prev", row)

    def test_structured_mcp_secrets_are_dropped_whatever_their_shape(self) -> None:
        p = self.p
        tool_input = {
            "user": "u-1007",
            "password": ["McpListSENTINELa1"],
            "client_secret": {"value": "McpMapSENTINELb2"},
            "credentials": [{"token": "McpNestSENTINELc3"}],
            "apiKey": 31337,
            "note": "Bearer McpNoteSENTINELd4",
        }
        decision = p.decide(p.event("mcp__contosoadmin__rotate_secret", tool_input))
        self.assertFalse(decision.allowed)
        text = p.ledger_bytes().decode("ascii")
        for value in ("McpListSENTINELa1", "McpMapSENTINELb2", "McpNestSENTINELc3",
                      "McpNoteSENTINELd4"):  # fmt: skip
            self.assertNoLeak(value, text)
            self.assertNoLeak(value, decision.reason)
        self.assertNotIn("31337", self.last_row()["command_redacted"])

    def test_long_commands_are_redacted_before_they_are_cut(self) -> None:
        p = self.p
        filler = " ".join(["contoso"] * 80)
        many = " ".join(["segment"] * 1300)  # > 8 KiB of short words
        cases = (
            ("LongCutSENTINELpw0", f"az x {filler[:497]} --password=LongCutSENTINELpw0 {filler}"),
            ("TailSENTINELpw1", f"az x {many} --password=TailSENTINELpw1"),
        )
        for secret, command in cases:
            with self.subTest(secret=secret):
                self.assertFalse(p.decide(p.bash(command)).allowed)
                row = self.last_row()
                self.assertLessEqual(len(row["command_redacted"]), ledger.MAX_COMMAND_CHARS)
                self.assertTrue(row["command_redacted"].endswith("...[cut]"))
                self.assertNoLeak(secret, p.ledger_bytes().decode("ascii"))
                self.assertNotIn(sha256_text(command), p.ledger_bytes().decode("ascii"))
        for line in p.ledger_bytes().split(b"\n")[:-1]:
            self.assertLessEqual(len(line) + 1, ledger.MAX_ROW_BYTES)

    def test_allowed_write_with_a_secret_keeps_no_raw_secret_or_raw_hash(self) -> None:
        p = self.p
        command = "python3 scripts/bulk.py --password=StepPwSENTINELz9"
        step = {"id": "rotate", "command": command, "targets": ["users/u-1007"]}
        p.prepare("critical", steps=[step])
        ev = p.bash(command)
        self.assertAllowed(p.decide(ev))
        p.settle(ev, "ok")
        raw_fp = hashlib.sha256(
            schema.canonical_json({"input": ev["tool_input"], "tool": "Bash"}).encode("ascii")
        ).hexdigest()
        for blob in (p.ledger_bytes().decode("ascii"), p.state_bytes().decode("utf-8")):
            self.assertNoLeak("StepPwSENTINELz9", blob)
            self.assertNotIn(sha256_text(command), blob)
            self.assertNotIn(raw_fp, blob)

    def test_hook_process_stdout_and_stderr_hold_no_secret(self) -> None:
        p = self.p
        p.install()
        label, command, values = SECRET_CASES[0]
        proc = p.run(p.guard_argv(), p.bash(command))
        self.assertEqual(proc.returncode, 2, label)
        for value in values:
            self.assertNoLeak(value, proc.stdout.decode("ascii"))
            self.assertNoLeak(value, proc.stderr.decode("utf-8", "replace"))
            self.assertNoLeak(value, p.ledger_bytes().decode("ascii"))


# =========================================================================== ledger x guard


class GuardLedgerFailureTests(S4Case):
    def test_ledger_lock_timeout_denies_reads_and_halts_reserved_writes(self) -> None:
        p = self.p
        p.prepare("critical")
        paths.ensure_dir(str(p.project), "audit", "ledger")
        read = p.bash(sim("list users"))
        write = p.bash(purge("u-1007"))
        with fsutil.locked(p.roots.ledger_lock, 2.0):
            self.assertDenied(p.decide(read, ledger_timeout=0.05), "ledger_error")
            self.assertDenied(p.decide(write, ledger_timeout=0.05), "ledger_error")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "ledger_error"))
        self.assertEqual(doc["inflight"]["token"], write["tool_use_id"])
        self.assertTrue(p.inflight_exists())
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "halted")

    def test_truncated_tail_is_left_alone_and_never_allows(self) -> None:
        p = self.p
        p.prepare("critical")
        month = p.ledger_files()[-1]
        with month.open("ab") as handle:
            handle.write(b'{"v":1,"event":"pre","decision":"al')
        before = month.read_bytes()
        self.assertDenied(p.decide(p.bash(sim("list users"))), "ledger_error")
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "ledger_error")
        self.assertEqual(month.read_bytes(), before)
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "ledger_error"))

    def test_state_lock_timeout_denies(self) -> None:
        p = self.p
        p.prepare("critical")
        with fsutil.locked(p.roots.state_lock, 2.0):
            self.assertDenied(p.decide(p.bash(purge("u-1007")), lock_timeout=0.05), "lock_timeout")
        self.assertFalse(p.inflight_exists())

    def test_registry_lock_held_is_not_an_approval(self) -> None:
        p = self.p
        p.prepare("critical")
        with fsutil.locked(p.roots.approvals_lock, 5.0):
            self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_invalid")
        self.assertFalse(p.inflight_exists())

    def test_state_commit_failure_releases_or_keeps_blocking(self) -> None:
        p = self.p
        p.prepare("critical")
        real = fsutil.atomic_write
        target = os.path.join(".cab", "state", "changes", f"{CHANGE_ID}.json")

        def failing(path: Any, data: bytes, **kw: Any) -> None:
            if os.fspath(path).endswith(target):
                raise OSError(28, "fixture: no space left")
            real(path, data, **kw)

        with mock.patch.object(fsutil, "atomic_write", failing):
            self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_error")
        self.assertFalse(p.inflight_exists())
        self.assertEqual(p.doc()["units"], [])

        mismatch = fsutil.ReservationMismatch("fixture: release failed")
        with (
            mock.patch.object(fsutil, "atomic_write", failing),
            mock.patch.object(fsutil, "release", side_effect=mismatch),
        ):
            self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_error")
        # no imaginary rollback: the orphan reservation stays and blocks every write
        self.assertTrue(p.inflight_exists())
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_invalid")
        p.resume(clear_inflight=True)
        self.assertFalse(p.inflight_exists())
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))


# =========================================================================== intake


CAB_CLI = ".claude/hooks/cab/cab"
# Only this exact literal shape of the pinned CLI is an agent intake call (guard step 1a).
INTAKE_FIXTURE_ALLOWED = (
    f"{CAB_CLI} intake CHG-0001 --from-file work/intake.toml",
    f"{CAB_CLI} intake CHG-0001 --from-file 'work/my answers.toml'",
    f'{CAB_CLI} intake CHG-0001 --from-file "work/intake.toml"',
    f"'{CAB_CLI}' intake CHG-0001 --from-file work/intake.toml",
)
# Interactive intake, malformed fixture shapes and every wrapper: human-only (step 2).
INTAKE_AGENT_DENIED = (
    f"{CAB_CLI} intake CHG-0001",
    f"{CAB_CLI} 'intake' CHG-0001",
    f"{CAB_CLI} in''take CHG-0001",
    f"{CAB_CLI} INTAKE CHG-0001",
    f"{CAB_CLI} intake CHG-0001 --from-file",
    f"{CAB_CLI} intake CHG-0001 --from-file=work/intake.toml",
    f"{CAB_CLI} intake --from-file work/intake.toml CHG-0001",
    f"{CAB_CLI} intake CHG-0001 --from-file work/intake.toml extra",
    f"{CAB_CLI} intake CHG-0001 --from-file work/intake.toml; {CAB_CLI} intake CHG-0001",
    f"{CAB_CLI} intake CHG-0001 < work/answers.txt",
    f"printf 'a\\nb\\n' | {CAB_CLI} intake CHG-0001",
    f"bash -c '{CAB_CLI} intake CHG-0001'",
    f'sh -c "{CAB_CLI} intake CHG-0001 --from-file work/intake.toml"',
    f"env CONTOSO=1 {CAB_CLI} intake CHG-0001",
    f"script -q /dev/null {CAB_CLI} intake CHG-0001",
    f"script -q /dev/null {CAB_CLI} intake CHG-0001 --from-file work/intake.toml",
    f"script -qc '{CAB_CLI} intake CHG-0001' /dev/null",
    f"unbuffer {CAB_CLI} intake CHG-0001",
    f"expect -c 'spawn {CAB_CLI} intake CHG-0001; interact'",
    f'python3 -c \'import pty; pty.spawn(["{CAB_CLI}", "intake", "CHG-0001"])\'',
    f"socat - EXEC:'{CAB_CLI} intake CHG-0001',pty",
    f"tmux new-session '{CAB_CLI} intake CHG-0001'",
    "cab intake CHG-0001",
    "python3 -m cab_of_one intake CHG-0001",
    "bash scripts/run-intake.sh",
)


class IntakeGuardTests(S4Case):
    """Agent calls of ``cab intake``: only the exact fixture form passes (main session).

    Fixture data only; the pinned CLI file is a fictional stub and nothing is executed."""

    def setUp(self) -> None:
        super().setUp()
        self.p.write(CAB_CLI, "#!/bin/sh\n# fictional pinned cab entry\n")
        self.p.write("scripts/run-intake.sh", f"{CAB_CLI} intake CHG-0001\n")

    def absolute(self) -> str:
        return shlex.quote(str(self.p.path(CAB_CLI)))

    def assert_row(self, ev: Mapping[str, Any], decision: str, code: str) -> None:
        row = self.last_row()
        self.assertEqual(
            (row["decision"], row["reason_code"], row["tool_use_id"]),
            (decision, code, ev["tool_use_id"]),
        )

    def test_exact_fixture_form_stays_an_agent_call(self) -> None:
        p = self.p
        cases = [(c, None) for c in INTAKE_FIXTURE_ALLOWED]
        cases.append((f"{self.absolute()} intake CHG-0001 --from-file work/intake.toml",
                      str(p.path("work"))))  # fmt: skip
        for command, cwd in cases:
            with self.subTest(command=command):
                self.assertTrue(guard._fixed_cli(command, cwd or str(p.project), p.roots))
                ev = p.bash(command, cwd=cwd)
                self.assertAllowed(p.decide(ev))
                self.assert_row(ev, "allow", "cab_cli")

    def test_interactive_intake_and_wrappers_are_human_only(self) -> None:
        p = self.p
        commands = (*INTAKE_AGENT_DENIED, f"{self.absolute()} intake CHG-0001")
        for command in commands:
            with self.subTest(command=command):
                self.assertFalse(guard._fixed_cli(command, str(p.project), p.roots))
                ev = p.bash(command)
                decision = p.decide(ev)
                self.assertDenied(decision, "approval_cmd")
                self.assertIn("interactive cab intake", decision.reason)
                self.assert_row(ev, "deny", "approval_cmd")

    def test_subagents_never_run_intake(self) -> None:
        p = self.p
        extra = {"agent_id": "agent-0001", "agent_type": "runbook-author"}
        for command in (INTAKE_FIXTURE_ALLOWED[0], f"{CAB_CLI} intake CHG-0001"):
            with self.subTest(command=command):
                ev = p.bash(command, extra=extra)
                self.assertDenied(p.decide(ev), "approval_cmd")

    def test_reading_intake_files_is_not_an_intake_call(self) -> None:
        p = self.p
        for command in (
            f"cat {CHANGE_DIR}/intake.md",
            f"grep -n Purpose {CHANGE_DIR}/intake.md",
            "cat work/intake.toml",
            "ls .claude/skills/change-intake",
        ):
            with self.subTest(command=command):
                self.assertAllowed(p.decide(p.bash(command)))


if __name__ == "__main__":
    unittest.main()
