"""Classifier x real simtenant integration (S3). Fictional Contoso data only.

Every command string is classified first and then executed through the real
simtenant CLI entry point (``simtenant.run``) with the same argv, from the
project root, against state files under <project>/.local/test-tmp/ only.
No network, no real tenant, no subprocess. The classifier's view (kind,
targets, state scope, tier) is compared with what the real CLI accepts and
with which objects really changed.
"""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import json
import shlex
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "simtenant" / "simtenant.py"
TMP_ROOT = ROOT / ".local" / "test-tmp"
sys.path.insert(0, str(ROOT / "src"))

from cab_of_one.runtime.adapters import simtenant as adapter  # noqa: E402
from cab_of_one.runtime.classification_types import leaves  # noqa: E402
from cab_of_one.runtime.classify import (  # noqa: E402
    catalog_match,
    classify_tool_call,
    decide_tier,
    tier_floor,
)
from cab_of_one.runtime.planhash import plan_hash  # noqa: E402


def _load_simtenant():
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # no __pycache__ next to the module
    try:
        spec = importlib.util.spec_from_file_location("simtenant_for_classifier_tests", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


st = _load_simtenant()

T0 = 1_800_000_000.0
PROGRAM = "python3 simtenant/simtenant.py"
POLICY = {
    "tiers": {"critical_patterns": []},
    "classifier": {"trusted_simtenant_scripts": ["simtenant/simtenant.py"]},
}
SAFE = {"reversible": True, "has_dependents": False, "targets_enumerated": True}
NEW_USER = {
    "display_name": "Test User 2009",
    "given_name": "Test",
    "surname": "User2009",
    "user_principal_name": "test.user2009@contoso.example",
    "mail": None,
    "department": None,
    "job_title": None,
    "account_enabled": True,
    "usage_location": "US",
    "manager_id": None,
}


def classify(command: str):
    return classify_tool_call(
        "Bash", {"command": command}, policy=POLICY, read_file=lambda path: None
    )


def tier(r, entries, answers=None, irreversible=False):
    return decide_tier(
        answers or SAFE,
        irreversible=irreversible,
        catalog_hit=catalog_match(r, entries),
        floor=tier_floor(r, POLICY),
    )


class IntegrationCase(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="classifier-", dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        rel = self.tmp.relative_to(ROOT).as_posix()
        self.state = f"{rel}/state.json"
        self.other = f"{rel}/other.json"
        self.assertEqual(self.execute(self.cmd("reset"))[0], 0)

    # -- helpers

    def cmd(self, words: str, state: str | None = None) -> str:
        return f"{PROGRAM} --state {state or self.state} {words}"

    def execute(self, command: str):
        argv = shlex.split(command)
        self.assertEqual(argv[:2], ["python3", "simtenant/simtenant.py"])
        with contextlib.chdir(ROOT):
            return st.run(argv[2:], clock=lambda: T0)

    def snapshot(self, state: str | None = None) -> dict:
        data = json.loads((ROOT / (state or self.state)).read_text(encoding="utf-8"))
        flat = {}
        for section in ("objects", "deleted", "purged_ids"):
            for res, items in data[section].items():
                for oid, obj in items.items():
                    flat[(section, res, oid)] = obj
        return flat

    def changed_targets(self, before: dict, after: dict) -> set[str]:
        keys = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        return {f"{res}/{oid}" for _, res, oid in keys}

    def entry(self, **overrides) -> dict:
        base = {
            "id": "dl-member-add",
            "enabled": True,
            "adapter": "simtenant",
            "command_pattern": "simtenant add groups g-2017 --member *",
            "target_scope": ["groups/g-2017"],
            "state_scope": self.state,
        }
        base.update(overrides)
        return base


class TestRealFlow(IntegrationCase):
    def test_reset_classify_execute_query(self):
        reset = classify(self.cmd("reset"))
        self.assertEqual((reset.kind, reset.unknown), ("write", False))
        self.assertIn("tenant_wide", reset.flags)
        self.assertEqual(tier_floor(reset, POLICY), "critical")
        self.assertIsNone(catalog_match(reset, [self.entry(command_pattern="*")]))

        add = self.cmd("add groups g-2017 --member u-1050")
        r = classify(add)
        self.assertEqual(
            (r.kind, r.unknown, r.targets, r.targets_complete, r.scope),
            ("write", False, ("groups/g-2017",), True, self.state),
        )
        self.assertEqual(catalog_match(r, [self.entry()]), "dl-member-add")
        self.assertEqual(tier(r, [self.entry()]), "standard")
        before = self.snapshot()
        code, payload = self.execute(add)
        self.assertEqual((code, payload["ok"], payload["changed"]), (0, True, True))
        self.assertEqual(self.changed_targets(before, self.snapshot()), set(r.targets))

        get = self.cmd("get groups g-2017")
        read = classify(get)
        self.assertEqual((read.kind, read.targets), ("read", ("groups/g-2017",)))
        before = self.snapshot()
        code, payload = self.execute(get)
        self.assertEqual(code, 0)
        self.assertIn("u-1050", payload["object"]["members"])
        self.assertEqual(self.snapshot(), before)

    def test_classified_targets_equal_objects_really_changed(self):
        commands = [
            self.cmd("add groups g-2005 --member u-1023"),
            self.cmd("set mailboxes mbx-1042 --field forwarding_smtp_address --value null"),
            self.cmd("delete users u-1050"),
            self.cmd(f"add users u-2009 --record {shlex.quote(json.dumps(NEW_USER))}"),
        ]
        r = classify("\n".join(commands))
        self.assertEqual((r.kind, r.unknown, r.targets_complete), ("write", False, True))
        fixture = self.tmp / "targets.txt"  # stands in for the plan's enumerated targets
        fixture.write_text("\n".join(r.targets) + "\n", encoding="utf-8")
        before = self.snapshot()
        for command in commands:
            self.assertEqual(self.execute(command)[0], 0, command)
        enumerated = set(fixture.read_text(encoding="utf-8").split())
        self.assertEqual(self.changed_targets(before, self.snapshot()), enumerated)

    def test_plan_hash_binds_the_classified_targets(self):
        add = self.cmd("add groups g-2017 --member u-1050")
        r = classify(add)
        self.assertEqual(
            (r.kind, r.unknown, r.targets, r.targets_complete),
            ("write", False, ("groups/g-2017",), True),
        )
        change = self.tmp / "CHG-0001"
        change.mkdir()
        baseline = {
            "change.toml": (
                f'id = "CHG-0001"\ntier = "standard"\ncommand = {json.dumps(add)}\n'
            ).encode(),
            "plan.md": f"# Add u-1050 to g-2017 (fictional)\n\n```\n{add}\n```\n".encode(),
            "targets.csv": ("target\n" + "".join(f"{t}\n" for t in r.targets)).encode(),
        }
        for name, data in baseline.items():
            (change / name).write_bytes(data)
        approved = plan_hash(change)
        for name, data in baseline.items():  # rewriting identical bytes keeps the hash
            (change / name).write_bytes(data)
        self.assertEqual(plan_hash(change), approved)

        def planned_command() -> str:
            return tomllib.loads((change / "change.toml").read_text(encoding="utf-8"))["command"]

        def planned_targets() -> set[str]:
            with (change / "targets.csv").open(newline="", encoding="utf-8") as fh:
                return {row["target"] for row in csv.DictReader(fh)}

        self.assertEqual(planned_command(), add)
        enumerated = planned_targets()
        self.assertEqual(enumerated, set(r.targets))
        before = self.snapshot()
        code, payload = self.execute(planned_command())
        self.assertEqual((code, payload["ok"], payload["changed"]), (0, True, True))
        self.assertEqual(self.changed_targets(before, self.snapshot()), enumerated)
        self.assertEqual(plan_hash(change), approved)  # executing does not touch the plan

        extra_cmd = self.cmd("add groups g-2005 --member u-1023")
        extra = classify(extra_cmd)
        self.assertEqual(
            (extra.kind, extra.unknown, extra.targets, extra.targets_complete),
            ("write", False, ("groups/g-2005",), True),
        )
        self.assertNotIn(extra.targets[0], enumerated)
        before = self.snapshot()
        self.assertEqual(self.execute(extra_cmd)[0], 0)  # a real target outside the plan
        self.assertEqual(self.changed_targets(before, self.snapshot()), set(extra.targets))

        mutations = {
            "targets.csv": baseline["targets.csv"] + f"{extra.targets[0]}\n".encode(),
            "change.toml": baseline["change.toml"].replace(add.encode(), extra_cmd.encode()),
            "plan.md": baseline["plan.md"].replace(add.encode(), extra_cmd.encode()),
        }
        checks = {
            "targets.csv": lambda: self.assertEqual(
                planned_targets(), enumerated | set(extra.targets)
            ),
            "change.toml": lambda: self.assertEqual(planned_command(), extra_cmd),
            "plan.md": lambda: self.assertIn(extra_cmd, (change / "plan.md").read_text("utf-8")),
        }
        seen = {approved}
        for name, mutated in mutations.items():
            with self.subTest(file=name):
                self.assertNotEqual(mutated, baseline[name])
                try:
                    (change / name).write_bytes(mutated)
                    checks[name]()
                    amended = plan_hash(change)
                    self.assertNotEqual(amended, approved)
                    self.assertNotIn(amended, seen)
                    seen.add(amended)
                finally:
                    (change / name).write_bytes(baseline[name])
                self.assertEqual(plan_hash(change), approved)
        self.assertEqual(len(seen), 4)


class TestContractParity(IntegrationCase):
    def test_commands_the_classifier_understands_run_on_the_real_cli(self):
        record = shlex.quote(json.dumps(NEW_USER))
        cases = [
            ("list users", "read"),
            ("list groups --deleted", "read"),
            ("get mailbox mbx-3001", "read"),
            ("get Users u-1042", "read"),
            ("set users u-1142 --field job_title --value 'Senior AE'", "write"),
            ("set mailboxes mbx-1042 --field forwarding_smtp_address --value null", "write"),
            ("add groups g-2005 --member u-1023", "write"),
            ("remove groups g-2005 --member u-1023", "write"),
            ("add licenses lic-5003 --member u-1142", "write"),
            ("remove licenses lic-5003 --member u-1142", "write"),
            ("add policies pol-4001 --member g-2001", "write"),
            (f"add users u-2009 --record {record}", "write"),
            ("delete users u-1050 --delay-seconds 0", "write"),
            ("restore users u-1050", "write"),
            ("set users u-1142 --field department --value Marketing --dry-run", "write"),
            ("purge users u-1142 --lie", "write"),
            ("reset --seed simtenant/seed/contoso.json", "write"),
        ]
        for words, kind in cases:
            with self.subTest(words=words):
                command = self.cmd(words)
                r = classify(command)
                self.assertEqual((r.kind, r.unknown), (kind, False), r.reasons)
                code, payload = self.execute(command)
                self.assertEqual(code, 0, payload)

    def test_commands_the_real_cli_rejects_are_unknown_and_change_nothing(self):
        for words in (
            "get devices d-1001",
            "get domains contoso.example",
            "get users U-1042",
            "get users u-1",
            "delete users g-2001",
            "add groups g-2001 --member g-2017",
            "add users u-1042 --member u-1007",
            "add groups g-2017 --member 'Jordan Reyes'",
            "set users u-1042 --field id --value u-9999",
            "set groups g-2001 --field members --value '[]'",
            "get users u-1042 --lie",
            "list users --dry-run",
            "reset users",
            "add groups g-2001",
            "delete users u-1042 --delay-seconds 86401",
            "frobnicate users u-1042",
            "add users u-2010 --record '[1]'",
        ):
            with self.subTest(words=words):
                command = self.cmd(words)
                r = classify(command)
                self.assertEqual((r.kind, r.unknown, r.targets_complete), ("write", True, False))
                before = self.snapshot()
                code, payload = self.execute(command)
                self.assertNotEqual(code, 0, payload)
                self.assertEqual(self.snapshot(), before)

    def test_adapter_tables_match_the_real_schema(self):
        self.assertEqual(adapter.RESOURCES, st.RESOURCES)
        self.assertEqual(adapter.RESOURCE_ALIASES, st.RESOURCE_ALIASES)
        self.assertEqual(adapter.PREFIX_TO_RESOURCE, st.PREFIX_TO_RESOURCE)
        self.assertEqual(adapter.MAX_DELAY_SECONDS, st.MAX_DELAY_SECONDS)
        for res, schema in st.SCHEMA.items():
            with self.subTest(resource=res):
                modes = {name: spec["mode"] for name, spec in schema["fields"].items()}
                mutable = {n for n, m in modes.items() if m == "mutable"}
                extra = {"id"} | {n for n, m in modes.items() if m in ("create_only", "relation")}
                self.assertEqual(adapter.MUTABLE_FIELDS[res], mutable)
                self.assertEqual(adapter.RECORD_EXTRA_FIELDS[res], extra)
                self.assertEqual(adapter.MEMBER_KINDS[res], tuple(schema["member_kinds"]))
        for sample in ("u-1042", "U-1042", "u-1", "u-123456789", "mbx-3001", "g-2001x", "d-1001"):
            with self.subTest(id=sample):
                self.assertEqual(bool(adapter.ID_RE.match(sample)), bool(st.ID_RE.match(sample)))

    def test_every_seed_object_and_relation_is_a_complete_target(self):
        data = json.loads((ROOT / self.state).read_text(encoding="utf-8"))
        for res, items in data["objects"].items():
            rel = st.SCHEMA[res]["relation"]
            for oid, obj in items.items():
                with self.subTest(target=f"{res}/{oid}"):
                    r = classify(self.cmd(f"get {res} {oid}"))
                    self.assertEqual(
                        (r.kind, r.targets, r.targets_complete), ("read", (f"{res}/{oid}",), True)
                    )
                for member in obj.get(rel, []) if rel else []:
                    with self.subTest(member=f"{res}/{oid} {member}"):
                        w = classify(self.cmd(f"remove {res} {oid} --member {member}"))
                        self.assertEqual(
                            (w.kind, w.unknown, w.targets_complete), ("write", False, True)
                        )


class TestStateScope(IntegrationCase):
    def test_other_state_file_never_matches_the_catalogue(self):
        self.assertEqual(self.execute(self.cmd("reset", self.other))[0], 0)
        entries = [self.entry()]
        mine = classify(self.cmd("add groups g-2017 --member u-1050"))
        theirs = classify(self.cmd("add groups g-2017 --member u-1050", self.other))
        self.assertEqual(mine.canonical, theirs.canonical)  # canonical stays verb-centred
        self.assertEqual(catalog_match(mine, entries), "dl-member-add")
        self.assertIsNone(catalog_match(theirs, entries))
        self.assertEqual(tier(theirs, entries), "normal")
        both = classify(
            self.cmd("add groups g-2017 --member u-1050")
            + " && "
            + self.cmd("add groups g-2017 --member u-1023", self.other)
        )
        self.assertIsNone(catalog_match(both, entries))
        absolute = shlex.quote(str(ROOT / self.state))
        same_file = classify(self.cmd("add groups g-2017 --member u-1050", absolute))
        self.assertIsNone(same_file.scope)
        self.assertIsNone(catalog_match(same_file, entries))
        self.assertEqual(
            self.execute(self.cmd("add groups g-2017 --member u-1023", self.other))[0], 0
        )
        self.assertNotIn("u-1023", self.snapshot()[("objects", "groups", "g-2017")]["members"])

    def test_directory_change_or_nested_shell_drops_trust(self):
        inner = self.cmd("get users u-1042")
        for command in (
            f"cd .local; {inner}",
            f"cd .local; bash -c {shlex.quote(inner)}",
            f"cd .local && sh -c {shlex.quote('bash -c ' + shlex.quote(inner))}",
        ):
            with self.subTest(command=command):
                r = classify(command)
                self.assertEqual((r.kind, r.unknown), ("write", True))
        nested = classify(f"bash -c {shlex.quote(inner)}")
        self.assertEqual((nested.kind, nested.scope), ("read", self.state))


class TestCatalogueAndFloor(IntegrationCase):
    def test_unsupported_targets_are_never_standard(self):
        wide = self.entry(command_pattern="*", target_scope=["groups/g-2017", "users/u-1042"])
        for words in (
            "add groups g-2017 --member 'Jordan Reyes'",
            "add groups g-2017 --member g-2001",
            "delete users U-1042",
            "get devices d-1001",
        ):
            with self.subTest(words=words):
                r = classify(self.cmd(words))
                self.assertIsNone(catalog_match(r, [wide]))
                self.assertNotEqual(tier(r, [wide]), "standard")
        ps = classify("pwsh -NoProfile -Command 'Set-MgUser -UserId u-1042 -Department Sales'")
        self.assertIsNone(catalog_match(ps, [dict(wide, adapter="m365-powershell")]))

    def test_target_scope_and_every_write_leaf(self):
        entries = [self.entry()]
        self.assertIsNone(
            catalog_match(classify(self.cmd("add groups g-2001 --member u-1050")), entries)
        )
        composite = classify(
            self.cmd("add groups g-2017 --member u-1050") + "\n" + self.cmd("delete users u-1042")
        )
        self.assertIsNone(catalog_match(composite, entries))
        self.assertIsNone(
            catalog_match(
                classify(self.cmd("add groups g-2017 --member u-1050")),
                [self.entry(state_scope=None)],
            )
        )

    def test_licence_reclaim_policy_write_and_hold_release_stay_critical(self):
        def field(res, oid, name):
            return lambda s: s[("objects", res, oid)][name]

        cases = [
            (
                "remove licenses lic-5001 --member u-1042",
                lambda s: "u-1042" not in field("licenses", "lic-5001", "assigned_to")(s),
            ),
            (
                "set policies pol-4001 --field state --value disabled",
                lambda s: field("policies", "pol-4001", "state")(s) == "disabled",
            ),
            (
                "remove policies pol-4002 --member g-2010",
                lambda s: field("policies", "pol-4002", "include")(s) == [],
            ),
            (
                "set mailboxes mbx-3001 --field litigation_hold_enabled --value false",
                lambda s: field("mailboxes", "mbx-3001", "litigation_hold_enabled")(s) is False,
            ),
            ("purge users u-1142 --dry-run", lambda s: ("purged_ids", "users", "u-1142") in s),
        ]
        for words, effect in cases:
            with self.subTest(words=words):
                command = self.cmd(words)
                r = classify(command)
                self.assertEqual((r.kind, r.unknown, r.targets_complete), ("write", False, True))
                covering = self.entry(command_pattern="*", target_scope=list(r.targets))
                self.assertEqual(catalog_match(r, [covering]), "dl-member-add")
                self.assertEqual(tier_floor(r, POLICY), "critical")
                self.assertEqual(tier(r, [covering]), "critical")
                code, payload = self.execute(command)
                self.assertEqual(code, 0, payload)
                self.assertTrue(effect(self.snapshot()), words)


class TestSecurityCounterexamples(IntegrationCase):
    def test_review_probes_are_closed(self):
        for command in (
            "pwsh -NoProfile -Command 'Get-MgUser -Property @{Name=(Remove-MgUser -UserId u-1)}'",
            "pwsh -NoProfile -Command 'Write-Output @{Name=(Remove-MgUser -UserId u-1)}'",
            "curl -K request.conf",
            "curl --config request.conf",
            "curl -H @headers.txt https://example.com/",
            "curl -X DELETE https://graph.microsoft.com/v1.0/users/u-1 "
            "-X GET https://graph.microsoft.com/v1.0/users/u-2",
            f"cd other; bash -c {shlex.quote(self.cmd('get users u-1042'))}",
        ):
            with self.subTest(command=command):
                r = classify(command)
                self.assertEqual((r.kind, r.unknown), ("write", True), r.reasons)
                self.assertIsNone(catalog_match(r, [self.entry(command_pattern="*")]))
        for command in (
            "pwsh -NoProfile -Command 'Get-MgUser -Property @{Name=(Remove-MgUser -UserId u-1)}'",
            "pwsh -NoProfile -Command 'Write-Output @{Name=(Remove-MgUser -UserId u-1)}'",
        ):
            with self.subTest(floor=command):
                self.assertEqual(tier_floor(classify(command), POLICY), "critical")

    def test_dry_run_and_lie_never_lower(self):
        r = classify(self.cmd("purge users u-1042 --dry-run --lie"))
        self.assertEqual(r.kind, "write")
        self.assertEqual(tier_floor(r, POLICY), "critical")
        self.assertTrue(all(leaf.kind == "write" for leaf in leaves(r)))


if __name__ == "__main__":
    unittest.main()
