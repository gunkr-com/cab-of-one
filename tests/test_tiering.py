"""Tier golden set (DESIGN §6-2 G) and catalogue/floor invariants.

The 15 golden cases are loaded from evals/tiering/cases.toml, the single source
of truth; nothing here repeats them. All data is fictional Contoso. Every
critical result comes from the core floor, the irreversible flag or Q1; none
depends on a user-added pattern unless a test says so in its policy.
"""

from __future__ import annotations

import inspect
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cab_of_one.runtime.classification_types import leaves  # noqa: E402
from cab_of_one.runtime.classify import (  # noqa: E402
    catalog_match,
    classify_tool_call,
    decide_tier,
    tier_floor,
)

CASES_FILE = ROOT / "evals" / "tiering" / "cases.toml"


def load_cases() -> dict:
    with CASES_FILE.open("rb") as handle:
        return tomllib.load(handle)


EVAL = load_cases()
POLICY = EVAL["policy"]
CATALOGS = EVAL["catalogs"]
CASES = EVAL["case"]
DL_ADD = CATALOGS["on"][0]  # the enabled distribution-list entry

SAFE = {"reversible": True, "has_dependents": False, "targets_enumerated": True}
S = "simtenant --state s.json"


def command_of(case: dict) -> str:
    if "command" in case:
        return case["command"]
    spec = case["expand"]
    template = case["command_template"]
    numbers = range(spec["start"], spec["start"] + spec["count"])
    return "\n".join(template.replace("{n}", str(n)) for n in numbers)


def classify(cmd, policy=POLICY):
    return classify_tool_call("Bash", {"command": cmd}, policy=policy, read_file=lambda path: None)


def tier_for(cmd, answers, irreversible, catalog, policy=POLICY):
    r = classify(cmd, policy)
    floor = tier_floor(r, policy)
    hit = catalog_match(r, CATALOGS[catalog] if isinstance(catalog, str) else catalog)
    return decide_tier(answers, irreversible=irreversible, catalog_hit=hit, floor=floor), r


def writes_of(r):
    return [leaf for leaf in leaves(r) if leaf.kind == "write"]


class GoldenTests(unittest.TestCase):
    def test_file_shape(self):
        self.assertEqual(EVAL["schema"], 1)
        self.assertEqual([c["id"] for c in CASES], [f"G{k:02d}" for k in range(1, 16)])
        expected = {c["id"]: c["expected"] for c in CASES}
        self.assertEqual(
            expected,
            {
                "G01": "standard",
                "G02": "normal",
                "G03": "standard",
                "G04": "critical",
                "G05": "normal",
                "G06": "normal",
                "G07": "normal",
                "G08": "critical",
                "G09": "blocked",
                "G10": "critical",
                "G11": "normal",
                "G12": "normal",
                "G13": "critical",
                "G14": "normal",
                "G15": "critical",
            },
        )
        self.assertEqual(POLICY["tiers"]["critical_patterns"], [])

    def test_golden_15(self):
        for case in CASES:
            with self.subTest(case=case["id"]):
                tier, r = tier_for(
                    command_of(case), case["answers"], case["irreversible"], case["catalog"]
                )
                self.assertEqual(r.kind, "write", (case["id"], r.reasons))
                self.assertFalse(r.unknown, (case["id"], r.reasons))
                self.assertEqual(len(writes_of(r)), case["target_count"], case["id"])
                self.assertEqual(tier, case["expected"], (case["id"], r.canonical, r.reasons))

    def test_g03_really_classifies_500_distinct_commands(self):
        case = next(c for c in CASES if c["id"] == "G03")
        r = classify(command_of(case))
        writes = writes_of(r)
        self.assertEqual(len(writes), 500)
        members = {w.canonical.rsplit(" ", 1)[1] for w in writes}
        self.assertEqual(len(members), 500)
        self.assertEqual(min(members), "u-3000")
        self.assertEqual(max(members), "u-3499")
        self.assertEqual(r.targets, ("groups/g-2017",))
        self.assertTrue(r.targets_complete)
        self.assertEqual(r.scope, "s.json")
        self.assertEqual(catalog_match(r, CATALOGS["on"]), "dl-member-add")

    def test_target_count_is_not_an_input(self):
        params = set(inspect.signature(decide_tier).parameters)
        self.assertEqual(params, {"answers", "irreversible", "catalog_hit", "floor"})
        by_id = {c["id"]: c for c in CASES}
        self.assertEqual(by_id["G01"]["expected"], by_id["G03"]["expected"])

    def test_more_objects_do_not_change_the_tier(self):
        def adds(n):
            return " && ".join(f"{S} add groups g-2017 --member u-{3000 + k}" for k in range(n))

        def purges(n):
            return " && ".join(f"{S} purge users u-{1000 + k}" for k in range(n))

        for n in (1, 3, 12):
            with self.subTest(n=n):
                self.assertEqual(tier_for(adds(n), SAFE, False, "on")[0], "standard")
                self.assertEqual(tier_for(purges(n), SAFE, False, "none")[0], "critical")


class FloorTests(unittest.TestCase):
    def test_core_floor_cannot_be_removed_by_policy(self):
        r = classify(f"{S} purge users u-1042")
        self.assertEqual(tier_floor(r, POLICY), "critical")
        self.assertEqual(tier_floor(r, {"tiers": {"critical_patterns": []}}), "critical")

    def test_user_pattern_adds_critical(self):
        policy = dict(POLICY, tiers={"critical_patterns": ["simtenant * groups g-2005*"]})
        cmd = f"{S} add groups g-2005 --member u-1023"
        self.assertIsNone(tier_floor(classify(cmd), POLICY))
        self.assertEqual(tier_floor(classify(cmd, policy), policy), "critical")

    def test_reset_is_critical(self):
        self.assertEqual(tier_for(f"{S} reset", SAFE, False, "none")[0], "critical")
        self.assertEqual(
            tier_for(f"{S} reset --seed seed.json", SAFE, False, "none")[0], "critical"
        )

    def test_simtenant_policy_licence_and_hold_writes_are_critical(self):
        for cmd in (
            f"{S} set policies pol-4001 --field state --value disabled",
            f"{S} remove policies pol-4001 --member g-2005",
            f"{S} add policies pol-4002 --member u-1050",
            f"{S} delete policies pol-4003",
            f"{S} set policies pol-4004 --field controls --value '[]'",
            f"{S} remove licenses lic-5001 --member u-1042",
            f"{S} add licenses lic-5003 --member u-1142",
            f"{S} set licenses lic-5001 --field seats_total --value 7",
            f"{S} set mailboxes mbx-3001 --field litigation_hold_enabled --value false",
        ):
            with self.subTest(cmd=cmd):
                r = classify(cmd)
                self.assertEqual((r.kind, r.unknown), ("write", False), r.reasons)
                self.assertEqual(tier_floor(r, POLICY), "critical")
                self.assertEqual(tier_for(cmd, SAFE, False, "on")[0], "critical")

    def test_simtenant_reads_of_policies_and_licences_have_no_floor(self):
        for cmd in (f"{S} get policies pol-4001", f"{S} list licenses"):
            with self.subTest(cmd=cmd):
                self.assertIsNone(tier_floor(classify(cmd), POLICY))

    def test_unknown_admin_is_at_least_normal_and_never_standard(self):
        r = classify("python3 tool.py")
        self.assertTrue(r.unknown)
        self.assertEqual(tier_floor(r, POLICY), "normal")
        self.assertIsNone(catalog_match(r, CATALOGS["on"]))
        self.assertEqual(
            decide_tier(SAFE, irreversible=False, catalog_hit=None, floor="normal"), "normal"
        )

    def test_reads_have_no_floor(self):
        self.assertIsNone(
            tier_floor(classify("curl https://graph.microsoft.com/v1.0/domains"), POLICY)
        )


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.r = classify(f"{S} add groups g-2017 --member u-1050")

    def test_enabled_entry_matches(self):
        self.assertEqual(catalog_match(self.r, CATALOGS["on"]), "dl-member-add")

    def test_disabled_or_ambiguous_enabled_does_not_match(self):
        for enabled in (False, "true", 1, None):
            with self.subTest(enabled=enabled):
                self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, enabled=enabled)]))
        no_key = {k: v for k, v in DL_ADD.items() if k != "enabled"}
        self.assertIsNone(catalog_match(self.r, [no_key]))

    def test_scope_must_be_exact(self):
        self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, target_scope=["groups/g-*"])]))
        self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, target_scope=["groups/g-2001"])]))
        self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, target_scope="groups/g-2017")]))
        self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, adapter="azure-cli")]))
        other = classify(f"{S} add groups g-2001 --member u-1050")
        self.assertIsNone(catalog_match(other, CATALOGS["on"]))

    def test_state_scope_is_required_and_exact(self):
        no_scope = {k: v for k, v in DL_ADD.items() if k != "state_scope"}
        self.assertIsNone(catalog_match(self.r, [no_scope]))
        for bad in ("", "*.json", "s*.json", "./s.json", "/abs/s.json", "../s.json", 3, None):
            with self.subTest(state_scope=bad):
                self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, state_scope=bad)]))
        self.assertIsNone(catalog_match(self.r, [dict(DL_ADD, state_scope="b.json")]))

    def test_other_state_file_does_not_match(self):
        others = ("b.json", "sub/s.json", "/tmp/s.json", "../s.json", "~/s.json", "a/../s.json")
        for state in others:
            with self.subTest(state=state):
                r = classify(f"simtenant --state '{state}' add groups g-2017 --member u-1050")
                self.assertEqual((r.kind, r.unknown), ("write", False), r.reasons)
                self.assertIsNone(catalog_match(r, CATALOGS["on"]))
        same = classify("simtenant --state ./s.json add groups g-2017 --member u-1050")
        self.assertEqual(same.scope, "s.json")
        self.assertEqual(catalog_match(same, CATALOGS["on"]), "dl-member-add")

    def test_state_after_cd_has_no_scope(self):
        r = classify(f"cd other && {S} add groups g-2017 --member u-1050")
        self.assertEqual(r.kind, "write")
        self.assertIsNone(r.scope)
        self.assertIsNone(catalog_match(r, CATALOGS["on"]))

    def test_every_write_segment_must_be_covered(self):
        mixed = classify(f"{S} add groups g-2017 --member u-1050 && {S} delete users u-1042")
        self.assertIsNone(catalog_match(mixed, CATALOGS["on"]))
        cross = classify(
            f"{S} add groups g-2017 --member u-1050 && "
            "simtenant --state b.json add groups g-2017 --member u-1023"
        )
        self.assertIsNone(catalog_match(cross, CATALOGS["on"]))
        with_read = classify(
            f"simtenant --state b.json get users u-1042 && {S} add groups g-2017 --member u-1050"
        )
        self.assertEqual(catalog_match(with_read, CATALOGS["on"]), "dl-member-add")

    def test_incomplete_or_tenant_wide_targets_never_match(self):
        entry = {
            "id": "x",
            "enabled": True,
            "adapter": "simtenant",
            "command_pattern": "*",
            "target_scope": ["users/u-1042"],
            "state_scope": "s.json",
        }
        self.assertIsNone(catalog_match(classify(f"{S} reset"), [entry]))
        self.assertIsNone(
            catalog_match(
                classify("pwsh -Command 'Set-MgUser -UserId u-1'"),
                [dict(entry, adapter="m365-powershell")],
            )
        )
        self.assertIsNone(
            catalog_match(
                classify(f"{S} add groups g-2017 --member Jordan"),
                [dict(entry, target_scope=["groups/g-2017"])],
            )
        )


if __name__ == "__main__":
    unittest.main()
