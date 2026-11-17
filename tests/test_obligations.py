"""Tests for cab_of_one.runtime.obligations (S5 C0). Pure data in, data out; no files."""

from __future__ import annotations

import copy
import unittest
from dataclasses import dataclass
from typing import Any

from cab_of_one.runtime.obligations import (
    ObligationsError,
    evaluate,
    stop_message,
)

CID = "CHG-0007"
PLAN = "a" * 64
SECRET = "sk-FICTIONAL-SECRET-0123456789"
AT = "2026-11-12T00:00:00.000Z"


@dataclass(frozen=True)
class View:
    active: str | None
    change: dict[str, Any] | None


def unit(n: int, targets: list[str], outcome: str | None, verify: str | None) -> dict[str, Any]:
    return {
        "n": n,
        "tool_use_id": f"toolu_{n:04d}",
        "step": "s1",
        "targets": targets,
        "canary": False,
        "outcome": outcome,
        "verify": verify,
        "at": AT,
    }


def change(units: list[dict[str, Any]], state: str = "executing", **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "id": CID,
        "state": state,
        "plan_hash": PLAN,
        "units": units,
        "inflight": None,
        "halted": None,
    }
    doc.update(extra)
    return doc


def command(target: str) -> str:
    return f"python3 -I scripts/simtenant.py --state tenant.json get {target}"


def record(u: dict[str, Any], verdicts: dict[str, str]) -> dict[str, Any]:
    results = {}
    for target, verdict in verdicts.items():
        results[target] = {
            "verdict": verdict,
            "attempts": 1,
            "reason": {"PASS": None, "FAIL": "not_converged", "UNMEASURED": "time_budget"}[verdict],
            "human_command": command(target),
            "last": None,
            "checked": {},
        }
    agg = (
        "PASS"
        if all(v == "PASS" for v in verdicts.values())
        else "FAIL"
        if "FAIL" in verdicts.values()
        else "UNMEASURED"
    )
    return {
        "schema": 1,
        "change_id": CID,
        "line": u["n"],
        "unit": u["n"],
        "seq_before": 10 + u["n"],
        "seq": 11 + u["n"],
        "plan_hash": PLAN,
        "verdict": agg,
        "started_at": AT,
        "finished_at": AT,
        "schedule": [2, 5],
        "results": results,
    }


class NoChangeTests(unittest.TestCase):
    def test_no_active_change(self) -> None:
        ob = evaluate(View(None, None), {})
        self.assertFalse(ob.blocking)
        self.assertFalse(ob.reportable)
        self.assertEqual(stop_message(ob).kind, "none")

    def test_no_active_but_change_or_evidence_is_invalid(self) -> None:
        with self.assertRaises(ObligationsError):
            evaluate(View(None, change([])), {})
        with self.assertRaises(ObligationsError):
            evaluate(View(None, None), {1: {}})

    def test_planned_without_writes(self) -> None:
        for state in ("draft", "planned", "reviewed", "approved", "executing"):
            ob = evaluate(View(CID, change([], state)), {})
            self.assertEqual(stop_message(ob).kind, "none", state)

    def test_all_pass_has_no_output(self) -> None:
        u1 = unit(1, ["user/u1"], "ok", "PASS")
        ob = evaluate(View(CID, change([u1])), {1: record(u1, {"user/u1": "PASS"})})
        self.assertEqual(stop_message(ob), stop_message(evaluate(View(None, None), {})))


class BlockTests(unittest.TestCase):
    def test_no_observation_blocks_and_counts(self) -> None:
        units = [
            unit(1, ["user/u1"], "ok", None),
            unit(2, ["user/u2"], "failed", None),
            unit(3, ["user/u3"], "unknown", None),
        ]
        ob = evaluate(View(CID, change(units)), {})
        self.assertEqual(ob.unverified_units, (1, 2, 3))
        self.assertEqual((ob.unverified_failed, ob.unverified_unknown), (1, 1))
        msg = stop_message(ob)
        self.assertEqual(msg.kind, "block")
        self.assertIn(
            f"{CID} has 3 writes with no verification after them (1 failed, 1 result "
            f"unknown). Run .claude/hooks/cab/cab verify {CID}.",
            msg.text,
        )

    def test_inflight_blocks(self) -> None:
        u1 = unit(1, ["user/u1"], None, None)
        doc = change([u1], inflight={"token": "toolu_0001", "unit": 1})
        ob = evaluate(View(CID, doc), {})
        self.assertEqual(ob.inflight_token, "toolu_0001")
        self.assertEqual(ob.unverified_units, ())
        msg = stop_message(ob)
        self.assertEqual(msg.kind, "block")
        self.assertIn(
            f"{CID}: a write never returned a result. Stop writing; a person must run "
            f"cab resume {CID} in their own terminal.",
            msg.text,
        )

    def test_unsettled_unit_without_inflight_is_invalid(self) -> None:
        with self.assertRaises(ObligationsError):
            evaluate(View(CID, change([unit(1, ["user/u1"], None, None)])), {})

    def test_halted_verify_failed_offers_close(self) -> None:
        u1 = unit(1, ["user/u1"], "ok", "FAIL")
        doc = change([u1], "halted", halted={"code": "verify_failed", "at": AT})
        ob = evaluate(View(CID, doc), {1: record(u1, {"user/u1": "FAIL"})})
        self.assertTrue(ob.close_can_fail)
        msg = stop_message(ob)
        self.assertEqual(msg.kind, "block")
        self.assertIn(f"{CID} is halted [verify_failed].", msg.text)
        self.assertIn(f"or end it as failed: .claude/hooks/cab/cab close {CID}.", msg.text)

    def test_halted_without_fail_or_with_debt_does_not_offer_close(self) -> None:
        u1 = unit(1, ["user/u1"], "failed", None)
        doc = change([u1], "halted", halted={"code": "write_failed", "at": AT})
        ob = evaluate(View(CID, doc), {})
        self.assertFalse(ob.close_can_fail)
        self.assertNotIn("end it as failed", stop_message(ob).text)
        u2 = unit(1, ["user/u1"], "ok", "FAIL")
        doc2 = change([u2], "halted", halted={"code": "settle_mismatch", "at": AT})
        ob2 = evaluate(View(CID, doc2), {1: record(u2, {"user/u1": "FAIL"})})
        self.assertFalse(ob2.close_can_fail)
        self.assertEqual(stop_message(ob2).kind, "block")

    def test_halted_state_and_code_must_agree(self) -> None:
        with self.assertRaises(ObligationsError):
            evaluate(View(CID, change([], "halted")), {})
        with self.assertRaises(ObligationsError):
            evaluate(View(CID, change([], halted={"code": "x", "at": AT})), {})

    def test_close_incomplete_blocks(self) -> None:
        for state in ("closed", "failed"):
            u1 = unit(1, ["user/u1"], "ok", "PASS")
            evidence = {1: record(u1, {"user/u1": "PASS"})}
            ob = evaluate(View(CID, change([u1], state)), evidence)
            self.assertTrue(ob.close_incomplete)
            msg = stop_message(ob)
            self.assertEqual(msg.kind, "block")
            self.assertIn("close did not finish", msg.text)
            self.assertIn(f"cab close {CID} again", msg.text)

    def test_block_is_never_softened_to_report(self) -> None:
        u1 = unit(1, ["user/u1"], "ok", "UNMEASURED")
        u2 = unit(2, ["user/u2"], "ok", None)
        ob = evaluate(View(CID, change([u1, u2])), {1: record(u1, {"user/u1": "UNMEASURED"})})
        self.assertTrue(ob.blocking)
        self.assertFalse(ob.reportable)
        self.assertEqual(stop_message(ob).kind, "block")


class ReportTests(unittest.TestCase):
    def test_fail_after_resume_reports_without_blocking(self) -> None:
        u1 = unit(1, ["user/u1"], "ok", "FAIL")
        ob = evaluate(View(CID, change([u1])), {1: record(u1, {"user/u1": "FAIL"})})
        self.assertFalse(ob.blocking)
        msg = stop_message(ob)
        self.assertEqual(msg.kind, "report")
        expected = f"{CID} is not verified (1 FAIL, 0 UNMEASURED); it is not closed."
        self.assertIn(expected, msg.text)
        self.assertIn(command("user/u1"), msg.text)
        self.assertIn(f"cab status {CID}", msg.text)

    def test_open_unverified_distinguishes_unmeasured(self) -> None:
        targets = [f"user/u{i}" for i in range(1, 8)]
        u1 = unit(1, targets, "ok", "UNMEASURED")
        verdicts = {t: "UNMEASURED" for t in targets}
        verdicts["user/u1"] = "PASS"
        ob = evaluate(View(CID, change([u1], "open-unverified")), {1: record(u1, verdicts)})
        self.assertEqual(ob.unverified_units, ())
        self.assertEqual(ob.unmeasured_units, (1,))
        self.assertEqual(len(ob.pending), 6)
        self.assertTrue(all(p.verdict == "UNMEASURED" for p in ob.pending))
        self.assertEqual(len(ob.commands()), 5)
        msg = stop_message(ob)
        self.assertEqual(msg.kind, "report")
        self.assertIn("(0 FAIL, 6 UNMEASURED)", msg.text)
        self.assertNotIn(command("user/u1"), msg.text)
        self.assertEqual(msg.text.count("simtenant.py"), 5)

    def test_report_never_claims_success(self) -> None:
        u1 = unit(1, ["user/u1"], "ok", "UNMEASURED")
        evidence = {1: record(u1, {"user/u1": "UNMEASURED"})}
        ob = evaluate(View(CID, change([u1], "open-unverified")), evidence)
        text = stop_message(ob).text.lower()
        self.assertIn("it is not closed.", text)
        for word in ("pass", "done", "success", "all_pass", "is closed"):
            self.assertNotIn(word, text)

    def test_human_command_is_redacted(self) -> None:
        u1 = unit(1, ["user/u1"], "ok", "UNMEASURED")
        rec = record(u1, {"user/u1": "UNMEASURED"})
        rec["results"]["user/u1"]["human_command"] = f"probe --client-secret {SECRET} user/u1"
        ob = evaluate(View(CID, change([u1], "open-unverified")), {1: rec})
        self.assertNotIn(SECRET, stop_message(ob).text)
        self.assertNotIn(SECRET, repr(ob))
        self.assertIn("[REDACTED]", ob.pending[0].human_command)


class EvidenceMismatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.u1 = unit(1, ["user/u1", "user/u2"], "ok", "FAIL")
        self.doc = change([self.u1])
        self.rec = record(self.u1, {"user/u1": "FAIL", "user/u2": "PASS"})

    def bad(self, rec: Any = None, evidence: Any = None, doc: Any = None) -> str:
        if evidence is None:
            evidence = {1: rec}
        with self.assertRaises(ObligationsError) as ctx:
            evaluate(View(CID, doc or self.doc), evidence)
        return ctx.exception.code

    def mutate(self, path: list[Any], value: Any) -> dict[str, Any]:
        rec = copy.deepcopy(self.rec)
        node = rec
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return rec

    def test_baseline_is_valid(self) -> None:
        evaluate(View(CID, self.doc), {1: self.rec})

    def test_mismatches(self) -> None:
        self.assertEqual(self.bad(evidence={}), "evidence_missing")
        self.assertEqual(self.bad(evidence={1: self.rec, 2: self.rec}), "evidence_extra")
        self.assertEqual(self.bad(evidence={"1": self.rec}), "evidence_missing")
        self.assertEqual(self.bad(self.mutate(["change_id"], "CHG-0008")), "evidence_change")
        self.assertEqual(self.bad(self.mutate(["unit"], 2)), "evidence_unit")
        self.assertEqual(self.bad(self.mutate(["verdict"], "PASS")), "evidence_verdict")
        self.assertEqual(self.bad(self.mutate(["plan_hash"], "b" * 64)), "evidence_plan")
        self.assertEqual(
            self.bad(self.mutate(["results", "user/u1", "verdict"], "PASS")), "evidence_verdict"
        )
        rec = copy.deepcopy(self.rec)
        del rec["results"]["user/u2"]
        self.assertEqual(self.bad(rec), "evidence_targets")
        self.assertEqual(
            self.bad(self.mutate(["results", "user/u1", "human_command"], "a\nb")),
            "evidence_command",
        )
        self.assertEqual(
            self.bad(self.mutate(["results", "user/u1", "human_command"], "")),
            "evidence_command",
        )
        self.assertEqual(self.bad("not a record"), "evidence_record")

    def test_bad_view(self) -> None:
        self.assertEqual(self.bad(self.rec, doc=change([], "verifying")), "state_state")
        other = copy.deepcopy(self.doc)
        other["id"] = "CHG-0008"
        self.assertEqual(self.bad(self.rec, doc=other), "view")
        with self.assertRaises(ObligationsError):
            evaluate(View("bad", self.doc), {1: self.rec})
        with self.assertRaises(ObligationsError):
            evaluate(View(CID, None), {})

    def test_inputs_not_mutated(self) -> None:
        doc, rec = copy.deepcopy(self.doc), copy.deepcopy(self.rec)
        evaluate(View(CID, doc), {1: rec})
        self.assertEqual((doc, rec), (self.doc, self.rec))


if __name__ == "__main__":
    unittest.main()
