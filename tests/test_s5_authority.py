"""S5 Owner A: receipts and exact identity, verification without terminal transition,
evidence commit ordering, strict snapshots, close, resume CAS and the fixed CLI step.

Covers S5_IMPLEMENT_CONTRACT §6 "A" and S5_CONTRACT_ACCEPTANCE corrections 1 (verify.json
is strict JSON with ordinal records) and 2 (close needs every step and every target).
Fixture projects live in <repo>/.local/test-tmp (test_guard.Project); all data is
fictional Contoso data. Nothing here runs a probe: evidence records are fixture data.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import fsutil, guard, ledger, schema  # noqa: E402
from cab_of_one.runtime.schema import Invalid  # noqa: E402
from cab_of_one.runtime.state import (  # noqa: E402
    CloseResult,
    Conflict,
    Halted,
    NotAllowed,
    Replay,
    StateCorrupt,
    input_hmac,
    unverified_units,
)
from test_guard import (  # noqa: E402
    CHANGE_DIR,
    CHANGE_ID,
    OPERATOR,
    POLICY_TOML,
    REVIEW_SESSION,
    REVIEWER,
    T0,
    TENANT,
    TTL_HOURS,
    Project,
    S4Case,
    change_toml,
    observation,
    purge,
    set_department,
    sha256_text,
    targets_csv,
    verify_result,
)

STATE_FILE = os.path.join(".cab", "state", "changes", f"{CHANGE_ID}.json")
ACTIVE_FILE = os.path.join(".cab", "state", "active.json")
SECRET_STEP = "python3 scripts/bulk.py --password=StepPwSENTINELz9"
OTHER_SECRET = "python3 scripts/bulk.py --password=OtherPwSENTINELq1"
CLI = ".claude/hooks/cab/cab"


def failing_write(match: str) -> Any:
    """atomic_write that fails for paths ending with ``match`` (fault injection)."""
    real = fsutil.atomic_write

    def write(path: Any, data: bytes, **kw: Any) -> None:
        if os.fspath(path).endswith(match):
            raise OSError(28, "fixture: no space left")
        real(path, data, **kw)

    return write


def code(fn: Any, *args: Any, **kw: Any) -> str | None:
    try:
        fn(*args, **kw)
    except Invalid as exc:
        return exc.code
    return None


class A5Case(S4Case):
    def write(self, command: str, outcome: str | None = "ok", verdict: str | None = None):
        """One allowed write, optionally settled and verified. Returns the event."""
        p = self.p
        ev = p.bash(command)
        self.assertAllowed(p.decide(ev))
        if outcome is not None:
            p.settle(ev, outcome)
        if verdict is not None:
            p.verify(len(p.doc()["units"]), verdict)
        return ev

    def verify_bytes(self) -> bytes:
        return (self.p.folder / "verify.json").read_bytes()

    def state_file_bytes(self) -> bytes:
        return self.p.read(STATE_FILE)


# =========================================================================== identity


class IdentityTests(A5Case):
    def test_exact_identity_settles_and_stores_an_immutable_receipt(self) -> None:
        p = self.p
        p.prepare("critical")
        ev = self.write(purge("u-1007"), outcome=None)
        unit = p.doc()["units"][0]
        call = unit["call"]
        self.assertEqual((call["session_id"], call["tool"]), (ev["session_id"], "Bash"))
        self.assertEqual(call["input_hmac"], input_hmac(call["salt"], "Bash", ev["tool_input"]))
        self.assertIsNone(unit["receipt"])
        p.settle(ev, "ok")
        unit = p.doc()["units"][0]
        self.assertEqual(unit["outcome"], "ok")
        self.assertEqual(
            {k: unit["receipt"][k] for k in ("source", "outcome", "exit")},
            {"source": "post", "outcome": "ok", "exit": None},
        )
        self.assertFalse(p.inflight_exists())

    def test_identity_variants_halt_and_keep_the_reservation(self) -> None:
        cases = {
            "secret only": {"tool_input": {"command": OTHER_SECRET}},
            "session": {"session_id": "sess-other-01"},
            "missing session": {"session_id": None},
            "tool": {"tool_name": "mcp__contosoadmin__set_user"},
            "non-JSON input": {"tool_input": {"command": {1, 2}}},
            "fingerprint": {"fingerprint": "0" * 64},
        }
        for label, changes in cases.items():
            with self.subTest(case=label):
                p = Project(self)
                p.prepare("critical", steps=[
                    {"id": "rotate", "command": SECRET_STEP, "targets": ["users/u-1007"]}
                ])  # fmt: skip
                ev = p.bash(SECRET_STEP)
                self.assertAllowed(p.decide(ev))
                if label == "secret only":
                    # the redacted fingerprints agree; only the exact-input HMAC differs
                    other = dict(ev, tool_input={"command": OTHER_SECRET})
                    self.assertEqual(p.fingerprint(ev), p.fingerprint(other))
                with self.assertRaises(Halted) as caught:
                    p.settle(ev, "ok", **changes)
                self.assertEqual(caught.exception.code, "settle_mismatch")
                doc = p.doc()
                self.assertEqual((doc["state"], doc["halted"]["code"]),
                                 ("halted", "settle_mismatch"))  # fmt: skip
                self.assertEqual(doc["inflight"]["token"], ev["tool_use_id"])
                self.assertIsNone(doc["units"][0]["outcome"])
                self.assertTrue(p.inflight_exists())
                # the exact result still settles the kept reservation
                p.settle(ev, "ok")
                self.assertEqual(p.doc()["units"][0]["outcome"], "ok")

    def test_identical_repeat_is_a_replay_byte_for_byte(self) -> None:
        p = self.p
        p.prepare("critical")
        ev = self.write(purge("u-1007"))
        state, book = p.state_bytes(), p.ledger_bytes()
        with self.assertRaises(Replay):
            p.settle(ev, "ok")
        self.assertEqual((p.state_bytes(), p.ledger_bytes()), (state, book))

    def test_post_then_failure_restores_debt_and_the_canary(self) -> None:
        p = self.p
        p.prepare("critical")
        ev = self.write(purge("u-1007"), verdict="PASS")
        self.assertEqual(p.doc()["canary"], "passed")
        with self.assertRaises(Halted) as caught:
            p.settle(ev, "failed")
        self.assertEqual(caught.exception.code, "result_conflict")
        doc = p.doc()
        unit = doc["units"][0]
        self.assertEqual((unit["outcome"], unit["verify"], unit["verify_ref"]),
                         ("unknown", None, None))  # fmt: skip
        self.assertEqual((unit["receipt"]["source"], unit["receipt"]["outcome"]), ("post", "ok"))
        self.assertEqual((doc["canary"], doc["canary_unit"]), ("awaiting", 1))
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "result_conflict"))
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])
        p.resume()
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "canary_awaiting")

    def test_different_outcome_or_exit_is_a_conflict(self) -> None:
        for label, first, second in (
            ("ok then unknown", {}, {"outcome": "unknown"}),
            ("other response", {}, {"response_sha256": "1" * 64}),
            ("failure exit", {"outcome": "failed"}, {"outcome": "failed", "exit": 2}),
        ):
            with self.subTest(case=label):
                p = Project(self)
                p.prepare("critical")
                ev = p.bash(purge("u-1007"))
                self.assertAllowed(p.decide(ev))
                outcome = first.pop("outcome", "ok")
                p.settle(ev, outcome, **first)
                outcome2 = second.pop("outcome", "ok")
                with self.assertRaises(Halted) as caught:
                    p.settle(ev, outcome2, **second)
                self.assertEqual(caught.exception.code, "result_conflict")
                self.assertEqual(p.doc()["units"][0]["outcome"], "unknown")

    def test_resume_then_late_post_is_a_conflict(self) -> None:
        p = self.p
        p.prepare("critical")
        ev = self.write(purge("u-1007"), outcome=None)
        p.resume(clear_inflight=True)
        with self.assertRaises(Halted) as caught:
            p.settle(ev, "ok")
        self.assertEqual(caught.exception.code, "result_conflict")
        doc = p.doc()
        self.assertEqual(doc["units"][0]["outcome"], "unknown")
        self.assertEqual(doc["canary"], "awaiting")

    def test_settled_token_with_other_identity_changes_no_unit(self) -> None:
        p = self.p
        p.prepare("critical")
        ev = self.write(purge("u-1007"), verdict="PASS")
        unit_before = p.doc()["units"][0]
        with self.assertRaises(Halted) as caught:
            p.settle(ev, "failed", session_id="sess-other-01")
        self.assertEqual(caught.exception.code, "settle_mismatch")
        doc = p.doc()
        self.assertEqual(doc["units"][0], unit_before)
        self.assertEqual(doc["halted"]["code"], "settle_mismatch")

    def test_no_active_or_ended_change_refuses(self) -> None:
        p = self.p
        p.prepare("standard", targets=("users/u-1007",))
        ev = self.write(set_department("u-1007"), verdict="PASS")
        result = p.close()
        self.assertEqual((result.state, result.reason), ("closed", "all_pass"))
        with self.assertRaises(NotAllowed) as caught:
            p.settle(ev, "failed")
        self.assertEqual(caught.exception.code, "no_open_change")

    def test_salt_and_hmac_stay_in_protected_state_only(self) -> None:
        p = self.p
        p.prepare("critical", steps=[
            {"id": "rotate", "command": SECRET_STEP, "targets": ["users/u-1007"]}
        ])  # fmt: skip
        ev = self.write(SECRET_STEP, verdict="PASS")
        call = p.doc()["units"][0]["call"]
        raw = hashlib.sha256(
            schema.canonical_json({"input": ev["tool_input"], "tool": "Bash"}).encode("ascii")
        ).hexdigest()
        for blob in (p.ledger_bytes().decode("ascii"), self.verify_bytes().decode("ascii")):
            for value in (call["salt"], call["input_hmac"], raw, "StepPwSENTINELz9"):
                self.assertNotIn(value, blob)


# =========================================================================== verification


class VerifyTransitionTests(A5Case):
    def test_noncanary_pass_keeps_executing_and_allows_the_next_write(self) -> None:
        p = self.p
        p.prepare("normal")
        self.write(set_department("u-1023"), verdict="PASS")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["units"][0]["verify"]), ("executing", "PASS"))
        self.assertAllowed(p.decide(p.bash(set_department("u-1015"))))

    def test_noncanary_unmeasured_keeps_executing(self) -> None:
        p = self.p
        p.prepare("normal")
        self.write(set_department("u-1023"), verdict="UNMEASURED")
        self.assertEqual(p.doc()["state"], "executing")
        self.assertAllowed(p.decide(p.bash(set_department("u-1015"))))

    def test_noncanary_fail_halts(self) -> None:
        p = self.p
        p.prepare("normal")
        self.write(set_department("u-1023"), verdict="FAIL")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "verify_failed"))
        self.assertDenied(p.decide(p.bash(set_department("u-1015"))), "halted")

    def test_verify_works_while_halted_and_keeps_the_halt(self) -> None:
        p = self.p
        p.prepare("normal")
        self.write(set_department("u-1023"), outcome="failed", verdict="PASS")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "write_failed"))
        self.assertEqual(doc["units"][0]["verify"], "PASS")

    def test_verify_refused_before_execution(self) -> None:
        p = self.p
        p.prepare("standard")
        doc = p.doc()
        with self.assertRaises(NotAllowed) as caught:
            p.store().record_verify(
                CHANGE_ID, 1, {"users/u-1007": "PASS"}, doc["seq"], p.plan_hash,
                evidence=p.evidence({"users/u-1007": "PASS"}),
            )  # fmt: skip
        self.assertEqual(caught.exception.code, "state")


# =========================================================================== evidence


class EvidenceTests(A5Case):
    def setUp(self) -> None:
        super().setUp()
        self.p.prepare("normal")
        self.ev = self.write(set_department("u-1023"))

    def test_verify_json_is_strict_json_with_ordinal_records(self) -> None:
        p = self.p
        p.verify(1, "UNMEASURED")
        p.verify(1, "PASS")
        data = self.verify_bytes()
        doc = schema.parse_verify_doc(data)
        self.assertEqual(json.loads(data), doc)
        self.assertEqual([r["line"] for r in doc["records"]], [1, 2])
        unit = p.doc()["units"][0]
        record = doc["records"][1]
        self.assertEqual(unit["verify_ref"], {
            "line": 2, "sha256": hashlib.sha256(schema.canonical_bytes(record)).hexdigest(),
        })  # fmt: skip
        state = p.doc()
        self.assertEqual(record["seq"], state["seq"])
        self.assertEqual(record["seq_before"] + 1, record["seq"])
        self.assertEqual(p.store().verify_evidence(state), {1: record})

    def test_state_commit_failure_leaves_an_unreferenced_record(self) -> None:
        p = self.p
        before = self.state_file_bytes()
        with mock.patch.object(fsutil, "atomic_write", failing_write(STATE_FILE)):
            with self.assertRaises(OSError):
                p.verify(1, "PASS")
        self.assertEqual(self.state_file_bytes(), before)
        self.assertIsNone(p.doc()["units"][0]["verify"])
        first = schema.parse_verify_doc(self.verify_bytes())["records"]
        self.assertEqual(len(first), 1)
        rows = [r for r in p.ledger_rows() if r.get("action") == "verify"]
        self.assertEqual(len(rows), 1)  # an intent without a committed seq
        p.verify(1, "PASS")
        records = schema.parse_verify_doc(self.verify_bytes())["records"]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], first[0])  # line 1 remains, untouched
        self.assertEqual(p.doc()["units"][0]["verify_ref"]["line"], 2)
        self.assertEqual(set(p.store().verify_evidence(p.doc())), {1})

    def test_ledger_failure_leaves_the_state_unchanged(self) -> None:
        p = self.p
        before = self.state_file_bytes()
        doc = p.doc()
        results = {"users/u-1023": "PASS"}
        store = p.store(ledger_timeout=0.05)
        with fsutil.locked(p.roots.ledger_lock, 2.0):
            with self.assertRaises(ledger.LedgerError):
                store.record_verify(
                    CHANGE_ID, 1, results, doc["seq"], p.plan_hash,
                    evidence=p.evidence(results),
                )  # fmt: skip
        self.assertEqual(self.state_file_bytes(), before)
        self.assertEqual(len(schema.parse_verify_doc(self.verify_bytes())["records"]), 1)
        p.verify(1, "PASS")
        self.assertEqual(p.doc()["units"][0]["verify_ref"]["line"], 2)

    def test_damaged_or_unsafe_log_is_refused_unchanged(self) -> None:
        p = self.p
        path = p.folder / "verify.json"
        for label, data in (
            ("truncated", b'{"records":[{"schema":1'),
            ("not canonical", b'{"schema": 1, "records": []}\n'),
            ("trailing garbage", schema.canonical_bytes({"schema": 1, "records": []}) + b"x"),
        ):
            with self.subTest(case=label):
                path.write_bytes(data)
                with self.assertRaises(NotAllowed) as caught:
                    p.verify(1, "PASS")
                self.assertEqual(caught.exception.code, "verify_log_damaged")
                self.assertEqual(path.read_bytes(), data)
        path.unlink()
        outside = p.tmp / "verify-outside.json"
        outside.write_bytes(schema.canonical_bytes({"schema": 1, "records": []}))
        p.symlink(outside, path)
        with self.assertRaises(NotAllowed) as caught:
            p.verify(1, "PASS")
        self.assertEqual(caught.exception.code, "verify_log_damaged")
        self.assertEqual(outside.read_bytes(), schema.canonical_bytes({"schema": 1, "records": []}))

    def test_tampering_and_cross_references_are_corrupt(self) -> None:
        p = self.p
        p.verify(1, "PASS")
        second = self.write(set_department("u-1015"), verdict="PASS")
        self.assertIsNotNone(second)
        store = p.store()
        doc = p.doc()
        self.assertEqual(set(store.verify_evidence(doc)), {1, 2})

        cross = copy.deepcopy(doc)
        cross["units"][1]["verify_ref"] = dict(cross["units"][0]["verify_ref"])
        with self.assertRaises(StateCorrupt):
            store.verify_evidence(cross)

        future = copy.deepcopy(doc)
        future["seq"] = store.verify_evidence(doc)[2]["seq"] - 1  # record seq > doc.seq
        with self.assertRaises(StateCorrupt):
            store.verify_evidence(future)

        path = p.folder / "verify.json"
        original = path.read_bytes()
        vdoc = json.loads(original)
        vdoc["records"][0]["results"]["users/u-1023"]["human_command"] += " --forged"
        path.write_bytes(schema.canonical_bytes(vdoc))
        with self.assertRaises(StateCorrupt) as caught:
            store.verify_evidence(doc)
        self.assertEqual(caught.exception.code, "verify_mismatch")
        path.write_bytes(original.replace(b'"records":[', b'"records": [', 1))
        with self.assertRaises(StateCorrupt):
            store.verify_evidence(doc)
        path.unlink()
        with self.assertRaises(StateCorrupt):
            store.verify_evidence(doc)

    def test_evidence_must_be_a_valid_record(self) -> None:
        p = self.p
        doc = p.doc()
        results = {"users/u-1023": "PASS"}
        good = p.evidence(results)
        bad_cases = {
            "missing key": {k: v for k, v in good.items() if k != "schedule"},
            "extra key": dict(good, note="x"),
            "schedule too long": dict(good, schedule=[1] * 11),
            "pass with reason": dict(good, results={"users/u-1023": dict(
                good["results"]["users/u-1023"], reason="x")}),
            "fail reason": dict(good, results={"users/u-1023": dict(
                verify_result("users/u-1023", "FAIL", T0), reason="timeout")}),
            "finished first": dict(good, started_at=schema.utc_text(T0 + 1)),
        }  # fmt: skip
        for label, evidence in bad_cases.items():
            with self.subTest(case=label):
                with self.assertRaises(NotAllowed) as caught:
                    p.store().record_verify(
                        CHANGE_ID, 1, results, doc["seq"], p.plan_hash, evidence=evidence
                    )
                self.assertEqual(caught.exception.code, "evidence")
        self.assertFalse((p.folder / "verify.json").exists())


# =========================================================================== close


class CloseTests(A5Case):
    def one_target(self) -> None:
        self.p.prepare("standard", targets=("users/u-1007",))

    def assert_inactive(self, state: str) -> None:
        p = self.p
        self.assertIsNone(p.store().load().active)
        self.assertEqual(p.change_doc()["state"], state)

    def test_all_pass_closes_and_releases_the_pointer(self) -> None:
        self.one_target()
        self.write(set_department("u-1007"), verdict="PASS")
        result = self.p.close()
        self.assertIsInstance(result, CloseResult)
        self.assertEqual((result.state, result.reason), ("closed", "all_pass"))
        self.assert_inactive("closed")
        self.assertDenied(self.p.decide(self.p.bash(set_department("u-1007"))), "no_open_change")
        row = [r for r in self.p.ledger_rows() if r.get("action") == "close"][-1]
        self.assertEqual(row["reason_code"], "all_pass")

    def test_any_fail_fails(self) -> None:
        self.one_target()
        self.write(set_department("u-1007"), verdict="FAIL")
        self.assertEqual(self.p.doc()["halted"]["code"], "verify_failed")
        result = self.p.close()
        self.assertEqual((result.state, result.reason), ("failed", "verify_failed"))
        self.assert_inactive("failed")
        self.assertIsNone(self.p.change_doc()["halted"])

    def test_unmeasured_stays_active_open_unverified(self) -> None:
        p = self.p
        self.one_target()
        self.write(set_department("u-1007"), verdict="UNMEASURED")
        result = p.close()
        self.assertEqual((result.state, result.reason), ("open-unverified", "unmeasured"))
        self.assertEqual(p.store().load().active, CHANGE_ID)
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "execution_ended")
        with self.assertRaises(NotAllowed) as caught:
            p.store().new_change("CHG-0002", "other", OPERATOR)
        self.assertEqual(caught.exception.code, "one_active_change")
        p.verify(1, "PASS")  # verify is allowed while open-unverified
        self.assertEqual(p.doc()["state"], "open-unverified")
        result = p.close()
        self.assertEqual((result.state, result.reason), ("closed", "all_pass"))
        self.assert_inactive("closed")

    def test_fail_while_open_unverified_halts(self) -> None:
        p = self.p
        self.one_target()
        self.write(set_department("u-1007"), verdict="UNMEASURED")
        p.close()
        p.verify(1, "FAIL")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "verify_failed"))
        self.assertEqual(p.close().state, "failed")

    def test_not_executed(self) -> None:
        self.one_target()
        result = self.p.close()
        self.assertEqual((result.state, result.reason), ("failed", "not_executed"))
        self.assert_inactive("failed")

    def test_execution_incomplete_targets(self) -> None:
        self.p.prepare("standard", targets=("users/u-1007", "users/u-1015"))
        self.write(set_department("u-1007"), verdict="PASS")
        result = self.p.close()
        self.assertEqual((result.state, result.reason), ("failed", "execution_incomplete"))
        self.assert_inactive("failed")

    def test_execution_incomplete_steps_on_the_same_target(self) -> None:
        # acceptance correction 2: one of two declared steps on the same target ran
        p = self.p
        steps = [
            {"id": "step-a", "command": "python3 scripts/bulk.py --batch one",
             "targets": ["users/u-1007"]},
            {"id": "step-b", "command": "python3 scripts/bulk.py --batch two",
             "targets": ["users/u-1007"]},
        ]  # fmt: skip
        p.prepare("critical", targets=("users/u-1007",), steps=steps)
        self.write(steps[0]["command"], verdict="PASS")
        self.assertEqual(p.doc()["executed_steps"], ["step-a"])
        result = p.close()
        self.assertEqual((result.state, result.reason), ("failed", "execution_incomplete"))
        self.assert_inactive("failed")

    def test_both_steps_on_the_same_target_close(self) -> None:
        p = self.p
        steps = [
            {"id": "step-a", "command": "python3 scripts/bulk.py --batch one",
             "targets": ["users/u-1007"]},
            {"id": "step-b", "command": "python3 scripts/bulk.py --batch two",
             "targets": ["users/u-1007"]},
        ]  # fmt: skip
        p.prepare("critical", targets=("users/u-1007",), steps=steps)
        self.write(steps[0]["command"], verdict="PASS")
        self.write(steps[1]["command"], verdict="PASS")
        self.assertEqual(p.close().state, "closed")

    def test_refusals(self) -> None:
        p = self.p
        self.one_target()
        ev = self.write(set_department("u-1007"), outcome=None)
        with self.assertRaises(Conflict) as caught:
            p.close()
        self.assertEqual(caught.exception.code, "inflight")
        p.settle(ev, "ok")
        seq = p.doc()["seq"]
        with self.assertRaises(Conflict) as caught:
            p.close(expect_seq=seq - 1)
        self.assertEqual(caught.exception.code, "seq")
        with self.assertRaises(NotAllowed) as caught:
            p.close()
        self.assertEqual(caught.exception.code, "unverified_units")
        p.verify(1, "PASS")
        original = p.read(f"{CHANGE_DIR}/plan.md")
        p.write(f"{CHANGE_DIR}/plan.md", original + b"edited\n")
        with self.assertRaises(Conflict) as caught:
            p.close()
        self.assertEqual(caught.exception.code, "plan_changed")
        p.write(f"{CHANGE_DIR}/plan.md", original)
        path = p.folder / "verify.json"
        data = path.read_bytes()
        vdoc = json.loads(data)
        vdoc["records"][0]["started_at"] = schema.utc_text(T0 - 1)
        path.write_bytes(schema.canonical_bytes(vdoc))
        with self.assertRaises(StateCorrupt):
            p.close()
        path.write_bytes(data)
        self.assertEqual(p.store().load().active, CHANGE_ID)
        self.assertEqual(p.close().state, "closed")

    def test_halt_codes(self) -> None:
        # write_failed with every unit PASS: a person resumes (not closable as success)
        p = self.p
        self.one_target()
        self.write(set_department("u-1007"), outcome="failed", verdict="PASS")
        with self.assertRaises(NotAllowed) as caught:
            p.close()
        self.assertEqual(caught.exception.code, "halted")
        # result_conflict is never closable
        q = Project(self)
        q.prepare("standard", targets=("users/u-1007",))
        ev = q.bash(set_department("u-1007"))
        self.assertAllowed(q.decide(ev))
        q.settle(ev, "ok")
        q.verify(1, "PASS")
        with self.assertRaises(Halted):
            q.settle(ev, "failed")
        with self.assertRaises(NotAllowed) as caught:
            q.close()
        self.assertEqual(caught.exception.code, "halted")
        self.assertEqual(q.store().load().active, CHANGE_ID)

    def test_failed_pointer_write_then_idempotent_finish(self) -> None:
        p = self.p
        self.one_target()
        self.write(set_department("u-1007"), verdict="PASS")
        with mock.patch.object(fsutil, "atomic_write", failing_write(ACTIVE_FILE)):
            with self.assertRaises(OSError):
                p.close()
        doc = p.doc()  # pointer still set on the ended change
        self.assertEqual(doc["state"], "closed")
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "execution_ended")
        with self.assertRaises(NotAllowed):
            p.store().new_change("CHG-0002", "other", OPERATOR)
        with self.assertRaises(NotAllowed) as caught:
            p.settle(p.bash(set_department("u-1007")), "ok")
        self.assertEqual(caught.exception.code, "closed")
        with self.assertRaises(Conflict):
            p.close(expect_seq=doc["seq"] - 1)
        result = p.close()
        self.assertEqual((result.state, result.reason, result.seq),
                         ("closed", "already_closed", doc["seq"]))  # fmt: skip
        self.assert_inactive("closed")


class KnownTargetStepTests(A5Case):
    """Known-target writes (targets extracted from the command) and planned steps.

    A known-target write stays allowed by its targets. It counts as an executed planned
    step only through an exact, unique, literal binding to one approved step whose targets
    equal the extracted ones; close still requires every planned step (fixture data)."""

    U7 = "users/u-1007"

    def step(self, sid: str, command: str, targets: tuple[str, ...] = (U7,)) -> dict[str, Any]:
        return {"id": sid, "command": command, "targets": list(targets)}

    def test_planned_known_target_command_records_its_step_and_closes(self) -> None:
        p = self.p
        command = set_department("u-1007")
        p.prepare("normal", targets=(self.U7,), steps=[self.step("s1", command)])
        self.write(command, verdict="PASS")
        doc = p.doc()
        self.assertEqual(doc["executed_steps"], ["s1"])
        self.assertEqual(doc["units"][0]["step"], "s1")
        self.assertEqual(doc["units"][0]["targets"], [self.U7])
        result = p.close()
        self.assertEqual((result.state, result.reason), ("closed", "all_pass"))

    def test_two_planned_commands_on_one_target_one_run_stays_incomplete(self) -> None:
        p = self.p
        first, second = set_department("u-1007", "Sales"), set_department("u-1007", "Finance")
        p.prepare("normal", targets=(self.U7,),
                  steps=[self.step("s1", first), self.step("s2", second)])  # fmt: skip
        self.write(first, verdict="PASS")
        self.assertEqual(p.doc()["executed_steps"], ["s1"])  # s2 is not inferred by target
        result = p.close()
        self.assertEqual((result.state, result.reason), ("failed", "execution_incomplete"))

    def test_both_planned_known_target_commands_close(self) -> None:
        p = self.p
        first, second = set_department("u-1007", "Sales"), set_department("u-1007", "Finance")
        p.prepare("normal", targets=(self.U7,),
                  steps=[self.step("s1", first), self.step("s2", second)])  # fmt: skip
        self.write(first, verdict="PASS")
        self.write(second, verdict="PASS")
        self.assertEqual(p.doc()["executed_steps"], ["s1", "s2"])
        self.assertEqual(p.close().state, "closed")

    def test_nonmatching_command_or_targets_never_counts_a_step(self) -> None:
        cases = {
            # same target, another literal command: allowed by target, never step s1
            "other command": (
                [self.step("s1", set_department("u-1007", "Sales"))],
                (self.U7,), set_department("u-1007", "Finance"),
            ),
            # same command, but the step claims more targets than the command writes
            "step targets differ": (
                [self.step("s1", set_department("u-1007"), (self.U7, "users/u-1015"))],
                (self.U7, "users/u-1015"), set_department("u-1007"),
            ),
        }  # fmt: skip
        for label, (steps, targets, command) in cases.items():
            with self.subTest(case=label):
                self.p = Project(self)
                p = self.p
                p.prepare("normal", targets=targets, steps=steps)
                self.write(command, verdict="PASS")
                doc = p.doc()
                self.assertEqual(doc["executed_steps"], [])
                self.assertIsNone(doc["units"][0]["step"])
                result = p.close()
                self.assertEqual((result.state, result.reason), ("failed", "execution_incomplete"))

    def test_ambiguous_duplicate_planned_command_never_claims_a_step(self) -> None:
        p = self.p
        command = set_department("u-1007")
        p.prepare("normal", targets=(self.U7,),
                  steps=[self.step("s1", command), self.step("s2", command)])  # fmt: skip
        self.write(command, verdict="PASS")  # still allowed by its known target
        doc = p.doc()
        self.assertEqual(doc["executed_steps"], [])
        self.assertIsNone(doc["units"][0]["step"])
        result = p.close()
        self.assertEqual((result.state, result.reason), ("failed", "execution_incomplete"))

    def test_replay_and_repeat_never_duplicate_the_step(self) -> None:
        p = self.p
        command = set_department("u-1007")
        p.prepare("normal", targets=(self.U7,), steps=[self.step("s1", command)])
        ev = self.write(command, outcome="ok")
        before = self.state_file_bytes()
        with self.assertRaises(Replay):
            p.settle(ev, "ok")
        self.assertEqual(self.state_file_bytes(), before)  # a replay changes no byte
        p.verify(1, "PASS")
        self.write(command, verdict="PASS")  # the same exact step again: allowed, as before
        doc = p.doc()  # parsed strictly by the Store
        self.assertEqual(doc["executed_steps"], ["s1"])
        self.assertEqual([u["step"] for u in doc["units"]], ["s1", "s1"])
        self.assertEqual(p.close().state, "closed")

    def test_unknown_target_binding_is_unchanged(self) -> None:
        p = self.p
        bulk = "python3 scripts/bulk.py --batch one"
        p.prepare("critical", targets=(self.U7,), steps=[self.step("bulk-one", bulk)])
        self.assertDenied(p.decide(p.bash("python3 scripts/bulk.py --batch zzz")),
                          "binding_missing")  # fmt: skip
        self.write(bulk, verdict="PASS")
        self.assertEqual(p.doc()["executed_steps"], ["bulk-one"])
        self.assertDenied(p.decide(p.bash(bulk)), "step_used")
        self.assertEqual(p.doc()["executed_steps"], ["bulk-one"])
        self.assertEqual(p.close().state, "closed")


# =========================================================================== snapshot


class SnapshotTests(A5Case):
    def test_values_must_be_strict_observations(self) -> None:
        p = self.p
        p.prepare("standard", snapshot=False)
        store = p.store()
        good = p.observations()
        target = p.targets[0]
        bad_values = {
            "arbitrary json": {"fixture": "before"},
            "unknown status": dict(good[target], status="present"),
            "exit missing": dict(good[target], exit=None),
            "object missing": dict(good[target], object=None),
            "reason on measured": dict(good[target], reason="x"),
            "extra key": dict(good[target], note="x"),
            "empty command": dict(good[target], human_command=""),
            "unmeasured without reason": observation(target, T0, "unmeasured") | {"reason": None},
            "absent with object": observation(target, T0, "absent") | {"object": {"a": 1}},
        }
        for label, value in bad_values.items():
            with self.subTest(case=label):
                values = dict(good, **{target: value})
                with self.assertRaises(NotAllowed) as caught:
                    store.record_snapshot(CHANGE_ID, values, p.plan_hash, OPERATOR)
                self.assertEqual(caught.exception.code, "snapshot_values")
        self.assertIsNone(p.doc()["snapshot_sha"])

    def test_stale_or_future_observation_is_refused(self) -> None:
        p = self.p
        p.prepare("standard", snapshot=False)
        target = p.targets[0]
        for at in (T0 - 301, T0 + 6):
            with self.subTest(at=at):
                values = dict(p.observations(), **{target: observation(target, at)})
                with self.assertRaises(NotAllowed) as caught:
                    p.snapshot(values=values)
                self.assertEqual(caught.exception.code, "snapshot_stale_observation")
        values = dict(p.observations(), **{target: observation(target, T0 - 300)})
        p.snapshot(values=values)

    def test_incomplete_snapshot_is_recorded_but_never_a_baseline(self) -> None:
        p = self.p
        p.prepare("standard", snapshot=False)
        p.snapshot(values=p.observations({"users/u-1015": "unmeasured"}))
        self.assertIsNotNone(p.doc()["snapshot_sha"])
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "snapshot_incomplete")
        q = Project(self)
        q.prepare("critical", snapshot=False, review=None, approve=False)
        q.snapshot(values=q.observations({"users/u-1042": "unmeasured"}))
        with self.assertRaises(NotAllowed) as caught:
            q.store().begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        self.assertEqual(caught.exception.code, "snapshot_incomplete")

    def test_absent_and_soft_deleted_are_measured(self) -> None:
        p = self.p
        p.prepare("standard", snapshot=False)
        statuses = {"users/u-1015": "absent", "users/u-1023": "soft_deleted"}
        p.snapshot(values=p.observations(statuses))
        self.assertAllowed(p.decide(p.bash(set_department("u-1007"))))

    def test_fresh_snapshot_invalidates_review_and_approval(self) -> None:
        p = self.p
        p.prepare("critical")
        self.assertEqual(p.doc()["state"], "approved")
        p.snapshot()
        doc = p.doc()
        self.assertEqual(doc["state"], "planned")
        for key in ("review_start", "review_sha", "ack_review_sha", "approval_nonce"):
            self.assertIsNone(doc[key], key)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_missing")
        row = [r for r in p.ledger_rows() if r.get("action") == "snapshot"][-1]
        self.assertEqual(row["reason_code"], "review_invalidated")
        p.review()
        p.approve()
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))

    def test_first_write_after_the_ttl_needs_a_new_snapshot(self) -> None:
        p = self.p
        p.prepare("standard")
        p.clock.advance(TTL_HOURS * 3600 + 1)
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "snapshot_stale")
        p.snapshot()
        self.assertAllowed(p.decide(p.bash(set_department("u-1007"))))

    def test_executing_change_keeps_its_baseline(self) -> None:
        p = self.p
        p.prepare("standard")
        self.write(set_department("u-1007"), verdict="PASS")
        p.clock.advance(TTL_HOURS * 3600 + 1)
        self.assertAllowed(p.decide(p.bash(set_department("u-1015"))))


SNAP_SECRET = "RawSnapSENTINELp1"


class SnapshotDigestTests(A5Case):
    """Fix 1: object_sha256 == sha256(canonical_json(redact_value(object))) and the stored
    observation is already redacted, at record time and whenever a snapshot is accepted."""

    def setUp(self) -> None:
        super().setUp()
        self.p.prepare("standard", snapshot=False)
        self.target = self.p.targets[0]

    def obs(self, obj: dict[str, Any], digest: str | None = None, **changes: Any) -> dict:
        value = observation(self.target, self.p.clock.now)
        value["object"] = obj
        value["object_sha256"] = digest or sha256_text(schema.canonical_json(obj))
        value.update(changes)
        return value

    def refused(self, value: dict[str, Any], *secrets: str) -> None:
        p = self.p
        book = p.ledger_bytes()
        values = dict(p.observations(), **{self.target: value})
        with self.assertRaises(NotAllowed) as caught:
            p.snapshot(values=values)
        self.assertEqual(caught.exception.code, "snapshot_values")
        self.assertIsNone(p.doc()["snapshot_sha"])
        self.assertFalse((p.folder / "snapshot.json").exists())
        self.assertEqual(p.ledger_bytes(), book)  # nothing written, nothing logged
        for secret in secrets:
            self.assertNotIn(secret, str(caught.exception))
            self.assertNotIn(secret, repr(caught.exception))

    def test_fixture_digest_is_accepted(self) -> None:
        p = self.p
        p.snapshot()
        self.assertAllowed(p.decide(p.bash(set_department("u-1007"))))

    def test_bad_digest_is_refused(self) -> None:
        good = observation(self.target, self.p.clock.now)
        self.refused(dict(good, object_sha256="0" * 64))
        changed = dict(good, object=dict(good["object"], department="Finance"))
        self.refused(changed)  # digest of the old object

    def test_raw_secret_with_raw_or_redacted_digest_is_refused(self) -> None:
        raw = {"id": "u-1007", "department": "Sales", "password": SNAP_SECRET}
        raw_digest = sha256_text(schema.canonical_json(raw))
        self.refused(self.obs(raw, raw_digest), SNAP_SECRET, raw_digest)
        redacted = dict(raw, password=ledger.REDACTED)
        redacted_digest = sha256_text(schema.canonical_json(redacted))
        self.refused(self.obs(raw, redacted_digest), SNAP_SECRET)
        self.refused(self.obs(redacted, raw_digest), raw_digest)
        bearer = {"id": "u-1007", "note": f"Bearer {SNAP_SECRET}"}
        self.refused(self.obs(bearer), SNAP_SECRET)

    def test_valid_redacted_object_is_accepted(self) -> None:
        p = self.p
        obj = {"id": "u-1007", "department": "Sales", "password": ledger.REDACTED,
               "nested": [{"token": ledger.REDACTED}]}  # fmt: skip
        values = dict(p.observations(), **{self.target: self.obs(obj)})
        p.snapshot(values=values)
        data = (p.folder / "snapshot.json").read_bytes()
        self.assertIn(ledger.REDACTED.encode(), data)
        self.assertAllowed(p.decide(p.bash(set_department("u-1007"))))

    def test_policy_extra_patterns_apply(self) -> None:
        secret = "CONTOSO-SECRET-4821"
        self.refused(self.obs({"id": "u-1007", "note": secret}), secret)
        argv = ["python3", "simtenant/simtenant.py", "get", "users", secret]
        self.refused(self.obs({"id": "u-1007"}, argv=argv, human_command=shlex.join(argv)), secret)
        self.refused(self.obs({"id": "u-1007"}, human_command=f"get users {secret}"), secret)
        p = self.p
        ok = self.obs({"id": "u-1007", "note": ledger.REDACTED})
        p.snapshot(values=dict(p.observations(), **{self.target: ok}))
        self.assertIsNotNone(p.doc()["snapshot_sha"])

    def test_unmeasured_and_absent_stay_strict(self) -> None:
        unmeasured = observation(self.target, self.p.clock.now, "unmeasured")
        self.refused(dict(unmeasured, object_sha256="0" * 64))
        absent = observation(self.target, self.p.clock.now, "absent")
        self.refused(dict(absent, object_sha256="0" * 64))
        p = self.p
        p.snapshot(values=dict(p.observations(), **{self.target: absent}))
        self.assertIsNotNone(p.doc()["snapshot_sha"])

    def test_accepted_snapshot_is_rechecked_at_the_gates(self) -> None:
        # A committed snapshot that is no longer redacted under the current policy (an
        # extra pattern now matches a stored value) is not a baseline any more.
        p = self.p
        p.snapshot()
        self.assertAllowed(p.decide(p.bash(set_department("u-1007"))))
        q = Project(self)
        q.prepare("critical", review=None, approve=False)
        stricter = POLICY_TOML.replace(
            'extra_patterns = ["CONTOSO-SECRET-[0-9]{4}"]',
            'extra_patterns = ["CONTOSO-SECRET-[0-9]{4}", "Sales"]',
        )
        self.assertNotEqual(stricter, POLICY_TOML)
        q.write("policy/policy.toml", stricter)
        with self.assertRaises(NotAllowed) as caught:
            q.store().begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        self.assertEqual(caught.exception.code, "snapshot_invalid")
        p.write("policy/policy.toml", stricter)
        self.assertDenied(p.decide(p.bash(set_department("u-1015"))), "snapshot_invalid")


class ReviewSessionTests(A5Case):
    """Fix 2: the review stop must come from the parent session that started it."""

    def setUp(self) -> None:
        super().setUp()
        self.p.prepare("critical", review=None, approve=False)

    def unchanged(self, before: bytes, rows: int) -> None:
        p = self.p
        self.assertEqual(self.state_file_bytes(), before)
        self.assertEqual(len(p.ledger_rows()), rows)
        self.assertFalse((p.folder / "review.json").exists())

    def test_exact_session_succeeds_and_is_recorded(self) -> None:
        p = self.p
        store = p.store()
        store.begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        start = p.doc()["review_start"]
        self.assertEqual((start["agent_id"], start["session_id"]), (REVIEWER, REVIEW_SESSION))
        row = [r for r in p.ledger_rows() if r.get("action") == "review_start"][-1]
        self.assertEqual(row["session_id"], REVIEW_SESSION)
        store.finish_review(CHANGE_ID, REVIEWER, REVIEW_SESSION, "PASS", [])
        doc = p.doc()
        self.assertEqual((doc["state"], doc["review_start"]), ("reviewed", None))
        review = json.loads((p.folder / "review.json").read_bytes())
        self.assertEqual(review["session_id"], REVIEW_SESSION)
        p.review_sha = doc["review_sha"]
        p.approve()
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))

    def test_same_agent_id_from_another_session_is_refused(self) -> None:
        p = self.p
        store = p.store()
        store.begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        before, rows = self.state_file_bytes(), len(p.ledger_rows())
        for session in ("sess-other-01", None, "", "bad session", "x" * 129, 42):
            with self.subTest(session=session):
                with self.assertRaises(NotAllowed) as caught:
                    store.finish_review(CHANGE_ID, REVIEWER, session, "PASS", [])  # type: ignore
                self.assertEqual(caught.exception.code, "review_session")
                self.unchanged(before, rows)
        self.assertEqual(p.doc()["review_start"]["session_id"], REVIEW_SESSION)
        store.finish_review(CHANGE_ID, REVIEWER, REVIEW_SESSION, "PASS", [])
        self.assertEqual(p.doc()["state"], "reviewed")

    def test_missing_or_invalid_start_session_is_refused(self) -> None:
        p = self.p
        store = p.store()
        before, rows = self.state_file_bytes(), len(p.ledger_rows())
        for session in (None, "", "bad session", "x" * 129, 42):
            with self.subTest(session=session):
                with self.assertRaises(NotAllowed) as caught:
                    store.begin_review(CHANGE_ID, REVIEWER, session_id=session)  # type: ignore
                self.assertEqual(caught.exception.code, "review_session")
                self.unchanged(before, rows)
        with self.assertRaises(TypeError):
            store.begin_review(CHANGE_ID, REVIEWER)  # type: ignore[call-arg]
        self.assertIsNone(p.doc()["review_start"])

    def test_refused_stop_keeps_an_existing_approval(self) -> None:
        q = Project(self)
        q.prepare("critical")
        before = q.read(STATE_FILE)
        with self.assertRaises(NotAllowed) as caught:
            q.store().finish_review(CHANGE_ID, REVIEWER, "sess-other-01", "PASS", [])
        self.assertEqual(caught.exception.code, "review_not_started")
        self.assertEqual(q.read(STATE_FILE), before)
        self.assertAllowed(q.decide(q.bash(purge("u-1007"))))

    def test_plan_hash_checks_still_apply(self) -> None:
        p = self.p
        store = p.store()
        store.begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        rel = f"{CHANGE_DIR}/plan.md"
        original = p.read(rel)
        p.write(rel, original + b"edited during review\n")
        store.finish_review(CHANGE_ID, REVIEWER, REVIEW_SESSION, "PASS", [])
        self.assertEqual(p.doc()["state"], "planned")

    def test_review_start_schema_requires_the_session(self) -> None:
        from test_schema import HEX, state_doc

        start = {"plan_hash": HEX, "agent_id": REVIEWER, "session_id": REVIEW_SESSION,
                 "at": "2027-01-15T08:00:00.000Z"}  # fmt: skip
        schema.parse_state(state_doc(review_start=start))
        without = {k: v for k, v in start.items() if k != "session_id"}
        for label, value in (
            ("missing", without),
            ("invalid", dict(start, session_id="bad session")),
            ("null", dict(start, session_id=None)),
        ):
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_state, state_doc(review_start=value)),
                                 "state_review")  # fmt: skip


# =========================================================================== resume


class ResumeTests(A5Case):
    def test_stale_sequence_is_a_conflict_and_debt_stays(self) -> None:
        p = self.p
        p.prepare("critical")
        self.write(purge("u-1007"), outcome="failed")
        seq = p.doc()["seq"]
        with self.assertRaises(Conflict) as caught:
            p.resume(expect_seq=seq - 1)
        self.assertEqual(caught.exception.code, "seq")
        self.assertEqual(p.doc()["state"], "halted")
        p.resume(expect_seq=seq)
        doc = p.doc()
        self.assertEqual(doc["state"], "executing")
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])
        self.assertEqual(doc["canary"], "awaiting")

    def test_resume_requires_a_keyword_sequence(self) -> None:
        p = self.p
        p.prepare("critical")
        with self.assertRaises(TypeError):
            p.store().resume(CHANGE_ID, OPERATOR)  # type: ignore[call-arg]


# =========================================================================== guard


class FixedCliTests(A5Case):
    def setUp(self) -> None:
        super().setUp()
        self.p.write(CLI, "#!/bin/sh\n# fictional pinned cab entry\n")

    def absolute(self) -> str:
        return shlex.quote(str(self.p.path(CLI)))

    def test_allowed_calls_write_a_row(self) -> None:
        p = self.p
        work = str(p.path("work"))
        cases = (
            (f"{CLI} status", None),
            (f"{CLI} new CHG-0002 contoso-x", None),
            (f"{CLI} plan check CHG-0001", None),
            (f"{CLI} tier CHG-0001", None),
            (f"{CLI} snapshot CHG-0001", None),
            (f"{CLI} verify CHG-0001", None),
            (f"{CLI} close CHG-0001", None),
            (f"{CLI} intake CHG-0001 --from-file changes/intake.toml", None),
            (f"{self.absolute()} status", work),
        )
        for command, cwd in cases:
            with self.subTest(command=command):
                ev = p.bash(command, cwd=cwd)
                self.assertAllowed(p.decide(ev))
                row = self.last_row()
                self.assertEqual(
                    (row["decision"], row["reason_code"], row["agent"], row["tool_use_id"]),
                    ("allow", "cab_cli", "main", ev["tool_use_id"]),
                )

    def assert_not_fixed(
        self, command: str, cwd: str | None = None, *, pure: bool = True, **kw: Any
    ) -> None:
        p = self.p
        cwd_path = cwd if cwd is not None else str(p.project)
        if pure:  # the caller check (main session) is in decide, not in _fixed_cli
            self.assertFalse(guard._fixed_cli(command, cwd_path, p.roots), command)
        ev = p.bash(command, cwd=cwd, **kw)
        p.decide(ev)
        rows = [r for r in p.ledger_rows() if r.get("tool_use_id") == ev["tool_use_id"]]
        self.assertNotIn("cab_cli", [r.get("reason_code") for r in rows])

    def test_everything_else_takes_the_normal_path(self) -> None:
        for command in (
            f"{CLI} status; echo hi",
            f"{CLI} status && echo hi",
            f"{CLI} status | cat",
            f"{CLI} status &",
            f"{CLI} status > work/out.txt",
            f"{CLI} status $CHG",
            f"{CLI} status `id`",
            f"{CLI} status $(id)",
            f"{CLI} status\n",
            f"{CLI} status # note",
            f"{CLI} status *",
            f"( {CLI} status )",
            f"CONTOSO=1 {CLI} status",
            f"{CLI} approve CHG-0001",
            f"{CLI} ack CHG-0001 x",
            f"{CLI} resume CHG-0001",
            f"{CLI} status approve",
            f"{CLI} plan",
            f"{CLI} plan apply",
            f"{CLI} setup apply",
            f"{CLI} audit",
            f"{CLI} status a b c d e f g",
            f"./{CLI} status",
            f"bash {CLI} status",
            "cab status",
            f"{CLI}",
        ):
            with self.subTest(command=command):
                self.assert_not_fixed(command)

    def test_caller_cwd_and_file_checks(self) -> None:
        p = self.p
        self.assert_not_fixed(f"{CLI} status", cwd=str(p.path("work")))
        self.assert_not_fixed(
            f"{CLI} status", pure=False,
            extra={"agent_id": "agent-0001", "agent_type": "verifier"},
        )  # fmt: skip
        entry = p.path(CLI)
        p.hardlink(entry, p.tmp / "cab-alias")
        self.assert_not_fixed(f"{CLI} status")
        os.unlink(p.tmp / "cab-alias")
        data = entry.read_bytes()
        entry.unlink()
        self.assert_not_fixed(f"{CLI} status")
        outside = p.tmp / "cab-outside"
        outside.write_bytes(data)
        p.symlink(outside, entry)
        self.assert_not_fixed(f"{CLI} status")

    def test_ledger_failure_denies(self) -> None:
        p = self.p
        p.prepare("critical", review=None, snapshot=False, approve=False)
        with fsutil.locked(p.roots.ledger_lock, 2.0):
            decision = p.decide(p.bash(f"{CLI} status"), ledger_timeout=0.05)
        self.assertDenied(decision, "ledger_error")


class GuardStateTests(A5Case):
    def test_new_messages_are_fixed_texts(self) -> None:
        for name in ("snapshot_incomplete", "snapshot_stale", "execution_ended"):
            with self.subTest(code=name):
                self.assertIn(name, guard.MESSAGES)
                self.assertTrue(guard.message(name).endswith(f"[{name}]"))


# =========================================================================== schema


class SchemaTests(unittest.TestCase):
    def test_strict_json_value(self) -> None:
        self.assertEqual(schema.strict_json_value('"Sales"'), "Sales")
        self.assertEqual(schema.strict_json_value('[1, {"a": null}]'), [1, {"a": None}])
        cases = {
            '{"a":1,"a":2}': "duplicate_key",
            "NaN": "non_finite",
            "[" * 10 + "]" * 10: "too_deep",
            '"' + "x" * 1100 + '"': "too_large",
            "": "syntax",
            "﻿1": "bom",
        }
        for text, expected in cases.items():
            with self.subTest(text=text[:12]):
                self.assertEqual(code(schema.strict_json_value, text), expected)

    def test_change_verify_specs(self) -> None:
        base = change_toml("CHG-0001", "critical")

        def spec(body: str) -> str:
            return base + "\n" + body

        good = spec(
            '[[verify]]\ntarget = "users/u-1007"\nexpect = "active"\n'
            'argv = ["python3", "simtenant/simtenant.py", "get", "users", "u-1007"]\n'
            '[[verify.check]]\npointer = "/object/department"\nop = "eq"\n'
            "value_json = '\"Sales\"'\n"
        )
        plan = schema.load_change(good.encode(), "CHG-0001")
        self.assertEqual(len(plan.verify), 1)
        expected = schema.Check("/object/department", "eq", '"Sales"')
        self.assertEqual(plan.verify[0].checks[0], expected)
        self.assertEqual(schema.load_change(base.encode(), "CHG-0001").verify, ())
        absent = spec('[[verify]]\ntarget = "users/u-1007"\nexpect = "absent"\nargv = ["x"]\n')
        self.assertEqual(schema.load_change(absent.encode(), "CHG-0001").verify[0].checks, ())
        bad = {
            "active without checks": absent.replace('"absent"', '"active"'),
            "absent with checks": good.replace('"active"', '"absent"'),
            "unknown expect": absent.replace('"absent"', '"present"'),
            "unknown op": good.replace('op = "eq"', 'op = "gt"'),
            "bad pointer": good.replace('"/object/department"', '"object/department"'),
            "bad escape": good.replace('"/object/department"', '"/object/~2x"'),
            "deep pointer": good.replace('"/object/department"', '"' + "/a" * 9 + '"'),
            "bad value": good.replace("'\"Sales\"'", "'Sales'"),
            "empty argv": absent.replace('argv = ["x"]', "argv = []"),
            "extra key": absent + 'note = "x"\n',
            "duplicate target": absent + absent[len(base) + 1 :],
        }
        for label, text in bad.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.load_change, text.encode(), "CHG-0001"),
                                 "change_verify")  # fmt: skip

    def test_observation_variants(self) -> None:
        obs = observation("users/u-1007", T0)
        schema.parse_observation(obs, with_object=True)
        last = observation("users/u-1007", T0, with_object=False)
        schema.parse_observation(last, with_object=False)
        self.assertEqual(code(schema.parse_observation, obs, with_object=False), "observation")
        self.assertEqual(code(schema.parse_observation, last, with_object=True), "observation")
        unmeasured = observation("users/u-1007", T0, "unmeasured")
        schema.parse_observation(unmeasured, with_object=True)
        big = dict(obs, object={"blob": "x" * (70 * 1024)})
        self.assertEqual(code(schema.parse_observation, big, with_object=True), "observation")
        self.assertTrue(schema.snapshot_complete({"targets": {"a/b": obs}}))
        self.assertFalse(schema.snapshot_complete({"targets": {"a/b": obs, "a/c": unmeasured}}))

    def record(self, **changes: Any) -> dict[str, Any]:
        rec = {
            "schema": 1, "change_id": "CHG-0001", "line": 1, "unit": 1, "seq_before": 7,
            "seq": 8, "plan_hash": "a" * 64, "verdict": "PASS",
            "started_at": schema.utc_text(T0), "finished_at": schema.utc_text(T0),
            "schedule": [2, 5], "results": {"users/u-1007": verify_result("users/u-1007",
                                                                          "PASS", T0)},
        }  # fmt: skip
        rec.update(changes)
        return rec

    def test_verify_record(self) -> None:
        schema.parse_verify_record(self.record())
        schema.parse_verify_record(schema.canonical_bytes(self.record()))
        mixed = {
            "users/u-1007": verify_result("users/u-1007", "PASS", T0),
            "users/u-1015": verify_result("users/u-1015", "UNMEASURED", T0),
        }
        schema.parse_verify_record(self.record(results=mixed, verdict="UNMEASURED"))
        mixed["users/u-1023"] = verify_result("users/u-1023", "FAIL", T0)
        schema.parse_verify_record(self.record(results=mixed, verdict="FAIL"))
        bad = {
            "seq gap": self.record(seq=9),
            "aggregate": self.record(results=mixed, verdict="UNMEASURED"),
            "schedule value": self.record(schedule=[601]),
            "extra key": dict(self.record(), note="x"),
            "pass without last": self.record(results={"users/u-1007": dict(
                verify_result("users/u-1007", "PASS", T0), last=None)}),
            "attempts": self.record(results={"users/u-1007": dict(
                verify_result("users/u-1007", "PASS", T0), attempts=12)}),
            "checked pointer": self.record(results={"users/u-1007": dict(
                verify_result("users/u-1007", "PASS", T0), checked={"x": None})}),
        }  # fmt: skip
        for label, rec in bad.items():
            with self.subTest(case=label):
                self.assertIsNotNone(code(schema.parse_verify_record, rec))

    def test_verify_doc_is_canonical_with_ordinals(self) -> None:
        doc = {"schema": 1, "records": [self.record(), self.record(line=2)]}
        schema.parse_verify_doc(schema.canonical_bytes(doc))
        swapped = {"schema": 1, "records": [self.record(line=2), self.record()]}
        self.assertEqual(code(schema.parse_verify_doc, schema.canonical_bytes(swapped)),
                         "verify_records")  # fmt: skip
        pretty = json.dumps(doc, indent=1).encode()
        self.assertEqual(code(schema.parse_verify_doc, pretty), "verify_not_canonical")

    def test_unit_receipt_and_ref_invariants(self) -> None:
        from test_schema import CALL, HEX, state_doc

        at = "2027-01-15T08:00:00.000Z"

        def settled(**unit_changes: Any) -> dict[str, Any]:
            unit = dict(state_doc()["units"][0], outcome="ok",
                        receipt={"source": "post", "outcome": "ok", "at": at, "exit": None,
                                 "response_sha256": HEX})  # fmt: skip
            unit.update(unit_changes)
            return state_doc(inflight=None, units=[unit], settled_ids=["toolu_1"])

        schema.parse_state(settled())
        schema.parse_state(settled(outcome="unknown"))  # a conflict keeps the first receipt
        schema.parse_state(settled(verify="PASS", verify_ref={"line": 1, "sha256": HEX}))
        resume = {"source": "resume", "outcome": "unknown", "at": at, "exit": None,
                  "response_sha256": None}  # fmt: skip
        schema.parse_state(settled(outcome="unknown", receipt=resume))
        bad = {
            "receipt without outcome": settled(outcome=None),
            "outcome without receipt": settled(receipt=None),
            "verify without ref": settled(verify="PASS"),
            "ref without verify": settled(verify_ref={"line": 1, "sha256": HEX}),
            "resume ok": settled(receipt=dict(resume, outcome="ok")),
            "resume exit": settled(outcome="unknown", receipt=dict(resume, exit=1)),
            "failure response": settled(outcome="failed", receipt={
                "source": "failure", "outcome": "failed", "at": at, "exit": 7,
                "response_sha256": HEX}),
            "post exit": settled(receipt={"source": "post", "outcome": "ok", "at": at,
                                          "exit": 0, "response_sha256": HEX}),
            "outcome differs": settled(outcome="failed"),
            "no call": settled(call=None),
            "bad salt": settled(call=dict(CALL, salt="x")),
        }  # fmt: skip
        for label, doc in bad.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_state, doc), "state_unit")


class PlanVerifyTargetTests(A5Case):
    def test_verify_target_outside_targets_csv_is_plan_invalid(self) -> None:
        p = self.p
        p.prepare("standard")
        text = change_toml(CHANGE_ID, "standard") + (
            '\n[[verify]]\ntarget = "users/u-9999"\nexpect = "absent"\nargv = ["x"]\n'
        )
        p.write(f"{CHANGE_DIR}/change.toml", text)
        p.write(f"{CHANGE_DIR}/targets.csv", targets_csv(p.targets))
        with self.assertRaises(NotAllowed) as caught:
            p.store().load_plan(CHANGE_ID)
        self.assertEqual(caught.exception.code, "plan_invalid")
        self.assertDenied(p.decide(p.bash(set_department("u-1007"))), "plan_invalid")

    def test_load_plan_is_public_and_lockless(self) -> None:
        p = self.p
        p.prepare("standard")
        with fsutil.locked(p.roots.state_lock, 2.0):
            plan, targets, current = p.store().load_plan(CHANGE_ID)
        self.assertEqual((targets, current), (p.targets, p.plan_hash))
        self.assertEqual(plan.tenant, TENANT)


if __name__ == "__main__":
    unittest.main()
