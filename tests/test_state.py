"""Store: compare-and-set, transactions, reservations, settle/verify/resume.

Fixture projects live in <repo>/.local/test-tmp (see test_guard.Project). Approvals created
here are fixture data. The S5 additions (receipts, evidence, close) are covered in
test_s5_authority; TTY prompts and probe routing belong to other owners.
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import fsutil, ledger  # noqa: E402
from cab_of_one.runtime.state import (  # noqa: E402
    Conflict,
    Halted,
    NotAllowed,
    Replay,
    StateCorrupt,
    StoreError,
    unverified_units,
)
from test_guard import (  # noqa: E402
    APPROVER,
    CHANGE_DIR,
    CHANGE_ID,
    OPERATOR,
    REVIEW_SESSION,
    REVIEWER,
    SLUG,
    S4Case,
    purge,
)


def failing_write(match: str) -> Any:
    """atomic_write that fails for paths ending with ``match`` (fault injection)."""
    real = fsutil.atomic_write

    def write(path: Any, data: bytes, **kw: Any) -> None:
        if os.fspath(path).endswith(match):
            raise OSError(28, "fixture: no space left")
        real(path, data, **kw)

    return write


class LifecycleCasTests(S4Case):
    def test_one_active_change(self) -> None:
        store = self.p.store()
        self.assertEqual(store.new_change(CHANGE_ID, SLUG, OPERATOR), 1)
        with self.assertRaises(NotAllowed) as caught:
            store.new_change("CHG-0002", "other", OPERATOR)
        self.assertEqual(caught.exception.code, "one_active_change")
        for cid, slug in (("CHG-1", "x"), ("CHG-0003", "Bad Slug"), ("../CHG-0004", "x")):
            with self.subTest(cid=cid, slug=slug):
                with self.assertRaises(NotAllowed):
                    store.new_change(cid, slug, OPERATOR)

    def test_concurrent_new_change_has_one_winner(self) -> None:
        barrier = threading.Barrier(2, timeout=10)
        results: dict[str, Any] = {}

        def run(cid: str) -> None:
            store = self.p.store()
            try:
                barrier.wait()
                results[cid] = store.new_change(cid, f"race-{cid[-1]}", OPERATOR)
            except Exception as exc:  # recorded and asserted below
                results[cid] = exc

        threads = [threading.Thread(target=run, args=(cid,)) for cid in ("CHG-0001", "CHG-0002")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
            self.assertFalse(thread.is_alive())
        winners = [cid for cid, value in results.items() if value == 1]
        self.assertEqual(len(winners), 1, results)
        loser = next(value for cid, value in results.items() if cid not in winners)
        self.assertIsInstance(loser, NotAllowed | fsutil.LockTimeout)
        self.assertEqual(self.p.store().load().active, winners[0])

    def test_expected_plan_hash_and_sequence(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        store = p.store()
        with self.assertRaises(Conflict) as caught:
            store.mark_planned(CHANGE_ID, "critical", "0" * 64, OPERATOR)
        self.assertEqual(caught.exception.code, "plan_changed")
        seq = p.doc()["seq"]
        cases = (
            (seq - 1, p.plan_hash, p.review_sha, "seq"),
            (seq, "0" * 64, p.review_sha, "plan_changed"),
            (seq, p.plan_hash, "0" * 64, "review"),
        )
        for expect_seq, expect_hash, review_sha, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(Conflict) as caught:
                    store.approve(CHANGE_ID, expect_seq, expect_hash, review_sha, APPROVER)
                self.assertEqual(caught.exception.code, code)
        self.assertEqual(p.doc()["state"], "reviewed")
        self.assertFalse((p.folder / "approval.json").exists())

    def test_plan_edit_between_check_and_approve_is_a_conflict(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        p.write(f"{CHANGE_DIR}/plan.md", "# edited after review\n")
        seq = p.doc()["seq"]
        with self.assertRaises(Conflict):
            p.store().approve(CHANGE_ID, seq, p.plan_hash, p.review_sha, APPROVER)

    def test_replan_invalidates_review_approval_and_snapshot(self) -> None:
        p = self.p
        p.prepare("critical")
        p.replan("critical")
        doc = p.doc()
        self.assertEqual(doc["state"], "planned")
        for key in ("review_sha", "approval_nonce", "snapshot_sha", "ack_review_sha"):
            self.assertIsNone(doc[key], key)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_missing")

    def test_review_mismatch_and_ack_rules(self) -> None:
        p = self.p
        p.prepare("critical", review=None)
        store = p.store()
        with self.assertRaises(NotAllowed):
            store.finish_review(CHANGE_ID, REVIEWER, REVIEW_SESSION, "PASS", [])
        store.begin_review(CHANGE_ID, REVIEWER, session_id=REVIEW_SESSION)
        with self.assertRaises(NotAllowed):
            store.finish_review(CHANGE_ID, "agent-other", REVIEW_SESSION, "PASS", [])
        sha = store.finish_review(CHANGE_ID, REVIEWER, REVIEW_SESSION, "PASS", [])
        with self.assertRaises(NotAllowed):
            store.ack(CHANGE_ID, sha, OPERATOR)  # PASS needs no acknowledgement
        with self.assertRaises(NotAllowed):
            store.begin_review(CHANGE_ID, "bad agent id", session_id=REVIEW_SESSION)

    def test_snapshot_primitive_requires_exact_plan_targets(self) -> None:
        p = self.p
        p.prepare("critical", snapshot=False, review=None, approve=False)
        store = p.store()
        with self.assertRaises(NotAllowed) as caught:
            store.record_snapshot(CHANGE_ID, {"users/u-1007": 1}, p.plan_hash, OPERATOR)
        self.assertEqual(caught.exception.code, "snapshot_targets")
        with self.assertRaises(NotAllowed) as caught:  # S5: values must be observations
            store.record_snapshot(CHANGE_ID, {t: None for t in p.targets}, p.plan_hash, OPERATOR)
        self.assertEqual(caught.exception.code, "snapshot_values")
        values = p.observations()
        with self.assertRaises(Conflict):
            store.record_snapshot(CHANGE_ID, values, "0" * 64, OPERATOR)
        store.record_snapshot(CHANGE_ID, values, p.plan_hash, OPERATOR)
        self.assertIsNotNone(p.doc()["snapshot_sha"])


class ApprovalTransactionTests(S4Case):
    """An approval interrupted part way must never become an allow."""

    def assert_not_approved(self) -> None:
        p = self.p
        self.assertEqual(p.doc()["state"], "reviewed")
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "approval_missing")
        self.assertFalse(p.inflight_exists())

    def retry_succeeds(self) -> None:
        p = self.p
        p.approve()
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))

    def test_failure_after_registry_line(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        with mock.patch.object(fsutil, "atomic_write", failing_write("approval.json")):
            with self.assertRaises(OSError):
                p.approve()
        self.assertTrue(os.path.isfile(p.roots.approvals_file))
        self.assertFalse((p.folder / "approval.json").exists())
        self.assert_not_approved()
        self.retry_succeeds()

    def test_failure_at_the_ledger(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        store = p.store(ledger_timeout=0.05)
        with fsutil.locked(p.roots.ledger_lock, 2.0):
            with self.assertRaises(ledger.LedgerError):
                seq = store.load().change["seq"]
                store.approve(CHANGE_ID, seq, p.plan_hash, p.review_sha, APPROVER)
        self.assertTrue((p.folder / "approval.json").exists())
        self.assert_not_approved()
        self.retry_succeeds()

    def test_failure_at_the_state_commit(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        target = os.path.join(".cab", "state", "changes", f"{CHANGE_ID}.json")
        with mock.patch.object(fsutil, "atomic_write", failing_write(target)):
            with self.assertRaises(OSError):
                p.approve()
        self.assert_not_approved()
        self.retry_succeeds()

    def test_truncated_registry_refuses_new_approvals(self) -> None:
        p = self.p
        p.prepare("critical", approve=False)
        registry = Path(p.roots.approvals_file)
        registry.parent.mkdir(parents=True, exist_ok=True)
        registry.write_bytes(b'{"schema":1')
        with self.assertRaises(StoreError) as caught:
            p.approve()
        self.assertEqual(caught.exception.code, "registry_truncated")
        self.assertEqual(registry.read_bytes(), b'{"schema":1')
        self.assert_not_approved()


class SettleTests(S4Case):
    def setUp(self) -> None:
        super().setUp()
        self.p.prepare("critical")
        self.first = self.p.bash(purge("u-1007"))
        self.assertAllowed(self.p.decide(self.first))

    def test_only_the_exact_token_and_fingerprint_settle(self) -> None:
        p = self.p
        with self.assertRaises(Halted) as caught:
            p.settle(self.first, "ok", tool_use_id="toolu_unknown")
        self.assertEqual(caught.exception.code, "unguarded_write")
        doc = p.doc()
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "unguarded_write"))
        self.assertEqual(doc["inflight"]["token"], self.first["tool_use_id"])
        self.assertTrue(p.inflight_exists())

    def test_settle_input_is_validated(self) -> None:
        p = self.p
        cases = (
            {"outcome": "success"},
            {"tool_use_id": "bad token"},
            {"source": "resume"},
            {"exit": 256, "source": "failure", "outcome": "failed", "response_sha256": None},
            {"exit": True, "source": "failure", "outcome": "failed", "response_sha256": None},
            {"response_sha256": "ABC"},
            {"exit": 1},  # a post carries no exit code
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(NotAllowed):
                    p.store().settle(p.receipt(self.first, **{"outcome": "ok", **changes}))
        with self.assertRaises(NotAllowed):
            p.store().settle("toolu_x")  # type: ignore[arg-type]
        self.assertIsNotNone(p.doc()["inflight"])

    def test_replay_and_conflict(self) -> None:
        # S5: an identical repeat changes nothing; a different later result is a conflict
        p = self.p
        p.settle(self.first, "ok")
        before = p.state_bytes()
        with self.assertRaises(Replay):
            p.settle(self.first, "ok")
        self.assertEqual(p.state_bytes(), before)
        with self.assertRaises(Halted) as caught:
            p.settle(self.first, "failed")
        self.assertEqual(caught.exception.code, "result_conflict")
        doc = p.doc()
        unit = doc["units"][0]
        self.assertEqual((unit["outcome"], unit["verify"]), ("unknown", None))
        self.assertEqual(unit["receipt"]["outcome"], "ok")  # the first receipt is kept
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "result_conflict"))

    def test_result_without_reservation_halts(self) -> None:
        p = self.p
        p.settle(self.first, "ok")
        p.verify(1, "PASS")
        stray = p.bash(purge("u-1015"))
        with self.assertRaises(Halted):
            p.settle(stray, "ok")
        self.assertEqual(p.doc()["halted"]["code"], "unguarded_write")

    def test_verify_rules(self) -> None:
        p = self.p
        doc = p.doc()
        store = p.store()
        good = {"users/u-1007": "PASS"}
        evidence = p.evidence(good)
        with self.assertRaises(Conflict):  # still in flight
            store.record_verify(CHANGE_ID, 1, good, doc["seq"], p.plan_hash, evidence=evidence)
        p.settle(self.first, "ok")
        doc = p.doc()
        with self.assertRaises(TypeError):  # S5: evidence is required
            store.record_verify(CHANGE_ID, 1, good, doc["seq"], p.plan_hash)  # type: ignore
        cases = (
            (1, good, doc["seq"] - 1, p.plan_hash, Conflict),
            (1, good, doc["seq"], "0" * 64, Conflict),
            (2, good, doc["seq"], p.plan_hash, NotAllowed),
            (1, {"users/u-1015": "PASS"}, doc["seq"], p.plan_hash, NotAllowed),
            (1, {"users/u-1007": "OK"}, doc["seq"], p.plan_hash, NotAllowed),
            (1, {}, doc["seq"], p.plan_hash, NotAllowed),
            (1, {"users/u-1007": "FAIL"}, doc["seq"], p.plan_hash, NotAllowed),  # != evidence
        )
        for unit, results, seq, plan, error in cases:
            with self.subTest(unit=unit, results=results, seq=seq):
                with self.assertRaises(error):
                    store.record_verify(CHANGE_ID, unit, results, seq, plan, evidence=evidence)
        self.assertFalse((p.folder / "verify.json").exists())
        p.verify(1, "UNMEASURED")
        self.assertEqual([u["n"] for u in unverified_units(p.doc())], [1])
        p.verify(1, "FAIL")
        doc = p.doc()
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])
        self.assertEqual((doc["state"], doc["halted"]["code"]), ("halted", "verify_failed"))

    def test_inflight_file_missing_is_inconsistent(self) -> None:
        p = self.p
        os.unlink(p.roots.inflight_file)
        self.assertDenied(p.decide(p.bash(purge("u-1015"))), "state_invalid")
        with self.assertRaises(StateCorrupt):
            p.settle(self.first, "ok")

    def test_resume_never_resets_obligations(self) -> None:
        p = self.p
        with self.assertRaises(NotAllowed):
            p.resume()
        stale = p.doc()["seq"] - 1
        with self.assertRaises(Conflict) as caught:  # S5: the person's view must be current
            p.resume(clear_inflight=True, expect_seq=stale)
        self.assertEqual(caught.exception.code, "seq")
        p.resume(clear_inflight=True)
        doc = p.doc()
        unit = doc["units"][0]
        self.assertEqual((unit["outcome"], unit["verify"]), ("unknown", None))
        self.assertEqual(unit["receipt"]["source"], "resume")
        self.assertIn(self.first["tool_use_id"], doc["settled_ids"])
        self.assertEqual(doc["canary"], "awaiting")
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])
        with self.assertRaises(NotAllowed):
            p.resume()  # nothing to resume
        with self.assertRaises(Halted) as caught:
            p.settle(self.first, "ok")  # S5: any result after a resume is a conflict
        self.assertEqual(caught.exception.code, "result_conflict")
        doc = p.doc()
        self.assertEqual(doc["units"][0]["outcome"], "unknown")
        self.assertEqual(doc["units"][0]["receipt"]["source"], "resume")
        self.assertEqual([u["n"] for u in unverified_units(doc)], [1])


class OrphanReservationTests(S4Case):
    def test_orphan_reservation_blocks_until_a_person_clears_it(self) -> None:
        p = self.p
        p.prepare("critical")
        fsutil.reserve(p.roots.inflight_file, "toolu_orphan")
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_invalid")
        with self.assertRaises(StateCorrupt):
            p.resume()
        p.resume(clear_inflight=True)
        self.assertFalse(p.inflight_exists())
        self.assertAllowed(p.decide(p.bash(purge("u-1007"))))

    def test_symlinked_reservation_is_refused(self) -> None:
        p = self.p
        p.prepare("critical")
        target = p.tmp / "outside-token"
        target.write_text("toolu_x")
        p.symlink(target, p.roots.inflight_file)
        self.assertDenied(p.decide(p.bash(purge("u-1007"))), "state_invalid")
        self.assertEqual(target.read_text(), "toolu_x")


if __name__ == "__main__":
    unittest.main()
