"""Durable change state, approvals, write reservations, results and closeout: the ``Store``.

Files (all under the project, all protected by deny rules and guard step 2)::

    .cab/state/lock                      L_state (flock)
    .cab/state/active.json               {"schema": 1, "change_id": "CHG-NNNN" | null}
    .cab/state/changes/CHG-NNNN.json     change state (schema.parse_state)
    .cab/state/inflight                  reservation token (fsutil.reserve, O_EXCL)
    changes/CHG-NNNN-<slug>/{review,approval,snapshot,verify}.json
    <state_home>/approvals.jsonl         external approval registry, L_ext = approvals.lock

Locks are always taken in the order L_state -> L_ext -> L_ledger and L_ext is released
before L_ledger. Every mutating method takes L_state, re-reads and re-validates all
authority inside it, and checks ``expect_seq`` / ``expect_plan_hash`` where a person may
have looked at older data. Nothing here waits for a person or runs a probe under a lock.

Failure policy: a step that fails half way never leaves an allow path. A reservation
whose state commit fails is released when possible; a failed ledger row after a
committed reservation halts the change; a result that cannot be matched to its exact
reservation (session, tool, exact-input HMAC and redacted fingerprint) halts the change
and keeps the reservation. Nothing expires on its own; only ``resume`` (a person, through
the TTY command) clears a reservation.

S5 additions:

- Each unit records its call identity at reservation: session, tool, a per-unit salt
  and an HMAC over the raw tool input. Only this protected state holds the HMAC; the
  ledger and ``verify.json`` hold redacted hashes only.
- The first settlement writes an immutable receipt. An identical repeat is a ``Replay``;
  any other later result (Post then Failure, a different outcome, anything after a
  person's ``resume``) is ``result_conflict``: the unit becomes ``unknown``, loses its
  verification and a canary waits again. A conflict only ever adds debt.
- ``record_verify`` never ends execution. Evidence is appended to ``verify.json``
  (strict JSON ``{"schema": 1, "records": [...]}``) before the ledger row and the state
  commit; only a record named by a committed ``verify_ref`` counts. Records left by a
  failed commit stay in the file, unreferenced; nothing deletes or repairs them.
- ``close`` is the only terminal transition; only ``closed`` is success.

Advisory locks serialise hooks and the CLI only; they do not stop a direct hostile write
or a sync client.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import os
import secrets
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import fsutil, paths, schema
from .classification_types import KIND_WRITE, Result, leaves
from .classify import catalog_match, decide_tier
from .ledger import (
    Ledger,
    LedgerError,
    LedgerFormatError,
    read_jsonl_strict,
    redact,
    redact_value,
)
from .paths import Roots, UnsafePath
from .planhash import PLAN_FILES, PlanHashError, plan_hash
from .schema import TIER_RANK, ChangePlan, Invalid, Policy, Step, canonical_bytes, utc_text
from .shellscan import binding_safe

__all__ = [
    "CloseResult",
    "Conflict",
    "GateResult",
    "Halted",
    "NotAllowed",
    "Receipt",
    "Replay",
    "StateCorrupt",
    "Store",
    "StoreError",
    "View",
    "WriteContext",
    "input_hmac",
    "unverified_units",
]

MAX_REGISTRY_BYTES = 16 * 1024 * 1024
OPEN_STATES = ("draft", "planned", "reviewed", "approved", "executing", "halted")
ENDED_STATES = ("open-unverified", "closed", "failed")
VERIFY_STATES = ("executing", "halted", "open-unverified")
CLOSABLE_HALTS = ("write_failed", "write_unknown", "verify_failed")
SNAPSHOT_PAST = 300.0
SNAPSHOT_FUTURE = 5.0
_REGISTRY_FLAGS = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC


class StoreError(Exception):
    """Refusal with a fixed, non-sensitive code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Conflict(StoreError):
    """Compare-and-set failed: sequence, plan hash or review changed meanwhile."""


class StateCorrupt(StoreError):
    """State files are unreadable, invalid or disagree with each other."""


class NotAllowed(StoreError):
    """The transition is not allowed from the current state."""


class Replay(StoreError):
    """The tool_use_id was already settled with this exact result; nothing changed."""


class Halted(StoreError):
    """The result could not be matched to its exact reservation, or it conflicts with the
    stored receipt; the change is halted."""


@dataclass(frozen=True)
class View:
    active: str | None
    change: dict[str, Any] | None


@dataclass(frozen=True)
class WriteContext:
    """One administrative write as the guard sees it. ``command`` (the exact Bash text)
    and ``mcp_input_sha256`` are used for step binding only and are never stored.
    ``tool_input`` is the raw input; it is only fed to the per-unit HMAC."""

    tool_name: str
    tool_use_id: str
    session_id: str
    agent_type: str | None
    result: Result
    floor: str | None
    command: str | None
    mcp_input_sha256: str | None
    fingerprint: str
    cwd_is_project: bool
    ledger_command: str | None
    cls: dict[str, Any]
    tool_input: Mapping[str, Any]


@dataclass(frozen=True)
class Receipt:
    """A Post/PostFailure result, built by the hook. The raw input is hashed, never stored
    or logged. ``source`` is ``post`` or ``failure``; ``exit`` is set only for failures,
    ``response_sha256`` (sha256 of the redacted response) only for posts."""

    tool_use_id: str
    session_id: str | None
    tool_name: str
    tool_input: Mapping[str, Any]
    fingerprint: str
    source: str
    outcome: str
    exit: int | None
    response_sha256: str | None


@dataclass(frozen=True)
class CloseResult:
    seq: int
    state: str
    reason: str


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    code: str
    tier: str | None = None
    change_id: str | None = None


def unverified_units(change: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Units whose targets may have been written and have no PASS yet.

    Every settled unit counts, whatever its outcome: a failed or unknown write may have
    changed its targets before it ended. ``close`` requires PASS for all of them.
    """
    units = change.get("units", [])
    return [dict(u) for u in units if u["outcome"] is not None and u["verify"] != "PASS"]


def input_hmac(salt: str, tool_name: str, tool_input: Any) -> str | None:
    """HMAC-SHA256 keyed by the unit salt over the canonical raw call, or None when the
    input cannot be canonicalised (a non-JSON value): such a call never matches."""
    try:
        key = bytes.fromhex(salt)
        msg = schema.canonical_json({"input": tool_input, "tool": tool_name}).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        return None
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _frame_hash(files: Mapping[str, bytes]) -> str:
    """planhash framing over bytes already read (to bind what was parsed to the hash)."""
    digest = hashlib.sha256()
    for name in PLAN_FILES:
        data = files[name]
        digest.update(name.encode("ascii") + b"\x00" + str(len(data)).encode("ascii") + b"\x00")
        digest.update(data)
    return digest.hexdigest()


def _receipt_ok(receipt: Any) -> bool:
    """Structural validity only. Identity (session, tool, input) is checked against the
    unit later; a wrong identity halts instead of being refused."""
    if not isinstance(receipt, Receipt):
        return False
    if not schema.is_token(receipt.tool_use_id):
        return False
    if receipt.source not in ("post", "failure") or receipt.outcome not in schema.OUTCOMES:
        return False
    if receipt.exit is not None and (type(receipt.exit) is not int or not 0 <= receipt.exit <= 255):
        return False
    if receipt.response_sha256 is not None and not schema.is_hex64(receipt.response_sha256):
        return False
    if receipt.source == "failure":
        return receipt.outcome != "ok" and receipt.response_sha256 is None
    return receipt.exit is None


class Store:
    def __init__(
        self,
        roots: Roots,
        policy: Policy,
        catalog: Sequence[Mapping[str, Any]] = (),
        *,
        ledger: Ledger,
        clock: Callable[[], float] = time.time,
        lock_timeout: float = 3.0,
        ext_timeout: float = 1.0,
    ) -> None:
        self.roots = roots
        self.policy = policy
        self.catalog = tuple(catalog)
        self.ledger = ledger
        self.clock = clock
        self.lock_timeout = lock_timeout
        self.ext_timeout = ext_timeout

    # ------------------------------------------------------------------ reading

    def _read(self, rel: str, limit: int) -> bytes | None:
        try:
            return paths.read_authority(self.roots.project, rel, limit)
        except UnsafePath:
            raise StateCorrupt("state_unsafe") from None

    def _read_active(self) -> str | None:
        data = self._read(".cab/state/active.json", 4096)
        if data is None:
            return None
        try:
            return schema.parse_active(data)
        except Invalid:
            raise StateCorrupt("active_invalid") from None

    def _read_change(self, change_id: str) -> dict[str, Any]:
        if not schema.is_change_id(change_id):
            raise NotAllowed("change_name")
        data = self._read(f".cab/state/changes/{change_id}.json", schema.MAX_STATE_BYTES)
        if data is None:
            raise StateCorrupt("state_missing")
        try:
            doc = schema.parse_state(data)
        except Invalid:
            raise StateCorrupt("state_invalid") from None
        if doc["id"] != change_id:
            raise StateCorrupt("state_invalid")
        return doc

    def _token_on_disk(self) -> str | None:
        data = self._read(".cab/state/inflight", fsutil.MAX_TOKEN_BYTES)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise StateCorrupt("inflight_invalid") from None

    def _consistent(self, doc: Mapping[str, Any]) -> None:
        expected = doc["inflight"]["token"] if doc["inflight"] is not None else None
        if self._token_on_disk() != expected:
            raise StateCorrupt("inflight_mismatch")

    def _active_doc(self, change_id: str) -> dict[str, Any]:
        if self._read_active() != change_id:
            raise NotAllowed("not_active")
        return self._read_change(change_id)

    def _change_dir(self, doc: Mapping[str, Any]) -> str:
        name = f"{doc['id']}-{doc['slug']}"
        for folder in (self.roots.at("changes"), self.roots.at("changes", name)):
            try:
                st = os.lstat(folder)
            except FileNotFoundError:
                raise NotAllowed("plan_invalid") from None
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise NotAllowed("plan_invalid")
        return self.roots.at("changes", name)

    def _load_plan(self, doc: Mapping[str, Any]) -> tuple[ChangePlan, tuple[str, ...], str]:
        """Parsed plan, targets and the plan hash of exactly the bytes that were parsed."""
        folder = self._change_dir(doc)
        try:
            files = {}
            for name in PLAN_FILES:
                data = paths.read_authority(folder, name, schema.MAX_TARGETS_BYTES)
                if data is None:
                    raise NotAllowed("plan_invalid")
                files[name] = data
            current = plan_hash(folder)
            plan = schema.load_change(files["change.toml"], doc["id"])
            targets = schema.parse_targets(files["targets.csv"])
        except (PlanHashError, UnsafePath, Invalid):
            raise NotAllowed("plan_invalid") from None
        if _frame_hash(files) != current:
            raise NotAllowed("plan_changed")  # edited while it was being read
        target_set = set(targets)
        for step in plan.steps:
            if not set(step.targets) <= target_set:
                raise NotAllowed("plan_invalid")
        for spec in plan.verify:
            if spec.target not in target_set:
                raise NotAllowed("plan_invalid")
        return plan, targets, current

    def load(self) -> View:
        """Unlocked read for display, SessionStart and Stop. Never use it to authorise."""
        active = self._read_active()
        return View(active, self._read_change(active) if active else None)

    def load_plan(self, change_id: str) -> tuple[ChangePlan, tuple[str, ...], str]:
        """Lockless plan read for display and probe runs: (plan, targets, plan hash).

        The caller compares the hash with the recorded one; every commit re-checks it
        under the lock anyway.
        """
        return self._load_plan(self._read_change(change_id))

    # ------------------------------------------------------------------ evidence

    def _verify_doc(self, folder: str) -> dict[str, Any] | None:
        """Strictly parsed ``verify.json`` or None when it does not exist."""
        data = paths.read_authority(folder, "verify.json", schema.MAX_VERIFY_BYTES)
        if data is None:
            return None
        return schema.parse_verify_doc(data)

    def verify_evidence(self, doc: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
        """Committed evidence: {unit n: record} for every unit with a ``verify_ref``.

        Lockless. A record counts only when the referenced ordinal exists, its canonical
        bytes hash to the reference, and its change, unit, verdict, plan hash and sequence
        agree with the committed state (``seq == seq_before + 1 <= doc.seq``). Anything
        else raises ``StateCorrupt("verify_mismatch")``. Unreferenced records are ignored.
        """
        refs = [u for u in doc["units"] if u["verify_ref"] is not None]
        if not refs:
            return {}
        try:
            vdoc = self._verify_doc(self._change_dir(doc))
        except (UnsafePath, Invalid, NotAllowed):
            raise StateCorrupt("verify_mismatch") from None
        if vdoc is None:
            raise StateCorrupt("verify_mismatch")
        records = vdoc["records"]
        out: dict[int, dict[str, Any]] = {}
        for unit in refs:
            ref = unit["verify_ref"]
            line = ref["line"]
            if not 1 <= line <= len(records):
                raise StateCorrupt("verify_mismatch")
            record = records[line - 1]
            if not hmac.compare_digest(_sha(canonical_bytes(record)), ref["sha256"]):
                raise StateCorrupt("verify_mismatch")
            if (
                record["line"] != line
                or record["change_id"] != doc["id"]
                or record["unit"] != unit["n"]
                or record["verdict"] != unit["verify"]
                or record["plan_hash"] != doc["plan_hash"]
                or record["seq"] != record["seq_before"] + 1
                or record["seq"] > doc["seq"]
                or set(record["results"]) != set(unit["targets"])
            ):
                raise StateCorrupt("verify_mismatch")
            out[unit["n"]] = record
        return out

    # ------------------------------------------------------------------ writing

    def _write_change(self, doc: dict[str, Any]) -> None:
        try:
            schema.parse_state(doc)
        except Invalid:
            raise StoreError("state_build_invalid") from None
        paths.ensure_dir(self.roots.project, ".cab", "state", "changes")
        target = self.roots.at(".cab", "state", "changes", f"{doc['id']}.json")
        fsutil.atomic_write(target, canonical_bytes(doc))

    def _commit(self, doc: dict[str, Any], now: float) -> None:
        doc["seq"] += 1
        doc["updated_at"] = utc_text(now)
        self._write_change(doc)

    def _halt(self, doc: dict[str, Any], code: str, tool_use_id: str | None, now: float) -> dict:
        if doc["halted"] is not None:
            return doc
        new = copy.deepcopy(doc)
        new["state"] = "halted"
        new["halted"] = {"code": code, "at": utc_text(now), "tool_use_id": tool_use_id}
        self._commit(new, now)
        return new

    def _log(self, action: str, doc: Mapping[str, Any], seq: int, **fields: Any) -> None:
        self.ledger.append(
            "state", action=action, change_id=doc["id"], state=doc["state"], seq=seq, **fields
        )

    @staticmethod
    def _actor(actor: Any) -> str:
        if not isinstance(actor, str) or not actor or len(actor) > 128:
            raise NotAllowed("actor")
        return actor

    def _locked(self) -> Any:
        return fsutil.locked(self.roots.state_lock, self.lock_timeout)

    def _observation_public_ok(self, obs: Mapping[str, Any]) -> bool:
        """Integrity of a parsed snapshot observation against the current redactor.

        The stored ``argv``, ``human_command`` and ``object`` must already be redacted
        (redaction with the policy's extra patterns changes nothing), and for a measured
        object ``object_sha256 == sha256(canonical_json(redact_value(object)))``. So no
        raw secret, and no hash of one, becomes public snapshot evidence. Never raises;
        the rejected values are never logged or shown.
        """
        extra = self.policy.extra_patterns
        try:
            for word in obs["argv"]:
                if redact(word, extra) != word:
                    return False
            if redact(obs["human_command"], extra) != obs["human_command"]:
                return False
            if obs["status"] not in ("active", "soft_deleted"):
                return obs["object"] is None and obs["object_sha256"] is None
            obj = obs["object"]
            if not isinstance(obj, dict):
                return False
            shown = schema.canonical_json(redact_value(obj, extra))
            if shown != schema.canonical_json(obj):
                return False
            digest = hashlib.sha256(shown.encode("ascii")).hexdigest()
            return hmac.compare_digest(digest, obs["object_sha256"])
        except Exception:
            return False

    # ------------------------------------------------------------------ lifecycle

    def new_change(self, change_id: str, slug: str, actor: str) -> int:
        self._actor(actor)
        if not schema.is_change_id(change_id) or not schema.is_slug(slug):
            raise NotAllowed("change_name")
        now = self.clock()
        with self._locked():
            if self._read_active() is not None:
                raise NotAllowed("one_active_change")
            existing = self._read(f".cab/state/changes/{change_id}.json", schema.MAX_STATE_BYTES)
            if existing is not None:
                raise NotAllowed("exists")
            paths.ensure_dir(self.roots.project, ".cab", "state", "changes")
            paths.ensure_dir(self.roots.project, "changes", f"{change_id}-{slug}")
            at = utc_text(now)
            doc = {
                "schema": 1, "id": change_id, "slug": slug, "seq": 1, "state": "draft",
                "tier": None, "plan_hash": None, "review_start": None, "review_sha": None,
                "ack_review_sha": None, "approval_nonce": None, "snapshot_sha": None,
                "canary": "pending", "canary_unit": None, "units": [], "executed_steps": [],
                "settled_ids": [], "inflight": None, "halted": None,
                "created_at": at, "updated_at": at,
            }  # fmt: skip
            self._log("new", doc, 1, actor=actor)
            self._write_change(doc)
            fsutil.atomic_write(
                self.roots.active_file, canonical_bytes({"schema": 1, "change_id": change_id})
            )
            return 1

    def mark_planned(self, change_id: str, tier: str, expect_plan_hash: str, actor: str) -> int:
        """Record tier and plan hash. Re-planning drops review, ack, approval and snapshot."""
        self._actor(actor)
        if tier not in TIER_RANK:
            raise NotAllowed("tier")
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["state"] not in ("draft", "planned", "reviewed", "approved"):
                raise NotAllowed("state")
            if doc["inflight"] is not None:
                raise Conflict("inflight")
            _, _, current = self._load_plan(doc)
            if current != expect_plan_hash:
                raise Conflict("plan_changed")
            new = copy.deepcopy(doc)
            new.update(
                tier=tier, plan_hash=current, review_start=None, review_sha=None,
                ack_review_sha=None, approval_nonce=None, snapshot_sha=None, state="planned",
            )  # fmt: skip
            self._log("planned", new, doc["seq"] + 1, tier=tier, actor=actor)
            self._commit(new, now)
            return new["seq"]

    def begin_review(self, change_id: str, agent_id: str, *, session_id: str) -> str:
        """SubagentStart of the safety reviewer: remember the plan hash it starts from,
        the reviewer's agent ID and the parent session that started it.

        Requires a valid, complete and fresh snapshot of this plan."""
        if not schema.is_agent_id(agent_id):
            raise NotAllowed("agent_id")
        if not schema.is_token(session_id):
            raise NotAllowed("review_session")
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["state"] not in ("planned", "reviewed", "approved"):
                raise NotAllowed("state")
            if doc["tier"] not in ("normal", "critical"):
                raise NotAllowed("tier")
            if doc["inflight"] is not None:
                raise Conflict("inflight")
            _, targets, current = self._load_plan(doc)
            if current != doc["plan_hash"]:
                raise Conflict("plan_changed")
            code = self._snapshot_code(doc, self._change_dir(doc), current, targets, now)
            if code is not None:
                raise NotAllowed(code)
            new = copy.deepcopy(doc)
            new.update(
                review_start={
                    "plan_hash": current, "agent_id": agent_id, "session_id": session_id,
                    "at": utc_text(now),
                },
                review_sha=None, ack_review_sha=None, approval_nonce=None, state="planned",
            )  # fmt: skip
            self._log("review_start", new, doc["seq"] + 1, session_id=session_id)
            self._commit(new, now)
            return current

    def finish_review(
        self,
        change_id: str,
        agent_id: str,
        session_id: str,
        verdict: str,
        findings: Sequence[Mapping[str, str]],
    ) -> str:
        """SubagentStop of the safety reviewer: write review.json, return its SHA-256.

        ``session_id`` must be the parent session recorded by ``begin_review``; otherwise
        ``NotAllowed("review_session")`` and nothing is written (review_start, review,
        approval and ledger stay as they were). The review counts only when start, end and
        recorded plan hashes are equal and the verdict is not BLOCK; otherwise the change
        stays ``planned``.
        """
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            start = doc["review_start"]
            if start is None or start["agent_id"] != agent_id:
                raise NotAllowed("review_not_started")
            if not schema.is_token(session_id) or not hmac.compare_digest(
                session_id, start["session_id"]
            ):
                raise NotAllowed("review_session")
            _, _, end = self._load_plan(doc)
            review = {
                "schema": 1, "change_id": change_id, "verdict": verdict,
                "findings": [dict(f) for f in findings] if isinstance(findings, list) else None,
                "plan_hash_start": start["plan_hash"], "plan_hash_end": end,
                "agent_id": agent_id, "session_id": session_id,
                "started_at": start["at"], "stopped_at": utc_text(now),
            }  # fmt: skip
            try:
                data = canonical_bytes(review)
                schema.parse_review(data)
            except (Invalid, TypeError, ValueError):
                raise NotAllowed("review_invalid") from None
            sha = _sha(data)
            valid = verdict != "BLOCK" and start["plan_hash"] == end == doc["plan_hash"]
            new = copy.deepcopy(doc)
            new.update(
                review_sha=sha, review_start=None, ack_review_sha=None, approval_nonce=None,
                state="reviewed" if valid else "planned",
            )  # fmt: skip
            self._log("review", new, doc["seq"] + 1, outcome=verdict)
            fsutil.atomic_write(os.path.join(self._change_dir(doc), "review.json"), data)
            self._commit(new, now)
            return sha

    def ack(self, change_id: str, review_sha: str, actor: str) -> int:
        """A person acknowledged the conditions of a PASS_WITH_CONDITIONS review."""
        self._actor(actor)
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["state"] != "reviewed" or doc["review_sha"] != review_sha:
                raise Conflict("review")
            review = self._review(doc)
            if review is None or review["verdict"] != "PASS_WITH_CONDITIONS":
                raise NotAllowed("verdict")
            new = copy.deepcopy(doc)
            new["ack_review_sha"] = review_sha
            self._log("ack", new, doc["seq"] + 1, actor=actor)
            self._commit(new, now)
            return new["seq"]

    def record_snapshot(
        self, change_id: str, values: Mapping[str, Any], expect_plan_hash: str, actor: str
    ) -> int:
        """Write snapshot.json: one strict, fresh observation per planned target.

        Values must be snapshot observations (``schema.parse_observation``) observed in
        ``[now-300s, now+5s]``, already redacted, with ``object_sha256`` equal to the
        sha256 of the canonical redacted object (``snapshot_values`` otherwise, before any
        write). An incomplete snapshot (any ``unmeasured``) is recorded but
        never satisfies a gate. A fresh snapshot clears review, acknowledgement and
        approval: the state goes back to ``planned`` and they must be redone.
        """
        self._actor(actor)
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["state"] not in ("planned", "reviewed", "approved"):
                raise NotAllowed("state")
            if doc["inflight"] is not None:
                raise Conflict("inflight")
            _, targets, current = self._load_plan(doc)
            if current != expect_plan_hash or current != doc["plan_hash"]:
                raise Conflict("plan_changed")
            if not isinstance(values, Mapping) or set(values) != set(targets):
                raise NotAllowed("snapshot_targets")
            clean: dict[str, Any] = {}
            for target in targets:
                try:
                    obs = schema.parse_observation(copy.deepcopy(values[target]), with_object=True)
                except (Invalid, TypeError, ValueError, RecursionError):
                    raise NotAllowed("snapshot_values") from None
                if not self._observation_public_ok(obs):
                    raise NotAllowed("snapshot_values")  # unredacted or digest mismatch
                at = schema.utc_parse(obs["observed_at"])
                if not now - SNAPSHOT_PAST <= at <= now + SNAPSHOT_FUTURE:
                    raise NotAllowed("snapshot_stale_observation")
                clean[target] = obs
            snap = {
                "schema": 1, "change_id": change_id, "plan_hash": current,
                "taken_at": utc_text(now), "targets": clean,
            }  # fmt: skip
            try:
                data = canonical_bytes(snap)
                schema.parse_snapshot(data)
            except (Invalid, TypeError, ValueError):
                raise NotAllowed("snapshot_values") from None
            new = copy.deepcopy(doc)
            new["snapshot_sha"] = _sha(data)
            invalidated = any(
                doc[k] is not None
                for k in ("review_start", "review_sha", "ack_review_sha", "approval_nonce")
            )
            if invalidated:
                new.update(
                    review_start=None, review_sha=None, ack_review_sha=None,
                    approval_nonce=None, state="planned",
                )  # fmt: skip
            self._log(
                "snapshot", new, doc["seq"] + 1, actor=actor,
                reason_code="review_invalidated" if invalidated else None,
            )  # fmt: skip
            fsutil.atomic_write(os.path.join(self._change_dir(doc), "snapshot.json"), data)
            self._commit(new, now)
            return new["seq"]

    def approve(
        self,
        change_id: str,
        expect_seq: int,
        expect_plan_hash: str,
        review_sha: str,
        approver: Mapping[str, str],
    ) -> dict[str, Any]:
        """Commit a person's approval (the TTY prompt happened before, outside the lock).

        Order: registry line (L_ext, fsync) -> approval.json -> ledger -> state. A failure
        in between leaves records that disagree, and the guard refuses on disagreement.
        Requires a valid, complete and fresh snapshot of this plan.
        """
        if not isinstance(approver, Mapping) or set(approver) != {"os_user", "git_user"}:
            raise NotAllowed("approver")
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["seq"] != expect_seq:
                raise Conflict("seq")
            if doc["state"] != "reviewed" or doc["tier"] not in ("normal", "critical"):
                raise NotAllowed("state")
            if doc["inflight"] is not None:
                raise Conflict("inflight")
            _, targets, current = self._load_plan(doc)
            if current != expect_plan_hash or current != doc["plan_hash"]:
                raise Conflict("plan_changed")
            if doc["review_sha"] != review_sha:
                raise Conflict("review")
            if self._review_code(doc, current) is not None:
                raise NotAllowed("review_invalid")
            code = self._snapshot_code(doc, self._change_dir(doc), current, targets, now)
            if code is not None:
                raise NotAllowed(code)
            record = {
                "schema": 1, "change_id": change_id, "project": self.roots.project,
                "plan_hash": current, "review_sha256": review_sha, "tier": doc["tier"],
                "approver": {"os_user": approver["os_user"], "git_user": approver["git_user"]},
                "approved_at": utc_text(now),
                "expires_at": utc_text(now + self.policy.ttl_hours * 3600),
                "nonce": secrets.token_hex(16),
            }  # fmt: skip
            try:
                line = canonical_bytes(schema.parse_approval(record))
            except (Invalid, TypeError, ValueError):
                raise NotAllowed("approver") from None
            self._append_registry(line)
            fsutil.atomic_write(os.path.join(self._change_dir(doc), "approval.json"), line)
            new = copy.deepcopy(doc)
            new.update(approval_nonce=record["nonce"], state="approved")
            self._log("approve", new, doc["seq"] + 1, tier=doc["tier"])
            self._commit(new, now)
            return record

    def _append_registry(self, line: bytes) -> None:
        home = os.path.dirname(os.path.dirname(os.path.dirname(self.roots.state_home)))
        paths.ensure_dir(home, *paths.STATE_HOME_PARTS)
        with fsutil.locked(self.roots.approvals_lock, self.ext_timeout):
            fd = os.open(self.roots.approvals_file, _REGISTRY_FLAGS, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise StoreError("registry_unsafe")
                if st.st_size > 0 and os.pread(fd, 1, st.st_size - 1) != b"\n":
                    raise StoreError("registry_truncated")
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)

    # ------------------------------------------------------------------ authority checks

    def _review(self, doc: Mapping[str, Any]) -> dict[str, Any] | None:
        try:
            data = paths.read_authority(self._change_dir(doc), "review.json", 1 << 20)
            if data is None or doc["review_sha"] is None or _sha(data) != doc["review_sha"]:
                return None
            return schema.parse_review(data)
        except (UnsafePath, Invalid, NotAllowed):
            return None

    def _review_code(self, doc: Mapping[str, Any], current: str) -> str | None:
        review = self._review(doc)
        if review is None or review["change_id"] != doc["id"]:
            return "review_invalid"
        if review["plan_hash_start"] != current or review["plan_hash_end"] != current:
            return "review_invalid"
        if review["verdict"] == "PASS":
            return None
        acked = doc["ack_review_sha"] is not None and doc["ack_review_sha"] == doc["review_sha"]
        if review["verdict"] == "PASS_WITH_CONDITIONS" and acked:
            return None
        return "review_invalid"

    def _registry_rows(self) -> list[dict[str, Any]]:
        try:
            st = os.lstat(self.roots.state_home)
        except FileNotFoundError:
            return []
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise StoreError("registry_unsafe")
        with fsutil.locked(self.roots.approvals_lock, self.ext_timeout):
            data = paths.read_authority(
                self.roots.state_home, "approvals.jsonl", MAX_REGISTRY_BYTES
            )
        return read_jsonl_strict(data) if data else []

    def _approval_code(
        self, doc: Mapping[str, Any], folder: str, current: str, effective: str, now: float
    ) -> str | None:
        try:
            data = paths.read_authority(folder, "approval.json", 1 << 20)
        except UnsafePath:
            return "approval_invalid"
        if data is None or doc["approval_nonce"] is None:
            return "approval_missing"
        try:
            approval = schema.parse_approval(data)
            if canonical_bytes(approval) != data:
                return "approval_invalid"
            rows = self._registry_rows()
            last = None
            for row in rows:
                schema.parse_approval(row)
                if row["change_id"] == doc["id"] and row["project"] == self.roots.project:
                    last = row
        except (Invalid, LedgerFormatError, UnsafePath, StoreError, fsutil.FsError, OSError):
            return "approval_invalid"
        if last is None or last != approval:
            return "approval_invalid"
        if approval["change_id"] != doc["id"] or approval["project"] != self.roots.project:
            return "approval_invalid"
        if not hmac.compare_digest(approval["nonce"], doc["approval_nonce"]):
            return "approval_invalid"
        if approval["plan_hash"] != current or approval["review_sha256"] != doc["review_sha"]:
            return "approval_invalid"
        rank = TIER_RANK[approval["tier"]]
        if rank < TIER_RANK[effective] or rank < TIER_RANK[doc["tier"]]:
            return "approval_invalid"
        approved = schema.utc_parse(approval["approved_at"])
        expires = schema.utc_parse(approval["expires_at"])
        if expires - approved > self.policy.ttl_hours * 3600 + 1:
            return "approval_invalid"
        if approved > now:
            return "approval_invalid"
        if now >= expires:
            return "approval_expired"
        return None

    def _snapshot_code(
        self,
        doc: Mapping[str, Any],
        folder: str,
        current: str,
        targets: Sequence[str],
        now: float,
    ) -> str | None:
        """None when snapshot.json is the committed, plan-bound, complete baseline.

        Every observation must pass the redaction and digest rule of ``record_snapshot``
        under the current policy, else ``snapshot_invalid``. ``snapshot_stale``:
        no unit ran yet and the snapshot is older than the policy TTL
        (an executing change keeps its baseline)."""
        try:
            data = paths.read_authority(folder, "snapshot.json", schema.MAX_STATE_BYTES)
            if data is None or doc["snapshot_sha"] is None or _sha(data) != doc["snapshot_sha"]:
                return "snapshot_invalid"
            snap = schema.parse_snapshot(data)
        except (UnsafePath, Invalid):
            return "snapshot_invalid"
        if snap["change_id"] != doc["id"] or snap["plan_hash"] != current:
            return "snapshot_invalid"
        if set(snap["targets"]) != set(targets):
            return "snapshot_invalid"
        # same integrity rule as record_snapshot, against the current redactor and policy
        if not all(self._observation_public_ok(v) for v in snap["targets"].values()):
            return "snapshot_invalid"
        if not schema.snapshot_complete(snap):
            return "snapshot_incomplete"
        taken = schema.utc_parse(snap["taken_at"])
        if not doc["units"] and now - taken > self.policy.ttl_hours * 3600:
            return "snapshot_stale"
        return None

    def _scope_code(self, writes: Sequence[Result], tenant: str) -> str | None:
        for leaf in writes:
            if leaf.scope is None or leaf.scope != tenant:
                return "scope_mismatch"
            if leaf.adapter == "simtenant" and not paths.state_file_safe(self.roots, leaf.scope):
                return "scope_unsafe"
        return None

    @staticmethod
    def _bound_step(ctx: WriteContext, plan: ChangePlan) -> Step | str:
        if ctx.tool_name == "Bash" and ctx.command is not None:
            matches = [s for s in plan.steps if s.command is not None and s.command == ctx.command]
            if not matches:
                return "binding_missing"
            if not binding_safe(ctx.command):
                return "binding_dynamic"
        elif ctx.tool_name.startswith("mcp__") and ctx.mcp_input_sha256 is not None:
            matches = [
                s
                for s in plan.steps
                if s.tool == ctx.tool_name and s.input_sha256 == ctx.mcp_input_sha256
            ]
            if not matches:
                return "binding_missing"
        else:
            return "binding_missing"
        if len(matches) != 1:
            return "binding_ambiguous"
        return matches[0]

    @classmethod
    def _known_target_step(
        cls, ctx: WriteContext, plan: ChangePlan, unit_targets: Sequence[str]
    ) -> Step | None:
        """The approved step a known-target write executes, or None.

        Uses exactly the binding of the unknown-target path (``_bound_step``: one step with
        this literal, safe Bash command or this MCP tool and input hash) and additionally
        requires the step's targets to equal the extracted targets. Never matches by target
        alone and never refuses: a None only means "no planned step counted"."""
        bound = cls._bound_step(ctx, plan)
        if not isinstance(bound, Step):
            return None
        extracted, planned = tuple(unit_targets), tuple(bound.targets)
        if len(set(extracted)) != len(extracted) or len(set(planned)) != len(planned):
            return None
        if set(planned) != set(extracted):
            return None
        return bound

    # ------------------------------------------------------------------ guard

    def guard_write(self, ctx: WriteContext) -> GateResult:
        """Gate one administrative write (S4_DESIGN §4 step 6) and reserve it.

        Allowed only after every check passes, the reservation file is created, the state
        commit succeeds and the ledger row is durable. Any failure is a deny.
        """
        now = self.clock()
        try:
            with self._locked():
                return self._gate(ctx, now)
        except fsutil.LockTimeout:
            return GateResult(False, "lock_timeout")
        except StateCorrupt:
            return GateResult(False, "state_invalid")
        except (StoreError, fsutil.FsError, OSError, LedgerError):
            return GateResult(False, "state_invalid")

    def _gate(self, ctx: WriteContext, now: float) -> GateResult:
        active = self._read_active()
        if active is None:
            return GateResult(False, "no_open_change")
        if not ctx.cwd_is_project:
            return GateResult(False, "cwd_not_project", None, active)
        doc = self._read_change(active)
        self._consistent(doc)
        tier, cid = doc["tier"], doc["id"]

        def deny(code: str) -> GateResult:
            return GateResult(False, code, tier, cid)

        # 1. execution ended: open-unverified, or closed/failed with the pointer still set
        if doc["state"] in ENDED_STATES:
            return deny("execution_ended")
        # 2. state for the recorded tier
        if tier is None or doc["plan_hash"] is None:
            return deny("not_planned")
        if tier == "standard":
            if doc["state"] not in ("planned", "executing", "halted"):
                return deny("not_planned")
        elif doc["state"] not in ("approved", "executing", "halted"):
            return deny("approval_missing")
        try:
            plan, targets, current = self._load_plan(doc)
        except NotAllowed as exc:
            return deny(exc.code)
        # 3. effective tier: answers, catalogue (standard needs a current hit) and floor
        result = ctx.result
        hit = catalog_match(result, list(self.catalog))
        effective = decide_tier(
            plan.answers, irreversible=plan.irreversible, catalog_hit=hit, floor=ctx.floor
        )
        if effective == "blocked":
            return deny("tier_blocked")
        if effective not in TIER_RANK or TIER_RANK[effective] > TIER_RANK[tier]:
            return deny("tier_floor")
        # 4. plan hash, review, approval
        if current != doc["plan_hash"]:
            return deny("plan_changed")
        folder = self._change_dir(doc)
        if tier in ("normal", "critical"):
            code = self._review_code(doc, current)
            if code is None:
                code = self._approval_code(doc, folder, current, effective, now)
            if code:
                return deny(code)
        # 5. complete, fresh snapshot bound to the plan (every tier)
        code = self._snapshot_code(doc, folder, current, targets, now)
        if code:
            return deny(code)
        # 6. targets: extracted and in scope, or an exact approved step
        writes = [leaf for leaf in leaves(result) if leaf.kind == KIND_WRITE]
        step: Step | None = None
        if result.targets_complete and result.targets and not result.unknown:
            code = self._scope_code(writes, plan.tenant)
            if code:
                return deny(code)
            unit_targets = tuple(result.targets)
            if not set(unit_targets) <= set(targets):
                return deny("target_outside")
            # The write is allowed by its extracted targets, as before. It also counts as
            # a planned step only for an exact, unique, literal binding to one approved step
            # whose targets are exactly the extracted ones. Anything else (no match, several
            # matches, a dynamic command, other targets) is allowed but never counted, so
            # close still reports the step as not executed.
            step = self._known_target_step(ctx, plan, unit_targets)
        else:
            bound = self._bound_step(ctx, plan)
            if isinstance(bound, str):
                return deny(bound)
            if bound.id in doc["executed_steps"]:
                return deny("step_used")
            step = bound
            unit_targets = step.targets
        # 7. first unit alone, then nothing until its verify PASS
        canary_unit = False
        if tier in self.policy.canary_tiers and len(targets) > 1:
            if doc["canary"] == "awaiting":
                return deny("canary_awaiting")
            if doc["canary"] == "pending":
                if len(writes) != 1 or len(unit_targets) != 1:
                    return deny("canary_first_unit")
                canary_unit = True
        # 8-9. halted, in flight, replayed id
        if doc["halted"] is not None:
            return deny("halted")
        if doc["inflight"] is not None:
            return deny("inflight")
        if ctx.tool_use_id in doc["settled_ids"] or any(
            u["tool_use_id"] == ctx.tool_use_id for u in doc["units"]
        ):
            return deny("duplicate_id")
        # 10. call identity: session, tool and an HMAC over the exact raw input
        if not schema.is_token(ctx.session_id):
            return deny("event_invalid")
        salt = secrets.token_hex(16)
        digest = input_hmac(salt, ctx.tool_name, ctx.tool_input)
        if digest is None or len(ctx.tool_name) > 256:
            return deny("event_invalid")
        call = {
            "session_id": ctx.session_id, "tool": ctx.tool_name, "salt": salt,
            "input_hmac": digest,
        }  # fmt: skip

        try:
            fsutil.reserve(self.roots.inflight_file, ctx.tool_use_id)
        except fsutil.ReservationHeld:
            return deny("inflight")
        except (fsutil.FsError, OSError, ValueError):
            return deny("state_invalid")
        new = copy.deepcopy(doc)
        n = len(new["units"]) + 1
        at = utc_text(now)
        step_id = step.id if step is not None else None
        new["units"].append(
            {
                "n": n, "tool_use_id": ctx.tool_use_id, "step": step_id,
                "targets": list(unit_targets), "canary": canary_unit,
                "outcome": None, "verify": None, "at": at,
                "call": call, "receipt": None, "verify_ref": None,
            }
        )  # fmt: skip
        new["inflight"] = {
            "token": ctx.tool_use_id, "unit": n, "step": step_id,
            "targets": list(unit_targets), "canary": canary_unit,
            "input_sha256": ctx.fingerprint, "at": at,
        }  # fmt: skip
        # A repeated known-target write of an already counted step stays allowed (as
        # before) and is recorded on its unit, but the step is listed once only. The
        # unknown-target path never gets here with a used step (``step_used`` above).
        if step_id is not None and step_id not in new["executed_steps"]:
            new["executed_steps"].append(step_id)
        new["state"] = "executing"
        try:
            self._commit(new, now)
        except Exception:
            try:
                fsutil.release(self.roots.inflight_file, ctx.tool_use_id)
            except Exception:
                pass  # the reservation stays and blocks writes until a person resumes
            return deny("state_error")
        try:
            self.ledger.append(
                "pre",
                command=ctx.ledger_command,
                session_id=ctx.session_id,
                tool_use_id=ctx.tool_use_id,
                agent="main",
                agent_type=ctx.agent_type,
                change_id=cid,
                decision="allow",
                reason_code="write_reserved",
                tool=ctx.tool_name,
                cls=ctx.cls,
                tier=tier,
                unit=n,
                seq=new["seq"],
            )
        except LedgerError:
            try:
                self._halt(new, "ledger_error", ctx.tool_use_id, now)
            except Exception:
                pass  # the reservation alone still blocks every write
            return deny("ledger_error")
        return GateResult(True, "write_reserved", tier, cid)

    # ------------------------------------------------------------------ results

    @staticmethod
    def _same_call(call: Mapping[str, Any], receipt: Receipt) -> bool:
        """Exact identity: session, tool and the HMAC over the raw input."""
        if type(receipt.session_id) is not str or receipt.session_id != call["session_id"]:
            return False
        if type(receipt.tool_name) is not str or receipt.tool_name != call["tool"]:
            return False
        digest = input_hmac(call["salt"], receipt.tool_name, receipt.tool_input)
        return digest is not None and hmac.compare_digest(digest, call["input_hmac"])

    def settle(self, receipt: Receipt) -> int:
        """Record the result of a reserved write (Post/PostFailure hooks).

        - the in-flight token with the exact identity settles once and stores the receipt;
          ``failed``/``unknown`` halt the change; a canary unit waits for verify PASS;
        - the in-flight token with any other identity halts (``settle_mismatch``) and keeps
          the reservation;
        - an already settled token with the exact identity and an equal result (not after
          a ``resume``) is a ``Replay`` and changes no byte; any other result is
          ``result_conflict``: the unit becomes ``unknown``, its verification is dropped,
          a canary unit waits again and the change halts; the receipt keeps the original;
        - an already settled token with another identity halts and changes no unit;
        - an unknown token halts (``unguarded_write``).
        """
        if not _receipt_ok(receipt):
            raise NotAllowed("settle_input")
        tool_use_id = receipt.tool_use_id
        now = self.clock()
        with self._locked():
            active = self._read_active()
            if active is None:
                raise NotAllowed("no_open_change")
            doc = self._read_change(active)
            self._consistent(doc)
            if doc["state"] in ("closed", "failed"):
                raise NotAllowed("closed")
            inflight = doc["inflight"]
            if inflight is not None and inflight["token"] == tool_use_id:
                return self._settle_inflight(doc, receipt, now)
            settled = [u for u in doc["units"] if u["tool_use_id"] == tool_use_id and u["receipt"]]
            if not settled:
                halted = self._halt(doc, "unguarded_write", tool_use_id, now)
                self._log_best_effort("unguarded_write", halted, receipt)
                raise Halted("unguarded_write")
            unit = settled[0]
            if not self._same_call(unit["call"], receipt):
                halted = self._halt(doc, "settle_mismatch", tool_use_id, now)
                self._log_best_effort("settle_mismatch", halted, receipt)
                raise Halted("settle_mismatch")
            stored = unit["receipt"]
            same = (
                stored["source"] != "resume"
                and stored["source"] == receipt.source
                and stored["outcome"] == receipt.outcome
                and stored["exit"] == receipt.exit
                and stored["response_sha256"] == receipt.response_sha256
            )
            if same:
                raise Replay("replay")
            self._conflict(doc, unit["n"], receipt, now)
            raise Halted("result_conflict")

    def _settle_inflight(self, doc: dict[str, Any], receipt: Receipt, now: float) -> int:
        inflight = doc["inflight"]
        tool_use_id = receipt.tool_use_id
        unit_doc = doc["units"][inflight["unit"] - 1]
        fp_ok = isinstance(receipt.fingerprint, str) and hmac.compare_digest(
            receipt.fingerprint, inflight["input_sha256"]
        )
        if not fp_ok or not self._same_call(unit_doc["call"], receipt):
            halted = self._halt(doc, "settle_mismatch", tool_use_id, now)
            self._log_best_effort("settle_mismatch", halted, receipt)
            raise Halted("settle_mismatch")
        outcome = receipt.outcome
        new = copy.deepcopy(doc)
        unit = new["units"][inflight["unit"] - 1]
        unit["outcome"] = outcome
        unit["receipt"] = {
            "source": receipt.source, "outcome": outcome, "at": utc_text(now),
            "exit": receipt.exit, "response_sha256": receipt.response_sha256,
        }  # fmt: skip
        new["settled_ids"].append(tool_use_id)
        new["inflight"] = None
        if inflight["canary"]:
            new["canary"] = "awaiting"
            new["canary_unit"] = unit["n"]
        if outcome != "ok" and new["halted"] is None:
            code = "write_failed" if outcome == "failed" else "write_unknown"
            new["state"] = "halted"
            new["halted"] = {"code": code, "at": utc_text(now), "tool_use_id": tool_use_id}
        try:
            fsutil.release(self.roots.inflight_file, tool_use_id)
        except fsutil.ReservationError:
            raise StateCorrupt("inflight_mismatch") from None
        self._commit(new, now)
        try:
            self.ledger.append(
                "settle", change_id=new["id"], tool_use_id=tool_use_id, outcome=outcome,
                unit=unit["n"], state=new["state"], seq=new["seq"], source=receipt.source,
                exit=receipt.exit, response_sha256=receipt.response_sha256,
            )  # fmt: skip
        except LedgerError:
            self._halt(new, "ledger_error", tool_use_id, now)
            raise Halted("ledger_error") from None
        return new["seq"]

    def _conflict(self, doc: dict[str, Any], n: int, receipt: Receipt, now: float) -> None:
        """A later, different result for a settled unit: add debt, never remove it."""
        new = copy.deepcopy(doc)
        unit = new["units"][n - 1]
        unit["outcome"] = "unknown"
        unit["verify"] = None
        unit["verify_ref"] = None
        if unit["canary"]:
            new["canary"] = "awaiting"
            new["canary_unit"] = n
        if new["halted"] is None:
            new["state"] = "halted"
            new["halted"] = {
                "code": "result_conflict", "at": utc_text(now),
                "tool_use_id": receipt.tool_use_id,
            }  # fmt: skip
        self._commit(new, now)
        self._log_best_effort("result_conflict", new, receipt)

    def _log_best_effort(self, code: str, doc: Mapping[str, Any], receipt: Receipt) -> None:
        try:
            self.ledger.append(
                "settle", change_id=doc["id"], tool_use_id=receipt.tool_use_id,
                reason_code=code, state=doc["state"], seq=doc["seq"], source=receipt.source,
                outcome=receipt.outcome, exit=receipt.exit,
                response_sha256=receipt.response_sha256,
            )  # fmt: skip
        except LedgerError:
            pass  # already halted

    def record_verify(
        self,
        change_id: str,
        unit: int,
        results: Mapping[str, str],
        expect_seq: int,
        expect_plan_hash: str,
        *,
        evidence: Mapping[str, Any],
    ) -> int:
        """Record re-read results for one settled unit (exact unit, seq and plan hash).

        ``evidence`` is ``{started_at, finished_at, schedule, results}``; ``results[t]``
        must equal ``evidence["results"][t]["verdict"]``. Order under L_state: validate,
        read and strictly parse ``verify.json`` (damaged -> ``verify_log_damaged``, bytes
        untouched), append one record and atomically replace the file, write the ledger
        row, commit the state with ``verify`` and ``verify_ref``. Only all-PASS is PASS.

        Allowed in ``executing``, ``halted`` and ``open-unverified``; execution never ends
        here. PASS of the awaiting canary releases it; any FAIL halts (``verify_failed``)
        unless the change is already halted.
        """
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["seq"] != expect_seq:
                raise Conflict("seq")
            if doc["inflight"] is not None or self._token_on_disk() is not None:
                raise Conflict("inflight")
            if doc["state"] not in VERIFY_STATES:
                raise NotAllowed("state")
            _, _, current = self._load_plan(doc)
            if current != expect_plan_hash or current != doc["plan_hash"]:
                raise Conflict("plan_changed")
            if type(unit) is not int or not 1 <= unit <= len(doc["units"]):
                raise NotAllowed("unit")
            if doc["units"][unit - 1]["outcome"] is None:
                raise NotAllowed("unit")
            expected = set(doc["units"][unit - 1]["targets"])
            if not isinstance(results, Mapping) or not expected or set(results) != expected:
                raise NotAllowed("results")
            values = list(results.values())
            if any(v not in schema.VERIFY_VALUES for v in values):
                raise NotAllowed("results")
            overall = schema.verify_aggregate(values)
            if not isinstance(evidence, Mapping) or set(evidence) != {
                "started_at", "finished_at", "schedule", "results",
            }:  # fmt: skip
                raise NotAllowed("evidence")
            ev_results = evidence["results"]
            if not isinstance(ev_results, Mapping) or set(ev_results) != expected:
                raise NotAllowed("evidence")
            for target in expected:
                item = ev_results[target]
                if not isinstance(item, Mapping) or item.get("verdict") != results[target]:
                    raise NotAllowed("evidence")
            folder = self._change_dir(doc)
            try:
                vdoc = self._verify_doc(folder)
            except (UnsafePath, Invalid):
                raise NotAllowed("verify_log_damaged") from None
            records = list(vdoc["records"]) if vdoc is not None else []
            if any(r["change_id"] != doc["id"] for r in records):
                raise NotAllowed("verify_log_damaged")
            line = len(records) + 1
            if line > schema.MAX_VERIFY_RECORDS:
                raise NotAllowed("verify_log_full")
            record = {
                "schema": 1, "change_id": doc["id"], "line": line, "unit": unit,
                "seq_before": doc["seq"], "seq": doc["seq"] + 1, "plan_hash": current,
                "verdict": overall, "started_at": evidence["started_at"],
                "finished_at": evidence["finished_at"],
                "schedule": copy.deepcopy(evidence["schedule"]),
                "results": copy.deepcopy(dict(ev_results)),
            }  # fmt: skip
            try:
                schema.parse_verify_record(record)
                rec_bytes = canonical_bytes(record)
            except (Invalid, TypeError, ValueError, RecursionError):
                raise NotAllowed("evidence") from None
            if len(rec_bytes) > schema.MAX_VERIFY_RECORD_BYTES:
                raise NotAllowed("evidence")
            data = canonical_bytes({"schema": 1, "records": [*records, record]})
            if len(data) > schema.MAX_VERIFY_BYTES:
                raise NotAllowed("verify_log_full")
            # 1. evidence (an unreferenced record is never evidence)
            fsutil.atomic_write(os.path.join(folder, "verify.json"), data)
            # 2. ledger row: an intent until a state with this seq is committed
            new = copy.deepcopy(doc)
            target_unit = new["units"][unit - 1]
            target_unit["verify"] = overall
            target_unit["verify_ref"] = {"line": line, "sha256": _sha(rec_bytes)}
            if new["canary"] == "awaiting" and new["canary_unit"] == unit:
                if overall == "PASS":
                    new["canary"] = "passed"
            if overall == "FAIL" and new["halted"] is None:
                new["state"] = "halted"
                new["halted"] = {"code": "verify_failed", "at": utc_text(now), "tool_use_id": None}
            self._log("verify", new, doc["seq"] + 1, unit=unit, outcome=overall)
            # 3. state commit (verify and verify_ref land together)
            self._commit(new, now)
            return new["seq"]

    def resume(
        self, change_id: str, actor: str, *, expect_seq: int, clear_inflight: bool = False
    ) -> int:
        """A person's ``cab resume`` (TTY). Clears a halt; with ``clear_inflight`` also a
        reservation that never got a result, recorded as outcome ``unknown`` with a
        ``resume`` receipt (its targets count as written and stay unverified; a canary
        unit waits for PASS). Any later result for that call is ``result_conflict``.
        Verification obligations and used steps are never reset."""
        self._actor(actor)
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if type(expect_seq) is not int or doc["seq"] != expect_seq:
                raise Conflict("seq")
            if doc["state"] in ("closed", "failed"):
                raise NotAllowed("state")
            on_disk = self._token_on_disk()
            inflight = doc["inflight"]
            new = copy.deepcopy(doc)
            release_token = None
            if inflight is not None:
                if not clear_inflight:
                    raise NotAllowed("inflight")
                if on_disk not in (None, inflight["token"]):
                    raise StateCorrupt("inflight_mismatch")
                unit = new["units"][inflight["unit"] - 1]
                unit["outcome"] = "unknown"
                unit["receipt"] = {
                    "source": "resume", "outcome": "unknown", "at": utc_text(now),
                    "exit": None, "response_sha256": None,
                }  # fmt: skip
                new["settled_ids"].append(inflight["token"])
                if inflight["canary"]:
                    new["canary"] = "awaiting"
                    new["canary_unit"] = unit["n"]
                new["inflight"] = None
                release_token = on_disk
            elif on_disk is not None:
                if not clear_inflight:
                    raise StateCorrupt("inflight_mismatch")
                release_token = on_disk  # orphan reservation without a unit
            elif doc["state"] != "halted":
                raise NotAllowed("not_halted")
            new["halted"] = None
            if new["state"] == "halted":
                new["state"] = "executing"
            self._log("resume", new, doc["seq"] + 1, actor=actor)
            if release_token is not None:
                fsutil.release(self.roots.inflight_file, release_token)
            self._commit(new, now)
            return new["seq"]

    # ------------------------------------------------------------------ closeout

    def close(
        self, change_id: str, actor: str, expect_seq: int, expect_plan_hash: str
    ) -> CloseResult:
        """End a change. Only ``closed`` (every unit PASS with committed evidence, every
        planned target and step executed) is success.

        Rules, in order:
          1. already ``closed``/``failed`` with the pointer still set and ``seq`` equal:
             clear the pointer (``already_closed``);
          2. seq CAS, nothing in flight (state or disk);
          3. nothing settled and still before execution: ``failed/not_executed``;
          4. plan-hash CAS;
          5. state ``executing``, ``open-unverified`` or halted with ``write_failed``,
             ``write_unknown`` or ``verify_failed``; any other halt: ``NotAllowed("halted")``;
          6. any unit without a verdict: ``NotAllowed("unverified_units")``;
          7. committed evidence must match (``StateCorrupt``);
          8. any FAIL: ``failed/verify_failed``;
          9. halted without FAIL: ``NotAllowed("halted")``;
         10. any UNMEASURED: ``open-unverified/unmeasured`` (stays active, no writes);
         11. a planned target or step never executed: ``failed/execution_incomplete``;
         12. otherwise ``closed/all_pass``.
        Writes: ledger, then the state (halt cleared), then ``active.json`` = null for
        closed/failed. A failed pointer write leaves the pointer on the ended change;
        running ``close`` again finishes it (rule 1).
        """
        self._actor(actor)
        now = self.clock()
        with self._locked():
            doc = self._active_doc(change_id)
            if doc["state"] in ("closed", "failed"):
                if type(expect_seq) is not int or doc["seq"] != expect_seq:
                    raise Conflict("seq")
                self._log("close_finish", doc, doc["seq"], actor=actor,
                          reason_code="already_closed")  # fmt: skip
                self._clear_active()
                return CloseResult(doc["seq"], doc["state"], "already_closed")
            if type(expect_seq) is not int or doc["seq"] != expect_seq:
                raise Conflict("seq")
            if doc["inflight"] is not None or self._token_on_disk() is not None:
                raise Conflict("inflight")
            settled = [u for u in doc["units"] if u["outcome"] is not None]
            if not settled and doc["state"] in ("draft", "planned", "reviewed", "approved"):
                return self._finish(doc, "failed", "not_executed", actor, now)
            plan, targets, current = self._load_plan(doc)
            if current != expect_plan_hash or current != doc["plan_hash"]:
                raise Conflict("plan_changed")
            state = doc["state"]
            halted = doc["halted"]
            if state == "halted":
                if halted is None or halted["code"] not in CLOSABLE_HALTS:
                    raise NotAllowed("halted")
            elif state not in ("executing", "open-unverified"):
                raise NotAllowed("state")
            if any(u["verify"] is None for u in settled):
                raise NotAllowed("unverified_units")
            self.verify_evidence(doc)
            verdicts = [u["verify"] for u in settled]
            if "FAIL" in verdicts:
                return self._finish(doc, "failed", "verify_failed", actor, now)
            if state == "halted":
                raise NotAllowed("halted")
            if "UNMEASURED" in verdicts:
                return self._finish(doc, "open-unverified", "unmeasured", actor, now)
            written = {t for u in settled for t in u["targets"]}
            steps_done = set(doc["executed_steps"])
            if not set(targets) <= written or not {s.id for s in plan.steps} <= steps_done:
                return self._finish(doc, "failed", "execution_incomplete", actor, now)
            return self._finish(doc, "closed", "all_pass", actor, now)

    def _finish(
        self, doc: dict[str, Any], state: str, reason: str, actor: str, now: float
    ) -> CloseResult:
        new = copy.deepcopy(doc)
        new["state"] = state
        new["halted"] = None
        self._log("close", new, doc["seq"] + 1, actor=actor, reason_code=reason)
        self._commit(new, now)
        if state in ("closed", "failed"):
            self._clear_active()
        return CloseResult(new["seq"], state, reason)

    def _clear_active(self) -> None:
        fsutil.atomic_write(
            self.roots.active_file, canonical_bytes({"schema": 1, "change_id": None})
        )
