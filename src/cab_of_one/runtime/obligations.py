"""Pure obligation evaluation for Stop and ``cab status`` (S5 C0).

``evaluate(view, evidence)`` reads the current ``View`` (``active`` and ``change``, as
``Store.load()`` returns them) plus the committed evidence dict (``Store.verify_evidence``:
unit number -> verify record) and says what is still owed. It never reads files, never
calls the Store and never writes anything.

It distinguishes:

- *no observation*: a settled unit whose ``verify`` is null. Failed and unknown writes
  count, because they may have written;
- *durable* FAIL / UNMEASURED: committed verdicts, each target with the exact redacted
  command a person must run;
- an in-flight write, a halted change, and a close that did not finish (the active
  pointer still names a ``closed``/``failed`` change).

Any inconsistency between the view and the evidence raises ``ObligationsError``; the
caller must then treat the state as invalid (Stop blocks with ``state_invalid``).

``stop_message(ob)`` builds the fixed Stop texts (S5 contract section 4.3). A block is
never softened into a report, and no text here says verified, done or closed unless the
state is literally ``closed``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .ledger import redact

__all__ = [
    "CLI",
    "MAX_REPORT_COMMANDS",
    "STATES",
    "Obligations",
    "ObligationsError",
    "Pending",
    "StopMessage",
    "evaluate",
    "stop_message",
]

CLI = ".claude/hooks/cab/cab"
MAX_REPORT_COMMANDS = 5
MAX_COMMAND_CHARS = 2048
STATES = frozenset(
    {
        "draft",
        "planned",
        "reviewed",
        "approved",
        "executing",
        "halted",
        "closed",
        "failed",
        "open-unverified",
    }
)
ENDED = frozenset({"closed", "failed"})
CLOSE_CAN_FAIL_CODES = frozenset({"write_failed", "write_unknown", "verify_failed"})
VERDICTS = ("PASS", "FAIL", "UNMEASURED")

_CHANGE_ID = re.compile(r"CHG-[0-9]{4}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ObligationsError(Exception):
    """View or evidence is unusable. ``code`` is fixed and non-sensitive."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Pending:
    """One target of a committed FAIL or UNMEASURED unit."""

    unit: int
    target: str
    verdict: str
    reason: str | None
    human_command: str


@dataclass(frozen=True)
class Obligations:
    change_id: str | None
    state: str | None
    inflight_token: str | None
    halted_code: str | None
    unverified_units: tuple[int, ...]
    unverified_failed: int
    unverified_unknown: int
    fail_units: tuple[int, ...]
    unmeasured_units: tuple[int, ...]
    pending: tuple[Pending, ...]
    close_incomplete: bool
    close_can_fail: bool

    @property
    def blocking(self) -> bool:
        return bool(
            self.inflight_token is not None
            or self.unverified_units
            or self.halted_code is not None
            or self.close_incomplete
        )

    @property
    def reportable(self) -> bool:
        return not self.blocking and bool(
            self.fail_units or self.unmeasured_units or self.state == "open-unverified"
        )

    def commands(self, limit: int = MAX_REPORT_COMMANDS) -> tuple[str, ...]:
        """Distinct human commands of FAIL/UNMEASURED targets, in unit/target order."""
        out: list[str] = []
        for item in self.pending:
            if item.human_command not in out:
                out.append(item.human_command)
            if len(out) >= limit:
                break
        return tuple(out)


NOTHING = Obligations(None, None, None, None, (), 0, 0, (), (), (), False, False)


# --------------------------------------------------------------------------- checks


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ObligationsError(code)


def _int(value: Any) -> bool:
    return type(value) is int


def _command(value: Any) -> str:
    _require(
        type(value) is str and 0 < len(value) <= MAX_COMMAND_CHARS and not _CONTROL.search(value),
        "evidence_command",
    )
    return redact(value)


def _aggregate(verdicts: list[str]) -> str:
    if all(v == "PASS" for v in verdicts):
        return "PASS"
    if any(v == "FAIL" for v in verdicts):
        return "FAIL"
    return "UNMEASURED"


def _record_pending(
    change_id: str, plan_hash: Any, unit: Mapping[str, Any], record: Any
) -> list[Pending]:
    n = unit["n"]
    _require(isinstance(record, Mapping), "evidence_record")
    _require(record.get("change_id") == change_id, "evidence_change")
    _require(record.get("unit") == n, "evidence_unit")
    _require(record.get("verdict") == unit["verify"], "evidence_verdict")
    _require(plan_hash is not None and record.get("plan_hash") == plan_hash, "evidence_plan")
    results = record.get("results")
    _require(isinstance(results, Mapping), "evidence_results")
    targets = unit.get("targets")
    _require(type(targets) is list, "state_unit")
    _require(set(results) == set(targets), "evidence_targets")
    verdicts: list[str] = []
    pending: list[Pending] = []
    for target in targets:
        result = results[target]
        _require(isinstance(result, Mapping), "evidence_result")
        verdict = result.get("verdict")
        _require(verdict in VERDICTS, "evidence_result")
        verdicts.append(verdict)
        if verdict == "PASS":
            continue
        reason = result.get("reason")
        _require(reason is None or type(reason) is str, "evidence_result")
        command = _command(result.get("human_command"))
        pending.append(Pending(n, target, verdict, reason, command))
    _require(_aggregate(verdicts) == record.get("verdict"), "evidence_verdict")
    return pending


# --------------------------------------------------------------------------- evaluate


def evaluate(view: Any, evidence: Mapping[int, Any]) -> Obligations:
    """What the active change still owes. Raises ``ObligationsError`` when unusable."""
    active = getattr(view, "active", None)
    change = getattr(view, "change", None)
    if active is None:
        _require(change is None, "view")
        _require(isinstance(evidence, Mapping) and not evidence, "evidence_extra")
        return NOTHING
    _require(type(active) is str and bool(_CHANGE_ID.fullmatch(active)), "view")
    _require(isinstance(change, Mapping), "view")
    _require(change.get("id") == active, "view")
    _require(isinstance(evidence, Mapping), "evidence")

    state = change.get("state")
    _require(state in STATES, "state_state")
    units = change.get("units")
    _require(type(units) is list, "state_units")

    inflight = change.get("inflight")
    token = None
    if inflight is not None:
        _require(isinstance(inflight, Mapping), "inflight")
        _require(type(inflight.get("token")) is str, "inflight")
        token = inflight["token"]

    halted = change.get("halted")
    halted_code = None
    if halted is not None:
        _require(isinstance(halted, Mapping) and type(halted.get("code")) is str, "halted")
        halted_code = halted["code"]
    _require((state == "halted") == (halted_code is not None), "halted")

    unverified: list[int] = []
    failed = unknown = 0
    fail_units: list[int] = []
    unmeasured_units: list[int] = []
    pending: list[Pending] = []
    referenced: set[int] = set()
    for index, unit in enumerate(units):
        _require(isinstance(unit, Mapping) and unit.get("n") == index + 1, "state_unit")
        n = unit["n"]
        outcome = unit.get("outcome")
        verify = unit.get("verify")
        _require(outcome in (None, "ok", "failed", "unknown"), "state_unit")
        _require(verify in (None, *VERDICTS), "state_unit")
        if outcome is None:
            # Only the in-flight reservation may be unsettled; it is reported as inflight.
            is_inflight = inflight is not None and inflight.get("unit") == n
            _require(verify is None and is_inflight, "state_unit")
            continue
        if verify is None:
            unverified.append(n)
            if outcome == "failed":
                failed += 1
            elif outcome == "unknown":
                unknown += 1
            continue
        _require(n in evidence, "evidence_missing")
        referenced.add(n)
        pending.extend(_record_pending(active, change.get("plan_hash"), unit, evidence[n]))
        if verify == "FAIL":
            fail_units.append(n)
        elif verify == "UNMEASURED":
            unmeasured_units.append(n)
    _require(all(_int(k) for k in evidence) and set(evidence) == referenced, "evidence_extra")

    close_incomplete = state in ENDED
    close_can_fail = (
        state == "halted"
        and halted_code in CLOSE_CAN_FAIL_CODES
        and token is None
        and not unverified
        and bool(fail_units)
    )
    return Obligations(
        change_id=active,
        state=state,
        inflight_token=token,
        halted_code=halted_code,
        unverified_units=tuple(unverified),
        unverified_failed=failed,
        unverified_unknown=unknown,
        fail_units=tuple(fail_units),
        unmeasured_units=tuple(unmeasured_units),
        pending=tuple(pending),
        close_incomplete=close_incomplete,
        close_can_fail=close_can_fail,
    )


# --------------------------------------------------------------------------- Stop texts


@dataclass(frozen=True)
class StopMessage:
    """``kind`` is ``none``, ``block`` (Stop decision block) or ``report`` (systemMessage)."""

    kind: str
    text: str


def stop_message(ob: Obligations) -> StopMessage:
    cid = ob.change_id
    if cid is None:
        return StopMessage("none", "")
    parts: list[str] = []
    if ob.inflight_token is not None:
        parts.append(
            f"{cid}: a write never returned a result. Stop writing; a person must run "
            f"cab resume {cid} in their own terminal."
        )
    if ob.unverified_units:
        parts.append(
            f"{cid} has {len(ob.unverified_units)} writes with no verification after them "
            f"({ob.unverified_failed} failed, {ob.unverified_unknown} result unknown). "
            f"Run {CLI} verify {cid}."
        )
    if ob.halted_code is not None:
        text = (
            f"{cid} is halted [{ob.halted_code}]. Stop writing; a person decides: "
            f"cab resume {cid} in their own terminal"
        )
        if ob.close_can_fail:
            text += f", or end it as failed: {CLI} close {cid}"
        parts.append(text + ".")
    if ob.close_incomplete:
        parts.append(
            f"{cid} is {ob.state} but its close did not finish. Run {CLI} close {cid} again."
        )
    if parts:
        return StopMessage("block", " ".join(parts))
    if ob.reportable:
        n_fail = sum(1 for p in ob.pending if p.verdict == "FAIL")
        n_unm = sum(1 for p in ob.pending if p.verdict == "UNMEASURED")
        commands = ob.commands()
        text = f"{cid} is not verified ({n_fail} FAIL, {n_unm} UNMEASURED); it is not closed."
        if commands:
            text += " A person must check: " + "; ".join(commands) + "."
        text += f" See {CLI} status {cid}."
        return StopMessage("report", text)
    return StopMessage("none", "")
