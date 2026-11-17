"""S5 snapshot and verify runs over the read runner (S5_IMPLEMENT_CONTRACT §3).

``run_snapshot`` takes one fresh, typed observation per planned target and records it with
``Store.record_snapshot``. A target without a supported read runner is recorded as
``unmeasured`` with its exact redacted command; the snapshot is then incomplete (exit 11)
and is never a baseline.

``run_verify`` re-reads the tenant for *every* settled unit whose verification is not PASS
(including failed and unknown writes), retrying only pending targets on the policy
schedule within ``TOTAL_BUDGET``. Probes run without the state lock. Results are then
committed unit by unit through the CAS chain ``s = record_verify(..., s, plan_hash0)``;
a conflict stops the chain and the report names what was and was not committed.

Verdicts per target: PASS on the first match; FAIL only when the final scheduled attempt
completed as a mismatch and nothing ever matched; UNMEASURED otherwise (including
``time_budget``). Exit codes: 0 all PASS, 10 any FAIL, 11 any UNMEASURED, 3 not allowed,
4 conflict / plan changed / lock timeout, 5 state or store error.

Store API used (as declared in the contract, §2.2): ``load() -> View(active, change)``,
``load_plan(change_id) -> (ChangePlan, targets, plan_hash)``, ``record_verify``,
``record_snapshot``. Exceptions: ``state.Conflict``, ``state.NotAllowed``,
``state.StateCorrupt`` and ``fsutil.LockTimeout``. The change document names its change
``id`` (``state.Store.new_change``); ``View.active`` is the active change ID.

Evidence is public: every observation, command and checked value is redacted with the
policy's ``extra_patterns`` as well (``ledger.redact``/``redact_value``), and an object
digest is the sha256 of that redacted object, which is exactly what
``Store.record_snapshot`` checks. A policy without readable ``extra_patterns`` is
``redaction_unavailable`` (exit 5) before anything runs.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import fsutil, ledger, probes, schema
from .probes import (
    MATCH,
    MISMATCH,
    R_SCOPE_UNSAFE,
    R_SCRIPT_CHANGED,
    RUN_TIMEOUT,
    TOTAL_BUDGET,
    UNMEASURABLE,
    Clock,
    ExecSpec,
    RedactionUnavailable,
    Runner,
    Unmeasured,
)

__all__ = [
    "EXIT_CONFLICT",
    "EXIT_ERROR",
    "EXIT_FAIL",
    "EXIT_NOT_ALLOWED",
    "EXIT_OK",
    "EXIT_UNMEASURED",
    "FAIL",
    "PASS",
    "UNMEASURED",
    "SnapshotReport",
    "TargetResult",
    "UnitVerdict",
    "VerifyReport",
    "aggregate",
    "extra_patterns",
    "measure",
    "retry_schedule",
    "run_snapshot",
    "run_verify",
    "snapshot_lines",
    "verify_lines",
]

PASS = "PASS"
FAIL = "FAIL"
UNMEASURED = "UNMEASURED"

EXIT_OK = 0
EXIT_NOT_ALLOWED = 3
EXIT_CONFLICT = 4
EXIT_ERROR = 5
EXIT_FAIL = 10
EXIT_UNMEASURED = 11

VERIFY_STATES = frozenset({"executing", "halted", "open-unverified"})
SNAPSHOT_STATES = frozenset({"planned", "reviewed", "approved"})
REVIEW_FIELDS = ("review_start", "review_sha", "ack_review_sha", "approval_nonce")
MAX_SCHEDULE = 10
MAX_DELAY = 600

R_TIME_BUDGET = "time_budget"
R_NOT_CONVERGED = "not_converged"
R_NO_TARGETS = "unit_without_targets"
_TERMINAL_REASONS = frozenset({R_SCRIPT_CHANGED, R_SCOPE_UNSAFE})
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MISSING: Any = object()


# --------------------------------------------------------------------------- reports


@dataclass(frozen=True)
class TargetResult:
    """One target's verdict and its redacted evidence (``evidence()`` is the record entry)."""

    target: str
    verdict: str
    attempts: int
    reason: str | None
    human_command: str
    last: Mapping[str, Any] | None
    checked: Mapping[str, str | None]

    def evidence(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "attempts": self.attempts,
            "reason": self.reason,
            "human_command": self.human_command,
            "last": None if self.last is None else dict(self.last),
            "checked": dict(self.checked),
        }


@dataclass(frozen=True)
class UnitVerdict:
    unit: int
    verdict: str
    targets: tuple[str, ...]
    committed: bool
    seq: int | None


@dataclass(frozen=True)
class VerifyReport:
    change_id: str
    exit: int
    code: str | None
    seq: int | None
    verdict: str | None
    units: tuple[UnitVerdict, ...] = ()
    results: Mapping[str, TargetResult] = field(default_factory=dict)
    schedule: tuple[int, ...] = ()
    started_at: str | None = None
    finished_at: str | None = None
    recorded_plan_hash: str | None = None

    @property
    def committed(self) -> tuple[int, ...]:
        return tuple(u.unit for u in self.units if u.committed)

    @property
    def not_committed(self) -> tuple[int, ...]:
        return tuple(u.unit for u in self.units if not u.committed)


@dataclass(frozen=True)
class SnapshotReport:
    change_id: str
    exit: int
    code: str | None
    seq: int | None
    complete: bool
    values: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    unmeasured: tuple[tuple[str, str, str], ...] = ()  # (target, reason, human_command)
    review_invalidated: bool = False
    recorded_plan_hash: str | None = None


# --------------------------------------------------------------------------- helpers


def _f(obj: Any, name: str, default: Any = None) -> Any:
    """Field of a state/plan object, whether it is a mapping or an attribute object."""
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _code(exc: BaseException, default: str) -> str:
    arg = exc.args[0] if exc.args else None
    return arg if isinstance(arg, str) and _CODE_RE.match(arg) else default


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _store_errors() -> tuple[type[BaseException], type[BaseException], type[BaseException]]:
    from . import state

    return state.Conflict, state.NotAllowed, state.StateCorrupt


def aggregate(verdicts: Sequence[str]) -> str:
    """All PASS -> PASS; otherwise any FAIL -> FAIL; otherwise UNMEASURED. Empty is never PASS."""
    items = list(verdicts)
    if items and all(v == PASS for v in items):
        return PASS
    if any(v == FAIL for v in items):
        return FAIL
    return UNMEASURED


def retry_schedule(policy: Any) -> tuple[int, ...]:
    """``policy.retry_seconds`` (default 2,5,10,20,40): at most 10 ints, each 0..600."""
    raw = getattr(policy, "retry_seconds", _MISSING)
    if raw is _MISSING or raw is None:
        return probes.DEFAULT_RETRY_SECONDS
    if isinstance(raw, str | bytes) or not isinstance(raw, Sequence) or len(raw) > MAX_SCHEDULE:
        raise ValueError("retry_seconds")
    out = []
    for item in raw:
        if not _is_int(item) or not 0 <= item <= MAX_DELAY:
            raise ValueError("retry_seconds")
        out.append(int(item))
    return tuple(out)


def _active_doc(store: Any, change_id: str) -> tuple[Any, str | None]:
    view = store.load()
    active = _f(view, "active")
    doc = _f(view, "change")
    if doc is None or active is None:
        return None, "no_open_change"
    # The real Store: View.active is the active ID and the change document's ID is "id".
    if not isinstance(active, str) or active != change_id or _f(doc, "id") != change_id:
        return None, "not_active"
    return doc, None


# --------------------------------------------------------------------------- public evidence


def extra_patterns(policy: Any) -> tuple[str, ...]:
    """The policy's redaction ``extra_patterns`` (strings), or ``RedactionUnavailable``."""
    raw = getattr(policy, "extra_patterns", _MISSING)
    if raw is _MISSING or isinstance(raw, str | bytes) or not isinstance(raw, Sequence):
        raise RedactionUnavailable("policy extra_patterns are not readable")
    if not all(isinstance(p, str) for p in raw):
        raise RedactionUnavailable("policy extra_patterns are not readable")
    return tuple(raw)


def _bounded(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _public_text(text: Any, extra: Sequence[str], limit: int) -> str:
    try:
        shown = ledger.redact(text, extra)
    except Exception:  # noqa: BLE001 - never fall back to the unredacted text
        raise RedactionUnavailable("policy redaction failed") from None
    return _bounded(shown, limit)


def _public_checked(
    checked: Mapping[str, str | None], extra: Sequence[str]
) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for pointer, shown in checked.items():
        if shown is None:
            out[pointer] = None
            continue
        text = _public_text(shown, extra, 1 << 30)
        out[pointer] = text if len(text) <= probes.MAX_CHECKED_CHARS else None
    return out


def _public_observation(
    obs: Mapping[str, Any],
    response: Mapping[str, Any] | None,
    extra: Sequence[str],
    *,
    with_object: bool,
) -> dict[str, Any]:
    """``obs`` redacted with the policy patterns too; its digest is of the redacted object.

    The probe layer redacts with the built-in patterns only. The object digest is
    recomputed from the raw response object as ``sha256(canonical_json(redact_value(
    object, extra)))``, the value ``Store.record_snapshot`` recomputes, so no digest of
    a policy-pattern secret is ever recorded.
    """
    out = dict(obs)
    out["argv"] = [_public_text(w, extra, probes.MAX_ARG_CHARS) for w in obs["argv"]]
    out["human_command"] = _public_text(obs["human_command"], extra, probes.MAX_HUMAN_COMMAND)
    if obs["object_sha256"] is None:
        return out
    raw = response.get("object") if isinstance(response, Mapping) else None
    if raw is None:
        raise RedactionUnavailable("observed object is not available for redaction")
    try:
        shown = ledger.redact_value(raw, extra)
        text = schema.canonical_json(shown)
    except Exception:  # noqa: BLE001
        raise RedactionUnavailable("policy redaction failed") from None
    out["object_sha256"] = hashlib.sha256(text.encode("ascii")).hexdigest()
    out["object"] = shown if with_object else None
    return out


def _specs_by_target(plan: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for spec in tuple(_f(plan, "verify", ()) or ()):
        target = _f(spec, "target")
        if isinstance(target, str) and target not in out:
            out[target] = spec
    return out


def _no_probe(target: str) -> Unmeasured:
    shown, human = probes.display_command([f"no [[verify]] probe for {target}"])
    return Unmeasured(probes.R_NO_RUNNER, human, shown)


def _prepare(
    target: str, specs: Mapping[str, Any], plan: Any, policy: Any, roots: Any
) -> ExecSpec | Unmeasured:
    spec = specs.get(target)
    if spec is None:
        return _no_probe(target)
    return probes.validate(spec, plan, policy, roots)


# --------------------------------------------------------------------------- measure


@dataclass
class _Track:
    ex: ExecSpec
    spec: Any
    attempts: int = 0
    last: dict[str, Any] | None = None
    checked: dict[str, str | None] = field(default_factory=dict)
    outcome: str | None = None
    reason: str | None = None


def measure(
    targets: Sequence[str],
    plan: Any,
    policy: Any,
    roots: Any,
    *,
    runner: Runner,
    clock: Clock,
    schedule: Sequence[int],
) -> tuple[dict[str, TargetResult], str, str]:
    """Probe every target: round 0 at once, then one round per delay for pending targets only.

    Returns (results by target, started_at, finished_at). Unsupported probes are
    UNMEASURED with 0 runner calls. The aggregate wall budget is ``TOTAL_BUDGET``.
    """
    extra = extra_patterns(policy)  # before anything runs
    started_at = schema.utc_text(clock.now())
    t0 = clock.monotonic()
    specs = _specs_by_target(plan)
    results: dict[str, TargetResult] = {}
    pending: dict[str, _Track] = {}

    def human(text: str) -> str:
        return _public_text(text, extra, probes.MAX_HUMAN_COMMAND)

    def finish(target: str, track: _Track, verdict: str, reason: str | None) -> None:
        results[target] = TargetResult(
            target=target,
            verdict=verdict,
            attempts=track.attempts,
            reason=reason,
            human_command=human(track.ex.human_command),
            last=track.last,
            checked=dict(track.checked),
        )
        pending.pop(target, None)

    for target in dict.fromkeys(targets):
        prepared = _prepare(target, specs, plan, policy, roots)
        if isinstance(prepared, Unmeasured):
            results[target] = TargetResult(
                target, UNMEASURED, 0, prepared.reason, human(prepared.human_command), None, {}
            )
        else:
            pending[target] = _Track(prepared, specs[target])

    def attempt(target: str) -> None:
        track = pending[target]
        remaining = TOTAL_BUDGET - (clock.monotonic() - t0)
        if remaining <= 0:
            finish(target, track, UNMEASURED, R_TIME_BUDGET)
            return
        refused = probes.recheck(track.ex, roots)
        if refused is not None:  # nothing runs; not counted as an attempt
            track.last = _public_observation(
                probes.unmeasured_observation(
                    refused,
                    track.ex.display_argv,
                    track.ex.human_command,
                    schema.utc_text(clock.now()),
                ),
                None,
                extra,
                with_object=False,
            )
            track.checked = {}
            finish(target, track, UNMEASURED, refused)
            return
        obs, resp = probes.observe(
            track.ex, runner, clock, roots, with_object=False, timeout=min(RUN_TIMEOUT, remaining)
        )
        track.attempts += 1
        outcome, reason, checked = probes.compare(track.spec, obs, resp)  # on the raw response
        track.last = _public_observation(obs, resp, extra, with_object=False)
        track.checked = _public_checked(checked, extra)
        track.outcome, track.reason = outcome, reason
        if outcome == MATCH:
            finish(target, track, PASS, None)
        elif outcome == UNMEASURABLE and reason in _TERMINAL_REASONS:
            finish(target, track, UNMEASURED, reason)

    for target in list(pending):
        attempt(target)
    budget_out = False
    for delay in schedule:
        if not pending:
            break
        if (clock.monotonic() - t0) + delay >= TOTAL_BUDGET:
            budget_out = True
            break
        clock.sleep(delay)
        for target in list(pending):
            attempt(target)

    for target, track in list(pending.items()):
        if budget_out:
            finish(target, track, UNMEASURED, R_TIME_BUDGET)
        elif track.outcome == MISMATCH:
            finish(target, track, FAIL, R_NOT_CONVERGED)
        else:
            finish(target, track, UNMEASURED, track.reason or probes.R_UNEXPECTED_RESPONSE)
    finished_at = schema.utc_text(clock.now())
    return {t: results[t] for t in dict.fromkeys(targets)}, started_at, finished_at


# --------------------------------------------------------------------------- verify


def _settled_unverified(doc: Any) -> list[Any]:
    units = [u for u in tuple(_f(doc, "units", ()) or ()) if _f(u, "outcome") is not None]
    chosen = [u for u in units if _f(u, "verify") != PASS and _is_int(_f(u, "n"))]
    return sorted(chosen, key=lambda u: _f(u, "n"))


def _unit_targets(unit: Any) -> tuple[str, ...]:
    raw = _f(unit, "targets", ()) or ()
    if isinstance(raw, str | bytes) or not isinstance(raw, Sequence):
        return ()
    return tuple(dict.fromkeys(t for t in raw if isinstance(t, str) and t))


def run_verify(
    store: Any, roots: Any, change_id: str, *, runner: Runner, clock: Clock, policy: Any
) -> VerifyReport:
    try:
        return _run_verify(store, roots, change_id, runner=runner, clock=clock, policy=policy)
    except RedactionUnavailable:
        return VerifyReport(change_id, EXIT_ERROR, "redaction_unavailable", None, None)


def _run_verify(
    store: Any, roots: Any, change_id: str, *, runner: Runner, clock: Clock, policy: Any
) -> VerifyReport:
    conflict, not_allowed, corrupt = _store_errors()

    def stop(exit_code: int, code: str, **kw: Any) -> VerifyReport:
        return VerifyReport(change_id, exit_code, code, kw.pop("seq", None), None, **kw)

    try:
        doc, why = _active_doc(store, change_id)
    except corrupt:
        return stop(EXIT_ERROR, "state_invalid")
    except fsutil.LockTimeout:
        return stop(EXIT_CONFLICT, "lock_timeout")
    if why is not None:
        return stop(EXIT_NOT_ALLOWED, why)
    seq0 = _f(doc, "seq")
    recorded = _f(doc, "plan_hash")
    if _f(doc, "inflight") is not None:
        return stop(EXIT_NOT_ALLOWED, "write_in_flight", seq=seq0)
    if _f(doc, "state") not in VERIFY_STATES:
        return stop(EXIT_NOT_ALLOWED, "state", seq=seq0)
    if not _is_int(seq0):
        return stop(EXIT_ERROR, "state_invalid")
    try:
        plan, _targets, h0 = store.load_plan(change_id)
    except Exception:  # noqa: BLE001 - unreadable or invalid plan
        return stop(EXIT_CONFLICT, "plan_invalid", seq=seq0, recorded_plan_hash=recorded)
    if not isinstance(h0, str) or h0 != recorded:
        return stop(EXIT_CONFLICT, "plan_changed", seq=seq0, recorded_plan_hash=recorded)
    try:
        schedule = retry_schedule(policy)
    except ValueError:
        return stop(EXIT_NOT_ALLOWED, "policy_invalid", seq=seq0)

    selected = _settled_unverified(doc)
    if not selected:
        return stop(EXIT_NOT_ALLOWED, "nothing_to_verify", seq=seq0)
    unit_targets = {_f(u, "n"): _unit_targets(u) for u in selected}
    all_targets = list(dict.fromkeys(t for ts in unit_targets.values() for t in ts))

    measured, started_at, finished_at = measure(
        all_targets, plan, policy, roots, runner=runner, clock=clock, schedule=schedule
    )

    def report(
        exit_code: int, code: str | None, seq: int, units: list[UnitVerdict]
    ) -> VerifyReport:
        verdict = aggregate([u.verdict for u in units]) if units else None
        return VerifyReport(
            change_id=change_id,
            exit=exit_code,
            code=code,
            seq=seq,
            verdict=verdict,
            units=tuple(units),
            results=measured,
            schedule=tuple(schedule),
            started_at=started_at,
            finished_at=finished_at,
            recorded_plan_hash=recorded,
        )

    def pending_units(done: list[UnitVerdict]) -> list[UnitVerdict]:
        seen = {u.unit for u in done}
        out = list(done)
        for unit in selected:
            n = _f(unit, "n")
            if n in seen:
                continue
            ts = unit_targets[n]
            verdict = aggregate([measured[t].verdict for t in ts])
            out.append(UnitVerdict(n, verdict, ts, False, None))
        return out

    # The plan must still be the one the probes were chosen from: nothing is appended otherwise.
    try:
        _p, _t, h1 = store.load_plan(change_id)
    except Exception:  # noqa: BLE001
        h1 = None
    if h1 != h0:
        return report(EXIT_CONFLICT, "plan_changed", seq0, pending_units([]))

    seq = seq0
    done: list[UnitVerdict] = []
    stop_exit: int | None = None
    stop_code: str | None = None
    for unit in selected:
        n = _f(unit, "n")
        ts = unit_targets[n]
        if not ts:
            done.append(UnitVerdict(n, UNMEASURED, ts, False, None))
            stop_code = stop_code or R_NO_TARGETS
            continue
        verdicts = {t: measured[t].verdict for t in ts}
        evidence = {
            "started_at": started_at,
            "finished_at": finished_at,
            "schedule": list(schedule),
            "results": {t: measured[t].evidence() for t in ts},
        }
        try:
            new_seq = store.record_verify(change_id, n, verdicts, seq, h0, evidence=evidence)
        except conflict as exc:
            stop_exit, stop_code = EXIT_CONFLICT, _code(exc, "conflict")
            break
        except fsutil.LockTimeout:
            stop_exit, stop_code = EXIT_CONFLICT, "lock_timeout"
            break
        except not_allowed as exc:
            stop_exit, stop_code = EXIT_NOT_ALLOWED, _code(exc, "not_allowed")
            break
        except corrupt as exc:
            stop_exit, stop_code = EXIT_ERROR, _code(exc, "state_invalid")
            break
        except Exception:  # noqa: BLE001 - unknown store failure: stop, claim nothing
            stop_exit, stop_code = EXIT_ERROR, "store_error"
            break
        if not _is_int(new_seq) or new_seq <= seq:
            stop_exit, stop_code = EXIT_ERROR, "store_error"
            break
        seq = new_seq
        done.append(UnitVerdict(n, aggregate(list(verdicts.values())), ts, True, seq))

    units = pending_units(done)
    if stop_exit is not None:
        return report(stop_exit, stop_code, seq, units)
    verdicts_all = [u.verdict for u in units]
    if FAIL in verdicts_all:
        exit_code = EXIT_FAIL
    elif any(v != PASS for v in verdicts_all):
        exit_code = EXIT_UNMEASURED
    else:
        exit_code = EXIT_OK
    return report(exit_code, stop_code, seq, units)


# --------------------------------------------------------------------------- snapshot


def run_snapshot(
    store: Any,
    roots: Any,
    change_id: str,
    *,
    runner: Runner,
    clock: Clock,
    policy: Any,
    actor: str = "cab-snapshot",
) -> SnapshotReport:
    try:
        return _run_snapshot(
            store, roots, change_id, runner=runner, clock=clock, policy=policy, actor=actor
        )
    except RedactionUnavailable:
        return SnapshotReport(change_id, EXIT_ERROR, "redaction_unavailable", None, False)


def _run_snapshot(
    store: Any,
    roots: Any,
    change_id: str,
    *,
    runner: Runner,
    clock: Clock,
    policy: Any,
    actor: str,
) -> SnapshotReport:
    conflict, not_allowed, corrupt = _store_errors()

    def stop(exit_code: int, code: str, **kw: Any) -> SnapshotReport:
        return SnapshotReport(change_id, exit_code, code, kw.pop("seq", None), False, **kw)

    try:
        doc, why = _active_doc(store, change_id)
    except corrupt:
        return stop(EXIT_ERROR, "state_invalid")
    except fsutil.LockTimeout:
        return stop(EXIT_CONFLICT, "lock_timeout")
    if why is not None:
        return stop(EXIT_NOT_ALLOWED, why)
    seq0 = _f(doc, "seq")
    recorded = _f(doc, "plan_hash")
    state_name = _f(doc, "state")
    if _f(doc, "inflight") is not None:
        return stop(EXIT_NOT_ALLOWED, "write_in_flight", seq=seq0)
    if state_name not in SNAPSHOT_STATES:
        return stop(EXIT_NOT_ALLOWED, "state", seq=seq0)
    try:
        plan, targets, h0 = store.load_plan(change_id)
    except Exception:  # noqa: BLE001
        return stop(EXIT_CONFLICT, "plan_invalid", seq=seq0, recorded_plan_hash=recorded)
    if not isinstance(h0, str) or h0 != recorded:
        return stop(EXIT_CONFLICT, "plan_changed", seq=seq0, recorded_plan_hash=recorded)
    target_list = [t for t in dict.fromkeys(tuple(targets or ())) if isinstance(t, str) and t]
    if not target_list:
        return stop(EXIT_NOT_ALLOWED, "no_targets", seq=seq0)

    extra = extra_patterns(policy)  # before anything runs
    specs = _specs_by_target(plan)
    t0 = clock.monotonic()
    values: dict[str, dict[str, Any]] = {}

    def unmeasured_value(reason: str, prepared: Any) -> dict[str, Any]:
        obs = probes.unmeasured_observation(
            reason, prepared.display_argv, prepared.human_command, schema.utc_text(clock.now())
        )
        return _public_observation(obs, None, extra, with_object=True)

    for target in target_list:
        prepared = _prepare(target, specs, plan, policy, roots)
        if isinstance(prepared, Unmeasured):
            values[target] = unmeasured_value(prepared.reason, prepared)
            continue
        remaining = TOTAL_BUDGET - (clock.monotonic() - t0)
        if remaining <= 0:
            values[target] = unmeasured_value(R_TIME_BUDGET, prepared)
            continue
        obs, resp = probes.observe(
            prepared, runner, clock, roots, with_object=True, timeout=min(RUN_TIMEOUT, remaining)
        )
        values[target] = _public_observation(obs, resp, extra, with_object=True)

    unmeasured = tuple(
        (t, str(v["reason"]), str(v["human_command"]))
        for t, v in values.items()
        if v["status"] == probes.STATUS_UNMEASURED
    )
    complete = not unmeasured
    invalidated = state_name in ("reviewed", "approved") or any(
        _f(doc, name) is not None for name in REVIEW_FIELDS
    )

    def result(exit_code: int, code: str | None, seq: Any) -> SnapshotReport:
        return SnapshotReport(
            change_id=change_id,
            exit=exit_code,
            code=code,
            seq=seq,
            complete=complete,
            values=values,
            unmeasured=unmeasured,
            review_invalidated=invalidated and exit_code in (EXIT_OK, EXIT_UNMEASURED),
            recorded_plan_hash=recorded,
        )

    try:
        _p, _t, h1 = store.load_plan(change_id)
    except Exception:  # noqa: BLE001
        h1 = None
    if h1 != h0:
        return result(EXIT_CONFLICT, "plan_changed", seq0)
    try:
        seq = store.record_snapshot(change_id, values, h0, actor)
    except conflict as exc:
        return result(EXIT_CONFLICT, _code(exc, "conflict"), seq0)
    except fsutil.LockTimeout:
        return result(EXIT_CONFLICT, "lock_timeout", seq0)
    except not_allowed as exc:
        return result(EXIT_NOT_ALLOWED, _code(exc, "not_allowed"), seq0)
    except corrupt as exc:
        return result(EXIT_ERROR, _code(exc, "state_invalid"), seq0)
    except Exception:  # noqa: BLE001
        return result(EXIT_ERROR, "store_error", seq0)
    if not _is_int(seq):
        return result(EXIT_ERROR, "store_error", seq0)
    if complete:
        return result(EXIT_OK, None, seq)
    return result(EXIT_UNMEASURED, "snapshot_incomplete", seq)


# --------------------------------------------------------------------------- text


def verify_lines(report: VerifyReport) -> list[str]:
    """Plain lines for the CLI. Only redacted fields; never says verified unless all PASS."""
    lines = []
    head = f"{report.change_id}: verify exit {report.exit}"
    if report.code:
        head += f" ({report.code})"
    lines.append(head)
    if report.code == "plan_changed" and report.recorded_plan_hash:
        lines.append(f"recorded plan hash: {report.recorded_plan_hash}")
    for u in report.units:
        state = f"committed at seq {u.seq}" if u.committed else "NOT committed"
        lines.append(f"unit {u.unit}: {u.verdict} ({state})")
    for target, r in report.results.items():
        line = f"  {target}: {r.verdict} after {r.attempts} attempt(s)"
        if r.reason:
            line += f" [{r.reason}]"
        lines.append(line)
        if r.verdict != PASS:
            lines.append(f"    a person can check with: {r.human_command}")
    if report.verdict == PASS and report.exit == EXIT_OK:
        lines.append("all selected units PASS")
    elif report.units:
        lines.append("not verified; the change is not closed")
    return lines


def snapshot_lines(report: SnapshotReport) -> list[str]:
    lines = [f"{report.change_id}: snapshot exit {report.exit}"]
    if report.code:
        lines[0] += f" ({report.code})"
    if report.code == "plan_changed" and report.recorded_plan_hash:
        lines.append(f"recorded plan hash: {report.recorded_plan_hash}")
    for target, reason, command in report.unmeasured:
        lines.append(f"  {target}: UNMEASURED [{reason}] a person must run: {command}")
    if report.review_invalidated:
        lines.append("review and approval were cleared by this snapshot")
    if report.exit == EXIT_OK and report.complete:
        lines.append("snapshot complete")
    elif report.exit in (EXIT_OK, EXIT_UNMEASURED):
        lines.append("snapshot incomplete: writes will be refused")
    return lines
