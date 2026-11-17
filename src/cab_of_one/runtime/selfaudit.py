"""Self-audit of the controls: ``cab audit`` (DESIGN §3-9 items 1 and 3, E7).

``audit_projects`` scans a *supplied* transcripts root (``--projects-root``; choosing the
user's default root is the caller's job) and reports sessions whose administrative writes
happened

* **outside the harness**: the call's ``cwd`` is not exactly a registered project root, or
* where **hooks did not run**: the cwd is a registered project but that project's ledger
  has no valid SessionStart row for the session (``--bare``, ``disableAllHooks``, an
  untrusted folder, ... all look the same here).

Classification calls the frozen S3 ``classify_tool_call`` with ``read_file=None``: no
script, file or command named by a transcript is ever opened or run, so script execution
is unknown-admin (= write). Unknown-admin counts as an administrative write, and so does
every built-in tool that the supplied policy does not list in ``not_admin_tools`` (the
guard treats those calls the same way). Write codes keep these cases apart.

Reports contain counts, fixed reason codes, session IDs, tool names and cwd paths. They
never contain a command, a tool input, a secret or any transcript text.

Ledger evidence comes from ``load_session_evidence`` (or any caller-built
``SessionEvidence``). The SessionStart event name is written by S5 and is therefore a
required argument here, not a guess. ``ledger_metrics`` gives minimal counts from valid
ledger rows. The hash chain (T1) is not implemented, so nothing here verifies one.
"""

from __future__ import annotations

import math
import os
import re
import stat
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from . import paths, schema
from .classification_types import KIND_WRITE, Result
from .classify import classify_tool_call
from .ledger import LEDGER_VERSION, iter_jsonl_bytes
from .transcripts import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_LINE_BYTES,
    ToolCall,
    Transcript,
    discover,
    parse_file,
)

__all__ = [
    "CATEGORY_HOOKS_MISSING",
    "CATEGORY_INDETERMINATE",
    "CATEGORY_INSIDE",
    "CATEGORY_NO_WRITES",
    "CATEGORY_OUTSIDE",
    "LABELS",
    "AuditReport",
    "LedgerMetrics",
    "SessionEvidence",
    "SessionFinding",
    "audit_projects",
    "ledger_metrics",
    "load_session_evidence",
]

DAY = 24 * 60 * 60
DEFAULT_DAYS = 14
MAX_DAYS = 3650
MAX_LEDGER_FILES = 600
MAX_LEDGER_FILE_BYTES = 64 * 1024 * 1024
MAX_REPORT_TEXT = 256

CATEGORY_NO_WRITES = "no_admin_writes"
CATEGORY_INSIDE = "inside_harness"
CATEGORY_OUTSIDE = "outside_harness"
CATEGORY_HOOKS_MISSING = "hooks_missing"
CATEGORY_INDETERMINATE = "indeterminate"

LABELS = {
    CATEGORY_NO_WRITES: "no admin writes",
    CATEGORY_INSIDE: "inside the harness",
    CATEGORY_OUTSIDE: "outside the harness",
    CATEGORY_HOOKS_MISSING: "hooks did not run",
    CATEGORY_INDETERMINATE: "indeterminate",
}

# Write codes: why a call counts as an administrative write.
W_KNOWN = "write_known"  # an adapter recognised a write
W_UNKNOWN_BASH = "write_unknown_bash"  # Bash text that could not be classified as safe
W_MCP = "write_mcp"  # MCP tool not listed as read-only, or a write-surface server
W_UNLISTED_TOOL = "write_unlisted_tool"  # built-in tool missing from not_admin_tools
W_MALFORMED = "write_malformed_call"  # tool name or input unusable

_MONTH_FILE = re.compile(r"[0-9]{4}-[0-9]{2}\.jsonl")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,47}")
_EVENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,31}")
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

_EVIDENCE_PROBLEMS = frozenset(
    {
        "ledger_file_unsafe",
        "ledger_file_unreadable",
        "ledger_malformed",
        "ledger_truncated",
        "ledger_files_over_limit",
        "ledger_row_version",
        "start_row_invalid",
    }
)
_METRIC_PROBLEMS = (_EVIDENCE_PROBLEMS - {"start_row_invalid"}) | {"row_time_invalid"}
_SCAN_PROBLEMS = (
    "symlink_skipped",
    "not_regular",
    "file_unreadable",
    "file_limit",
    "dir_unreadable",
    "dir_entry_limit",
)


# --------------------------------------------------------------------------- results


@dataclass(frozen=True)
class SessionEvidence:
    """SessionStart evidence of one registered project.

    ``status`` is ``"ok"`` when every ledger row was readable and understood, else
    ``"indeterminate"`` (a missing SessionStart could then hide in a broken row).
    """

    status: str
    session_ids: frozenset[str] = frozenset()
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class SessionFinding:
    session_id: str | None
    category: str
    label: str
    writes: int
    subagent_writes: int
    write_codes: dict[str, int]
    tools: dict[str, int]
    cwds: tuple[str, ...]
    projects: tuple[str, ...]
    reasons: tuple[str, ...]
    last_activity: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "category": self.category,
            "label": self.label,
            "writes": self.writes,
            "subagent_writes": self.subagent_writes,
            "write_codes": dict(sorted(self.write_codes.items())),
            "tools": dict(sorted(self.tools.items())),
            "cwds": list(self.cwds),
            "projects": list(self.projects),
            "reasons": list(self.reasons),
            "last_activity": self.last_activity,
        }


@dataclass(frozen=True)
class AuditReport:
    status: str  # "ok" | "indeterminate" | "error"
    error: str | None
    days: int
    now: str | None
    sessions: int = 0
    with_admin_writes: int = 0
    inside: int = 0
    outside: int = 0
    hooks_missing: int = 0
    indeterminate: int = 0
    findings: tuple[SessionFinding, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        """True only for a complete scan without outside, hook-less or unknown sessions."""
        return self.status == "ok" and not (self.outside or self.hooks_missing)

    def summary(self) -> str:
        if self.error is not None:
            return f"audit could not run: {self.error}"
        return (
            f"{self.days}d: {self.sessions} sessions, {self.with_admin_writes} with admin "
            f"writes; {self.inside} inside the harness; {self.outside} outside the harness; "
            f"{self.hooks_missing} where hooks did not run; {self.indeterminate} indeterminate."
        )

    def lines(self) -> list[str]:
        out = [self.summary()]
        for f in self.findings:
            sid = f.session_id or "(unknown session)"
            if f.category == CATEGORY_OUTSIDE:
                where = ", ".join(f.cwds) or "(unknown cwd)"
                out.append(f"{f.label}: session {sid} (cwd {where}, {f.writes} writes)")
            elif f.category == CATEGORY_HOOKS_MISSING:
                where = ", ".join(f.projects)
                out.append(f"{f.label}: session {sid} (project {where}, {f.writes} writes)")
            else:
                out.append(
                    f"{f.label}: session {sid} ({f.writes} writes; reasons "
                    f"{', '.join(f.reasons) or 'none'})"
                )
        if self.status == "indeterminate" and not any(
            f.category == CATEGORY_INDETERMINATE for f in self.findings
        ):
            out.append("indeterminate: some files or entries could not be read (see counts)")
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "error": self.error,
            "days": self.days,
            "now": self.now,
            "sessions": self.sessions,
            "with_admin_writes": self.with_admin_writes,
            "inside": self.inside,
            "outside": self.outside,
            "hooks_missing": self.hooks_missing,
            "indeterminate": self.indeterminate,
            "findings": [f.to_dict() for f in self.findings],
            "counts": dict(sorted(self.counts.items())),
        }


@dataclass(frozen=True)
class LedgerMetrics:
    """Minimal counts from valid ledger rows inside the window. No chain is verified."""

    status: str  # "ok" | "indeterminate" | "error"
    error: str | None
    rows: int = 0
    events: dict[str, int] = field(default_factory=dict)
    pre_decisions: dict[str, int] = field(default_factory=dict)
    deny_reasons: dict[str, int] = field(default_factory=dict)
    settle_outcomes: dict[str, int] = field(default_factory=dict)
    state_actions: dict[str, int] = field(default_factory=dict)
    problems: dict[str, int] = field(default_factory=dict)
    chain: str = "not_implemented"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "error": self.error,
            "rows": self.rows,
            "events": dict(sorted(self.events.items())),
            "pre_decisions": dict(sorted(self.pre_decisions.items())),
            "deny_reasons": dict(sorted(self.deny_reasons.items())),
            "settle_outcomes": dict(sorted(self.settle_outcomes.items())),
            "state_actions": dict(sorted(self.state_actions.items())),
            "problems": dict(sorted(self.problems.items())),
            "chain": self.chain,
        }


# --------------------------------------------------------------------------- helpers


def _bump(counts: dict[str, int], key: str, n: int = 1) -> None:
    counts[key] = counts.get(key, 0) + n


def _canon(path: Any) -> str | None:
    """Lexical comparison form of an absolute path (no filesystem access)."""
    if type(path) is not str or not path or "\x00" in path or not os.path.isabs(path):
        return None
    normal = os.path.normpath(path)
    if normal == "/":
        return None
    return paths.norm(normal)


def _clean_text(value: str) -> str:
    text = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in value)
    return text if len(text) <= MAX_REPORT_TEXT else text[: MAX_REPORT_TEXT - 3] + "..."


def _tool_label(name: str) -> str:
    return name if _TOOL_NAME.fullmatch(name or "") else "(invalid tool name)"


def _code_key(value: Any) -> str:
    return value if type(value) is str and _CODE.fullmatch(value) else "other"


def _utc(ts: float | None) -> str | None:
    if ts is None or not math.isfinite(ts):
        return None
    try:
        return schema.utc_text(ts)
    except (OverflowError, OSError, ValueError):
        return None


def _s3_for(policy: Any, inside: bool) -> Any:
    """The S3 mapping for one call. Outside a registered root, relative trusted simtenant
    paths name other files, so they are dropped exactly as ``Policy.s3_for`` does."""
    if isinstance(policy, schema.Policy):
        return policy.s3_for(inside)
    s3 = {} if policy is None else policy
    if inside or not isinstance(s3, Mapping):
        return s3
    clf = s3.get("classifier")
    if not isinstance(clf, Mapping):
        return s3
    clf = dict(clf)
    scripts = clf.get("trusted_simtenant_scripts")
    if isinstance(scripts, list):
        clf["trusted_simtenant_scripts"] = [
            v for v in scripts if isinstance(v, str) and v.startswith("/")
        ]
    commands = clf.get("trusted_simtenant_commands")
    if isinstance(commands, list):
        clf["trusted_simtenant_commands"] = [
            v for v in commands if isinstance(v, str) and (v.startswith("/") or "/" not in v)
        ]
    out = dict(s3)
    out["classifier"] = clf
    return out


def _policy_usable(s3: Any) -> bool:
    probe = classify_tool_call("Read", {}, policy=s3, read_file=None)
    return not (probe.unknown and any(r.startswith("policy is unusable") for r in probe.reasons))


def _classify(call: ToolCall, s3: Any) -> Result | None:
    try:
        r = classify_tool_call(call.name, call.input, policy=s3, read_file=None)
    except Exception:  # classify_tool_call never raises; stay conservative regardless
        r = None
    return r if isinstance(r, Result) else None


def _write_code(call: ToolCall, r: Result | None) -> str:
    if r is None or not call.name or not isinstance(call.input, Mapping):
        return W_MALFORMED
    if not r.unknown:
        return W_KNOWN
    if call.name == "Bash":
        return W_UNKNOWN_BASH
    if call.name.startswith("mcp__"):
        return W_MCP
    return W_UNLISTED_TOOL


# --------------------------------------------------------------------------- ledger


def _ledger_rows(
    project_root: Any, max_file_bytes: int, max_files: int
) -> tuple[list[dict[str, Any]], dict[str, int], str | None]:
    """Valid JSON rows of ``<project>/audit/ledger/YYYY-MM.jsonl`` (read only, no symlinks)."""
    counts: dict[str, int] = {}
    if type(project_root) is not str or not os.path.isabs(project_root) or "\x00" in project_root:
        return [], counts, "project_invalid"
    root = os.path.normpath(project_root)
    try:
        st = os.lstat(root)
    except FileNotFoundError:
        return [], counts, "project_missing"
    except OSError:
        return [], counts, "project_unreadable"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return [], counts, "project_unsafe"
    for parts in (("audit",), ("audit", "ledger")):
        folder = os.path.join(root, *parts)
        try:
            fst = os.lstat(folder)
        except FileNotFoundError:
            counts["ledger_missing"] = 1
            return [], counts, None
        except OSError:
            return [], counts, "ledger_dir_unreadable"
        if stat.S_ISLNK(fst.st_mode) or not stat.S_ISDIR(fst.st_mode):
            return [], counts, "ledger_dir_unsafe"
    try:
        with os.scandir(os.path.join(root, "audit", "ledger")) as it:
            names = sorted(e.name for e in it if _MONTH_FILE.fullmatch(e.name))
    except OSError:
        return [], counts, "ledger_dir_unreadable"
    if len(names) > max_files:
        _bump(counts, "ledger_files_over_limit")
        names = names[-max_files:]
    rows: list[dict[str, Any]] = []
    for name in names:
        try:
            data = paths.read_authority(root, f"audit/ledger/{name}", max_file_bytes)
        except paths.UnsafePath:
            _bump(counts, "ledger_file_unsafe")
            continue
        except OSError:
            _bump(counts, "ledger_file_unreadable")
            continue
        if data is None:
            continue
        for line in iter_jsonl_bytes(data):
            if line.status == "ok" and line.value is not None:
                rows.append(line.value)
            else:
                _bump(counts, "ledger_" + line.status)
    return rows, counts, None


def load_session_evidence(
    project_root: str,
    *,
    start_events: Iterable[str],
    max_file_bytes: int = MAX_LEDGER_FILE_BYTES,
    max_files: int = MAX_LEDGER_FILES,
) -> SessionEvidence:
    """Session IDs with a valid SessionStart row in one project's ledger.

    ``start_events`` are the ledger ``event`` names that S5 writes for SessionStart. A row
    counts when it has ``v == 1``, one of those events and a token-shaped ``session_id``.
    No ledger folder at all is measured evidence of "no SessionStart" (status ok).
    """
    try:
        events = frozenset(start_events)
    except TypeError:
        events = frozenset()
    if not events or not all(type(e) is str and _EVENT_NAME.fullmatch(e) for e in events):
        return SessionEvidence("indeterminate", frozenset(), ("start_events_invalid",))
    rows, counts, error = _ledger_rows(project_root, max_file_bytes, max_files)
    if error is not None:
        return SessionEvidence("indeterminate", frozenset(), (error,))
    ids: set[str] = set()
    for row in rows:
        if row.get("v") != LEDGER_VERSION:
            _bump(counts, "ledger_row_version")
            continue
        if row.get("event") not in events:
            continue
        sid = row.get("session_id")
        if schema.is_token(sid):
            ids.add(sid)
        else:
            _bump(counts, "start_row_invalid")
    problems = tuple(sorted(k for k in counts if k in _EVIDENCE_PROBLEMS))
    status = "indeterminate" if problems else "ok"
    return SessionEvidence(status, frozenset(ids), problems)


def ledger_metrics(
    project_root: str,
    *,
    now: float | None = None,
    days: int = DEFAULT_DAYS,
    max_file_bytes: int = MAX_LEDGER_FILE_BYTES,
    max_files: int = MAX_LEDGER_FILES,
) -> LedgerMetrics:
    """Counts of valid ledger rows in the window: events, guard decisions and deny reason
    codes, settle outcomes and state actions. Keys are fixed codes; anything else is
    counted as ``other``. Not a chain verification (T1 is not implemented)."""
    if type(days) is not int or not 1 <= days <= MAX_DAYS:
        return LedgerMetrics("error", "days_invalid")
    current = time.time() if now is None else now
    if isinstance(current, bool) or not isinstance(current, int | float):
        return LedgerMetrics("error", "now_invalid")
    if not math.isfinite(current):
        return LedgerMetrics("error", "now_invalid")
    rows, problems, error = _ledger_rows(project_root, max_file_bytes, max_files)
    if error is not None:
        return LedgerMetrics("error", error)
    cutoff = current - days * DAY
    events: dict[str, int] = {}
    decisions: dict[str, int] = {}
    denies: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    actions: dict[str, int] = {}
    total = 0
    for row in rows:
        if row.get("v") != LEDGER_VERSION:
            _bump(problems, "ledger_row_version")
            continue
        try:
            ts = schema.utc_parse(row.get("ts"))
        except schema.Invalid:
            _bump(problems, "row_time_invalid")
            continue
        if ts < cutoff or ts > current + DAY:
            continue
        total += 1
        event = _code_key(row.get("event"))
        _bump(events, event)
        if event == "pre":
            decision = _code_key(row.get("decision"))
            _bump(decisions, decision)
            if decision == "deny":
                _bump(denies, _code_key(row.get("reason_code")))
        elif event == "settle":
            outcome = row.get("outcome")
            _bump(outcomes, _code_key(outcome) if outcome is not None else "none")
        elif event == "state":
            _bump(actions, _code_key(row.get("action")))
    status = "indeterminate" if any(k in _METRIC_PROBLEMS for k in problems) else "ok"
    return LedgerMetrics(
        status, None, total, events, decisions, denies, outcomes, actions, problems
    )


# --------------------------------------------------------------------------- audit


@dataclass
class _Session:
    session_id: str | None
    calls: list[ToolCall] = field(default_factory=list)
    keys: set[tuple[str, str]] = field(default_factory=set)
    reasons: set[str] = field(default_factory=set)
    cwds: list[str] = field(default_factory=list)
    last_ts: float | None = None
    mtime: float | None = None

    def add_file(self, t: Transcript, mtime: float) -> None:
        self.reasons.update(t.reasons())
        for cwd in t.cwds:
            if cwd not in self.cwds:
                self.cwds.append(cwd)
        if t.last_ts is not None:
            self.last_ts = t.last_ts if self.last_ts is None else max(self.last_ts, t.last_ts)
        self.mtime = mtime if self.mtime is None else max(self.mtime, mtime)

    def add_call(self, call: ToolCall, counts: dict[str, int]) -> None:
        if call.tool_use_id is not None:
            key = (call.tool_use_id, call.digest)
            if key in self.keys:
                _bump(counts, "duplicate_across_files")
                return
            self.keys.add(key)
        self.calls.append(call)

    @property
    def activity(self) -> float | None:
        return self.last_ts if self.last_ts is not None else self.mtime


def audit_projects(
    projects_root: str,
    *,
    registry: Iterable[str],
    evidence: Mapping[str, SessionEvidence],
    policy: Any = None,
    days: int = DEFAULT_DAYS,
    now: float | None = None,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
    record_types: Iterable[str] | None = None,
) -> AuditReport:
    """Audit the transcripts under ``projects_root`` (E7).

    ``registry``: absolute, canonical roots of the registered operations projects; a
    call's ``cwd`` must equal one of them exactly (a subfolder is *outside*, because
    tenant writes run from the project root). Comparison is lexical (normpath, NFC, case
    folded); no path named by a transcript is resolved or opened.
    ``evidence``: ``SessionEvidence`` per registered root (``load_session_evidence``). A
    registered root without evidence makes its sessions indeterminate, never "inside".
    ``policy``: a ``schema.Policy`` or an S3 policy mapping (None = S3 defaults).
    ``days``/``now``: the window is ``[now - days, now]`` on the session's last record
    timestamp (file mtime when no record has one).
    """
    if type(days) is not int or not 1 <= days <= MAX_DAYS:
        return AuditReport("error", "days_invalid", days if type(days) is int else 0, None)
    current = time.time() if now is None else now
    if isinstance(current, bool) or not isinstance(current, int | float):
        return AuditReport("error", "now_invalid", days, None)
    if not math.isfinite(current):
        return AuditReport("error", "now_invalid", days, None)
    now_text = _utc(current)
    if not _policy_usable(_s3_for(policy, True)):
        return AuditReport("error", "policy_unusable", days, now_text)
    s3_inside, s3_outside = _s3_for(policy, True), _s3_for(policy, False)

    counts: dict[str, int] = {}
    registered: dict[str, str] = {}
    for entry in registry if registry is not None else ():
        key = _canon(entry)
        if key is None:
            _bump(counts, "registry_entry_invalid")
            continue
        registered.setdefault(key, os.path.normpath(entry))
    proofs: dict[str, SessionEvidence] = {}
    for root, ev in (evidence or {}).items():
        key = _canon(root)
        if key is None or not isinstance(ev, SessionEvidence):
            _bump(counts, "evidence_entry_invalid")
            continue
        proofs[key] = ev

    disc = discover(projects_root, max_files=max_files)
    if disc.error is not None:
        return AuditReport("error", disc.error, days, now_text, counts=counts)
    for code, n in disc.counts.items():
        _bump(counts, code, n)
    scan_incomplete = any(disc.counts.get(c, 0) for c in _SCAN_PROBLEMS)

    cutoff = current - days * DAY
    sessions: dict[tuple[str, str], _Session] = {}
    unnamed = 0
    for ref in disc.refs:
        if ref.mtime < cutoff:
            _bump(counts, "files_before_window")
            continue
        _bump(counts, "files_parsed")
        t = parse_file(
            ref,
            max_file_bytes=max_file_bytes,
            max_line_bytes=max_line_bytes,
            record_types=record_types,
        )
        for code, n in t.counts.items():
            _bump(counts, "transcript_" + code, n)
        if ref.session_id is not None:
            file_key = ("id", ref.session_id)
        else:
            unnamed += 1
            file_key = ("file", str(unnamed))
        holder = sessions.setdefault(file_key, _Session(ref.session_id))
        holder.add_file(t, ref.mtime)
        for call in t.calls:
            key = ("id", call.session_id) if call.session_id is not None else file_key
            target = sessions.setdefault(key, _Session(call.session_id))
            if target is not holder:
                target.add_file(
                    Transcript(t.path, t.kind, t.file_session_id, t.file_agent_id,
                               cwds=t.cwds, last_ts=t.last_ts),
                    ref.mtime,
                )  # fmt: skip
            target.add_call(call, counts)

    findings: list[SessionFinding] = []
    totals = dict.fromkeys(
        (CATEGORY_NO_WRITES, CATEGORY_INSIDE, CATEGORY_OUTSIDE, CATEGORY_HOOKS_MISSING,
         CATEGORY_INDETERMINATE), 0
    )  # fmt: skip
    in_window = 0
    with_writes = 0
    order = sorted(sessions.items(), key=lambda kv: (kv[0][0], kv[0][1]))
    for _key, sess in order:
        activity = sess.activity
        if activity is None or activity < cutoff:
            _bump(counts, "sessions_before_window")
            continue
        if sess.last_ts is None:
            _bump(counts, "session_time_from_mtime")
        in_window += 1
        finding = _judge(sess, registered, proofs, s3_inside, s3_outside)
        totals[finding.category] += 1
        if finding.writes:
            with_writes += 1
        if finding.category in (CATEGORY_OUTSIDE, CATEGORY_HOOKS_MISSING, CATEGORY_INDETERMINATE):
            findings.append(finding)

    status = "ok"
    damaged = any("transcript_indeterminate" in f.reasons for f in findings)
    if totals[CATEGORY_INDETERMINATE] or scan_incomplete or damaged:
        status = "indeterminate"
    rank = {CATEGORY_OUTSIDE: 0, CATEGORY_HOOKS_MISSING: 1, CATEGORY_INDETERMINATE: 2}
    findings.sort(key=lambda f: (rank[f.category], f.session_id or ""))
    return AuditReport(
        status,
        None,
        days,
        now_text,
        in_window,
        with_writes,
        totals[CATEGORY_INSIDE],
        totals[CATEGORY_OUTSIDE],
        totals[CATEGORY_HOOKS_MISSING],
        totals[CATEGORY_INDETERMINATE],
        tuple(findings),
        counts,
    )


def _judge(
    sess: _Session,
    registered: Mapping[str, str],
    proofs: Mapping[str, SessionEvidence],
    s3_inside: Any,
    s3_outside: Any,
) -> SessionFinding:
    reasons: set[str] = set(sess.reasons)
    if reasons:
        reasons.add("transcript_indeterminate")
    write_codes: dict[str, int] = {}
    tools: dict[str, int] = {}
    outside_cwds: list[str] = []
    inside_projects: list[str] = []
    writes = 0
    subagent_writes = 0
    outside = 0
    unknown_cwd = 0
    for call in sess.calls:
        cwd = call.cwd
        if cwd is None and len(sess.cwds) == 1:
            cwd = sess.cwds[0]
        key = _canon(cwd) if cwd is not None else None
        inside = key is not None and key in registered
        r = _classify(call, s3_inside if inside else s3_outside)
        if r is not None and r.kind != KIND_WRITE:
            continue
        writes += 1
        if call.agent_id is not None or call.sidechain:
            subagent_writes += 1
        _bump(write_codes, _write_code(call, r))
        _bump(tools, _tool_label(call.name))
        if key is None:
            unknown_cwd += 1
            reasons.add("write_cwd_unknown")
            continue
        if inside:
            if registered[key] not in inside_projects:
                inside_projects.append(registered[key])
            continue
        outside += 1
        if any(key.startswith(root.rstrip("/") + "/") for root in registered):
            reasons.add("cwd_under_registered")
        else:
            reasons.add("cwd_not_registered")
        shown = _clean_text(cwd or "")
        if shown not in outside_cwds:
            outside_cwds.append(shown)

    hooks_missing = False
    unproven = False
    for project in inside_projects:
        ev = proofs.get(_canon(project) or "")
        if sess.session_id is None:
            unproven = True
            reasons.add("session_id_unknown")
        elif ev is None:
            unproven = True
            reasons.add("evidence_not_supplied")
        elif sess.session_id in ev.session_ids:
            continue
        elif ev.status == "ok":
            hooks_missing = True
            reasons.add("no_session_start")
        else:
            unproven = True
            reasons.add("evidence_indeterminate")

    # Every remaining reason (damaged transcript, unknown cwd, unproven SessionStart) means
    # the session cannot be called clean or inside (unproven and unknown_cwd always add one).
    if unproven or unknown_cwd:
        reasons.add("write_unproven")
    if outside:
        category = CATEGORY_OUTSIDE
    elif hooks_missing:
        category = CATEGORY_HOOKS_MISSING
    elif reasons:
        category = CATEGORY_INDETERMINATE
    elif writes:
        category = CATEGORY_INSIDE
    else:
        category = CATEGORY_NO_WRITES
    return SessionFinding(
        sess.session_id,
        category,
        LABELS[category],
        writes,
        subagent_writes,
        write_codes,
        tools,
        tuple(outside_cwds),
        tuple(_clean_text(p) for p in inside_projects),
        tuple(sorted(reasons)),
        _utc(sess.activity),
    )
