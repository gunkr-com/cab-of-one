"""Audit hooks for every event except PreToolUse and Stop (S5 C-main).

Pinned entry: ``<project>/.claude/hooks/cab/audit.py <mode>`` with ``mode`` one of
``post`` (PostToolUse), ``fail`` (PostToolUseFailure), ``substart`` (SubagentStart),
``substop`` (SubagentStop), ``start`` (SessionStart) and ``end`` (SessionEnd).

What each mode does, and nothing more:

- ``post``/``fail``: settle the write the guard reserved. ``hookevents.recognize`` gives
  the settlement metadata from the measured shapes only (contract section 5); ``ok`` is
  metadata and never a verification PASS. The receipt carries the exact session, tool and
  raw input (the Store hashes it with the unit salt and never stores it) plus the
  redacted fingerprint. A call is settled when its token is in flight, already settled,
  or the call classifies as a write. No or invalid ``tool_use_id`` is ``unbound``; an
  unknown write without an active change is ``unguarded_no_change``; a Store refusal is
  ``error``. None of these change the state, so a held reservation and its debt stay.
  ``AskUserQuestion`` in the main session writes an ``intake`` row (``source=askuser``,
  ``reason_code=answers_unmeasured``): a question was asked; the answer content is not
  measured and is never claimed.
- ``substart``/``substop``: the ``safety-reviewer`` with a valid ``agent_id`` and the
  parent session's ``session_id`` starts and finishes the review through the Store. The
  verdict comes only from exactly one final fenced strict JSON block in the supplied
  ``last_assistant_message``; transcripts are never read. A missing or unreadable block
  is recorded as ``BLOCK`` with a fixed finding, never as PASS. Other agents are logged
  without authority.
- ``start``: one ledger row ``session_start`` (the constant ``SESSION_START_EVENT``,
  which ``selfaudit.load_session_evidence`` must be given) carrying the result of a guard
  self test. The self test runs the real ``guard.decide`` on a synthetic administrative
  write inside a fresh fictional fixture under ``.cab/state/selftest/`` (no active
  change) and passes only on the exact ``no_open_change`` denial. It is a synthetic
  source self test, not a measurement of the live hook registration (L2). It also reads
  the generated setup metadata ``.claude/hooks/cab/session-profile.json`` (exactly
  ``{"admin_identity": bool, "bypass_guarded": bool}`` in canonical bytes; see
  ``session_profile_bytes``) with a no-follow, single-link, bounded read and adds a warning
  for an admin agent identity and for bypass-guarded mode. Missing, unsafe or invalid
  metadata is an UNMEASURED-settings warning: it never grants anything, never silences a
  warning and never changes the self test result, the state or any approval condition.
- ``end``: one ``session_end`` row with the reason and whether a handoff is due. Nothing
  else is written; no evidence is touched.

Output: none, exit 0, except ``start``, which prints one SessionStart JSON object
(``additionalContext``, plus ``systemMessage`` when the self test failed). How Claude Code
shows these is UNMEASURED until L2. Nothing here raises to the caller.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from . import fsutil, guard, hookevents, obligations, paths, schema
from .classification_types import KIND_WRITE, Result, leaves
from .classify import MAX_SCRIPT_BYTES, classify_tool_call
from .hookevents import EventError
from .ledger import Ledger, LedgerError, display_command, fingerprint
from .paths import Roots
from .schema import Invalid, Policy
from .state import Halted, Receipt, Replay, Store, StoreError

__all__ = [
    "MODES",
    "SAFETY_REVIEWER",
    "SESSION_PROFILE_KEYS",
    "SESSION_PROFILE_PATH",
    "SESSION_START_EVENT",
    "START_EVENTS",
    "Runtime",
    "SelfTest",
    "SessionProfile",
    "main",
    "open_runtime",
    "parse_review_message",
    "parse_session_profile",
    "read_session_profile",
    "run_guard_selftest",
    "session_profile_bytes",
    "session_profile_warnings",
]

SESSION_START_EVENT = "session_start"
SESSION_END_EVENT = "session_end"
START_EVENTS = (SESSION_START_EVENT,)
MODES: Mapping[str, str] = {
    "post": "PostToolUse",
    "fail": "PostToolUseFailure",
    "substart": "SubagentStart",
    "substop": "SubagentStop",
    "start": "SessionStart",
    "end": "SessionEnd",
}
_ROW_EVENTS: Mapping[str, str] = {
    "post": "post",
    "fail": "post",
    "substart": "subagent_start",
    "substop": "subagent_stop",
    "start": SESSION_START_EVENT,
    "end": SESSION_END_EVENT,
}
SAFETY_REVIEWER = "safety-reviewer"
ASK_TOOL = "AskUserQuestion"
MAX_REVIEW_MESSAGE_BYTES = 256 * 1024
MAX_REVIEW_JSON_BYTES = 64 * 1024
MAX_FINDINGS = 100
MAX_FINDING_DETAIL = 2000
MAX_QUESTION_EXCERPT = 200
REVIEW_VERDICTS = ("PASS", "PASS_WITH_CONDITIONS", "BLOCK")
UNREADABLE_REVIEW_DETAIL = (
    "The reviewer's final message did not end with exactly one strict JSON review block. "
    "Recorded as BLOCK; run the review again."
)

_CODE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_AGENT_TYPE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_FINDING_CODE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
_CONTROL_TEXT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_FENCE_OPEN = re.compile(r"```(?:json)?[ \t]*\n")


# --------------------------------------------------------------------------- runtime


@dataclass(frozen=True)
class Runtime:
    roots: Roots
    policy: Policy
    catalog: tuple[dict[str, Any], ...]
    ledger: Ledger
    store: Store


def open_runtime(
    roots: Roots,
    *,
    clock: Callable[[], float] = time.time,
    lock_timeout: float = guard.STATE_LOCK_TIMEOUT,
    ledger_timeout: float = guard.LEDGER_LOCK_TIMEOUT,
) -> Runtime:
    """Policy, catalogue, ledger and Store of an installed project. Raises on any problem."""
    policy, catalog = guard.load_runtime(roots)
    book = Ledger(
        roots, extra_patterns=policy.extra_patterns, clock=clock, lock_timeout=ledger_timeout
    )
    store = Store(
        roots,
        policy,
        catalog,
        ledger=book,
        clock=clock,
        lock_timeout=lock_timeout,
        ext_timeout=guard.EXT_LOCK_TIMEOUT,
    )
    return Runtime(roots, policy, catalog, book, store)


def _code(value: Any, default: str | None = "other") -> str | None:
    if type(value) is str and _CODE.fullmatch(value):
        return value
    return default


def _row(rt: Runtime, event: str, **fields: Any) -> bool:
    """Best-effort ledger row. A failure never changes what the hook does."""
    try:
        rt.ledger.append(event, **fields)
        return True
    except Exception:
        return False


def _agent_type(data: Mapping[str, Any]) -> str | None:
    value = data.get("agent_type")
    return value if type(value) is str and _AGENT_TYPE.fullmatch(value) else None


def _session(data: Mapping[str, Any]) -> str | None:
    value = data.get("session_id")
    return value if schema.is_token(value) else None


def _cls(r: Result | None) -> dict[str, Any] | None:
    if r is None:
        return None
    return {
        "kind": r.kind,
        "unknown": r.unknown,
        "adapter": r.adapter,
        "verb": r.verb,
        "floor": None,
        "targets_complete": r.targets_complete,
        "n": len(leaves(r)),
    }


def _store_failure(exc: BaseException) -> str:
    if isinstance(exc, StoreError):
        return _code(exc.code, "store_error") or "store_error"
    if isinstance(exc, fsutil.LockTimeout):
        return "lock_timeout"
    if isinstance(exc, LedgerError):
        return "ledger_error"
    return "internal_error"


# --------------------------------------------------------------------------- Post / Failure


def _classify(rt: Runtime, data: Mapping[str, Any], tool: str | None, tool_input: Any) -> Any:
    """Classification exactly as the guard does it (cwd-aware ``s3_for``); None when the
    call cannot be classified (it is then treated as a write)."""
    if tool is None or not isinstance(tool_input, dict):
        return None
    cwd = data.get("cwd")
    if type(cwd) is not str or not os.path.isabs(cwd) or "\x00" in cwd:
        cwd = None
    s3 = rt.policy.s3_for(paths.same_dir(cwd, rt.roots.project))

    def read_file(path: str) -> bytes | None:
        return paths.read_project_file(rt.roots, cwd, path, MAX_SCRIPT_BYTES)

    try:
        r = classify_tool_call(tool, tool_input, policy=s3, read_file=read_file)
    except Exception:
        return None
    return r if isinstance(r, Result) else None


def _fixed_cli_call(rt: Runtime, data: Mapping[str, Any], who: Any, tool_input: Any) -> bool:
    """The same fixed-CLI test as guard step 1a (main session Bash only)."""
    if who.is_subagent or who.tool_name != "Bash" or not isinstance(tool_input, dict):
        return False
    cwd = data.get("cwd")
    if type(cwd) is not str or not os.path.isabs(cwd):
        cwd = None
    try:
        return guard._fixed_cli(tool_input.get("command"), cwd, rt.roots)
    except Exception:
        return False


def _question_excerpt(tool_input: Any) -> str:
    """A short question excerpt for the ledger (redacted again by the ledger)."""
    if isinstance(tool_input, Mapping):
        questions = tool_input.get("questions")
        if isinstance(questions, list) and questions and isinstance(questions[0], Mapping):
            text = questions[0].get("question")
            if type(text) is str and text:
                return text[:MAX_QUESTION_EXCERPT]
    return "(question shape not recognised)"


def handle_post(rt: Runtime, data: Mapping[str, Any]) -> str:
    """Settle one Post/Failure event. Returns the ledger decision (for tests)."""
    pr = hookevents.recognize(data)
    who = pr.identity
    tool = who.tool_name
    raw_input = data.get("tool_input")
    extra = rt.policy.extra_patterns
    r = _classify(rt, data, tool, pr.tool_input)
    is_write = r is None or r.kind == KIND_WRITE
    if is_write and _fixed_cli_call(rt, data, who, pr.tool_input):
        # Guard step 1a allowed this exact pinned-CLI call without a reservation; the CLI
        # itself writes through the Store. It is not an unguarded tenant write.
        is_write = False

    def post_row(decision: str, code: str | None, change_id: str | None) -> None:
        command = None
        if tool is not None:
            try:
                command = display_command(tool, raw_input, extra)
            except Exception:
                command = None
        _row(
            rt,
            "post",
            command=command,
            session_id=who.session_id,
            tool_use_id=who.tool_use_id,
            agent="subagent" if who.is_subagent else "main",
            agent_type=_agent_type(data),
            change_id=change_id,
            tool=tool,
            cls=_cls(r),
            decision=decision,
            reason_code=code,
            source=pr.source,
            outcome=pr.outcome,
            exit=pr.exit,
            response_sha256=pr.response_sha256,
        )

    try:
        view = rt.store.load()
    except Exception as exc:
        post_row("error", _store_failure(exc), None)
        return "error"
    doc = view.change
    token = who.tool_use_id
    inflight = doc.get("inflight") if isinstance(doc, Mapping) else None
    inflight_token = inflight.get("token") if isinstance(inflight, Mapping) else None
    known = (
        token is not None
        and isinstance(doc, Mapping)
        and (
            token == inflight_token
            or any(isinstance(u, Mapping) and u.get("tool_use_id") == token for u in doc["units"])
        )
    )

    decision = "none"
    if token is None:
        if is_write or inflight_token is not None:
            decision = "unbound"
            post_row(decision, "tool_use_id_invalid", view.active)
    elif not (is_write or known):
        decision = "none"  # not an administrative write: no row (reads were logged at Pre)
    elif view.active is None:
        decision = "unguarded_no_change"
        post_row(decision, "no_open_change", None)
    else:
        receipt = Receipt(
            tool_use_id=token,
            session_id=who.session_id,
            tool_name=tool if tool is not None else "",
            tool_input=raw_input,  # raw: only the Store's HMAC sees it
            fingerprint=fingerprint(tool if tool is not None else "", raw_input, extra),
            source=pr.source,
            outcome=pr.outcome,
            exit=pr.exit,
            response_sha256=pr.response_sha256,
        )
        code: str | None = None
        try:
            rt.store.settle(receipt)
            decision = "settled"
        except Replay:
            decision = "replay"
        except Halted as exc:
            decision, code = "halted", _code(exc.code, "halted")
        except Exception as exc:
            decision, code = "error", _store_failure(exc)
        post_row(decision, code, view.active)

    if pr.source == "post" and tool == ASK_TOOL and who.is_main and view.active is not None:
        _row(
            rt,
            "intake",
            command=_question_excerpt(pr.tool_input),
            session_id=who.session_id,
            tool_use_id=token,
            change_id=view.active,
            source="askuser",
            reason_code="answers_unmeasured",
            outcome="unknown",
            response_sha256=pr.response_sha256,
        )
    return decision


# --------------------------------------------------------------------------- review


def _finding_ok(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != {"code", "detail"}:
        return False
    code, detail = item["code"], item["detail"]
    if type(code) is not str or not _FINDING_CODE.fullmatch(code):
        return False
    if type(detail) is not str or len(detail) > MAX_FINDING_DETAIL:
        return False
    return not _CONTROL_TEXT.search(detail)


def parse_review_message(text: Any) -> tuple[str, list[dict[str, str]]] | str:
    """``(verdict, findings)`` from exactly one final fenced strict JSON block, or a fixed
    refusal code. The block must be the only fence in the message and nothing but
    whitespace may follow it. Its object has exactly ``verdict`` and ``findings``."""
    if type(text) is not str:
        return "review_missing"
    if len(text.encode("utf-8", "surrogatepass")) > MAX_REVIEW_MESSAGE_BYTES:
        return "review_too_large"
    if text.count("```") != 2:
        return "review_block_count"
    start = text.find("```")
    if start > 0 and text[start - 1] != "\n":
        return "review_block_shape"
    opening = _FENCE_OPEN.match(text, start)
    if opening is None:
        return "review_block_shape"
    close = text.find("```", opening.end())
    if close < 0 or (close > 0 and text[close - 1] != "\n"):
        return "review_block_shape"
    if text[close + 3 :].strip():
        return "review_not_final"
    body = text[opening.end() : close]
    try:
        doc = schema.strict_json(body.encode("utf-8"), max_bytes=MAX_REVIEW_JSON_BYTES)
    except (Invalid, UnicodeEncodeError):
        return "review_json_invalid"
    if set(doc) != {"verdict", "findings"}:
        return "review_keys"
    verdict = doc["verdict"]
    if type(verdict) is not str or verdict not in REVIEW_VERDICTS:
        return "review_verdict"
    findings = doc["findings"]
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        return "review_findings"
    if not all(_finding_ok(f) for f in findings):
        return "review_findings"
    return verdict, [{"code": f["code"], "detail": f["detail"]} for f in findings]


def _active(rt: Runtime) -> tuple[str | None, str | None]:
    """(active change, failure code)."""
    try:
        return rt.store.load().active, None
    except Exception as exc:
        return None, _store_failure(exc)


def handle_substart(rt: Runtime, data: Mapping[str, Any]) -> str:
    sid = _session(data)
    agent_id = data.get("agent_id")
    agent_type = _agent_type(data)
    active, failure = _active(rt)
    decision, code = "logged", failure
    if agent_type == SAFETY_REVIEWER:
        if not schema.is_agent_id(agent_id) or sid is None:
            decision, code = "refused", "identity_invalid"
        elif failure is not None:
            decision = "error"
        elif active is None:
            decision, code = "refused", "no_open_change"
        else:
            try:
                rt.store.begin_review(active, agent_id, session_id=sid)
                decision, code = "review_start", None
            except Exception as exc:
                decision, code = "error", _store_failure(exc)
    _row(
        rt,
        "subagent_start",
        session_id=sid,
        agent="subagent",
        agent_type=agent_type,
        change_id=active,
        decision=decision,
        reason_code=code,
    )
    return decision


def handle_substop(rt: Runtime, data: Mapping[str, Any]) -> str:
    sid = _session(data)
    agent_id = data.get("agent_id")
    agent_type = _agent_type(data)
    active, failure = _active(rt)
    decision, code, outcome = "logged", failure, None
    if agent_type == SAFETY_REVIEWER:
        if not schema.is_agent_id(agent_id) or sid is None:
            decision, code = "refused", "identity_invalid"
        elif failure is not None:
            decision = "error"
        elif active is None:
            decision, code = "refused", "no_open_change"
        else:
            parsed = parse_review_message(data.get("last_assistant_message"))
            if isinstance(parsed, tuple):
                verdict, findings = parsed
                code = None
            else:
                # Absent or unreadable handback: never a PASS. Recorded as BLOCK.
                verdict = "BLOCK"
                findings = [{"code": "review_unreadable", "detail": UNREADABLE_REVIEW_DETAIL}]
                code = parsed
            outcome = verdict
            try:
                rt.store.finish_review(active, agent_id, sid, verdict, findings)
                decision = "review_recorded"
            except Exception as exc:
                decision, code = "error", _store_failure(exc)
    elif agent_type == "verifier":
        # Judgement results from the verifier are not attached to evidence in v0.1.
        code = code or "verifier_unmeasured"
    _row(
        rt,
        "subagent_stop",
        session_id=sid,
        agent="subagent",
        agent_type=agent_type,
        change_id=active,
        decision=decision,
        reason_code=code,
        outcome=outcome,
    )
    return decision


# --------------------------------------------------------------------------- self test

SELFTEST_POLICY = """\
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
mcp_write_servers = ["cabselftest"]
"""
SELFTEST_CATALOG = "schema = 1\n"
SELFTEST_TOOL = "mcp__cabselftest__set_user"
SELFTEST_DIR = (".cab", "state", "selftest")
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class SelfTest:
    ok: bool
    code: str


def _write_new(path: str, text: str) -> None:
    fd = os.open(path, _NEW_FILE, 0o600)
    try:
        data = text.encode("ascii")
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def _real_child(path: str, parent: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    return os.path.dirname(os.path.realpath(path)) == os.path.realpath(parent)


def _authority_bytes(roots: Roots, rel: str) -> bytes | None | str:
    try:
        return paths.read_authority(roots.project, rel, 1 << 20)
    except Exception:
        return "unreadable"


def run_guard_selftest(
    roots: Roots,
    *,
    clock: Callable[[], float] = time.time,
    decide: Callable[..., Any] | None = None,
) -> SelfTest:
    """Synthetic guard self test in an isolated fictional fixture (see the module doc)."""
    decide = decide or guard.decide
    try:
        base = paths.ensure_dir(roots.project, *SELFTEST_DIR)
    except Exception:
        return SelfTest(False, "fixture_unsafe")
    before = _authority_bytes(roots, ".cab/state/active.json")
    try:
        work = tempfile.mkdtemp(prefix="run-", dir=base)
    except OSError:
        return SelfTest(False, "fixture_unsafe")
    try:
        if not _real_child(work, base):
            return SelfTest(False, "fixture_unsafe")
        project = paths.ensure_dir(work, "proj")
        home = paths.ensure_dir(work, "home")
        paths.ensure_dir(project, "policy")
        paths.ensure_dir(project, ".cab", "state")
        _write_new(os.path.join(project, "policy", "policy.toml"), SELFTEST_POLICY)
        _write_new(os.path.join(project, "policy", "standard-changes.toml"), SELFTEST_CATALOG)
        fixture = Roots(project, os.path.join(home, *paths.STATE_HOME_PARTS))
        event = {
            "hook_event_name": "PreToolUse",
            "session_id": "cab-selftest",
            "tool_use_id": "cab-selftest-" + secrets.token_hex(8),
            "cwd": project,
            "tool_name": SELFTEST_TOOL,
            "tool_input": {"user_id": "u-0000", "department": "Selftest"},
        }
        decision = decide(event, fixture, clock=clock)
        if _authority_bytes(roots, ".cab/state/active.json") != before:
            return SelfTest(False, "side_effect")
        if getattr(decision, "allowed", None) is not False:
            return SelfTest(False, "not_denied")
        if getattr(decision, "reason", None) != guard.message("no_open_change"):
            return SelfTest(False, "unexpected_denial")
        return SelfTest(True, "no_open_change_denied")
    except Exception:
        return SelfTest(False, "selftest_error")
    finally:
        try:
            if _real_child(work, base):
                shutil.rmtree(work, ignore_errors=True)
        except Exception:
            pass


# --------------------------------------------------------------------------- session profile

#: Generated by setup (``render``), generator-owned and protected (``.claude/**``). Holds
#: two booleans only: never a profile string, a name or a secret.
SESSION_PROFILE_PATH = ".claude/hooks/cab/session-profile.json"
SESSION_PROFILE_KEYS = ("admin_identity", "bypass_guarded")
MAX_SESSION_PROFILE_BYTES = 4096
_PROFILE_PROBLEM = {
    "missing": "is missing",
    "unsafe": "is not a plain single-link file (a link, hard link, folder or oversized file)",
    "invalid": "is not exactly the generated two-boolean document",
}


@dataclass(frozen=True)
class SessionProfile:
    """``status`` is ``ok``, ``missing``, ``unsafe`` or ``invalid``; the booleans are set
    only when ``status == "ok"``."""

    status: str
    admin_identity: bool | None = None
    bypass_guarded: bool | None = None


def session_profile_bytes(*, admin_identity: bool, bypass_guarded: bool) -> bytes:
    """The one canonical form (sorted keys, indent 2, ASCII, one trailing LF)."""
    if type(admin_identity) is not bool or type(bypass_guarded) is not bool:
        raise TypeError("session profile values must be bool")
    doc = {"admin_identity": admin_identity, "bypass_guarded": bypass_guarded}
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def parse_session_profile(data: Any) -> tuple[bool, bool]:
    """``(admin_identity, bypass_guarded)`` of exactly canonical metadata bytes.

    Raises ``ValueError`` for anything else: other or extra keys, a non-bool value (``1``,
    ``"true"``, null), duplicate keys, other whitespace or encoding, or oversized input.
    """
    if type(data) is not bytes or len(data) > MAX_SESSION_PROFILE_BYTES:
        raise ValueError("session_profile")
    try:
        doc = schema.strict_json(data, max_bytes=MAX_SESSION_PROFILE_BYTES)
    except Invalid:
        raise ValueError("session_profile") from None
    if set(doc) != set(SESSION_PROFILE_KEYS):
        raise ValueError("session_profile")
    admin, bypass = doc["admin_identity"], doc["bypass_guarded"]
    if type(admin) is not bool or type(bypass) is not bool:
        raise ValueError("session_profile")
    if data != session_profile_bytes(admin_identity=admin, bypass_guarded=bypass):
        raise ValueError("session_profile")
    return admin, bypass


def read_session_profile(roots: Roots) -> SessionProfile:
    """Read the installed metadata: no symlink anywhere below the project, regular file,
    one link, bounded, unchanged while read (``paths.read_authority``). Never raises."""
    try:
        data = paths.read_authority(roots.project, SESSION_PROFILE_PATH, MAX_SESSION_PROFILE_BYTES)
    except Exception:  # UnsafePath (link, hard link, not regular, too large, changed) or I/O
        return SessionProfile("unsafe")
    if data is None:
        return SessionProfile("missing")
    try:
        admin, bypass = parse_session_profile(data)
    except Exception:
        return SessionProfile("invalid")
    return SessionProfile("ok", admin, bypass)


def session_profile_warnings(profile: SessionProfile) -> list[str]:
    """Fixed warning sentences for SessionStart. An unreadable profile is a warning that
    the settings are unmeasured; it is never read as "no admin, no bypass"."""
    if profile.status != "ok":
        problem = _PROFILE_PROBLEM.get(profile.status, _PROFILE_PROBLEM["invalid"])
        return [
            f"WARNING: the setup metadata {SESSION_PROFILE_PATH} {problem}. Whether the "
            "agent identity is admin and whether bypass permissions mode was chosen are "
            "UNMEASURED; nothing is assumed and nothing is granted. Ask a person to run "
            ".claude/hooks/cab/cab doctor or to run setup again."
        ]
    out: list[str] = []
    if profile.admin_identity:
        out.append(
            "WARNING (setup profile): the agent identity is admin. Credentials available to "
            "this session can change the tenant directly, and the hooks gate only the write "
            "surfaces they recognise. Prefer read-only credentials and keep every tenant "
            "write inside an approved change (docs/identity.md)."
        )
    if profile.bypass_guarded:
        out.append(
            "WARNING (setup profile): this project was set up for bypass permissions mode "
            "(bypass-guarded). Deny rules and the cab-of-one hooks still apply; allow rules "
            "and permission prompts do not, so no tool call waits for a person. Whether this "
            "session actually runs in bypass mode is not measured. Re-run the bypass checks "
            "after every settings change."
        )
    return out


# --------------------------------------------------------------------------- session


def _obligations_text(rt: Runtime) -> tuple[str | None, str | None, str, bool]:
    """(active, state, one-line status, handoff due). Never raises."""
    try:
        view = rt.store.load()
        evidence = rt.store.verify_evidence(view.change) if view.change is not None else {}
        ob = obligations.evaluate(view, evidence)
    except Exception:
        return None, None, "the change state could not be read (cab status, cab doctor)", True
    if ob.change_id is None:
        return None, None, "no active change", False
    msg = obligations.stop_message(ob)
    text = f"active change {ob.change_id} is {ob.state}"
    if msg.kind != "none":
        text += ". " + msg.text
    return ob.change_id, ob.state, text, msg.kind != "none"


def handle_start(
    rt: Runtime,
    data: Mapping[str, Any],
    *,
    clock: Callable[[], float],
    selftest: Callable[..., SelfTest] = run_guard_selftest,
) -> dict[str, Any]:
    result = selftest(rt.roots, clock=clock)
    warnings = session_profile_warnings(read_session_profile(rt.roots))
    active, state_name, status, _due = _obligations_text(rt)
    _row(
        rt,
        SESSION_START_EVENT,
        session_id=_session(data),
        change_id=active,
        state=state_name,
        source=_code(data.get("source"), None),
        decision="selftest_pass" if result.ok else "selftest_fail",
        reason_code=result.code,
    )
    context = (
        "This is a cab-of-one IT operations project. Tenant writes need an open change "
        f"(/change); the hooks enforce it. Status: {status}. Guard self test (synthetic "
        f"fixture, not a live check): {'pass' if result.ok else 'FAIL [' + result.code + ']'}."
    )
    if warnings:  # from the installed setup metadata; independent of the self test result
        context += " " + " ".join(warnings)
    out: dict[str, Any] = {
        "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}
    }
    if not result.ok:
        out["systemMessage"] = (
            f"cab-of-one: the guard self test FAILED [{result.code}]. Writes may not be "
            "gated as intended. Ask a person to run .claude/hooks/cab/cab doctor."
        )
    return out


def handle_end(rt: Runtime, data: Mapping[str, Any]) -> str:
    active, state_name, _status, due = _obligations_text(rt)
    decision = "handoff_due" if due else "logged"
    _row(
        rt,
        SESSION_END_EVENT,
        session_id=_session(data),
        change_id=active,
        state=state_name,
        reason_code=_code(data.get("reason")),
        decision=decision,
    )
    return decision


# --------------------------------------------------------------------------- entry


def _emit(stream: Any, payload: Mapping[str, Any]) -> None:
    try:
        stream.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")
        stream.flush()
    except Exception:
        pass


def _unavailable_start() -> dict[str, Any]:
    text = (
        "cab-of-one: the audit hook could not load the project runtime (layout, policy or "
        "catalogue). The guard then allows only Read, Grep and Glob. Ask a person to run "
        ".claude/hooks/cab/cab doctor."
    )
    return {
        "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text},
        "systemMessage": text,
    }


def main(
    entry: str,
    mode: str,
    *,
    stdin: Any = None,
    stdout: Any = None,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    clock: Callable[[], float] = time.time,
    resolve: Callable[..., Roots] = paths.resolve_roots,
    selftest: Callable[..., SelfTest] = run_guard_selftest,
) -> int:
    """Run one audit hook. Always returns 0; never raises an ``Exception``."""
    out = sys.stdout if stdout is None else stdout
    try:
        event_name = MODES.get(mode) if type(mode) is str else None
        if event_name is None:
            return 0
        env = os.environ if env is None else env
        home = env.get("HOME") if home is None else home
        try:
            data: dict[str, Any] | None = hookevents.read_event(
                sys.stdin if stdin is None else stdin, {event_name}
            )
            read_code = None
        except EventError as exc:
            data, read_code = None, exc.code
        try:
            rt: Runtime | None = open_runtime(resolve(entry, env, home), clock=clock)
        except Exception:
            rt = None
        if rt is None:
            if mode == "start":
                _emit(out, _unavailable_start())
            return 0
        if data is None:
            _row(rt, _ROW_EVENTS[mode], decision="unreadable", reason_code=_code(read_code))
            if mode == "start":
                _emit(out, _unavailable_start())
            return 0
        if mode in ("post", "fail"):
            handle_post(rt, data)
        elif mode == "substart":
            handle_substart(rt, data)
        elif mode == "substop":
            handle_substop(rt, data)
        elif mode == "start":
            _emit(out, handle_start(rt, data, clock=clock, selftest=selftest))
        else:
            handle_end(rt, data)
    except Exception:
        return 0
    return 0
