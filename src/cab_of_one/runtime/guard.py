"""PreToolUse guard: the S4_DESIGN §4 decision order on top of S1 (hookio), S3 (classify).

0. hookio: malformed input or any exception -> exit 2 with a fixed message.
1. Roots, policy or catalogue invalid -> only Read, Grep and Glob pass; everything else
   is denied.
1a. Fixed CLI step (S5): a main-session Bash call that is exactly one literal invocation
   of the pinned ``.claude/hooks/cab/cab`` with an agent verb (new, intake --from-file,
   plan check, tier, snapshot, verify, status, close) is allowed after a durable ledger
   row. Nothing else is loosened: approve/ack/resume and interactive intake stay
   human-only and subagents are unchanged.
2. Protected paths and human-only ``cab`` commands (Write/Edit/NotebookEdit paths and
   ``shellscan`` for Bash) -> deny, for every caller.
3. S3 classification; scripts are read only inside the project, relative to the event cwd.
4. Subagents (``agent_id`` present): role-local files only, reads with a durable ledger
   row, not-admin Bash only from the strict allow list, never an administrative write.
5. Main session: not-admin is no objection; a read is allowed after its ledger row.
6. Administrative write: ``Store.guard_write`` (state lock, re-validation, reservation,
   ledger row) or deny.

"Allow" is always *no objection* (exit 0, ``{}``): Claude Code's own permission and deny
rules still apply. Deny reasons are fixed texts plus a reason code; they never contain the
command, the input or an exception message.
"""

from __future__ import annotations

import os
import re
import stat
import time
from collections.abc import Callable, Mapping
from typing import Any

from . import hookio, paths, schema, shellscan
from .classification_types import KIND_NOT_ADMIN, KIND_READ, Result, leaves
from .classify import MAX_SCRIPT_BYTES, classify_tool_call, tier_floor
from .hookio import Decision
from .ledger import Ledger, LedgerError, display_command, fingerprint
from .paths import ROLE_FILES, Roots
from .schema import Event, Invalid, Policy
from .state import Store, WriteContext

__all__ = ["MESSAGES", "decide", "load_runtime", "main", "message"]

READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob"})
PATH_TOOLS = {
    "Write": "file_path",
    "Edit": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
}
STATE_LOCK_TIMEOUT = 3.0
EXT_LOCK_TIMEOUT = 1.0
LEDGER_LOCK_TIMEOUT = 2.0

CLI_REL = (".claude", "hooks", "cab", "cab")
CLI_VERBS = frozenset({"new", "intake", "plan", "tier", "snapshot", "verify", "status", "close"})
CLI_MAX_COMMAND = 4096
CLI_MAX_WORDS = 8
_CLI_FORBIDDEN = re.compile(r"[$`#\x00-\x1f\x7f]")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")

MESSAGES: dict[str, str] = {
    "policy_invalid": (
        "The policy, catalogue or project layout is invalid, so only Read, Grep and Glob "
        "are allowed. Ask a person to run cab doctor."
    ),
    "event_invalid": "The hook event is missing a required field, so the call is blocked.",
    "internal_error": "The guard failed, so the call is blocked. Ask a person to run cab doctor.",
    "protected_path": (
        "This path is protected (harness, policy, audit, state, approval, review, verify or "
        "snapshot files). Only cab and the hooks write it."
    ),
    "approval_cmd": (
        "cab approve, ack, resume, interactive cab intake and setup apply/uninstall run only "
        "in a person's own terminal. Agents may run only the exact fixture form "
        ".claude/hooks/cab/cab intake CHG-NNNN --from-file FILE."
    ),
    "opaque_write": (
        "The write target could not be determined literally. Use literal paths outside "
        "protected files."
    ),
    "opaque_script": (
        "A script or inline program could not be read, or it refers to protected files."
    ),
    "subagent_write": "Only the main session writes. Return your finding instead.",
    "subagent_path": "This agent may write only its own file in the active change folder.",
    "subagent_bash": "Subagents may run only read-only commands from the allow list.",
    "ledger_error": (
        "The audit ledger could not be written, so the call is blocked. Ask a person to run "
        "cab doctor."
    ),
    "lock_timeout": "The change state is busy. Try again.",
    "state_invalid": (
        "The change state is invalid or inconsistent. Ask a person to run cab doctor."
    ),
    "state_error": "The change state could not be updated, so the write is blocked.",
    "no_open_change": "No open change. Start one with /change.",
    "cwd_not_project": "Run tenant writes from the project root.",
    "not_planned": "The change has no checked plan for this write yet. Run cab plan check.",
    "approval_missing": (
        "{tier} tier requires approval. Ask a person to run cab approve in their own terminal."
    ),
    "approval_invalid": (
        "The approval does not match the plan, review or registry. Ask a person to run cab "
        "approve again."
    ),
    "approval_expired": "The approval expired. Ask a person to run cab approve again.",
    "plan_invalid": "The change plan files are missing or invalid. Run cab plan check.",
    "plan_changed": (
        "The plan changed after it was checked, reviewed or approved. Run cab plan check again."
    ),
    "tier_blocked": "Targets are not enumerated. List them in targets.csv first.",
    "tier_floor": (
        "This command needs a higher tier than the change records. Re-plan the change at that tier."
    ),
    "review_invalid": (
        "The safety review is missing, blocked, stale or not acknowledged. Run the review again."
    ),
    "snapshot_invalid": (
        "Take a snapshot of the planned targets for this plan first (cab snapshot)."
    ),
    "snapshot_incomplete": (
        "The snapshot did not measure every planned target, so writes are refused. Only "
        "targets with a supported read can be written (cab snapshot lists the rest)."
    ),
    "snapshot_stale": (
        "The snapshot is older than the approval lifetime and nothing ran yet. Take a new "
        "snapshot (cab snapshot); review and approval must then be redone."
    ),
    "execution_ended": (
        "Execution of this change has ended (closed, failed or not verified). No more "
        "writes; check cab status."
    ),
    "scope_mismatch": "The command's tenant scope is not the planned scope.",
    "scope_unsafe": "The tenant state path is not a plain file inside the project.",
    "target_outside": "A target of this command is not in targets.csv.",
    "binding_missing": (
        "The targets of this command cannot be read from it. Run the exact command of an "
        "approved step."
    ),
    "binding_dynamic": (
        "Approved step commands must be literal: no expansion, glob or here-document."
    ),
    "binding_ambiguous": "More than one approved step has this command. Fix the plan.",
    "step_used": "This step already ran. A step runs once.",
    "canary_first_unit": (
        "{tier} change: run the first unit alone (one write, one target) and verify it "
        "before the rest."
    ),
    "canary_awaiting": "Verify the first unit with cab verify before the next write.",
    "halted": (
        "The change is halted after a failed or unknown write. A person must run cab resume."
    ),
    "inflight": (
        "A write is in flight without a result. Wait for it, or a person must run cab resume."
    ),
    "duplicate_id": "This tool call ID was already used.",
}


def message(code: str, tier: str | None = None) -> str:
    text = MESSAGES.get(code)
    if text is None:
        code, text = "internal_error", MESSAGES["internal_error"]
    label = tier if tier in schema.TIER_RANK else "this"
    text = text.replace("{tier}", label)
    return text + " [" + code + "]"


def load_runtime(roots: Roots) -> tuple[Policy, tuple[dict[str, Any], ...]]:
    """Policy and catalogue, strictly validated. Raises on any problem."""
    data = paths.read_authority(roots.project, "policy/policy.toml", schema.MAX_POLICY_BYTES)
    if data is None:
        raise Invalid("policy_missing")
    policy = schema.load_policy(data)
    data = paths.read_authority(
        roots.project, "policy/standard-changes.toml", schema.MAX_POLICY_BYTES
    )
    if data is None:
        raise Invalid("catalog_missing")
    return policy, schema.load_catalog(data)


def _cls(r: Result | None, floor: str | None = None) -> dict[str, Any] | None:
    if r is None:
        return None
    return {
        "kind": r.kind,
        "unknown": r.unknown,
        "adapter": r.adapter,
        "verb": r.verb,
        "floor": floor,
        "targets_complete": r.targets_complete,
        "n": len(leaves(r)),
    }


class _Log:
    """Pre-decision ledger rows. A deny stays a deny when its row cannot be written."""

    def __init__(self, ledger: Ledger, ev: Event, extra: tuple[str, ...]) -> None:
        self.ledger = ledger
        self.ev = ev
        self.extra = extra

    def _row(self, decision: str, code: str, r: Result | None, **fields: Any) -> None:
        ev = self.ev
        self.ledger.append(
            "pre",
            command=display_command(ev.tool_name, ev.tool_input, self.extra),
            session_id=ev.session_id,
            tool_use_id=ev.tool_use_id,
            agent="subagent" if ev.is_subagent else "main",
            agent_type=ev.agent_type,
            decision=decision,
            reason_code=code,
            tool=ev.tool_name,
            cls=_cls(r, fields.pop("floor", None)),
            **fields,
        )

    def deny(self, code: str, r: Result | None = None, **fields: Any) -> Decision:
        try:
            self._row("deny", code, r, **fields)
        except Exception:
            pass  # recording a deny can fail; the deny itself never changes
        return Decision.deny(message(code, fields.get("tier")))

    def read(self, r: Result) -> Decision:
        try:
            self._row("allow", "read", r)
        except LedgerError:
            return Decision.deny(message("ledger_error"))
        return Decision.allow()

    def cli(self) -> Decision:
        """Fixed CLI step: allowed only after its durable row."""
        try:
            self._row("allow", "cab_cli", None)
        except Exception:
            return Decision.deny(message("ledger_error"))
        return Decision.allow()


def _cli_file_ok(roots: Roots) -> bool:
    """The pinned CLI: real directories down to a regular, single-link, non-symlink file."""
    cursor = roots.project
    try:
        for index, part in enumerate(CLI_REL):
            cursor = os.path.join(cursor, part)
            st = os.lstat(cursor)
            if stat.S_ISLNK(st.st_mode):
                return False
            if index < len(CLI_REL) - 1:
                if not stat.S_ISDIR(st.st_mode):
                    return False
            elif not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                return False
    except OSError:
        return False
    return True


def _fixed_cli(command: Any, cwd: str | None, roots: Roots) -> bool:
    """True only for one literal call of the pinned CLI with an agent verb.

    ``.claude/hooks/cab/cab`` (with the event cwd being the project) or
    ``<project>/.claude/hooks/cab/cab``; exactly one simple command, no separator,
    redirection, substitution, group, assignment, glob, ``$``, backtick, ``#`` or control
    character (quotes are allowed and only make words literal); at most 8 words;
    ``plan`` only as ``plan check``; never a human-only verb.
    """
    if not isinstance(command, str) or not command or len(command) > CLI_MAX_COMMAND:
        return False
    if _CLI_FORBIDDEN.search(command):
        return False
    try:
        cmds = shellscan.parse(command)
    except shellscan.ParseError:
        return False
    if len(cmds) != 1:
        return False
    cmd = cmds[0]
    if cmd.redirs or cmd.procsubs or cmd.group is not None or cmd.sep != "":
        return False
    words = cmd.words
    if not 2 <= len(words) <= CLI_MAX_WORDS:
        return False
    for word in words:
        # quoting is allowed (a project path may contain spaces); expansion is not
        if not word.literal or word.subs or not word.text:
            return False
    if _ASSIGN.match(words[0].raw):
        return False
    head = words[0].text
    if head == "/".join(CLI_REL):
        if not paths.same_dir(cwd, roots.project):
            return False
    elif head != os.path.join(roots.project, *CLI_REL):
        return False
    if not _cli_file_ok(roots):
        return False
    verb = words[1].text
    if verb not in CLI_VERBS:
        return False
    if verb == "plan" and (len(words) < 3 or words[2].text != "check"):
        return False
    # Only the fixture form is an agent verb: ``intake CHG-NNNN --from-file PATH``. The
    # interactive form (``intake CHG-NNNN``) is a person's terminal command; it falls
    # through to step 2, where shellscan refuses it as human-only.
    if verb == "intake" and (len(words) != 5 or words[3].text != "--from-file"):
        return False
    return not shellscan.approval_text(command)


def _scan_context(roots: Roots) -> shellscan.ScanContext:
    def protected(path: str, cwd: str | None, ancestors: bool) -> bool | None:
        return paths.protected_match(path, cwd, roots, ancestors=ancestors)

    def read_text(path: str, cwd: str | None) -> str | None:
        data = paths.read_project_file(roots, cwd, path, MAX_SCRIPT_BYTES)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def is_dir(path: str, cwd: str | None) -> bool:
        if not os.path.isabs(path):
            if cwd is None:
                return False
            path = os.path.join(cwd, path)
        return os.path.isdir(path)

    return shellscan.ScanContext(protected, read_text, is_dir)


def _protected_code(ev: Event, roots: Roots, ctx: shellscan.ScanContext) -> str | None:
    """Guard step 2."""
    if ev.tool_name in PATH_TOOLS:
        path = ev.tool_input.get(PATH_TOOLS[ev.tool_name])
        if not isinstance(path, str) or not path:
            return "event_invalid"
        hit = paths.protected_match(path, ev.cwd, roots)
        if hit is None:
            return "event_invalid"
        return "protected_path" if hit else None
    if ev.tool_name == "Bash":
        command = ev.tool_input.get("command")
        if isinstance(command, str):
            return shellscan.scan(command, ev.cwd, ctx)
    return None


def _fail_path(tool: Any) -> Decision:
    """Guard step 1: nothing can be trusted, so only the three read-only tools pass."""
    if tool in READ_ONLY_TOOLS:
        return Decision.allow()
    return Decision.deny(message("policy_invalid"))


def decide(
    event: Mapping[str, Any],
    roots: Roots | None,
    *,
    classify: Callable[..., Any] = classify_tool_call,
    clock: Callable[[], float] = time.time,
    lock_timeout: float = STATE_LOCK_TIMEOUT,
    ledger_timeout: float = LEDGER_LOCK_TIMEOUT,
) -> Decision:
    """One PreToolUse decision. Never raises an ``Exception``; failures are denies."""
    try:
        return _decide(event, roots, classify, clock, lock_timeout, ledger_timeout)
    except Exception:
        return Decision.deny(message("internal_error"))


def _decide(
    event: Mapping[str, Any],
    roots: Roots | None,
    classify: Callable[..., Any],
    clock: Callable[[], float],
    lock_timeout: float,
    ledger_timeout: float,
) -> Decision:
    tool = event.get("tool_name") if isinstance(event, Mapping) else None
    # 1. roots, policy, catalogue
    if roots is None:
        return _fail_path(tool)
    try:
        policy, catalog = load_runtime(roots)
    except Exception:
        return _fail_path(tool)
    ledger = Ledger(
        roots, extra_patterns=policy.extra_patterns, clock=clock, lock_timeout=ledger_timeout
    )
    try:
        ev = schema.parse_event(event)
    except Invalid:
        return Decision.deny(message("event_invalid"))
    log = _Log(ledger, ev, policy.extra_patterns)

    # 1a. the pinned cab CLI, main session only
    if not ev.is_subagent and ev.tool_name == "Bash":
        if _fixed_cli(ev.tool_input.get("command"), ev.cwd, roots):
            return log.cli()

    # 2. protected paths and human-only commands
    scan_ctx = _scan_context(roots)
    code = _protected_code(ev, roots, scan_ctx)
    if code:
        return log.deny(code)

    # 3. classification
    cwd_is_project = paths.same_dir(ev.cwd, roots.project)
    s3 = policy.s3_for(cwd_is_project)

    def read_file(path: str) -> bytes | None:
        return paths.read_project_file(roots, ev.cwd, path, MAX_SCRIPT_BYTES)

    r = classify(ev.tool_name, ev.tool_input, policy=s3, read_file=read_file)
    if not isinstance(r, Result):
        return log.deny("internal_error")
    admin_fields = bool(ev.session_id and ev.tool_use_id and ev.cwd)
    command = ev.tool_input.get("command") if ev.tool_name == "Bash" else None

    # 4. subagents
    if ev.is_subagent:
        if ev.tool_name in PATH_TOOLS:
            if _role_file_ok(ev, roots, policy, catalog, ledger):
                return Decision.allow()
            return log.deny("subagent_path", r)
        if ev.tool_name in READ_ONLY_TOOLS and r.kind == KIND_NOT_ADMIN:
            return Decision.allow()
        if r.kind == KIND_READ:
            if not admin_fields:
                return log.deny("event_invalid", r)
            if isinstance(command, str) and shellscan.scan(command, ev.cwd, scan_ctx, strict=True):
                return log.deny("subagent_bash", r)
            return log.read(r)
        if r.kind == KIND_NOT_ADMIN:
            if ev.tool_name != "Bash":
                return Decision.allow()
            if isinstance(command, str) and shellscan.subagent_command_ok(
                command, policy.subagent_bash_allow, ev.cwd, scan_ctx
            ):
                return Decision.allow()
            return log.deny("subagent_bash", r)
        return log.deny("subagent_write", r)

    # 5. main session
    if r.kind == KIND_NOT_ADMIN:
        return Decision.allow()
    if not admin_fields:
        return log.deny("event_invalid", r)
    if r.kind == KIND_READ:
        return log.read(r)

    # 6. administrative write
    floor = tier_floor(r, s3)
    mcp_sha = schema.input_sha256(ev.tool_input) if ev.tool_name.startswith("mcp__") else None
    store = Store(
        roots,
        policy,
        catalog,
        ledger=ledger,
        clock=clock,
        lock_timeout=lock_timeout,
        ext_timeout=EXT_LOCK_TIMEOUT,
    )
    ctx = WriteContext(
        tool_name=ev.tool_name,
        tool_use_id=ev.tool_use_id or "",
        session_id=ev.session_id or "",
        agent_type=ev.agent_type,
        result=r,
        floor=floor,
        command=command if isinstance(command, str) else None,
        mcp_input_sha256=mcp_sha,
        fingerprint=fingerprint(ev.tool_name, ev.tool_input, policy.extra_patterns),
        cwd_is_project=cwd_is_project,
        ledger_command=display_command(ev.tool_name, ev.tool_input, policy.extra_patterns),
        cls=_cls(r, floor) or {},
        tool_input=ev.tool_input,
    )
    gate = store.guard_write(ctx)
    if gate.allowed:
        return Decision.allow()
    return log.deny(gate.code, r, floor=floor, tier=gate.tier, change_id=gate.change_id)


def _role_file_ok(ev: Event, roots: Roots, policy: Policy, catalog: tuple, ledger: Ledger) -> bool:
    names = ROLE_FILES.get(ev.agent_type or "") if ev.agent_id is not None else None
    if not names:
        return False
    try:
        view = Store(roots, policy, catalog, ledger=ledger).load()
    except Exception:
        return False
    if view.change is None:
        return False
    folder = f"{view.change['id']}-{view.change['slug']}"
    path = ev.tool_input.get(PATH_TOOLS[ev.tool_name])
    return paths.role_file_match(path, ev.cwd, roots, folder, names)


def main(entry: str) -> None:
    """Entry point for the pinned copy at ``<project>/.claude/hooks/cab/guard.py``."""

    def handler(data: dict[str, Any]) -> Decision:
        try:
            roots = paths.resolve_roots(entry, os.environ, os.environ.get("HOME"))
        except Exception:
            roots = None
        return decide(data, roots)

    hookio.run_hook(handler)
