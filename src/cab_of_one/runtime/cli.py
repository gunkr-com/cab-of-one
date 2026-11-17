"""``cab``: the runtime CLI of an installed cab-of-one project (S5 C-main).

Pinned entry: ``<project>/.claude/hooks/cab/cab``. Roots come from that entry through
``paths.resolve_cli_roots`` (``CLAUDE_PROJECT_DIR`` must match only when it is set); an
entry that is not installed exits 3. The installed runtime never needs the setup package
or the plugin.

Commands::

    new CHG-NNNN <slug>                 open a change (draft)
    intake CHG-NNNN --from-file F       fixture answers -> intake.md, ledger source=fixture
    intake CHG-NNNN                     person's terminal: six questions, genuine TTY,
                                        exact typed ID -> intake.md, ledger source=terminal
    plan check CHG-NNNN                 validate plan, probes, intake.md and a completed
                                        intake row of the same source as intake.md
                                        (fixture or terminal; askuser never counts)
    tier CHG-NNNN                       show the computed tier (no state change)
    snapshot CHG-NNNN                   one fresh strict read per target (exit 11 incomplete)
    verify CHG-NNNN                     re-read every settled, not-PASS unit (10 FAIL, 11 UNM)
    status [CHG-NNNN]                   selected, redacted state fields and obligations
    close CHG-NNNN                      0 closed, 10 failed, 11 open-unverified
    approve | ack CHG-NNNN              person only, genuine TTY, exact typed ID
    resume CHG-NNNN [--clear-inflight]  person only, genuine TTY, exact typed ID
    audit [metrics] [--days N] [--json] S6 self audit of this project (person's command)
    doctor [--json]                     S6 static doctor (person's command)

Exit codes: 0 ok, 1 not confirmed, 2 usage or invalid plan/input, 3 refused or not
allowed, 4 conflict (seq, plan hash, review, lock timeout), 5 state/ledger/internal error,
10 failed, 11 unmeasured/incomplete. Errors are fixed codes and texts on stderr; no
traceback, no input echo. Output shows only selected redacted fields: never call salts,
HMACs, raw-input digests, nonces or whole protected documents.

Person-only commands read the summary without a lock, confirm at a genuine TTY
(``terminal.require_human``), then commit through the Store with the sequence, plan hash or
review hash that was shown (compare-and-set). There is no attest, abandon or unguarded
resume, and no command writes global configuration.

Terminal intake (``intake CHG-NNNN``) follows the same pattern: TTY and uid checks before
any prompt, the six answers collected without a lock, a redacted summary confirmed through
``terminal.require_human``, then, under the Store's state lock, the active change document
is re-read and must equal the one read before the questions; ``intake.md`` is created only
if no such file exists (never replaced) and the ledger row is appended. If the row cannot
be written, the file this call created is removed again. It records answers only: no
approval, and the TTY check is not proof of who typed them.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import (
    config_lock,
    doctor,
    fsutil,
    intake,
    obligations,
    paths,
    probes,
    schema,
    selfaudit,
    terminal,
    verifyrun,
)
from .audithook import START_EVENTS, Runtime, open_runtime
from .classify import MAX_SCRIPT_BYTES, catalog_match, classify_tool_call, decide_tier, tier_floor
from .ledger import LEDGER_VERSION, LedgerError, iter_jsonl_bytes
from .paths import Roots, UnsafePath
from .probes import SubprocessRunner, SystemClock
from .schema import TIER_RANK, Invalid
from .state import Conflict, NotAllowed, StateCorrupt, StoreError

__all__ = [
    "EXIT_CONFLICT",
    "EXIT_ERROR",
    "EXIT_FAILED",
    "EXIT_MISMATCH",
    "EXIT_OK",
    "EXIT_REFUSED",
    "EXIT_UNMEASURED",
    "EXIT_USAGE",
    "FIXTURE_INTAKE_ROW",
    "INTAKE_FIELDS",
    "MANIFEST_PROBLEMS",
    "TERMINAL_INTAKE_ROW",
    "Deps",
    "completed_intake",
    "compute_tier",
    "console_main",
    "intake_md_source",
    "intake_row_source",
    "main",
    "source_main",
]

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3
EXIT_CONFLICT = 4
EXIT_ERROR = 5
EXIT_FAILED = 10
EXIT_UNMEASURED = 11

AGENT_ACTOR = "cab-cli"
MAX_INTAKE_FILE = 64 * 1024
MAX_INTAKE_VALUE = 2048
MAX_INTAKE_MD = 256 * 1024
MAX_LEDGER_FILES = 600
MAX_LEDGER_FILE = 64 * 1024 * 1024
MAX_STATUS_UNITS = 50
MAX_SETTINGS_BYTES = 1024 * 1024
CLI = ".claude/hooks/cab/cab"

# intake.md labels, matching the S7 change-intake template; fixture TOML key -> label.
INTAKE_FIELDS: tuple[tuple[str, str], ...] = (
    ("purpose", "- Purpose:"),
    ("in_scope", "- In scope:"),
    ("out_of_scope", "- Out of scope / lookalikes excluded:"),
    ("timing", "- Timing:"),
    ("known_dependents", "- Known dependents:"),
    ("success_criteria", "- Success criteria:"),
)
# Completed interview evidence for plan check. Only the rows cmd_intake itself writes count:
# exactly these field values and keys per source, for the same change. AskUserQuestion rows
# (a question was asked; answers are not measured), timeouts, unknown or malformed sources
# fail closed; no format for measured AskUserQuestion answers exists, so none is guessed.
FIXTURE_INTAKE_ROW: dict[str, str] = {
    "source": "fixture",
    "reason_code": "fixture_file",
    "actor": AGENT_ACTOR,
}
_FIXTURE_INTAKE_KEYS = frozenset({"v", "event", "change_id", "ts", *FIXTURE_INTAKE_ROW})
# Terminal intake: the actor names the code path that wrote the row (the CLI's terminal
# intake), not a verified person. ``response_sha256`` is the sha256 of the exact intake.md
# bytes written (already redacted text), so the row only counts for that file.
TERMINAL_ACTOR = "cab-cli-terminal"
TERMINAL_INTAKE_ROW: dict[str, str] = {
    "source": "terminal",
    "reason_code": "terminal_answers",
    "actor": TERMINAL_ACTOR,
}
_TERMINAL_INTAKE_KEYS = frozenset(
    {"v", "event", "change_id", "ts", "response_sha256", *TERMINAL_INTAKE_ROW}
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
# The single source line each writer puts in intake.md; plan check requires exactly one.
FIXTURE_SOURCE_LINE = "- Source: fixture (not answers given by a person)"
TERMINAL_SOURCE_LINE = (
    "- Source: terminal (typed at a terminal that passed a TTY check; not proof of who typed them)"
)
INTAKE_SOURCE_LINES: dict[str, str] = {
    "fixture": FIXTURE_SOURCE_LINE,
    "terminal": TERMINAL_SOURCE_LINE,
}
# validate() refusals that make the plan itself wrong (exit 2); others are warnings.
PROBE_PLAN_ERRORS = frozenset(
    {
        probes.R_PROBE_NOT_READ,
        probes.R_PROBE_INVALID,
        probes.R_PROBE_TARGET_MISMATCH,
        probes.R_SCOPE_MISMATCH,
    }
)
DOCTOR_FAIL_CLOSED_EVENTS = ("PreToolUse", "Stop", "ConfigChange")
# Settings sources this file-only doctor does not measure (SETTINGS_PATH_FACTS 2026-11-12).
UNMEASURED_SETTINGS = (
    "managed settings files (managed-settings.json, managed-settings.d/, managed-mcp.json) "
    "are not read; their absence would not prove that no managed policy exists",
    "MDM managed preferences and Windows registry policies",
    "server-delivered and host policies",
    "command-line settings (--settings) of each launch",
    "worktree or main-checkout local settings and older starting-directory files",
    "the user settings of Claude Code's own environment if it differs from this terminal "
    "(for example another CLAUDE_CONFIG_DIR)",
    "the manifest's settings contributions, CLAUDE.md/.gitignore blocks and create-once "
    "files are not compared by doctor; only its generated-file hashes are",
)
#: Problems with ``.cab/manifest.json`` itself: (doctor status, fixed text). A manifest that
#: cannot be used is never treated as an empty manifest (which the doctor would pass).
MANIFEST_PROBLEMS: dict[str, tuple[str, str]] = {
    "manifest_absent": (
        doctor.FAIL,
        ".cab/manifest.json is missing, so generated files were not checked (setup did not "
        "finish, or the manifest was removed).",
    ),
    "manifest_unsafe": (
        doctor.FAIL,
        ".cab/manifest.json (or a folder above it) is a link, a hard link, not a regular file "
        "or too large; it was not read.",
    ),
    "manifest_corrupt": (
        doctor.FAIL,
        ".cab/manifest.json is not a valid schema-1 manifest; it was not used.",
    ),
    "manifest_empty": (
        doctor.FAIL,
        ".cab/manifest.json lists no generated files, so nothing could be checked.",
    ),
    "manifest_reader_unavailable": (
        doctor.UNKNOWN,
        "The pinned manifest reader (cab_of_one/setup/manifest.py) is not installed with the "
        "hooks, so generated files were not checked.",
    ),
}

_CONTROL_TEXT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MONTH_FILE = re.compile(r"[0-9]{4}-[0-9]{2}\.jsonl")

MESSAGES: dict[str, str] = {
    "usage": "usage: cab <new|intake|plan check|tier|snapshot|verify|status|close|approve|"
    "ack|resume|audit|doctor> ... (intake CHG-NNNN [--from-file F])",
    "bad_change_id": "the change ID must look like CHG-0007.",
    "unknown_command": "unknown command.",
    "setup_unavailable": "cab setup runs from the cab-of-one plugin source, not from an "
    "installed project runtime.",
    "setup_broken": "the setup package could not be loaded.",
    "roots": "this is not an installed cab-of-one project entry (run "
    ".claude/hooks/cab/cab from the project).",
    "runtime_invalid": "the policy, catalogue or layout is invalid. Run cab doctor.",
    "not_active": "that change is not the active change.",
    "no_active_change": "there is no active change.",
    "state": "the change is not in a state that allows this command.",
    "state_invalid": "the change state is invalid or inconsistent. Run cab doctor.",
    "lock_timeout": "the change state is busy. Try again.",
    "ledger_error": "the audit ledger could not be written.",
    "ledger_unreadable": "the audit ledger has broken lines; a person must inspect it.",
    "plan_invalid": "the change plan files are missing or invalid.",
    "plan_changed": "the plan changed since it was read. Run cab plan check again.",
    "verify_missing": "every target in targets.csv needs exactly one [[verify]] probe.",
    "probe_invalid": "a [[verify]] probe is not a literal read of its own target in the "
    "planned scope.",
    "intake_missing": "intake.md is missing or lacks a required line.",
    "interview_missing": "no completed interview evidence exists for this change. Only an "
    "intake.md written by cab intake (from a fixture file, or at a person's terminal) with "
    "its matching ledger row counts; AskUserQuestion rows record that a question was asked, "
    "not the answers.",
    "state_changed": "the change state changed while the questions were answered. Nothing "
    "was written; run cab intake again.",
    "tier_blocked": "targets are not enumerated. List them in targets.csv first.",
    "intake_file": "the intake file is not a readable project file.",
    "intake_invalid": "the intake file must be TOML with exactly the six string answers.",
    "intake_exists": "intake.md already exists; it is not overwritten.",
    "change_folder": "the change folder is missing or not a plain directory.",
    "review_invalid": "the review is missing or does not match the recorded hash.",
    "ack_missing": "the review has conditions; a person must run cab ack first.",
    "not_conditions": "the review has no conditions to acknowledge.",
    "snapshot_incomplete": "there is no complete snapshot of this plan. Run cab snapshot.",
    "inflight_needs_clear": "a write never returned a result. Make sure it has stopped, "
    "then run cab resume with --clear-inflight.",
    "not_halted": "the change is not halted and nothing is in flight.",
    "home_invalid": "the home directory is unknown.",
    "internal_error": "internal error; nothing more is shown.",
    "interrupted": "interrupted.",
}


class CliError(Exception):
    def __init__(self, code: str, exit_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.exit = exit_code


def _default_git(project: str) -> str:
    return terminal.git_user_name(project)


@dataclass
class Deps:
    """Injectable effects. Production uses the defaults."""

    clock: Callable[[], float] = time.time
    probe_clock: Any = field(default_factory=SystemClock)
    runner: Any = field(default_factory=SubprocessRunner)
    terminal_os: terminal.TerminalOS | None = None
    git_lookup: Callable[[str], str] = _default_git
    resolve: Callable[..., Roots] = paths.resolve_cli_roots
    cwd: Callable[[], str] = os.getcwd


@dataclass
class _Ctx:
    argv: list[str]
    env: Mapping[str, str]
    home: str | None
    stdin: Any
    stdout: Any
    stderr: Any
    deps: Deps
    entry: str
    rt: Runtime | None = None

    def out(self, *lines: str) -> None:
        for line in lines:
            self.stdout.write(terminal.sanitize(line, 2000) + "\n")
        self.stdout.flush()

    def raw(self, text: str) -> None:
        self.stdout.write(text + "\n")
        self.stdout.flush()

    def runtime(self) -> Runtime:
        if self.rt is None:
            try:
                roots = self.deps.resolve(self.entry, self.env, self.home)
            except Exception:  # RootsError or anything else: not an installed entry
                raise CliError("roots", EXIT_REFUSED) from None
            try:
                self.rt = open_runtime(roots, clock=self.deps.clock)
            except Exception:
                raise CliError("runtime_invalid", EXIT_ERROR) from None
        return self.rt


def _err(stream: Any, code: str, text: str | None = None) -> None:
    text = text if text is not None else MESSAGES.get(code, "refused.")
    try:
        stream.write(f"cab: {code}: {text}\n")
        stream.flush()
    except Exception:
        pass


def _store_error(exc: BaseException) -> CliError:
    if isinstance(exc, Conflict):
        return CliError(exc.code, EXIT_CONFLICT)
    if isinstance(exc, fsutil.LockTimeout):
        return CliError("lock_timeout", EXIT_CONFLICT)
    if isinstance(exc, NotAllowed):
        if exc.code in ("plan_invalid",):
            return CliError(exc.code, EXIT_USAGE)
        if exc.code == "plan_changed":
            return CliError(exc.code, EXIT_CONFLICT)
        return CliError(exc.code, EXIT_REFUSED)
    if isinstance(exc, StateCorrupt):
        return CliError("state_invalid", EXIT_ERROR)
    if isinstance(exc, StoreError):
        return CliError(exc.code, EXIT_REFUSED)
    if isinstance(exc, LedgerError):
        return CliError("ledger_error", EXIT_ERROR)
    return CliError("internal_error", EXIT_ERROR)


def _store_call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except (StoreError, fsutil.FsError, LedgerError, OSError, UnsafePath) as exc:
        raise _store_error(exc) from None


def _cid(value: Any) -> str:
    if not schema.is_change_id(value):
        raise CliError("bad_change_id", EXIT_USAGE)
    return value


def _active_doc(rt: Runtime, cid: str) -> dict[str, Any]:
    view = _store_call(rt.store.load)
    if view.active != cid or view.change is None:
        raise CliError("not_active", EXIT_REFUSED)
    return view.change


def _change_folder(rt: Runtime, doc: Mapping[str, Any]) -> str:
    folder = rt.roots.at("changes", f"{doc['id']}-{doc['slug']}")
    for path in (rt.roots.at("changes"), folder):
        try:
            st = os.lstat(path)
        except OSError:
            raise CliError("change_folder", EXIT_REFUSED) from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise CliError("change_folder", EXIT_REFUSED)
    return folder


def _authority(folder: str, name: str, limit: int) -> bytes | None:
    try:
        return paths.read_authority(folder, name, limit)
    except UnsafePath:
        raise CliError("state_invalid", EXIT_ERROR) from None


# --------------------------------------------------------------------------- ledger reading


def ledger_rows(roots: Roots) -> tuple[list[dict[str, Any]], bool]:
    """Every valid ledger row and whether any line or file was broken. Read only."""
    folder = roots.ledger_dir
    try:
        st = os.lstat(folder)
    except FileNotFoundError:
        return [], False
    except OSError:
        return [], True
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return [], True
    try:
        names = sorted(n for n in os.listdir(folder) if _MONTH_FILE.fullmatch(n))
    except OSError:
        return [], True
    if len(names) > MAX_LEDGER_FILES:
        return [], True
    rows: list[dict[str, Any]] = []
    broken = False
    for name in names:
        try:
            data = paths.read_authority(folder, name, MAX_LEDGER_FILE)
        except UnsafePath:
            broken = True
            continue
        if data is None:
            continue
        for line in iter_jsonl_bytes(data):
            if line.status != "ok" or line.value is None:
                broken = True
            else:
                rows.append(line.value)
    return rows, broken


# --------------------------------------------------------------------------- tier


def compute_tier(rt: Runtime, plan: Any) -> str:
    """Contract 4.4: ``decide_tier(answers, irreversible, catalog_hit=every step hit,
    floor=max floor)`` over the step commands. No steps (or an MCP step, whose input is
    only a hash) means no catalogue hit; the guard re-checks the floor at every write."""
    s3 = rt.policy.s3_for(True)

    def read_file(path: str) -> bytes | None:
        return paths.read_project_file(rt.roots, rt.roots.project, path, MAX_SCRIPT_BYTES)

    floors: list[str] = []
    hits: list[str | None] = []
    for step in plan.steps:
        if step.command is None:
            hits.append(None)
            continue
        r = classify_tool_call("Bash", {"command": step.command}, policy=s3, read_file=read_file)
        floor = tier_floor(r, s3)
        if floor is not None:
            floors.append(floor)
        hits.append(catalog_match(r, list(rt.catalog)))
    floor = max(floors, key=lambda f: TIER_RANK.get(f, 2)) if floors else None
    hit = hits[-1] if hits and all(h is not None for h in hits) else None
    return decide_tier(plan.answers, irreversible=plan.irreversible, catalog_hit=hit, floor=floor)


# --------------------------------------------------------------------------- commands


def cmd_new(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 2:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    seq = _store_call(rt.store.new_change, cid, args[1], AGENT_ACTOR)
    ctx.out(
        f"{cid}: opened as draft (seq {seq}).",
        f"Next: ask the person to run {CLI} intake {cid} in their own terminal (do not write "
        "intake.md yourself). Then write change.toml (with one [[verify]] per target), "
        f"plan.md and targets.csv, then run {CLI} plan check {cid}.",
    )
    return EXIT_OK


def _intake_text(cid: str, answers: Mapping[str, str], source: str = "fixture") -> str:
    lines = [f"# Intake: {cid}"]
    for key, label in INTAKE_FIELDS:
        value = answers[key].replace("\n", " ").strip()
        lines.append(f"{label} {value}")
    if source == "terminal":
        lines.append("- Unanswered: none (each question was answered at a terminal)")
    else:
        lines.append("- Unanswered: (fixture file; no interview took place)")
    lines.append(INTAKE_SOURCE_LINES[source])
    return "\n".join(lines) + "\n"


def cmd_intake(ctx: _Ctx, args: list[str]) -> int:
    if len(args) == 1:
        return _intake_terminal(ctx, _cid(args[0]))
    if len(args) != 3 or args[1] != "--from-file":
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    if doc["state"] not in ("draft", "planned"):
        raise CliError("state", EXIT_REFUSED)
    data = paths.read_project_file(rt.roots, ctx.deps.cwd(), args[2], MAX_INTAKE_FILE)
    if data is None:
        raise CliError("intake_file", EXIT_REFUSED)
    try:
        answers = schema.strict_toml(data, max_bytes=MAX_INTAKE_FILE)
    except Invalid:
        raise CliError("intake_invalid", EXIT_USAGE) from None
    if set(answers) != {k for k, _ in INTAKE_FIELDS}:
        raise CliError("intake_invalid", EXIT_USAGE)
    for value in answers.values():
        if type(value) is not str or not value.strip() or len(value) > MAX_INTAKE_VALUE:
            raise CliError("intake_invalid", EXIT_USAGE)
        if _CONTROL_TEXT.search(value):
            raise CliError("intake_invalid", EXIT_USAGE)
    folder = _change_folder(rt, doc)
    if _authority(folder, "intake.md", MAX_INTAKE_MD) is not None:
        raise CliError("intake_exists", EXIT_REFUSED)
    try:
        fsutil.atomic_write(
            os.path.join(folder, "intake.md"), _intake_text(cid, answers).encode("utf-8")
        )
    except (fsutil.FsError, OSError):
        raise CliError("change_folder", EXIT_ERROR) from None
    try:
        rt.ledger.append("intake", change_id=cid, **FIXTURE_INTAKE_ROW)
    except LedgerError:
        raise CliError("ledger_error", EXIT_ERROR) from None
    ctx.out(f"{cid}: intake.md written from a fixture file (source=fixture, not a person).")
    return EXIT_OK


def _intake_summary(cid: str, answers: Mapping[str, str], redacted: int) -> list[str]:
    lines = [f"Write intake.md for {cid} from these answers:"]
    for key, label in INTAKE_FIELDS:
        lines.append(f"  {label.removeprefix('- ')} {answers[key]}")
    if redacted:
        lines.append(
            f"  note: secret-looking text in {redacted} answer(s) was replaced with "
            "[REDACTED]; intake.md stores the text shown here."
        )
    lines.append("This records interview answers only. It approves nothing.")
    lines.append(f"Type {cid} and press Enter to write intake.md; anything else cancels.")
    return lines


def _intake_terminal(ctx: _Ctx, cid: str) -> int:
    """``cab intake CHG-NNNN`` at a person's terminal (see the module doc).

    Order: TTY/uid preflight (nothing shown before it) -> lockless read of the active
    change -> six answers -> redacted summary and exact typed ID (``require_human``) ->
    under the state lock: same change document as before, no intake.md, exclusive create,
    ledger row. A refusal at any step writes nothing."""
    pre = intake.preflight(ctx.stdin, ctx.stdout, ctx.deps.terminal_os)
    if not pre.ok:
        _err(ctx.stderr, pre.code, intake.MESSAGES[pre.code])
        return pre.exit
    rt = ctx.runtime()
    baseline = _active_doc(rt, cid)
    if baseline["state"] not in ("draft", "planned"):
        raise CliError("state", EXIT_REFUSED)
    folder = _change_folder(rt, baseline)
    if _authority(folder, "intake.md", MAX_INTAKE_MD) is not None:
        raise CliError("intake_exists", EXIT_REFUSED)
    got = intake.collect(
        [key for key, _ in INTAKE_FIELDS],
        change_id=cid,
        stdin=ctx.stdin,
        stdout=ctx.stdout,
        limit=MAX_INTAKE_VALUE,
    )
    if not got.ok or got.answers is None:
        _err(ctx.stderr, got.code, intake.MESSAGES.get(got.code, "cancelled."))
        return got.exit
    answers, redacted = intake.redact_answers(got.answers, rt.policy.extra_patterns)
    data = _intake_text(cid, answers, "terminal").encode("utf-8")
    if len(data) > MAX_INTAKE_MD:
        raise CliError("internal_error", EXIT_ERROR)
    check = _human(ctx, cid, _intake_summary(cid, answers, redacted), rt.roots.project)
    if not check.confirmed:
        return check.exit

    path = os.path.join(folder, "intake.md")
    created: tuple[int, int] | None = None
    recorded = False
    try:
        with fsutil.locked(rt.roots.state_lock, rt.store.lock_timeout):
            view = _store_call(rt.store.load)
            if view.active != cid or view.change != baseline:
                raise CliError("state_changed", EXIT_CONFLICT)
            if _change_folder(rt, view.change) != folder:
                raise CliError("state_changed", EXIT_CONFLICT)
            if _authority(folder, "intake.md", MAX_INTAKE_MD) is not None:
                raise CliError("intake_exists", EXIT_REFUSED)
            try:
                created = intake.publish_new(folder, "intake.md", data)
            except FileExistsError:
                raise CliError("intake_exists", EXIT_REFUSED) from None
            except (OSError, ValueError, TypeError):
                raise CliError("change_folder", EXIT_ERROR) from None
            try:
                rt.ledger.append(
                    "intake",
                    change_id=cid,
                    response_sha256=hashlib.sha256(data).hexdigest(),
                    **TERMINAL_INTAKE_ROW,
                )
            except LedgerError:
                raise CliError("ledger_error", EXIT_ERROR) from None
            recorded = True
    except fsutil.LockTimeout:
        raise CliError("lock_timeout", EXIT_CONFLICT) from None
    except (fsutil.FsError, OSError):
        raise CliError("state_invalid", EXIT_ERROR) from None
    finally:
        if created is not None and not recorded:
            intake.unpublish(path, created)  # only the file this call created
    ctx.out(
        f"{cid}: intake.md written from answers typed at this terminal (source=terminal, "
        f"OS user {check.os_user}).",
        "  The TTY check is not proof of who typed them, and intake approves nothing.",
        f"  Next: {CLI} plan check {cid}",
    )
    return EXIT_OK


def _intake_ok(data: bytes | None) -> bool:
    if data is None:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [line.rstrip() for line in text.split("\n")]
    return all(any(line.startswith(label) for line in lines) for _, label in INTAKE_FIELDS)


def intake_md_source(data: bytes | None) -> str | None:
    """``fixture`` or ``terminal`` when intake.md has exactly one ``- Source:`` line and it
    is exactly the line that writer produces; otherwise None (hand-written, edited or
    unknown)."""
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    found = [line for line in text.split("\n") if line.startswith("- Source:")]
    if len(found) != 1:
        return None
    for source, line in INTAKE_SOURCE_LINES.items():
        if found[0] == line:
            return source
    return None


def _exact_row(row: Mapping[str, Any], cid: str, keys: frozenset[str],
               fixed: Mapping[str, str]) -> bool:  # fmt: skip
    if set(row) != keys:
        return False
    if type(row["v"]) is not int or row["v"] != LEDGER_VERSION:
        return False
    if row["event"] != "intake" or row["change_id"] != cid or type(row["ts"]) is not str:
        return False
    return all(type(row[key]) is str and row[key] == value for key, value in fixed.items())


def intake_row_source(row: Mapping[str, Any], cid: str) -> str | None:
    """``fixture`` or ``terminal`` for exactly a row ``cab intake`` writes for ``cid``.

    Strict per source: the fixture row has exactly the fixture keys and values; the
    terminal row has exactly the terminal keys and values plus a lowercase hex
    ``response_sha256``. Any other source (askuser, timeout, unknown), any missing, extra
    or mistyped field, or another change's row is None."""
    if not isinstance(row, Mapping):
        return None
    if _exact_row(row, cid, _FIXTURE_INTAKE_KEYS, FIXTURE_INTAKE_ROW):
        return "fixture"
    if _exact_row(row, cid, _TERMINAL_INTAKE_KEYS, TERMINAL_INTAKE_ROW):
        digest = row["response_sha256"]
        if type(digest) is str and _HEX64.fullmatch(digest):
            return "terminal"
    return None


def completed_intake(row: Mapping[str, Any], cid: str) -> bool:
    """True only for a row ``cab intake`` writes for ``cid`` (fixture or terminal).

    This checks the row alone; ``plan check`` also requires that intake.md names the same
    source and, for a terminal row, that its hash is the current intake.md."""
    return intake_row_source(row, cid) is not None


def _evidence(row: Mapping[str, Any], cid: str, source: str | None, digest: str) -> bool:
    found = intake_row_source(row, cid)
    if found is None or found != source:
        return False
    return found != "terminal" or row["response_sha256"] == digest


def _plan_or_error(rt: Runtime, cid: str) -> tuple[Any, tuple[str, ...], str]:
    return _store_call(rt.store.load_plan, cid)


def cmd_plan(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 2 or args[0] != "check":
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[1])
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    if doc["state"] not in ("draft", "planned", "reviewed", "approved"):
        raise CliError("state", EXIT_REFUSED)
    plan, targets, current = _plan_or_error(rt, cid)
    specs = list(plan.verify)
    if len(specs) != len(targets) or {s.target for s in specs} != set(targets):
        raise CliError("verify_missing", EXIT_USAGE)
    warnings: list[str] = []
    for spec in specs:
        checked = probes.validate(spec, plan, rt.policy, rt.roots)
        if isinstance(checked, probes.Unmeasured):
            if checked.reason in PROBE_PLAN_ERRORS:
                ctx.out(f"  {spec.target}: probe refused [{checked.reason}]")
                raise CliError("probe_invalid", EXIT_USAGE)
            warnings.append(
                f"  warning: {spec.target}: no supported read runner [{checked.reason}]; "
                "writes will be refused at snapshot."
            )
    intake_md = _authority(_change_folder(rt, doc), "intake.md", MAX_INTAKE_MD)
    if intake_md is None or not _intake_ok(intake_md):
        raise CliError("intake_missing", EXIT_USAGE)
    source = intake_md_source(intake_md)
    digest = hashlib.sha256(intake_md).hexdigest()
    rows, broken = ledger_rows(rt.roots)
    if broken:
        raise CliError("ledger_unreadable", EXIT_ERROR)
    completed = sum(1 for r in rows if _evidence(r, cid, source, digest))
    if not completed:
        raise CliError("interview_missing", EXIT_USAGE)
    not_counted = sum(
        1
        for r in rows
        if r.get("event") == "intake"
        and r.get("change_id") == cid
        and not _evidence(r, cid, source, digest)
    )
    tier = compute_tier(rt, plan)
    if tier not in TIER_RANK:
        raise CliError("tier_blocked", EXIT_USAGE)
    seq = _store_call(rt.store.mark_planned, cid, tier, current, AGENT_ACTOR)
    lines = [
        f"{cid}: planned, tier {tier} (seq {seq}).",
        f"  plan hash: {current}",
        f"  targets: {len(targets)}; verify probes: {len(specs)}",
    ]
    if source == "terminal":
        lines.append(
            f"  interview evidence: terminal {completed} (answers typed at a terminal that "
            "passed a TTY check; not proof of who typed them, and not an approval)"
        )
    else:
        lines.append(
            f"  interview evidence: fixture {completed} (a fixture file, not answers given by "
            "a person)"
        )
    if not_counted:
        lines.append(
            f"  not counted: {not_counted} other intake rows (questions asked, timed out, "
            "unknown source, or not matching this intake.md; answers are not measured)"
        )
    ctx.out(*lines, *warnings)
    if doc["state"] in ("reviewed", "approved"):
        ctx.out("  re-planning cleared the review, approval and snapshot.")
    return EXIT_OK


def cmd_tier(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    plan, _targets, _current = _plan_or_error(rt, cid)
    tier = compute_tier(rt, plan)
    ctx.out(f"{cid}: computed tier {tier}; recorded tier {doc['tier'] or 'none'}.")
    return EXIT_OK if tier in TIER_RANK else EXIT_USAGE


def cmd_snapshot(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    report = verifyrun.run_snapshot(
        rt.store, rt.roots, cid, runner=ctx.deps.runner, clock=ctx.deps.probe_clock,
        policy=rt.policy, actor=AGENT_ACTOR,
    )  # fmt: skip
    ctx.out(*verifyrun.snapshot_lines(report))
    return report.exit


def cmd_verify(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    report = verifyrun.run_verify(
        rt.store, rt.roots, cid, runner=ctx.deps.runner, clock=ctx.deps.probe_clock,
        policy=rt.policy,
    )  # fmt: skip
    ctx.out(*verifyrun.verify_lines(report))
    return report.exit


def _status_lines(rt: Runtime, doc: Mapping[str, Any]) -> list[str]:
    cid = doc["id"]
    lines = [
        f"{cid} ({doc['slug']})",
        f"  state: {doc['state']}  seq: {doc['seq']}  tier: {doc['tier'] or 'none'}",
        f"  plan hash: {doc['plan_hash'] or 'none'}",
        f"  canary: {doc['canary']}",
        f"  halted: {doc['halted']['code'] if doc['halted'] else 'no'}",
        f"  in flight: {'unit ' + str(doc['inflight']['unit']) if doc['inflight'] else 'none'}",
        f"  review: {'recorded' if doc['review_sha'] else 'none'}; "
        f"approval: {'recorded' if doc['approval_nonce'] else 'none'}; "
        f"snapshot: {'recorded' if doc['snapshot_sha'] else 'none'}",
    ]
    units = doc["units"]
    lines.append(f"  units: {len(units)}")
    for unit in units[:MAX_STATUS_UNITS]:
        targets = unit["targets"]
        shown = ", ".join(targets[:3]) + (f" (+{len(targets) - 3})" if len(targets) > 3 else "")
        lines.append(
            f"    unit {unit['n']}: {shown}; result {unit['outcome'] or 'pending'}; "
            f"verify {unit['verify'] or 'none'}"
        )
    if len(units) > MAX_STATUS_UNITS:
        lines.append(f"    ... and {len(units) - MAX_STATUS_UNITS} more")
    return lines


def cmd_status(ctx: _Ctx, args: list[str]) -> int:
    if len(args) > 1:
        raise CliError("usage", EXIT_USAGE)
    rt = ctx.runtime()
    view = _store_call(rt.store.load)
    if args:
        cid = _cid(args[0])
        if view.active != cid:
            raise CliError("not_active", EXIT_REFUSED)
    if view.change is None:
        ctx.out("no active change")
        return EXIT_OK
    doc = view.change
    lines = _status_lines(rt, doc)
    try:
        evidence = rt.store.verify_evidence(doc)
        ob = obligations.evaluate(view, evidence)
    except Exception:
        ctx.out(*lines, "  obligations: the state or its evidence is inconsistent [state_invalid]")
        return EXIT_ERROR
    msg = obligations.stop_message(ob)
    if msg.kind == "none":
        lines.append("  owed: nothing" + (" (closed)" if ob.state == "closed" else ""))
    else:
        lines.append(f"  owed: {msg.text}")
    rows, broken = ledger_rows(rt.roots)
    if broken:
        lines.append("  ledger: some lines are broken; a person must inspect it")
    committed = {rec.get("seq") for rec in evidence.values()}
    attempts = [
        r
        for r in rows
        if r.get("event") == "state"
        and r.get("action") == "verify"
        and r.get("change_id") == doc["id"]
        and r.get("seq") not in committed
    ]
    if attempts:
        lines.append(
            f"  verify rows in the ledger without current committed evidence: {len(attempts)}"
        )
    ctx.out(*lines)
    return EXIT_OK


def cmd_close(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    result = _store_call(rt.store.close, cid, AGENT_ACTOR, doc["seq"], doc["plan_hash"] or "")
    if result.state == "closed":
        ctx.out(f"{cid}: closed ({result.reason}); every unit PASS with committed evidence.")
        return EXIT_OK
    if result.state == "failed":
        ctx.out(f"{cid}: failed ({result.reason}). It is not closed and not verified.")
        return EXIT_FAILED
    ctx.out(
        f"{cid}: {result.state} ({result.reason}). Not verified and not closed; writes stay "
        f"refused. A person checks the UNMEASURED targets ({CLI} status {cid})."
    )
    return EXIT_UNMEASURED


# --------------------------------------------------------------------------- person only


def _review(rt: Runtime, doc: Mapping[str, Any]) -> dict[str, Any] | None:
    folder = _change_folder(rt, doc)
    data = _authority(folder, "review.json", 1 << 20)
    if data is None or doc["review_sha"] is None:
        return None
    if hashlib.sha256(data).hexdigest() != doc["review_sha"]:
        return None
    try:
        review = schema.parse_review(data)
    except Invalid:
        return None
    return review if review["change_id"] == doc["id"] else None


def _snapshot_taken(rt: Runtime, doc: Mapping[str, Any], plan_hash: str) -> str | None:
    folder = _change_folder(rt, doc)
    data = _authority(folder, "snapshot.json", schema.MAX_STATE_BYTES)
    if data is None or doc["snapshot_sha"] is None:
        return None
    if hashlib.sha256(data).hexdigest() != doc["snapshot_sha"]:
        return None
    try:
        snap = schema.parse_snapshot(data)
    except Invalid:
        return None
    if snap["plan_hash"] != plan_hash or not schema.snapshot_complete(snap):
        return None
    return snap["taken_at"]


def _conditions(review: Mapping[str, Any]) -> list[str]:
    return [f"{f['code']}: {f['detail']}" for f in review["findings"]]


def _human(ctx: _Ctx, cid: str, summary: Sequence[str], project: str) -> terminal.HumanCheck:
    """``terminal.require_human``; a refusal is reported like every CLI error, as
    ``cab: <fixed code>: <fixed text>`` (C0 prints only the text, so stderr=None there)."""
    check = terminal.require_human(
        cid,
        summary,
        stdin=ctx.stdin,
        stdout=ctx.stdout,
        stderr=None,
        osx=ctx.deps.terminal_os,
        git_lookup=lambda: ctx.deps.git_lookup(project),
    )
    if not check.confirmed:
        _err(ctx.stderr, check.code, terminal.MESSAGES.get(check.code, "refused."))
    return check


def cmd_approve(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    if doc["state"] != "reviewed" or doc["tier"] not in ("normal", "critical"):
        raise CliError("state", EXIT_REFUSED)
    _plan, targets, current = _plan_or_error(rt, cid)
    if current != doc["plan_hash"]:
        raise CliError("plan_changed", EXIT_CONFLICT)
    review = _review(rt, doc)
    if review is None:
        raise CliError("review_invalid", EXIT_REFUSED)
    if review["verdict"] == "PASS_WITH_CONDITIONS" and doc["ack_review_sha"] != doc["review_sha"]:
        raise CliError("ack_missing", EXIT_REFUSED)
    if review["verdict"] not in ("PASS", "PASS_WITH_CONDITIONS"):
        raise CliError("review_invalid", EXIT_REFUSED)
    taken = _snapshot_taken(rt, doc, current)
    if taken is None:
        raise CliError("snapshot_incomplete", EXIT_REFUSED)
    summary = terminal.approve_summary(
        change_id=cid,
        tier=doc["tier"],
        plan_hash=current,
        targets=list(targets),
        review_verdict=review["verdict"],
        conditions=_conditions(review),
        snapshot_taken_at=taken,
    )
    check = _human(ctx, cid, summary, rt.roots.project)
    if not check.confirmed:
        return check.exit
    record = _store_call(
        rt.store.approve, cid, doc["seq"], current, doc["review_sha"],
        {"os_user": check.os_user, "git_user": check.git_user},
    )  # fmt: skip
    ctx.out(f"{cid}: approved by {check.os_user}; expires at {record['expires_at']}.")
    return EXIT_OK


def cmd_ack(ctx: _Ctx, args: list[str]) -> int:
    if len(args) != 1:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    if doc["state"] != "reviewed":
        raise CliError("state", EXIT_REFUSED)
    review = _review(rt, doc)
    if review is None:
        raise CliError("review_invalid", EXIT_REFUSED)
    if review["verdict"] != "PASS_WITH_CONDITIONS":
        raise CliError("not_conditions", EXIT_REFUSED)
    summary = [f"Acknowledge the review conditions of {cid}"]
    summary += [f"  condition: {c}" for c in _conditions(review)]
    summary.append(f"Type {cid} and press Enter to acknowledge; anything else cancels.")
    check = _human(ctx, cid, summary, rt.roots.project)
    if not check.confirmed:
        return check.exit
    _store_call(rt.store.ack, cid, doc["review_sha"], check.os_user)
    ctx.out(f"{cid}: review conditions acknowledged by {check.os_user}.")
    return EXIT_OK


def cmd_resume(ctx: _Ctx, args: list[str]) -> int:
    if not args or len(args) > 2:
        raise CliError("usage", EXIT_USAGE)
    cid = _cid(args[0])
    flags = args[1:]
    if flags not in ([], ["--clear-inflight"]):
        raise CliError("usage", EXIT_USAGE)
    clear = bool(flags)
    rt = ctx.runtime()
    doc = _active_doc(rt, cid)
    if doc["state"] in ("closed", "failed"):
        raise CliError("state", EXIT_REFUSED)
    if doc["inflight"] is not None and not clear:
        raise CliError("inflight_needs_clear", EXIT_REFUSED)
    if doc["inflight"] is None and doc["halted"] is None and not clear:
        raise CliError("not_halted", EXIT_REFUSED)
    summary = terminal.resume_summary(doc, clear_inflight=clear)
    check = _human(ctx, cid, summary, rt.roots.project)
    if not check.confirmed:
        return check.exit
    seq = _store_call(rt.store.resume, cid, check.os_user, expect_seq=doc["seq"],
                      clear_inflight=clear)  # fmt: skip
    ctx.out(f"{cid}: resumed by {check.os_user} (seq {seq}). Verification debt is unchanged.")
    return EXIT_OK


# --------------------------------------------------------------------------- S6 slots


def _days(args: list[str]) -> tuple[int, list[str]]:
    days = selfaudit.DEFAULT_DAYS
    rest: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--days" and i + 1 < len(args):
            value = args[i + 1]
            if not value.isdigit() or not 1 <= int(value) <= selfaudit.MAX_DAYS:
                raise CliError("usage", EXIT_USAGE)
            days = int(value)
            i += 2
        else:
            rest.append(args[i])
            i += 1
    return days, rest


def cmd_audit(ctx: _Ctx, args: list[str]) -> int:
    days, rest = _days(args)
    as_json = "--json" in rest
    rest = [a for a in rest if a != "--json"]
    rt = ctx.runtime()
    project = rt.roots.project
    if rest == ["metrics"]:
        metrics = selfaudit.ledger_metrics(project, days=days)
        ctx.raw(json.dumps(metrics.to_dict(), ensure_ascii=True, sort_keys=True))
        return EXIT_OK if metrics.status == "ok" else EXIT_USAGE
    if rest:
        raise CliError("usage", EXIT_USAGE)
    config_dir = _user_settings_dir(ctx.env, ctx.home)
    if config_dir is None:
        raise CliError("home_invalid", EXIT_REFUSED)
    projects_root = os.path.realpath(os.path.join(config_dir, "projects"))
    evidence = {project: selfaudit.load_session_evidence(project, start_events=START_EVENTS)}
    report = selfaudit.audit_projects(
        projects_root, registry=[project], evidence=evidence, policy=rt.policy, days=days
    )
    if as_json:
        ctx.raw(json.dumps(report.to_dict(), ensure_ascii=True, sort_keys=True))
    else:
        ctx.out(*report.lines(), "registry: this project only (no project registry in v0.1)")
    if report.status == "error":
        return EXIT_USAGE
    if report.outside or report.hooks_missing:
        return EXIT_MISMATCH
    return EXIT_OK if report.clean else EXIT_USAGE


def _user_settings_dir(env: Mapping[str, str], home: str | None) -> str | None:
    """``CLAUDE_CONFIG_DIR`` relocates user configuration; otherwise ``~/.claude``."""
    relocated = env.get("CLAUDE_CONFIG_DIR") if isinstance(env, Mapping) else None
    if isinstance(relocated, str) and relocated:
        if os.path.isabs(relocated) and "\x00" not in relocated:
            return os.path.normpath(relocated)
        return None
    if not isinstance(home, str) or not os.path.isabs(home) or "\x00" in home:
        return None
    return os.path.join(home, ".claude")


def _user_layer(env: Mapping[str, str], home: str | None) -> doctor.SettingsLayer:
    """The user settings file of this process's environment, read-only and bounded.

    The person's terminal may not share Claude Code's environment (for example a
    different ``CLAUDE_CONFIG_DIR``); that difference is listed as unmeasured."""
    folder = _user_settings_dir(env, home)
    if folder is None:
        return doctor.SettingsLayer("user", None, "unreadable")
    try:
        data = paths.read_authority(folder, "settings.json", MAX_SETTINGS_BYTES)
    except UnsafePath:
        return doctor.SettingsLayer("user", None, "unsafe")
    except Exception:
        return doctor.SettingsLayer("user", None, "unreadable")
    if data is None:
        return doctor.SettingsLayer("user", None, "missing")
    try:
        return doctor.SettingsLayer("user", schema.strict_json(data, max_bytes=MAX_SETTINGS_BYTES))
    except Invalid:
        return doctor.SettingsLayer("user", None, "invalid")


def manifest_files(project: str) -> tuple[dict[str, str] | None, str | None]:
    """``(files, None)``: the generated-file hashes of the project's ``.cab/manifest.json``,
    or ``(None, problem)`` with a ``MANIFEST_PROBLEMS`` code. Never raises.

    The read is ``config_lock.read_project_file`` (each component opened relative to its
    folder with O_NOFOLLOW; regular, single-link, at most ``config_lock.MAX_FILE_BYTES``)
    and the parse is the pinned ``setup.manifest.load_manifest`` (strict schema 1), the
    same reader and loader the installed ConfigChange lock uses.
    """
    try:
        from ..setup import manifest as manifest_mod
    except Exception:
        return None, "manifest_reader_unavailable"
    try:
        raw = config_lock.read_project_file(project, config_lock.MANIFEST_REL)
    except Exception:  # UnsafeFile: link, hard link, non-regular, oversized, unreadable
        return None, "manifest_unsafe"
    if raw is None:
        return None, "manifest_absent"
    try:
        record = manifest_mod.load_manifest(raw)
        files = {str(k): str(v) for k, v in record.files.items()}
    except Exception:
        return None, "manifest_corrupt"
    if not files:
        return None, "manifest_empty"
    return files, None


def cmd_doctor(ctx: _Ctx, args: list[str]) -> int:
    if args not in ([], ["--json"]):
        raise CliError("usage", EXIT_USAGE)
    try:
        roots = ctx.deps.resolve(ctx.entry, ctx.env, ctx.home)
    except Exception:
        raise CliError("roots", EXIT_REFUSED) from None
    project_layer, local_layer = doctor.read_project_layers(roots.project)
    files, problem = manifest_files(roots.project)
    # Managed settings are deliberately not supplied: file absence cannot prove that no
    # managed policy exists, so doctor reports that layer as UNKNOWN. Version and mods are
    # not measured here either and stay UNKNOWN. The deny floor is the pinned lock's own.
    report = doctor.inspect_project(
        roots.project,
        [project_layer, local_layer, _user_layer(ctx.env, ctx.home)],
        manifest=files,
        required_deny=config_lock.FLOOR_DENY,
        fail_closed_events=DOCTOR_FAIL_CLOSED_EVENTS,
    )
    if problem is not None:
        status, text = MANIFEST_PROBLEMS[problem]
        issue = doctor.Issue("manifest", status, problem, text, None, config_lock.MANIFEST_REL)
        report = doctor.DoctorReport(report.issues + (issue,), report.notes)
    if args:
        payload = {"doctor": report.to_dict(), "unmeasured_sources": list(UNMEASURED_SETTINGS)}
        ctx.raw(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    else:
        ctx.out(
            *report.lines(),
            *(f"note: {n}" for n in report.notes),
            *(f"not measured: {s}" for s in UNMEASURED_SETTINGS),
            "These results describe the files read here, not the effective settings.",
        )
    if report.passed:
        return EXIT_OK
    return EXIT_MISMATCH if report.overall == doctor.FAIL else EXIT_USAGE


COMMANDS: dict[str, Callable[[_Ctx, list[str]], int]] = {
    "new": cmd_new,
    "intake": cmd_intake,
    "plan": cmd_plan,
    "tier": cmd_tier,
    "snapshot": cmd_snapshot,
    "verify": cmd_verify,
    "status": cmd_status,
    "close": cmd_close,
    "approve": cmd_approve,
    "ack": cmd_ack,
    "resume": cmd_resume,
    "audit": cmd_audit,
    "doctor": cmd_doctor,
}


# --------------------------------------------------------------------------- entry points


def main(
    argv: Sequence[str],
    *,
    entry: str,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    deps: Deps | None = None,
) -> int:
    """Run one installed-runtime command; returns the exit code. Never raises."""
    err = sys.stderr if stderr is None else stderr
    try:
        args = [a for a in argv]
        if not all(type(a) is str for a in args):
            _err(err, "usage")
            return EXIT_USAGE
        env = os.environ if env is None else env
        ctx = _Ctx(
            argv=args,
            env=env,
            home=env.get("HOME") if home is None else home,
            stdin=sys.stdin if stdin is None else stdin,
            stdout=sys.stdout if stdout is None else stdout,
            stderr=err,
            deps=deps or Deps(),
            entry=entry,
        )
        if not args:
            _err(err, "usage")
            return EXIT_USAGE
        if args[0] == "setup":
            _err(err, "setup_unavailable")
            return EXIT_REFUSED
        command = COMMANDS.get(args[0])
        if command is None:
            _err(err, "unknown_command")
            return EXIT_USAGE
        return command(ctx, args[1:])
    except CliError as exc:
        _err(err, exc.code)
        return exc.exit
    except KeyboardInterrupt:
        _err(err, "interrupted")
        return 130
    except BaseException:
        _err(err, "internal_error")
        return EXIT_ERROR


def source_main(argv: Sequence[str], *, source_root: str | None, entry: str, **kwargs: Any) -> int:
    """Source checkout / console entry. ``setup`` goes lazily to the S9 setup CLI when it
    exists; everything else is the installed-runtime ``main`` (a source checkout is not an
    installed project, so runtime commands exit 3 there)."""
    err = kwargs.get("stderr") or sys.stderr
    args = list(argv)
    if args and args[0] == "setup":
        try:
            module = importlib.import_module("cab_of_one.setup.cli")
        except ModuleNotFoundError as exc:
            if exc.name in ("cab_of_one.setup.cli", "cab_of_one.setup"):
                _err(err, "setup_unavailable")
                return EXIT_REFUSED
            _err(err, "setup_broken")
            return EXIT_ERROR
        except BaseException:
            _err(err, "setup_broken")
            return EXIT_ERROR
        setup_main = getattr(module, "main", None)
        if not callable(setup_main):
            _err(err, "setup_unavailable")
            return EXIT_REFUSED
        try:
            return int(setup_main(args[1:], source_root=source_root))
        except SystemExit as exc:
            return exc.code if type(exc.code) is int else EXIT_ERROR
        except BaseException:
            _err(err, "setup_broken")
            return EXIT_ERROR
    return main(args, entry=entry, **kwargs)


def console_main() -> None:
    """``[project.scripts] cab``: setup dispatch only; runtime commands need the pinned
    project entry and therefore exit 3 here."""
    raise SystemExit(source_main(sys.argv[1:], source_root=None, entry=sys.argv[0]))
