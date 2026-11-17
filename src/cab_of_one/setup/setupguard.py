"""Generator-session hooks shipped by the plugin (S10, DESIGN §10-3). Not a runtime gate.

Two events, one entry (``hooks/setup_guard.py`` calls ``main``):

``UserPromptExpansion`` (``expansion_decision``)
- Only the generator skill is considered: ``command_name`` exactly one of
  ``COMMAND_NAMES`` (bare and plugin-namespaced spellings, with and without a leading
  slash; which one Claude Code sends is not documented and awaits the G6 measurement).
  Other commands are not touched. A missing or non-string ``command_name`` blocks,
  because it cannot be shown not to be this skill.
- ``permission_mode`` must be ``default`` or ``acceptEdits``. ``bypassPermissions``,
  ``auto``, ``dontAsk``, anything unknown and a missing mode block. ``command_source``
  is never consulted.
- On allow, the event's own ``session_id`` is bound in ``.cab/setup/session.json`` with
  ``session.begin`` (same ID idempotent, another ID refused unchanged). A binding that
  cannot be made blocks the expansion: the generator never runs unguarded.

``PreToolUse`` (``pretool_decision``)
- No marker: no objection (unrelated, unregistered sessions are not constrained).
- Malformed or unsafe marker, unknown project dir: only Read, Grep, Glob and
  AskUserQuestion pass; everything else is denied with the fix-it message.
- Marker bound to another session: no objection. A call whose ``session_id`` is missing
  or malformed cannot prove that, so it is treated like the bound session.
- Bound session: Read/Grep/Glob/AskUserQuestion pass. Write/Edit pass only for a plain
  path strictly inside ``.cab/setup/`` that is not a control entry (``session.json``,
  its lock and temp files, ``discovery.json``, ``staged``) and has no symlink or
  hardlink on the way. Bash passes only for literal read-only commands
  (``READ_ONLY_PROGRAMS``, ``command -v``, a git subset) and the pinned
  ``<plugin>/scripts/cab setup discover|render`` without ``--out``. No redirection,
  substitution, group, background job, assignment, wrapper, alias or nested shell.
  ``begin``, ``end``, ``apply`` and ``uninstall`` are refused, so the marker cannot be
  rebound or removed from inside the session. Writes and Bash also require
  ``permission_mode`` ``default`` or ``acceptEdits``. Every other tool is denied.

Every error blocks. Messages never contain inputs, paths or commands.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ..runtime import shellscan
from ..runtime.hookevents import EventError, read_event
from ..runtime.hookio import Decision
from ..runtime.paths import norm
from ..runtime.schema import is_token
from . import session

__all__ = [
    "ALLOWED_MODES",
    "COMMAND_NAMES",
    "READ_ONLY_PROGRAMS",
    "READ_TOOLS",
    "SETUP_SUBCOMMANDS",
    "Blocked",
    "bash_allowed",
    "expansion_decision",
    "main",
    "pretool_decision",
    "setup_write_allowed",
]

PLUGIN = "cab-of-one"
COMMAND_NAMES = frozenset(
    {"cab-of-one", "cab-of-one:cab-of-one", "/cab-of-one", "/cab-of-one:cab-of-one"}
)
ALLOWED_MODES = frozenset({"default", "acceptEdits"})
READ_TOOLS = frozenset({"Read", "Grep", "Glob", "AskUserQuestion"})
WRITE_TOOLS = frozenset({"Write", "Edit"})
SETUP_SUBCOMMANDS = frozenset({"discover", "render"})
MAX_COMMAND_CHARS = 16 * 1024
EVENTS = frozenset({"PreToolUse", "UserPromptExpansion"})

READ_ONLY_PROGRAMS = frozenset(
    {"ls", "cat", "head", "tail", "wc", "grep", "rg", "pwd", "stat", "file", "tree",
     "basename", "dirname", "realpath", "echo", "which"}
)  # fmt: skip
_FORBIDDEN_OPTIONS: Mapping[str, tuple[str, ...]] = {
    "rg": ("--pre",),
    "file": ("-C", "--compile"),
    "tree": ("-o", "--output", "-R"),
}
_GIT_SUBCOMMANDS = frozenset({"status", "rev-parse", "ls-files", "log", "diff"})
_GIT_FORBIDDEN = ("--output", "--ext-diff", "--textconv", "--exec", "--upload-pack", "-O")
_SETUP_FORBIDDEN_ARGS = frozenset({"--out", "--output", "apply", "uninstall", "begin", "end"})
_CONTROL_ENTRIES = frozenset({"session.json", "session.lock", "discovery.json", "staged"})
_CONTROL_PREFIXES = (".session.", ".discovery.", "staged.")
_NAME = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_TENANT_WORD = re.compile(r"(?i)^(?:connect-\w+|invoke-(?:restmethod|webrequest)|login)$")
_TENANT_PROGRAMS = frozenset(
    {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "ftp", "telnet", "rsync",
     "http", "https", "socat", "openssl", "az", "pwsh", "powershell", "gam", "aws", "gcloud",
     "kubectl", "terraform", "m365", "mgc"}
)  # fmt: skip
_SAFE_SEPS = frozenset({"", "\n", "&&", "||", ";", "|"})

MSG_MODE = (
    "Start /cab-of-one in Manual or Accept edits mode, so every write to .claude/ asks you first."
)
MSG_COMMAND_UNKNOWN = "the expanded command could not be identified; setup hooks block it."
MSG_SESSION_ID = "this session has no usable ID, so the setup session cannot be guarded."
MSG_PROJECT = "the project folder is unknown, so the setup session cannot be guarded."
MSG_CONFLICT = (
    "another setup session is registered in .cab/setup/session.json. Finish it, or remove "
    "that file yourself in a terminal, then start /cab-of-one again."
)
MSG_MARKER_BAD = (
    ".cab/setup/session.json is unreadable or unsafe. A person must inspect or remove it in "
    "a terminal; until then only Read, Grep, Glob and questions are allowed."
)
MSG_BIND_FAILED = "the setup session could not be registered; /cab-of-one did not start."
MSG_TENANT = "No tenant access during setup."
MSG_APPLY = (
    "apply, uninstall and session changes are for a person's own terminal: "
    'python3 "<plugin path>/scripts/cab" setup apply.'
)
MSG_BASH = (
    "during setup Bash runs only read-only commands and the plugin's cab setup discover or "
    "render, without redirection, substitution or wrappers."
)
MSG_WRITE = "during setup Write and Edit are allowed only for plain files inside .cab/setup/."
MSG_TOOL = "this tool is not available during setup (Read, Grep, Glob, questions only)."
MSG_SETUP_MODE = "setup writes need Manual or Accept edits mode. " + MSG_MODE
MSG_INTERNAL = "the setup guard failed; blocking."


@dataclass(frozen=True)
class Blocked:
    """UserPromptExpansion result: ``blocked`` with a reason, or not blocked."""

    blocked: bool
    reason: str = ""


# --------------------------------------------------------------------------- expansion


def _project(project_dir: object) -> str | None:
    if not isinstance(project_dir, str) or not os.path.isabs(project_dir):
        return None
    if "\x00" in project_dir:
        return None
    return project_dir


def expansion_decision(
    data: Mapping[str, Any],
    *,
    project_dir: str | None,
    bind: Callable[[str, str], object] = session.begin,
) -> Blocked:
    name = data.get("command_name")
    if not isinstance(name, str):
        return Blocked(True, MSG_COMMAND_UNKNOWN)
    if name not in COMMAND_NAMES:
        return Blocked(False)
    mode = data.get("permission_mode")
    if not isinstance(mode, str) or mode not in ALLOWED_MODES:
        return Blocked(True, MSG_MODE)
    sid = data.get("session_id")
    if not is_token(sid):
        return Blocked(True, MSG_SESSION_ID)
    project = _project(project_dir)
    if project is None:
        return Blocked(True, MSG_PROJECT)
    try:
        bind(project, sid)
    except session.SessionError as exc:
        if exc.code == "session_conflict":
            return Blocked(True, MSG_CONFLICT)
        if exc.code in ("marker_malformed", "marker_unsafe"):
            return Blocked(True, MSG_MARKER_BAD)
        return Blocked(True, MSG_BIND_FAILED)
    except Exception:
        return Blocked(True, MSG_BIND_FAILED)
    return Blocked(False)


# --------------------------------------------------------------------------- writes


def _rel_under(path: str, bases: set[str]) -> list[str] | None:
    lexical = os.path.normpath(path)
    target = norm(lexical)
    for base in bases:
        b = norm(base).rstrip("/")
        if target.startswith(b + "/"):
            return [p for p in lexical[len(base.rstrip("/")) + 1 :].split("/") if p]
    return None


def setup_write_allowed(path: object, project_dir: str) -> bool:
    """True only for a plain, non-control file path strictly inside ``.cab/setup/``."""
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        return False
    project = _project(project_dir)
    if project is None:
        return False
    real_project = os.path.realpath(project)
    bases = {os.path.normpath(project), real_project}
    rel = _rel_under(path, bases)
    # Exact folder names: a case or Unicode alias of .cab/setup is refused, not mapped.
    if rel is None or len(rel) < 3 or rel[0] != ".cab" or rel[1] != "setup":
        return False
    inner = rel[2:]
    if any(p in (".", "..") for p in inner):
        return False
    first = norm(inner[0])
    if first in _CONTROL_ENTRIES or first.startswith(_CONTROL_PREFIXES):
        return False
    cursor = real_project
    parts = [".cab", "setup", *inner]
    for i, part in enumerate(parts):
        cursor = os.path.join(cursor, part)
        try:
            st = os.lstat(cursor)
        except FileNotFoundError:
            return True  # Write creates the rest; nothing below can be a symlink yet
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            return False
        last = i == len(parts) - 1
        if last:
            return stat.S_ISREG(st.st_mode) and st.st_nlink == 1
        if not stat.S_ISDIR(st.st_mode):
            return False
    return False


# --------------------------------------------------------------------------- bash


def _pinned(word: str, plugin_root: str | None) -> bool:
    if not plugin_root or not os.path.isabs(plugin_root):
        return False
    pinned = os.path.normpath(os.path.join(plugin_root, "scripts", "cab"))
    candidates = {pinned, os.path.realpath(pinned)}
    # The literal word must already be normal: no "//", "/./" or ".." spellings.
    return os.path.isabs(word) and word == os.path.normpath(word) and word in candidates


def _setup_args(args: list[str]) -> bool:
    if len(args) < 2 or args[0] != "setup" or args[1] not in SETUP_SUBCOMMANDS:
        return False
    for arg in args[2:]:
        key = arg.split("=", 1)[0].lower()
        if key in _SETUP_FORBIDDEN_ARGS:
            return False
    return True


def _simple_ok(words: list[str], plugin_root: str | None) -> bool:
    program = words[0]
    if "/" in program:
        return _pinned(program, plugin_root) and _setup_args(words[1:])
    if program == "python3":
        return len(words) >= 2 and _pinned(words[1], plugin_root) and _setup_args(words[2:])
    if program == "command":
        return len(words) >= 3 and words[1] == "-v" and all(_NAME.fullmatch(w) for w in words[2:])
    if program == "git":
        if len(words) < 2 or words[1] not in _GIT_SUBCOMMANDS:
            return False
        return not any(w.startswith(_GIT_FORBIDDEN) for w in words[2:])
    if program in READ_ONLY_PROGRAMS:
        forbidden = _FORBIDDEN_OPTIONS.get(program, ())
        return not any(w.startswith(forbidden) for w in words[1:]) if forbidden else True
    return False


def _tenant_like(words: list[str]) -> bool:
    for word in words:
        base = os.path.basename(word).lower()
        if base in _TENANT_PROGRAMS or _TENANT_WORD.fullmatch(base):
            return True
    return False


def bash_allowed(command: object, plugin_root: str | None) -> tuple[bool, str]:
    """``(True, "")`` or ``(False, reason)`` for a Bash command in a guarded session."""
    if not isinstance(command, str) or not command.strip() or len(command) > MAX_COMMAND_CHARS:
        return False, MSG_BASH
    if shellscan.approval_text(command):
        return False, MSG_APPLY
    try:
        cmds = shellscan.parse(command)
    except shellscan.ParseError:
        return False, MSG_BASH
    if not cmds:
        return False, MSG_BASH
    texts: list[list[str]] = []
    ok = True
    for cmd in cmds:
        words = [w.text for w in cmd.words]
        texts.append(words)
        if (
            cmd.redirs
            or cmd.procsubs
            or cmd.group is not None
            or cmd.sep not in _SAFE_SEPS
            or not cmd.words
            or any((not w.literal) or w.subs for w in cmd.words)
            or _ASSIGN.match(words[0])
            or not _simple_ok(words, plugin_root)
        ):
            ok = False
    if ok:
        return True, ""
    # Denied: pick the most helpful fixed message. Words only choose the message.
    for words in texts:
        lowered = {w.lower() for w in words}
        if "setup" in lowered and lowered & {"begin", "end", "apply", "uninstall"}:
            return False, MSG_APPLY
    if any(_tenant_like(words) for words in texts):
        return False, MSG_TENANT
    return False, MSG_BASH


# --------------------------------------------------------------------------- pretool


def pretool_decision(
    data: Mapping[str, Any],
    *,
    project_dir: str | None,
    plugin_root: str | None,
    lookup: Callable[[str], session.Lookup] = session.load,
) -> Decision:
    tool = data.get("tool_name")
    project = _project(project_dir)
    found = lookup(project) if project is not None else session.Lookup("malformed", None, "project")
    if found.status == "absent":
        return Decision.allow()
    if tool in READ_TOOLS:
        return Decision.allow()
    if found.status != "bound" or project is None:
        return Decision.deny(MSG_MARKER_BAD)
    sid = data.get("session_id")
    if is_token(sid) and sid != found.session_id:
        return Decision.allow()  # an unrelated session in the same project
    mode = data.get("permission_mode")
    if tool in WRITE_TOOLS or tool == "Bash":
        if not isinstance(mode, str) or mode not in ALLOWED_MODES:
            return Decision.deny(MSG_SETUP_MODE)
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return Decision.deny(MSG_TOOL)
    if tool in WRITE_TOOLS:
        if setup_write_allowed(tool_input.get("file_path"), project):
            return Decision.allow()
        return Decision.deny(MSG_WRITE)
    if tool == "Bash":
        ok, reason = bash_allowed(tool_input.get("command"), plugin_root)
        return Decision.allow() if ok else Decision.deny(reason)
    return Decision.deny(MSG_TOOL)


# --------------------------------------------------------------------------- I/O


def _line(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def _pretool_out(decision: Decision) -> tuple[int, str, str]:
    if decision.allowed:
        return 0, "{}\n", ""
    message = f"{PLUGIN}: {decision.reason}"
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }
    return 2, _line(payload), message


def _expansion_out(result: Blocked) -> tuple[int, str, str]:
    if not result.blocked:
        return 0, "{}\n", ""
    message = f"{PLUGIN}: {result.reason}"
    return 0, _line({"decision": "block", "reason": message}), message


def _failure_out() -> tuple[int, str, str]:
    message = f"{PLUGIN}: {MSG_INTERNAL}"
    payload = {
        "decision": "block",
        "reason": message,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        },
    }
    return 2, _line(payload), message


def evaluate(stdin: Any, env: Mapping[str, str]) -> tuple[int, str, str]:
    """Exit code, stdout text and stderr text for one event. Never raises."""
    try:
        data = read_event(stdin, EVENTS)
    except EventError:
        return _failure_out()
    except BaseException:
        return _failure_out()
    try:
        project_dir = env.get("CLAUDE_PROJECT_DIR")
        if data["hook_event_name"] == "UserPromptExpansion":
            return _expansion_out(expansion_decision(data, project_dir=project_dir))
        plugin_root = env.get("CLAUDE_" + "PLUGIN_ROOT")
        return _pretool_out(
            pretool_decision(data, project_dir=project_dir, plugin_root=plugin_root)
        )
    except BaseException:
        return _failure_out()


def main(*, stdin: Any = None, stdout: Any = None, stderr: Any = None,
         env: Mapping[str, str] | None = None, exit_process: bool = True) -> int:  # fmt: skip
    code, out, err = evaluate(
        sys.stdin if stdin is None else stdin, os.environ if env is None else env
    )
    try:
        (sys.stdout if stdout is None else stdout).write(out)
        (sys.stdout if stdout is None else stdout).flush()
    except BaseException:
        code = 2
    if err:
        try:
            (sys.stderr if stderr is None else stderr).write(err + "\n")
        except BaseException:
            pass
    if exit_process:
        raise SystemExit(code)
    return code
