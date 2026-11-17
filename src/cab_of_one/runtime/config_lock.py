"""ConfigChange lock for a generated project (S10, DESIGN §10-1, §10-6 floor).

Runs from the pinned copy ``<project>/.claude/hooks/cab/config_lock.py``. Claude Code
calls it before a changed settings or skill file is applied to the running session.
``decision: block`` keeps that change out of *this session*; it does not undo the file on
disk, and nothing here claims a rollback. ``cab doctor`` and the next session's checks
see the file as it is.

Decisions (``evaluate``)
- ``policy_settings``: managed changes cannot be blocked (documented). The hook does not
  pretend to: it allows, and logs ``policy_settings_unblockable``.
- ``project_settings`` (``<project>/.claude/settings.json``) and ``skills`` (a file under
  ``<project>/.claude/skills/``): allowed only when the ``verifier`` returns exactly
  ``True`` for that project-relative path. A ``False``, a non-bool or an exception blocks.
  ``evaluate(verifier=None)`` blocks every such change (``manifest_verifier_pending``).
- ``local_settings`` (``.claude/settings.local.json``) and ``user_settings``
  (``<home>/.claude/settings.json``) are a person's files and are never written here.
  The change is blocked only when the new file sets ``disableAllHooks: true`` (which
  would switch the guard off) or cannot be read safely; otherwise it is allowed.
- An unknown ``source``, a missing ``file_path`` or a path outside the expected location
  blocks.

Default verifier (``manifest_verifier`` / ``manifest_check``)
``main`` uses it unless a caller injects another one. It needs only the standard library
and the pinned ``cab_of_one.setup.manifest`` (render pins ``setup/__init__.py`` and
``setup/manifest.py`` next to the runtime), so an installed project needs neither the
plugin nor a source checkout. It reads ``.cab/manifest.json`` and the changed file
relative to the project, one component at a time without following any link; each must
be a regular, single-link file of at most 1 MiB. Then:

- ``.claude/settings.json`` must hold the **floor itself** (``floor_gap``: every
  ``FLOOR_DENY`` rule, every ``FLOOR_HOOKS`` entry with its matcher and, where required,
  ``onFailure: block``, and no ``disableAllHooks``), checked directly against the file.
  The manifest records only what the merge *added*; a floor item a person already had is
  not recorded, so a recorded contribution alone never proves the floor. After the floor,
  ``manifest.config_file_matches(..., required_deny=FLOOR_DENY)`` must also hold.
- a skill file must be one the manifest owns, with its recorded SHA-256.

``FLOOR_DENY`` and ``FLOOR_HOOKS`` are defined here and imported by ``setup.render``, so
the floor the lock checks is, by construction, the floor the renderer writes into that
same pinned copy.

``main(entry, ...)`` resolves the project from the installed entry path
(``paths.resolve_roots``), reads one strict event, decides, writes one JSON line and
logs one ledger row best effort (a ledger failure never turns a block into an allow).
Any error blocks with exit 2.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from . import paths
from .hookevents import EventError, read_event
from .schema import Invalid, is_token, strict_json

__all__ = [
    "BLOCKABLE_SOURCES",
    "EVENT",
    "FLOOR_DENY",
    "FLOOR_HOOKS",
    "HOOK_COMMAND_PREFIX",
    "HOOK_DIR",
    "MANIFEST_REL",
    "MAX_FILE_BYTES",
    "SETTINGS_REL",
    "UNBLOCKABLE_SOURCES",
    "UnsafeFile",
    "Verdict",
    "Verifier",
    "evaluate",
    "floor_gap",
    "hook_command",
    "main",
    "manifest_check",
    "manifest_verifier",
    "read_project_file",
]

EVENT = "ConfigChange"
BLOCKABLE_SOURCES = frozenset({"project_settings", "local_settings", "skills", "user_settings"})
UNBLOCKABLE_SOURCES = frozenset({"policy_settings"})
MAX_SETTINGS_BYTES = 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024  # manifest and changed file (= manifest.MAX_JSON_BYTES)
PREFIX = "cab-of-one"
SETTINGS_REL = ".claude/settings.json"
MANIFEST_REL = ".cab/manifest.json"
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

#: ``verifier(project_root, relative_path) -> bool``: True only when the file matches
#: the protected manifest and floor. Default: ``manifest_verifier``.
Verifier = Callable[[str, str], bool]

# --------------------------------------------------------------------------- floor

HOOK_DIR = ".claude/hooks/cab/"
HOOK_COMMAND_PREFIX = 'python3 "$CLAUDE_PROJECT_DIR"/' + HOOK_DIR

# Protected locations (runtime paths.protected_match) and human-only commands
# (runtime shellscan). Edit rules cover every built-in file-editing tool.
_PROTECTED_RULE_PATHS = (
    "./.claude/**",
    "./policy/**",
    "./audit/**",
    "./.cab/state/**",
    "./.cab/manifest.json",
    "./.cab/backups/**",
    "./changes/*/approval.json",
    "./changes/*/review.json",
    "./changes/*/verify.json",
    "./changes/*/snapshot.json",
    "~/.local/state/cab-of-one/**",
)
FLOOR_DENY: tuple[str, ...] = tuple(
    f"{tool}({path})" for path in _PROTECTED_RULE_PATHS for tool in ("Edit", "Write")
) + (
    "Bash(cab approve:*)",
    "Bash(cab ack:*)",
    "Bash(cab resume:*)",
    "Bash(cab setup apply:*)",
    "Bash(cab setup uninstall:*)",
)

#: (event, matcher or None, entry file, argument, timeout seconds, fail closed)
FLOOR_HOOKS: tuple[tuple[str, str | None, str, str, int, bool], ...] = (
    ("PreToolUse", "*", "guard.py", "", 10, True),
    ("PostToolUse", "*", "audit.py", "post", 10, False),
    ("PostToolUseFailure", "*", "audit.py", "fail", 10, False),
    ("SubagentStart", None, "audit.py", "substart", 10, False),
    ("SubagentStop", None, "audit.py", "substop", 10, False),
    ("SessionStart", None, "audit.py", "start", 30, False),
    ("SessionEnd", None, "audit.py", "end", 10, False),
    ("Stop", None, "closeout.py", "", 10, True),
    ("ConfigChange", None, "config_lock.py", "", 10, True),
)


def hook_command(entry: str, arg: str) -> str:
    """The exact settings command of a pinned hook entry."""
    return HOOK_COMMAND_PREFIX + entry + (" " + arg if arg else "")


def _hook_present(groups: object, matcher: str | None, command: str, closed: bool) -> bool:
    if not isinstance(groups, list):
        return False
    for group in groups:
        if not isinstance(group, dict) or group.get("matcher") != matcher:
            continue
        hooks = group.get("hooks")
        if not isinstance(hooks, list):
            continue
        for hook in hooks:
            if (
                isinstance(hook, dict)
                and hook.get("type") == "command"
                and hook.get("command") == command
                and (not closed or hook.get("onFailure") == "block")
            ):
                return True
    return False


def floor_gap(doc: object) -> tuple[str, str] | None:
    """None when a parsed ``.claude/settings.json`` holds the whole settings floor, else
    ``(code, detail)``: ``floor_settings`` with ``document``, ``disableAllHooks``,
    ``permissions.deny`` or ``hooks``, or ``floor_hook`` with the missing event.

    Checked against the file itself, never against what a manifest recorded. Never raises.
    """
    if not isinstance(doc, dict):
        return ("floor_settings", "document")
    if "disableAllHooks" in doc and doc["disableAllHooks"] is not False:
        return ("floor_settings", "disableAllHooks")
    permissions = doc.get("permissions")
    deny = permissions.get("deny") if isinstance(permissions, dict) else None
    if not isinstance(deny, list) or not set(FLOOR_DENY) <= {d for d in deny if type(d) is str}:
        return ("floor_settings", "permissions.deny")
    hooks = doc.get("hooks")
    if not isinstance(hooks, dict):
        return ("floor_settings", "hooks")
    for event, matcher, entry, arg, _timeout, closed in FLOOR_HOOKS:
        if not _hook_present(hooks.get(event), matcher, hook_command(entry, arg), closed):
            return ("floor_hook", event)
    return None


# --------------------------------------------------------------------------- messages

_MESSAGES = {
    "manifest_verifier_pending": "no manifest check is installed, so the change is held.",
    "manifest_mismatch": "the file no longer matches .cab/manifest.json.",
    "manifest_missing": ".cab/manifest.json is missing, so the change is held.",
    "manifest_unsafe": ".cab/manifest.json is not a plain file inside the project.",
    "manifest_invalid": ".cab/manifest.json could not be read.",
    "target_unsafe": "the changed file is a link, a hard link, special or too large.",
    "floor_missing": "the settings would drop a required cab-of-one deny rule or hook.",
    "verifier_unavailable": "the manifest check is not installed with the hooks.",
    "verifier_error": "the manifest check failed.",
    "hooks_disabled": "disableAllHooks would switch the cab-of-one guard off.",
    "settings_unreadable": "the changed settings file could not be read safely.",
    "source_unknown": "the change source is unknown.",
    "path_missing": "the change did not name its file.",
    "path_unexpected": "the changed file is not where this source should be.",
    "event_invalid": "the change event could not be read.",
    "roots": "the project layout could not be confirmed.",
    "internal": "the lock failed.",
}


@dataclass(frozen=True)
class Verdict:
    block: bool
    code: str
    source: str | None


# --------------------------------------------------------------------------- safe reads


class UnsafeFile(Exception):
    """A path component is a link or not a directory, or the file is not a regular,
    single-link file within the size limit."""


def _rel_parts(rel: object) -> list[str]:
    if not isinstance(rel, str) or not rel or "\x00" in rel or rel.startswith("/"):
        raise UnsafeFile("rel")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise UnsafeFile("rel")
    return parts


def read_project_file(project: str, rel: str, *, limit: int = MAX_FILE_BYTES) -> bytes | None:
    """Bytes of ``<project>/<rel>``, or None when it (or a parent folder) does not exist.

    Every component is opened relative to the previous folder with ``O_NOFOLLOW``, so no
    link is followed anywhere below ``project`` and a folder swapped for a link after a
    check cannot redirect the read. Raises ``UnsafeFile`` for a link, a non-directory
    parent, a non-regular or hard-linked file, or more than ``limit`` bytes.
    """
    parts = _rel_parts(rel)
    if not isinstance(project, str) or not os.path.isabs(project) or "\x00" in project:
        raise UnsafeFile("project")
    try:
        folder = os.open(project, _OPEN_DIR)
    except OSError:
        raise UnsafeFile("project") from None
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, _OPEN_DIR, dir_fd=folder)
            except FileNotFoundError:
                return None
            except OSError:
                raise UnsafeFile("parent") from None
            os.close(folder)
            folder = child
        try:
            fd = os.open(parts[-1], _OPEN_READ, dir_fd=folder)
        except FileNotFoundError:
            return None
        except OSError:
            raise UnsafeFile("file") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
                raise UnsafeFile("file")
            chunks: list[bytes] = []
            total = 0
            while total <= limit:
                chunk = os.read(fd, limit + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > limit:
                raise UnsafeFile("size")
            return b"".join(chunks)
        except OSError:
            raise UnsafeFile("file") from None
        finally:
            os.close(fd)
    finally:
        os.close(folder)


def _skill_rel(rel: str) -> bool:
    parts = rel.split("/")
    return (
        len(parts) >= 3
        and parts[0] == ".claude"
        and parts[1] == "skills"
        and not any(p in ("", ".", "..") for p in parts)
    )


# --------------------------------------------------------------------------- default verifier


def _manifest_check(project: str, rel: str) -> str:
    if not isinstance(rel, str) or (rel != SETTINGS_REL and not _skill_rel(rel)):
        return "path_unexpected"
    try:
        from ..setup import manifest as manifest_mod
    except Exception:
        return "verifier_unavailable"
    try:
        raw = read_project_file(project, MANIFEST_REL)
    except UnsafeFile:
        return "manifest_unsafe"
    if raw is None:
        return "manifest_missing"
    try:
        record = manifest_mod.load_manifest(raw)
    except Exception:
        return "manifest_invalid"
    try:
        data = read_project_file(project, rel)
    except UnsafeFile:
        return "target_unsafe"
    if rel == SETTINGS_REL:
        if data is None:
            return "floor_missing"
        try:
            doc = manifest_mod.loads_strict(data)
        except Exception:
            return "settings_unreadable"
        if floor_gap(doc) is not None:
            return "floor_missing"
    matched = manifest_mod.config_file_matches(record, rel, data, required_deny=FLOOR_DENY)
    return "verified" if matched is True else "manifest_mismatch"


def manifest_check(project: str, rel: str) -> str:
    """``verified`` or the block code for one changed project file. Never raises."""
    try:
        return _manifest_check(project, rel)
    except Exception:
        return "verifier_error"


def manifest_verifier(project: str, rel: str) -> bool:
    """The default ``Verifier``: True only when ``manifest_check`` says ``verified``."""
    return manifest_check(project, rel) == "verified"


# --------------------------------------------------------------------------- helpers


def _rel(path: object, bases: set[str]) -> str | None:
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        return None
    lexical = os.path.normpath(path)
    for base in bases:
        b = base.rstrip("/")
        if lexical.startswith(b + "/"):
            return lexical[len(b) + 1 :]
    return None


def _read_settings(path: str) -> dict[str, Any] | None:
    """Parsed settings, ``{}`` when the file is gone, None when unsafe or invalid."""
    try:
        fd = os.open(path, _OPEN_READ)
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SETTINGS_BYTES:
            return None
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_SETTINGS_BYTES:
            chunk = os.read(fd, MAX_SETTINGS_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        return strict_json(b"".join(chunks), max_bytes=MAX_SETTINGS_BYTES)
    except Invalid:
        return None


def _personal(path: str) -> Verdict | None:
    doc = _read_settings(path)
    if doc is None:
        return Verdict(True, "settings_unreadable", None)
    if doc.get("disableAllHooks") is True:
        return Verdict(True, "hooks_disabled", None)
    return None


def _verified(verifier: Verifier | None, project: str, rel: str) -> str | None:
    """None when verified, else the block code."""
    if verifier is None:
        return "manifest_verifier_pending"
    if verifier is manifest_verifier:  # same decision, with its specific block code
        code = manifest_check(project, rel)
        return None if code == "verified" else code
    try:
        result = verifier(project, rel)
    except Exception:
        return "verifier_error"
    if result is True:
        return None
    return "manifest_mismatch" if result is False else "verifier_error"


# --------------------------------------------------------------------------- decision


def evaluate(
    data: Mapping[str, Any], *, project: str, home: str | None, verifier: Verifier | None
) -> Verdict:
    source = data.get("source")
    if type(source) is not str:
        return Verdict(True, "source_unknown", None)
    if source in UNBLOCKABLE_SOURCES:
        return Verdict(False, "policy_settings_unblockable", source)
    if source not in BLOCKABLE_SOURCES:
        return Verdict(True, "source_unknown", None)
    file_path = data.get("file_path")
    if file_path is None:
        return Verdict(True, "path_missing", source)

    if source == "user_settings":
        if not isinstance(home, str) or not os.path.isabs(home):
            return Verdict(True, "path_unexpected", source)
        expected = os.path.normpath(os.path.join(home, ".claude", "settings.json"))
        homes = {expected, os.path.join(os.path.realpath(home), ".claude", "settings.json")}
        if not isinstance(file_path, str) or os.path.normpath(file_path) not in homes:
            return Verdict(True, "path_unexpected", source)
        found = _personal(file_path)
        return Verdict(True, found.code, source) if found else Verdict(False, "allowed", source)

    bases = {os.path.normpath(project), os.path.realpath(project)}
    rel = _rel(file_path, bases)
    if rel is None:
        return Verdict(True, "path_unexpected", source)

    if source == "local_settings":
        if rel != ".claude/settings.local.json":
            return Verdict(True, "path_unexpected", source)
        found = _personal(os.path.join(os.path.realpath(project), rel))
        return Verdict(True, found.code, source) if found else Verdict(False, "allowed", source)

    if source == "project_settings":
        if rel != SETTINGS_REL:
            return Verdict(True, "path_unexpected", source)
    elif not _skill_rel(rel):  # skills
        return Verdict(True, "path_unexpected", source)
    code = _verified(verifier, os.path.realpath(project), rel)
    if code is not None:
        return Verdict(True, code, source)
    return Verdict(False, "verified", source)


# --------------------------------------------------------------------------- I/O


def _line(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def _block_text(code: str) -> str:
    return f"{PREFIX}: settings change blocked: {_MESSAGES.get(code, _MESSAGES['internal'])}"


def _log(roots: Any, data: Mapping[str, Any], verdict: Verdict, ledger_factory: Any) -> None:
    try:
        factory = ledger_factory
        if factory is None:
            from .ledger import Ledger

            factory = Ledger
        sid = data.get("session_id")
        factory(roots).append(
            "config_change",
            session_id=sid if is_token(sid) else None,
            decision="block" if verdict.block else "allow",
            reason_code=verdict.code,
            source=verdict.source,
        )
    except Exception:
        pass  # best effort; the decision stands


def main(
    entry: str,
    *,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    verifier: Verifier | None = None,
    ledger_factory: Any = None,
    exit_process: bool = True,
) -> int:
    """Hook entry. ``verifier=None`` means the default ``manifest_verifier``; a caller
    (tests, a future integration) may inject another ``Verifier``."""
    environ = os.environ if env is None else env
    user_home = home if home is not None else environ.get("HOME")
    check = manifest_verifier if verifier is None else verifier
    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr
    code, out, err = 2, _line({"decision": "block", "reason": _block_text("internal")}), ""
    try:
        try:
            data = read_event(sys.stdin if stdin is None else stdin, {EVENT})
        except EventError:
            data = None
        if data is None:
            err = _block_text("event_invalid")
            code, out = 2, _line({"decision": "block", "reason": err})
        else:
            try:
                roots = paths.resolve_roots(entry, environ, user_home)
            except (paths.RootsError, Exception):
                roots = None
            if roots is None:
                verdict = (
                    Verdict(False, "policy_settings_unblockable", "policy_settings")
                    if data.get("source") in UNBLOCKABLE_SOURCES
                    else Verdict(True, "roots", None)
                )
            else:
                verdict = evaluate(data, project=roots.project, home=user_home, verifier=check)
                _log(roots, data, verdict, ledger_factory)
            if verdict.block:
                err = _block_text(verdict.code)
                code, out = 0, _line({"decision": "block", "reason": err})
            else:
                code, out = 0, "{}\n"
    except BaseException:
        err = _block_text("internal")
        code, out = 2, _line({"decision": "block", "reason": err})
    try:
        out_stream.write(out)
        out_stream.flush()
    except BaseException:
        code = 2
    if err:
        try:
            err_stream.write(err + "\n")
        except BaseException:
            pass
    if exit_process:
        raise SystemExit(code)
    return code
