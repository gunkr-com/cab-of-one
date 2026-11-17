"""Generated-layout roots, protected paths and safe authority reads (S4).

The guard runs from a pinned copy at ``<project>/.claude/hooks/cab/guard.py``. The project
root is derived from that installed entry path, never from the event ``cwd``, and must agree
with ``$CLAUDE_PROJECT_DIR``. A source checkout is not an operations project.

Path comparisons are best effort against accidents, not a sandbox: every candidate is
checked twice (lexically against the event cwd, and with existing symlinks resolved), after
NFC normalisation and case folding, because macOS file systems usually ignore both.

Refusals raise ``RootsError`` / ``UnsafePath`` carrying a fixed, non-sensitive ``code``.
"""

from __future__ import annotations

import errno
import os
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from . import fsutil

__all__ = [
    "AUTHORITY_FILES",
    "ROLE_FILES",
    "Roots",
    "RootsError",
    "UnsafePath",
    "ensure_dir",
    "norm",
    "protected_match",
    "read_authority",
    "read_project_file",
    "resolve_cli_roots",
    "resolve_roots",
    "role_file_match",
    "same_dir",
    "state_file_safe",
]

ENTRY_DIRS = (".claude", "hooks", "cab")
STATE_HOME_PARTS = (".local", "state", "cab-of-one")
AUTHORITY_FILES = frozenset({"approval.json", "review.json", "verify.json", "snapshot.json"})
ROLE_FILES: dict[str, tuple[str, ...]] = {
    "runbook-author": ("change.toml", "plan.md"),
    "recorder": ("record.md",),
}
_PROTECTED_TOP = frozenset({".claude", "policy", "audit"})
_PROTECTED_CAB = frozenset({"state", "backups", "manifest.json"})
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class RootsError(Exception):
    """The generated layout could not be confirmed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class UnsafePath(Exception):
    """A path is a symlink, hardlinked, not regular, too large or outside its root."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def norm(path: str) -> str:
    """Comparison form: NFC, case folded, NFC again (case folding can denormalise)."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", path).casefold())


@dataclass(frozen=True)
class Roots:
    """Absolute, symlink-free project root and the external approval registry folder."""

    project: str
    state_home: str

    def __post_init__(self) -> None:
        for value in (self.project, self.state_home):
            if not isinstance(value, str) or not os.path.isabs(value) or "\x00" in value:
                raise RootsError("roots_not_absolute")
            if os.path.normpath(value) != value or value == "/":
                raise RootsError("roots_not_normal")

    def at(self, *parts: str) -> str:
        return os.path.join(self.project, *parts)

    @property
    def state_dir(self) -> str:
        return self.at(".cab", "state")

    @property
    def state_lock(self) -> str:
        return self.at(".cab", "state", "lock")

    @property
    def active_file(self) -> str:
        return self.at(".cab", "state", "active.json")

    @property
    def inflight_file(self) -> str:
        return self.at(".cab", "state", "inflight")

    @property
    def ledger_dir(self) -> str:
        return self.at("audit", "ledger")

    @property
    def ledger_lock(self) -> str:
        return self.at("audit", "ledger", ".lock")

    @property
    def approvals_file(self) -> str:
        return os.path.join(self.state_home, "approvals.jsonl")

    @property
    def approvals_lock(self) -> str:
        return os.path.join(self.state_home, "approvals.lock")


# --------------------------------------------------------------------------- roots


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _component_over_name_max(path: str) -> bool:
    """True when a component of absolute ``path`` exceeds its existing parent's NAME_MAX.

    Walks the existing parents from ``/`` and asks each one ``PC_NAME_MAX``. Only a
    positive limit that the component's bytes exceed proves the name impossible. A failed
    query, a missing parent or a path that is not absolute answers False (not proven).
    A component whose limit is unknown or unlimited (-1) proves nothing and is passed over.
    """
    if not os.path.isabs(path):
        return False
    parent = "/"
    for part in path.split("/"):
        if not part:
            continue
        try:
            limit = os.pathconf(parent, "PC_NAME_MAX")
        except (OSError, ValueError):
            return False
        if limit > 0 and len(os.fsencode(part)) > limit:
            return True
        parent = os.path.join(parent, part)
    return False


def _probe_lstat(path: str) -> os.stat_result | None:
    """``lstat`` for the hardlink probe; None when no file can exist at ``path``.

    That is: the entry is missing (ENOENT), a parent is not a directory (ENOTDIR), or
    ENAMETOOLONG is caused by a component longer than its parent file system's
    ``PC_NAME_MAX`` (a literal word, not a file name). Any other ENAMETOOLONG (such as an
    over-long whole path), permission and I/O errors re-raise, so the caller fails closed.
    ``pathconf`` is only consulted on ENAMETOOLONG, never on the normal path.
    """
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        if exc.errno == errno.ENAMETOOLONG and _component_over_name_max(path):
            return None
        raise


def _require_dir(path: str, code: str) -> None:
    st = _lstat(path)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RootsError(code)


def _require_file(path: str, code: str) -> None:
    st = _lstat(path)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RootsError(code)
    if st.st_nlink != 1:
        raise RootsError(code)


def _entry_project(entry: str) -> str:
    """The project of an installed entry at ``<project>/.claude/hooks/cab/<file>``."""
    if not isinstance(entry, str) or not entry or "\x00" in entry:
        raise RootsError("entry_invalid")
    real_entry = os.path.realpath(entry)
    folder = os.path.dirname(real_entry)
    names = []
    cursor = folder
    for _ in ENTRY_DIRS:
        names.append(os.path.basename(cursor))
        cursor = os.path.dirname(cursor)
    if tuple(reversed(names)) != ENTRY_DIRS:
        raise RootsError("entry_not_installed")
    project = cursor
    if project in ("", "/") or not os.path.isabs(project):
        raise RootsError("entry_not_installed")
    return project


def _check_declared(declared: object, project: str) -> None:
    if not isinstance(declared, str) or not os.path.isabs(declared) or "\x00" in declared:
        raise RootsError("project_dir_missing")
    if os.path.realpath(declared) != project:
        raise RootsError("project_dir_mismatch")


def _layout_roots(project: str, home: str | None) -> Roots:
    """Shared layout checks: real policy and state folders, a usable home."""
    _require_dir(os.path.join(project, "policy"), "policy_dir_unsafe")
    _require_file(os.path.join(project, "policy", "policy.toml"), "policy_file_unsafe")
    _require_file(os.path.join(project, "policy", "standard-changes.toml"), "catalog_file_unsafe")
    _require_dir(os.path.join(project, ".cab"), "state_dir_unsafe")
    _require_dir(os.path.join(project, ".cab", "state"), "state_dir_unsafe")

    if not isinstance(home, str) or not os.path.isabs(home) or "\x00" in home:
        raise RootsError("home_invalid")
    state_home = os.path.normpath(os.path.join(home, *STATE_HOME_PARTS))
    return Roots(project, state_home)


def resolve_roots(entry: str, env: Mapping[str, str], home: str | None) -> Roots:
    """Roots of an installed project, from the guard entry path. Raises ``RootsError``.

    ``entry`` must really live at ``<project>/.claude/hooks/cab/<file>``, the resolved
    ``CLAUDE_PROJECT_DIR`` must be that same directory, and ``policy/`` and ``.cab/state/``
    must be real directories (no symlink) holding the policy and catalogue files.
    ``home`` is the user's home directory; the registry lives under it.
    """
    project = _entry_project(entry)
    declared = env.get("CLAUDE_PROJECT_DIR") if isinstance(env, Mapping) else None
    _check_declared(declared, project)
    return _layout_roots(project, home)


def resolve_cli_roots(entry: str, env: Mapping[str, str], home: str | None) -> Roots:
    """Roots for the pinned ``cab`` CLI. As ``resolve_roots``, except that a person's own
    terminal usually has no ``CLAUDE_PROJECT_DIR``: it must match only when it is set.
    """
    project = _entry_project(entry)
    if not isinstance(env, Mapping):
        raise RootsError("project_dir_missing")
    if "CLAUDE_PROJECT_DIR" in env:
        _check_declared(env.get("CLAUDE_PROJECT_DIR"), project)
    return _layout_roots(project, home)


def same_dir(a: str | None, b: str) -> bool:
    """True when ``a`` and ``b`` resolve to the same directory (NFC/case folded)."""
    if not isinstance(a, str) or not os.path.isabs(a) or "\x00" in a:
        return False
    return norm(os.path.realpath(a)) == norm(os.path.realpath(b))


# --------------------------------------------------------------------------- protected paths


def _relative(candidate: str, base: str) -> str | None:
    c, b = norm(candidate), norm(base)
    if c == b:
        return ""
    if c.startswith(b.rstrip("/") + "/"):
        return c[len(b.rstrip("/")) + 1 :]
    return None


def _is_ancestor(candidate: str, base: str) -> bool:
    c, b = norm(candidate).rstrip("/") or "/", norm(base)
    return c == "/" or b.startswith(c + "/")


def _protected_rel(rel: str, ancestors: bool) -> bool:
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return ancestors  # the project itself
    if parts[0] in _PROTECTED_TOP:
        return True
    if parts[0] == ".cab":
        if len(parts) >= 2 and parts[1] in _PROTECTED_CAB:
            return True
        return ancestors and len(parts) == 1
    if parts[0] == "changes":
        if len(parts) == 3 and parts[2] in AUTHORITY_FILES:
            return True
        return ancestors and len(parts) <= 2
    return False


def protected_match(
    path: str, cwd: str | None, roots: Roots, *, ancestors: bool = False
) -> bool | None:
    """Is ``path`` (relative paths use ``cwd``) a protected location?

    Protected: ``.claude/**``, ``policy/**``, ``audit/**``, ``.cab/state/**``,
    ``.cab/manifest.json``, ``.cab/backups/**``, ``changes/*/{approval,review,verify,
    snapshot}.json`` and everything under the approval registry folder. With
    ``ancestors=True`` (removal, move, mode change) a directory that contains a protected
    location also counts. An existing file with more than one hard link is protected,
    since its other name is unknown. Returns None when a relative path has no cwd.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        return True
    if os.path.isabs(path):
        joined = path
    elif isinstance(cwd, str) and os.path.isabs(cwd):
        joined = os.path.join(cwd, path)
    else:
        return None
    lexical = os.path.normpath(joined)
    real = os.path.realpath(joined)
    homes = {roots.state_home, os.path.realpath(roots.state_home)}
    for candidate in {lexical, real}:
        rel = _relative(candidate, roots.project)
        if rel is not None and _protected_rel(rel, ancestors):
            return True
        for home in homes:
            if _relative(candidate, home) is not None:
                return True
            if ancestors and _is_ancestor(candidate, home):
                return True
    for candidate in (lexical, real):
        st = _probe_lstat(candidate)
        if st is not None and stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            return True
    return False


def state_file_safe(roots: Roots, scope: str) -> bool:
    """A simtenant state path (relative to the project) is a plain, single-link file.

    Every parent below the project is a real directory, the file and its ``.lock`` are
    missing or regular single-link files, neither is protected, and the path resolves to
    itself (no symlink anywhere). Moved unchanged from S4 ``Store._state_path_safe``.
    """
    if not isinstance(scope, str):
        return False
    parts = scope.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    cursor = roots.project
    for part in parts[:-1]:
        cursor = os.path.join(cursor, part)
        try:
            st = os.lstat(cursor)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return False
    final = os.path.join(roots.project, *parts)
    for path in (final, final + ".lock"):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            st = None
        if st is not None and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
            return False
        if protected_match(path, None, roots):
            return False
    return norm(os.path.realpath(final)) == norm(final)


def role_file_match(
    path: str, cwd: str | None, roots: Roots, change_dir: str, names: Sequence[str]
) -> bool:
    """True when ``path`` is exactly ``<project>/changes/<change_dir>/<one of names>``.

    Both the lexical and the resolved form must name it, parents must be real
    directories, and an existing file must be a regular single-link file.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    if not os.path.isabs(path):
        if not isinstance(cwd, str) or not os.path.isabs(cwd):
            return False
        path = os.path.join(cwd, path)
    allowed = {norm(os.path.join(roots.project, "changes", change_dir, n)) for n in names}
    lexical = os.path.normpath(path)
    if norm(lexical) not in allowed or norm(os.path.realpath(path)) not in allowed:
        return False
    for folder in (roots.at("changes"), roots.at("changes", change_dir)):
        st = _lstat(folder)
        if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return False
    st = _lstat(lexical)
    if st is None:
        return True
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1


# --------------------------------------------------------------------------- safe reads


def _rel_parts(rel: str) -> list[str]:
    if not isinstance(rel, str) or not rel or "\x00" in rel or rel.startswith("/"):
        raise UnsafePath("relative_invalid")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise UnsafePath("relative_invalid")
    return parts


def _walk_parents(root: str, parts: Sequence[str]) -> bool:
    """Every parent below ``root`` is a real directory. False when one is missing."""
    st = _lstat(root)
    if st is None:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("parent_unsafe")
    cursor = root
    for part in parts[:-1]:
        cursor = os.path.join(cursor, part)
        st = _lstat(cursor)
        if st is None:
            return False
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise UnsafePath("parent_unsafe")
    return True


def read_authority(root: str, rel: str, max_bytes: int) -> bytes | None:
    """Bytes of ``root/rel``, or None when it does not exist.

    Raises ``UnsafePath`` for a symlink anywhere below ``root``, a non-regular or
    hardlinked file, a file over ``max_bytes`` or one replaced while it was read.
    """
    parts = _rel_parts(rel)
    if not _walk_parents(root, parts):
        return None
    path = os.path.join(root, *parts)
    try:
        fd = os.open(path, _OPEN_READ)
    except FileNotFoundError:
        return None
    except OSError:
        if os.path.islink(path):
            raise UnsafePath("symlink") from None
        raise UnsafePath("unreadable") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePath("not_regular")
        if st.st_nlink != 1:
            raise UnsafePath("hardlink")
        if st.st_size > max_bytes:
            raise UnsafePath("too_large")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, max_bytes + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise UnsafePath("too_large")
    now = _lstat(path)
    if now is None or (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
        raise UnsafePath("changed")
    return data


def read_project_file(roots: Roots, cwd: str | None, path: str, max_bytes: int) -> bytes | None:
    """A script or input file inside the project (relative paths use ``cwd``), else None.

    Used for classification and scanning only: never raises, refuses symlinked final
    components, non-regular files, files over ``max_bytes`` and anything outside the
    project after resolving symlinks.
    """
    try:
        if not isinstance(path, str) or not path or "\x00" in path:
            return None
        if os.path.isabs(path):
            joined = path
        elif isinstance(cwd, str) and os.path.isabs(cwd):
            joined = os.path.join(cwd, path)
        else:
            return None
        lexical = os.path.normpath(joined)
        # Resolve the parent only: the final component must not be a symlink (O_NOFOLLOW).
        candidate = os.path.join(
            os.path.realpath(os.path.dirname(lexical)), os.path.basename(lexical)
        )
        if not _relative(candidate, roots.project):
            return None
        child = fsutil.safe_child(roots.project, os.path.relpath(candidate, roots.project))
        fd = os.open(child, _OPEN_READ)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
                return None
            chunks: list[bytes] = []
            total = 0
            while total <= max_bytes:
                chunk = os.read(fd, max_bytes + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
        if total > max_bytes:
            return None
        return b"".join(chunks)
    except (OSError, ValueError, fsutil.FsError):
        return None


def ensure_dir(base: str, *parts: str) -> str:
    """Create ``base/parts...`` (0o700) as needed. Refuses symlinks and non-directories."""
    st = _lstat(base)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("base_unsafe")
    cursor = base
    for part in parts:
        if not part or part in (".", "..") or "/" in part or "\x00" in part:
            raise UnsafePath("relative_invalid")
        cursor = os.path.join(cursor, part)
        st = _lstat(cursor)
        if st is None:
            try:
                os.mkdir(cursor, 0o700)
            except FileExistsError:
                pass
            st = _lstat(cursor)
        if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise UnsafePath("dir_unsafe")
    return cursor
