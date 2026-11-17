"""Generator-session marker ``<project>/.cab/setup/session.json`` (S10, DESIGN §10-3).

The marker is the authority input of the setup PreToolUse guard: a session whose ID is
bound here is constrained to read-only tools, ``.cab/setup/`` writes and pinned setup
commands. It therefore has one strict shape and one binding:

    {"kind": "cab-of-one-setup", "schema": 1, "session_id": "<token>"}

API (every refusal raises ``SessionError`` with a fixed code; no path or ID in messages)

- ``begin(project_root, session_id) -> Binding``
  Binds ``session_id``. Idempotent for the *same* ID. A marker bound to another ID is
  ``session_conflict`` and is left unchanged, so no caller can rebind (and thereby
  unregister) a guarded session. A malformed marker is ``marker_malformed``; nothing
  repairs or replaces it. Creation uses O_CREAT|O_EXCL under a lock, so two concurrent
  begins cannot both bind. The intended caller is the plugin UserPromptExpansion hook,
  with the ``session_id`` of the real event that a person started.
- ``load(project_root) -> Lookup``
  ``absent``, ``bound`` (with the ID) or ``malformed`` (with a code). Never raises for a
  bad marker: the guard decides how to fail closed.
- ``end(project_root, session_id)``
  Removes the marker only when it is bound to that same ID. It is for a person's own
  terminal (or a later apply step); the setup guard refuses it from a guarded session.

The project root must be an absolute, existing, non-symlink directory. ``.cab`` and
``.cab/setup`` must be real directories (they are created 0700 when missing); the marker
must be a regular single-link file. Paths are never followed through symlinks.
"""

from __future__ import annotations

import contextlib
import os
import stat
from dataclasses import dataclass

from ..runtime import fsutil
from ..runtime.schema import Invalid, canonical_bytes, is_token, strict_json

__all__ = [
    "KIND",
    "MARKER_NAME",
    "MARKER_REL",
    "Binding",
    "Lookup",
    "SessionError",
    "begin",
    "end",
    "load",
    "marker_bytes",
    "parse_marker",
]

KIND = "cab-of-one-setup"
SCHEMA_VERSION = 1
MARKER_NAME = "session.json"
LOCK_NAME = "session.lock"
MARKER_REL = ".cab/setup/session.json"
MAX_MARKER_BYTES = 4096
LOCK_TIMEOUT = 2.0
_KEYS = frozenset({"kind", "schema", "session_id"})
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_OPEN_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class SessionError(Exception):
    """A marker operation was refused. ``code`` is fixed and non-sensitive."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Binding:
    session_id: str
    created: bool  # False when the same ID was already bound


@dataclass(frozen=True)
class Lookup:
    status: str  # "absent", "bound" or "malformed"
    session_id: str | None = None
    code: str = ""


# --------------------------------------------------------------------------- paths


def _root(project_root: object) -> str:
    if not isinstance(project_root, str) or not project_root or "\x00" in project_root:
        raise SessionError("root_invalid")
    if not os.path.isabs(project_root):
        raise SessionError("root_not_absolute")
    try:
        st = os.lstat(project_root)
    except OSError:
        raise SessionError("root_missing") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SessionError("root_not_directory")
    real = os.path.realpath(project_root)
    if real == "/":
        raise SessionError("root_invalid")
    return real


def _setup_dir(root: str, *, create: bool) -> str | None:
    cursor = root
    for part in (".cab", "setup"):
        cursor = os.path.join(cursor, part)
        try:
            st = os.lstat(cursor)
        except FileNotFoundError:
            if not create:
                return None
            with contextlib.suppress(FileExistsError):
                os.mkdir(cursor, 0o700)
            st = os.lstat(cursor)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise SessionError("setup_dir_unsafe")
    return cursor


def _check_id(session_id: object) -> str:
    if not is_token(session_id):
        raise SessionError("session_id_invalid")
    return session_id  # type: ignore[return-value]


# --------------------------------------------------------------------------- marker


def marker_bytes(session_id: str) -> bytes:
    return canonical_bytes(
        {"kind": KIND, "schema": SCHEMA_VERSION, "session_id": _check_id(session_id)}
    )


def parse_marker(data: bytes) -> str:
    """The bound session ID, or ``SessionError`` (``marker_malformed``)."""
    try:
        doc = strict_json(data, max_bytes=MAX_MARKER_BYTES, max_depth=2)
    except Invalid:
        raise SessionError("marker_malformed") from None
    if set(doc) != _KEYS:
        raise SessionError("marker_malformed")
    if doc["kind"] != KIND or type(doc["schema"]) is not int or doc["schema"] != SCHEMA_VERSION:
        raise SessionError("marker_malformed")
    if not is_token(doc["session_id"]):
        raise SessionError("marker_malformed")
    return doc["session_id"]


def _read_marker(path: str) -> bytes | None:
    """Marker bytes, None when absent. Raises ``SessionError`` for an unsafe file."""
    try:
        fd = os.open(path, _OPEN_READ)
    except FileNotFoundError:
        return None
    except OSError:
        raise SessionError("marker_unsafe") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_MARKER_BYTES:
            raise SessionError("marker_unsafe")
        data = os.read(fd, MAX_MARKER_BYTES + 1)
    except OSError:
        raise SessionError("marker_unsafe") from None
    finally:
        os.close(fd)
    if len(data) > MAX_MARKER_BYTES:
        raise SessionError("marker_unsafe")
    return data


def load(project_root: str) -> Lookup:
    """Current binding. A bad root or folder is ``malformed`` too (fail closed upstream)."""
    try:
        root = _root(project_root)
        folder = _setup_dir(root, create=False)
        if folder is None:
            return Lookup("absent")
        data = _read_marker(os.path.join(folder, MARKER_NAME))
        if data is None:
            return Lookup("absent")
        return Lookup("bound", parse_marker(data))
    except SessionError as exc:
        return Lookup("malformed", None, exc.code)
    except Exception:
        return Lookup("malformed", None, "marker_unreadable")


def begin(project_root: str, session_id: str) -> Binding:
    """Bind ``session_id``; same ID is idempotent, another ID is ``session_conflict``."""
    sid = _check_id(session_id)
    root = _root(project_root)
    folder = _setup_dir(root, create=True)
    assert folder is not None
    path = os.path.join(folder, MARKER_NAME)
    data = marker_bytes(sid)
    try:
        with fsutil.locked(os.path.join(folder, LOCK_NAME), LOCK_TIMEOUT):
            existing = _read_marker(path)
            if existing is not None:
                if parse_marker(existing) != sid:
                    raise SessionError("session_conflict")
                return Binding(sid, False)
            try:
                fd = os.open(path, _OPEN_CREATE, 0o600)
            except FileExistsError:
                raise SessionError("session_conflict") from None
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(path)
                raise
            finally:
                os.close(fd)
    except fsutil.LockTimeout:
        raise SessionError("lock_timeout") from None
    except fsutil.SymlinkRefused:
        raise SessionError("marker_unsafe") from None
    except SessionError:
        raise
    except OSError:
        raise SessionError("write_failed") from None
    return Binding(sid, True)


def end(project_root: str, session_id: str) -> None:
    """Remove the marker if it is bound to ``session_id``; otherwise refuse unchanged."""
    sid = _check_id(session_id)
    root = _root(project_root)
    folder = _setup_dir(root, create=False)
    if folder is None:
        raise SessionError("not_bound")
    path = os.path.join(folder, MARKER_NAME)
    try:
        with fsutil.locked(os.path.join(folder, LOCK_NAME), LOCK_TIMEOUT):
            existing = _read_marker(path)
            if existing is None:
                raise SessionError("not_bound")
            if parse_marker(existing) != sid:
                raise SessionError("session_conflict")
            os.unlink(path)
    except fsutil.LockTimeout:
        raise SessionError("lock_timeout") from None
    except fsutil.SymlinkRefused:
        raise SessionError("marker_unsafe") from None
    except SessionError:
        raise
    except OSError:
        raise SessionError("remove_failed") from None
