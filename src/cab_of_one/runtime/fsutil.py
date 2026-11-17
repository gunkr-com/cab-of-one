"""Filesystem primitives: atomic writes, advisory locks, one-holder reservations, safe paths.

Every function works only on the paths it is given. Nothing reads the home directory,
environment-based configuration, or any global state.

Failure contract: every refusal or contention is an exception. No function returns a
"did not happen" value that a caller could ignore by accident.

- ``atomic_write``  -> ``None`` or raises (``SymlinkRefused``, ``FsError``, ``OSError``)
- ``locked``        -> context manager; raises ``LockTimeout`` / ``SymlinkRefused``
- ``reserve``       -> ``None`` or raises ``ReservationHeld`` / ``SymlinkRefused``
- ``release``       -> ``None`` or raises ``ReservationMismatch`` / ``SymlinkRefused`` /
  ``LockTimeout``
- ``safe_child``    -> ``Path`` or raises ``PathEscape`` / ``FsError``

POSIX only (macOS, Linux, WSL): uses ``fcntl.flock`` and ``O_NOFOLLOW``.
"""

from __future__ import annotations

import contextlib
import fcntl
import hmac
import math
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

__all__ = [
    "FsError",
    "LockTimeout",
    "PathEscape",
    "ReservationError",
    "ReservationHeld",
    "ReservationMismatch",
    "SymlinkRefused",
    "atomic_write",
    "locked",
    "release",
    "reserve",
    "safe_child",
]

StrPath = str | os.PathLike[str]

MAX_TOKEN_BYTES = 1024
DEFAULT_RELEASE_TIMEOUT = 5.0

# O_NONBLOCK keeps open() from hanging on a FIFO planted at the path; it has no effect on
# regular files, and every opened descriptor is checked to be a regular file.
_OPEN_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class FsError(Exception):
    """Base class for refusals raised by this module."""


class SymlinkRefused(FsError):
    """The final path component is a symbolic link; this module never writes through one."""


class PathEscape(FsError):
    """A relative path is absolute, climbs with '..', or resolves outside its root."""


class LockTimeout(FsError):
    """The lock was not acquired before the monotonic deadline."""


class ReservationError(FsError):
    """Base class for reservation refusals."""


class ReservationHeld(ReservationError):
    """Another holder already owns the reservation."""


class ReservationMismatch(ReservationError):
    """Release refused: the path is not reserved, or it is reserved with another token."""


# --------------------------------------------------------------------------- helpers


def _path_str(path: StrPath) -> str:
    value = os.fspath(path)
    if not isinstance(value, str):
        raise TypeError("path must be str or os.PathLike[str]")
    if "\x00" in value:
        raise FsError("path contains NUL")
    return value


def _refuse_if_symlink(path: str) -> None:
    if os.path.islink(path):
        raise SymlinkRefused("refusing symlink at final path component")


def _open_nofollow(path: str, flags: int, mode: int = 0o600) -> int:
    try:
        return os.open(path, flags | _OPEN_FLAGS, mode)
    except OSError:
        # ELOOP (Linux, macOS) or EMLINK (BSD) when the final component is a symlink.
        if os.path.islink(path):
            raise SymlinkRefused("refusing symlink at final path component") from None
        raise


def _require_regular(fd: int) -> os.stat_result:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise FsError("not a regular file")
    return st


def _check_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, int | float):
        raise TypeError("timeout must be a number of seconds")
    value = float(timeout)
    if not math.isfinite(value) or value < 0:
        raise ValueError("timeout must be finite and >= 0")
    return value


def _flock_until(fd: int, timeout: float) -> None:
    """Take an exclusive flock on ``fd`` or raise LockTimeout (monotonic deadline)."""
    deadline = time.monotonic() + timeout
    delay = 0.005
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LockTimeout(f"lock not acquired within {timeout:g}s") from None
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 0.05)


def _fsync_dir(directory: str) -> None:
    """Best-effort durability of a rename/unlink. Some filesystems refuse directory fsync."""
    try:
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(dfd)
    finally:
        os.close(dfd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _read_upto(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        chunk = os.read(fd, limit - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _token_bytes(token: str) -> bytes:
    if not isinstance(token, str):
        raise TypeError("token must be str")
    if not token or any(ch in token for ch in "\x00\r\n"):
        raise ValueError("token must be non-empty and contain no NUL or line breaks")
    try:
        raw = token.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("token must be valid Unicode") from None
    if len(raw) > MAX_TOKEN_BYTES:
        raise ValueError(f"token longer than {MAX_TOKEN_BYTES} bytes")
    return raw


def _parent(path: str) -> str:
    return os.path.dirname(path) or "."


# --------------------------------------------------------------------------- atomic write


def atomic_write(path: StrPath, data: bytes, *, mode: int | None = None) -> None:
    """Replace ``path`` with ``data`` atomically.

    Writes a temporary file in the same directory, flushes and fsyncs it, then
    ``os.replace``-s it over the target. On any failure the temporary file is removed and
    an existing target is left byte-for-byte unchanged.

    Mode: an existing regular file keeps its permission bits. A new file is created 0o600
    unless ``mode`` is given. Refuses when the target is a symlink or not a regular file.
    Only the final component is checked; use ``safe_child`` for containment under a root.
    """
    if not isinstance(data, bytes | bytearray | memoryview):
        raise TypeError("data must be bytes")
    if mode is not None and (
        isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o7777
    ):
        raise ValueError("mode must be an int between 0 and 0o7777")
    target = _path_str(path)
    directory = _parent(target)
    name = os.path.basename(target)
    if not name:
        raise FsError("path has no file name")

    final_mode = mode
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        st = None
    if st is not None:
        if stat.S_ISLNK(st.st_mode):
            raise SymlinkRefused("refusing to write through a symlink")
        if not stat.S_ISREG(st.st_mode):
            raise FsError("target exists and is not a regular file")
        if final_mode is None:
            final_mode = stat.S_IMODE(st.st_mode)

    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
    replaced = False
    try:
        with open(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            if final_mode is not None:
                os.fchmod(handle.fileno(), final_mode)
            os.fsync(handle.fileno())
        # Re-check right before the rename: a symlink planted meanwhile is refused too.
        _refuse_if_symlink(target)
        os.replace(tmp, target)
        replaced = True
    finally:
        if not replaced:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
    _fsync_dir(directory)


# --------------------------------------------------------------------------- lock


@contextlib.contextmanager
def locked(path: StrPath, timeout: float) -> Iterator[None]:
    """Hold an exclusive ``fcntl.flock`` on ``path`` for the duration of the ``with`` block.

    The lock file is created (0o600) if missing and is never deleted, because deleting
    lock files reintroduces races. ``timeout`` is in seconds on a monotonic clock; 0 means
    a single attempt. Raises ``LockTimeout`` when the deadline passes and
    ``SymlinkRefused`` when the lock path is a symlink. The lock is released when the block
    exits, normally or by exception.

    flock is per open file description, so two ``locked`` calls on the same path exclude
    each other across processes and across threads of one process.
    """
    limit = _check_timeout(timeout)
    target = _path_str(path)
    _refuse_if_symlink(target)
    fd = _open_nofollow(target, os.O_RDWR | os.O_CREAT)
    try:
        _require_regular(fd)
        _flock_until(fd, limit)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- reservation


def reserve(path: StrPath, token: str) -> None:
    """Create the reservation file ``path`` holding ``token``.

    Uses ``O_CREAT | O_EXCL``, so among concurrent callers exactly one succeeds. The others
    raise ``ReservationHeld``. A symlink at ``path`` raises ``SymlinkRefused``. Stale
    reservations are never broken here; recovery is a separate, human-run step.
    """
    raw = _token_bytes(token)
    target = _path_str(path)
    _refuse_if_symlink(target)
    try:
        fd = _open_nofollow(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        if os.path.islink(target):
            raise SymlinkRefused("refusing symlink at final path component") from None
        raise ReservationHeld("already reserved") from None
    try:
        created = os.fstat(fd)
        try:
            # Hold the lock while the token is written so a concurrent release never reads
            # a half-written token as if it were complete.
            _flock_until(fd, DEFAULT_RELEASE_TIMEOUT)
            _write_all(fd, raw)
            os.fsync(fd)
        except BaseException:
            # Undo our own half-made reservation (same inode only), then re-raise.
            with contextlib.suppress(OSError):
                now = os.lstat(target)
                if (now.st_dev, now.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(target)
            raise
    finally:
        os.close(fd)
    _fsync_dir(_parent(target))


def release(path: StrPath, token: str, *, timeout: float = DEFAULT_RELEASE_TIMEOUT) -> None:
    """Remove the reservation at ``path`` if, and only if, it holds ``token``.

    Raises ``ReservationMismatch`` when nothing is reserved, when the token differs, or when
    the file was replaced while we waited. The read-compare-unlink runs under a flock on the
    reservation file itself, with an inode re-check, so two releases of the same token
    cannot both succeed and a stale release cannot remove a newer reservation.
    """
    raw = _token_bytes(token)
    limit = _check_timeout(timeout)
    target = _path_str(path)
    _refuse_if_symlink(target)
    try:
        fd = _open_nofollow(target, os.O_RDONLY)
    except FileNotFoundError:
        raise ReservationMismatch("not reserved") from None
    try:
        opened = _require_regular(fd)
        _flock_until(fd, limit)
        held = _read_upto(fd, MAX_TOKEN_BYTES + 1)
        try:
            current = os.lstat(target)
        except FileNotFoundError:
            raise ReservationMismatch("not reserved") from None
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ReservationMismatch("reservation changed while waiting")
        if not hmac.compare_digest(held, raw):
            raise ReservationMismatch("token does not match the reservation")
        os.unlink(target)
    finally:
        os.close(fd)
    _fsync_dir(_parent(target))


# --------------------------------------------------------------------------- safe paths


def safe_child(root: StrPath, relative: StrPath) -> Path:
    """Return ``root/relative`` after proving it stays inside ``root``.

    Refuses (``PathEscape``): absolute paths, empty paths, any '..' component, NUL bytes,
    and paths whose resolved location (following existing symlinks) is outside the real
    root or is the root itself. ``FsError`` if ``root`` is not an existing directory.

    The returned path is the real root joined with the normalised relative parts, without
    resolving symlinks inside the root, so ``atomic_write`` can still refuse a final
    symlink. This is a check, not a lock: a path changed after the check is not covered.
    """
    root_s = _path_str(root)
    rel_s = os.fspath(relative)
    if not isinstance(rel_s, str):
        raise TypeError("relative must be str or os.PathLike[str]")
    if "\x00" in rel_s:
        raise PathEscape("path contains NUL")
    rel = PurePosixPath(rel_s)
    if rel.is_absolute():
        raise PathEscape("absolute path refused")
    parts = rel.parts
    if not parts:
        raise PathEscape("empty path refused")
    if ".." in parts:
        raise PathEscape("'..' component refused")

    root_real = os.path.realpath(root_s)
    if not os.path.isdir(root_real):
        raise FsError("root is not an existing directory")
    candidate = os.path.join(root_real, *parts)
    resolved = os.path.realpath(candidate)
    if resolved == root_real or os.path.commonpath([root_real, resolved]) != root_real:
        raise PathEscape("path resolves outside the root")
    return Path(candidate)
