"""Plan hash: one SHA-256 over the three files that define a change.

Framing, in this fixed order: ``change.toml``, ``plan.md``, ``targets.csv``. For each file
the digest is fed ``name NUL decimal-length NUL raw-bytes``. No timestamps, UUIDs, paths,
or file metadata enter the digest, so the same bytes always give the same hash and any
changed byte gives a different one. Other files in the folder are ignored.

Refusals raise ``PlanHashError``: a missing file, a directory or other non-regular file in
place of one, a symlink (even one pointing inside the folder), a symlinked change folder,
or a file whose size changed while it was being read.
"""

from __future__ import annotations

import hashlib
import os
import stat

__all__ = ["PLAN_FILES", "PlanHashError", "plan_hash"]

PLAN_FILES: tuple[str, ...] = ("change.toml", "plan.md", "targets.csv")

_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CHUNK = 1 << 20


class PlanHashError(Exception):
    """The change folder cannot be hashed safely."""


def plan_hash(change_dir: str | os.PathLike[str]) -> str:
    """Return the lowercase hex SHA-256 plan hash of ``change_dir``."""
    base = os.fspath(change_dir)
    if not isinstance(base, str):
        raise TypeError("change_dir must be str or os.PathLike[str]")
    try:
        st = os.lstat(base)
    except FileNotFoundError:
        raise PlanHashError("change folder not found") from None
    if stat.S_ISLNK(st.st_mode):
        raise PlanHashError("change folder is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise PlanHashError("change folder is not a directory")

    digest = hashlib.sha256()
    for name in PLAN_FILES:
        data = _read_plan_file(os.path.join(base, name), name)
        digest.update(name.encode("ascii"))
        digest.update(b"\x00")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(data)
    return digest.hexdigest()


def _read_plan_file(path: str, name: str) -> bytes:
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except FileNotFoundError:
        raise PlanHashError(f"{name} is missing") from None
    except OSError:
        if os.path.islink(path):
            raise PlanHashError(f"{name} is a symlink") from None
        raise PlanHashError(f"{name} could not be opened") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PlanHashError(f"{name} is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) != st.st_size:
        raise PlanHashError(f"{name} changed while it was being read")
    return data
