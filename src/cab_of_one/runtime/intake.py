"""Terminal intake for ``cab intake CHG-NNNN`` (DESIGN section 3-2 terminal fallback).

``cab intake CHG-NNNN`` (no ``--from-file``) asks the six intake questions at the
person's own terminal. This module holds the parts that do not need the Store:

1. ``preflight`` -- stdin and stdout must both be genuine TTYs (the stream says so *and*
   ``os.isatty`` on its descriptor agrees), ``uid == euid``, and the OS user name must
   resolve from the password database. Any failure is exit 3 **before** anything is
   printed or read. Same rules as ``terminal.require_human``, which runs again for the
   final confirmation.
2. ``collect`` -- exactly one bounded line per question, in ``INTAKE_FIELDS`` order. No
   retries: an empty, oversized, non-UTF-8 or control-character answer, or end of input
   (Ctrl-D), cancels the whole intake. Ctrl-C raises ``KeyboardInterrupt`` to the caller.
   Nothing is written by this module while asking; typed text is never echoed back in
   an error.
3. ``publish_new`` -- write ``intake.md`` only if no file of that name exists, never
   replacing one: a temporary file is fsynced and then hard-linked to the final name
   (``link`` fails when anything, a symlink included, already has that name).
   ``unpublish`` removes only the exact inode this process created.

The TTY check prevents mistakes. It is not proof that a person typed the answers: a
pseudo-terminal wrapper can satisfy it (DESIGN section 3-6). The guard refuses agent
calls of interactive intake, including wrappers, as far as it can recognise them.
Terminal intake records interview answers only; it never creates an approval.
"""

from __future__ import annotations

import contextlib
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import terminal
from .ledger import redact

__all__ = [
    "MAX_ANSWER_BYTES",
    "MESSAGES",
    "QUESTIONS",
    "Collected",
    "Preflight",
    "check_answer",
    "collect",
    "preflight",
    "publish_new",
    "redact_answers",
    "unpublish",
]

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3

#: Upper bound for one typed answer, in UTF-8 bytes, excluding the final LF.
MAX_ANSWER_BYTES = 2048

#: One question per ``cli.INTAKE_FIELDS`` key (tests check the two stay in step).
QUESTIONS: dict[str, str] = {
    "purpose": "Purpose: what should this change achieve?",
    "in_scope": "In scope: which objects or systems does it change, and how are they listed?",
    "out_of_scope": "Out of scope: what must it not touch (lookalikes excluded)?",
    "timing": "Timing: when may it run, and is there a deadline or freeze?",
    "known_dependents": "Known dependents: what relies on these objects?",
    "success_criteria": "Success criteria: what will you check to call it done?",
}

# C0 (tab included), DEL, C1, line/paragraph separators and bidirectional controls.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,256}")

MESSAGES: dict[str, str] = {
    "not_a_tty": terminal.MESSAGES["not_a_tty"],
    "uid_mismatch": terminal.MESSAGES["uid_mismatch"],
    "os_user_unknown": terminal.MESSAGES["os_user_unknown"],
    "output_error": "refused: the questions could not be shown. Nothing was written.",
    "intake_cancelled": "cancelled: the input ended before every question was answered. "
    "Nothing was written.",
    "answer_empty": "cancelled: an answer was empty. Nothing was written.",
    "answer_too_long": f"cancelled: an answer was longer than {MAX_ANSWER_BYTES} bytes. "
    "Nothing was written.",
    "answer_invalid": "cancelled: an answer was not valid UTF-8 text or held control "
    "characters. Nothing was written.",
    "input_error": "cancelled: an answer could not be read. Nothing was written.",
}


@dataclass(frozen=True)
class Preflight:
    ok: bool
    code: str
    exit: int
    os_user: str | None = None


@dataclass(frozen=True)
class Collected:
    ok: bool
    code: str
    exit: int
    answers: dict[str, str] | None = None


# --------------------------------------------------------------------------- tty


def _genuine_tty(stream: Any, osx: terminal.TerminalOS) -> bool:
    try:
        if stream.isatty() is not True:
            return False
        fd = stream.fileno()
        return type(fd) is int and fd >= 0 and osx.isatty(fd) is True
    except Exception:
        return False


def preflight(stdin: Any, stdout: Any, osx: terminal.TerminalOS | None = None) -> Preflight:
    """TTY, uid and OS user checks. Prints and reads nothing."""
    osx = osx or terminal.TerminalOS()
    if not (_genuine_tty(stdin, osx) and _genuine_tty(stdout, osx)):
        return Preflight(False, "not_a_tty", EXIT_REFUSED)
    try:
        uid, euid = osx.getuid(), osx.geteuid()
    except Exception:
        return Preflight(False, "uid_mismatch", EXIT_REFUSED)
    if type(uid) is not int or type(euid) is not int or uid != euid:
        return Preflight(False, "uid_mismatch", EXIT_REFUSED)
    try:
        user = osx.username(uid)
    except Exception:
        user = None
    if type(user) is not str or not _NAME.fullmatch(user):
        return Preflight(False, "os_user_unknown", EXIT_REFUSED)
    return Preflight(True, "ok", EXIT_OK, user)


# --------------------------------------------------------------------------- answers


def check_answer(raw: Any, limit: int = MAX_ANSWER_BYTES) -> tuple[str | None, str]:
    """``(answer, "ok")`` or ``(None, code)`` for one line read with ``readline(limit+1)``.

    Exactly one trailing LF is required and stripped; nothing else is trimmed except
    surrounding spaces. ``b""`` (or ``""``) is end of input."""
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeEncodeError:
            return None, "answer_invalid"
    if not isinstance(raw, bytes | bytearray):
        return None, "input_error"
    raw = bytes(raw)
    if raw == b"":
        return None, "intake_cancelled"
    if not raw.endswith(b"\n"):
        # No LF: either the line was longer than the limit, or the input ended mid-line.
        return None, ("answer_too_long" if len(raw) > limit else "intake_cancelled")
    body = raw[:-1]
    if len(body) > limit:
        return None, "answer_too_long"
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "answer_invalid"
    if _CONTROL.search(text):
        return None, "answer_invalid"
    text = text.strip(" ")
    if not text:
        return None, "answer_empty"
    return text, "ok"


def collect(
    keys: Sequence[str],
    *,
    change_id: str,
    stdin: Any,
    stdout: Any,
    limit: int = MAX_ANSWER_BYTES,
) -> Collected:
    """Ask one question per key, in order. Stops at the first unusable answer."""
    total = len(keys)
    try:
        stdout.write(
            terminal.sanitize(
                f"Terminal intake for {change_id}: {total} questions, one line each. An "
                "empty answer, Ctrl-D or Ctrl-C cancels and writes nothing."
            )
            + "\n"
        )
        stdout.write(
            "Answers are saved in the change folder (intake.md), which the agent reads and "
            "git may keep. Do not type secrets.\n"
        )
        stdout.flush()
    except Exception:
        return Collected(False, "output_error", EXIT_REFUSED)
    # Read the binary layer when there is one (as terminal.require_human does), so the
    # byte limit and the single LF rule apply to what was actually typed.
    source = getattr(stdin, "buffer", stdin)
    answers: dict[str, str] = {}
    for index, key in enumerate(keys, 1):
        try:
            stdout.write(terminal.sanitize(f"[{index}/{total}] {QUESTIONS[key]}") + "\n> ")
            stdout.flush()
        except Exception:
            return Collected(False, "output_error", EXIT_REFUSED)
        try:
            raw = source.readline(limit + 1)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return Collected(False, "input_error", EXIT_MISMATCH)
        text, code = check_answer(raw, limit)
        if text is None:
            return Collected(False, code, EXIT_MISMATCH)
        answers[key] = text
    return Collected(True, "ok", EXIT_OK, answers)


def redact_answers(
    answers: Mapping[str, str], extra: Sequence[Any] = ()
) -> tuple[dict[str, str], int]:
    """Answers with secret-looking text replaced (the ledger redactor) and how many
    answers changed. The person confirms, and intake.md stores, the redacted text."""
    out: dict[str, str] = {}
    changed = 0
    for key, value in answers.items():
        shown = redact(value, extra)
        if shown != value:
            changed += 1
        out[key] = shown
    return out, changed


# --------------------------------------------------------------------------- files


def publish_new(folder: str, name: str, data: bytes) -> tuple[int, int]:
    """Create ``folder/name`` with ``data`` without ever replacing an existing entry.

    Returns the ``(st_dev, st_ino)`` of the created file. Raises ``FileExistsError`` when
    the name is taken (a file, a directory or a symlink) and ``OSError`` for anything
    else, including file systems without hard links; in every failure nothing is left
    at ``folder/name`` by this call."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not name or "/" in name or name in (".", ".."):
        raise ValueError("bad file name")
    target = os.path.join(folder, name)
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=folder)
    try:
        with open(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            st = os.fstat(handle.fileno())
        os.link(tmp, target)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    with contextlib.suppress(OSError):
        dfd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    return st.st_dev, st.st_ino


def unpublish(path: str, ident: tuple[int, int]) -> bool:
    """Remove ``path`` only if it is still the regular file ``ident`` names."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if (st.st_dev, st.st_ino) != tuple(ident) or not os.path.isfile(path):
        return False
    try:
        os.unlink(path)
    except OSError:
        return False
    return True
