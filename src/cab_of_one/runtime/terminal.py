"""Terminal confirmation for person-only commands (``approve``, ``ack``, ``resume``), S5 C0.

``require_human(change_id, summary, ...)`` does, in this order:

1. require that stdin and stdout are both genuine TTYs (the stream says so *and*
   ``os.isatty`` on its file descriptor agrees) and that ``uid == euid``; resolve the OS
   user name from the password database (never from environment variables). Any
   failure returns exit 3 **before** anything is shown or read;
2. show the redacted summary (control characters replaced) and a prompt;
3. read at most ``MAX_CONFIRM_CHARS`` characters plus one LF. Only that trailing LF is
   stripped; the rest must equal the change ID exactly. Anything else is exit 1;
4. only after a match, optionally look up the git user name.

There is no termios manipulation, no echo control and no retry. The check prevents
mistakes; it is not proof that a person is present (a pseudo-terminal wrapper can satisfy
it, DESIGN section 3-6). Nothing here writes a file.

``git_user_name`` runs ``git config --get user.name`` as a fixed argv with no shell, a
2 s deadline and a 256-byte cap enforced while reading; any failure is ``""``.

``resume_summary`` carries the warning required by the Codex S5 acceptance item 4:
before an in-flight reservation is cleared, the person must first make sure the old call
has stopped; if that is uncertain the unit stays as may-have-written debt.
"""

from __future__ import annotations

import os
import re
import select
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .ledger import redact

__all__ = [
    "EXIT_MISMATCH",
    "EXIT_OK",
    "EXIT_REFUSED",
    "GIT_ARGV",
    "MAX_CONFIRM_CHARS",
    "HumanCheck",
    "TerminalOS",
    "approve_summary",
    "git_user_name",
    "require_human",
    "resume_summary",
    "sanitize",
]

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_REFUSED = 3
MAX_CONFIRM_CHARS = 64
MAX_SUMMARY_LINES = 200
MAX_LINE_CHARS = 512
GIT_ARGV = ("git", "config", "--get", "user.name")
GIT_TIMEOUT = 2.0
GIT_MAX_BYTES = 256

_CHANGE_ID = re.compile(r"CHG-[0-9]{4}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,256}")

MESSAGES = {
    "not_a_tty": "this command needs a person at a real terminal (stdin and stdout must be "
    "a TTY). Run it yourself in your own terminal.",
    "uid_mismatch": "refused: real and effective user IDs differ.",
    "os_user_unknown": "refused: the OS user could not be determined.",
    "bad_change_id": "refused: invalid change ID.",
    "output_error": "refused: the summary could not be shown.",
    "input_error": "refused: the confirmation could not be read.",
    "mismatch": "not confirmed: the typed text did not match the change ID. Nothing was written.",
}


def _default_username(uid: int) -> str | None:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return None


def _default_home(uid: int) -> str | None:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_dir
    except (KeyError, OverflowError):
        return None


@dataclass(frozen=True)
class TerminalOS:
    """Injectable OS facts. Tests replace these; production uses the defaults."""

    isatty: Callable[[int], bool] = os.isatty
    getuid: Callable[[], int] = os.getuid
    geteuid: Callable[[], int] = os.geteuid
    username: Callable[[int], str | None] = _default_username


@dataclass(frozen=True)
class HumanCheck:
    """Outcome of ``require_human``. ``confirmed`` is true only for an exact match."""

    confirmed: bool
    code: str
    exit: int
    os_user: str | None = None
    git_user: str = ""
    uid: int | None = field(default=None, repr=False)


# --------------------------------------------------------------------------- text


def sanitize(text: Any, max_chars: int = MAX_LINE_CHARS) -> str:
    """One redacted display line: secrets redacted, control characters replaced."""
    if not isinstance(text, str):
        text = str(text)
    line = _CONTROL.sub("?", redact(text))
    if len(line) > max_chars:
        line = line[: max_chars - 3] + "..."
    return line


def resume_summary(change: Mapping[str, Any], *, clear_inflight: bool) -> list[str]:
    """Summary lines for ``cab resume``. Reads only the given state dict."""
    cid = change.get("id")
    halted = change.get("halted") if isinstance(change.get("halted"), Mapping) else None
    units = change.get("units") if isinstance(change.get("units"), list) else []
    debt = sum(
        1
        for u in units
        if isinstance(u, Mapping) and u.get("outcome") is not None and u.get("verify") is None
    )
    lines = [
        f"Resume {cid}",
        f"  state: {change.get('state')}",
        f"  halted: {halted.get('code') if halted else 'no'}",
        f"  writes with no verification: {debt}",
    ]
    inflight = change.get("inflight")
    if clear_inflight and isinstance(inflight, Mapping):
        lines += [
            f"  in-flight write: unit {inflight.get('unit')} never returned a result.",
            "WARNING: before you confirm, make sure that old call has stopped (check the "
            "Claude Code session and any process it started). This command does not stop it "
            "and cannot detect every result that arrives later.",
            "Clearing records the unit's result as unknown. It may have written: it stays "
            "unverified debt until a verify observes its targets. Nothing is reset.",
        ]
    elif isinstance(inflight, Mapping):
        lines.append(f"  in-flight write: unit {inflight.get('unit')} (not cleared)")
    lines.append(f"Type {cid} and press Enter to confirm; anything else cancels.")
    return lines


def approve_summary(
    *,
    change_id: str,
    tier: str,
    plan_hash: str,
    targets: Sequence[str],
    review_verdict: str | None,
    conditions: Sequence[str] = (),
    snapshot_taken_at: str | None,
    plan_summary: Sequence[str] = (),
) -> list[str]:
    """Summary lines for ``cab approve`` (DESIGN section 3-6)."""
    lines = [f"Approve {change_id}", f"  tier: {tier}", f"  plan hash: {plan_hash}"]
    lines += [f"  plan: {line}" for line in plan_summary]
    lines.append(f"  targets: {len(targets)}")
    lines += [f"    {t}" for t in list(targets)[:5]]
    if len(targets) > 5:
        lines.append(f"    ... and {len(targets) - 5} more")
    lines.append(f"  review: {review_verdict or 'none'}")
    lines += [f"    condition: {c}" for c in conditions]
    if snapshot_taken_at:
        lines.append(f"  snapshot complete at {snapshot_taken_at}")
    else:
        lines.append("  snapshot: not complete")
    lines.append(f"Type {change_id} and press Enter to approve; anything else cancels.")
    return lines


# --------------------------------------------------------------------------- tty


def _genuine_tty(stream: Any, osx: TerminalOS) -> bool:
    try:
        if stream.isatty() is not True:
            return False
        fd = stream.fileno()
        return type(fd) is int and fd >= 0 and osx.isatty(fd) is True
    except Exception:
        return False


def _say(stream: Any, text: str) -> None:
    try:
        stream.write(text + "\n")
        stream.flush()
    except Exception:
        pass


def _refuse(code: str, err: Any, exit_code: int = EXIT_REFUSED) -> HumanCheck:
    if err is not None:
        _say(err, "cab: " + MESSAGES[code])
    return HumanCheck(False, code, exit_code)


def require_human(
    change_id: str,
    summary: Sequence[str],
    *,
    stdin: Any,
    stdout: Any,
    stderr: Any = None,
    osx: TerminalOS | None = None,
    git_lookup: Callable[[], str] | None = None,
) -> HumanCheck:
    """Gate a person-only command. See the module doc for the exact order."""
    osx = osx or TerminalOS()
    if type(change_id) is not str or not _CHANGE_ID.fullmatch(change_id):
        return _refuse("bad_change_id", stderr)
    if not (_genuine_tty(stdin, osx) and _genuine_tty(stdout, osx)):
        return _refuse("not_a_tty", stderr)
    try:
        uid, euid = osx.getuid(), osx.geteuid()
    except Exception:
        return _refuse("uid_mismatch", stderr)
    if type(uid) is not int or type(euid) is not int or uid != euid:
        return _refuse("uid_mismatch", stderr)
    try:
        os_user = osx.username(uid)
    except Exception:
        os_user = None
    if type(os_user) is not str or not _NAME.fullmatch(os_user):
        return _refuse("os_user_unknown", stderr)

    try:
        for line in list(summary)[:MAX_SUMMARY_LINES]:
            stdout.write(sanitize(line) + "\n")
        stdout.write("> ")
        stdout.flush()
    except Exception:
        return _refuse("output_error", stderr)

    # Read the binary layer when there is one, so no newline translation can turn
    # "CHG-0007\r\n" into a match: only the single trailing LF is ever stripped.
    source = getattr(stdin, "buffer", stdin)
    try:
        raw = source.readline(MAX_CONFIRM_CHARS + 1)
    except Exception:
        return _refuse("input_error", stderr, EXIT_MISMATCH)
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return _refuse("input_error", stderr, EXIT_MISMATCH)
    if type(raw) is not str or not raw.endswith("\n"):
        return _refuse("mismatch", stderr, EXIT_MISMATCH)
    typed = raw[:-1]
    if len(typed) > MAX_CONFIRM_CHARS or typed != change_id:
        return _refuse("mismatch", stderr, EXIT_MISMATCH)

    git_user = ""
    if git_lookup is not None:
        try:
            value = git_lookup()
        except Exception:
            value = ""
        git_user = value if type(value) is str and _NAME.fullmatch(value) else ""
    return HumanCheck(True, "confirmed", EXIT_OK, os_user, git_user, uid)


# --------------------------------------------------------------------------- git


def _kill(proc: Any) -> None:
    try:
        proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=1.0)
    except Exception:
        pass


def _bounded_run(
    argv: Sequence[str],
    *,
    cwd: str | None,
    env: Mapping[str, str],
    timeout: float,
    max_bytes: int,
    popen: Callable[..., Any] = subprocess.Popen,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes | None:
    """stdout of ``argv`` (no shell), or ``None`` on spawn error, timeout, overflow or a
    non-zero exit. The cap and the deadline are enforced while reading."""
    try:
        proc = popen(
            list(argv),
            shell=False,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except Exception:
        return None
    deadline = monotonic() + timeout
    data = bytearray()
    try:
        fd = proc.stdout.fileno()
        while True:
            left = deadline - monotonic()
            if left <= 0:
                _kill(proc)
                return None
            ready, _, _ = select.select([fd], [], [], left)
            if not ready:
                continue
            chunk = os.read(fd, max_bytes + 1 - len(data))
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                _kill(proc)
                return None
        left = max(0.0, deadline - monotonic())
        try:
            code = proc.wait(timeout=left)
        except Exception:
            _kill(proc)
            return None
    except Exception:
        _kill(proc)
        return None
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    return bytes(data) if code == 0 else None


def git_user_name(
    cwd: str | None = None,
    *,
    home: str | None = None,
    runner: Callable[..., bytes | None] = _bounded_run,
) -> str:
    """``git config --get user.name`` or ``""``. Optional; never raises."""
    try:
        if home is None:
            home = _default_home(os.getuid())
        env = {"PATH": os.defpath, "LC_ALL": "C"}
        if home:
            env["HOME"] = home
        out = runner(GIT_ARGV, cwd=cwd, env=env, timeout=GIT_TIMEOUT, max_bytes=GIT_MAX_BYTES)
        if type(out) is not bytes or len(out) > GIT_MAX_BYTES:
            return ""
        text = out.decode("utf-8")
        if text.endswith("\n"):
            text = text[:-1]
        return text if _NAME.fullmatch(text) else ""
    except Exception:
        return ""
