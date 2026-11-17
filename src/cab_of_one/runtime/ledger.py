"""Audit ledger: redacted, append-only JSONL rows written by hooks and the ``cab`` CLI (S4).

Order is fixed: secrets are redacted first, then the redacted text is hashed and
truncated, then the row is serialised. No raw command, raw input or hash of either is
ever stored. Rows are canonical JSON with ``ensure_ascii=True`` (so U+2028/U+2029 and every
control character are escaped), at most 8 KiB, framed by one LF.

``Ledger.append`` holds ``audit/ledger/.lock`` (flock), opens the month file with
``O_APPEND | O_NOFOLLOW``, requires a regular single-link file, writes every byte and
fsyncs. Any failure is ``LedgerError`` with a fixed code; the caller decides (an allow
becomes a deny; a settle failure halts the change). The lock is advisory: it serialises
hooks and the CLI, it does not stop a process that writes the file directly, and it is
not reliable on synced or network file systems.

Hash chaining is T1 and is NOT implemented: ``NoChain`` is the only chain and rows carry
no ``prev`` field. Nothing here claims tamper evidence.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import fsutil, paths
from .paths import Roots
from .schema import Invalid, canonical_bytes, canonical_json, strict_json, utc_text

__all__ = [
    "MAX_COMMAND_CHARS",
    "MAX_ROW_BYTES",
    "REDACTED",
    "JsonlLine",
    "Ledger",
    "LedgerError",
    "LedgerFormatError",
    "NoChain",
    "display_command",
    "fingerprint",
    "iter_jsonl",
    "iter_jsonl_bytes",
    "read_jsonl_strict",
    "redact",
    "redact_value",
]

LEDGER_VERSION = 1
MAX_COMMAND_CHARS = 512
MAX_ROW_BYTES = 8 * 1024
MAX_FIELD_CHARS = 256
REDACTED = "[REDACTED]"
_CUT = "...[cut]"
_APPEND_FLAGS = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC

# A shell or JSON value: a double-quoted string (with escapes), a single-quoted string,
# or a bare run of characters up to whitespace or a shell operator.
_VALUE = r"""(?:"(?:[^"\\\n]|\\.)*"?|'[^'\n]*'?|[^\s'"`;|&<>]+)"""
_SECRET_NAMES = (
    r"client[-_]?secret|password|passwd|pwd|secret|api[-_]?key|access[-_]?key|"
    r"access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|token|private[-_]?key|"
    r"account[-_]?key|sas[-_]?token|connection[-_]?string|certificate[-_]?password|"
    r"app[-_]?secret|shared[-_]?access[-_]?key|aws[-_]?secret[-_]?access[-_]?key"
)

_BUILTIN: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), replacement)
    for pattern, replacement in (
        # PEM private keys (a truncated block is cut to the end of the text)
        (
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            REDACTED,
        ),
        # Authorization and API-key headers: everything to the end of the header value
        (
            r"(?i)(\b(?:proxy-)?authorization\s*[:=]\s*)[^\r\n\"']+",
            r"\1" + REDACTED,
        ),
        (
            r"(?i)(\b(?:x-api-key|api-key|ocp-apim-subscription-key|x-functions-key)\s*:\s*)"
            r"[^\r\n\"']+",
            r"\1" + REDACTED,
        ),
        # Bearer tokens and JWTs anywhere
        (r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+", r"\1" + REDACTED),
        (r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?", REDACTED),
        # AWS access key IDs
        (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", REDACTED),
        # connection strings and SAS signatures
        (
            r"(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|"
            r"ClientSecret|Client_Secret)\s*=\s*[^;\"'\s]+",
            r"\1=" + REDACTED,
        ),
        (r"(?i)([?&]sig=)[^&\s\"'#]+", r"\1" + REDACTED),
        # credentials in URLs
        (r"(//[^/\s:@\"']+:)[^@\s/\"']+@", r"\1" + REDACTED + "@"),
        # CLI options: -ClientSecret X, -Password X, --password=X, --client-secret X ...
        (
            r"(?i)((?<![\w-])--?(?:" + _SECRET_NAMES + r"|clientsecret|accesstoken)"
            r"(?![\w-]))(\s*[=:]\s*|\s+)" + _VALUE,
            r"\1\2" + REDACTED,
        ),
        # az login ... -p VALUE
        (r"(?i)(\blogin\b[^\n]*?\s-[pP]\s+)" + _VALUE, r"\1" + REDACTED),
        # ConvertTo-SecureString [-String] "VALUE"
        (r"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)" + _VALUE, r"\1" + REDACTED),
        # key = value / "key": "value" (env, TOML, JSON, query strings)
        (
            r"(?i)([\"']?(?<![\w-])(?:" + _SECRET_NAMES + r")[\"']?\s*[:=]\s*)" + _VALUE,
            r"\1" + REDACTED,
        ),
    )
)
_SECRET_KEY = re.compile(r"(?i)^(?:" + _SECRET_NAMES + r"|authorization|clientsecret)$")


class LedgerError(Exception):
    """The ledger could not be written. ``code`` is fixed and non-sensitive."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LedgerFormatError(Exception):
    """A JSONL authority input has a malformed or truncated line."""

    def __init__(self, code: str, lineno: int) -> None:
        super().__init__(f"{code} at line {lineno}")
        self.code = code
        self.lineno = lineno


# --------------------------------------------------------------------------- redaction


def _compile(extra: Sequence[str | re.Pattern[str]]) -> tuple[re.Pattern[str], ...]:
    out = []
    for item in extra:
        out.append(item if isinstance(item, re.Pattern) else re.compile(item))
    return tuple(out)


def redact(text: str, extra: Sequence[str | re.Pattern[str]] = ()) -> str:
    """Replace known secret shapes (and policy ``extra_patterns``) with ``[REDACTED]``."""
    if not isinstance(text, str):
        return REDACTED
    out = text
    for pattern, replacement in _BUILTIN:
        out = pattern.sub(replacement, out)
    for pattern in _compile(extra):
        out = pattern.sub(REDACTED, out)
    return out


def redact_value(value: Any, extra: Sequence[str | re.Pattern[str]] = ()) -> Any:
    """Redact a JSON-like value. A secret-named key loses its whole value, whatever its
    shape (string, number, list or nested object); every other string is redacted."""
    compiled = _compile(extra)
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            name = str(key)
            if _SECRET_KEY.match(name):
                out[redact(name, compiled)] = REDACTED
            else:
                out[redact(name, compiled)] = redact_value(item, compiled)
        return out
    if isinstance(value, list | tuple):
        return [redact_value(item, compiled) for item in value]
    if isinstance(value, str):
        return redact(value, compiled)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    return REDACTED


def display_command(
    tool_name: str, tool_input: Any, extra: Sequence[str | re.Pattern[str]] = ()
) -> str | None:
    """Redacted text that stands for a tool call in the ledger (untruncated)."""
    if not isinstance(tool_input, Mapping):
        return None
    if tool_name == "Bash":
        command = tool_input.get("command")
        return redact(command, extra) if isinstance(command, str) else None
    if tool_name.startswith("mcp__"):
        return canonical_json(redact_value(tool_input, extra))
    for key in ("file_path", "notebook_path"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return redact(value, extra)
    return None


def fingerprint(
    tool_name: str, tool_input: Any, extra: Sequence[str | re.Pattern[str]] = ()
) -> str:
    """Binding of a reservation to its call, from the redacted input only."""
    body = {"input": redact_value(tool_input, extra), "tool": str(tool_name)}
    return hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()


def _clean(text: str, limit: int) -> str:
    cleaned = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - len(_CUT)] + _CUT


# --------------------------------------------------------------------------- JSONL reading


@dataclass(frozen=True)
class JsonlLine:
    lineno: int
    value: dict[str, Any] | None
    status: str  # "ok", "malformed" or "truncated"


def iter_jsonl_bytes(data: bytes, *, max_line: int = 64 * 1024) -> Iterator[JsonlLine]:
    """Split on b"\\n" only (never ``splitlines``). A final line without LF is truncated.

    Broken lines are reported, never skipped silently.
    """
    pos = 0
    lineno = 0
    while pos < len(data):
        lineno += 1
        end = data.find(b"\n", pos)
        if end < 0:
            yield JsonlLine(lineno, None, "truncated")
            return
        line = data[pos:end]
        pos = end + 1
        try:
            yield JsonlLine(lineno, strict_json(line, max_bytes=max_line), "ok")
        except Invalid:
            yield JsonlLine(lineno, None, "malformed")


def iter_jsonl(path: str, *, max_bytes: int = 64 * 1024 * 1024) -> Iterator[JsonlLine]:
    """``iter_jsonl_bytes`` over a regular file opened without following symlinks."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LedgerFormatError("not_regular", 0)
        if st.st_size > max_bytes:
            raise LedgerFormatError("too_large", 0)
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    if total > max_bytes:
        raise LedgerFormatError("too_large", 0)
    yield from iter_jsonl_bytes(b"".join(chunks))


def read_jsonl_strict(data: bytes) -> list[dict[str, Any]]:
    """Every line parsed, or ``LedgerFormatError`` at the first broken one."""
    rows = []
    for line in iter_jsonl_bytes(data):
        if line.status != "ok" or line.value is None:
            raise LedgerFormatError(line.status, line.lineno)
        rows.append(line.value)
    return rows


# --------------------------------------------------------------------------- appending


class NoChain:
    """S4 placeholder. The hash chain is T1 and is not implemented; rows have no prev."""

    def link(self, prev_line: bytes | None) -> None:
        return None


_ALLOWED_FIELDS = frozenset(
    {
        "session_id",
        "tool_use_id",
        "agent",
        "agent_type",
        "change_id",
        "decision",
        "reason_code",
        "tool",
        "cls",
        "seq",
        "state",
        "tier",
        "outcome",
        "unit",
        "action",
        "actor",
        # S5 settlement metadata. Only redacted-response hashes: salts, HMACs and hashes
        # of raw inputs are never ledger fields.
        "exit",
        "response_sha256",
        "source",
    }
)
_CLS_KEYS = ("kind", "unknown", "adapter", "verb", "floor", "targets_complete", "n")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SOURCE = re.compile(r"[a-z][a-z0-9_]{0,31}")


class Ledger:
    """Writer for ``audit/ledger/YYYY-MM.jsonl`` (UTC month of the row time)."""

    def __init__(
        self,
        roots: Roots,
        *,
        extra_patterns: Sequence[str | re.Pattern[str]] = (),
        clock: Callable[[], float] = time.time,
        lock_timeout: float = 2.0,
    ) -> None:
        self.roots = roots
        self.extra = _compile(extra_patterns)
        self.clock = clock
        self.lock_timeout = lock_timeout
        self.chain = NoChain()

    def path_for(self, ts: float) -> str:
        month = time.strftime("%Y-%m", time.gmtime(ts))
        return os.path.join(self.roots.ledger_dir, f"{month}.jsonl")

    def row(self, event: str, *, command: str | None = None, **fields: Any) -> bytes:
        """The bytes ``append`` would write now (redacted, bounded, LF-framed)."""
        return self._build(self.clock(), event, command, fields)

    def _build(self, ts: float, event: str, command: str | None, fields: dict) -> bytes:
        if set(fields) - _ALLOWED_FIELDS:
            raise LedgerError("field_unknown")
        row: dict[str, Any] = {"v": LEDGER_VERSION, "event": _clean(str(event), 32)}
        for key, value in fields.items():
            row[key] = self._field(key, value)
        row["ts"] = utc_text(ts)
        redacted = None
        if command is not None:
            # Redact the whole text first; only the redacted form is hashed or shown.
            redacted = redact(command, self.extra) if isinstance(command, str) else REDACTED
            row["command_sha256"] = hashlib.sha256(redacted.encode("utf-8")).hexdigest()
        for limit in (MAX_COMMAND_CHARS, 128, 0):
            if redacted is not None:
                row["command_redacted"] = _clean(redacted, limit) if limit else _CUT
            data = canonical_bytes(row)
            if len(data) <= MAX_ROW_BYTES:
                return data
        raise LedgerError("row_too_large")

    def _field(self, key: str, value: Any) -> Any:
        if key == "cls":
            if value is None:
                return None
            if not isinstance(value, Mapping) or set(value) - set(_CLS_KEYS):
                raise LedgerError("field_cls")
            return {k: self._scalar(value.get(k)) for k in _CLS_KEYS}
        if key == "exit":
            if value is not None and (type(value) is not int or not 0 <= value <= 255):
                raise LedgerError("field_exit")
            return value
        if key == "response_sha256":
            if value is not None and (type(value) is not str or not _HEX64.fullmatch(value)):
                raise LedgerError("field_response")
            return value
        if key == "source":
            if value is not None and (type(value) is not str or not _SOURCE.fullmatch(value)):
                raise LedgerError("field_source")
            return value
        return self._scalar(value)

    def _scalar(self, value: Any) -> Any:
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return _clean(redact(value, self.extra), MAX_FIELD_CHARS)
        raise LedgerError("field_type")

    def append(self, event: str, *, command: str | None = None, **fields: Any) -> None:
        """Append one row, or raise ``LedgerError``.

        A month file whose last byte is not LF (an earlier partial write or a truncated
        tail) is known audit damage: the append fails with ``truncated_tail`` and the file
        is left byte-for-byte as it was. Nothing repairs it automatically; a person must.
        """
        try:
            ts = self.clock()
            data = self._build(ts, event, command, fields)
            ts_path = self.path_for(ts)
            paths.ensure_dir(self.roots.project, "audit", "ledger")
            with fsutil.locked(self.roots.ledger_lock, self.lock_timeout):
                fd = os.open(ts_path, _APPEND_FLAGS, 0o600)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                        raise LedgerError("not_regular")
                    if st.st_size > 0 and os.pread(fd, 1, st.st_size - 1) != b"\n":
                        raise LedgerError("truncated_tail")
                    view = memoryview(data)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise LedgerError("short_write")
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except LedgerError:
            raise
        except fsutil.LockTimeout:
            raise LedgerError("lock_timeout") from None
        except Exception:
            raise LedgerError("append_failed") from None
