"""Claude Code transcript parser for ``cab audit`` (DESIGN §3-9 item 1, §9-1, appendix B).

The transcript format is not a documented, stable contract, so every format assumption
lives in this one module and anything it does not recognise is reported as
*indeterminate*, never as clean.

Layout read (appendix B): main transcripts ``<root>/<project-dir>/<sessionId>.jsonl`` and
subagent transcripts ``<root>/<project-dir>/<sessionId>/subagents/agent-<agentId>.jsonl``.
Nothing deeper is visited. Symlinks are never followed (directories and files alike), each
file is opened with ``O_NOFOLLOW | O_NONBLOCK``, must be a regular file and is read only up
to a byte bound.

Lines are split on ``b"\\n"`` only (never ``splitlines``, which would also split on U+2028,
U+2029 and other separators that may legally appear inside JSON strings). A final line
without LF is *truncated*. Each line goes through ``schema.strict_json`` (no duplicate keys,
no NaN, bounded size and depth).

What is extracted: ``tool_use`` blocks of ``assistant`` records, with the record's
``sessionId``, ``cwd``, ``agentId``, ``isSidechain`` and ``timestamp``. Streaming repeats
the same tool call on several lines; calls are de-duplicated by tool-use ID and content.
Nothing is executed and no file named by a transcript is ever opened.

Public API: ``discover``, ``parse_file``, ``parse_bytes``, ``TranscriptRef``,
``Discovery``, ``Transcript``, ``ToolCall`` and the reason-code constants.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .schema import Invalid, canonical_json, is_agent_id, is_token, strict_json

__all__ = [
    "INDETERMINATE_REASONS",
    "KIND_MAIN",
    "KIND_SUBAGENT",
    "MAX_FILES",
    "MAX_FILE_BYTES",
    "MAX_LINE_BYTES",
    "RECORD_TYPES",
    "Discovery",
    "ToolCall",
    "Transcript",
    "TranscriptRef",
    "discover",
    "parse_bytes",
    "parse_file",
]

KIND_MAIN = "main"
KIND_SUBAGENT = "subagent"

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_FILES = 20_000
MAX_ENTRIES_PER_DIR = 100_000
MAX_DEPTH = 64
MAX_TOOL_NAME_CHARS = 256
MAX_CWD_CHARS = 4096

# Record types this parser knows. Anything else is "unrecognized" and makes the file
# indeterminate: an unknown record could carry a tool call this parser cannot see.
RECORD_TYPES = frozenset(
    {
        "user",
        "assistant",
        "system",
        "summary",
        "file-history-snapshot",
        "queue-operation",
        "progress",
        "attachment",
    }
)
# Content blocks of an assistant message. Only ``tool_use`` is a local tool call; other
# block types (server tools, remote MCP blocks, future types) are unrecognized.
ASSISTANT_BLOCK_TYPES = frozenset({"text", "thinking", "redacted_thinking", "tool_use"})

# Reason codes (fixed identifiers; they never contain transcript content).
R_SYMLINK = "symlink_skipped"
R_NOT_REGULAR = "not_regular"
R_FILE_TOO_LARGE = "file_too_large"
R_FILE_UNREADABLE = "file_unreadable"
R_TRUNCATED = "truncated_line"
R_MALFORMED = "malformed_line"
R_OVERSIZE = "oversize_line"
R_UNRECOGNIZED = "unrecognized_record"
R_MALFORMED_RECORD = "malformed_record"
R_UNRECOGNIZED_BLOCK = "unrecognized_block"
R_MALFORMED_TOOL_USE = "malformed_tool_use"
R_TOOL_ID_CONFLICT = "tool_id_conflict"
R_TOOL_ID_MISSING = "tool_id_missing"
R_DUPLICATE_TOOL_ID = "duplicate_tool_id"
R_SESSION_INVALID = "session_id_invalid"
R_SESSION_MISMATCH = "session_id_mismatch"
R_AGENT_MISMATCH = "agent_id_mismatch"
R_CWD_INVALID = "cwd_invalid"
R_TIMESTAMP_INVALID = "timestamp_invalid"
R_BLANK = "blank_line"

INDETERMINATE_REASONS = frozenset(
    {
        R_SYMLINK,
        R_NOT_REGULAR,
        R_FILE_TOO_LARGE,
        R_FILE_UNREADABLE,
        R_TRUNCATED,
        R_MALFORMED,
        R_OVERSIZE,
        R_UNRECOGNIZED,
        R_MALFORMED_RECORD,
        R_UNRECOGNIZED_BLOCK,
        R_MALFORMED_TOOL_USE,
        R_TOOL_ID_CONFLICT,
    }
)

_MAIN_FILE = re.compile(r"(.+)\.jsonl")
_AGENT_FILE = re.compile(r"agent-(.+)\.jsonl")
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


# --------------------------------------------------------------------------- data


@dataclass(frozen=True)
class ToolCall:
    """One tool call as the transcript recorded it.

    ``session_id`` is the record's own ``sessionId`` (else the file's session);
    ``cwd`` is the record's ``cwd`` (None when absent or not absolute). ``input`` is the
    parsed JSON value and is handed only to the classifier, never to a report.
    """

    tool_use_id: str | None
    name: str
    input: Any
    session_id: str | None
    cwd: str | None
    agent_id: str | None
    sidechain: bool
    timestamp: float | None
    lineno: int
    digest: str


@dataclass(frozen=True)
class Transcript:
    """Parse result of one transcript file."""

    path: str
    kind: str
    file_session_id: str | None
    file_agent_id: str | None
    calls: tuple[ToolCall, ...] = ()
    session_ids: frozenset[str] = frozenset()
    cwds: tuple[str, ...] = ()
    first_ts: float | None = None
    last_ts: float | None = None
    lines: int = 0
    records: int = 0
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def indeterminate(self) -> bool:
        return any(self.counts.get(code, 0) for code in INDETERMINATE_REASONS)

    @property
    def status(self) -> str:
        return "indeterminate" if self.indeterminate else "ok"

    def reasons(self) -> tuple[str, ...]:
        """Indeterminate reason codes present in this file, sorted."""
        return tuple(sorted(c for c in INDETERMINATE_REASONS if self.counts.get(c, 0)))


@dataclass(frozen=True)
class TranscriptRef:
    """A transcript file found by ``discover`` (metadata from ``lstat`` only)."""

    path: str
    kind: str
    project_dir: str
    session_id: str | None
    agent_id: str | None
    mtime: float
    size: int


@dataclass(frozen=True)
class Discovery:
    refs: tuple[TranscriptRef, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None


# --------------------------------------------------------------------------- helpers


def _bump(counts: dict[str, int], code: str, n: int = 1) -> None:
    counts[code] = counts.get(code, 0) + n


def _parse_ts(value: Any) -> float | None:
    if type(value) is not str or not 10 <= len(value) <= 40:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None
    return moment.timestamp()


def _digest(name: str, value: Any) -> str:
    try:
        body = canonical_json({"input": value, "name": name})
    except (TypeError, ValueError):
        body = "unserialisable:" + name
    return hashlib.sha256(body.encode("ascii")).hexdigest()


def _clean_cwd(value: Any) -> str | None:
    if type(value) is not str or not value or len(value) > MAX_CWD_CHARS:
        return None
    if "\x00" in value or not value.startswith("/"):
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return None
    return value


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _scan(path: str) -> list[os.DirEntry[str]] | None:
    try:
        with os.scandir(path) as it:
            out: list[os.DirEntry[str]] = []
            for entry in it:
                out.append(entry)
                if len(out) > MAX_ENTRIES_PER_DIR:
                    break
    except OSError:
        return None
    out.sort(key=lambda e: e.name)
    return out


def _is_dir_nolink(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _is_link(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_symlink()
    except OSError:
        return True


# --------------------------------------------------------------------------- discovery


def discover(projects_root: str, *, max_files: int = MAX_FILES) -> Discovery:
    """Find transcript files under ``projects_root`` without following symlinks.

    ``projects_root`` itself must be a real directory (not a symlink); a caller that keeps
    it behind a link passes the resolved path explicitly. At most ``max_files`` refs are
    returned; the rest are counted as ``file_limit``.
    """
    counts: dict[str, int] = {}
    if not isinstance(projects_root, str) or not projects_root or "\x00" in projects_root:
        return Discovery(error="root_invalid")
    if not os.path.isabs(projects_root):
        return Discovery(error="root_not_absolute")
    st = _lstat(projects_root)
    if st is None:
        return Discovery(error="root_missing")
    if stat.S_ISLNK(st.st_mode):
        return Discovery(error="root_symlink")
    if not stat.S_ISDIR(st.st_mode):
        return Discovery(error="root_not_dir")
    top = _scan(projects_root)
    if top is None:
        return Discovery(error="root_unreadable")
    if len(top) > MAX_ENTRIES_PER_DIR:
        _bump(counts, "dir_entry_limit")

    refs: list[TranscriptRef] = []

    def add(path: str, kind: str, project: str, sid: str | None, aid: str | None) -> None:
        if len(refs) >= max_files:
            _bump(counts, "file_limit")
            return
        fst = _lstat(path)
        if fst is None:
            _bump(counts, R_FILE_UNREADABLE)
            return
        if stat.S_ISLNK(fst.st_mode):
            _bump(counts, R_SYMLINK)
            return
        if not stat.S_ISREG(fst.st_mode):
            _bump(counts, R_NOT_REGULAR)
            return
        refs.append(TranscriptRef(path, kind, project, sid, aid, fst.st_mtime, fst.st_size))

    for proj in top:
        if _is_link(proj):
            _bump(counts, R_SYMLINK)
            continue
        if not _is_dir_nolink(proj):
            continue  # stray files at the top level are not transcripts
        entries = _scan(proj.path)
        if entries is None:
            _bump(counts, "dir_unreadable")
            continue
        if len(entries) > MAX_ENTRIES_PER_DIR:
            _bump(counts, "dir_entry_limit")
        for entry in entries:
            if _is_link(entry):
                _bump(counts, R_SYMLINK)
                continue
            m = _MAIN_FILE.fullmatch(entry.name)
            if m and not _is_dir_nolink(entry):
                sid = m.group(1) if is_token(m.group(1)) else None
                if sid is None:
                    _bump(counts, R_SESSION_INVALID)
                add(entry.path, KIND_MAIN, proj.name, sid, None)
                continue
            if not _is_dir_nolink(entry):
                continue
            sub = os.path.join(entry.path, "subagents")
            sst = _lstat(sub)
            if sst is None:
                continue
            if stat.S_ISLNK(sst.st_mode):
                _bump(counts, R_SYMLINK)
                continue
            if not stat.S_ISDIR(sst.st_mode):
                continue
            agents = _scan(sub)
            if agents is None:
                _bump(counts, "dir_unreadable")
                continue
            sid = entry.name if is_token(entry.name) else None
            for agent in agents:
                if _is_link(agent):
                    _bump(counts, R_SYMLINK)
                    continue
                am = _AGENT_FILE.fullmatch(agent.name)
                if not am or _is_dir_nolink(agent):
                    continue
                aid = am.group(1) if is_agent_id(am.group(1)) else None
                if sid is None:
                    _bump(counts, R_SESSION_INVALID)
                add(agent.path, KIND_SUBAGENT, proj.name, sid, aid)
    return Discovery(tuple(refs), counts, None)


# --------------------------------------------------------------------------- reading


def _read_bounded(path: str, max_bytes: int) -> tuple[bytes | None, str | None]:
    try:
        fd = os.open(path, _OPEN_READ)
    except OSError:
        st = _lstat(path)
        if st is not None and stat.S_ISLNK(st.st_mode):
            return None, R_SYMLINK
        return None, R_FILE_UNREADABLE
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, R_NOT_REGULAR
        if st.st_size > max_bytes:
            return None, R_FILE_TOO_LARGE
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, min(1 << 20, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None, R_FILE_UNREADABLE
    finally:
        os.close(fd)
    if total > max_bytes:
        return None, R_FILE_TOO_LARGE
    return b"".join(chunks), None


def parse_file(
    ref: TranscriptRef,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
    record_types: Iterable[str] | None = None,
) -> Transcript:
    """Read and parse one discovered file. Never raises for file problems."""
    data, problem = _read_bounded(ref.path, max_file_bytes)
    if data is None:
        code = problem or R_FILE_UNREADABLE
        return Transcript(ref.path, ref.kind, ref.session_id, ref.agent_id, counts={code: 1})
    return parse_bytes(
        data,
        path=ref.path,
        kind=ref.kind,
        file_session_id=ref.session_id,
        file_agent_id=ref.agent_id,
        max_line_bytes=max_line_bytes,
        record_types=record_types,
    )


def parse_bytes(
    data: bytes,
    *,
    path: str = "",
    kind: str = KIND_MAIN,
    file_session_id: str | None = None,
    file_agent_id: str | None = None,
    max_line_bytes: int = MAX_LINE_BYTES,
    record_types: Iterable[str] | None = None,
) -> Transcript:
    """Parse transcript bytes. Splits on LF only; broken lines are counted, never hidden."""
    known = RECORD_TYPES if record_types is None else frozenset(record_types)
    counts: dict[str, int] = {}
    calls: list[ToolCall] = []
    seen: dict[str, set[str]] = {}
    session_ids: set[str] = set()
    cwds: list[str] = []
    first_ts: float | None = None
    last_ts: float | None = None
    records = 0
    lineno = 0
    pos = 0
    n = len(data) if isinstance(data, bytes | bytearray) else 0
    if not isinstance(data, bytes | bytearray):
        counts[R_FILE_UNREADABLE] = 1
    while pos < n:
        lineno += 1
        end = data.find(b"\n", pos)
        if end < 0:
            _bump(counts, R_TRUNCATED)
            break
        line = bytes(data[pos:end])
        pos = end + 1
        if not line.strip(b" \t\r"):
            _bump(counts, R_BLANK)
            continue
        if len(line) > max_line_bytes:
            _bump(counts, R_OVERSIZE)
            continue
        try:
            rec = strict_json(line, max_bytes=max_line_bytes, max_depth=MAX_DEPTH)
        except Invalid:
            _bump(counts, R_MALFORMED)
            continue
        rtype = rec.get("type")
        if type(rtype) is not str or rtype not in known:
            _bump(counts, R_UNRECOGNIZED)
            continue
        records += 1

        sid: str | None = None
        if "sessionId" in rec:
            raw_sid = rec.get("sessionId")
            if is_token(raw_sid):
                sid = raw_sid
                session_ids.add(raw_sid)
            else:
                _bump(counts, R_SESSION_INVALID)
        if sid is not None and file_session_id is not None and sid != file_session_id:
            _bump(counts, R_SESSION_MISMATCH)
        if sid is None:
            sid = file_session_id

        cwd = None
        if "cwd" in rec:
            cwd = _clean_cwd(rec.get("cwd"))
            if cwd is None:
                _bump(counts, R_CWD_INVALID)
            elif cwd not in cwds:
                cwds.append(cwd)

        ts = None
        if "timestamp" in rec:
            ts = _parse_ts(rec.get("timestamp"))
            if ts is None:
                _bump(counts, R_TIMESTAMP_INVALID)
            else:
                first_ts = ts if first_ts is None else min(first_ts, ts)
                last_ts = ts if last_ts is None else max(last_ts, ts)

        agent = None
        raw_agent = rec.get("agentId")
        if is_agent_id(raw_agent):
            agent = raw_agent
            if file_agent_id is not None and raw_agent != file_agent_id:
                _bump(counts, R_AGENT_MISMATCH)
        if agent is None:
            agent = file_agent_id
        sidechain = rec.get("isSidechain") is True

        if rtype not in ("user", "assistant"):
            continue
        message = rec.get("message")
        if not isinstance(message, Mapping):
            _bump(counts, R_MALFORMED_RECORD)
            continue
        if rtype == "user":
            continue  # tool results and prompts; no tool calls are taken from them
        content = message.get("content")
        if isinstance(content, str):
            continue
        if not isinstance(content, list):
            _bump(counts, R_MALFORMED_RECORD)
            continue
        for block in content:
            btype = block.get("type") if isinstance(block, Mapping) else None
            if type(btype) is not str or btype not in ASSISTANT_BLOCK_TYPES:
                _bump(counts, R_UNRECOGNIZED_BLOCK)
                continue
            if btype != "tool_use":
                continue
            name = block.get("name")
            tool_input = block.get("input")
            if type(name) is not str or not name or len(name) > MAX_TOOL_NAME_CHARS:
                _bump(counts, R_MALFORMED_TOOL_USE)
                name = ""  # classified as unknown-admin by the caller
            if not isinstance(tool_input, Mapping):
                _bump(counts, R_MALFORMED_TOOL_USE)
            tid = block.get("id")
            if type(tid) is not str or not tid or len(tid) > 256:
                _bump(counts, R_TOOL_ID_MISSING)
                tid = None
            digest = _digest(name, tool_input)
            if tid is not None:
                variants = seen.setdefault(tid, set())
                if digest in variants:
                    _bump(counts, R_DUPLICATE_TOOL_ID)
                    continue
                if variants:
                    _bump(counts, R_TOOL_ID_CONFLICT)  # keep every distinct variant
                variants.add(digest)
            calls.append(
                ToolCall(tid, name, tool_input, sid, cwd, agent, sidechain, ts, lineno, digest)
            )
    return Transcript(
        path,
        kind,
        file_session_id,
        file_agent_id,
        tuple(calls),
        frozenset(session_ids),
        tuple(cwds),
        first_ts,
        last_ts,
        lineno,
        records,
        counts,
    )
