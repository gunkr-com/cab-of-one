"""Pure helpers for non-PreToolUse hook events (S5 C0).

Nothing here touches the Store, the ledger file, the state directory or the network.
C-main (``audithook``/``closeout``) owns those effects.

``read_event(stream, expected)``
    Reads one bounded hook event (at most ``MAX_EVENT_BYTES`` + 1 bytes are ever pulled)
    and parses it as strict JSON: duplicate keys, NaN/Infinity, a BOM, non-UTF-8, a
    non-object root and over-deep nesting are refused. ``hook_event_name`` must be one
    of ``expected``. Failure raises ``EventError`` with a fixed, non-sensitive code.

``identity(data)``
    The call identity. A malformed ``session_id``, ``tool_use_id`` or ``tool_name`` is
    ``None``; any ``agent_id`` key, or a missing/malformed session or tool name, makes
    the call *not* the main session.

``recognize(data)``
    Settlement metadata for ``PostToolUse``/``PostToolUseFailure``. Only the shapes
    measured with Claude Code 2.1.322 (S5 contract section 5) are recognised:

    - a Bash ``PostToolUse`` whose ``tool_response`` is a dict with exactly the keys
      ``stdout:str, stderr:str, interrupted:bool, isImage:bool, noOutputExpected:bool``
      and ``interrupted is False`` is ``ok``; any other shape, and any non-Bash
      ``PostToolUse``, is ``unknown``;
    - a ``PostToolUseFailure`` is ``failed``, or ``unknown`` when ``is_interrupt is
      True``; ``exit`` is read only from an ``error`` string whose first line fully
      matches ``Exit code N`` with N <= 255.

    stdout/stderr *content* is never inspected, and ``ok`` is settlement metadata, never
    a verification PASS. ``response_sha256`` is the SHA-256 of the canonical JSON of the
    *redacted* response; the raw response is not kept. The raw ``tool_input`` is carried
    (hidden from ``repr``) only so the caller can feed the exact-input HMAC.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Any

from .ledger import redact_value
from .schema import Invalid, canonical_json, is_token, strict_json

__all__ = [
    "BASH_SUCCESS_KEYS",
    "MAX_EVENT_BYTES",
    "POST_EVENTS",
    "EventError",
    "Identity",
    "PostResult",
    "identity",
    "parse_exit",
    "read_event",
    "recognize",
    "response_sha256",
]

MAX_EVENT_BYTES = 16 * 1024 * 1024
MAX_TOOL_CHARS = 256
POST = "PostToolUse"
FAILURE = "PostToolUseFailure"
POST_EVENTS = frozenset({POST, FAILURE})

# The measured Bash success shape (shape probe 20261112T063344Z). Order is irrelevant.
BASH_SUCCESS_KEYS: Mapping[str, type] = {
    "stdout": str,
    "stderr": str,
    "interrupted": bool,
    "isImage": bool,
    "noOutputExpected": bool,
}

_CHUNK = 64 * 1024
_EXIT_LINE = re.compile(r"Exit code ([0-9]{1,3})")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

SHAPE_BASH_SUCCESS = "bash_success"
SHAPE_BASH_INTERRUPTED = "bash_interrupted"
SHAPE_FAILURE = "failure"
SHAPE_FAILURE_INTERRUPT = "failure_interrupt"
SHAPE_UNRECOGNIZED = "unrecognized"


class EventError(Exception):
    """A hook event could not be read. ``code`` is fixed and never contains input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------- reading


def _read_bounded(stream: Any) -> bytes:
    source = getattr(stream, "buffer", stream)
    parts: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = source.read(min(_CHUNK, MAX_EVENT_BYTES + 1 - total))
        except Exception:
            raise EventError("unreadable") from None
        if isinstance(chunk, str):
            try:
                chunk = chunk.encode("utf-8")
            except UnicodeEncodeError:
                raise EventError("encoding") from None
        if not isinstance(chunk, bytes | bytearray):
            raise EventError("unreadable")
        if not chunk:
            break
        parts.append(bytes(chunk))
        total += len(chunk)
        if total > MAX_EVENT_BYTES:
            raise EventError("too_large")
    return b"".join(parts)


def read_event(stream: Any, expected: Collection[str]) -> dict[str, Any]:
    """Read and strictly parse one hook event whose name is in ``expected``."""
    raw = _read_bounded(stream)
    if not raw:
        raise EventError("empty")
    try:
        data = strict_json(raw, max_bytes=MAX_EVENT_BYTES)
    except Invalid as exc:
        raise EventError(exc.code) from None
    except Exception:
        raise EventError("syntax") from None
    name = data.get("hook_event_name")
    if type(name) is not str or name not in expected:
        raise EventError("event_name")
    return data


# --------------------------------------------------------------------------- identity


@dataclass(frozen=True)
class Identity:
    """Who made the call. Fields are ``None`` when absent or malformed."""

    session_id: str | None
    tool_use_id: str | None
    tool_name: str | None
    is_subagent: bool
    is_main: bool


def _tool_name(value: Any) -> str | None:
    if type(value) is not str or not value or len(value) > MAX_TOOL_CHARS:
        return None
    if _CONTROL.search(value):
        return None
    return value


def identity(data: Mapping[str, Any]) -> Identity:
    session_id = data.get("session_id")
    session_id = session_id if is_token(session_id) else None
    tool_use_id = data.get("tool_use_id")
    tool_use_id = tool_use_id if is_token(tool_use_id) else None
    tool_name = _tool_name(data.get("tool_name"))
    # The presence of agent_id marks a subagent or teammate, whatever its value.
    is_subagent = "agent_id" in data
    is_main = not is_subagent and session_id is not None and tool_name is not None
    return Identity(session_id, tool_use_id, tool_name, is_subagent, is_main)


# --------------------------------------------------------------------------- recognition


@dataclass(frozen=True)
class PostResult:
    """Normalised settlement metadata for one Post/Failure event.

    ``source`` is ``post`` or ``failure``; ``outcome`` is ``ok``, ``failed`` or
    ``unknown``; ``shape`` names the recognised form (diagnostic only).
    ``tool_input`` is the raw input or ``None`` when it is not a JSON object; it is
    excluded from ``repr`` and must only be fed to the exact-input HMAC.
    """

    hook_event_name: str
    identity: Identity
    source: str
    outcome: str
    exit: int | None
    response_sha256: str | None
    shape: str
    tool_input: dict[str, Any] | None = field(repr=False, compare=False)


def response_sha256(response: Any) -> str:
    """SHA-256 of the canonical JSON of the redacted response."""
    redacted = redact_value(response)
    return hashlib.sha256(canonical_json(redacted).encode("ascii")).hexdigest()


def parse_exit(error: Any) -> int | None:
    """``N`` from an error whose first line is exactly ``Exit code N`` (N <= 255)."""
    if type(error) is not str:
        return None
    first = error.split("\n", 1)[0]
    match = _EXIT_LINE.fullmatch(first)
    if match is None:
        return None
    value = int(match.group(1))
    return value if value <= 255 else None


def _bash_success(response: Any) -> str:
    if type(response) is not dict or set(response) != set(BASH_SUCCESS_KEYS):
        return SHAPE_UNRECOGNIZED
    for key, kind in BASH_SUCCESS_KEYS.items():
        if type(response[key]) is not kind:
            return SHAPE_UNRECOGNIZED
    if response["interrupted"] is not False:
        return SHAPE_BASH_INTERRUPTED
    return SHAPE_BASH_SUCCESS


def recognize(data: Mapping[str, Any]) -> PostResult:
    """Settlement metadata for a parsed Post/Failure event. Raises ``EventError`` for
    any other event name. Never inspects stdout or stderr content."""
    name = data.get("hook_event_name")
    if name not in POST_EVENTS:
        raise EventError("event_name")
    who = identity(data)
    raw_input = data.get("tool_input")
    tool_input = raw_input if type(raw_input) is dict else None

    if name == POST:
        has_response = "tool_response" in data
        response = data.get("tool_response")
        digest = response_sha256(response) if has_response else None
        shape = _bash_success(response) if who.tool_name == "Bash" else SHAPE_UNRECOGNIZED
        outcome = "ok" if shape == SHAPE_BASH_SUCCESS else "unknown"
        return PostResult(name, who, "post", outcome, None, digest, shape, tool_input)

    if data.get("is_interrupt") is True:
        outcome, shape = "unknown", SHAPE_FAILURE_INTERRUPT
    else:
        outcome, shape = "failed", SHAPE_FAILURE
    return PostResult(
        name, who, "failure", outcome, parse_exit(data.get("error")), None, shape, tool_input
    )
