"""PreToolUse hook boundary: stdin JSON in, exactly one fail-closed decision out.

This module is the I/O boundary for Claude Code ``PreToolUse`` command hooks only. Other
hook events have different output contracts and must not use it; an input whose
``hook_event_name`` is not ``PreToolUse`` is blocked.

Contract of ``run_hook(handler)``:

- stdin must be one UTF-8 JSON object with ``hook_event_name == "PreToolUse"`` and a
  non-empty string ``tool_name``. Duplicate keys, NaN/Infinity, non-objects, oversized or
  undecodable input are malformed.
- ``handler(data)`` must return a ``Decision``. Nothing else is accepted.
- Allow: exit 0 and ``{}`` on stdout. "Allow" means *no objection*: it does not emit
  ``permissionDecision: "allow"``, so Claude Code's normal permission rules and deny rules
  still apply. This module never auto-allows any tool, Read included; whether a
  well-formed Read may pass before policy parsing is the guard's decision.
- Deny: exit 2, the reason on stderr, and a ``permissionDecision: "deny"`` object on stdout.
- Malformed input, a handler exception (any ``BaseException``, ``SystemExit`` included) or
  a wrong return type: exit 2 with a fixed message. Error messages never contain the raw
  input, exception messages, commands or secrets; at most the exception type name.
- stdout receives exactly one JSON line. Anything the handler prints to ``sys.stdout`` or
  ``sys.stderr`` is discarded (writes straight to file descriptors are not intercepted).

Streams are injectable for unit tests. With ``exit_process=True`` (the default) the
function raises ``SystemExit`` so a hook script cannot forget to exit non-zero.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TextIO

__all__ = [
    "EXIT_ALLOW",
    "EXIT_BLOCK",
    "HOOK_EVENT",
    "Decision",
    "run_hook",
]

HOOK_EVENT = "PreToolUse"
EXIT_ALLOW = 0
EXIT_BLOCK = 2
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_REASON_CHARS = 2000

_PREFIX = "cab-of-one"
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_TYPE_NAME = re.compile(r"[^A-Za-z0-9_]")


@dataclass(frozen=True, slots=True)
class Decision:
    """A PreToolUse decision. Build with ``Decision.allow()`` or ``Decision.deny(reason)``."""

    allowed: bool
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise TypeError("allowed must be bool")
        if type(self.reason) is not str:
            raise TypeError("reason must be str")
        if not self.allowed and not _clean_reason(self.reason):
            raise ValueError("a deny decision needs a non-empty reason")

    @classmethod
    def allow(cls) -> Decision:
        return cls(True)

    @classmethod
    def deny(cls, reason: str) -> Decision:
        return cls(False, reason)


Handler = Callable[[dict[str, Any]], Decision]


class _Rejected(Exception):
    """Internal: carries a fixed, non-sensitive label for a blocked call."""

    def __init__(self, label: str) -> None:
        super().__init__(label)
        self.label = label


def run_hook(
    handler: Handler,
    *,
    stdin: Any = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    exit_process: bool = True,
) -> int:
    """Read one PreToolUse event, ask ``handler``, write one response. See module doc."""
    in_stream = sys.stdin if stdin is None else stdin
    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr

    code, payload, message = _evaluate(handler, in_stream)
    code = _emit(code, payload, message, out_stream, err_stream)
    if exit_process:
        raise SystemExit(code)
    return code


# --------------------------------------------------------------------------- evaluation


def _evaluate(handler: Handler, in_stream: Any) -> tuple[int, dict[str, Any], str]:
    try:
        data = _read_event(in_stream)
    except _Rejected as rejected:
        return _blocked(rejected.label)
    except BaseException as exc:  # fail closed on anything, including interrupts
        return _blocked(f"input could not be read ({_type_name(exc)})")

    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            result = handler(data)
    except BaseException as exc:  # SystemExit(0) from a handler must not exit 0
        return _blocked(f"internal error ({_type_name(exc)})")

    try:
        allowed, reason = _check_result(result)
    except _Rejected as rejected:
        return _blocked(rejected.label)
    except BaseException as exc:
        return _blocked(f"invalid handler result ({_type_name(exc)})")

    if allowed:
        return EXIT_ALLOW, {}, ""
    return _denied(reason)


def _read_event(in_stream: Any) -> dict[str, Any]:
    raw = _read_bounded(in_stream)
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _Rejected("malformed input (not UTF-8)") from None
    else:
        text = raw
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constants)
    except _Rejected:
        raise
    except (ValueError, RecursionError):
        raise _Rejected("malformed input (invalid JSON)") from None
    if not isinstance(data, dict):
        raise _Rejected("malformed input (not a JSON object)")
    if data.get("hook_event_name") != HOOK_EVENT:
        raise _Rejected("unexpected hook event (this boundary is PreToolUse only)")
    tool_name = data.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise _Rejected("malformed input (missing tool_name)")
    return data


def _read_bounded(in_stream: Any) -> bytes | str:
    source = getattr(in_stream, "buffer", in_stream)
    raw = source.read(MAX_INPUT_BYTES + 1)
    if not isinstance(raw, bytes | str):
        raise _Rejected("input could not be read")
    if len(raw) > MAX_INPUT_BYTES:
        raise _Rejected("input too large")
    return raw


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Rejected("malformed input (duplicate key)")
        result[key] = value
    return result


def _no_constants(_name: str) -> Any:
    raise _Rejected("malformed input (NaN or Infinity)")


def _check_result(result: object) -> tuple[bool, str]:
    if not isinstance(result, Decision):
        raise _Rejected(f"invalid handler result ({_type_name(result)})")
    allowed = result.allowed
    reason = result.reason
    if type(allowed) is not bool or type(reason) is not str:
        raise _Rejected("invalid handler result (Decision fields)")
    if allowed:
        return True, ""
    cleaned = _clean_reason(reason)
    if not cleaned:
        raise _Rejected("invalid handler result (deny without reason)")
    return False, cleaned


# --------------------------------------------------------------------------- output


def _blocked(label: str) -> tuple[int, dict[str, Any], str]:
    return _denied(f"tool call blocked: {label}.")


def _denied(reason: str) -> tuple[int, dict[str, Any], str]:
    message = f"{_PREFIX}: {reason}"
    payload = {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }
    return EXIT_BLOCK, payload, message


def _emit(code: int, payload: dict[str, Any], message: str, out: Any, err: Any) -> int:
    """Write the single JSON line, then the stderr reason. Any write failure blocks."""
    line = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    try:
        _write_text(out, line + "\n")
    except BaseException:
        code = EXIT_BLOCK
        if not message:
            message = f"{_PREFIX}: tool call blocked: hook response could not be written."
    if message:
        with contextlib.suppress(Exception):
            _write_text(err, message + "\n")
    return code


def _write_text(stream: Any, text: str) -> None:
    if isinstance(stream, io.RawIOBase | io.BufferedIOBase):
        stream.write(text.encode("ascii", "replace"))
    else:
        stream.write(text)
    stream.flush()


def _clean_reason(reason: str) -> str:
    single_line = " ".join(_CONTROL.sub(" ", reason).split())
    if len(single_line) > MAX_REASON_CHARS:
        single_line = single_line[: MAX_REASON_CHARS - 3].rstrip() + "..."
    return single_line


def _type_name(obj: object) -> str:
    name = _TYPE_NAME.sub("", type(obj).__name__)[:64]
    return name or "unknown"
