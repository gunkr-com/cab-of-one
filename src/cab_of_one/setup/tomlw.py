"""Deterministic TOML writer for generator profiles (a deliberately small subset).

Supported values: ``str``, ``int`` (signed 64-bit), finite ``float``, ``bool``, ``list`` of
those primitives, and nested mappings with ``str`` keys (written as ``[tables]``).
Everything else is refused with ``TomlWriteError``: ``None``, NaN, infinities, tuples,
sets, bytes, dates and times, nested lists, tables inside lists, non-string keys, lone
surrogates, cycles, and exact-type subclasses such as enums.

Output rules, so that the same input always gives the same bytes:

- keys sorted by code point at every level; plain key/values before sub-tables;
- every table gets an explicit header, so empty tables survive a round trip;
- strings use basic-string quoting with escapes for quote, backslash and control chars;
  other Unicode is written as-is (UTF-8 when encoded);
- floats use ``repr`` (shortest round-trip form); LF line endings; a trailing newline;
- no timestamps, UUIDs, comments or environment-dependent content.

Invariant: ``tomllib.loads(dumps(x)) == x`` for every accepted ``x``.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

__all__ = ["TomlWriteError", "dumps"]

MAX_DEPTH = 32
_INT_MIN = -(2**63)
_INT_MAX = 2**63 - 1
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class TomlWriteError(ValueError):
    """The value cannot be written by this TOML subset."""


def dumps(profile: Mapping[str, Any]) -> str:
    """Serialise ``profile`` to a TOML document string (see module doc)."""
    if not isinstance(profile, Mapping):
        raise TomlWriteError("top level must be a mapping")
    lines: list[str] = []
    _emit_table(profile, (), lines, set())
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def _emit_table(
    table: Mapping[str, Any], path: tuple[str, ...], lines: list[str], active: set[int]
) -> None:
    if len(path) > MAX_DEPTH:
        raise TomlWriteError(f"nesting deeper than {MAX_DEPTH} at {_where(path)}")
    marker = id(table)
    if marker in active:
        raise TomlWriteError(f"cycle at {_where(path)}")
    active.add(marker)

    items = [(key, table[key]) for key in _sorted_keys(table, path)]
    plain = [(key, value) for key, value in items if not isinstance(value, Mapping)]
    nested = [(key, value) for key, value in items if isinstance(value, Mapping)]

    if path:
        if lines:
            lines.append("")
        lines.append(f"[{_dotted(path)}]")
    for key, value in plain:
        lines.append(f"{_key(key)} = {_value(value, (*path, key))}")
    for key, value in nested:
        _emit_table(value, (*path, key), lines, active)

    active.discard(marker)


def _sorted_keys(table: Mapping[str, Any], path: tuple[str, ...]) -> list[str]:
    keys = list(table.keys())
    for key in keys:
        if type(key) is not str:
            raise TomlWriteError(f"non-string key ({type(key).__name__}) in {_where(path)}")
        _require_unicode(key, path)
    return sorted(keys)


def _value(value: Any, path: tuple[str, ...]) -> str:
    if value is None:
        raise TomlWriteError(f"None is not representable in TOML at {_where(path)}")
    kind = type(value)
    if kind is bool:
        return "true" if value else "false"
    if kind is int:
        if not _INT_MIN <= value <= _INT_MAX:
            raise TomlWriteError(f"integer outside signed 64-bit range at {_where(path)}")
        return str(value)
    if kind is float:
        if not math.isfinite(value):
            raise TomlWriteError(f"NaN and infinity are refused at {_where(path)}")
        return repr(value)
    if kind is str:
        return _string(value, path)
    if kind is list:
        return _array(value, path)
    raise TomlWriteError(f"unsupported type {kind.__name__} at {_where(path)}")


def _array(items: list[Any], path: tuple[str, ...]) -> str:
    parts: list[str] = []
    for item in items:
        if isinstance(item, list | tuple | Mapping):
            raise TomlWriteError(
                f"arrays may hold only strings, numbers and booleans at {_where(path)}"
            )
        parts.append(_value(item, path))
    return "[" + ", ".join(parts) + "]"


def _string(text: str, path: tuple[str, ...]) -> str:
    _require_unicode(text, path)
    out: list[str] = []
    for ch in text:
        escaped = _ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif ch < " " or "\x7f" <= ch <= "\x9f":
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _require_unicode(text: str, path: tuple[str, ...]) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise TomlWriteError(f"string is not valid Unicode at {_where(path)}") from None


def _key(key: str) -> str:
    if _BARE_KEY.fullmatch(key):
        return key
    return _string(key, ())


def _dotted(path: tuple[str, ...]) -> str:
    return ".".join(_key(part) for part in path)


def _where(path: tuple[str, ...]) -> str:
    if not path:
        return "<top level>"
    try:
        return _dotted(path)
    except TomlWriteError:
        return "<unprintable key>"
