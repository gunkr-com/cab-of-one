"""Generator profile: strict typed schema, loader and immutable model (DESIGN §10-4-3).

A profile is the interview's answers. It can tighten the generated controls or fit them to
the systems in use; it has no field that removes the core floor (§10-4-4).

Rules:

- ``schema = 1`` and exactly the documented tables and keys: unknown, missing and duplicate
  keys are refused (``tomllib`` already refuses duplicates);
- booleans are exact ``bool`` and integers exact ``int`` (``true`` is never ``1``);
- enumerations, integer bounds, list sizes and list-entry patterns are checked; duplicate list
  entries are refused; lists are stored sorted, so entry order never changes the output;
- ``systems.demo_simtenant = true`` is accepted only through ``load_reference_profile`` with
  a known reference name. ``load_profile`` never enables the demo.

Refusals raise ``ProfileError(code, field)``. ``field`` is a schema path, never a value.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from . import tomlw

__all__ = [
    "EXTRA_CRITICAL",
    "FIELDS",
    "REFERENCE_PROFILES",
    "ROUTINE_CHANGES",
    "Field",
    "Profile",
    "ProfileError",
    "load_profile",
    "load_reference_profile",
    "revalidate",
]

SCHEMA_VERSION = 1
MAX_PROFILE_BYTES = 64 * 1024
REFERENCE_PROFILES = frozenset({"contoso-solo"})

ROUTINE_CHANGES = (
    "forwarding-removal",
    "group-add-allowlisted",
    "joiner-license-group",
    "leaver-block-signin",
)
EXTRA_CRITICAL = ("admin-units", "break-glass", "executive-mailboxes", "finance-groups")

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 .&,'-]{0,62}[A-Za-z0-9.])?")
_PS_MODULE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,31}(?:\.[A-Za-z][A-Za-z0-9]{0,31}){0,5}")
_SERVER = re.compile(r"[A-Za-z0-9_-]{1,64}")  # same shape as the runtime policy schema
_PATH_PART = re.compile(r"[A-Za-z0-9._*-]{1,64}")
_MAX_PATH = 200
_MAX_PATH_PARTS = 16
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class ProfileError(ValueError):
    """The profile is refused. ``code`` is fixed; ``field`` is a schema path or None."""

    def __init__(self, code: str, field: str | None = None) -> None:
        super().__init__(code if field is None else f"{code}: {field}")
        self.code = code
        self.field = field


@dataclass(frozen=True)
class Field:
    """One profile field. ``kind`` is bool, int, enum, name or list."""

    kind: str
    choices: tuple[str, ...] = ()
    lo: int = 0
    hi: int = 0
    item: str = ""  # list entries: enum, ps_module, server or path
    max_items: int = 0


_BOOL = Field("bool")

_TABLES: dict[str, dict[str, Field]] = {
    "org": {
        "name": Field("name"),
        "it_team": Field("enum", choices=("solo", "small")),
    },
    "systems": {
        "entra": _BOOL,
        "exchange_online": _BOOL,
        "intune": _BOOL,
        "sharepoint_teams": _BOOL,
        "azure": _BOOL,
        "demo_simtenant": _BOOL,
    },
    "surfaces": {
        "powershell_modules": Field("list", item="ps_module", max_items=16),
        "azure_cli": _BOOL,
        "graph_http": _BOOL,
        "mcp_write_servers": Field("list", item="server", max_items=64),
    },
    "identity": {
        "agent_identity": Field("enum", choices=("read-only", "admin")),
        "deny_read_paths": Field("list", item="path", max_items=32),
    },
    "approval": {
        "approvers": Field("enum", choices=("self", "named")),
        "approval_ttl_hours": Field("int", lo=1, hi=24),  # runtime policy bounds
    },
    "session": {
        "permission_mode": Field("enum", choices=("manual", "bypass-guarded", "auto")),
        "git": _BOOL,
        "multi_machine": _BOOL,
        "sync_folder": _BOOL,
        "ticketing": Field("enum", choices=("none", "planner", "jira", "servicenow", "other")),
    },
    "changes": {
        "routine": Field("list", choices=ROUTINE_CHANGES, item="enum", max_items=8),
        "extra_critical": Field("list", choices=EXTRA_CRITICAL, item="enum", max_items=8),
    },
}

#: Every field by dotted path (``"systems.intune"``). Read-only.
FIELDS: Mapping[str, Field] = MappingProxyType(
    {f"{table}.{key}": spec for table, keys in _TABLES.items() for key, spec in keys.items()}
)

_M365 = ("systems.entra", "systems.exchange_online", "systems.intune", "systems.sharepoint_teams")


@dataclass(frozen=True, eq=False)
class Profile:
    """A validated profile. ``values`` maps dotted paths to bool, int, str or tuple[str]."""

    values: Mapping[str, Any]
    reference: str | None

    def __getitem__(self, key: str) -> Any:
        return self.values[key]

    def nested(self) -> dict[str, Any]:
        """A fresh plain mapping in the TOML shape (lists, not tuples)."""
        out: dict[str, Any] = {"schema": SCHEMA_VERSION}
        for path, value in self.values.items():
            table, key = path.split(".", 1)
            out.setdefault(table, {})[key] = list(value) if isinstance(value, tuple) else value
        return out

    def canonical_toml(self) -> bytes:
        return tomlw.dumps(self.nested()).encode("utf-8")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_toml()).hexdigest()


# --------------------------------------------------------------------------- loading


def load_profile(source: str | os.PathLike[str] | bytes | bytearray) -> Profile:
    """Load a user profile from a path or from bytes. Never enables the simtenant demo."""
    if isinstance(source, bytes | bytearray):
        data = bytes(source)
    elif isinstance(source, str | os.PathLike):
        data = _read_file(source)
    else:
        raise ProfileError("source_type")
    return _build(_parse(data), None)


def load_reference_profile(name: str, source_root: str | os.PathLike[str]) -> Profile:
    """Load ``<source_root>/profiles/<name>.toml`` for a known reference profile.

    This is the only path on which ``systems.demo_simtenant = true`` is accepted.
    """
    if type(name) is not str or name not in REFERENCE_PROFILES:
        raise ProfileError("reference_unknown")
    root = os.fspath(source_root)
    if not isinstance(root, str):
        raise ProfileError("source_type")
    folder = os.path.join(root, "profiles")
    st = _lstat(folder)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ProfileError("reference_missing")
    return _build(_parse(_read_file(os.path.join(folder, name + ".toml"))), name)


def revalidate(profile: Any) -> Profile:
    """Validate a ``Profile`` again from its values (defence against hand-built models)."""
    if not isinstance(profile, Profile):
        raise ProfileError("not_profile")
    reference = profile.reference
    if reference is not None and (
        type(reference) is not str or reference not in REFERENCE_PROFILES
    ):
        raise ProfileError("reference_unknown")
    if not isinstance(profile.values, Mapping):
        raise ProfileError("not_profile")
    try:
        doc = profile.nested()
    except (AttributeError, TypeError, ValueError):
        raise ProfileError("not_profile") from None
    return _build(doc, reference)


# --------------------------------------------------------------------------- internals


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None


def _read_file(path: str | os.PathLike[str]) -> bytes:
    name = os.fspath(path)
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ProfileError("source_type")
    try:
        fd = os.open(name, _OPEN_READ)
    except FileNotFoundError:
        raise ProfileError("profile_missing") from None
    except OSError:
        if os.path.islink(name):
            raise ProfileError("profile_symlink") from None
        raise ProfileError("profile_unreadable") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ProfileError("profile_not_regular")
        if st.st_size > MAX_PROFILE_BYTES:
            raise ProfileError("too_large")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PROFILE_BYTES:
            chunk = os.read(fd, MAX_PROFILE_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _parse(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_PROFILE_BYTES:
        raise ProfileError("too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError("encoding") from None
    if text.startswith("﻿"):
        raise ProfileError("bom")
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        raise ProfileError("syntax") from None  # includes duplicate keys and tables


def _build(doc: Any, reference: str | None) -> Profile:
    if not isinstance(doc, dict):
        raise ProfileError("not_table", "<top level>")
    expected = {"schema", *_TABLES}
    if set(doc) - expected:
        raise ProfileError("unknown_key", "<top level>")
    for key in sorted(expected - set(doc)):
        raise ProfileError("missing_key", key)
    if type(doc["schema"]) is not int or doc["schema"] != SCHEMA_VERSION:
        raise ProfileError("schema_version", "schema")

    values: dict[str, Any] = {}
    for table, fields in _TABLES.items():
        body = doc[table]
        if not isinstance(body, dict):
            raise ProfileError("not_table", table)
        if set(body) - set(fields):
            raise ProfileError("unknown_key", table)
        for key in fields:
            if key not in body:
                raise ProfileError("missing_key", f"{table}.{key}")
        for key, spec in fields.items():
            path = f"{table}.{key}"
            values[path] = _check(spec, body[key], path)

    if values["systems.demo_simtenant"] and reference is None:
        raise ProfileError("demo_requires_reference", "systems.demo_simtenant")
    if not (
        any(values[k] for k in (*_M365, "systems.azure", "systems.demo_simtenant"))
        or values["surfaces.powershell_modules"]
        or values["surfaces.azure_cli"]
        or values["surfaces.graph_http"]
        or values["surfaces.mcp_write_servers"]
    ):
        raise ProfileError("no_write_surface", "systems")
    return Profile(MappingProxyType(values), reference)


def _check(spec: Field, value: Any, path: str) -> Any:
    kind = spec.kind
    if kind == "bool":
        if type(value) is not bool:
            raise ProfileError("type_bool", path)
        return value
    if kind == "int":
        if type(value) is not int:
            raise ProfileError("type_int", path)
        if not spec.lo <= value <= spec.hi:
            raise ProfileError("out_of_range", path)
        return value
    if kind == "enum":
        if type(value) is not str or value not in spec.choices:
            raise ProfileError("bad_choice", path)
        return value
    if kind == "name":
        if type(value) is not str or not _NAME.fullmatch(value):
            raise ProfileError("bad_name", path)
        return value
    if kind == "list":
        if type(value) is not list:
            raise ProfileError("type_list", path)
        if len(value) > spec.max_items:
            raise ProfileError("too_many", path)
        items = [_item(spec, entry, path) for entry in value]
        if len(set(items)) != len(items):
            raise ProfileError("duplicate_entry", path)
        return tuple(sorted(items))
    raise ProfileError("schema_internal", path)  # pragma: no cover


def _item(spec: Field, value: Any, path: str) -> str:
    if type(value) is not str:
        raise ProfileError("bad_entry", path)
    if spec.item == "enum":
        ok = value in spec.choices
    elif spec.item == "ps_module":
        ok = len(value) <= 128 and bool(_PS_MODULE.fullmatch(value))
    elif spec.item == "server":
        ok = bool(_SERVER.fullmatch(value))
    elif spec.item == "path":
        ok = _safe_rule_path(value)
    else:  # pragma: no cover
        ok = False
    if not ok:
        raise ProfileError("bad_entry", path)
    return value


def _safe_rule_path(value: str) -> bool:
    """A project-relative permission-rule path: ``./`` then plain components.

    No absolute or home paths, no ``.``/``..`` components, no empty components, no spaces,
    parentheses, quotes, backslashes or control characters (they would break the rule text).
    """
    if len(value) > _MAX_PATH or not value.startswith("./"):
        return False
    parts = value[2:].split("/")
    if not parts or len(parts) > _MAX_PATH_PARTS:
        return False
    for part in parts:
        if not _PATH_PART.fullmatch(part) or set(part) == {"."}:
            return False
    return True
