"""Strict schema-1 manifest and the shared setup vocabulary for merge/uninstall (S9).

Pure data: nothing in this module reads or writes files. ``setup.merge`` plans a merge or
an uninstall against these records; ``apply``/``uninstall`` (not written yet) perform the
plans and write ``.cab/manifest.json`` with :func:`dump_manifest`.

The manifest records what the generator owns in a project, never what a person owns:

``files``
    generated files under ``.claude/agents/``, ``.claude/skills/`` and
    ``.claude/hooks/cab/`` (plus the exact paths in ``OWNED_FILES``: ``docs/identity.md``
    and the two reference-demo files ``simtenant/simtenant.py`` and
    ``simtenant/seed/contoso.json``) with the SHA-256 of the bytes the generator last wrote.
``offered``
    create-once files (policy, standard changes, evidence READMEs, handoff notes) with the
    SHA-256 of the version the generator last created or proposed. They belong to a person
    and are never overwritten or removed.
``settings``
    exactly the list items, hook matcher groups, scalars and containers the generator
    added to ``.claude/settings.json`` (items that were already there are not recorded).
``claude_block`` / ``gitignore_block``
    the SHA-256 of the generator's marker block in ``CLAUDE.md`` / the project
    ``.gitignore`` and the separator bytes it added. Neither file is ever owned whole.

Generated files carry no timestamp; ``applied_at`` is stored only when a caller passes it.
``.claude/settings.local.json``, user and managed settings, ``changes/``, ``audit/``,
``.cab/`` and every other ``simtenant/`` or ``docs/`` path can never be recorded as owned.
"""

from __future__ import annotations

import codecs
import datetime
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

__all__ = [
    "CLAUDE_PATH",
    "CREATE_ONCE",
    "DEMO_FILES",
    "GENERATOR_NAME",
    "GITIGNORE_PATH",
    "LIST_KEYS",
    "OWNED_COMMAND_PREFIXES",
    "OWNED_FILES",
    "OWNED_PREFIXES",
    "PERSON_FILES",
    "PROPOSAL_SUFFIX",
    "QUIET_FILES",
    "SCHEMA",
    "SETTINGS_LOCAL_PATH",
    "SETTINGS_PATH",
    "BlockRecord",
    "ClaudeBlockRecord",
    "Manifest",
    "ManifestError",
    "SettingsContribution",
    "SetupDataError",
    "canon",
    "check_applied_at",
    "check_event_name",
    "check_json_key",
    "check_rel_path",
    "check_sha256",
    "check_version",
    "config_file_matches",
    "dump_json_document",
    "dump_manifest",
    "group_ownership",
    "is_owned_command",
    "load_manifest",
    "loads_strict",
    "manifest_to_obj",
    "norm_path",
    "path_class",
    "sha256_hex",
    "validate_owned_group",
]

SCHEMA = 1
GENERATOR_NAME = "cab-of-one"
MAX_JSON_BYTES = 1 << 20
MAX_JSON_DEPTH = 64
MAX_PATH_CHARS = 512

SETTINGS_PATH = ".claude/settings.json"
SETTINGS_LOCAL_PATH = ".claude/settings.local.json"
CLAUDE_PATH = "CLAUDE.md"
GITIGNORE_PATH = ".gitignore"
PROPOSAL_SUFFIX = ".cab-new"
OWNED_PREFIXES = (".claude/agents/", ".claude/hooks/cab/", ".claude/skills/")
# The fictional Contoso tenant of the reference demo (rules: simtenant-demo module). Exactly
# these two files; anything else below simtenant/ (state, other seeds, caches, a person's
# own files) is never generator-owned and is refused as a generated path.
DEMO_FILES = ("simtenant/simtenant.py", "simtenant/seed/contoso.json")
# Exact generator-owned files outside the owned prefixes: the identity guide (DESIGN §10-4-4)
# and the demo files. Deliberately a closed list of exact, case-sensitive paths, never a
# folder: no arbitrary top-level writes.
OWNED_FILES = ("docs/identity.md",) + DEMO_FILES
# Create once, then a person's file. A changed generator version becomes a .cab-new proposal.
PERSON_FILES = ("policy/policy.toml", "policy/standard-changes.toml")
# Create once, then a person's file. Never proposed again (evidence READMEs, handoff notes).
QUIET_FILES = ("HANDOFF.md", "PROGRESS.md", "audit/README.md", "changes/README.md")
CREATE_ONCE = frozenset(PERSON_FILES + QUIET_FILES)
LIST_KEYS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "permissions.additionalDirectories": ("permissions", "additionalDirectories"),
        "permissions.allow": ("permissions", "allow"),
        "permissions.ask": ("permissions", "ask"),
        "permissions.deny": ("permissions", "deny"),
    }
)
# A hook command is the generator's only when it starts with one of these exact prefixes and
# then names a plain relative file below .claude/hooks/cab/ (optionally followed by ASCII args).
OWNED_COMMAND_PREFIXES = (
    '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/',
    'python3 "$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/',
)
CLAUDE_LEADS = frozenset({"", "\n", "\n\n", "\r\n", "\r\n\r\n"})
CLAUDE_TRAILS = frozenset({"", "\n", "\r\n"})

_SHA_RE = re.compile(r"[0-9a-f]{64}")
_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
_EVENT_RE = re.compile(r"[A-Z][A-Za-z]{0,63}")
_STAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_COMMAND_TAIL_RE = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*(?: [ -~]*)?"
)
_UNSAFE_KEYS = frozenset({"__proto__"})
_HOOK_GROUP_KEYS = frozenset({"matcher", "hooks"})
_EVIDENCE_ROOTS = ("audit", "changes")
_RESERVED_ROOTS = (".cab", ".git")
_LIST_PATHS = frozenset(LIST_KEYS.values())
_TOP_KEYS = frozenset(
    {
        "applied_at",
        "claude_block",
        "files",
        "generator",
        "gitignore_block",
        "offered",
        "profile_sha256",
        "schema",
        "settings",
    }
)
_GENERATOR_KEYS = frozenset({"name", "version"})
_SETTINGS_KEYS = frozenset({"containers", "file_created", "hook_groups", "lists", "scalars"})
_SCALAR_KEYS = frozenset({"path", "value"})
_BLOCK_KEYS = frozenset({"file_created", "lead", "sha256", "trail"})


class SetupDataError(ValueError):
    """Input data is malformed or unsafe. ``code`` is a fixed, non-sensitive word."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class ManifestError(SetupDataError):
    """A manifest document or record is not valid schema 1."""


# --------------------------------------------------------------------------- identifiers


def sha256_hex(data: bytes) -> str:
    """Lower-case hex SHA-256 of exact ``bytes``."""
    if type(data) is not bytes:
        raise SetupDataError("bytes_required")
    return hashlib.sha256(data).hexdigest()


def check_sha256(value: object, code: str = "sha256_invalid") -> str:
    if type(value) is not str or not _SHA_RE.fullmatch(value):
        raise SetupDataError(code, repr(value)[:80])
    return value


def check_version(value: object) -> str:
    if type(value) is not str or not _VERSION_RE.fullmatch(value):
        raise SetupDataError("version_invalid", repr(value)[:80])
    return value


def check_event_name(value: object) -> str:
    if type(value) is not str or not _EVENT_RE.fullmatch(value):
        raise SetupDataError("hook_event_invalid", repr(value)[:80])
    return value


def check_applied_at(value: object) -> str | None:
    """None, or an explicit UTC stamp ``YYYY-MM-DDTHH:MM:SSZ`` supplied by the caller."""
    if value is None:
        return None
    if type(value) is not str or not _STAMP_RE.fullmatch(value):
        raise SetupDataError("applied_at_invalid", repr(value)[:80])
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SetupDataError("applied_at_invalid", value) from None
    return value


# --------------------------------------------------------------------------- paths


def norm_path(path: str) -> str:
    """Comparison form for case-insensitive, normalising file systems (macOS default)."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", path).casefold())


def check_rel_path(path: object) -> str:
    """A normalised project-relative path: ASCII ``[A-Za-z0-9._-]`` components joined by
    ``/``, no empty, ``.`` or ``..`` component, no ``.cab-new`` suffix (reserved for
    proposals). Raises ``SetupDataError``; never rewrites the path."""
    if type(path) is not str:
        raise SetupDataError("path_type", repr(path)[:80])
    if not path or len(path) > MAX_PATH_CHARS:
        raise SetupDataError("path_length", path[:80])
    for part in path.split("/"):
        if part in (".", "..") or not _COMPONENT_RE.fullmatch(part):
            raise SetupDataError("path_unsafe", path[:200])
        if part.endswith(PROPOSAL_SUFFIX):
            raise SetupDataError("path_reserved", path[:200])
    return path


def path_class(path: object) -> str:
    """Merge class of a generated path: settings, claude, gitignore, person, quiet or owned.

    Anything else is refused: ``.claude/settings.local.json`` (path_forbidden), evidence
    under ``changes/``/``audit/`` other than their READMEs (path_evidence), ``.cab/`` and
    ``.git/`` (path_reserved) and every other location (path_not_allowed), including any
    ``docs/`` or ``simtenant/`` path that is not exactly in ``OWNED_FILES`` (case-sensitive).
    """
    checked = check_rel_path(path)
    folded = norm_path(checked)
    first = folded.split("/", 1)[0]
    if folded == norm_path(SETTINGS_LOCAL_PATH):
        raise SetupDataError("path_forbidden", checked)
    if checked == SETTINGS_PATH:
        return "settings"
    if checked == CLAUDE_PATH:
        return "claude"
    if checked == GITIGNORE_PATH:
        return "gitignore"
    if checked in PERSON_FILES:
        return "person"
    if checked in QUIET_FILES:
        return "quiet"
    if first in _EVIDENCE_ROOTS:
        raise SetupDataError("path_evidence", checked)
    if first in _RESERVED_ROOTS:
        raise SetupDataError("path_reserved", checked)
    if checked.startswith(OWNED_PREFIXES) or checked in OWNED_FILES:
        return "owned"
    raise SetupDataError("path_not_allowed", checked)


# --------------------------------------------------------------------------- strict JSON


def _check_text(value: str, code: str) -> None:
    if "\x00" in value:
        raise SetupDataError(code, "nul")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise SetupDataError(code, "surrogate") from None


def check_json_key(key: object) -> str:
    """A non-empty object key without NUL, lone surrogates or ``__proto__``."""
    if type(key) is not str or not key:
        raise SetupDataError("json_key_unsafe", repr(key)[:80])
    _check_text(key, "json_key_unsafe")
    if key in _UNSAFE_KEYS:
        raise SetupDataError("json_key_unsafe", key)
    return key


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        check_json_key(key)
        if key in out:
            raise SetupDataError("json_duplicate_key", key[:80])
        out[key] = value
    return out


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value) or repr(value) != token:
        raise SetupDataError("json_number_not_canonical", token[:40])
    return value


def _parse_int(token: str) -> int:
    if token == "-0":
        raise SetupDataError("json_number_not_canonical", token)
    return int(token)


def _parse_constant(token: str) -> Any:
    raise SetupDataError("json_constant", token)


def _check_tree(value: Any, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise SetupDataError("json_too_deep")
    kind = type(value)
    if kind is dict:
        for item in value.values():
            _check_tree(item, depth + 1)
    elif kind is list:
        for item in value:
            _check_tree(item, depth + 1)
    elif kind is str:
        _check_text(value, "json_string_unsafe")


def loads_strict(data: bytes) -> Any:
    """Parse UTF-8 JSON bytes, refusing anything that would be silently normalised.

    Refused: non-bytes, over 1 MiB, a BOM, invalid UTF-8, duplicate keys, empty or
    ``__proto__`` keys, NaN/Infinity, numbers that overflow or would not re-serialise to
    the same text (``1.50``, ``1e5``, ``-0``), NUL or lone surrogates in strings, nesting
    deeper than 64 and trailing data. Raises ``SetupDataError``.
    """
    if type(data) is not bytes:
        raise SetupDataError("json_bytes_required")
    if len(data) > MAX_JSON_BYTES:
        raise SetupDataError("json_too_large")
    if data.startswith(codecs.BOM_UTF8):
        raise SetupDataError("json_bom")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SetupDataError("json_not_utf8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_parse_float,
            parse_int=_parse_int,
            parse_constant=_parse_constant,
        )
    except SetupDataError:
        raise
    except (ValueError, RecursionError):
        raise SetupDataError("json_invalid") from None
    _check_tree(value, 0)
    return value


def canon(value: Any) -> str:
    """Canonical, type-strict JSON text (sorted keys): ``true`` != ``1`` != ``1.0``."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def dump_json_document(value: Any) -> bytes:
    """Settings file bytes: insertion order kept, 2-space indent, UTF-8, LF, final newline."""
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- hook ownership


def is_owned_command(command: object) -> bool:
    """True only for an anchored project-installed command below ``.claude/hooks/cab/``."""
    if type(command) is not str:
        return False
    for prefix in OWNED_COMMAND_PREFIXES:
        if command.startswith(prefix):
            return _COMMAND_TAIL_RE.fullmatch(command[len(prefix) :]) is not None
    return False


def group_ownership(group: object) -> str:
    """``owned`` (every command is ours), ``mixed`` (some are) or ``user`` (none are)."""
    if type(group) is not dict:
        return "user"
    hooks = group.get("hooks")
    if type(hooks) is not list or not hooks:
        return "user"
    flags = [type(entry) is dict and is_owned_command(entry.get("command")) for entry in hooks]
    if all(flags):
        return "owned"
    if any(flags):
        return "mixed"
    return "user"


def validate_owned_group(group: object) -> str:
    """Validate one generator matcher group and return its canonical JSON text.

    Shape: ``{"matcher"?: str, "hooks": [{"type": "command", "command": <owned>, ...}]}``
    with only string, integer or boolean values in each hook entry.
    """
    if type(group) is not dict or "hooks" not in group or not set(group) <= _HOOK_GROUP_KEYS:
        raise SetupDataError("hook_group_shape")
    if "matcher" in group:
        if type(group["matcher"]) is not str:
            raise SetupDataError("hook_group_matcher")
        _check_text(group["matcher"], "hook_group_matcher")
    hooks = group["hooks"]
    if type(hooks) is not list or not hooks:
        raise SetupDataError("hook_group_empty")
    for entry in hooks:
        if type(entry) is not dict or entry.get("type") != "command":
            raise SetupDataError("hook_entry_shape")
        if not is_owned_command(entry.get("command")):
            raise SetupDataError("hook_command_not_owned", str(entry.get("command"))[:120])
        for key, value in entry.items():
            check_json_key(key)
            if type(value) not in (str, int, bool):
                raise SetupDataError("hook_entry_value", key)
            if type(value) is str:
                _check_text(value, "hook_entry_value")
    return canon(group)


# --------------------------------------------------------------------------- records


def _seq(value: object, code: str) -> tuple[Any, ...]:
    if type(value) not in (list, tuple):
        raise SetupDataError(code, "type")
    return tuple(value)  # type: ignore[arg-type]


def _text_tuple(value: object, code: str) -> tuple[str, ...]:
    items = _seq(value, code)
    if not items:
        raise SetupDataError(code, "empty")
    for item in items:
        if type(item) is not str:
            raise SetupDataError(code, "type")
        _check_text(item, code)
    if len(set(items)) != len(items):
        raise SetupDataError(code, "duplicate")
    return items


def _key_path(value: object, code: str) -> tuple[str, ...]:
    parts = _seq(value, code)
    if not parts:
        raise SetupDataError(code, "empty")
    for part in parts:
        check_json_key(part)
    return parts


def _overlaps_list(path: tuple[str, ...]) -> bool:
    return any(path[: len(lp)] == lp or lp[: len(path)] == path for lp in _LIST_PATHS)


@dataclass(frozen=True)
class SettingsContribution:
    """What the generator added to ``.claude/settings.json``.

    ``lists``        list key name (``permissions.deny`` ...) -> items the generator appended
    ``hook_groups``  event -> canonical JSON text of each matcher group it appended
    ``scalars``      (key path, canonical JSON of the scalar) pairs it set
    ``containers``   key paths of objects/lists it created (pruned only when empty)
    ``file_created`` the generator created the settings file itself
    """

    lists: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    hook_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    scalars: tuple[tuple[tuple[str, ...], str], ...] = ()
    containers: tuple[tuple[str, ...], ...] = ()
    file_created: bool = False

    def __post_init__(self) -> None:
        try:
            lists, hooks, scalars, containers = self._checked()
        except ManifestError:
            raise
        except SetupDataError as exc:
            raise ManifestError(exc.code, exc.detail) from None
        object.__setattr__(self, "lists", MappingProxyType(lists))
        object.__setattr__(self, "hook_groups", MappingProxyType(hooks))
        object.__setattr__(self, "scalars", scalars)
        object.__setattr__(self, "containers", containers)

    def _checked(self) -> tuple[dict, dict, tuple, tuple]:
        if not isinstance(self.lists, Mapping) or not isinstance(self.hook_groups, Mapping):
            raise SetupDataError("settings_record_type")
        lists: dict[str, tuple[str, ...]] = {}
        for name, items in self.lists.items():
            if type(name) is not str or name not in LIST_KEYS:
                raise SetupDataError("settings_list_key", repr(name)[:80])
            lists[name] = _text_tuple(items, "settings_list_items")
        hooks: dict[str, tuple[str, ...]] = {}
        for event, groups in self.hook_groups.items():
            check_event_name(event)
            texts = _text_tuple(groups, "settings_hook_groups")
            for text in texts:
                if validate_owned_group(loads_strict(text.encode("utf-8"))) != text:
                    raise SetupDataError("settings_hook_group_not_canonical", event)
            hooks[event] = texts
        scalars: dict[tuple[str, ...], str] = {}
        for entry in _seq(self.scalars, "settings_scalars"):
            pair = _seq(entry, "settings_scalar_entry")
            if len(pair) != 2 or type(pair[1]) is not str:
                raise SetupDataError("settings_scalar_entry")
            path = _key_path(pair[0], "settings_scalar_path")
            if path[0] == "hooks" or _overlaps_list(path):
                raise SetupDataError("settings_scalar_path", ".".join(path))
            _check_text(pair[1], "settings_scalar_value")
            value = loads_strict(pair[1].encode("utf-8"))
            if not (value is None or type(value) in (str, int, bool)) or canon(value) != pair[1]:
                raise SetupDataError("settings_scalar_value", ".".join(path))
            if path in scalars:
                raise SetupDataError("settings_scalar_duplicate", ".".join(path))
            scalars[path] = pair[1]
        containers: set[tuple[str, ...]] = set()
        for entry in _seq(self.containers, "settings_containers"):
            path = _key_path(entry, "settings_container_path")
            if path in containers:
                raise SetupDataError("settings_container_duplicate", ".".join(path))
            containers.add(path)
        if type(self.file_created) is not bool:
            raise SetupDataError("settings_file_created")
        return (
            dict(sorted(lists.items())),
            dict(sorted(hooks.items())),
            tuple(sorted(scalars.items())),
            tuple(sorted(containers)),
        )

    @property
    def is_empty(self) -> bool:
        return not (self.lists or self.hook_groups or self.scalars or self.containers)


@dataclass(frozen=True)
class BlockRecord:
    """A generator marker block (``CLAUDE.md`` or ``.gitignore``): SHA-256 of BEGIN..END,
    the separator bytes added before (``lead``) and after (``trail``) it, and whether the
    generator created the file itself."""

    sha256: str
    lead: str = ""
    trail: str = ""
    file_created: bool = False

    def __post_init__(self) -> None:
        try:
            check_sha256(self.sha256, "block_sha256_invalid")
        except SetupDataError as exc:
            raise ManifestError(exc.code, exc.detail) from None
        if type(self.lead) is not str or self.lead not in CLAUDE_LEADS:
            raise ManifestError("block_lead")
        if type(self.trail) is not str or self.trail not in CLAUDE_TRAILS:
            raise ManifestError("block_trail")
        if type(self.file_created) is not bool:
            raise ManifestError("block_file_created")


ClaudeBlockRecord = BlockRecord


def _path_map(value: object, *, owned: bool) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise SetupDataError("path_map_type")
    out: dict[str, str] = {}
    seen: dict[str, str] = {}
    for path, digest in value.items():
        if owned:
            try:
                kind = path_class(path)
            except SetupDataError as exc:
                raise SetupDataError("owned_path_refused", f"{exc.code}: {path!r}"[:200]) from None
            if kind != "owned":
                raise SetupDataError("owned_path_refused", f"{kind}: {path}")
        elif type(path) is not str or path not in CREATE_ONCE:
            raise SetupDataError("offered_path_refused", repr(path)[:200])
        check_sha256(digest, "file_sha256_invalid")
        folded = norm_path(path)
        if folded in seen:
            raise SetupDataError("path_case_collision", f"{seen[folded]} / {path}")
        seen[folded] = path
        out[path] = digest
    return dict(sorted(out.items()))


@dataclass(frozen=True)
class Manifest:
    """Schema-1 record of generator ownership in one project. Immutable once built."""

    generator_version: str
    profile_sha256: str
    files: Mapping[str, str] = field(default_factory=dict)
    offered: Mapping[str, str] = field(default_factory=dict)
    settings: SettingsContribution = field(default_factory=SettingsContribution)
    claude_block: BlockRecord | None = None
    applied_at: str | None = None
    gitignore_block: BlockRecord | None = None

    def __post_init__(self) -> None:
        try:
            check_version(self.generator_version)
            check_sha256(self.profile_sha256, "profile_sha256_invalid")
            files = _path_map(self.files, owned=True)
            offered = _path_map(self.offered, owned=False)
            if type(self.settings) is not SettingsContribution:
                raise SetupDataError("settings_record_type")
            for block in (self.claude_block, self.gitignore_block):
                if block is not None and type(block) is not BlockRecord:
                    raise SetupDataError("block_record_type")
            check_applied_at(self.applied_at)
        except ManifestError:
            raise
        except SetupDataError as exc:
            raise ManifestError(exc.code, exc.detail) from None
        object.__setattr__(self, "files", MappingProxyType(files))
        object.__setattr__(self, "offered", MappingProxyType(offered))

    def same_content(self, other: Manifest) -> bool:
        """Equal apart from ``applied_at`` (used for "nothing to do")."""
        return replace(self, applied_at=None) == replace(other, applied_at=None)


# --------------------------------------------------------------------------- serialisation


def _block_obj(block: BlockRecord | None) -> dict[str, Any] | None:
    if block is None:
        return None
    return {
        "sha256": block.sha256,
        "lead": block.lead,
        "trail": block.trail,
        "file_created": block.file_created,
    }


def manifest_to_obj(manifest: Manifest) -> dict[str, Any]:
    settings = manifest.settings
    return {
        "schema": SCHEMA,
        "generator": {"name": GENERATOR_NAME, "version": manifest.generator_version},
        "profile_sha256": manifest.profile_sha256,
        "files": dict(manifest.files),
        "offered": dict(manifest.offered),
        "settings": {
            "file_created": settings.file_created,
            "lists": {name: list(items) for name, items in settings.lists.items()},
            "hook_groups": {
                event: [json.loads(text) for text in texts]
                for event, texts in settings.hook_groups.items()
            },
            "scalars": [
                {"path": list(path), "value": json.loads(text)} for path, text in settings.scalars
            ],
            "containers": [list(path) for path in settings.containers],
        },
        "claude_block": _block_obj(manifest.claude_block),
        "gitignore_block": _block_obj(manifest.gitignore_block),
        "applied_at": manifest.applied_at,
    }


def dump_manifest(manifest: Manifest) -> bytes:
    """Deterministic bytes: sorted keys, 2-space indent, UTF-8, LF, final newline."""
    if type(manifest) is not Manifest:
        raise ManifestError("manifest_type")
    text = json.dumps(manifest_to_obj(manifest), sort_keys=True, indent=2, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def _exact(obj: object, keys: frozenset[str], where: str) -> dict[str, Any]:
    if type(obj) is not dict:
        raise ManifestError("manifest_type", where)
    unknown = sorted(set(obj) - keys)
    if unknown:
        raise ManifestError("manifest_unknown_key", f"{where}.{unknown[0]}"[:120])
    missing = sorted(keys - set(obj))
    if missing:
        raise ManifestError("manifest_missing_key", f"{where}.{missing[0]}")
    return obj


def _typed(value: object, kind: type, where: str) -> Any:
    if type(value) is not kind:
        raise ManifestError("manifest_type", where)
    return value


def _from_obj(obj: object) -> Manifest:
    top = _exact(obj, _TOP_KEYS, "manifest")
    schema = top["schema"]
    if type(schema) is not int or schema != SCHEMA:
        raise ManifestError("manifest_schema", repr(schema)[:40])
    generator = _exact(top["generator"], _GENERATOR_KEYS, "generator")
    if generator["name"] != GENERATOR_NAME or type(generator["name"]) is not str:
        raise ManifestError("manifest_generator", repr(generator["name"])[:80])
    settings = _exact(top["settings"], _SETTINGS_KEYS, "settings")
    hook_groups: dict[str, tuple[str, ...]] = {}
    for event, groups in _typed(settings["hook_groups"], dict, "settings.hook_groups").items():
        hook_groups[event] = tuple(
            validate_owned_group(group) for group in _typed(groups, list, "settings.hook_groups")
        )
    scalars = []
    for raw in _typed(settings["scalars"], list, "settings.scalars"):
        entry = _exact(raw, _SCALAR_KEYS, "settings.scalars")
        key_path = _typed(entry["path"], list, "settings.scalars.path")
        scalars.append((key_path, canon(entry["value"])))
    return Manifest(
        generator_version=generator["version"],
        profile_sha256=top["profile_sha256"],
        files=_typed(top["files"], dict, "files"),
        offered=_typed(top["offered"], dict, "offered"),
        settings=SettingsContribution(
            lists=_typed(settings["lists"], dict, "settings.lists"),
            hook_groups=hook_groups,
            scalars=tuple(scalars),
            containers=tuple(_typed(settings["containers"], list, "settings.containers")),
            file_created=settings["file_created"],
        ),
        claude_block=_block_from(top["claude_block"], "claude_block"),
        applied_at=top["applied_at"],
        gitignore_block=_block_from(top["gitignore_block"], "gitignore_block"),
    )


def _block_from(obj: object, where: str) -> BlockRecord | None:
    if obj is None:
        return None
    fields = _exact(obj, _BLOCK_KEYS, where)
    return BlockRecord(
        sha256=fields["sha256"],
        lead=fields["lead"],
        trail=fields["trail"],
        file_created=fields["file_created"],
    )


def load_manifest(data: bytes) -> Manifest:
    """Parse and validate ``.cab/manifest.json`` bytes. Raises ``ManifestError``.

    Unknown or missing keys at any level, schema other than 1, invalid hashes, unsafe or
    case-colliding paths, ownership of settings/local/evidence/state paths, foreign hook
    commands and non-canonical scalars are all refused; nothing is normalised silently
    except sorting of the record's own maps.
    """
    try:
        obj = loads_strict(data)
    except SetupDataError as exc:
        raise ManifestError("manifest_json", exc.code) from None
    try:
        return _from_obj(obj)
    except ManifestError:
        raise
    except SetupDataError as exc:
        raise ManifestError(exc.code, exc.detail) from None


# --------------------------------------------------------------------------- config verifier


_ABSENT = object()


def _dig(doc: Any, path: tuple[str, ...]) -> Any:
    node = doc
    for key in path:
        if type(node) is not dict or key not in node:
            return _ABSENT
        node = node[key]
    return node


def _settings_hold(doc: Any, record: SettingsContribution, required_deny: tuple[str, ...]) -> bool:
    if type(doc) is not dict:
        return False
    if "disableAllHooks" in doc and doc["disableAllHooks"] is not False:
        return False
    if "sandbox" in doc:
        sandbox = doc["sandbox"]
        if type(sandbox) is not dict or ("enabled" in sandbox and sandbox["enabled"] is not True):
            return False
    for key in ("allowManagedHooksOnly", "allowManagedPermissionRulesOnly"):
        if key in doc and doc[key] is not False:
            return False
    deny = _dig(doc, ("permissions", "deny"))
    if required_deny and (type(deny) is not list or not set(required_deny) <= set(deny)):
        return False
    for name, items in record.lists.items():
        node = _dig(doc, LIST_KEYS[name])
        if type(node) is not list or not set(items) <= {i for i in node if type(i) is str}:
            return False
    hooks = doc.get("hooks")
    for event, texts in record.hook_groups.items():
        groups = hooks.get(event) if type(hooks) is dict else None
        if type(groups) is not list:
            return False
        present = set()
        for group in groups:
            try:
                present.add(canon(group))
            except (TypeError, ValueError):
                continue
        if not set(texts) <= present:
            return False
    for path, text in record.scalars:
        value = _dig(doc, path)
        if value is _ABSENT:
            return False
        try:
            if canon(value) != text:
                return False
        except (TypeError, ValueError):
            return False
    return True


def config_file_matches(
    manifest: Manifest,
    rel: str,
    data: bytes | None,
    *,
    required_deny: tuple[str, ...] = (),
) -> bool:
    """Pure core of the ConfigChange ``verifier(project_root, rel) -> bool`` (S10 contract).

    ``data`` is the changed file's bytes (None when it is gone or could not be read safely).

    - ``.claude/settings.json``: True only when the file is strict JSON, does not switch
      hooks or the sandbox off, does not set the managed-only keys, still holds every
      ``required_deny`` rule (pass ``render.FLOOR_DENY``) and every list item, hook group
      and scalar this manifest records as the generator's contribution. Items that were
      already in a person's file before the first apply are not recorded by the merge, so
      only ``required_deny`` protects those; hook groups that pre-existed are not checked.
    - a file under ``.claude/skills/``: True only when the manifest owns that exact path
      and ``data`` hashes to the recorded SHA-256. A person's own skill (not in the
      manifest), a deleted skill or an edited one is False (the session holds the change).
    - anything else: False.

    Never raises; any malformed input is False (fail closed).
    """
    try:
        if type(manifest) is not Manifest or type(rel) is not str:
            return False
        if data is not None and type(data) is not bytes:
            return False
        if type(required_deny) is not tuple or any(type(r) is not str for r in required_deny):
            return False
        if rel == SETTINGS_PATH:
            if data is None:
                return False
            try:
                doc = loads_strict(data)
            except SetupDataError:
                return False
            return _settings_hold(doc, manifest.settings, required_deny)
        if rel.startswith(".claude/skills/"):
            try:
                check_rel_path(rel)
            except SetupDataError:
                return False
            digest = manifest.files.get(rel)
            return digest is not None and data is not None and sha256_hex(data) == digest
        return False
    except Exception:
        return False
