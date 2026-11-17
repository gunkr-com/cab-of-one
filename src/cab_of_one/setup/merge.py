"""Pure merge and uninstall planning for ``cab setup`` (S9, DESIGN §10-3).

Nothing here touches the file system. Callers pass bytes and node kinds in and get back a
plan of exact byte operations; ``apply``/``uninstall`` (not written yet) perform it.

Inputs
    ``bundle``    rendered output: project-relative path -> bytes. Accepted paths are those
                  of :func:`manifest.path_class`. ``CLAUDE.md`` is one complete block from
                  :func:`make_claude_block`; ``.claude/settings.json`` is the generator's
                  own settings document (its contributions), never an already-merged file.
                  ``.gitignore`` is one block from :func:`make_gitignore_block`; the
                  person's ``.gitignore`` is never overwritten whole.
    ``existing``  the project now, for every path from :func:`paths_to_inspect`: a regular
                  single-link file -> its bytes; a directory, a symlink (never followed) or
                  anything else (hard link, device, fifo) -> :class:`NodeKind`. A missing
                  key means the path does not exist.
    ``scopes``    read-only bytes of ``.claude/settings.local.json``, ``~/.claude/settings.json``
                  and managed settings. Inspected for blockers, never output.

Outcome (:class:`MergePlan`)
    ``blockers``  stop the whole merge: the plan then has no actions and no manifest.
    ``conflicts`` never overwrite a person's bytes. A modified owned file, ``CLAUDE.md`` or
                  ``.gitignore`` block gets a ``<path>.cab-new`` proposal that only an explicit
                  ``take_new`` path resolves; policy files only ever get proposals.
    ``actions``   sorted, exact and complete (create, update, remove, propose).
    ``manifest``  the record the caller writes after every action succeeded.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from .manifest import (
    CLAUDE_PATH,
    GITIGNORE_PATH,
    LIST_KEYS,
    PROPOSAL_SUFFIX,
    SETTINGS_LOCAL_PATH,
    SETTINGS_PATH,
    BlockRecord,
    Manifest,
    SettingsContribution,
    SetupDataError,
    canon,
    check_applied_at,
    check_event_name,
    check_json_key,
    check_rel_path,
    check_sha256,
    check_version,
    dump_json_document,
    group_ownership,
    loads_strict,
    norm_path,
    path_class,
    sha256_hex,
    validate_owned_group,
)

__all__ = [
    "BEGIN_MARKER",
    "END_MARKER",
    "GITIGNORE_BEGIN",
    "GITIGNORE_END",
    "GITIGNORE_PATTERNS",
    "RESOLVABLE_CODES",
    "Action",
    "Issue",
    "MergePlan",
    "NodeKind",
    "SettingsScopes",
    "UninstallPlan",
    "make_claude_block",
    "make_gitignore_block",
    "paths_to_inspect",
    "plan_merge",
    "plan_uninstall",
]

BEGIN_MARKER = b"<!-- cab-of-one:begin -->"
END_MARKER = b"<!-- cab-of-one:end -->"
GITIGNORE_BEGIN = b"# cab-of-one:begin"
GITIGNORE_END = b"# cab-of-one:end"
# Local secrets (exact-input HMAC/salt under .cab/state/), backups and setup staging must
# never reach version control or public evidence.
GITIGNORE_PATTERNS = (".cab/state/", ".cab/backups/", ".cab/setup/")
_LOOSE_MARKERS = (b"cab-of-one:begin", b"cab-of-one:end")
_NEGATED_CAB = re.compile(rb"(?:^|[/*])\.cab(?:/|\*|$)")
RESOLVABLE_CODES = frozenset(
    {
        "claude_block_missing",
        "claude_block_modified",
        "gitignore_block_missing",
        "gitignore_block_modified",
        "owned_missing",
        "owned_modified",
    }
)
_SAFETY_ROOTS: tuple[tuple[str, ...], ...] = (
    ("allowManagedHooksOnly",),
    ("allowManagedPermissionRulesOnly",),
    ("disableAllHooks",),
    ("permissions", "defaultMode"),
    ("permissions", "disableBypassPermissionsMode"),
    ("sandbox",),
)
_LIST_NAMES = {path: name for name, path in LIST_KEYS.items()}
_LIST_PATHS = frozenset(_LIST_NAMES)
_MISSING = object()


class NodeKind(Enum):
    """A non-regular entry as seen by ``lstat`` (the caller never follows links)."""

    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


@dataclass(frozen=True)
class SettingsScopes:
    """Read-only settings from other scopes. Inspected for blockers only, never written."""

    local: bytes | None = None
    user: bytes | None = None
    managed: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        for value in (self.local, self.user):
            if value is not None and type(value) is not bytes:
                raise SetupDataError("scope_bytes_required")
        if type(self.managed) is not tuple or any(type(v) is not bytes for v in self.managed):
            raise SetupDataError("scope_bytes_required")


@dataclass(frozen=True, order=True)
class Issue:
    """A blocker, conflict, drift or note. ``code`` is fixed; ``detail`` is a key path or hint."""

    code: str
    path: str
    detail: str = ""


@dataclass(frozen=True)
class Action:
    """One exact operation. ``create``/``update``/``propose`` write ``data``; ``remove``
    unlinks ``path`` itself (never a link target)."""

    kind: str
    path: str
    data: bytes | None = None
    reason: str = ""


@dataclass(frozen=True)
class MergePlan:
    actions: tuple[Action, ...]
    blockers: tuple[Issue, ...]
    conflicts: tuple[Issue, ...]
    notes: tuple[Issue, ...]
    manifest: Manifest | None
    manifest_changed: bool

    @property
    def blocked(self) -> bool:
        return bool(self.blockers)

    @property
    def nothing_to_do(self) -> bool:
        return not (self.actions or self.blockers or self.conflicts or self.manifest_changed)

    @property
    def resolvable(self) -> tuple[str, ...]:
        """Paths an explicit ``take_new`` may resolve in a re-plan."""
        return tuple(sorted({i.path for i in self.conflicts if i.code in RESOLVABLE_CODES}))


@dataclass(frozen=True)
class UninstallPlan:
    actions: tuple[Action, ...]
    blockers: tuple[Issue, ...]
    drift: tuple[Issue, ...]
    notes: tuple[Issue, ...]


# --------------------------------------------------------------------------- small helpers


class _Tree:
    """The caller's view of the project, looked up exactly and case-insensitively."""

    def __init__(self, existing: object) -> None:
        if not isinstance(existing, Mapping):
            raise SetupDataError("existing_type")
        self._exact: dict[str, bytes | NodeKind] = {}
        self._folded: dict[str, list[str]] = {}
        for path, value in existing.items():
            if type(path) is not str or not path or "\x00" in path or path.startswith("/"):
                raise SetupDataError("existing_path_invalid", repr(path)[:80])
            if type(value) is not bytes and not isinstance(value, NodeKind):
                raise SetupDataError("existing_value_invalid", path[:200])
            self._exact[path] = value
            self._folded.setdefault(norm_path(path), []).append(path)

    def get(self, path: str) -> tuple[str, bytes | NodeKind | None]:
        """("absent", None), ("present", value) or ("case", None) for a spelling mismatch."""
        spellings = self._folded.get(norm_path(path))
        if not spellings:
            return "absent", None
        if spellings == [path]:
            return "present", self._exact[path]
        return "case", None


def _ancestors(path: str) -> list[str]:
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def _kind_code(kind: NodeKind) -> str:
    if kind is NodeKind.SYMLINK:
        return "target_symlink"
    if kind is NodeKind.DIRECTORY:
        return "target_is_directory"
    return "target_not_regular"


def _parent_issues(tree: _Tree, paths: Iterable[str]) -> list[Issue]:
    issues = []
    for path in paths:
        for parent in _ancestors(path):
            status, value = tree.get(parent)
            if status == "case":
                issues.append(Issue("case_collision", parent))
            elif status == "present" and value is not NodeKind.DIRECTORY:
                code = "parent_symlink" if value is NodeKind.SYMLINK else "parent_not_directory"
                issues.append(Issue(code, parent))
    return issues


def _kp(path: tuple[str, ...]) -> str:
    return ".".join(path)


def _get(doc: Any, path: tuple[str, ...]) -> Any:
    node = doc
    for key in path:
        if type(node) is not dict or key not in node:
            return _MISSING
        node = node[key]
    return node


def _delete(doc: Any, path: tuple[str, ...]) -> None:
    parent = _get(doc, path[:-1])
    if type(parent) is dict:
        parent.pop(path[-1], None)


def _canon_or_none(value: Any) -> str | None:
    try:
        return canon(value)
    except (TypeError, ValueError):
        return None


def _same_doc(a: Any, b: Any) -> bool:
    """Order-sensitive equality (key order is part of what a person sees)."""
    return json.dumps(a, ensure_ascii=False) == json.dumps(b, ensure_ascii=False)


def _last_str_index(node: list, item: str) -> int | None:
    for index in range(len(node) - 1, -1, -1):
        if type(node[index]) is str and node[index] == item:
            return index
    return None


def _last_group_index(node: list, text: str) -> int | None:
    for index in range(len(node) - 1, -1, -1):
        if _canon_or_none(node[index]) == text:
            return index
    return None


def _is_safety(path: tuple[str, ...]) -> bool:
    return any(path[: len(root)] == root for root in _SAFETY_ROOTS)


# --------------------------------------------------------------------------- settings


@dataclass
class _Desired:
    lists: dict[tuple[str, ...], list[str]] = field(default_factory=dict)
    groups: dict[str, list[tuple[str, Any]]] = field(default_factory=dict)
    scalars: list[tuple[tuple[str, ...], Any]] = field(default_factory=list)
    containers: set[tuple[str, ...]] = field(default_factory=set)


def _ours_hooks(value: Any, desired: _Desired) -> None:
    if type(value) is not dict or not value:
        raise SetupDataError("hooks_shape")
    desired.containers.add(("hooks",))
    for event, groups in value.items():
        check_event_name(event)
        if type(groups) is not list or not groups:
            raise SetupDataError("hooks_shape", event)
        entries: list[tuple[str, Any]] = []
        for group in groups:
            text = validate_owned_group(group)
            if any(text == seen for seen, _ in entries):
                raise SetupDataError("hook_group_duplicate", event)
            entries.append((text, group))
        desired.groups[event] = entries
        desired.containers.add(("hooks", event))


def _walk_ours(node: dict, path: tuple[str, ...], desired: _Desired) -> None:
    for key, value in node.items():
        check_json_key(key)
        here = path + (key,)
        if here == ("hooks",):
            _ours_hooks(value, desired)
        elif here in _LIST_PATHS:
            if (
                type(value) is not list
                or not value
                or any(type(item) is not str for item in value)
                or len(set(value)) != len(value)
            ):
                raise SetupDataError("list_entries", _kp(here))
            desired.lists[here] = list(value)
            desired.containers.add(here)
        elif type(value) is dict:
            desired.containers.add(here)
            _walk_ours(value, here, desired)
        elif value is None or type(value) in (str, int, bool):
            desired.scalars.append((here, value))
        else:
            raise SetupDataError("value_type", _kp(here))


def _parse_ours(doc: Any) -> _Desired:
    """The generator's settings document: what it wants present. Refuses unsafe intent."""
    if type(doc) is not dict:
        raise SetupDataError("top_level")
    desired = _Desired()
    _walk_ours(doc, (), desired)
    if doc.get("disableAllHooks", False) is not False:
        raise SetupDataError("disables_hooks")
    if "sandbox" in doc:
        sandbox = doc["sandbox"]
        if type(sandbox) is not dict or sandbox.get("enabled", True) is not True:
            raise SetupDataError("disables_sandbox")
    for key in ("allowManagedHooksOnly", "allowManagedPermissionRulesOnly"):
        if key in doc:
            raise SetupDataError("managed_only_key", key)
    return desired


def _scope_blockers(doc: Any, label: str, *, managed: bool) -> list[Issue]:
    """Settings that silently switch the harness off. Only an explicit ``false`` is safe."""
    if type(doc) is not dict:
        return [Issue("scope_unreadable", label, "top_level")]
    issues = []
    if "disableAllHooks" in doc and doc["disableAllHooks"] is not False:
        issues.append(Issue("hooks_disabled", label))
    if "sandbox" in doc:
        sandbox = doc["sandbox"]
        if type(sandbox) is not dict:
            issues.append(Issue("sandbox_unreadable", label))
        elif "enabled" in sandbox and sandbox["enabled"] is not True:
            issues.append(Issue("sandbox_disabled", label))
    if managed:
        for key, code in (
            ("allowManagedHooksOnly", "managed_hooks_only"),
            ("allowManagedPermissionRulesOnly", "managed_rules_only"),
        ):
            if key in doc and doc[key] is not False:
                issues.append(Issue(code, label))
    return issues


def _ensure(
    doc: dict,
    path: tuple[str, ...],
    kind: type,
    created: list[tuple[str, ...]],
    blockers: list[Issue],
) -> Any:
    """Container at ``path`` (``kind`` at the end, objects above), creating missing ones."""
    node: Any = doc
    for depth, key in enumerate(path):
        want = kind if depth == len(path) - 1 else dict
        here = path[: depth + 1]
        if key not in node:
            node[key] = want()
            created.append(here)
        child = node[key]
        if type(child) is not want:
            blockers.append(Issue("settings_type_conflict", SETTINGS_PATH, _kp(here)))
            return None
        node = child
    return node


def _strip(
    doc: dict,
    lists: Mapping[tuple[str, ...], Iterable[str]],
    groups: Mapping[str, Iterable[str]],
    scalars: Iterable[tuple[tuple[str, ...], str]],
) -> list[Issue]:
    """Remove exactly these contributions (last matching occurrence). Returns drift."""
    drift = []
    for path, items in lists.items():
        node = _get(doc, path)
        for item in items:
            index = _last_str_index(node, item) if type(node) is list else None
            if index is None:
                drift.append(Issue("settings_item_absent", SETTINGS_PATH, f"{_kp(path)}: {item}"))
            else:
                del node[index]
    hooks = doc.get("hooks")
    for event, texts in groups.items():
        node = hooks.get(event) if type(hooks) is dict else None
        for text in texts:
            index = _last_group_index(node, text) if type(node) is list else None
            if index is None:
                drift.append(Issue("settings_hook_group_absent", SETTINGS_PATH, event))
            else:
                del node[index]
    for path, text in scalars:
        current = _get(doc, path)
        if current is _MISSING:
            drift.append(Issue("settings_scalar_absent", SETTINGS_PATH, _kp(path)))
        elif _canon_or_none(current) == text:
            _delete(doc, path)
        else:
            drift.append(Issue("settings_scalar_modified", SETTINGS_PATH, _kp(path)))
    return drift


def _prune(doc: dict, containers: Iterable[tuple[str, ...]]) -> None:
    """Delete recorded containers that are now empty, deepest first."""
    for path in sorted(containers, key=len, reverse=True):
        node = _get(doc, path)
        if type(node) in (dict, list) and not node:
            _delete(doc, path)


def _merge_settings(
    user: dict, desired: _Desired, prev: SettingsContribution, blockers: list[Issue]
) -> tuple[dict, SettingsContribution, list[Issue]]:
    doc = copy.deepcopy(user)
    notes: list[Issue] = []
    created: list[tuple[str, ...]] = []
    prev_lists = {LIST_KEYS[name]: items for name, items in prev.lists.items()}
    prev_scalars = dict(prev.scalars)
    wanted_groups = {event: {t for t, _ in entries} for event, entries in desired.groups.items()}
    wanted_scalars = {path for path, _ in desired.scalars}

    # 1. Withdraw earlier contributions that the current bundle no longer wants.
    stale_lists = {
        path: [i for i in items if i not in desired.lists.get(path, ())]
        for path, items in prev_lists.items()
    }
    stale_groups = {
        event: [t for t in texts if t not in wanted_groups.get(event, ())]
        for event, texts in prev.hook_groups.items()
    }
    stale_scalars = [(p, t) for p, t in prev.scalars if p not in wanted_scalars]
    for issue in _strip(doc, stale_lists, stale_groups, stale_scalars):
        if issue.code == "settings_scalar_modified":
            notes.append(Issue("owned_scalar_released", SETTINGS_PATH, issue.detail))
    _prune(doc, [c for c in prev.containers if c not in desired.containers])

    # 2. Lists: append only missing items, never reorder or remove a person's entries.
    lists: dict[str, tuple[str, ...]] = {}
    for path, items in desired.lists.items():
        node = _ensure(doc, path, list, created, blockers)
        if node is None:
            continue
        before = set(prev_lists.get(path, ()))
        mine = []
        for item in items:
            if _last_str_index(node, item) is None:
                node.append(item)
                mine.append(item)
            elif item in before:
                mine.append(item)
        if mine:
            lists[_LIST_NAMES[path]] = tuple(mine)

    # 3. Hooks: append our matcher groups; a person's groups stay as they are, in order.
    groups: dict[str, tuple[str, ...]] = {}
    for event, entries in desired.groups.items():
        node = _ensure(doc, ("hooks", event), list, created, blockers)
        if node is None:
            continue
        present = {_canon_or_none(group) for group in node}
        before = set(prev.hook_groups.get(event, ()))
        mine = []
        for text, group in entries:
            if text not in present:
                node.append(copy.deepcopy(group))
                mine.append(text)
            elif text in before:
                mine.append(text)
        if mine:
            groups[event] = tuple(mine)
    hooks = doc.get("hooks")
    if type(hooks) is dict:
        for event, node in hooks.items():
            if type(node) is not list:
                continue
            for group in node:
                kind = group_ownership(group)
                if kind == "mixed":
                    blockers.append(Issue("hook_group_mixed", SETTINGS_PATH, event))
                elif kind == "owned" and _canon_or_none(group) not in wanted_groups.get(event, ()):
                    blockers.append(Issue("hook_group_unowned", SETTINGS_PATH, event))

    # 4. Scalars: absent -> set, equal -> keep, different -> conflict (unless still ours).
    scalars: list[tuple[tuple[str, ...], str]] = []
    for path, value in desired.scalars:
        text = canon(value)
        parent = _ensure(doc, path[:-1], dict, created, blockers)
        if parent is None:
            continue
        leaf = path[-1]
        if leaf not in parent:
            parent[leaf] = value
            scalars.append((path, text))
            continue
        current = _canon_or_none(parent[leaf])
        if current == text:
            if prev_scalars.get(path) == text:
                scalars.append((path, text))
        elif path in prev_scalars and current == prev_scalars[path]:
            parent[leaf] = value
            scalars.append((path, text))
        else:
            code = "settings_safety_conflict" if _is_safety(path) else "settings_scalar_conflict"
            blockers.append(Issue(code, SETTINGS_PATH, _kp(path)))

    containers = {
        c for c in prev.containers if c in desired.containers and _get(doc, c) is not _MISSING
    }
    containers.update(created)
    contribution = SettingsContribution(
        lists=lists,
        hook_groups=groups,
        scalars=tuple(scalars),
        containers=tuple(sorted(containers)),
    )
    return doc, contribution, notes


# --------------------------------------------------------------------------- marker blocks
#
# ``CLAUDE.md`` and the project ``.gitignore`` are a person's files. The generator only owns
# one marker block in each: bytes outside it are never changed, and uninstall removes only
# the exact recorded block and the separators the generator added.


@dataclass(frozen=True)
class _BlockSpec:
    path: str
    begin: bytes
    end: bytes
    prefix: str  # issue code prefix and manifest field: claude | gitignore
    anchored: bool  # markers must each be a whole line


_CLAUDE = _BlockSpec(CLAUDE_PATH, BEGIN_MARKER, END_MARKER, "claude", False)
_GITIGNORE = _BlockSpec(GITIGNORE_PATH, GITIGNORE_BEGIN, GITIGNORE_END, "gitignore", True)
_BLOCKS = (_CLAUDE, _GITIGNORE)


class _MarkerError(Exception):
    pass


def _loose_count(data: bytes) -> int:
    lowered = data.lower()
    return sum(lowered.count(marker) for marker in _LOOSE_MARKERS)


def _make_block(body: bytes, spec: _BlockSpec) -> bytes:
    if type(body) is not bytes:
        raise SetupDataError(f"{spec.prefix}_body_type")
    if b"\x00" in body or _loose_count(body):
        raise SetupDataError(f"{spec.prefix}_body_unsafe")
    if body and not body.endswith(b"\n"):
        raise SetupDataError(f"{spec.prefix}_body_newline")
    return spec.begin + b"\n" + body + spec.end


def make_claude_block(body: bytes) -> bytes:
    """``BEGIN\\n<body>END``. ``body`` is empty or ends with LF and holds no marker text."""
    return _make_block(body, _CLAUDE)


def make_gitignore_block(patterns: Iterable[str] = GITIGNORE_PATTERNS) -> bytes:
    """``# cab-of-one:begin\\n<one pattern per line>\\n# cab-of-one:end`` (LF).

    Patterns are printable ASCII without leading ``!``/``#`` or surrounding blanks, unique,
    and must include every entry of :data:`GITIGNORE_PATTERNS`.
    """
    lines: list[str] = []
    for pattern in patterns:
        if (
            type(pattern) is not str
            or not pattern
            or not pattern.isascii()
            or not pattern.isprintable()
            or pattern != pattern.strip()
            or pattern[0] in "!#"
            or pattern in lines
        ):
            raise SetupDataError("gitignore_pattern_invalid", repr(pattern)[:80])
        lines.append(pattern)
    block = _make_block("".join(p + "\n" for p in lines).encode("ascii"), _GITIGNORE)
    _check_gitignore_body(block)
    return block


def _check_block(block: bytes, spec: _BlockSpec) -> None:
    if (
        not block.startswith(spec.begin + b"\n")
        or not block.endswith(spec.end)
        or b"\x00" in block
        or _loose_count(block) != 2
        or block.count(spec.begin) != 1
        or block.count(spec.end) != 1
    ):
        raise SetupDataError(f"{spec.prefix}_block_shape")


def _check_gitignore_body(block: bytes) -> None:
    """Our ``.gitignore`` block ignores every required path and never re-includes."""
    body = block[len(GITIGNORE_BEGIN) + 1 : len(block) - len(GITIGNORE_END)]
    lines = body.split(b"\n")[:-1] if body else []
    for line in lines:
        if not line or line.startswith((b"!", b"#")) or b"\r" in line or line != line.strip():
            raise SetupDataError("gitignore_block_patterns", line.decode("ascii", "replace"))
    present = {line.decode("ascii", "replace") for line in lines}
    if not set(GITIGNORE_PATTERNS) <= present:
        raise SetupDataError("gitignore_block_patterns", "required")


def _gitignore_negates_cab(data: bytes, span: tuple[int, int] | None) -> bool:
    """A person's ``!`` line naming a ``.cab`` path component could re-include local
    secrets. Best effort: character-class tricks such as ``!.ca[b]/`` are not decoded."""
    outside = data if span is None else data[: span[0]] + b"\n" + data[span[1] :]
    for line in outside.split(b"\n"):
        text = line.strip().lower()
        if text.startswith(b"!") and _NEGATED_CAB.search(text[1:]):
            return True
    return False


def _whole_line(data: bytes, start: int, stop: int) -> bool:
    before = start == 0 or data[start - 1 : start] == b"\n"
    return before and data[stop : stop + 1] in (b"", b"\n", b"\r")


def _find_block(data: bytes, spec: _BlockSpec = _CLAUDE) -> tuple[int, int] | None:
    """Span of the one valid marker pair, None when there is no marker text at all.

    Raises ``_MarkerError`` for duplicates, unmatched, nested, out-of-order or lookalike
    (spacing/case variants, the other file's marker style) markers, and for ``.gitignore``
    markers that are not whole lines.
    """
    loose = _loose_count(data)
    if loose == 0:
        return None
    if loose == 2 and data.count(spec.begin) == 1 and data.count(spec.end) == 1:
        start = data.index(spec.begin)
        end = data.index(spec.end)
        stop = end + len(spec.end)
        if start < end and (
            not spec.anchored
            or (_whole_line(data, start, start + len(spec.begin)) and _whole_line(data, end, stop))
        ):
            return start, stop
    raise _MarkerError


def _encoding_ok(data: bytes) -> bool:
    """ASCII markers can only be located in an ASCII-compatible file (not UTF-16/32)."""
    return not data.startswith((b"\xff\xfe", b"\xfe\xff")) and b"\x00" not in data


def _append_block(data: bytes, block: bytes) -> tuple[bytes, str, str]:
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    if not data:
        lead = b""
    elif data.endswith(b"\n"):
        lead = newline
    else:
        lead = newline + newline
    return data + lead + block + newline, lead.decode("ascii"), newline.decode("ascii")


def _remove_block(
    data: bytes, record: BlockRecord, spec: _BlockSpec = _CLAUDE
) -> tuple[bytes | None, Issue | None]:
    """``data`` without the exact owned block and the separators it added."""
    if not _encoding_ok(data):
        return None, Issue(f"{spec.prefix}_encoding_unsupported", spec.path)
    try:
        span = _find_block(data, spec)
    except _MarkerError:
        return None, Issue(f"{spec.prefix}_markers_invalid", spec.path)
    if span is None:
        return None, Issue(f"{spec.prefix}_block_absent", spec.path)
    start, end = span
    if sha256_hex(data[start:end]) != record.sha256:
        return None, Issue(f"{spec.prefix}_block_modified", spec.path)
    lead = record.lead.encode("ascii")
    trail = record.trail.encode("ascii")
    if lead and data[:start].endswith(lead):
        start -= len(lead)
    if trail and data[end:].startswith(trail):
        end += len(trail)
    head, tail = data[:start], data[end:]
    if head and tail and not head.endswith(b"\n"):
        # A person added lines after our block in a file that had no final newline:
        # keep one line break so their first line is not glued to the line before.
        return head + (b"\r\n" if lead.startswith(b"\r\n") else b"\n") + tail, None
    return head + tail, None


# --------------------------------------------------------------------------- merge planner


@dataclass
class _Pending:
    issue: Issue
    proposal: bytes | None
    resolve: Callable[[], None] | None


def _check_bundle(bundle: object, blockers: list[Issue]) -> dict[str, tuple[str, bytes]]:
    if not isinstance(bundle, Mapping):
        raise SetupDataError("bundle_type")
    entries: dict[str, tuple[str, bytes]] = {}
    seen: dict[str, str] = {}
    for path, data in bundle.items():
        label = path if type(path) is str else repr(path)
        if type(data) is not bytes:
            raise SetupDataError("bundle_value_type", label[:200])
        try:
            kind = path_class(path)
        except SetupDataError as exc:
            blockers.append(Issue("bundle_path_refused", label[:200], exc.code))
            continue
        folded = norm_path(path)
        if folded in seen:
            blockers.append(Issue("bundle_case_collision", path, seen[folded]))
            continue
        seen[folded] = path
        entries[path] = (kind, data)
    for folded, path in seen.items():
        for parent in _ancestors(folded):
            if parent in seen:
                blockers.append(Issue("bundle_path_prefix", path, seen[parent]))
    return entries


class _Planner:
    def __init__(
        self, bundle: dict[str, tuple[str, bytes]], tree: _Tree, prev: Manifest | None
    ) -> None:
        self.bundle = bundle
        self.tree = tree
        self.prev = prev
        self.actions: list[Action] = []
        self.blockers: list[Issue] = []
        self.notes: list[Issue] = []
        self.pending: list[_Pending] = []
        self.files: dict[str, str] = {}
        self.offered: dict[str, str] = {}
        self.settings = SettingsContribution()
        self.blocks: dict[str, BlockRecord] = {}

    # -- bookkeeping

    def block(self, code: str, path: str, detail: str = "") -> None:
        self.blockers.append(Issue(code, path, detail))

    def note(self, code: str, path: str, detail: str = "") -> None:
        self.notes.append(Issue(code, path, detail))

    def act(self, kind: str, path: str, data: bytes | None, reason: str) -> None:
        self.actions.append(Action(kind, path, data, reason))

    def defer(self, issue: Issue, proposal: bytes | None, resolve: Callable[[], None] | None):
        self.pending.append(_Pending(issue, proposal, resolve))

    def node(self, path: str) -> tuple[bool, bytes | None]:
        """(usable, bytes or None). Case mismatches and non-regular entries block."""
        status, value = self.tree.get(path)
        if status == "case":
            self.block("case_collision", path)
            return False, None
        if isinstance(value, NodeKind):
            self.block(_kind_code(value), path)
            return False, None
        return True, value

    # -- scopes and settings

    def scopes(self, scopes: SettingsScopes) -> None:
        sources: list[tuple[str, bytes | None, bool]] = [
            (SETTINGS_LOCAL_PATH, scopes.local, False),
            ("~/.claude/settings.json", scopes.user, False),
        ]
        sources += [(f"managed-settings[{i}]", raw, True) for i, raw in enumerate(scopes.managed)]
        for label, raw, managed in sources:
            if raw is None:
                continue
            try:
                doc = loads_strict(raw)
            except SetupDataError as exc:
                self.block("scope_unreadable", label, exc.code)
                continue
            self.blockers.extend(_scope_blockers(doc, label, managed=managed))

    def settings_file(self) -> None:
        entry = self.bundle.get(SETTINGS_PATH)
        prev = self.prev.settings if self.prev else SettingsContribution()
        ok, current = self.node(SETTINGS_PATH)
        if not ok:
            return
        user: Any = {}
        if current is not None:
            try:
                user = loads_strict(current)
            except SetupDataError as exc:
                self.block("settings_invalid", SETTINGS_PATH, exc.code)
                return
            if type(user) is not dict:
                self.block("settings_invalid", SETTINGS_PATH, "top_level")
                return
            self.blockers.extend(_scope_blockers(user, SETTINGS_PATH, managed=False))
        if entry is None and prev.is_empty and not prev.file_created:
            return
        desired = _Desired()
        if entry is not None:
            try:
                desired = _parse_ours(loads_strict(entry[1]))
            except SetupDataError as exc:
                self.block("bundle_settings_invalid", SETTINGS_PATH, exc.code)
                return
        merged, contribution, notes = _merge_settings(user, desired, prev, self.blockers)
        self.notes.extend(notes)
        if current is None:
            created = bool(merged)
            if created:
                self.act("create", SETTINGS_PATH, dump_json_document(merged), "settings")
                if not prev.is_empty:
                    self.note("settings_recreated", SETTINGS_PATH)
        else:
            created = prev.file_created
            if created and not merged:
                self.act("remove", SETTINGS_PATH, None, "settings_empty")
                created = False
            elif not _same_doc(merged, user):
                self.act("update", SETTINGS_PATH, dump_json_document(merged), "settings")
        self.settings = replace(contribution, file_created=created)

    # -- marker blocks (CLAUDE.md, .gitignore)

    def _prev_block(self, spec: _BlockSpec) -> BlockRecord | None:
        if self.prev is None:
            return None
        return self.prev.claude_block if spec is _CLAUDE else self.prev.gitignore_block

    def _take_block(self, spec: _BlockSpec, kind: str, data: bytes, record: BlockRecord):
        def resolve() -> None:
            self.act(kind, spec.path, data, "take_new")
            self.blocks[spec.prefix] = record

        return resolve

    def block_file(self, spec: _BlockSpec) -> None:
        entry = self.bundle.get(spec.path)
        record = self._prev_block(spec)
        if entry is None and record is None:
            return
        ok, current = self.node(spec.path)
        if not ok:
            return
        if entry is None:
            self._stale_block(spec, current, record)
            return
        block = entry[1]
        try:
            _check_block(block, spec)
            if spec is _GITIGNORE:
                _check_gitignore_body(block)
        except SetupDataError as exc:
            self.block(f"bundle_{spec.prefix}_invalid", spec.path, exc.code)
            return
        digest = sha256_hex(block)
        reason = f"{spec.prefix}_block"
        missing = Issue(f"{spec.prefix}_block_missing", spec.path)
        if current is None:
            new = block + b"\n"
            fresh = BlockRecord(digest, "", "\n", True)
            if record is None:
                self.act("create", spec.path, new, reason)
                self.blocks[spec.prefix] = fresh
            else:
                self.blocks[spec.prefix] = record
                self.defer(missing, new, self._take_block(spec, "create", new, fresh))
            return
        if not _encoding_ok(current):
            self.block(f"{spec.prefix}_encoding_unsupported", spec.path)
            return
        try:
            span = _find_block(current, spec)
        except _MarkerError:
            self.block(f"{spec.prefix}_markers_invalid", spec.path)
            return
        if spec is _GITIGNORE and _gitignore_negates_cab(current, span):
            self.block("gitignore_negates_cab", spec.path)
            return
        if span is None:
            new, lead, trail = _append_block(current, block)
            created = record.file_created if record else False
            fresh = BlockRecord(digest, lead, trail, created)
            if record is None:
                self.act("update", spec.path, new, reason)
                self.blocks[spec.prefix] = fresh
            else:
                self.blocks[spec.prefix] = record
                self.defer(missing, new, self._take_block(spec, "update", new, fresh))
            return
        start, end = span
        inside = current[start:end]
        new = current[:start] + block + current[end:]
        fresh = replace(record, sha256=digest) if record else BlockRecord(digest)
        if inside == block:
            self.blocks[spec.prefix] = fresh
        elif record is not None and sha256_hex(inside) == record.sha256:
            self.act("update", spec.path, new, reason)
            self.blocks[spec.prefix] = fresh
        else:
            if record is not None:
                self.blocks[spec.prefix] = record
            modified = Issue(f"{spec.prefix}_block_modified", spec.path)
            self.defer(modified, new, self._take_block(spec, "update", new, fresh))

    def _stale_block(self, spec: _BlockSpec, current: bytes | None, record: BlockRecord) -> None:
        if current is None:
            self.note(f"{spec.prefix}_block_absent", spec.path)
            return
        new, issue = _remove_block(current, record, spec)
        if issue is not None or new is None:
            self.note(f"{spec.prefix}_block_released", spec.path, issue.code if issue else "")
            return
        if not new and record.file_created:
            self.act("remove", spec.path, None, f"{spec.prefix}_block_stale")
        else:
            self.act("update", spec.path, new, f"{spec.prefix}_block_stale")

    # -- files

    def _take_file(self, kind: str, path: str, data: bytes):
        def resolve() -> None:
            self.act(kind, path, data, "take_new")
            self.files[path] = sha256_hex(data)

        return resolve

    def owned(self, path: str, data: bytes) -> None:
        ok, current = self.node(path)
        if not ok:
            return
        prev_hash = self.prev.files.get(path) if self.prev else None
        digest = sha256_hex(data)
        if current is None:
            if prev_hash is None:
                self.act("create", path, data, "generated")
                self.files[path] = digest
            else:
                self.files[path] = prev_hash
                resolve = self._take_file("create", path, data)
                self.defer(Issue("owned_missing", path), data, resolve)
            return
        if prev_hash is None:
            # Not in the manifest: a person's file (even with identical bytes). Stop all.
            self.block("unowned_collision", path)
        elif current == data:
            self.files[path] = digest
        elif sha256_hex(current) == prev_hash:
            self.act("update", path, data, "generated")
            self.files[path] = digest
        else:
            self.files[path] = prev_hash
            resolve = self._take_file("update", path, data)
            self.defer(Issue("owned_modified", path), data, resolve)

    def create_once(self, path: str, data: bytes, kind: str) -> None:
        ok, current = self.node(path)
        if not ok:
            return
        prev_offer = self.prev.offered.get(path) if self.prev else None
        digest = sha256_hex(data)
        if prev_offer is not None:
            self.offered[path] = prev_offer
        if current is None:
            if prev_offer is None:
                self.act("create", path, data, "create_once")
                self.offered[path] = digest
            elif kind == "person":
                self.defer(Issue("person_file_missing", path), data, None)
                self.offered[path] = digest
            else:
                self.note("person_file_absent", path)
            return
        if current == data:
            return
        if kind == "person" and prev_offer != digest:
            self.defer(Issue("person_file_differs", path), data, None)
            self.offered[path] = digest
        else:
            self.note("person_file_kept", path)

    def stale(self) -> None:
        if self.prev is None:
            return
        bundle_folded = {norm_path(p): p for p in self.bundle}
        for path, digest in self.prev.files.items():
            if path in self.bundle:
                continue
            if norm_path(path) in bundle_folded:
                self.block("case_collision", path, bundle_folded[norm_path(path)])
                continue
            status, current = self.tree.get(path)
            if status == "case" or isinstance(current, NodeKind):
                self.note("stale_owned_released", path, "not_regular")
            elif current is None:
                self.note("stale_owned_absent", path)
            elif sha256_hex(current) == digest:
                self.act("remove", path, None, "stale_owned")
            else:
                self.note("stale_owned_released", path, "modified")
        for path, digest in self.prev.offered.items():
            self.offered.setdefault(path, digest)

    # -- conflicts, parents, result

    def finish_conflicts(self, take_new: Collection[Any]) -> list[Issue]:
        resolvable = {p.issue.path: p for p in self.pending if p.resolve is not None}
        taken: set[str] = set()
        for raw in sorted(set(take_new), key=repr):
            label = raw if type(raw) is str else repr(raw)
            try:
                check_rel_path(raw)
            except SetupDataError:
                self.block("take_new_invalid", label[:200])
                continue
            pending = resolvable.get(raw)
            if pending is None or pending.resolve is None:
                self.block("take_new_unexpected", raw)
                continue
            pending.resolve()
            taken.add(raw)
            self.note("taken_new", raw)
        conflicts = []
        for pending in self.pending:
            if pending.resolve is not None and pending.issue.path in taken:
                continue
            conflicts.append(pending.issue)
            if pending.proposal is None:
                continue
            target = pending.issue.path + PROPOSAL_SUFFIX
            ok, current = self.node(target)
            if ok and current != pending.proposal:
                self.act("propose", target, pending.proposal, pending.issue.code)
        return conflicts

    def result(
        self, version: str, profile: str, applied_at: str | None, conflicts: list[Issue]
    ) -> MergePlan:
        self.blockers.extend(_parent_issues(self.tree, (a.path for a in self.actions)))
        blockers = tuple(sorted(set(self.blockers)))
        conflict_t = tuple(sorted(set(conflicts)))
        notes = tuple(sorted(set(self.notes)))
        if blockers:
            return MergePlan((), blockers, conflict_t, notes, None, False)
        actions = tuple(sorted(self.actions, key=lambda a: (a.path, a.kind)))
        if len({a.path for a in actions}) != len(actions):
            raise SetupDataError("internal_duplicate_action")
        manifest = Manifest(
            generator_version=version,
            profile_sha256=profile,
            files=self.files,
            offered=self.offered,
            settings=self.settings,
            claude_block=self.blocks.get(_CLAUDE.prefix),
            applied_at=applied_at,
            gitignore_block=self.blocks.get(_GITIGNORE.prefix),
        )
        changed = self.prev is None or not manifest.same_content(self.prev)
        return MergePlan(actions, blockers, conflict_t, notes, manifest, changed)


def plan_merge(
    bundle: Mapping[str, bytes],
    existing: Mapping[str, bytes | NodeKind],
    *,
    manifest: Manifest | None,
    generator_version: str,
    profile_sha256: str,
    scopes: SettingsScopes | None = None,
    take_new: Collection[str] = (),
    applied_at: str | None = None,
) -> MergePlan:
    """Plan writing ``bundle`` into a project (DESIGN §10-3). Pure; never touches files.

    ``manifest`` is the current ``.cab/manifest.json`` (None on first install).
    ``take_new`` names exact paths from a previous plan's ``resolvable``; any other path
    blocks. Same bundle, same project and same manifest give ``nothing_to_do``.
    Raises ``SetupDataError`` only for wrongly typed arguments.
    """
    check_version(generator_version)
    check_sha256(profile_sha256, "profile_sha256_invalid")
    check_applied_at(applied_at)
    if manifest is not None and type(manifest) is not Manifest:
        raise SetupDataError("manifest_type")
    if scopes is None:
        scopes = SettingsScopes()
    elif type(scopes) is not SettingsScopes:
        raise SetupDataError("scopes_type")
    if isinstance(take_new, str | bytes) or not isinstance(take_new, Collection):
        raise SetupDataError("take_new_type")
    tree = _Tree(existing)
    early: list[Issue] = []
    entries = _check_bundle(bundle, early)
    planner = _Planner(entries, tree, manifest)
    planner.blockers.extend(early)
    planner.scopes(scopes)
    planner.settings_file()
    for spec in _BLOCKS:
        planner.block_file(spec)
    for path in sorted(entries):
        kind, data = entries[path]
        if kind == "owned":
            planner.owned(path, data)
        elif kind in ("person", "quiet"):
            planner.create_once(path, data, kind)
    planner.stale()
    conflicts = planner.finish_conflicts(take_new)
    return planner.result(generator_version, profile_sha256, applied_at, conflicts)


# --------------------------------------------------------------------------- uninstall


def _uninstall_settings(
    record: SettingsContribution, tree: _Tree, actions: list[Action], drift: list[Issue]
) -> None:
    if record.is_empty and not record.file_created:
        return
    status, current = tree.get(SETTINGS_PATH)
    if status == "case":
        drift.append(Issue("case_collision", SETTINGS_PATH))
        return
    if isinstance(current, NodeKind):
        drift.append(Issue(_kind_code(current), SETTINGS_PATH))
        return
    if current is None:
        drift.append(Issue("settings_absent", SETTINGS_PATH))
        return
    try:
        doc = loads_strict(current)
    except SetupDataError as exc:
        drift.append(Issue("settings_unreadable", SETTINGS_PATH, exc.code))
        return
    if type(doc) is not dict:
        drift.append(Issue("settings_unreadable", SETTINGS_PATH, "top_level"))
        return
    result = copy.deepcopy(doc)
    lists = {LIST_KEYS[name]: items for name, items in record.lists.items()}
    drift.extend(_strip(result, lists, record.hook_groups, record.scalars))
    _prune(result, record.containers)
    if record.file_created and not result:
        actions.append(Action("remove", SETTINGS_PATH, None, "settings_empty"))
    elif not _same_doc(result, doc):
        actions.append(Action("update", SETTINGS_PATH, dump_json_document(result), "settings"))


def _uninstall_block(
    spec: _BlockSpec,
    record: BlockRecord,
    tree: _Tree,
    actions: list[Action],
    drift: list[Issue],
) -> None:
    status, current = tree.get(spec.path)
    if status == "case":
        drift.append(Issue("case_collision", spec.path))
        return
    if isinstance(current, NodeKind):
        drift.append(Issue(_kind_code(current), spec.path))
        return
    if current is None:
        drift.append(Issue(f"{spec.prefix}_block_absent", spec.path))
        return
    new, issue = _remove_block(current, record, spec)
    if issue is not None or new is None:
        drift.append(issue or Issue(f"{spec.prefix}_block_absent", spec.path))
        return
    reason = f"{spec.prefix}_block"
    if not new and record.file_created:
        actions.append(Action("remove", spec.path, None, reason))
    else:
        actions.append(Action("update", spec.path, new, reason))


def plan_uninstall(manifest: Manifest, existing: Mapping[str, bytes | NodeKind]) -> UninstallPlan:
    """Plan a conservative uninstall. Pure; never touches files.

    Removes only generated files whose bytes still hash to the manifest, exactly the
    recorded settings contributions and the exact owned ``CLAUDE.md`` and ``.gitignore``
    blocks (with the separators the generator added). Everything a
    person changed is kept and reported as drift. Create-once files (policy, catalogue,
    READMEs, handoff notes), ``changes/``, ``audit/``, ``.cab-new`` proposals, local, user
    and managed settings are never touched. A non-directory parent blocks every action.
    """
    if type(manifest) is not Manifest:
        raise SetupDataError("manifest_type")
    tree = _Tree(existing)
    actions: list[Action] = []
    drift: list[Issue] = []
    notes: list[Issue] = []
    for path, digest in manifest.files.items():
        status, current = tree.get(path)
        if status == "case":
            drift.append(Issue("case_collision", path))
        elif isinstance(current, NodeKind):
            drift.append(Issue(_kind_code(current), path))
        elif current is None:
            drift.append(Issue("owned_absent", path))
        elif sha256_hex(current) == digest:
            actions.append(Action("remove", path, None, "owned_unchanged"))
        else:
            drift.append(Issue("owned_modified", path))
    for path in manifest.offered:
        notes.append(Issue("person_file_kept", path))
    _uninstall_settings(manifest.settings, tree, actions, drift)
    for spec, record in ((_CLAUDE, manifest.claude_block), (_GITIGNORE, manifest.gitignore_block)):
        if record is not None:
            _uninstall_block(spec, record, tree, actions, drift)
    blockers = tuple(sorted(set(_parent_issues(tree, (a.path for a in actions)))))
    planned = () if blockers else tuple(sorted(actions, key=lambda a: (a.path, a.kind)))
    return UninstallPlan(planned, blockers, tuple(sorted(set(drift))), tuple(sorted(set(notes))))


# --------------------------------------------------------------------------- inspection list


def paths_to_inspect(
    bundle_paths: Iterable[str], manifest: Manifest | None = None
) -> tuple[str, ...]:
    """Every path the caller must ``lstat`` (and read when regular) for a merge/uninstall:
    targets, their ``.cab-new`` proposals and every parent directory."""
    targets = {SETTINGS_PATH, CLAUDE_PATH, GITIGNORE_PATH}
    for path in bundle_paths:
        try:
            targets.add(check_rel_path(path))
        except SetupDataError:
            continue
    if manifest is not None:
        targets.update(manifest.files)
        targets.update(manifest.offered)
    every: set[str] = set()
    for path in targets:
        every.add(path)
        every.add(path + PROPOSAL_SUFFIX)
        every.update(_ancestors(path))
    return tuple(sorted(every))
