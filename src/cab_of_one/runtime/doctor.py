"""Static ``cab doctor`` checks (DESIGN §3-0, §3-9 item 2, §10-1, §10-2, §10-6, E8, E10).

``inspect_project`` looks at one generated project and at settings layers that the caller
supplies with their source labels (``managed``, ``cli``, ``local``, ``project``, ``user``).
It reads nothing outside ``project_root``: user and managed settings, the Claude Code
version and mod metadata are the caller's inputs. ``read_project_layers`` reads the two
project files (``.claude/settings.json`` and ``.claude/settings.local.json``).

Every operation is read only. Nothing is executed (the SessionStart self test that feeds
the guard a synthetic write is S5 integration), nothing is fixed automatically and no
tenant is contacted.

Each check yields ``PASS``, ``WARN``, ``FAIL`` or ``UNKNOWN``. ``UNKNOWN`` means *not
measured* (input not supplied, or a shape this module does not recognise) and is never
folded into ``PASS``. The doctor does not compute an effective, precedence-resolved
configuration: list keys are collected from every eligible layer (deny rules merge across
scopes), and risky scalars are reported wherever they appear, with the layer's label.

Our hook entries are recognised by their command path ``.claude/hooks/cab/<script>``;
``onFailure: "block"`` is checked on the handler entry, where DESIGN §4-2 puts it. The
official hooks docs say ``onFailure`` has no effect on Stop and SubagentStop, so for those
events only the prescribed field is checked and fail-closed behaviour is never claimed.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import paths, schema

__all__ = [
    "DEFAULT_FAIL_CLOSED_EVENTS",
    "DEFAULT_HOOK_SCRIPTS",
    "DEFAULT_REQUIRED_DENY",
    "FAIL",
    "MESSAGES",
    "ON_FAILURE_NO_EFFECT_EVENTS",
    "PASS",
    "REQUIRED_EVENTS",
    "SOURCES",
    "UNKNOWN",
    "WARN",
    "DoctorReport",
    "Issue",
    "SettingsLayer",
    "inspect_project",
    "parse_frontmatter",
    "read_project_layers",
]

PASS = "PASS"
UNKNOWN = "UNKNOWN"
WARN = "WARN"
FAIL = "FAIL"
_RANK = {PASS: 0, UNKNOWN: 1, WARN: 2, FAIL: 3}

SOURCES = ("managed", "cli", "local", "project", "user")
_EXPECTED_SOURCES = ("managed", "local", "project", "user")  # cli is per launch

REQUIRED_EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "SubagentStart",
    "SubagentStop",
    "SessionStart",
    "SessionEnd",
    "Stop",
    "ConfigChange",
)
DEFAULT_HOOK_SCRIPTS: dict[str, str] = {
    "PreToolUse": "guard.py",
    "PostToolUse": "audit.py",
    "PostToolUseFailure": "audit.py",
    "SubagentStart": "audit.py",
    "SubagentStop": "audit.py",
    "SessionStart": "audit.py",
    "SessionEnd": "audit.py",
    "Stop": "closeout.py",
    "ConfigChange": "config_lock.py",
}
TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure"})
DEFAULT_FAIL_CLOSED_EVENTS = ("PreToolUse",)
# Official hooks docs (".local/HOOK_S10_FACTS_2026-11-11.md"): onFailure is a handler
# field and has no effect on Stop/SubagentStop. For these events the doctor checks only
# that the prescribed field is present and never reports crash/timeout blocking.
ON_FAILURE_NO_EFFECT_EVENTS = frozenset({"Stop", "SubagentStop"})
HOOK_DIR = (".claude", "hooks", "cab")

_DENY_PATHS = (
    ".claude/**",
    "policy/**",
    "audit/**",
    ".cab/state/**",
    ".cab/manifest.json",
    ".cab/backups/**",
    "changes/*/approval.json",
    "changes/*/review.json",
    "changes/*/verify.json",
    "~/.local/state/cab-of-one/**",
)
HUMAN_COMMAND_RULES = (
    "Bash(cab approve:*)",
    "Bash(cab ack:*)",
    "Bash(cab resume:*)",
    "Bash(cab setup apply:*)",
    "Bash(cab setup uninstall:*)",
)
# Shape of DESIGN §4-2 with the §10-6 paths. The generator owns the exact strings; pass
# them as ``required_deny`` once they are frozen.
DEFAULT_REQUIRED_DENY = (
    tuple(
        f"{tool}({p if p.startswith('~') else './' + p})"
        for p in _DENY_PATHS
        for tool in ("Edit", "Write")
    )
    + HUMAN_COMMAND_RULES
)

SAFETY_REVIEWER = "safety-reviewer"
SAFETY_REVIEWER_TOOLS = frozenset({"Read", "Grep", "Glob"})

MAX_SETTINGS_BYTES = 1024 * 1024
MAX_AGENT_BYTES = 256 * 1024
MAX_AGENTS = 256
MAX_MANIFEST_ENTRIES = 4096
MAX_MANIFEST_FILE_BYTES = 16 * 1024 * 1024
MAX_MODS = 256

_HOOK_REF = re.compile(r"\.claude/hooks/cab/([A-Za-z0-9_.-]+)")
# The plugin root variable name is assembled at run time: the generator's floor check
# (S8 render.verify_floor) refuses any rendered byte sequence that contains the literal
# name, and this module is copied into generated projects. ``str.join`` is not
# constant-folded, so neither this source nor its bytecode holds the literal either.
_PLUGIN_ROOT_NAME = "_".join(("CLAUDE", "PLUGIN", "ROOT"))
_PLUGIN_ROOT = re.compile(re.escape(_PLUGIN_ROOT_NAME))
_VERSION = re.compile(r"\s*v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,6})(?![0-9])")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_LABEL = re.compile(r"[A-Za-z0-9_.:@/ ()*-]{1,128}")

MESSAGES: dict[str, str] = {
    "project_root_invalid": "The project root is not an absolute, real (non-symlink) folder.",
    "layer_not_supplied": "This settings layer was not supplied, so it was not measured.",
    "layer_source_unknown": "A settings layer has an unknown source label; it was ignored.",
    "layer_duplicate": "The same settings source was supplied twice; both were measured.",
    "layer_shape_unknown": "A settings layer is not a JSON object; it was not measured.",
    "layer_invalid": (
        "A project settings file is unreadable or not valid strict JSON; hooks and deny "
        "rules in it cannot be relied on."
    ),
    "layer_unmeasured": "A settings layer could not be read, so it was not measured.",
    "layers_ok": "Supplied settings layers were read.",
    "disable_all_hooks": "disableAllHooks is on, so no hook (and no guard) runs.",
    "disable_all_hooks_unknown": "disableAllHooks has a value that is not true or false.",
    "disable_all_hooks_off": "disableAllHooks is not set in any supplied layer.",
    "managed_hooks_only": "allowManagedHooksOnly is on: project hooks are silently disabled.",
    "managed_rules_only": (
        "allowManagedPermissionRulesOnly is on: project allow, ask and deny rules are ignored."
    ),
    "managed_masking_off": "Managed settings do not mask project hooks or permission rules.",
    "managed_masking_unmeasured": (
        "Managed settings were not supplied or not readable; hook and rule masking was not "
        "measured."
    ),
    "managed_flag_unknown": "A managed masking key has a value that is not true or false.",
    "hooks_schema_unknown": (
        "A hooks section has a shape this doctor does not recognise; it was not counted."
    ),
    "hook_missing": "A required cab hook is not registered for this event.",
    "hook_masked": (
        "project hooks are silently disabled: the cab hook for this event is only in a layer "
        "that allowManagedHooksOnly masks."
    ),
    "hook_ok": "The cab hook for this event is registered.",
    "hook_not_shared": (
        "The cab hook for this event is only in a personal settings layer, not in the "
        "project settings."
    ),
    "hook_type_unknown": "The cab hook entry is not a command hook; it was not counted.",
    "hook_matcher_narrow": "The cab hook matcher does not cover every tool.",
    "hook_matcher_unknown": "The cab hook matcher has an unrecognised value.",
    "hook_target_missing": "The hook script under .claude/hooks/cab/ does not exist.",
    "hook_target_unsafe": (
        "The hook script or its folder is a symlink, a hard link or not a regular file."
    ),
    "hook_target_ok": "The hook script exists as a regular file.",
    "on_failure_missing": (
        'The hook has no onFailure: "block", so a crash or timeout lets the call through.'
    ),
    "on_failure_location": (
        "onFailure is set on the matcher group, not on the hook entry; its effect is unverified."
    ),
    "on_failure_ok": 'The hook entry has onFailure: "block".',
    "on_failure_field_no_effect": (
        'The prescribed onFailure: "block" field is present, but onFailure has no effect on '
        "Stop/SubagentStop: a crash or timeout of this hook is not blocked (not fail-closed)."
    ),
    "on_failure_field_missing": (
        'The prescribed onFailure: "block" field is missing. It has no effect on '
        "Stop/SubagentStop, so this is drift from the generated configuration, not a "
        "fail-closed guarantee being lost."
    ),
    "hook_plugin_root": (
        "A cab hook refers to the plugin root variable; the runtime must not need the plugin."
    ),
    "hook_plugin_root_other": "A non-cab hook refers to the plugin root variable.",
    "hook_plugin_root_none": "No hook refers to the plugin root variable.",
    "permissions_schema_unknown": (
        "A permissions section has a shape this doctor does not recognise; it was not counted."
    ),
    "deny_missing": "A required deny rule is missing.",
    "deny_masked": (
        "project permission rules are ignored: a required deny rule exists only in a layer "
        "that allowManagedPermissionRulesOnly masks."
    ),
    "deny_ok": "All required deny rules are present.",
    "human_command_allowed": "A human-only cab command appears in an allow or ask list.",
    "allow_not_gate": ("allow rules are not a gate in bypass mode; no PreToolUse guard registered"),
    "allow_with_guard": (
        "allow rules exist; they do not gate in bypass mode, the PreToolUse guard and deny "
        "rules do."
    ),
    "allow_none": "No allow rules in the supplied layers.",
    "agents_dir_missing": "The project has no .claude/agents folder.",
    "agents_dir_unsafe": "The .claude/agents folder is a symlink or not a folder.",
    "agents_over_limit": "Too many agent files; the rest were not measured.",
    "agent_file_unsafe": "An agent file is a symlink, hard link, too large or unreadable.",
    "agent_frontmatter_unknown": (
        "An agent file's frontmatter could not be read with certainty; its tools are unknown."
    ),
    "agent_tools_missing": (
        "An agent has no explicit tools: list, so it inherits almost all tools."
    ),
    "agent_tools_unknown": "An agent's tools: value has an unrecognised form.",
    "agent_tools_wildcard": "An agent's tools: list contains a wildcard.",
    "agent_tools_ok": "The agent has an explicit tools: list.",
    "safety_reviewer_missing": "No safety-reviewer agent was found.",
    "safety_reviewer_tools": "safety-reviewer must have exactly the tools Read, Grep and Glob.",
    "safety_reviewer_ok": "safety-reviewer has exactly Read, Grep and Glob.",
    "version_not_supplied": "The Claude Code version was not supplied, so it was not checked.",
    "version_unparsed": "The Claude Code version or the minimum version could not be parsed.",
    "min_version_unknown": "No minimum Claude Code version is known (argument or policy).",
    "version_too_old": "The Claude Code version is below the minimum version.",
    "version_ok": "The Claude Code version meets the minimum version.",
    "policy_invalid": (
        "policy/policy.toml or policy/standard-changes.toml is missing or invalid; the guard "
        "then denies everything except Read, Grep and Glob."
    ),
    "policy_ok": "Policy and standard-change catalogue pass the strict schema.",
    "manifest_unmeasured": (
        "No manifest hashes were supplied, so generated files were not checked."
    ),
    "manifest_shape_unknown": "The supplied manifest is not a mapping of path to SHA-256.",
    "manifest_entry_invalid": "A manifest entry has an unsafe path or a malformed hash.",
    "manifest_file_missing": "A generated file listed in the manifest is missing.",
    "manifest_file_unsafe": "A generated file is a symlink, hard link, too large or unreadable.",
    "manifest_mismatch": "A generated file no longer matches its manifest hash.",
    "manifest_ok": "Every manifest file matches its hash.",
    "mods_unmeasured": "No mod metadata was supplied, so mods were not checked.",
    "mod_metadata_unknown": "A mod metadata entry has an unrecognised shape; it was not counted.",
    "mod_tool_check": (
        "A mod handles tool.check or tool.call; without managed settings or a Team/Enterprise "
        "login it can approve calls that deny rules or the guard blocked."
    ),
    "mods_ok": "No supplied mod handles tool.check or tool.call.",
}


# --------------------------------------------------------------------------- data


@dataclass(frozen=True)
class SettingsLayer:
    """One settings source. ``status``: ok | missing | invalid | unreadable | unsafe.

    ``missing`` means the source was looked for and does not exist (measured: empty).
    A source that was not looked for is simply not supplied.
    """

    source: str
    data: Mapping[str, Any] | None = None
    status: str = "ok"


@dataclass(frozen=True)
class Issue:
    check: str
    status: str
    code: str
    message: str
    source: str | None = None
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "status": self.status,
            "code": self.code,
            "message": self.message,
            "source": self.source,
            "subject": self.subject,
        }


@dataclass(frozen=True)
class DoctorReport:
    issues: tuple[Issue, ...]
    notes: tuple[str, ...] = ()

    @property
    def overall(self) -> str:
        """Worst status: FAIL > WARN > UNKNOWN > PASS. UNKNOWN is never PASS."""
        worst = PASS
        for issue in self.issues:
            if _RANK[issue.status] > _RANK[worst]:
                worst = issue.status
        return worst

    @property
    def passed(self) -> bool:
        return bool(self.issues) and all(i.status == PASS for i in self.issues)

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys((PASS, UNKNOWN, WARN, FAIL), 0)
        for issue in self.issues:
            out[issue.status] += 1
        return out

    def by_code(self, code: str) -> list[Issue]:
        return [i for i in self.issues if i.code == code]

    def lines(self) -> list[str]:
        out = []
        for i in sorted(self.issues, key=lambda x: (-_RANK[x.status], x.check)):
            where = ""
            if i.source:
                where += f" [{i.source}]"
            if i.subject:
                where += f" ({i.subject})"
            out.append(f"{i.status:<7} {i.check}{where}: {i.message}")
        c = self.counts()
        out.append(
            f"doctor: {self.overall} ({c[FAIL]} fail, {c[WARN]} warn, {c[UNKNOWN]} unknown, "
            f"{c[PASS]} pass)"
        )
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "counts": self.counts(),
            "issues": [i.to_dict() for i in self.issues],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class _Hook:
    source: str
    event: str
    matcher: Any
    type: Any
    command: str | None
    on_failure: Any
    group_on_failure: Any
    script: str | None


@dataclass
class _Ctx:
    root: str
    issues: list[Issue] = field(default_factory=list)

    def add(
        self,
        check: str,
        status: str,
        code: str,
        *,
        source: str | None = None,
        subject: str | None = None,
    ) -> None:
        if subject is not None:
            subject = _label(subject)
        self.issues.append(Issue(check, status, code, MESSAGES[code], source, subject))


def _label(value: str) -> str:
    text = "".join(ch if 0x20 <= ord(ch) != 0x7F else " " for ch in str(value))
    return text if len(text) <= 160 else text[:157] + "..."


# --------------------------------------------------------------------------- reading


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _real_dir(path: str) -> bool:
    st = _lstat(path)
    return st is not None and stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def _read_layer(project_root: str, rel: str, source: str) -> SettingsLayer:
    try:
        data = paths.read_authority(project_root, rel, MAX_SETTINGS_BYTES)
    except paths.UnsafePath:
        return SettingsLayer(source, None, "unsafe")
    except OSError:
        return SettingsLayer(source, None, "unreadable")
    if data is None:
        return SettingsLayer(source, None, "missing")
    try:
        doc = schema.strict_json(data, max_bytes=MAX_SETTINGS_BYTES, max_depth=64)
    except schema.Invalid:
        return SettingsLayer(source, None, "invalid")
    return SettingsLayer(source, doc, "ok")


def read_project_layers(project_root: str) -> tuple[SettingsLayer, SettingsLayer]:
    """``project`` (.claude/settings.json) and ``local`` (.claude/settings.local.json).

    Read only, no symlinks or hard links below the root, strict JSON (duplicate keys,
    NaN and a BOM are refused). User and managed layers are the caller's responsibility.
    """
    return (
        _read_layer(project_root, ".claude/settings.json", "project"),
        _read_layer(project_root, ".claude/settings.local.json", "local"),
    )


# --------------------------------------------------------------------------- frontmatter


def _unquote(text: str) -> str | None:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        inner = text[1:-1]
        if text[0] in inner:
            return None
        return inner
    if text[:1] in ("'", '"') or text[-1:] in ("'", '"'):
        return None
    return text


def _split_tools(text: str) -> list[str] | None:
    """Split ``Read, Grep, Bash(git log:*)`` on top-level commas."""
    out: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
        if ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if depth != 0:
        return None
    out.append("".join(buf))
    items = []
    for raw in out:
        item = _unquote(raw)
        if item is None:
            return None
        if item:
            items.append(item)
    return items


def parse_frontmatter(text: str) -> dict[str, Any] | None:
    """A small, conservative reader for agent frontmatter.

    Supported: ``key: scalar``, ``key: [a, b]`` and a block list (``key:`` followed by
    ``- item`` lines). A key followed by other indented lines is kept as ``...`` (complex,
    not interpreted). Returns None for anything else: no opening ``---``, no closing
    ``---``, CR line ends, tabs, a duplicate key or a line that is none of the above.
    """
    if not isinstance(text, str) or "\r" in text:
        return None
    lines = text.split("\n")
    if not lines or lines[0].rstrip(" ") != "---":
        return None
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].rstrip(" ") == "---")
    except StopIteration:
        return None
    out: dict[str, Any] = {}
    current: str | None = None
    for line in lines[1:end]:
        if "\t" in line:
            return None
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[0] == " " or stripped.startswith("- "):
            if current is None:
                return None
            value = out[current]
            if stripped.startswith("- ") and (value == [] or isinstance(value, list)):
                item = _unquote(stripped[2:])
                if item is None:
                    return None
                out[current] = [*value, item]
            elif value == [] or value is Ellipsis:
                out[current] = Ellipsis  # nested mapping or text: not interpreted
            else:
                return None
            continue
        key, sep, rest = line.partition(":")
        if not sep or not _KEY.fullmatch(key) or key in out:
            return None
        rest = rest.strip()
        if not rest:
            out[key] = []  # block list or nested value follows (or empty)
            current = key
            continue
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            out[key] = Ellipsis  # block scalar text: not interpreted
            current = key
            continue
        current = None
        if rest.startswith("["):
            if not rest.endswith("]"):
                return None
            items = _split_tools(rest[1:-1])
            if items is None:
                return None
            out[key] = items
            continue
        value = _unquote(rest)
        if value is None:
            return None
        out[key] = value
    return out


def _tools(value: Any) -> list[str] | None:
    if isinstance(value, list):
        items: list[str] = []
        for v in value:
            parts = _split_tools(v)
            if parts is None or len(parts) != 1:
                return None
            items.extend(parts)
        return items
    if isinstance(value, str):
        return _split_tools(value)
    return None


# --------------------------------------------------------------------------- checks


def _layers(ctx: _Ctx, layers: Any) -> list[SettingsLayer]:
    """Validated, usable layers (status ok, known source, mapping data)."""
    usable: list[SettingsLayer] = []
    seen: set[str] = set()
    items = list(layers) if isinstance(layers, Iterable) else []
    for layer in items:
        if not isinstance(layer, SettingsLayer) or layer.source not in SOURCES:
            src = layer.source if isinstance(layer, SettingsLayer) else None
            label = src if isinstance(src, str) and _LABEL.fullmatch(src) else None
            ctx.add("settings_layers", UNKNOWN, "layer_source_unknown", subject=label)
            continue
        if layer.source in seen:
            ctx.add("settings_layers", UNKNOWN, "layer_duplicate", source=layer.source)
        seen.add(layer.source)
        if layer.status == "missing":
            continue
        if layer.status != "ok":
            if layer.source in ("project", "local"):
                ctx.add("settings_layers", FAIL, "layer_invalid", source=layer.source)
            else:
                ctx.add("settings_layers", UNKNOWN, "layer_unmeasured", source=layer.source)
            continue
        if not isinstance(layer.data, Mapping):
            ctx.add("settings_layers", UNKNOWN, "layer_shape_unknown", source=layer.source)
            continue
        usable.append(layer)
    for source in _EXPECTED_SOURCES:
        if source not in seen:
            ctx.add("settings_layers", UNKNOWN, "layer_not_supplied", source=source)
    if not any(i.check == "settings_layers" for i in ctx.issues):
        ctx.add("settings_layers", PASS, "layers_ok")
    return usable


def _measured(layers_in: Any, source: str) -> str:
    """'ok' | 'missing' | 'unmeasured' for one source."""
    for layer in layers_in if isinstance(layers_in, Iterable) else []:
        if isinstance(layer, SettingsLayer) and layer.source == source:
            if layer.status == "missing":
                return "missing"
            if layer.status == "ok" and isinstance(layer.data, Mapping):
                return "ok"
            return "unmeasured"
    return "unmeasured"


def _disable_all(ctx: _Ctx, layers: list[SettingsLayer]) -> None:
    found = False
    for layer in layers:
        if "disableAllHooks" not in layer.data:
            continue
        value = layer.data["disableAllHooks"]
        if value is True:
            ctx.add("disable_all_hooks", FAIL, "disable_all_hooks", source=layer.source)
            found = True
        elif value is not False:
            ctx.add("disable_all_hooks", UNKNOWN, "disable_all_hooks_unknown", source=layer.source)
            found = True
    if not found:
        ctx.add("disable_all_hooks", PASS, "disable_all_hooks_off")


def _managed_flags(
    ctx: _Ctx, layers: list[SettingsLayer], managed_state: str
) -> tuple[bool, bool, bool]:
    """(hooks_only, rules_only, measured)."""
    if managed_state == "missing":
        ctx.add("managed_masking", PASS, "managed_masking_off", source="managed")
        return False, False, True
    managed = next((x for x in layers if x.source == "managed"), None)
    if managed is None:
        ctx.add("managed_masking", UNKNOWN, "managed_masking_unmeasured", source="managed")
        return False, False, False
    flags = []
    for key, code in (
        ("allowManagedHooksOnly", "managed_hooks_only"),
        ("allowManagedPermissionRulesOnly", "managed_rules_only"),
    ):
        value = managed.data.get(key, False)
        if value is True:
            # Whether it bites is decided per hook / per rule (hook_masked, deny_masked).
            ctx.add("managed_masking", WARN, code, source="managed")
            flags.append(True)
        elif value is False:
            flags.append(False)
        else:
            ctx.add("managed_masking", UNKNOWN, "managed_flag_unknown", source="managed",
                    subject=key)  # fmt: skip
            flags.append(True)  # an unreadable flag may mask: never assume it does not
    if not any(i.check == "managed_masking" for i in ctx.issues):
        ctx.add("managed_masking", PASS, "managed_masking_off", source="managed")
    return flags[0], flags[1], True


def _collect_hooks(ctx: _Ctx, layers: list[SettingsLayer]) -> list[_Hook]:
    out: list[_Hook] = []
    for layer in layers:
        if "hooks" not in layer.data:
            continue
        hooks = layer.data["hooks"]
        if not isinstance(hooks, Mapping):
            ctx.add("hooks", UNKNOWN, "hooks_schema_unknown", source=layer.source)
            continue
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                ctx.add("hooks", UNKNOWN, "hooks_schema_unknown", source=layer.source,
                        subject=str(event))  # fmt: skip
                continue
            for group in groups:
                if not isinstance(group, Mapping) or not isinstance(group.get("hooks"), list):
                    ctx.add("hooks", UNKNOWN, "hooks_schema_unknown", source=layer.source,
                            subject=str(event))  # fmt: skip
                    continue
                for handler in group["hooks"]:
                    if not isinstance(handler, Mapping):
                        ctx.add("hooks", UNKNOWN, "hooks_schema_unknown", source=layer.source,
                                subject=str(event))  # fmt: skip
                        continue
                    command = handler.get("command")
                    command = command if isinstance(command, str) else None
                    m = _HOOK_REF.search(command) if command else None
                    out.append(
                        _Hook(
                            layer.source,
                            str(event),
                            group.get("matcher"),
                            handler.get("type"),
                            command,
                            handler.get("onFailure"),
                            group.get("onFailure"),
                            m.group(1) if m else None,
                        )
                    )
    return out


def _hook_target(ctx: _Ctx, event: str, script: str) -> None:
    folder = ctx.root
    for part in HOOK_DIR:
        folder = os.path.join(folder, part)
        if not _real_dir(folder):
            code = "hook_target_missing" if _lstat(folder) is None else "hook_target_unsafe"
            ctx.add("hook_target", FAIL, code, subject=f"{event}: {script}")
            return
    st = _lstat(os.path.join(folder, script))
    if st is None:
        ctx.add("hook_target", FAIL, "hook_target_missing", subject=f"{event}: {script}")
    elif not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
        ctx.add("hook_target", FAIL, "hook_target_unsafe", subject=f"{event}: {script}")
    else:
        ctx.add("hook_target", PASS, "hook_target_ok", subject=f"{event}: {script}")


def _hooks(
    ctx: _Ctx,
    entries: list[_Hook],
    hook_scripts: Mapping[str, str],
    fail_closed: frozenset[str],
    hooks_only: bool,
) -> bool:
    """Required events. Returns True when a PreToolUse guard is registered and unmasked."""
    guard_ok = False
    for event in REQUIRED_EVENTS:
        script = hook_scripts.get(event)
        ours = [e for e in entries if e.event == event and script and e.script == script]
        live = [e for e in ours if not hooks_only or e.source == "managed"]
        if not live:
            code = "hook_masked" if ours else "hook_missing"
            ctx.add("hooks", FAIL, code, subject=event)
            continue
        commands = [e for e in live if e.type == "command"]
        if not commands:
            ctx.add("hooks", UNKNOWN, "hook_type_unknown", subject=event)
            continue
        if any(e.source in ("project", "managed") for e in commands):
            ctx.add("hooks", PASS, "hook_ok", subject=event)
        else:
            ctx.add("hooks", WARN, "hook_not_shared", source=commands[0].source, subject=event)
        _hook_target(ctx, event, script)
        if event in TOOL_EVENTS:
            matchers = [e.matcher for e in commands]
            if any(m in (None, "", "*") for m in matchers):
                pass
            elif all(isinstance(m, str) for m in matchers):
                sev = FAIL if event == "PreToolUse" else WARN
                ctx.add("hook_matcher", sev, "hook_matcher_narrow", subject=event)
            else:
                ctx.add("hook_matcher", UNKNOWN, "hook_matcher_unknown", subject=event)
        if event in fail_closed and event in ON_FAILURE_NO_EFFECT_EVENTS:
            # Documented: onFailure has no effect on Stop/SubagentStop. Only the prescribed
            # field is checked; a crash or timeout of this hook is never reported as blocked.
            if any(e.on_failure == "block" for e in commands):
                ctx.add("on_failure_field", PASS, "on_failure_field_no_effect", subject=event)
            elif any(e.group_on_failure == "block" for e in commands):
                ctx.add("on_failure_field", UNKNOWN, "on_failure_location", subject=event)
            else:
                ctx.add("on_failure_field", FAIL, "on_failure_field_missing", subject=event)
        elif event in fail_closed:
            if any(e.on_failure == "block" for e in commands):
                ctx.add("on_failure", PASS, "on_failure_ok", subject=event)
            elif any(e.group_on_failure == "block" for e in commands):
                ctx.add("on_failure", UNKNOWN, "on_failure_location", subject=event)
            else:
                ctx.add("on_failure", FAIL, "on_failure_missing", subject=event)
        if event == "PreToolUse":
            guard_ok = True
    plugin_hits = False
    for e in entries:
        if e.command and _PLUGIN_ROOT.search(e.command):
            plugin_hits = True
            if e.script is not None:
                ctx.add("plugin_root", FAIL, "hook_plugin_root", source=e.source, subject=e.event)
            else:
                ctx.add("plugin_root", WARN, "hook_plugin_root_other", source=e.source,
                        subject=e.event)  # fmt: skip
    if not plugin_hits:
        ctx.add("plugin_root", PASS, "hook_plugin_root_none")
    return guard_ok


def _rules(ctx: _Ctx, layers: list[SettingsLayer], key: str) -> dict[str, list[str]]:
    """Rule strings of one permissions list per source."""
    out: dict[str, list[str]] = {}
    for layer in layers:
        perms = layer.data.get("permissions")
        if perms is None:
            continue
        if not isinstance(perms, Mapping):
            ctx.add("permissions", UNKNOWN, "permissions_schema_unknown", source=layer.source)
            continue
        if key not in perms:
            continue
        values = perms[key]
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            ctx.add("permissions", UNKNOWN, "permissions_schema_unknown", source=layer.source,
                    subject=key)  # fmt: skip
            continue
        out.setdefault(layer.source, []).extend(values)
    return out


def _deny(
    ctx: _Ctx, layers: list[SettingsLayer], required: Sequence[str], rules_only: bool
) -> None:
    deny = _rules(ctx, layers, "deny")
    live = {r for src, rs in deny.items() if not rules_only or src == "managed" for r in rs}
    every = {r for rs in deny.values() for r in rs}
    missing = False
    for rule in required:
        if rule in live:
            continue
        missing = True
        ctx.add("deny_rules", FAIL, "deny_masked" if rule in every else "deny_missing",
                subject=rule)  # fmt: skip
    if not missing:
        ctx.add("deny_rules", PASS, "deny_ok")
    for key in ("allow", "ask"):
        for src, rs in _rules(ctx, layers, key).items():
            for rule in rs:
                if any(rule.startswith(h[:-3]) for h in HUMAN_COMMAND_RULES):
                    ctx.add("deny_rules", WARN, "human_command_allowed", source=src, subject=rule)


def _allow_gate(ctx: _Ctx, layers: list[SettingsLayer], guard_ok: bool) -> None:
    allow = _rules(ctx, layers, "allow")
    if not any(allow.values()):
        ctx.add("allow_gate", PASS, "allow_none")
    elif guard_ok:
        ctx.add("allow_gate", PASS, "allow_with_guard")
    else:
        ctx.add("allow_gate", FAIL, "allow_not_gate")


def _agents(ctx: _Ctx) -> None:
    rel_dir = ".claude/agents"
    folder = os.path.join(ctx.root, ".claude", "agents")
    st = _lstat(folder)
    if st is None:
        ctx.add("agents", FAIL, "agents_dir_missing")
        ctx.add("safety_reviewer", FAIL, "safety_reviewer_missing")
        return
    if (
        stat.S_ISLNK(st.st_mode)
        or not stat.S_ISDIR(st.st_mode)
        or not _real_dir(os.path.join(ctx.root, ".claude"))
    ):
        ctx.add("agents", FAIL, "agents_dir_unsafe")
        ctx.add("safety_reviewer", UNKNOWN, "safety_reviewer_missing")
        return
    try:
        with os.scandir(folder) as it:
            names = sorted(e.name for e in it if e.name.endswith(".md"))
    except OSError:
        ctx.add("agents", UNKNOWN, "agents_dir_unsafe")
        ctx.add("safety_reviewer", UNKNOWN, "safety_reviewer_missing")
        return
    if len(names) > MAX_AGENTS:
        ctx.add("agents", UNKNOWN, "agents_over_limit")
        names = names[:MAX_AGENTS]
    reviewer_seen = False
    reviewer_unknown = False
    for name in names:
        stem = name[:-3]
        try:
            data = paths.read_authority(ctx.root, f"{rel_dir}/{name}", MAX_AGENT_BYTES)
            text = data.decode("utf-8") if data is not None else None
        except (paths.UnsafePath, OSError, UnicodeDecodeError):
            text = None
        if text is None:
            ctx.add("agents", FAIL, "agent_file_unsafe", subject=stem)
            reviewer_unknown = reviewer_unknown or stem == SAFETY_REVIEWER
            continue
        fm = parse_frontmatter(text)
        if fm is None:
            ctx.add("agents", UNKNOWN, "agent_frontmatter_unknown", subject=stem)
            reviewer_unknown = reviewer_unknown or stem == SAFETY_REVIEWER
            continue
        agent = fm.get("name") if isinstance(fm.get("name"), str) and fm.get("name") else stem
        is_reviewer = SAFETY_REVIEWER in (agent, stem)
        if "tools" not in fm:
            ctx.add("agents", FAIL, "agent_tools_missing", subject=agent)
            if is_reviewer:
                reviewer_seen = True
                ctx.add("safety_reviewer", FAIL, "safety_reviewer_tools", subject=agent)
            continue
        tools = _tools(fm["tools"]) if fm["tools"] != [] else None
        if not tools:
            ctx.add("agents", UNKNOWN, "agent_tools_unknown", subject=agent)
            if is_reviewer:
                reviewer_seen = True
                ctx.add("safety_reviewer", UNKNOWN, "safety_reviewer_tools", subject=agent)
            continue
        if any("*" in t and "(" not in t for t in tools):
            ctx.add("agents", FAIL, "agent_tools_wildcard", subject=agent)
        else:
            ctx.add("agents", PASS, "agent_tools_ok", subject=agent)
        if is_reviewer:
            reviewer_seen = True
            if len(tools) == len(set(tools)) and set(tools) == SAFETY_REVIEWER_TOOLS:
                ctx.add("safety_reviewer", PASS, "safety_reviewer_ok", subject=agent)
            else:
                ctx.add("safety_reviewer", FAIL, "safety_reviewer_tools", subject=agent)
    if not reviewer_seen:
        sev = UNKNOWN if reviewer_unknown else FAIL
        ctx.add("safety_reviewer", sev, "safety_reviewer_missing")


def _parse_version(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    m = _VERSION.match(value)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _policy(ctx: _Ctx) -> str | None:
    """Strict policy and catalogue check (as the guard loads them). Returns min_claude_code."""
    try:
        data = paths.read_authority(ctx.root, "policy/policy.toml", schema.MAX_POLICY_BYTES)
        if data is None:
            raise schema.Invalid("policy_missing")
        policy = schema.load_policy(data)
        data = paths.read_authority(
            ctx.root, "policy/standard-changes.toml", schema.MAX_POLICY_BYTES
        )
        if data is None:
            raise schema.Invalid("catalog_missing")
        schema.load_catalog(data)
    except schema.Invalid as exc:
        ctx.add("policy", FAIL, "policy_invalid", subject=exc.code)
        return None
    except paths.UnsafePath as exc:
        ctx.add("policy", FAIL, "policy_invalid", subject=exc.code)
        return None
    except OSError:
        ctx.add("policy", FAIL, "policy_invalid", subject="unreadable")
        return None
    ctx.add("policy", PASS, "policy_ok")
    return policy.min_claude_code


def _version(ctx: _Ctx, version: Any, minimum: Any) -> None:
    if minimum is None:
        ctx.add("version", UNKNOWN, "min_version_unknown")
        return
    if version is None:
        ctx.add("version", UNKNOWN, "version_not_supplied")
        return
    have, need = _parse_version(version), _parse_version(minimum)
    if have is None or need is None:
        ctx.add("version", UNKNOWN, "version_unparsed")
    elif have < need:
        ctx.add("version", FAIL, "version_too_old", subject=f"{_vtext(have)} < {_vtext(need)}")
    else:
        ctx.add("version", PASS, "version_ok", subject=f"{_vtext(have)} >= {_vtext(need)}")


def _vtext(v: tuple[int, int, int]) -> str:
    return ".".join(str(x) for x in v)


def _manifest(ctx: _Ctx, manifest: Any) -> None:
    if manifest is None:
        ctx.add("manifest", UNKNOWN, "manifest_unmeasured")
        return
    if not isinstance(manifest, Mapping) or len(manifest) > MAX_MANIFEST_ENTRIES:
        ctx.add("manifest", UNKNOWN, "manifest_shape_unknown")
        return
    bad = False
    for rel, digest in sorted(manifest.items(), key=lambda kv: str(kv[0])):
        ok_rel = (
            isinstance(rel, str)
            and rel
            and "\x00" not in rel
            and not rel.startswith("/")
            and ".." not in rel.split("/")
            and _LABEL.fullmatch(rel) is not None
        )
        if not ok_rel or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            ctx.add("manifest", UNKNOWN, "manifest_entry_invalid",
                    subject=rel if isinstance(rel, str) and ok_rel else None)  # fmt: skip
            bad = True
            continue
        try:
            data = paths.read_authority(ctx.root, rel, MAX_MANIFEST_FILE_BYTES)
        except (paths.UnsafePath, OSError):
            ctx.add("manifest", FAIL, "manifest_file_unsafe", subject=rel)
            bad = True
            continue
        if data is None:
            ctx.add("manifest", FAIL, "manifest_file_missing", subject=rel)
            bad = True
        elif hashlib.sha256(data).hexdigest() != digest:
            ctx.add("manifest", FAIL, "manifest_mismatch", subject=rel)
            bad = True
    if not bad:
        ctx.add("manifest", PASS, "manifest_ok")


def _mods(ctx: _Ctx, mods: Any) -> None:
    if mods is None:
        ctx.add("mods", UNKNOWN, "mods_unmeasured")
        return
    if isinstance(mods, str | bytes | Mapping) or not isinstance(mods, Sequence):
        ctx.add("mods", UNKNOWN, "mod_metadata_unknown")
        return
    flagged = False
    for mod in list(mods)[:MAX_MODS]:
        name = mod.get("name") if isinstance(mod, Mapping) else None
        handles = mod.get("handles") if isinstance(mod, Mapping) else None
        enabled = mod.get("enabled", True) if isinstance(mod, Mapping) else None
        if (
            not isinstance(name, str)
            or not _LABEL.fullmatch(name)
            or not isinstance(handles, list)
            or not all(isinstance(h, str) for h in handles)
            or not isinstance(enabled, bool)
        ):
            ctx.add("mods", UNKNOWN, "mod_metadata_unknown")
            flagged = True
            continue
        if enabled and any(h in ("tool.check", "tool.call") for h in handles):
            ctx.add("mods", WARN, "mod_tool_check", subject=name)
            flagged = True
    if len(mods) > MAX_MODS:
        ctx.add("mods", UNKNOWN, "mod_metadata_unknown")
        flagged = True
    if not flagged:
        ctx.add("mods", PASS, "mods_ok")


# --------------------------------------------------------------------------- entry point


def inspect_project(
    project_root: str,
    settings_layers: Iterable[SettingsLayer],
    *,
    version: str | None = None,
    min_version: str | None = None,
    manifest: Mapping[str, str] | None = None,
    mods: Sequence[Mapping[str, Any]] | None = None,
    required_deny: Sequence[str] = DEFAULT_REQUIRED_DENY,
    hook_scripts: Mapping[str, str] = DEFAULT_HOOK_SCRIPTS,
    fail_closed_events: Iterable[str] = DEFAULT_FAIL_CLOSED_EVENTS,
) -> DoctorReport:
    """Static checks of one project. Read only; never raises for project content.

    ``settings_layers``: ``SettingsLayer`` per source the caller measured (use
    ``read_project_layers`` for project and local). ``version``: the running Claude Code
    version. ``min_version``: overrides ``policy.toml``'s ``min_claude_code``.
    ``manifest``: project-relative path -> SHA-256 hex (S9 adapts its manifest to this).
    ``mods``: ``[{"name": str, "enabled": bool, "handles": [str, ...]}]``.
    """
    notes = (
        "Command-line settings (--settings) are per launch and are not measured.",
        "No effective precedence is computed; list rules are merged from eligible layers.",
        "The SessionStart guard self test is not run here (S5).",
        "onFailure has no effect on Stop/SubagentStop; a crash or timeout of those hooks "
        "is not blocked, whatever the configuration says.",
    )
    if (
        not isinstance(project_root, str)
        or not os.path.isabs(project_root)
        or "\x00" in project_root
        or os.path.normpath(project_root) != project_root
        or not _real_dir(project_root)
    ):
        ctx = _Ctx("/")
        ctx.add("project", FAIL, "project_root_invalid")
        return DoctorReport(tuple(ctx.issues), notes)
    ctx = _Ctx(project_root)
    supplied = list(settings_layers) if isinstance(settings_layers, Iterable) else []
    layers = _layers(ctx, supplied)
    _disable_all(ctx, layers)
    hooks_only, rules_only, _ = _managed_flags(ctx, layers, _measured(supplied, "managed"))
    entries = _collect_hooks(ctx, layers)
    guard_ok = _hooks(ctx, entries, hook_scripts, frozenset(fail_closed_events), hooks_only)
    _deny(ctx, layers, required_deny, rules_only)
    _allow_gate(ctx, layers, guard_ok)
    _agents(ctx)
    policy_min = _policy(ctx)
    _version(ctx, version, min_version if min_version is not None else policy_min)
    _manifest(ctx, manifest)
    _mods(ctx, mods)
    return DoctorReport(tuple(ctx.issues), notes)
