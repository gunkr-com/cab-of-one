"""Deterministic rendering of a validated profile into project files (DESIGN §10-3, §10-6).

``render_bundle(profile, source_root)`` returns a ``Bundle``: a read-only mapping from
project-relative POSIX paths to bytes. It reads the source tree (this repository: rules,
templates, the runtime package to pin) and writes nothing. The same profile, rules and
source bytes always give the same bundle bytes: sorted keys, LF only, no timestamps, UUIDs
or environment-dependent content.

What the bundle holds, and who owns each artifact after ``apply`` (``artifact_kind``):

- ``settings-merge``: ``.claude/settings.json``. Our deny rules and hook groups, to be merged
  into the user's file by S9 (list items added, user items kept).
- ``claude-md-block``: ``CLAUDE.md``. Only the text between the cab-of-one markers.
- ``create-once``: ``policy/policy.toml`` and ``policy/standard-changes.toml`` (and the
  handoff notes ``PROGRESS.md``/``HANDOFF.md`` and the evidence READMEs
  ``changes/README.md``/``audit/README.md`` when a module maps them). Written on first
  apply, a person's files afterwards.
- ``gitignore-block``: ``.gitignore``. Only the cab-of-one marker block (S9
  ``merge.make_gitignore_block``) that keeps ``.cab/state/``, ``.cab/backups/`` and
  ``.cab/setup/`` out of version control. The person's other lines are never touched.
- ``generator-owned``: everything else (hook entries, pinned runtime package, agents, skills,
  demo files, and the session metadata ``.claude/hooks/cab/session-profile.json``). Tracked
  by hash in the S9 manifest.

``session-profile.json`` is generated from code, like the settings: exactly
``{"admin_identity": bool, "bypass_guarded": bool}`` in the canonical bytes of the pinned
``audithook.session_profile_bytes``. It carries two booleans only (no profile string, name
or secret). The SessionStart hook reads it to warn about an admin agent identity and about
bypass-guarded mode; a missing or damaged file there is an unmeasured-settings warning.

Pinned beside the runtime, always: ``cab_of_one/setup/__init__.py`` and
``cab_of_one/setup/manifest.py`` (``PINNED_SETUP``; standard library only). The installed
ConfigChange lock uses that manifest code as its default verifier, so a project needs
neither the plugin nor a source checkout. No other setup module is ever pinned.

``FLOOR_DENY`` and ``HOOKS`` are the runtime ``config_lock.FLOOR_DENY``/``FLOOR_HOOKS``
objects and the settings floor check is ``config_lock.floor_gap``: the floor written here
is the floor the pinned lock enforces.

``CLAUDE.md`` and ``.gitignore`` end with one LF here; S9 apply strips that LF before
handing the blocks to ``merge.plan_merge`` (``apply.merge_bundle``).

The core floor is checked on every render (``verify_floor``) and cannot be configured off:
deny rules for protected paths and human-only commands; fail-closed PreToolUse, Stop and
ConfigChange hooks; audit hooks; the SessionStart self-test hook; pinned hook entries and
runtime; the five agents with explicit tools (``safety-reviewer``: Read, Grep, Glob only);
the five core skills; a policy and catalogue the runtime schema accepts. A hook target the
source tree does not provide is a refusal, never a generated stub.

``stage_bundle`` (optional) writes a validated bundle to ``<project>/.cab/setup/staged/``
only. It never touches any other project path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import string
from collections.abc import Iterator, Mapping
from typing import Any

from ..runtime import audithook as runtime_audit
from ..runtime import config_lock as runtime_lock
from ..runtime import schema as runtime_schema
from ..runtime.adapters import ADAPTER_NAMES
from . import profile as profile_mod
from . import rules as rules_mod
from . import tomlw
from .merge import make_gitignore_block

__all__ = [
    "AGENT_TOOLS",
    "BLOCK_BEGIN",
    "BLOCK_END",
    "FLOOR_DENY",
    "HOOKS",
    "HOOK_ENTRIES",
    "PINNED_SETUP",
    "REQUIRED_FILES",
    "SESSION_PROFILE_PATH",
    "Bundle",
    "RenderError",
    "agent_tools",
    "artifact_kind",
    "render_bundle",
    "stage_bundle",
    "verify_floor",
]

SETTINGS_PATH = ".claude/settings.json"
POLICY_PATH = "policy/policy.toml"
CATALOG_PATH = "policy/standard-changes.toml"
CLAUDE_MD = "CLAUDE.md"
GITIGNORE_PATH = ".gitignore"
HANDOFF_FILES = ("HANDOFF.md", "PROGRESS.md")
#: Evidence READMEs: create-once person files (S9 manifest QUIET_FILES), never owned.
EVIDENCE_READMES = ("audit/README.md", "changes/README.md")
HOOK_DIR = runtime_lock.HOOK_DIR
#: Two-boolean SessionStart metadata (runtime ``audithook``); under the protected hook dir.
SESSION_PROFILE_PATH = runtime_audit.SESSION_PROFILE_PATH
RULES_PATH = "rules/modules.toml"
SIMTENANT_SCRIPT = "simtenant/simtenant.py"
STAGED_PARTS = (".cab", "setup", "staged")

BLOCK_BEGIN = "<!-- cab-of-one:begin -->"
BLOCK_END = "<!-- cab-of-one:end -->"
PLUGIN_ROOT_MARK = b"CLAUDE_PLUGIN_ROOT"

MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 2000
MAX_DEPTH = 8
IGNORED_NAMES = frozenset({"__pycache__", ".DS_Store"})
IGNORED_SUFFIXES = (".pyc", ".pyo")

# Deny rules for protected locations and human-only commands, and the hook table
# (event, matcher or None, entry file, argument, timeout seconds, fail closed). Both are
# the pinned runtime's own objects, so the installed ConfigChange lock checks this floor.
FLOOR_DENY: tuple[str, ...] = runtime_lock.FLOOR_DENY
HOOKS: tuple[tuple[str, str | None, str, str, int, bool], ...] = runtime_lock.FLOOR_HOOKS

#: (source path, project path) of the setup modules pinned beside the runtime for the
#: ConfigChange manifest check. Standard library only; nothing else from setup/ is pinned.
PINNED_SETUP_DIR = HOOK_DIR + "cab_of_one/setup/"
PINNED_SETUP: tuple[tuple[str, str], ...] = (
    ("src/cab_of_one/setup/__init__.py", PINNED_SETUP_DIR + "__init__.py"),
    ("src/cab_of_one/setup/manifest.py", PINNED_SETUP_DIR + "manifest.py"),
)
_PINNED_SETUP_DST = frozenset(dst for _src, dst in PINNED_SETUP)

CORE_AGENTS = ("impact-analyst", "recorder", "runbook-author", "safety-reviewer", "verifier")
CORE_SKILLS = ("blocker-catalog", "change", "change-intake", "readonly-probes", "tiering")
#: Upper bound of each agent's tools (base names). safety-reviewer must match exactly.
AGENT_TOOLS: Mapping[str, frozenset[str]] = {
    "impact-analyst": frozenset({"Read", "Grep", "Glob", "Bash"}),
    "runbook-author": frozenset({"Read", "Grep", "Glob", "Write"}),
    "safety-reviewer": frozenset({"Read", "Grep", "Glob"}),
    "verifier": frozenset({"Read", "Grep", "Glob", "Bash"}),
    "recorder": frozenset({"Read", "Grep", "Glob", "Write"}),
}
_READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob"})

HOOK_ENTRIES = ("guard.py", "audit.py", "closeout.py", "config_lock.py", "cab")  # cab = CLI

REQUIRED_FILES: tuple[str, ...] = tuple(
    sorted(
        {
            SETTINGS_PATH,
            POLICY_PATH,
            CATALOG_PATH,
            CLAUDE_MD,
            GITIGNORE_PATH,
            SESSION_PROFILE_PATH,
            *(HOOK_DIR + name for name in HOOK_ENTRIES),
            HOOK_DIR + "cab_of_one/__init__.py",
            HOOK_DIR + "cab_of_one/runtime/__init__.py",
            HOOK_DIR + "cab_of_one/runtime/guard.py",
            HOOK_DIR + "cab_of_one/runtime/config_lock.py",
            *_PINNED_SETUP_DST,
            *(f".claude/agents/{name}.md" for name in CORE_AGENTS),
            *(f".claude/skills/{name}/SKILL.md" for name in CORE_SKILLS),
        }
    )
)

_PATH_PART = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_OPEN_NEW = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

_EXTRA_CRITICAL_HINTS = {
    "admin-units": "administrative units that scope delegated admins",
    "break-glass": "emergency-access (break-glass) accounts",
    "executive-mailboxes": "executive mailboxes",
    "finance-groups": "finance groups and their mailboxes",
}
_ROUTINE_HINTS = {
    "forwarding-removal": "remove external forwarding from a mailbox",
    "group-add-allowlisted": "add a user to an allow-listed, non-privileged group",
    "joiner-license-group": "add a joiner to the standard licence group",
    "leaver-block-signin": "block sign-in for a leaver",
}


class RenderError(ValueError):
    """Rendering refused. ``detail`` is a project-relative path, module id or name."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------- bundle


class Bundle(Mapping[str, bytes]):
    """Read-only, sorted mapping of project-relative path -> bytes, plus render facts."""

    __slots__ = ("_files", "modules", "notices", "profile_sha256")

    def __init__(
        self,
        files: Mapping[str, bytes],
        modules: tuple[str, ...],
        notices: tuple[str, ...],
        profile_sha256: str,
    ) -> None:
        for path, data in files.items():
            if not _safe_output(path) or type(data) is not bytes:
                raise RenderError("bundle_entry", path if isinstance(path, str) else None)
        self._files = {path: files[path] for path in sorted(files)}
        self.modules = tuple(modules)
        self.notices = tuple(notices)
        self.profile_sha256 = profile_sha256

    def __getitem__(self, path: str) -> bytes:
        return self._files[path]

    def __iter__(self) -> Iterator[str]:
        return iter(self._files)

    def __len__(self) -> int:
        return len(self._files)

    def digest(self) -> str:
        """SHA-256 over ``path NUL length NUL bytes`` for every file in path order."""
        h = hashlib.sha256()
        for path, data in self._files.items():
            h.update(path.encode("utf-8") + b"\0" + str(len(data)).encode("ascii") + b"\0")
            h.update(data)
        return h.hexdigest()


def artifact_kind(path: str) -> str:
    """Ownership class of a bundle path after apply (see module docstring)."""
    if path == SETTINGS_PATH:
        return "settings-merge"
    if path == CLAUDE_MD:
        return "claude-md-block"
    if path == GITIGNORE_PATH:
        return "gitignore-block"
    if path in (POLICY_PATH, CATALOG_PATH) or path in HANDOFF_FILES or path in EVIDENCE_READMES:
        return "create-once"
    return "generator-owned"


# --------------------------------------------------------------------------- render


def render_bundle(
    profile: profile_mod.Profile,
    source_root: str | os.PathLike[str],
    *,
    rules: rules_mod.Rules | None = None,
) -> Bundle:
    """Render ``profile`` against the source tree at ``source_root``. Writes nothing."""
    root = _source_root(source_root)
    prof = profile_mod.revalidate(profile)
    _refuse_blocked(prof)
    if rules is None:
        rules = rules_mod.load_rules(_read_source(root, RULES_PATH))
    selected = rules_mod.select_modules(prof, rules)
    features = {f for m in selected for f in m.features}
    adapters = {a for m in selected for a in m.adapters}
    _check_coverage(prof, features, adapters)

    files: dict[str, bytes] = {}
    total = 0
    for module in selected:
        for spec in module.files:
            for src, dst in _expand(root, spec):
                data = _read_source(root, src)
                if spec.substitute:
                    data = _substitute(data, prof, dst)
                if dst in rules_mod.RESERVED_DST or not _safe_output(dst):
                    raise RenderError("reserved_output", dst)
                if dst in files:
                    raise RenderError("output_conflict", dst)
                total += len(data)
                if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
                    raise RenderError("source_too_large")
                files[dst] = data

    for path in files:
        if path.startswith(PINNED_SETUP_DIR):
            raise RenderError("reserved_output", path)
    for src, dst in PINNED_SETUP:
        data = _read_source(root, src)
        total += len(data)
        if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
            raise RenderError("source_too_large")
        files[dst] = data

    if CLAUDE_MD in files:
        files[CLAUDE_MD] = _claude_block(files[CLAUDE_MD])
    if GITIGNORE_PATH in files:
        raise RenderError("reserved_output", GITIGNORE_PATH)
    files[GITIGNORE_PATH] = _gitignore_block()
    if SESSION_PROFILE_PATH in files:
        raise RenderError("reserved_output", SESSION_PROFILE_PATH)
    files[SESSION_PROFILE_PATH] = _session_profile(prof)
    if "simtenant_trust" in features and SIMTENANT_SCRIPT not in files:
        raise RenderError("demo_files_missing", SIMTENANT_SCRIPT)
    files[SETTINGS_PATH] = _settings(prof, features)
    files[POLICY_PATH] = _policy(prof, features, adapters, selected)
    files[CATALOG_PATH] = _catalog(prof)

    verify_floor(files)
    notices = tuple(n for m in selected for n in m.notices)
    return Bundle(files, tuple(m.id for m in selected), notices, prof.sha256)


def _refuse_blocked(prof: profile_mod.Profile) -> None:
    """Profile answers the runtime cannot enforce yet are refused, never silently dropped."""
    if prof["approval.approvers"] == "named":
        raise RenderError("blocked_named_approvers", "approval.approvers")
    if prof["session.ticketing"] != "none":
        raise RenderError("blocked_ticketing", "session.ticketing")


def _check_coverage(prof: profile_mod.Profile, features: set[str], adapters: set[str]) -> None:
    """The rules must honour every profile value that tightens or fits the harness, and
    must not switch on the demo for a profile that did not ask for it."""
    need_features = set()
    if prof["surfaces.mcp_write_servers"]:
        need_features.add("mcp_write_servers")
    if prof["identity.deny_read_paths"]:
        need_features.add("read_deny_paths")
    if prof["session.permission_mode"] == "manual":
        need_features.add("disable_bypass_mode")
    demo = prof["systems.demo_simtenant"]
    if demo:
        if prof.reference is None:
            raise RenderError("demo_requires_reference", "systems.demo_simtenant")
        need_features.add("simtenant_trust")
    elif "simtenant_trust" in features or "simtenant" in adapters:
        raise RenderError("demo_not_requested", "systems.demo_simtenant")
    for name in sorted(need_features - features):
        raise RenderError("rules_missing_feature", name)

    m365 = any(
        prof[k]
        for k in (
            "systems.entra",
            "systems.exchange_online",
            "systems.intune",
            "systems.sharepoint_teams",
        )
    )
    need_adapters = set()
    if m365 or prof["surfaces.powershell_modules"]:
        need_adapters.add("m365-powershell")
    if m365 or prof["surfaces.graph_http"]:
        need_adapters.add("graph-http")
    if prof["systems.azure"] or prof["surfaces.azure_cli"]:
        need_adapters.add("azure-cli")
    if demo:
        need_adapters.add("simtenant")
    for name in sorted(need_adapters - adapters):
        raise RenderError("rules_missing_adapter", name)


def _template_vars(prof: profile_mod.Profile) -> dict[str, str]:
    return {
        "org_name": prof["org.name"],
        "it_team": prof["org.it_team"],
        "agent_identity": prof["identity.agent_identity"],
        "permission_mode": prof["session.permission_mode"],
        "approval_ttl_hours": str(prof["approval.approval_ttl_hours"]),
    }


def _substitute(data: bytes, prof: profile_mod.Profile, dst: str) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RenderError("template_encoding", dst) from None
    try:
        out = string.Template(text).substitute(_template_vars(prof))
    except (KeyError, ValueError):
        raise RenderError("template_variable", dst) from None
    return out.encode("utf-8")


def _claude_block(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RenderError("template_encoding", CLAUDE_MD) from None
    if BLOCK_BEGIN in text or BLOCK_END in text:
        raise RenderError("block_marker", CLAUDE_MD)
    if text and not text.endswith("\n"):
        text += "\n"
    return f"{BLOCK_BEGIN}\n{text}{BLOCK_END}\n".encode()


def _gitignore_block() -> bytes:
    """The private-state ignore block (S9 API), one trailing LF like ``CLAUDE.md``."""
    return make_gitignore_block() + b"\n"


def _session_profile(prof: profile_mod.Profile) -> bytes:
    """Two booleans from the validated profile enums; nothing else is copied."""
    return runtime_audit.session_profile_bytes(
        admin_identity=prof["identity.agent_identity"] == "admin",
        bypass_guarded=prof["session.permission_mode"] == "bypass-guarded",
    )


def _hook_command(entry: str, arg: str) -> str:
    return runtime_lock.hook_command(entry, arg)


def _settings(prof: profile_mod.Profile, features: set[str]) -> bytes:
    deny = list(FLOOR_DENY)
    if "read_deny_paths" in features:
        deny.extend(f"Read({path})" for path in prof["identity.deny_read_paths"])
    permissions: dict[str, Any] = {"deny": deny}
    if "disable_bypass_mode" in features:
        permissions["disableBypassPermissionsMode"] = "disable"
    hooks: dict[str, list[dict[str, Any]]] = {}
    for event, matcher, entry, arg, timeout, closed in HOOKS:
        hook: dict[str, Any] = {
            "type": "command",
            "command": _hook_command(entry, arg),
            "timeout": timeout,
        }
        if closed:
            hook["onFailure"] = "block"
        group: dict[str, Any] = {"hooks": [hook]}
        if matcher is not None:
            group["matcher"] = matcher
        hooks.setdefault(event, []).append(group)
    doc = {"hooks": hooks, "permissions": permissions}
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


_POLICY_HEADER = (
    "# Generated once by cab-of-one setup from the interview profile.\n"
    "# After apply this file belongs to a person; change it by pull request.\n"
    "# The core critical patterns live in the runtime and cannot be removed here.\n\n"
)
_CATALOG_HEADER = (
    "# Standard changes: pre-approved by a person. Generated once, empty.\n"
    "# The generator never writes an enabled entry. A person writes each [[entry]]\n"
    "# (id, enabled, adapter, command_pattern, target_scope, state_scope) by pull request.\n\n"
)


def _policy(
    prof: profile_mod.Profile,
    features: set[str],
    adapters: set[str],
    selected: list[rules_mod.Module],
) -> bytes:
    patterns = sorted({p for m in selected for p in m.critical_patterns})
    doc: dict[str, Any] = {
        "schema": 1,
        "harness": {
            "approval_ttl_hours": prof["approval.approval_ttl_hours"],
            "one_active_change": True,
        },
        "adapters": {"enabled": [name for name in ADAPTER_NAMES if name in adapters]},
        "tiers": {"critical_patterns": patterns},
        "execution": {"canary_tiers": ["critical"], "halt_on_failure": True},
    }
    servers = prof["surfaces.mcp_write_servers"]
    if "mcp_write_servers" in features and servers:
        doc["surfaces"] = {"mcp_write_servers": list(servers)}
    if "simtenant_trust" in features:
        doc["classifier"] = {"trusted_simtenant_scripts": [SIMTENANT_SCRIPT]}
    lines = [_POLICY_HEADER + tomlw.dumps(doc)]
    categories = sorted(set(prof["changes.extra_critical"]) | {"break-glass"})
    lines.append(
        "\n# Always-critical areas from the interview. Add a pattern to\n"
        "# [tiers].critical_patterns that names your real objects, for example\n"
        '# "*<object name>*". The generator does not know their names.\n'
    )
    lines.extend(f"# - {name}: {_EXTRA_CRITICAL_HINTS[name]}\n" for name in categories)
    data = "".join(lines).encode("utf-8")
    try:
        runtime_schema.load_policy(data)
    except runtime_schema.Invalid as exc:
        raise RenderError("policy_runtime_invalid", exc.code) from None
    return data


def _catalog(prof: profile_mod.Profile) -> bytes:
    lines = [_CATALOG_HEADER, "schema = 1\n"]
    routine = prof["changes.routine"]
    if routine:
        lines.append("\n# Proposals from the interview (not entries, not enabled):\n")
        lines.extend(f"# - {name}: {_ROUTINE_HINTS[name]}\n" for name in routine)
    data = "".join(lines).encode("utf-8")
    try:
        runtime_schema.load_catalog(data)
    except runtime_schema.Invalid as exc:
        raise RenderError("catalog_runtime_invalid", exc.code) from None
    return data


# --------------------------------------------------------------------------- floor


def verify_floor(files: Mapping[str, bytes]) -> None:
    """Raise ``RenderError`` unless ``files`` holds the whole core floor (DESIGN §10-4-4)."""
    for path in REQUIRED_FILES:
        if path not in files:
            raise RenderError("floor_missing", path)
    for path, data in files.items():
        if b"\r" in data:
            raise RenderError("not_lf", path)
        if PLUGIN_ROOT_MARK in data:
            raise RenderError("plugin_root_reference", path)
        if path.startswith(PINNED_SETUP_DIR) and path not in _PINNED_SETUP_DST:
            raise RenderError("floor_pinned_setup", path)

    block = files[CLAUDE_MD].decode("utf-8", "replace")
    if not (block.startswith(BLOCK_BEGIN + "\n") and block.endswith(BLOCK_END + "\n")):
        raise RenderError("floor_block", CLAUDE_MD)
    if files[GITIGNORE_PATH] != _gitignore_block():
        raise RenderError("floor_gitignore", GITIGNORE_PATH)

    _verify_settings(files)
    _verify_session_profile(files)

    try:
        policy = runtime_schema.load_policy(files[POLICY_PATH])
        catalog = runtime_schema.load_catalog(files[CATALOG_PATH])
    except runtime_schema.Invalid as exc:
        raise RenderError("floor_policy", exc.code) from None
    if "critical" not in policy.canary_tiers:
        raise RenderError("floor_policy", "canary")
    if any(entry.get("enabled") is True for entry in catalog):
        raise RenderError("floor_catalog", CATALOG_PATH)

    for path in files:
        if path.startswith(".claude/agents/") and path.endswith(".md"):
            name = path.rsplit("/", 1)[1][:-3]  # nested files count too (read-only limit)
            if path.count("/") > 2:
                name = ""
            tools = {_tool_base(t) for t in agent_tools(files[path], path)}
            limit = AGENT_TOOLS.get(name, _READ_ONLY_TOOLS)
            if not tools <= limit:
                raise RenderError("floor_agent_tools", path)
            if name == "safety-reviewer" and tools != AGENT_TOOLS["safety-reviewer"]:
                raise RenderError("floor_agent_tools", path)


def _verify_settings(files: Mapping[str, bytes]) -> None:
    try:
        doc = runtime_schema.strict_json(files[SETTINGS_PATH], max_bytes=MAX_FILE_BYTES)
    except runtime_schema.Invalid:
        raise RenderError("floor_settings", SETTINGS_PATH) from None
    if not isinstance(doc, dict):
        raise RenderError("floor_settings", SETTINGS_PATH)
    if "disableAllHooks" in doc:  # stricter than the lock: we never write the key at all
        raise RenderError("floor_settings", "disableAllHooks")
    gap = runtime_lock.floor_gap(doc)  # the same check the pinned ConfigChange lock runs
    if gap is not None:
        raise RenderError(*gap)
    for _event, _matcher, entry, _arg, _timeout, _closed in HOOKS:
        if HOOK_DIR + entry not in files:
            raise RenderError("floor_missing", HOOK_DIR + entry)


def _verify_session_profile(files: Mapping[str, bytes]) -> None:
    """Exact shape and types (the runtime parser), and agreement with the settings: a
    project whose settings disable bypass mode cannot claim to be bypass-guarded."""
    try:
        _admin, bypass = runtime_audit.parse_session_profile(files[SESSION_PROFILE_PATH])
    except ValueError:
        raise RenderError("floor_session_profile", SESSION_PROFILE_PATH) from None
    doc = json.loads(files[SETTINGS_PATH])  # already strictly parsed by _verify_settings
    permissions = doc.get("permissions")
    disabled = isinstance(permissions, dict) and "disableBypassPermissionsMode" in permissions
    if bypass and disabled:
        raise RenderError("floor_session_profile", SESSION_PROFILE_PATH)


def agent_tools(data: bytes, path: str = "agent") -> tuple[str, ...]:
    """The explicit ``tools:`` of an agent file's front matter. Refuses a missing list."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RenderError("agent_frontmatter", path) from None
    if not text.startswith("---\n"):
        raise RenderError("agent_frontmatter", path)
    end = text.find("\n---\n", 3)
    if end < 0:
        if text.endswith("\n---"):
            end = len(text) - 4
        else:
            raise RenderError("agent_frontmatter", path)
    lines = text[4:end].split("\n")
    found: list[str] | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.startswith("tools:"):
            continue
        if found is not None:
            raise RenderError("agent_tools_duplicate", path)
        value = line[len("tools:") :].strip()
        if value:
            if value.startswith("[") and value.endswith("]"):
                value = value[1:-1]
            found = [_unquote(v) for v in value.split(",") if v.strip()]
        else:
            found = []
            while index < len(lines) and re.match(r"^\s+-\s+\S", lines[index]):
                found.append(_unquote(lines[index].strip()[1:]))
                index += 1
    if not found:
        raise RenderError("agent_tools_missing", path)
    return tuple(found)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    return value


def _tool_base(tool: str) -> str:
    return tool.split("(", 1)[0].strip()


# --------------------------------------------------------------------------- source reads


def _source_root(source_root: str | os.PathLike[str]) -> str:
    root = os.fspath(source_root)
    if not isinstance(root, str) or not root or "\x00" in root:
        raise RenderError("source_root")
    root = os.path.abspath(root)
    st = _lstat(root)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RenderError("source_root")
    return root


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None


def _parts(rel: str) -> list[str]:
    parts = rel.rstrip("/").split("/")
    for part in parts:
        if not _PATH_PART.fullmatch(part) or set(part) == {"."}:
            raise RenderError("source_path", rel)
    return parts


def _real_dir(root: str, parts: list[str], rel: str) -> str:
    """``root/parts`` after checking that every component is a real directory."""
    cursor = root
    for part in parts:
        cursor = os.path.join(cursor, part)
        st = _lstat(cursor)
        if st is None:
            raise RenderError("source_missing", rel)
        if stat.S_ISLNK(st.st_mode):
            raise RenderError("source_symlink", rel)
        if not stat.S_ISDIR(st.st_mode):
            raise RenderError("source_not_dir", rel)
    return cursor


def _read_source(root: str, rel: str) -> bytes:
    parts = _parts(rel)
    folder = _real_dir(root, parts[:-1], rel)
    path = os.path.join(folder, parts[-1])
    try:
        fd = os.open(path, _OPEN_READ)
    except FileNotFoundError:
        raise RenderError("source_missing", rel) from None
    except OSError:
        if os.path.islink(path):
            raise RenderError("source_symlink", rel) from None
        raise RenderError("source_unreadable", rel) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RenderError("source_not_regular", rel)
        if st.st_size > MAX_FILE_BYTES:
            raise RenderError("source_too_large", rel)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_FILE_BYTES:
            chunk = os.read(fd, MAX_FILE_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    if total > MAX_FILE_BYTES:
        raise RenderError("source_too_large", rel)
    return b"".join(chunks)


def _expand(root: str, spec: rules_mod.FileSpec) -> list[tuple[str, str]]:
    """(source rel, project rel) pairs of a file spec; directories walk in name order."""
    if not spec.is_dir:
        return [(spec.src, spec.dst)]
    base = _real_dir(root, _parts(spec.src), spec.src)
    out: list[tuple[str, str]] = []
    _walk(base, spec.src, spec.dst, 0, out)
    if not out:
        raise RenderError("source_empty", spec.src)
    return out


def _walk(folder: str, src: str, dst: str, depth: int, out: list[tuple[str, str]]) -> None:
    if depth > MAX_DEPTH:
        raise RenderError("source_too_deep", src)
    with os.scandir(folder) as entries:
        names = sorted(entries, key=lambda e: e.name)
    for entry in names:
        name = entry.name
        if name in IGNORED_NAMES or name.endswith(IGNORED_SUFFIXES):
            continue
        rel = src + name
        if not _PATH_PART.fullmatch(name) or set(name) == {"."}:
            raise RenderError("source_name", src)
        if entry.is_symlink():
            raise RenderError("source_symlink", rel)
        if entry.is_dir(follow_symlinks=False):
            _walk(entry.path, rel + "/", dst + name + "/", depth + 1, out)
        elif entry.is_file(follow_symlinks=False):
            out.append((rel, dst + name))
            if len(out) > MAX_FILES:
                raise RenderError("source_too_large", src)
        else:
            raise RenderError("source_not_regular", rel)


def _safe_output(path: Any) -> bool:
    if type(path) is not str or not path or len(path) > 512 or path.startswith("/"):
        return False
    return all(_PATH_PART.fullmatch(p) and set(p) != {"."} for p in path.split("/"))


# --------------------------------------------------------------------------- staging


def stage_bundle(bundle: Bundle, project_root: str | os.PathLike[str]) -> str:
    """Write ``bundle`` to ``<project_root>/.cab/setup/staged/`` and return that path.

    The bundle's floor is verified first. ``staged`` must not exist yet (the caller decides
    what to do with an old one). Files are written into a fresh sibling folder and renamed
    into place, so a failure leaves no partial ``staged``. Only ``.cab/``, ``.cab/setup/`` and
    the staged tree are ever created; no other project path is touched.
    """
    if not isinstance(bundle, Bundle):
        raise RenderError("not_bundle")
    verify_floor(bundle)
    root = os.fspath(project_root)
    if not isinstance(root, str) or not os.path.isabs(root) or "\x00" in root:
        raise RenderError("project_root")
    root = os.path.normpath(root)
    st = _lstat(root)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RenderError("project_root")
    setup = root
    for part in STAGED_PARTS[:-1]:
        setup = os.path.join(setup, part)
        st = _lstat(setup)
        if st is None:
            os.mkdir(setup, 0o700)
            st = _lstat(setup)
        if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise RenderError("stage_unsafe", "/".join(STAGED_PARTS[:-1]))
    staged = os.path.join(setup, STAGED_PARTS[-1])
    if _lstat(staged) is not None:
        raise RenderError("staged_exists", "/".join(STAGED_PARTS))
    work = staged + ".partial"
    if _lstat(work) is not None:
        raise RenderError("staged_exists", "/".join(STAGED_PARTS) + ".partial")

    made_dirs: list[str] = []
    made_files: list[str] = []
    try:
        os.mkdir(work, 0o700)
        made_dirs.append(work)
        for path, data in bundle.items():
            parts = path.split("/")
            cursor = work
            for part in parts[:-1]:
                cursor = os.path.join(cursor, part)
                if _lstat(cursor) is None:
                    os.mkdir(cursor, 0o700)
                    made_dirs.append(cursor)
                st = _lstat(cursor)
                if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    raise RenderError("stage_unsafe", path)
            target = os.path.join(cursor, parts[-1])
            fd = os.open(target, _OPEN_NEW, 0o600)
            made_files.append(target)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
        if _lstat(staged) is not None:
            raise RenderError("staged_exists", "/".join(STAGED_PARTS))
        os.rename(work, staged)
    except BaseException:
        for path in reversed(made_files):
            try:
                os.unlink(path)
            except OSError:
                pass
        for path in reversed(made_dirs):
            try:
                os.rmdir(path)
            except OSError:
                pass
        raise
    return staged
