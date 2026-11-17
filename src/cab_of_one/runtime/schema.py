"""Strict, fail-closed parsers for hook events and S4 authority files.

Every refusal is ``Invalid(code)``; the code is a fixed identifier and never contains the
offending value. JSON rejects duplicate keys, NaN/Infinity, a BOM, non-objects, oversized
and over-deep input. TOML goes through ``tomllib`` (which rejects duplicate keys) and the
same depth/finite checks; TOML dates are refused. ``bool`` is never accepted as an int.

Authority files carry ``schema = 1`` and exactly the documented keys. Hook events are the
exception: Claude Code may add documented common metadata, so unknown event keys are
ignored and only the fields the guard uses are type-checked.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .adapters import ADAPTER_NAMES
from .adapters import simtenant as simtenant_adapter
from .classify import TIERS, classify_tool_call

__all__ = [
    "DEFAULT_RETRY_SECONDS",
    "DEFAULT_SUBAGENT_BASH_ALLOW",
    "FORBIDDEN_SUBAGENT_PROGRAMS",
    "MAX_VERIFY_BYTES",
    "MAX_VERIFY_RECORD_BYTES",
    "OBSERVATION_STATUSES",
    "RECEIPT_SOURCES",
    "STATES",
    "TIER_RANK",
    "ChangePlan",
    "Check",
    "Event",
    "Invalid",
    "Policy",
    "Step",
    "VerifySpec",
    "canonical_bytes",
    "canonical_json",
    "input_sha256",
    "is_agent_id",
    "is_change_id",
    "is_hex64",
    "is_slug",
    "is_token",
    "load_catalog",
    "load_change",
    "load_policy",
    "parse_active",
    "parse_approval",
    "parse_event",
    "parse_observation",
    "parse_review",
    "parse_snapshot",
    "parse_state",
    "parse_targets",
    "parse_verify_doc",
    "parse_verify_record",
    "snapshot_complete",
    "strict_json",
    "strict_json_value",
    "strict_toml",
    "utc_parse",
    "utc_text",
    "verify_aggregate",
]

SCHEMA_VERSION = 1
TIER_RANK = {"standard": 0, "normal": 1, "critical": 2}
# S5: "verifying" is gone. Verification never ends execution; only Store.close makes a
# terminal transition (closed, failed or the still-active open-unverified).
STATES = (
    "draft",
    "planned",
    "reviewed",
    "approved",
    "executing",
    "halted",
    "closed",
    "failed",
    "open-unverified",
)
VERDICTS = ("PASS", "PASS_WITH_CONDITIONS", "BLOCK")
OUTCOMES = ("ok", "failed", "unknown")
VERIFY_VALUES = ("PASS", "FAIL", "UNMEASURED")
CANARY_STATES = ("pending", "awaiting", "passed")
RECEIPT_SOURCES = ("post", "failure", "resume")
OBSERVATION_STATUSES = ("active", "soft_deleted", "absent", "unmeasured")
EXPECT_STATUSES = ("active", "soft_deleted", "absent")
CHECK_OPS = ("eq", "ne", "contains", "not_contains")

MAX_OBSERVATION_BYTES = 64 * 1024
MAX_VERIFY_BYTES = 4 * 1024 * 1024
MAX_VERIFY_RECORD_BYTES = 64 * 1024
MAX_VERIFY_RECORDS = 65536
MAX_JSON_VALUE_BYTES = 1024
MAX_JSON_VALUE_DEPTH = 8
MAX_CHECKS = 16

MAX_POLICY_BYTES = 256 * 1024
MAX_PLAN_BYTES = 256 * 1024
MAX_TARGETS_BYTES = 1024 * 1024
MAX_AUTHORITY_BYTES = 1024 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_TARGETS = 10_000
MAX_UNITS = 10_000

DEFAULT_RETRY_SECONDS = (2, 5, 10, 20, 40)
# Read-only programs a subagent may run when the classifier says not-admin. Every
# command is additionally scanned: any file write other than /dev/null is refused.
DEFAULT_SUBAGENT_BASH_ALLOW = (
    "cat",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "wc",
    "ls",
    "stat",
    "file",
    "jq",
    "sort",
    "uniq",
    "cut",
    "tr",
    "diff",
    "cmp",
    "comm",
    "echo",
    "printf",
    "pwd",
    "true",
    "false",
    "test",
    "[",
    "date",
    "basename",
    "dirname",
    "readlink",
    "realpath",
    "shasum",
    "sha256sum",
    "md5",
    "md5sum",
    "column",
    "nl",
    "od",
    "hexdump",
    "strings",
    "du",
    "df",
    "tree",
    "which",
)
# Programs that can run other code, change files or reach the network: never allow-listed.
FORBIDDEN_SUBAGENT_PROGRAMS = frozenset(
    {
        "bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh",
        "python", "python3", "pypy", "pypy3", "node", "nodejs", "deno", "bun", "ruby",
        "perl", "php", "lua", "rscript", "osascript", "tclsh", "wish", "expect", "pwsh",
        "powershell", "awk", "gawk", "mawk", "nawk", "sed", "jshell", "npx", "uv", "uvx",
        "env", "xargs", "sudo", "doas", "nohup", "timeout", "time", "nice", "ionice",
        "stdbuf", "exec", "eval", "command", "builtin", "source", ".", "find", "git",
        "script", "unbuffer", "socat", "tmux", "screen", "setsid", "chroot",
        "tee", "cp", "mv", "rm", "ln", "install", "rsync", "truncate", "touch", "chmod",
        "chown", "chgrp", "dd", "mkdir", "rmdir", "unlink", "shred", "mkfifo", "mknod",
        "curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "telnet", "ftp",
        "cab", "simtenant", "az", "gam", "aws", "m365", "mgc", "gcloud", "kubectl",
        "terraform", "pulumi", "azcopy", "make", "open", "launchctl",
        "crontab", "at", "watch", "vim", "vi", "nano", "emacs", "ed", "ex",
    }
)  # fmt: skip
_PYTHON_NAME = re.compile(r"^python[0-9.]*$")

_CHANGE_ID = re.compile(r"CHG-[0-9]{4}")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
_TARGET = re.compile(r"[a-z]+/[A-Za-z0-9._-]{1,64}")
_STEP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_AGENT_ID = re.compile(r"[A-Za-z0-9_.:@-]{1,128}")
_AGENT_TYPE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_ENTRY_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,47}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_TOOL = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,127}")
_SERVER = re.compile(r"[A-Za-z0-9_-]{1,64}")
_PROGRAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}")
_FINDING_CODE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_CONTROL_TEXT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # allows \t and \n
_PATTERN_SPECIALS = frozenset("*?[")


class Invalid(Exception):
    """Fail-closed refusal with a fixed reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------- encodings


def canonical_json(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    )


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON plus one LF. ASCII only, so U+2028/U+2029 are always escaped."""
    return (canonical_json(obj) + "\n").encode("ascii")


def input_sha256(tool_input: Any) -> str:
    """SHA-256 of the canonical JSON of a tool input (step binding for MCP tools)."""
    return hashlib.sha256(canonical_json(tool_input).encode("ascii")).hexdigest()


def utc_text(ts: float) -> str:
    moment = datetime.fromtimestamp(ts, UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def utc_parse(value: Any, code: str = "time") -> float:
    if type(value) is not str or not _UTC.fullmatch(value):
        raise Invalid(code)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").timestamp()
    except ValueError:
        raise Invalid(code) from None


# --------------------------------------------------------------------------- documents


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Invalid("duplicate_key")
        out[key] = value
    return out


def _no_constant(_name: str) -> Any:
    raise Invalid("non_finite")


def _walk(value: Any, depth: int, max_depth: int, *, toml: bool) -> None:
    if depth > max_depth:
        raise Invalid("too_deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise Invalid("key_type")
            _walk(item, depth + 1, max_depth, toml=toml)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, max_depth, toml=toml)
    elif type(value) is float:
        if not math.isfinite(value):
            raise Invalid("non_finite")
    elif value is None:
        if toml:
            raise Invalid("value_type")
    elif type(value) not in (str, int, bool):
        raise Invalid("value_type")


def _decode(data: Any, max_bytes: int) -> str:
    if not isinstance(data, bytes | bytearray):
        raise Invalid("not_bytes")
    if len(data) > max_bytes:
        raise Invalid("too_large")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("encoding") from None
    if text.startswith("﻿"):
        raise Invalid("bom")
    return text


def strict_json(data: Any, *, max_bytes: int, max_depth: int = MAX_DEPTH) -> dict[str, Any]:
    text = _decode(data, max_bytes)
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)
    except Invalid:
        raise
    except RecursionError:
        raise Invalid("too_deep") from None
    except ValueError:
        raise Invalid("syntax") from None
    if not isinstance(value, dict):
        raise Invalid("not_object")
    _walk(value, 0, max_depth, toml=False)
    return value


def strict_json_value(data: Any) -> Any:
    """One strict JSON value of any type (``[[verify]]`` check values).

    ``data`` is the JSON text (str or bytes), at most 1 KiB and 8 levels deep. Duplicate
    keys, NaN/Infinity, a BOM and non-string keys are refused as in ``strict_json``.
    """
    if isinstance(data, str):
        try:
            data = data.encode("utf-8")
        except UnicodeEncodeError:
            raise Invalid("encoding") from None
    text = _decode(data, MAX_JSON_VALUE_BYTES)
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)
    except Invalid:
        raise
    except RecursionError:
        raise Invalid("too_deep") from None
    except ValueError:
        raise Invalid("syntax") from None
    _walk(value, 0, MAX_JSON_VALUE_DEPTH, toml=False)
    return value


def strict_toml(data: Any, *, max_bytes: int, max_depth: int = 16) -> dict[str, Any]:
    text = _decode(data, max_bytes)
    try:
        value = tomllib.loads(text)
    except RecursionError:
        raise Invalid("too_deep") from None
    except (tomllib.TOMLDecodeError, ValueError):
        raise Invalid("syntax") from None
    _walk(value, 0, max_depth, toml=True)
    return value


# --------------------------------------------------------------------------- field checks


def _keys(obj: Any, required: set[str], optional: frozenset[str] | set[str], code: str) -> None:
    if not isinstance(obj, dict):
        raise Invalid(code)
    keys = set(obj)
    if not required <= keys or keys - required - set(optional):
        raise Invalid(code)


def _str(
    value: Any,
    code: str,
    *,
    max_len: int,
    pattern: re.Pattern[str] | None = None,
    empty: bool = False,
    text: bool = False,
) -> str:
    if type(value) is not str or len(value) > max_len or (not value and not empty):
        raise Invalid(code)
    if (_CONTROL_TEXT if text else _CONTROL).search(value):
        raise Invalid(code)
    if pattern is not None and not pattern.fullmatch(value):
        raise Invalid(code)
    return value


def _bool(value: Any, code: str) -> bool:
    if type(value) is not bool:
        raise Invalid(code)
    return value


def _int(value: Any, code: str, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise Invalid(code)
    return value


def _list(value: Any, code: str, max_len: int, *, nonempty: bool = False) -> list[Any]:
    if type(value) is not list or len(value) > max_len or (nonempty and not value):
        raise Invalid(code)
    return value


def _str_list(
    value: Any, code: str, *, max_items: int, max_len: int, pattern: re.Pattern[str] | None = None
) -> tuple[str, ...]:
    items = _list(value, code, max_items)
    out = tuple(_str(v, code, max_len=max_len, pattern=pattern) for v in items)
    if len(set(out)) != len(out):
        raise Invalid(code)
    return out


def _hex64(value: Any, code: str) -> str:
    return _str(value, code, max_len=64, pattern=_HEX64)


def _opt(value: Any, check: Any, code: str) -> Any:
    return None if value is None else check(value, code)


def _step_id(value: Any, code: str) -> str:
    return _str(value, code, max_len=32, pattern=_STEP_ID)


def _token(value: Any, code: str) -> str:
    return _str(value, code, max_len=128, pattern=_TOKEN)


def _change_id(value: Any, code: str) -> str:
    return _str(value, code, max_len=8, pattern=_CHANGE_ID)


def _nonce(value: Any, code: str) -> str:
    return _str(value, code, max_len=32, pattern=_HEX32)


def is_change_id(value: Any) -> bool:
    return type(value) is str and bool(_CHANGE_ID.fullmatch(value))


def is_slug(value: Any) -> bool:
    return type(value) is str and bool(_SLUG.fullmatch(value))


def is_token(value: Any) -> bool:
    """tool_use_id / session_id shape."""
    return type(value) is str and bool(_TOKEN.fullmatch(value))


def is_agent_id(value: Any) -> bool:
    return type(value) is str and bool(_AGENT_ID.fullmatch(value))


def is_hex64(value: Any) -> bool:
    return type(value) is str and bool(_HEX64.fullmatch(value))


def _schema(doc: dict[str, Any]) -> None:
    if type(doc.get("schema")) is not int or doc.get("schema") != SCHEMA_VERSION:
        raise Invalid("schema_version")


def _target(value: Any, code: str) -> str:
    return _str(value, code, max_len=128, pattern=_TARGET)


def _targets(value: Any, code: str, *, nonempty: bool) -> tuple[str, ...]:
    items = _list(value, code, MAX_TARGETS, nonempty=nonempty)
    out = tuple(_target(v, code) for v in items)
    if len(set(out)) != len(out):
        raise Invalid(code)
    return out


# --------------------------------------------------------------------------- hook event


@dataclass(frozen=True)
class Event:
    tool_name: str
    tool_input: dict[str, Any]
    session_id: str | None
    cwd: str | None
    tool_use_id: str | None
    is_subagent: bool
    agent_id: str | None
    agent_type: str | None


def parse_event(data: Mapping[str, Any]) -> Event:
    """Type-check the fields the guard uses. Unknown (added) metadata keys are ignored.

    ``agent_id`` marks a subagent or teammate: if the key is present the call is never
    treated as the main session, even when the value is empty or malformed (the role is
    then unknown). ``agent_type`` alone can describe a main session started with
    ``--agent`` and does not make a call a subagent.
    """
    if not isinstance(data, Mapping):
        raise Invalid("event")
    tool_name = _str(data.get("tool_name"), "tool_name", max_len=256)
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        raise Invalid("tool_input")

    def optional(key: str, pattern: re.Pattern[str]) -> str | None:
        if key not in data:
            return None
        return _str(data[key], key, max_len=128, pattern=pattern)

    session_id = optional("session_id", _TOKEN)
    tool_use_id = optional("tool_use_id", _TOKEN)
    cwd = None
    if "cwd" in data:
        cwd = _str(data["cwd"], "cwd", max_len=4096)
        if not os.path.isabs(cwd):
            raise Invalid("cwd")
    is_subagent = "agent_id" in data
    agent_id = None
    if is_subagent:
        raw = data.get("agent_id")
        if type(raw) is str and _AGENT_ID.fullmatch(raw):
            agent_id = raw
    agent_type = None
    raw_type = data.get("agent_type")
    if type(raw_type) is str and _AGENT_TYPE.fullmatch(raw_type):
        agent_type = raw_type
    return Event(
        tool_name, tool_input, session_id, cwd, tool_use_id, is_subagent, agent_id, agent_type
    )


# --------------------------------------------------------------------------- policy


@dataclass(frozen=True)
class Policy:
    """Validated ``policy/policy.toml``. ``s3`` is exactly what the S3 classifier reads."""

    s3: dict[str, Any]
    ttl_hours: int
    canary_tiers: frozenset[str]
    retry_seconds: tuple[int, ...]
    extra_patterns: tuple[str, ...]
    subagent_bash_allow: frozenset[str]
    min_claude_code: str | None

    def s3_for(self, cwd_is_project: bool) -> dict[str, Any]:
        """S3 policy for one call. Outside the project root a relative path names another
        file, so relative trusted simtenant scripts and path-like commands are dropped
        (they then classify as unknown-admin). Bare command words and absolute paths stay.
        """
        if cwd_is_project or "classifier" not in self.s3:
            return self.s3
        clf = dict(self.s3["classifier"])
        if "trusted_simtenant_scripts" in clf:
            clf["trusted_simtenant_scripts"] = [
                v for v in clf["trusted_simtenant_scripts"] if v.startswith("/")
            ]
        if "trusted_simtenant_commands" in clf:
            clf["trusted_simtenant_commands"] = [
                v for v in clf["trusted_simtenant_commands"] if v.startswith("/") or "/" not in v
            ]
        out = dict(self.s3)
        out["classifier"] = clf
        return out


def _table(doc: dict[str, Any], key: str, required: set[str], optional: set[str]) -> dict:
    value = doc.get(key, {})
    _keys(value, required, optional, f"policy_{key}")
    return value


def load_policy(data: bytes) -> Policy:
    doc = strict_toml(data, max_bytes=MAX_POLICY_BYTES)
    _keys(
        doc,
        {"schema", "harness", "adapters", "tiers", "execution"},
        {"surfaces", "classifier", "verify", "redaction", "guard"},
        "policy_keys",
    )
    _schema(doc)

    harness = _table(
        doc, "harness", {"approval_ttl_hours", "one_active_change"}, {"min_claude_code"}
    )
    ttl = _int(harness["approval_ttl_hours"], "policy_ttl", 1, 24)
    if harness["one_active_change"] is not True:
        raise Invalid("policy_floor")
    min_cc = None
    if "min_claude_code" in harness:
        min_cc = _str(harness["min_claude_code"], "policy_version", max_len=32, pattern=_VERSION)

    adapters = _table(doc, "adapters", {"enabled"}, set())
    enabled = _str_list(adapters["enabled"], "policy_adapters", max_items=8, max_len=32)
    if not set(enabled) <= set(ADAPTER_NAMES):
        raise Invalid("policy_adapters")

    tiers = _table(doc, "tiers", {"critical_patterns"}, set())
    patterns = _str_list(tiers["critical_patterns"], "policy_patterns", max_items=256, max_len=256)

    execution = _table(doc, "execution", {"canary_tiers", "halt_on_failure"}, set())
    canary = _str_list(execution["canary_tiers"], "policy_canary", max_items=3, max_len=16)
    if not set(canary) <= set(TIERS) or "critical" not in canary:
        raise Invalid("policy_floor")
    if execution["halt_on_failure"] is not True:
        raise Invalid("policy_floor")

    s3: dict[str, Any] = {
        "adapters": {"enabled": list(enabled)},
        "tiers": {"critical_patterns": list(patterns)},
    }
    if "surfaces" in doc:
        surfaces = _table(doc, "surfaces", set(), {"mcp_write_servers"})
        if "mcp_write_servers" in surfaces:
            s3["surfaces"] = {
                "mcp_write_servers": list(
                    _str_list(
                        surfaces["mcp_write_servers"],
                        "policy_surfaces",
                        max_items=64,
                        max_len=64,
                        pattern=_SERVER,
                    )
                )
            }
    if "classifier" in doc:
        clf_keys = {
            "trusted_simtenant_commands",
            "trusted_simtenant_scripts",
            "simtenant_resources",
            "mcp_read_tools",
            "not_admin_tools",
        }
        clf = _table(doc, "classifier", set(), clf_keys)
        s3["classifier"] = {
            key: list(_str_list(value, "policy_classifier", max_items=128, max_len=256))
            for key, value in clf.items()
        }
        for tool in s3["classifier"].get("not_admin_tools", []):
            if not _TOOL.fullmatch(tool):
                raise Invalid("policy_classifier")

    retry = DEFAULT_RETRY_SECONDS
    if "verify" in doc:
        verify = _table(doc, "verify", set(), {"retry_seconds"})
        if "retry_seconds" in verify:
            items = _list(verify["retry_seconds"], "policy_verify", 10, nonempty=True)
            retry = tuple(_int(v, "policy_verify", 0, 600) for v in items)

    extra: tuple[str, ...] = ()
    if "redaction" in doc:
        redaction = _table(doc, "redaction", set(), {"extra_patterns"})
        if "extra_patterns" in redaction:
            extra = _str_list(
                redaction["extra_patterns"], "policy_redaction", max_items=64, max_len=512
            )
            for pattern in extra:
                try:
                    if re.compile(pattern).search(""):
                        raise Invalid("policy_redaction")  # would match everywhere
                except re.error:
                    raise Invalid("policy_redaction") from None

    allow = DEFAULT_SUBAGENT_BASH_ALLOW
    if "guard" in doc:
        guard = _table(doc, "guard", set(), {"subagent_bash_allow"})
        if "subagent_bash_allow" in guard:
            allow = _str_list(
                guard["subagent_bash_allow"], "policy_guard", max_items=64, max_len=64
            )
            for name in allow:
                if name != "[" and not _PROGRAM.fullmatch(name):
                    raise Invalid("policy_guard")
                if name.lower() in FORBIDDEN_SUBAGENT_PROGRAMS or _PYTHON_NAME.match(name.lower()):
                    raise Invalid("policy_guard")

    # Parity with the frozen S3 contract: S3 must accept exactly this mapping.
    probe = classify_tool_call("Read", {}, policy=s3, read_file=None)
    if probe.unknown and any(r.startswith("policy is unusable") for r in probe.reasons):
        raise Invalid("policy_s3")

    return Policy(
        s3=s3,
        ttl_hours=ttl,
        canary_tiers=frozenset(canary),
        retry_seconds=retry,
        extra_patterns=extra,
        subagent_bash_allow=frozenset(allow),
        min_claude_code=min_cc,
    )


# --------------------------------------------------------------------------- catalogue


def load_catalog(data: bytes) -> tuple[dict[str, Any], ...]:
    """``policy/standard-changes.toml``: ``schema = 1`` and ``[[entry]]`` tables.

    Each entry has exactly the S3 catalogue keys (``id``, ``enabled``, ``adapter``,
    ``command_pattern``, ``target_scope``, ``state_scope``) plus an optional
    ``description``. ``state_scope`` is mandatory, exact and already normalised.
    """
    doc = strict_toml(data, max_bytes=MAX_POLICY_BYTES)
    _keys(doc, {"schema"}, {"entry"}, "catalog_keys")
    _schema(doc)
    entries = _list(doc.get("entry", []), "catalog_entries", 256)
    out = []
    seen: set[str] = set()
    required = {"id", "enabled", "adapter", "command_pattern", "target_scope", "state_scope"}
    for entry in entries:
        _keys(entry, required, {"description"}, "catalog_entry")
        eid = _str(entry["id"], "catalog_id", max_len=64, pattern=_ENTRY_ID)
        if eid in seen:
            raise Invalid("catalog_id")
        seen.add(eid)
        _bool(entry["enabled"], "catalog_enabled")
        if entry["adapter"] not in ADAPTER_NAMES:
            raise Invalid("catalog_adapter")
        _str(entry["command_pattern"], "catalog_pattern", max_len=512)
        _targets(entry["target_scope"], "catalog_targets", nonempty=True)
        scope = _str(entry["state_scope"], "catalog_scope", max_len=256)
        if _PATTERN_SPECIALS & set(scope) or simtenant_adapter.state_scope(scope) != scope:
            raise Invalid("catalog_scope")
        if "description" in entry:
            _str(entry["description"], "catalog_description", max_len=500)
        out.append({k: entry[k] for k in sorted(required)})
    return tuple(out)


# --------------------------------------------------------------------------- plan files


@dataclass(frozen=True)
class Step:
    id: str
    command: str | None
    tool: str | None
    input_sha256: str | None
    targets: tuple[str, ...]


@dataclass(frozen=True)
class Check:
    """One ``[[verify.check]]``: ``value_json`` is the canonical JSON text of the value."""

    pointer: str
    op: str
    value_json: str


@dataclass(frozen=True)
class VerifySpec:
    """One ``[[verify]]`` read probe: the read argv, the expected status and its checks."""

    target: str
    argv: tuple[str, ...]
    expect: str
    checks: tuple[Check, ...]


@dataclass(frozen=True)
class ChangePlan:
    id: str
    answers: dict[str, bool]
    irreversible: bool
    tenant: str
    steps: tuple[Step, ...]
    verify: tuple[VerifySpec, ...] = ()


def _pointer(value: Any, code: str) -> str:
    """RFC 6901 pointer from the response root: 1-8 tokens of at most 64 characters each,
    with ``~`` used only in the escapes ``~0`` and ``~1``."""
    text = _str(value, code, max_len=8 * 65)
    if not text.startswith("/"):
        raise Invalid(code)
    tokens = text[1:].split("/")
    if not 1 <= len(tokens) <= 8:
        raise Invalid(code)
    for token in tokens:
        if len(token) > 64 or re.search(r"~(?![01])", token):
            raise Invalid(code)
    return text


def _argv(value: Any, code: str) -> tuple[str, ...]:
    items = _list(value, code, 32, nonempty=True)
    return tuple(_str(v, code, max_len=512) for v in items)


def _verify_spec(raw: Any) -> VerifySpec:
    _keys(raw, {"target", "argv", "expect"}, {"check"}, "change_verify")
    target = _target(raw["target"], "change_verify")
    argv = _argv(raw["argv"], "change_verify")
    expect = raw["expect"]
    if expect not in EXPECT_STATUSES:
        raise Invalid("change_verify")
    checks = []
    for item in _list(raw.get("check", []), "change_verify", MAX_CHECKS):
        _keys(item, {"pointer", "op", "value_json"}, set(), "change_verify")
        pointer = _pointer(item["pointer"], "change_verify")
        if item["op"] not in CHECK_OPS:
            raise Invalid("change_verify")
        if type(item["value_json"]) is not str:
            raise Invalid("change_verify")
        try:
            value = strict_json_value(item["value_json"])
        except Invalid:
            raise Invalid("change_verify") from None
        checks.append(Check(pointer, item["op"], canonical_json(value)))
    if expect == "active" and not checks:
        raise Invalid("change_verify")  # exit 0 alone never proves an active object
    if expect == "absent" and checks:
        raise Invalid("change_verify")
    return VerifySpec(target, argv, expect, tuple(checks))


def load_change(data: bytes, expected_id: str) -> ChangePlan:
    """``change.toml``. Unknown keys are refused.

    ``[[steps]]`` bind commands whose targets the classifier cannot extract: exactly one
    of ``command`` (byte-exact Bash text) or ``tool`` + ``input_sha256`` (MCP), and a
    non-empty ``targets`` list. ``probe``, ``rollback`` and ``description`` are plain
    strings and are not interpreted.

    ``[[verify]]`` (S5, the only new top-level key): ``target``, ``argv`` (1-32 strings),
    ``expect`` (active, soft_deleted or absent) and ``[[verify.check]]`` tables with
    ``pointer`` (RFC 6901), ``op`` (eq, ne, contains, not_contains) and ``value_json``
    (a JSON text, at most 1 KiB, depth 8). active needs 1-16 checks, soft_deleted 0-16,
    absent none. At most one ``[[verify]]`` per target.
    """
    doc = strict_toml(data, max_bytes=MAX_PLAN_BYTES)
    _keys(
        doc,
        {"schema", "id", "irreversible", "answers", "scope"},
        {"steps", "title", "ticket", "verify"},
        "change_keys",
    )
    _schema(doc)
    cid = _change_id(doc["id"], "change_id")
    if cid != expected_id:
        raise Invalid("change_id")
    for key in ("title", "ticket"):
        if key in doc:
            _str(doc[key], f"change_{key}", max_len=200)
    answers = doc["answers"]
    _keys(answers, {"reversible", "has_dependents", "targets_enumerated"}, set(), "change_answers")
    for value in answers.values():
        _bool(value, "change_answers")
    irreversible = _bool(doc["irreversible"], "change_irreversible")
    scope = doc["scope"]
    _keys(scope, {"tenant"}, set(), "change_scope")
    tenant = _str(scope["tenant"], "change_scope", max_len=256)

    steps = []
    seen: set[str] = set()
    for raw in _list(doc.get("steps", []), "change_steps", 200):
        _keys(
            raw,
            {"id", "targets"},
            {"command", "tool", "input_sha256", "description", "probe", "rollback"},
            "change_step",
        )
        sid = _str(raw["id"], "change_step", max_len=32, pattern=_STEP_ID)
        if sid in seen:
            raise Invalid("change_step")
        seen.add(sid)
        targets = _targets(raw["targets"], "change_step", nonempty=True)
        command = tool = digest = None
        if "command" in raw:
            if "tool" in raw or "input_sha256" in raw:
                raise Invalid("change_step")
            command = _str(raw["command"], "change_step", max_len=65536, text=True)
        else:
            if "tool" not in raw or "input_sha256" not in raw:
                raise Invalid("change_step")
            tool = _str(raw["tool"], "change_step", max_len=256)
            digest = _hex64(raw["input_sha256"], "change_step")
        for key in ("description", "probe", "rollback"):
            if key in raw:
                _str(raw[key], "change_step", max_len=4096, text=True)
        steps.append(Step(sid, command, tool, digest, targets))
    specs = []
    for raw in _list(doc.get("verify", []), "change_verify", MAX_TARGETS):
        specs.append(_verify_spec(raw))
    if len({s.target for s in specs}) != len(specs):
        raise Invalid("change_verify")
    return ChangePlan(cid, dict(answers), irreversible, tenant, tuple(steps), tuple(specs))


def parse_targets(data: bytes) -> tuple[str, ...]:
    """``targets.csv``: header ``target``, one immutable target per LF-terminated line."""
    text = _decode(data, MAX_TARGETS_BYTES)
    if "\r" in text:
        raise Invalid("targets_crlf")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "target":
        raise Invalid("targets_header")
    rows = lines[1:]
    if not rows or len(rows) > MAX_TARGETS:
        raise Invalid("targets_rows")
    for row in rows:
        if not _TARGET.fullmatch(row):
            raise Invalid("targets_row")
    if len(set(rows)) != len(rows):
        raise Invalid("targets_duplicate")
    return tuple(rows)


# --------------------------------------------------------------------------- authority files


def _finding(value: Any) -> dict[str, str]:
    _keys(value, {"code", "detail"}, set(), "review_finding")
    _str(value["code"], "review_finding", max_len=32, pattern=_FINDING_CODE)
    _str(value["detail"], "review_finding", max_len=2000, empty=True, text=True)
    return value


def parse_review(data: bytes) -> dict[str, Any]:
    doc = strict_json(data, max_bytes=MAX_AUTHORITY_BYTES)
    _keys(
        doc,
        {
            "schema",
            "change_id",
            "verdict",
            "findings",
            "plan_hash_start",
            "plan_hash_end",
            "agent_id",
            "session_id",
            "started_at",
            "stopped_at",
        },
        set(),
        "review_keys",
    )
    _schema(doc)
    _str(doc["change_id"], "review_change", max_len=8, pattern=_CHANGE_ID)
    if doc["verdict"] not in VERDICTS:
        raise Invalid("review_verdict")
    for item in _list(doc["findings"], "review_findings", 100):
        _finding(item)
    _hex64(doc["plan_hash_start"], "review_hash")
    _hex64(doc["plan_hash_end"], "review_hash")
    _str(doc["agent_id"], "review_agent", max_len=128, pattern=_AGENT_ID)
    _str(doc["session_id"], "review_session", max_len=128, pattern=_TOKEN)
    if utc_parse(doc["started_at"], "review_time") > utc_parse(doc["stopped_at"], "review_time"):
        raise Invalid("review_time")
    return doc


def parse_approval(value: Any) -> dict[str, Any]:
    """An approval record (``approval.json`` or one registry line)."""
    doc = strict_json(value, max_bytes=MAX_AUTHORITY_BYTES) if isinstance(value, bytes) else value
    _keys(
        doc,
        {
            "schema",
            "change_id",
            "project",
            "plan_hash",
            "review_sha256",
            "tier",
            "approver",
            "approved_at",
            "expires_at",
            "nonce",
        },
        set(),
        "approval_keys",
    )
    _schema(doc)
    _str(doc["change_id"], "approval_change", max_len=8, pattern=_CHANGE_ID)
    project = _str(doc["project"], "approval_project", max_len=4096)
    if not os.path.isabs(project):
        raise Invalid("approval_project")
    _hex64(doc["plan_hash"], "approval_hash")
    _hex64(doc["review_sha256"], "approval_hash")
    if doc["tier"] not in TIER_RANK:
        raise Invalid("approval_tier")
    approver = doc["approver"]
    _keys(approver, {"os_user", "git_user"}, set(), "approval_approver")
    _str(approver["os_user"], "approval_approver", max_len=128)
    _str(approver["git_user"], "approval_approver", max_len=256, empty=True)
    if utc_parse(doc["approved_at"], "approval_time") >= utc_parse(
        doc["expires_at"], "approval_time"
    ):
        raise Invalid("approval_time")
    _str(doc["nonce"], "approval_nonce", max_len=32, pattern=_HEX32)
    return doc


_OBSERVATION_KEYS = {
    "status",
    "observed_at",
    "argv",
    "exit",
    "object",
    "object_sha256",
    "reason",
    "human_command",
}


def parse_observation(value: Any, *, with_object: bool) -> dict[str, Any]:
    """One strict observation of a target (snapshot value or verify ``last``).

    ``with_object=True`` is the snapshot variant: ``object`` is a JSON object for
    ``active``/``soft_deleted`` and null otherwise. Without it ``object`` is always null.
    ``object_sha256`` is present exactly for ``active``/``soft_deleted`` (its value is the
    sha256 of the redacted object; only its shape is checked here because the redactor and
    the policy's extra patterns live in the ledger module: ``Store`` recomputes it and
    requires the stored object to be already redacted). ``exit`` may
    be null only for ``unmeasured``, which alone carries a ``reason`` code.
    ``human_command`` is the redacted command a person can run.
    """
    code = "observation"
    _keys(value, _OBSERVATION_KEYS, set(), code)
    status = value["status"]
    if status not in OBSERVATION_STATUSES:
        raise Invalid(code)
    utc_parse(value["observed_at"], code)
    _argv(value["argv"], code)
    unmeasured = status == "unmeasured"
    if value["exit"] is None:
        if not unmeasured:
            raise Invalid(code)
    else:
        _int(value["exit"], code, 0, 255)
    present = status in ("active", "soft_deleted")
    obj = value["object"]
    if with_object and present:
        if not isinstance(obj, dict):
            raise Invalid(code)
        _walk(obj, 0, MAX_DEPTH, toml=False)
    elif obj is not None:
        raise Invalid(code)
    if present:
        _hex64(value["object_sha256"], code)
    elif value["object_sha256"] is not None:
        raise Invalid(code)
    if unmeasured:
        _str(value["reason"], code, max_len=48, pattern=_CODE)
    elif value["reason"] is not None:
        raise Invalid(code)
    _str(value["human_command"], code, max_len=2048)
    try:
        size = len(canonical_json(value))
    except (TypeError, ValueError):
        raise Invalid(code) from None
    if size > MAX_OBSERVATION_BYTES:
        raise Invalid(code)
    return value


def parse_snapshot(data: bytes) -> dict[str, Any]:
    """``snapshot.json``. Every target value is a strict snapshot observation."""
    doc = strict_json(data, max_bytes=MAX_STATE_BYTES)
    _keys(doc, {"schema", "change_id", "plan_hash", "taken_at", "targets"}, set(), "snapshot_keys")
    _schema(doc)
    _str(doc["change_id"], "snapshot_change", max_len=8, pattern=_CHANGE_ID)
    _hex64(doc["plan_hash"], "snapshot_hash")
    utc_parse(doc["taken_at"], "snapshot_time")
    targets = doc["targets"]
    if not isinstance(targets, dict) or not targets or len(targets) > MAX_TARGETS:
        raise Invalid("snapshot_targets")
    for key, value in targets.items():
        _target(key, "snapshot_targets")
        try:
            parse_observation(value, with_object=True)
        except Invalid:
            raise Invalid("snapshot_values") from None
    return doc


def snapshot_complete(doc: Mapping[str, Any]) -> bool:
    """True when every target of a parsed snapshot was measured (none ``unmeasured``)."""
    targets = doc.get("targets") if isinstance(doc, Mapping) else None
    if not isinstance(targets, Mapping) or not targets:
        return False
    return all(
        isinstance(v, Mapping) and v.get("status") in EXPECT_STATUSES for v in targets.values()
    )


def verify_aggregate(verdicts: Any) -> str:
    """All PASS -> PASS; otherwise any FAIL -> FAIL; otherwise UNMEASURED."""
    values = list(verdicts)
    if not values or any(v not in VERIFY_VALUES for v in values):
        raise Invalid("verify_verdict")
    if all(v == "PASS" for v in values):
        return "PASS"
    if "FAIL" in values:
        return "FAIL"
    return "UNMEASURED"


_RECORD_KEYS = {
    "schema",
    "change_id",
    "line",
    "unit",
    "seq_before",
    "seq",
    "plan_hash",
    "verdict",
    "started_at",
    "finished_at",
    "schedule",
    "results",
}
_RESULT_KEYS = {"verdict", "attempts", "reason", "human_command", "last", "checked"}


def _verify_result(value: Any) -> str:
    code = "verify_result"
    _keys(value, _RESULT_KEYS, set(), code)
    verdict = value["verdict"]
    if verdict not in VERIFY_VALUES:
        raise Invalid(code)
    attempts = _int(value["attempts"], code, 0, 11)
    reason = value["reason"]
    if verdict == "PASS":
        if reason is not None:
            raise Invalid(code)
    elif verdict == "FAIL":
        if reason != "not_converged":
            raise Invalid(code)
    else:
        _str(reason, code, max_len=48, pattern=_CODE)
    _str(value["human_command"], code, max_len=2048)
    last = value["last"]
    if last is not None:
        try:
            parse_observation(last, with_object=False)
        except Invalid:
            raise Invalid(code) from None
    if verdict in ("PASS", "FAIL"):
        # a verdict on the system needs a completed measurement
        if last is None or last["status"] == "unmeasured" or attempts < 1:
            raise Invalid(code)
    checked = value["checked"]
    if not isinstance(checked, dict) or len(checked) > MAX_CHECKS:
        raise Invalid(code)
    for pointer, shown in checked.items():
        _pointer(pointer, code)
        if shown is not None:
            _str(shown, code, max_len=MAX_JSON_VALUE_BYTES)
    return verdict


def parse_verify_record(value: Any) -> dict[str, Any]:
    """One evidence record of ``verify.json`` (bytes of one canonical record, or a dict).

    ``seq == seq_before + 1``; ``verdict`` is the aggregate of the target verdicts; each
    record is at most 64 KiB as canonical bytes.
    """
    if isinstance(value, bytes | bytearray):
        if len(value) > MAX_VERIFY_RECORD_BYTES:
            raise Invalid("verify_record")
        value = strict_json(bytes(value), max_bytes=MAX_VERIFY_RECORD_BYTES)
    code = "verify_record"
    _keys(value, _RECORD_KEYS, set(), code)
    _schema(value)
    _change_id(value["change_id"], code)
    _int(value["line"], code, 1, MAX_VERIFY_RECORDS)
    _int(value["unit"], code, 1, MAX_UNITS)
    seq_before = _int(value["seq_before"], code, 1, 2**53)
    if _int(value["seq"], code, 1, 2**53) != seq_before + 1:
        raise Invalid(code)
    _hex64(value["plan_hash"], code)
    if utc_parse(value["started_at"], code) > utc_parse(value["finished_at"], code):
        raise Invalid(code)
    for item in _list(value["schedule"], code, 10):
        _int(item, code, 0, 600)
    results = value["results"]
    if not isinstance(results, dict) or not results or len(results) > MAX_TARGETS:
        raise Invalid(code)
    verdicts = []
    for target, result in results.items():
        _target(target, code)
        verdicts.append(_verify_result(result))
    if value["verdict"] != verify_aggregate(verdicts):
        raise Invalid(code)
    try:
        size = len(canonical_bytes(value))
    except (TypeError, ValueError):
        raise Invalid(code) from None
    if size > MAX_VERIFY_RECORD_BYTES:
        raise Invalid(code)
    return value


def parse_verify_doc(data: bytes) -> dict[str, Any]:
    """``verify.json``: ``{"schema": 1, "records": [record, ...]}`` in canonical bytes.

    Each record's ``line`` is its 1-based ordinal. The file must be exactly the canonical
    bytes of what it parses to; anything else (a truncated or reformatted file) is
    refused, never repaired.
    """
    doc = strict_json(data, max_bytes=MAX_VERIFY_BYTES)
    _keys(doc, {"schema", "records"}, set(), "verify_keys")
    _schema(doc)
    records = _list(doc["records"], "verify_records", MAX_VERIFY_RECORDS)
    for index, record in enumerate(records):
        parse_verify_record(record)
        if record["line"] != index + 1:
            raise Invalid("verify_records")
    if canonical_bytes(doc) != bytes(data):
        raise Invalid("verify_not_canonical")
    return doc


def parse_active(data: bytes) -> str | None:
    doc = strict_json(data, max_bytes=4096)
    _keys(doc, {"schema", "change_id"}, set(), "active_keys")
    _schema(doc)
    return _opt(doc["change_id"], _change_id, "active_change")


_UNIT_KEYS = {
    "n",
    "tool_use_id",
    "step",
    "targets",
    "canary",
    "outcome",
    "verify",
    "at",
    "call",
    "receipt",
    "verify_ref",
}
_INFLIGHT_KEYS = {"token", "unit", "step", "targets", "canary", "input_sha256", "at"}


def _call(value: Any) -> None:
    """Call identity recorded at reservation (protected state only, never logged)."""
    code = "state_unit"
    _keys(value, {"session_id", "tool", "salt", "input_hmac"}, set(), code)
    _token(value["session_id"], code)
    _str(value["tool"], code, max_len=256)
    _str(value["salt"], code, max_len=32, pattern=_HEX32)
    _hex64(value["input_hmac"], code)


def _receipt(value: Any) -> None:
    """The first settlement of a unit; written once and never rewritten."""
    code = "state_unit"
    _keys(value, {"source", "outcome", "at", "exit", "response_sha256"}, set(), code)
    source, outcome = value["source"], value["outcome"]
    if source not in RECEIPT_SOURCES or outcome not in OUTCOMES:
        raise Invalid(code)
    utc_parse(value["at"], code)
    _opt(value["exit"], lambda v, c: _int(v, c, 0, 255), code)
    _opt(value["response_sha256"], _hex64, code)
    if source == "resume":
        if outcome != "unknown" or value["exit"] is not None:
            raise Invalid(code)
        if value["response_sha256"] is not None:
            raise Invalid(code)
    elif source == "failure":
        if outcome == "ok" or value["response_sha256"] is not None:
            raise Invalid(code)
    elif value["exit"] is not None:  # post
        raise Invalid(code)


def _unit(value: Any, n: int) -> None:
    _keys(value, _UNIT_KEYS, set(), "state_unit")
    if _int(value["n"], "state_unit", 1, MAX_UNITS) != n:
        raise Invalid("state_unit")
    _token(value["tool_use_id"], "state_unit")
    _opt(value["step"], _step_id, "state_unit")
    _targets(value["targets"], "state_unit", nonempty=False)
    _bool(value["canary"], "state_unit")
    if value["outcome"] is not None and value["outcome"] not in OUTCOMES:
        raise Invalid("state_unit")
    if value["verify"] is not None and value["verify"] not in VERIFY_VALUES:
        raise Invalid("state_unit")
    utc_parse(value["at"], "state_unit")
    _call(value["call"])
    receipt = value["receipt"]
    if (receipt is None) != (value["outcome"] is None):
        raise Invalid("state_unit")
    if receipt is not None:
        _receipt(receipt)
        if value["outcome"] not in (receipt["outcome"], "unknown"):
            raise Invalid("state_unit")
    ref = value["verify_ref"]
    if (ref is None) != (value["verify"] is None):
        raise Invalid("state_unit")
    if ref is not None:
        _keys(ref, {"line", "sha256"}, set(), "state_unit")
        _int(ref["line"], "state_unit", 1, MAX_VERIFY_RECORDS)
        _hex64(ref["sha256"], "state_unit")


_STATE_KEYS = {
    "schema",
    "id",
    "slug",
    "seq",
    "state",
    "tier",
    "plan_hash",
    "review_start",
    "review_sha",
    "ack_review_sha",
    "approval_nonce",
    "snapshot_sha",
    "canary",
    "canary_unit",
    "units",
    "executed_steps",
    "settled_ids",
    "inflight",
    "halted",
    "created_at",
    "updated_at",
}


def parse_state(value: Any) -> dict[str, Any]:
    """``.cab/state/changes/CHG-NNNN.json`` (bytes or an already-built dict).

    Besides types, the cross-field invariants are checked: the in-flight reservation is
    the last, unsettled unit; settled IDs are exactly the settled units; ``halted`` is set
    exactly in state ``halted``; an awaiting canary names an existing unit; nothing is in
    flight once execution ended. Every unit carries its call identity (``call``); a
    receipt exists exactly for a settled unit and a ``verify_ref`` exactly for a unit
    with a verdict. S4-era files (no ``call``) and ``verifying`` fail closed.
    """
    doc = strict_json(value, max_bytes=MAX_STATE_BYTES) if isinstance(value, bytes) else value
    _keys(doc, _STATE_KEYS, set(), "state_keys")
    _schema(doc)
    _str(doc["id"], "state_id", max_len=8, pattern=_CHANGE_ID)
    _str(doc["slug"], "state_slug", max_len=48, pattern=_SLUG)
    _int(doc["seq"], "state_seq", 1, 2**53)
    if doc["state"] not in STATES:
        raise Invalid("state_state")
    if doc["tier"] is not None and doc["tier"] not in TIER_RANK:
        raise Invalid("state_tier")
    _opt(doc["plan_hash"], _hex64, "state_hash")
    start = doc["review_start"]
    if start is not None:
        # S5 fix: the review is bound to the parent session that started it
        _keys(start, {"plan_hash", "agent_id", "session_id", "at"}, set(), "state_review")
        _hex64(start["plan_hash"], "state_review")
        _str(start["agent_id"], "state_review", max_len=128, pattern=_AGENT_ID)
        _token(start["session_id"], "state_review")
        utc_parse(start["at"], "state_review")
    for key in ("review_sha", "ack_review_sha", "snapshot_sha"):
        _opt(doc[key], _hex64, "state_hash")
    _opt(doc["approval_nonce"], _nonce, "state_nonce")
    if doc["canary"] not in CANARY_STATES:
        raise Invalid("state_canary")
    _opt(doc["canary_unit"], lambda v, c: _int(v, c, 1, MAX_UNITS), "state_canary")
    units = _list(doc["units"], "state_units", MAX_UNITS)
    for index, unit in enumerate(units):
        _unit(unit, index + 1)
    _str_list(doc["executed_steps"], "state_steps", max_items=200, max_len=32, pattern=_STEP_ID)
    settled = _str_list(
        doc["settled_ids"], "state_settled", max_items=MAX_UNITS, max_len=128, pattern=_TOKEN
    )
    inflight = doc["inflight"]
    if inflight is not None:
        _keys(inflight, _INFLIGHT_KEYS, set(), "state_inflight")
        _token(inflight["token"], "state_inflight")
        _int(inflight["unit"], "state_inflight", 1, MAX_UNITS)
        _opt(inflight["step"], _step_id, "state_inflight")
        _targets(inflight["targets"], "state_inflight", nonempty=False)
        _bool(inflight["canary"], "state_inflight")
        _hex64(inflight["input_sha256"], "state_inflight")
        utc_parse(inflight["at"], "state_inflight")
    halted = doc["halted"]
    if halted is not None:
        _keys(halted, {"code", "at", "tool_use_id"}, set(), "state_halted")
        _str(halted["code"], "state_halted", max_len=48, pattern=_CODE)
        utc_parse(halted["at"], "state_halted")
        _opt(halted["tool_use_id"], _token, "state_halted")
    utc_parse(doc["created_at"], "state_time")
    utc_parse(doc["updated_at"], "state_time")

    # cross-field invariants
    ids = [u["tool_use_id"] for u in units]
    if len(set(ids)) != len(ids):
        raise Invalid("state_invariant")
    open_units = [u for u in units if u["outcome"] is None]
    if inflight is None:
        if open_units:
            raise Invalid("state_invariant")
    else:
        last = units[-1] if units else None
        if (
            last is None
            or open_units != [last]
            or last["n"] != inflight["unit"]
            or last["tool_use_id"] != inflight["token"]
            or last["step"] != inflight["step"]
            or last["targets"] != inflight["targets"]
            or last["canary"] != inflight["canary"]
        ):
            raise Invalid("state_invariant")
    if set(settled) != {u["tool_use_id"] for u in units if u["outcome"] is not None}:
        raise Invalid("state_invariant")
    if (doc["state"] == "halted") != (halted is not None):
        raise Invalid("state_invariant")
    if doc["state"] in ("closed", "failed", "open-unverified") and inflight is not None:
        raise Invalid("state_invariant")
    if doc["canary"] == "awaiting":
        cu = doc["canary_unit"]
        if cu is None or cu > len(units) or units[cu - 1]["outcome"] is None:
            raise Invalid("state_invariant")
    for unit in units:
        if unit["verify"] is not None and unit["outcome"] is None:
            raise Invalid("state_invariant")
    return doc
