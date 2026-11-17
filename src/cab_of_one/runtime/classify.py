"""S3 classifier and tier floor (DESIGN §3-0 rule 3, §3-4, §4-2 guard steps 3-6, §10-4-4).

Pure standard-library code: no subprocess, no network, no direct file access.
The only way to look at a script is the ``read_file`` callback the guard passes
in (project-relative paths only, at most 256 KiB).

This is deliberately not a shell or PowerShell parser. Segments that can be
read with certainty are classified and merged (unknown-admin > write > read >
not-admin); dynamic syntax (command substitution, ``eval``, ``xargs``,
here-documents, subshells, control flow, expanded command names, encoded
commands) is unknown-admin, which the guard treats as write. Opaque script
execution is never not-admin, whether or not it contains admin markers.
``--dry-run`` and ``-WhatIf`` never lower a classification.

Directory and lookup changes are carried into nested shells (``bash -c``,
shell scripts): a relative path after ``cd`` never names a project file.

Public API: ``Result``, ``classify_tool_call``, ``tier_floor``,
``decide_tier``, ``catalog_match``.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .adapters import ADAPTER_NAMES, ADAPTERS, azure_cli, graph_http, m365_powershell, simtenant
from .classification_types import (
    FLAG_TENANT_WIDE,
    KIND_NOT_ADMIN,
    KIND_READ,
    KIND_WRITE,
    AdapterContext,
    Arg,
    Result,
    combine,
    leaves,
    make_not_admin,
    make_unknown,
)

__all__ = [
    "CORE_CRITICAL_PATTERNS",
    "DEFAULT_NOT_ADMIN_TOOLS",
    "MAX_SCRIPT_BYTES",
    "TIERS",
    "PolicyError",
    "Result",
    "catalog_match",
    "classify_tool_call",
    "decide_tier",
    "tier_floor",
]

MAX_SCRIPT_BYTES = 256 * 1024
MAX_COMMAND_CHARS = 256 * 1024
MAX_DEPTH = 8

TIERS = ("standard", "normal", "critical")
_RANK = {"standard": 0, "normal": 1, "critical": 2}

DEFAULT_NOT_ADMIN_TOOLS = ("Read", "Grep", "Glob", "Write", "Edit", "AskUserQuestion")

# Core "always critical" floor (DESIGN §3-4, §10-4-4). Matched case-insensitively
# with fnmatch against the canonical form of every write leaf; policy patterns
# are added to these and cannot remove them. Unknown-admin leaves are also
# matched with a leading "*" so a marker anywhere in opaque text counts.
CORE_CRITICAL_PATTERNS = (
    # permanent deletion
    "*purge*",
    "*permanentdelete*",
    "*permanentlydelete*",
    "*-permanent*",
    "*deleteditem*",
    "*harddelete*",
    "remove-mguser*",
    "remove-mailbox*",
    "remove-az*",
    "az * delete*",
    "http delete *",
    # whole virtual tenant
    "simtenant reset*",
    # tenant-wide authentication, conditional access, authentication methods
    "*conditionalaccess*",
    "*authenticationmethod*",
    "*authenticationstrength*",
    "*-mgpolicy*",
    "http * */authentication/*",
    "http * */v1.0/policies*",
    "http * */beta/policies*",
    # simtenant policies are conditional access, retention or transport rules: every
    # write to one (state, controls, include, create, delete, restore) is critical
    "simtenant * policies *",
    # privileged roles and grants
    "*roleassignment*",
    "*rolemanagement*",
    "*directoryrole*",
    "*roledefinition*",
    "*rolegroupmember*",
    "*oauth2permissiongrant*",
    "az role *",
    # domains, DNS, MX
    "*domaindns*",
    "*recordset*",
    "*dnszone*",
    "*dnsrecord*",
    "*-mgdomain*",
    "*accepteddomain*",
    "az network dns *",
    "http * */domains*",
    # mail flow
    "*transportrule*",
    "*transport_rule*",
    "*connector*",
    "*journalrule*",
    "*remotedomain*",
    # retention and holds (simtenant spells the hold field litigation_hold_enabled)
    "*litigationhold*",
    "*litigation_hold*",
    "*retentioncompliance*",
    "*retentionpolic*",
    "*caseholdpolic*",
    "*caseholdrule*",
    "*legalhold*",
    # licence changes (add and removal are not told apart, so both are critical);
    # simtenant licence writes include assign (add --member) and reclaim (remove --member)
    "set-mguserlicense*",
    "set-mggrouplicense*",
    "*assignlicense*",
    "simtenant * licenses *",
    # device wipe / retire
    "*manageddevice*wipe*",
    "*manageddevice*retire*",
    "clear-mobiledevice*",
    "http * */wipe*",
    "http * */retire*",
    # keys and secrets
    "az keyvault *",
    "az ad * credential *",
    "*addpassword*",
    "*removepassword*",
    "*addkey*",
    "*removekey*",
    "*-mgapplicationpassword*",
    "*-mgserviceprincipalpassword*",
    "*-mgapplicationkey*",
    "http * *.vault.azure.net/*",
)

_PATTERN_SPECIALS = frozenset("*?[")


class PolicyError(ValueError):
    """The policy mapping is unusable; callers fail closed."""


# ----------------------------------------------------------------- policy


@dataclass(frozen=True)
class _Config:
    enabled: frozenset[str]
    critical_patterns: tuple[str, ...]
    not_admin_tools: frozenset[str]
    mcp_read_tools: frozenset[str]
    mcp_write_servers: frozenset[str]
    trusted_simtenant_commands: frozenset[str]
    trusted_simtenant_scripts: frozenset[str]
    simtenant_resources: frozenset[str] | None


def _table(policy: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = policy.get(key, {})
    if not isinstance(value, Mapping):
        raise PolicyError(f"[{key}] must be a table")
    return value


def _str_list(
    table: Mapping[str, Any], key: str, default: Sequence[str] | None
) -> tuple[str, ...] | None:
    if key not in table:
        return None if default is None else tuple(default)
    value = table[key]
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise PolicyError(f"{key} must be a list of strings")
    out = []
    for item in value:
        if not isinstance(item, str) or not item or any(ord(ch) < 0x20 for ch in item):
            raise PolicyError(f"{key} must contain non-empty strings")
        out.append(item)
    return tuple(out)


def _load_config(policy: Any) -> _Config:
    if not isinstance(policy, Mapping):
        raise PolicyError("policy must be a table")
    adapters = _table(policy, "adapters")
    tiers = _table(policy, "tiers")
    surfaces = _table(policy, "surfaces")
    clf = _table(policy, "classifier")

    enabled = _str_list(adapters, "enabled", ADAPTER_NAMES) or ()
    for name in enabled:
        if name not in ADAPTER_NAMES:
            raise PolicyError(f"unknown adapter {name!r}")
    not_admin = _str_list(clf, "not_admin_tools", DEFAULT_NOT_ADMIN_TOOLS) or ()
    for tool in not_admin:
        if tool == "Bash" or tool.startswith("mcp__"):
            raise PolicyError("Bash and MCP tools cannot be listed as not-admin")
    commands = _str_list(clf, "trusted_simtenant_commands", ()) or ()
    for c in commands:
        if any(ch.isspace() or ch in "$`~*?[" for ch in c):
            raise PolicyError("trusted_simtenant_commands must be plain command words")
    scripts = _str_list(clf, "trusted_simtenant_scripts", ()) or ()
    for s in scripts:
        if any(ch in "$`*?[" for ch in s) or s.startswith("~") or ".." in s.split("/"):
            raise PolicyError("trusted_simtenant_scripts must be plain paths")
    resources = _str_list(clf, "simtenant_resources", None)
    if resources is not None:
        for res in resources:
            if res not in simtenant.DEFAULT_RESOURCES:
                raise PolicyError(f"simtenant_resources: {res!r} is not a simtenant resource")
    return _Config(
        enabled=frozenset(enabled),
        critical_patterns=_str_list(tiers, "critical_patterns", ()) or (),
        not_admin_tools=frozenset(not_admin),
        mcp_read_tools=frozenset(_str_list(clf, "mcp_read_tools", ()) or ()),
        mcp_write_servers=frozenset(_str_list(surfaces, "mcp_write_servers", ()) or ()),
        trusted_simtenant_commands=frozenset(commands),
        trusted_simtenant_scripts=frozenset(simtenant.strip_dot(s) for s in scripts),
        simtenant_resources=None if resources is None else frozenset(resources),
    )


# ----------------------------------------------------------------- shell lexer


class _Dynamic(Exception):
    """Shell syntax whose effect is decided at run time."""


class _Syntax(Exception):
    """Text the lexer cannot split with certainty."""


@dataclass(frozen=True)
class _Op:
    value: str


_OPS = (
    "&>>",
    "<<<",
    "&&",
    "||",
    ";;",
    "|&",
    "<<",
    ">>",
    "&>",
    ">&",
    "<&",
    "<>",
    ">|",
    "<(",
    ">(",
    ";",
    "|",
    "&",
    "<",
    ">",
    "(",
    ")",
)
_SEPARATORS = frozenset({"&&", "||", "|&", ";", "|", "&"})
_NEEDS_NEXT = frozenset({"&&", "||", "|&", "|"})
_PARAM_START = frozenset("_{@*#?$!-0123456789")


def _lex(s: str) -> list[Any]:
    out: list[Any] = []
    buf: list[str] = []
    start = -1
    expands = False
    quoted = False
    i = 0
    n = len(s)

    def flush(end: int) -> None:
        nonlocal buf, start, expands, quoted
        if start >= 0:
            out.append(Arg("".join(buf), expands, quoted, s[start:end]))
        buf = []
        start = -1
        expands = False
        quoted = False

    def dollar(j: int) -> bool:
        nx = s[j + 1] if j + 1 < n else ""
        if nx == "(":
            raise _Dynamic("command substitution $( )")
        return bool(nx) and (nx.isalpha() or nx in _PARAM_START)

    while i < n:
        c = s[i]
        if c in " \t\r":
            flush(i)
            i += 1
            continue
        if c == "\n":
            flush(i)
            out.append(_Op("\n"))
            i += 1
            continue
        if c == "#" and start < 0:
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "|&;<>()":
            fd_number = start >= 0 and not quoted and not expands and "".join(buf).isdigit()
            if c in "<>" and fd_number:
                buf, start = [], -1  # file-descriptor number of a redirection
            else:
                flush(i)
            op = next(o for o in _OPS if s.startswith(o, i))
            if op in ("<(", ">("):
                raise _Dynamic("process substitution")
            if op in ("(", ")"):
                raise _Dynamic("subshell, grouping or function definition")
            if op == "<<":
                raise _Dynamic("here-document")
            if op == ";;":
                raise _Syntax("';;' outside case")
            out.append(_Op(op))
            i += len(op)
            continue
        if start < 0:
            start = i
        if c == "\\":
            if i + 1 >= n:
                raise _Syntax("trailing backslash")
            if s[i + 1] == "\n":
                i += 2
                if not buf and not quoted:
                    start = -1
                continue
            buf.append(s[i + 1])
            quoted = True
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise _Syntax("unterminated single quote")
            buf.append(s[i + 1 : j])
            quoted = True
            i = j + 1
            continue
        if c == '"':
            quoted = True
            i += 1
            while True:
                if i >= n:
                    raise _Syntax("unterminated double quote")
                d = s[i]
                if d == '"':
                    i += 1
                    break
                if d == "\\" and i + 1 < n and s[i + 1] in '"\\$`\n':
                    if s[i + 1] != "\n":
                        buf.append(s[i + 1])
                    i += 2
                    continue
                if d == "`":
                    raise _Dynamic("backtick command substitution")
                if d == "$" and dollar(i):
                    expands = True
                buf.append(d)
                i += 1
            continue
        if c == "`":
            raise _Dynamic("backtick command substitution")
        if c == "$":
            nx = s[i + 1] if i + 1 < n else ""
            if nx in ("'", '"'):
                raise _Dynamic("$'...' or $\"...\" quoting")
            if dollar(i):
                expands = True
            buf.append(c)
            i += 1
            continue
        if c in "*?[{}" or (c == "~" and not buf):
            expands = True
        buf.append(c)
        i += 1
    flush(n)
    return out


def _split(tokens: Sequence[Any]) -> list[list[Arg]]:
    segs: list[list[Arg]] = []
    cur: list[Arg] = []
    need_target = False
    dangling = False
    for tok in tokens:
        if isinstance(tok, _Op):
            v = tok.value
            if need_target:
                raise _Syntax("redirection without a target")
            if v == "\n":
                if cur:
                    segs.append(cur)
                    cur = []
                    dangling = False
                continue
            if v in _SEPARATORS:
                if not cur:
                    raise _Syntax(f"'{v}' without a command before it")
                segs.append(cur)
                cur = []
                dangling = v in _NEEDS_NEXT
                continue
            need_target = True  # redirection; the target word is dropped
            continue
        if need_target:
            need_target = False
            continue
        cur.append(tok)
        dangling = False
    if need_target:
        raise _Syntax("redirection without a target")
    if cur:
        segs.append(cur)
    elif dangling:
        raise _Syntax("command ends with an operator")
    return segs


# ----------------------------------------------------------------- shell vocabulary

_SHELL_KEYWORDS = frozenset(
    {
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "until",
        "do",
        "done",
        "case",
        "esac",
        "select",
        "function",
        "{",
        "}",
        "[[",
        "]]",
        "coproc",
        "!",
    }
)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_SHELL_SHORT_OK = frozenset("eaxvunfBCEhHkmpPtT")
_SHELL_LONG_OK = frozenset({"--norc", "--noprofile", "--posix"})
_PYTHON_RE = re.compile(r"^python(\d+(\.\d+)?)?$")
_PY_FLAGS = frozenset(
    {"-I", "-B", "-u", "-E", "-s", "-S", "-O", "-OO", "-q", "-b", "-bb", "-d", "-v", "-x", "-R"}
)
_INTERPRETERS = frozenset(
    {
        "node",
        "nodejs",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "lua",
        "rscript",
        "osascript",
        "tclsh",
        "npx",
        "uv",
        "uvx",
    }
)
_ADMIN_TOOLS = frozenset({"gam", "aws", "m365", "mgc", "gcloud", "azcopy", "terraform", "pulumi"})
_SYSTEM_BIN_DIRS = frozenset(
    {"/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/usr/sbin", "/sbin"}
)
_INERT = frozenset(
    {
        "echo",
        "printf",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "git",
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "wc",
        "ls",
        "sort",
        "uniq",
        "cut",
        "tr",
        "diff",
        "cmp",
        "comm",
        "test",
        "[",
        "true",
        "false",
        "pwd",
        "mkdir",
        "rmdir",
        "touch",
        "cp",
        "mv",
        "rm",
        "ln",
        "chmod",
        "stat",
        "file",
        "which",
        "type",
        "whereis",
        "basename",
        "dirname",
        "realpath",
        "readlink",
        "date",
        "sleep",
        "tee",
        "pytest",
        "jq",
        "column",
        "nl",
        "fold",
        "fmt",
        "paste",
        "join",
        "od",
        "xxd",
        "hexdump",
        "shasum",
        "sha256sum",
        "md5",
        "md5sum",
        "du",
        "df",
        "tree",
        "set",
        "unset",
        "read",
        "wait",
        "jobs",
        "umask",
        "exit",
        "return",
        "shift",
    }
)
_DECLARERS = frozenset({"export", "declare", "typeset", "local", "readonly"})
_ENV_SENSITIVE = frozenset(
    {
        "PATH",
        "BASH_ENV",
        "ENV",
        "IFS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "PERL5OPT",
        "RUBYOPT",
        "PSModulePath",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "CDPATH",
        "PWD",
        "OLDPWD",
    }
)
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=")
_AWKS = frozenset({"awk", "gawk", "mawk", "nawk"})
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_WRAPPERS = frozenset(
    {"sudo", "doas", "env", "nohup", "timeout", "time", "command", "exec", "nice", "builtin"}
)
# sudo -D (chdir) and -R (chroot) change where relative paths point; they are not accepted.
_SUDO_VALUED = frozenset({"-u", "-g", "-C", "-p", "-U", "-h", "-r", "-t", "-T"})


@dataclass
class _State:
    cwd_changed: bool = False
    env_changed: bool = False

    def child(self) -> _State:
        """State a nested shell starts with: it inherits cwd and environment."""
        return _State(self.cwd_changed, self.env_changed)


@dataclass(frozen=True)
class _Env:
    cfg: _Config
    load: Callable[[str], str | None]

    def ctx(self, state: _State) -> AdapterContext:
        return AdapterContext(
            trusted_simtenant_commands=self.cfg.trusted_simtenant_commands,
            trusted_simtenant_scripts=self.cfg.trusted_simtenant_scripts,
            simtenant_resources=self.cfg.simtenant_resources,
            load_script=self.load,
            cwd_changed=state.cwd_changed,
        )


def _squash(text: str) -> str:
    return " ".join(text.split())


def _raw(words: Sequence[Arg]) -> str:
    return " ".join(w.text for w in words)


def _assignment(word: Arg) -> str | None:
    m = _ASSIGN_RE.match(word.raw or word.text)
    return m.group(1) if m else None


def _make_loader(read_file: Any) -> Callable[[str], str | None]:
    def load(path: str) -> str | None:
        if not callable(read_file) or not isinstance(path, str) or not path:
            return None
        path = simtenant.strip_dot(path)
        if not path or path.startswith(("/", "~")) or "\x00" in path or ".." in path.split("/"):
            return None  # only project-relative paths are ever requested
        try:
            data = read_file(path)
        except Exception:
            return None
        if not isinstance(data, bytes | bytearray) or len(data) > MAX_SCRIPT_BYTES:
            return None
        try:
            return bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            return None

    return load


def _scan_all(text: str) -> list[Result]:
    found: list[Result] = []
    for adapter in ADAPTERS:
        found.extend(adapter.scan_text(text))
    return found


def _opaque(texts: Sequence[str], reason: str, raw: str) -> Result:
    parts = [make_unknown(reason, canonical=raw)]
    for t in texts:
        parts.extend(_scan_all(t))
    return combine(parts, raw)


# ----------------------------------------------------------------- shell classification


def _classify_bash_text(
    text: str, env: _Env, depth: int, inherited: _State | None = None
) -> Result:
    canon = _squash(text)
    if depth > MAX_DEPTH:
        return make_unknown("nesting is too deep", canonical=canon)
    try:
        segments = _split(_lex(text))
    except _Dynamic as exc:
        return make_unknown(f"dynamic shell syntax: {exc}", canonical=canon)
    except _Syntax as exc:
        return make_unknown(f"shell text could not be split: {exc}", canonical=canon)
    state = inherited.child() if inherited is not None else _State()
    results = []
    for seg in segments:
        if state.env_changed:
            results.append(
                make_unknown("an earlier segment changed command lookup", canonical=_raw(seg))
            )
            continue
        results.append(_segment(seg, env, depth, state))
    return combine(results, canon)


def _segment(words: Sequence[Arg], env: _Env, depth: int, state: _State) -> Result:
    raw = _raw(words)
    if depth > MAX_DEPTH:
        return make_unknown("nesting is too deep", canonical=raw)
    words = list(words)
    bare_assignments = []
    while words and _assignment(words[0]) is not None:
        bare_assignments.append(_assignment(words[0]))
        words.pop(0)
    if not words:
        if any(name in _ENV_SENSITIVE for name in bare_assignments):
            state.env_changed = True
        return make_not_admin(raw, "variable assignment")
    if any(name in _ENV_SENSITIVE for name in bare_assignments):
        return make_unknown(
            "command runs with a changed lookup or interpreter environment", canonical=raw
        )

    w0 = words[0]
    name = w0.text
    if w0.raw == "[":
        return make_not_admin(raw, "test expression")
    if w0.expands:
        return make_unknown("command name is expanded at run time", canonical=raw)
    if not w0.quoted and name in _SHELL_KEYWORDS:
        return make_unknown(f"shell compound syntax ({name}) is not analysed", canonical=raw)
    if name == "eval":
        return make_unknown("eval runs text that is not analysed", canonical=raw)
    if name == "xargs":
        return make_unknown("xargs builds commands at run time", canonical=raw)
    if name == "trap":
        return make_unknown("trap runs text later", canonical=raw)
    if name in ("alias", "unalias", "hash", "enable", "shopt"):
        state.env_changed = True
        return make_not_admin(raw, "shell setup; later segments are unknown")
    if name in _DECLARERS:
        if any(_assignment(w) in _ENV_SENSITIVE or w.expands for w in words[1:]):
            state.env_changed = True
        return make_not_admin(raw, name)
    if name in ("cd", "pushd", "popd"):
        state.cwd_changed = True
        return make_not_admin(raw, "directory change")
    if name in ("source", "."):
        if len(words) < 2:
            return make_unknown("source without a file", canonical=raw)
        result = _run_script(words[1], "sh", env, depth, state, raw)
        state.env_changed = True  # sourced files can define functions, aliases and cd
        return result
    if name.lower() in _WRAPPERS:
        unwrapped = _unwrap(words, raw)
        if isinstance(unwrapped, Result):
            return unwrapped
        return _segment(unwrapped, env, depth + 1, state)
    return _dispatch(words, env, depth, state, raw)


def _unwrap(words: Sequence[Arg], raw: str) -> Result | list[Arg]:
    """Strip one wrapper. Returns the wrapped argv or a final Result."""
    name = words[0].text.lower()
    args = list(words[1:])

    def unk(reason: str) -> Result:
        return make_unknown(f"{name}: {reason}", canonical=raw)

    for a in args:
        if a.expands and a.text.startswith("-"):
            return unk("option is expanded at run time")
    i = 0
    if name in ("sudo", "doas"):
        valued = _SUDO_VALUED if name == "sudo" else frozenset({"-u", "-C"})
        flags = set("EHnSkPAb") if name == "sudo" else set("n")
        while i < len(args):
            t = args[i].text
            if t == "--":
                i += 1
                break
            if t in valued:
                i += 2
                continue
            if t.startswith("-") and len(t) > 1:
                if t.startswith("--") or not set(t[1:]) <= flags:
                    return unk(f"option {t} is not supported")
                i += 1
                continue
            break
        rest = args[i:]
        return rest if rest else unk("no command")
    if name == "env":
        while i < len(args):
            a = args[i]
            t = a.text
            if t in ("-i", "-", "--ignore-environment", "-0", "--null", "-v", "--debug"):
                i += 1
            elif t in ("-u", "--unset"):
                i += 2
            elif t.startswith("--unset="):
                i += 1
            elif t.startswith("-"):
                return unk(f"option {t} is not supported")
            elif _assignment(a) is not None:
                if _assignment(a) in _ENV_SENSITIVE:
                    return unk("changes the lookup or interpreter environment")
                i += 1
            else:
                break
        rest = args[i:]
        return rest if rest else make_not_admin(raw, "env listing")
    if name == "timeout":
        while i < len(args):
            t = args[i].text
            if t in ("--preserve-status", "--foreground", "-v", "--verbose"):
                i += 1
            elif t in ("-s", "--signal", "-k", "--kill-after"):
                i += 2
            elif t.startswith(("--signal=", "--kill-after=")):
                i += 1
            elif t.startswith("-"):
                return unk(f"option {t} is not supported")
            else:
                break
        duration_ok = (
            i < len(args)
            and not args[i].expands
            and re.match(r"^[0-9]+(\.[0-9]+)?[smhd]?$", args[i].text) is not None
        )
        if not duration_ok:
            return unk("duration is missing or not literal")
        rest = args[i + 1 :]
        return rest if rest else unk("no command")
    if name == "time":
        while i < len(args) and args[i].text == "-p":
            i += 1
        rest = args[i:]
        return rest if rest else make_not_admin(raw, "time")
    if name == "command":
        if args and args[0].text in ("-v", "-V"):
            return make_not_admin(raw, "command lookup")
        while i < len(args) and args[i].text == "-p":
            i += 1
        rest = args[i:]
        return rest if rest else make_not_admin(raw, "command")
    if name == "exec":
        while i < len(args):
            t = args[i].text
            if t in ("-c", "-l"):
                i += 1
            elif t == "-a":
                i += 2
            elif t.startswith("-"):
                return unk(f"option {t} is not supported")
            else:
                break
        rest = args[i:]
        return rest if rest else make_not_admin(raw, "exec redirection")
    if name == "nice":
        while i < len(args):
            t = args[i].text
            if t == "-n":
                i += 2
            elif re.match(r"^(-n?-?[0-9]+|--adjustment=-?[0-9]+)$", t):
                i += 1
            elif t.startswith("-"):
                return unk(f"option {t} is not supported")
            else:
                break
        rest = args[i:]
        return rest if rest else make_not_admin(raw, "nice")
    # nohup, builtin
    return args if args else make_not_admin(raw, name)


def _simtenant(words: Sequence[Arg], env: _Env, state: _State, raw: str) -> Result:
    if "simtenant" not in env.cfg.enabled:
        return _disabled("simtenant", raw)
    return simtenant.classify(words, env.ctx(state))


def _dispatch(words: Sequence[Arg], env: _Env, depth: int, state: _State, raw: str) -> Result:
    cfg = env.cfg
    ctx = env.ctx(state)
    w0 = words[0]
    name = w0.text

    # 1. simtenant only through explicit policy entries
    if name in cfg.trusted_simtenant_commands:
        if "/" in name and not name.startswith("/") and state.cwd_changed:
            return make_unknown("relative simtenant path after a directory change", canonical=raw)
        return _simtenant(words, env, state, raw)
    if "/" in name:
        norm = simtenant.strip_dot(name)
        if norm in cfg.trusted_simtenant_scripts:
            if not norm.startswith("/") and state.cwd_changed:
                return make_unknown(
                    "relative simtenant path after a directory change", canonical=raw
                )
            return _simtenant(words, env, state, raw)
        directory, base = posixpath.split(name)
        if base.lower() in simtenant.PROGRAM_BASENAMES:
            return make_unknown(
                "simtenant at a path that policy does not trust",
                adapter=simtenant.NAME,
                canonical=raw,
            )
        if directory not in _SYSTEM_BIN_DIRS:
            return _run_script(w0, "exec", env, depth, state, raw)
        name = base
    # Compare case-insensitively: on macOS `AZ` runs `az`.
    low = name.lower()
    if low in simtenant.PROGRAM_BASENAMES:
        return make_unknown(
            "simtenant command that policy does not trust", adapter=simtenant.NAME, canonical=raw
        )

    # 2. adapters
    if low in m365_powershell.HOSTS:
        if m365_powershell.NAME not in cfg.enabled:
            return _disabled(m365_powershell.NAME, raw)
        return m365_powershell.classify(words, ctx)
    if low == "az":
        if azure_cli.NAME not in cfg.enabled:
            return _disabled(azure_cli.NAME, raw)
        return azure_cli.classify(words, ctx)
    if low in graph_http.SHELL_PROGRAMS:
        probe = graph_http.classify(words, ctx)
        if graph_http.NAME in cfg.enabled:
            return probe
        # Disabled: only a fully parsed request to non-admin hosts stays not-admin.
        if probe.kind == KIND_NOT_ADMIN:
            return make_not_admin(raw, "HTTP client without an admin host")
        return _disabled(graph_http.NAME, raw)

    # 3. interpreters and scripts
    if low in _SHELLS:
        return _shell(words, env, depth, state, raw)
    if _PYTHON_RE.match(low):
        return _python(words, env, depth, state, raw)
    if low in _INTERPRETERS:
        args = words[1:]
        if len(args) == 1 and args[0].text in ("--version", "-v", "-V", "-h", "--help", "version"):
            return make_not_admin(raw, f"{name} version/help")
        texts = [_raw(args)]
        script = next((a for a in args if not a.text.startswith("-")), None)
        readable = (
            script is not None
            and not script.expands
            and not (state.cwd_changed and not script.text.startswith("/"))
        )
        if readable and script is not None:
            loaded = env.load(script.text)
            if loaded is not None:
                texts.append(loaded)
        return _opaque(texts, f"{name} execution is opaque", raw)

    # 4. other admin tools without an adapter
    if low in _ADMIN_TOOLS:
        return make_unknown(f"{name} is an admin tool without an adapter", canonical=raw)
    if low == "find" and any(a.text in _FIND_EXEC for a in words[1:]):
        return make_unknown("find -exec runs commands that are not analysed", canonical=raw)
    if low in _AWKS and any(
        ("system" in a.text or "|" in a.text or "getline" in a.text) for a in words[1:]
    ):
        return make_unknown("awk program can run commands", canonical=raw)
    if low in _INERT:
        return make_not_admin(raw, f"{name} is not an admin command")
    hits = _scan_all(raw)
    if hits:
        marker = make_unknown("admin marker inside a command that is not analysed", canonical=raw)
        return combine([marker, *hits], raw)
    return make_not_admin(raw)


def _disabled(adapter: str, raw: str) -> Result:
    return make_unknown(f"adapter {adapter} is not enabled in policy", canonical=raw)


def _shell(words: Sequence[Arg], env: _Env, depth: int, state: _State, raw: str) -> Result:
    name = words[0].text
    args = list(words[1:])
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if a.expands:
            return make_unknown(f"{name} argument is expanded at run time", canonical=raw)
        if t == "--":
            i += 1
            break
        if t.startswith("--"):
            if t in _SHELL_LONG_OK:
                i += 1
                continue
            return make_unknown(f"{name} option {t} is not supported", canonical=raw)
        if t.startswith(("-", "+")) and len(t) > 1:
            letters = set(t[1:])
            if "c" in letters and t.startswith("-"):
                if not letters - {"c"} <= _SHELL_SHORT_OK:
                    return make_unknown(f"{name} option {t} is not supported", canonical=raw)
                if i + 1 >= len(args):
                    return make_unknown(f"{name} -c without a command", canonical=raw)
                cmd = args[i + 1]
                if cmd.expands:
                    return make_unknown(f"{name} -c text is expanded at run time", canonical=raw)
                # The nested shell starts in the current directory and environment.
                return _classify_bash_text(cmd.text, env, depth + 1, state)
            if t[1:] == "o":
                i += 2
                continue
            if not letters <= _SHELL_SHORT_OK:
                return make_unknown(f"{name} option {t} is not supported", canonical=raw)
            i += 1
            continue
        break
    if i >= len(args):
        return make_unknown(f"{name} reads commands from stdin", canonical=raw)
    return _run_script(args[i], "sh", env, depth, state, raw)


def _python(words: Sequence[Arg], env: _Env, depth: int, state: _State, raw: str) -> Result:
    cfg = env.cfg
    args = list(words[1:])
    if len(args) == 1 and args[0].text in ("-V", "--version", "-h", "--help"):
        return make_not_admin(raw, "python version/help")
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if a.expands:
            return make_unknown("python argument is expanded at run time", canonical=raw)
        if t == "-c":
            code = args[i + 1].text if i + 1 < len(args) else ""
            return _opaque([code], "inline Python is opaque", raw)
        if t == "-m":
            return _opaque([_raw(args[i + 1 :])], "python -m module execution is opaque", raw)
        if t in _PY_FLAGS:
            i += 1
            continue
        if t in ("-W", "-X"):
            i += 2
            continue
        if t.startswith("-"):
            return make_unknown(f"python option {t} is not supported", canonical=raw)
        break
    if i >= len(args):
        return make_unknown("interactive python or stdin", canonical=raw)
    script = args[i]
    norm = simtenant.strip_dot(script.text)
    if norm in cfg.trusted_simtenant_scripts:
        if not norm.startswith("/") and state.cwd_changed:
            return make_unknown("relative simtenant path after a directory change", canonical=raw)
        return _simtenant(args[i:], env, state, raw)
    if posixpath.basename(script.text) in simtenant.PROGRAM_BASENAMES:
        return make_unknown(
            "simtenant at a path that policy does not trust", adapter=simtenant.NAME, canonical=raw
        )
    return _run_script(script, "python", env, depth, state, raw)


def _run_script(path: Arg, mode: str, env: _Env, depth: int, state: _State, raw: str) -> Result:
    """Classify a script by content. ``mode``: sh (shell text), exec (shebang), python (opaque)."""
    if path.expands:
        return make_unknown("script path is expanded at run time", canonical=raw)
    p = path.text
    if state.cwd_changed and not p.startswith("/"):
        return make_unknown("relative script path after a directory change", canonical=raw)
    text = env.load(p)
    if text is None:
        return make_unknown(f"script could not be read: {p}", canonical=raw)
    if mode == "sh":
        return _classify_bash_text(text, env, depth + 1, state)
    if mode == "exec" and text.startswith("#!"):
        interp = text[2:].split("\n", 1)[0].split()
        if interp and posixpath.basename(interp[0]) == "env":
            interp = interp[1:]
        prog = posixpath.basename(interp[0]) if interp and not interp[0].startswith("-") else ""
        if prog in _SHELLS:
            return _classify_bash_text(text, env, depth + 1, state)
        if prog.lower() in m365_powershell.HOSTS:
            if m365_powershell.NAME not in env.cfg.enabled:
                return _disabled(m365_powershell.NAME, raw)
            return m365_powershell.classify_script_text(text)
    return _opaque([text], f"script {p} is opaque", raw)


# ----------------------------------------------------------------- tool calls


def _classify_mcp(tool_name: str, cfg: _Config) -> Result:
    server, sep, tool = tool_name[len("mcp__") :].partition("__")
    if not sep or not server or not tool:
        return make_unknown("malformed MCP tool name", canonical=tool_name)
    if server in cfg.mcp_write_servers:
        return make_unknown(
            f"MCP server {server} is a write surface", adapter="mcp", verb=tool, canonical=tool_name
        )
    if tool_name in cfg.mcp_read_tools:
        return Result(
            KIND_READ,
            False,
            "mcp",
            tool,
            tool_name,
            (),
            False,
            frozenset(),
            ("listed in mcp_read_tools",),
            (),
        )
    return make_unknown(
        "MCP tool is not in mcp_read_tools", adapter="mcp", verb=tool, canonical=tool_name
    )


def _classify_tool(tool_name: Any, tool_input: Any, cfg: _Config, read_file: Any) -> Result:
    if not isinstance(tool_name, str) or not tool_name:
        return make_unknown("tool name is missing")
    if tool_name == "Bash":
        if not isinstance(tool_input, Mapping):
            return make_unknown("Bash input is not a mapping")
        command = tool_input.get("command")
        if not isinstance(command, str):
            return make_unknown("Bash command is not a string")
        if not command.strip():
            return make_unknown("Bash command is empty")
        if len(command) > MAX_COMMAND_CHARS:
            return make_unknown("Bash command is too long to analyse")
        env = _Env(cfg, _make_loader(read_file))
        return _classify_bash_text(command, env, 0)
    if tool_name.startswith("mcp__"):
        return _classify_mcp(tool_name, cfg)
    if tool_name in cfg.not_admin_tools:
        return make_not_admin(tool_name, "built-in tool on the not-admin list")
    return make_unknown("tool is not on the not-admin list", canonical=tool_name)


def classify_tool_call(tool_name: Any, tool_input: Any, *, policy: Any, read_file: Any) -> Result:
    """Classify one tool call. Never raises; every error is unknown-admin (kind=write)."""
    try:
        cfg = _load_config(policy)
    except Exception as exc:
        return make_unknown(f"policy is unusable ({type(exc).__name__}: {exc})")
    try:
        result = _classify_tool(tool_name, tool_input, cfg, read_file)
        if not isinstance(result, Result):
            return make_unknown("classifier produced no result")
        return result
    except RecursionError:
        return make_unknown("classifier recursion limit")
    except Exception as exc:
        return make_unknown(f"classifier error ({type(exc).__name__})")


# ----------------------------------------------------------------- tiers


def _pattern_hit(canonical: str, patterns: Sequence[str], anywhere: bool) -> bool:
    c = canonical.lower()
    for p in patterns:
        pl = p.lower()
        if fnmatch.fnmatchcase(c, pl) or (anywhere and fnmatch.fnmatchcase(c, "*" + pl)):
            return True
    return False


def tier_floor(r: Any, policy: Any) -> str | None:
    """Pattern floor for a write: "critical", "normal" (unknown-admin) or None.

    Reads and not-admin have no floor. A bad policy or argument returns
    "critical" (fail closed).
    """
    try:
        if not isinstance(r, Result):
            return "critical"
        cfg = _load_config(policy)
        writes = [x for x in leaves(r) if x.kind == KIND_WRITE]
        if not writes:
            return None
        patterns = CORE_CRITICAL_PATTERNS + cfg.critical_patterns
        for leaf in writes:
            if FLAG_TENANT_WIDE in leaf.flags:
                return "critical"
            if _pattern_hit(leaf.canonical, patterns, anywhere=leaf.unknown):
                return "critical"
        if r.unknown or any(x.unknown for x in writes):
            return "normal"
        return None
    except Exception:
        return "critical"


def _is_hit(catalog_hit: Any) -> bool:
    return catalog_hit is True or (isinstance(catalog_hit, str) and bool(catalog_hit))


def decide_tier(answers: Any, *, irreversible: Any, catalog_hit: Any, floor: Any) -> str:
    """Final tier from the three questions, the catalogue and the pattern floor.

    ``answers`` keys (bool only; anything else counts as the unsafe answer):
    ``reversible`` (Q1), ``has_dependents`` (Q2), ``targets_enumerated`` (Q3).
    Object count is deliberately not an input.
    """
    try:
        if not isinstance(answers, Mapping) or answers.get("targets_enumerated") is not True:
            return "blocked"
        if irreversible is not False or answers.get("reversible") is not True:
            base = "critical"
        elif answers.get("has_dependents") is not False or not _is_hit(catalog_hit):
            base = "normal"
        else:
            base = "standard"
        if floor is None:
            return base
        if floor not in _RANK:
            return "critical"
        return base if _RANK[base] >= _RANK[floor] else floor
    except Exception:
        return "blocked"


@dataclass(frozen=True)
class _Entry:
    eid: str
    adapter: str
    pattern: str
    targets: frozenset[str]
    state_scope: str


def _valid_entry(entry: Any) -> _Entry | None:
    if not isinstance(entry, Mapping) or entry.get("enabled") is not True:
        return None
    keys = ("id", "adapter", "command_pattern", "target_scope", "state_scope")
    eid, adapter, pattern, targets, state_scope = (entry.get(k) for k in keys)
    if not all(isinstance(v, str) and v for v in (eid, adapter, pattern)):
        return None
    if isinstance(targets, str | bytes) or not isinstance(targets, Sequence) or not targets:
        return None
    if not all(isinstance(t, str) and t and not (_PATTERN_SPECIALS & set(t)) for t in targets):
        return None  # target scope is a list of exact targets, not patterns
    # The state (tenant) scope is required and exact; an entry without one never matches.
    if not isinstance(state_scope, str) or _PATTERN_SPECIALS & set(state_scope):
        return None
    if simtenant.state_scope(state_scope) != state_scope:
        return None  # must already be a normalised project-relative path
    return _Entry(eid, adapter, pattern, frozenset(targets), state_scope)


def _catalogable(leaf: Result) -> bool:
    """A write leaf that a catalogue entry may cover at all."""
    return (
        not leaf.unknown
        and leaf.targets_complete
        and bool(leaf.targets)
        and FLAG_TENANT_WIDE not in leaf.flags
        and leaf.scope is not None
    )


def _covers(e: _Entry, leaf: Result) -> bool:
    return (
        leaf.adapter == e.adapter
        and leaf.scope == e.state_scope
        and fnmatch.fnmatchcase(leaf.canonical.lower(), e.pattern.lower())
        and set(leaf.targets) <= e.targets
    )


def catalog_match(r: Any, entries: Any) -> str | None:
    """ID of the first enabled standard-change entry covering every write leaf, else None.

    A leaf is covered when its adapter is exactly the entry's, its canonical
    form matches ``command_pattern``, every target is in ``target_scope`` and
    its state scope equals ``state_scope``. Object count is never a criterion.
    """
    try:
        if not isinstance(r, Result) or r.kind != KIND_WRITE or r.unknown:
            return None
        if not r.targets_complete:
            return None
        if isinstance(entries, str | bytes | Mapping) or not isinstance(entries, Sequence):
            return None
        writes = [x for x in leaves(r) if x.kind == KIND_WRITE]
        if not writes or not all(_catalogable(leaf) for leaf in writes):
            return None
        for entry in entries:
            e = _valid_entry(entry)
            if e is not None and all(_covers(e, leaf) for leaf in writes):
                return e.eid
        return None
    except Exception:
        return None
