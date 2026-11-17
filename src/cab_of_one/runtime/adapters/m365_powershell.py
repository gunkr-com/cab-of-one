"""Microsoft 365 PowerShell adapter (classification only, no target extraction).

This is not a PowerShell parser. The ``-Command`` text (or the ``-File``
script) is cut into statements at ``;``, ``|``, newlines, ``&&``/``||``,
braces and parentheses, with quotes respected. Every statement must start with
a Verb-Noun cmdlet, a known pipeline utility, a variable, an assignment or a
literal; anything else (control flow, ``&``, dot-sourcing, method calls,
``$( )``, ``@( )``, hashtable literals ``@{ }``, here-strings, block
comments, ``ForEach-Object <member>``) makes the whole call unknown-admin.
Hashtable values can hold evaluated code, so no hashtable is ever read.
Read verbs are Get, Find and Test; every other verb, Connect included, is
write. ``-WhatIf`` is recorded as a flag and never lowers the kind.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Sequence

from ..classification_types import (
    FLAG_ALL_SWITCH,
    FLAG_WHATIF,
    AdapterContext,
    Arg,
    Result,
    combine,
    make_not_admin,
    make_read,
    make_unknown,
    make_write,
)
from . import graph_http

NAME = "m365-powershell"
HOSTS = frozenset({"pwsh", "powershell", "pwsh.exe", "powershell.exe"})
READ_VERBS = frozenset({"get", "find", "test"})

NEUTRAL = frozenset(
    {
        "foreach-object",
        "%",
        "where-object",
        "?",
        "where",
        "select-object",
        "select",
        "sort-object",
        "sort",
        "group-object",
        "measure-object",
        "format-table",
        "ft",
        "format-list",
        "fl",
        "out-string",
        "out-null",
        "out-host",
        "write-output",
        "echo",
        "write-host",
        "convertto-json",
        "convertfrom-json",
    }
)
# ForEach-Object with a positional argument invokes a member on every input object.
FOREACH = frozenset({"foreach-object", "%", "foreach"})
DYNAMIC = frozenset(
    {
        "invoke-expression",
        "iex",
        "invoke-command",
        "icm",
        "start-process",
        "saps",
        "start",
        "start-job",
        "sajb",
        "start-threadjob",
        "add-type",
        "invoke-item",
        "ii",
        "new-module",
        "nmo",
        ".",
        "&",
    }
)
KEYWORDS = frozenset(
    {
        "if",
        "elseif",
        "else",
        "foreach",
        "for",
        "while",
        "do",
        "until",
        "switch",
        "try",
        "catch",
        "finally",
        "trap",
        "function",
        "filter",
        "workflow",
        "param",
        "begin",
        "process",
        "end",
        "return",
        "exit",
        "break",
        "continue",
        "throw",
        "data",
        "class",
        "enum",
        "using",
        "dynamicparam",
        "clean",
    }
)
_ASSIGN = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "??="})
_VERB_NOUN = re.compile(r"^([A-Za-z]+)-([A-Za-z][A-Za-z0-9]*)$")

_HOST_COMMAND = frozenset({"c", "com", "comm", "comma", "comman", "command"})
_HOST_FILE = frozenset({"f", "fi", "fil", "file"})
_HOST_FLAGS = frozenset(
    {"noprofile", "nop", "noninteractive", "noni", "nologo", "nol", "mta", "sta", "noexit"}
)
_HOST_VALUED = frozenset(
    {
        "executionpolicy",
        "ep",
        "ex",
        "outputformat",
        "of",
        "o",
        "inputformat",
        "inp",
        "if",
        "windowstyle",
        "w",
    }
)

_SCAN_RE = re.compile(r"(?<![\w-])([A-Za-z]+)-([A-Za-z][A-Za-z0-9]+)\b")
# Approved PowerShell verbs (lower case); used only to scan opaque text.
_APPROVED = frozenset(
    """
add approve assert backup block build checkpoint clear close compare complete compress
confirm connect convert convertfrom convertto copy debug deny deploy disable disconnect
dismount edit enable enter exit expand export find format get grant group hide import
initialize install invoke join limit lock measure merge mount move new open optimize out
ping pop protect publish push read receive redo register remove rename repair request reset
resize resolve restart restore resume revoke save search select send set show skip split
start step stop submit suspend switch sync test trace unblock undo uninstall unlock
unprotect unpublish unregister update use wait watch write
""".split()
)


class _PSUnknown(Exception):
    pass


def matches(argv: Sequence[Arg], ctx: AdapterContext) -> bool:
    return bool(argv) and posixpath.basename(argv[0].text).lower() in HOSTS


def classify(argv: Sequence[Arg], ctx: AdapterContext) -> Result:
    host = posixpath.basename(argv[0].text).lower()
    raw = " ".join(a.text for a in argv)

    def unk(reason: str) -> Result:
        return make_unknown(f"{host}: {reason}", adapter=NAME, canonical=raw)

    args = list(argv[1:])
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if a.expands:
            return unk("argument is expanded by the shell before PowerShell sees it")
        if not t.startswith("-"):
            if host.startswith("powershell"):
                return _command(args[i:], raw)
            return _file(a, ctx, raw)
        name = t.lstrip("-").lower()
        if name in _HOST_COMMAND:
            return _command(args[i + 1 :], raw)
        if name in _HOST_FILE:
            if i + 1 >= len(args):
                return unk("-File without a path")
            return _file(args[i + 1], ctx, raw)
        if name.startswith("e") and name not in _HOST_VALUED:
            return unk("encoded command or arguments are not decoded")
        if name in _HOST_FLAGS:
            i += 1
            continue
        if name in _HOST_VALUED:
            i += 2
            continue
        return unk(f"unsupported host option {t}")
    return unk("no -Command or -File: commands come from stdin or an interactive session")


def _command(rest: Sequence[Arg], raw: str) -> Result:
    if not rest:
        return make_unknown("-Command without text", adapter=NAME, canonical=raw)
    if any(a.expands for a in rest):
        return make_unknown(
            "shell expansion inside the PowerShell command", adapter=NAME, canonical=raw
        )
    text = " ".join(a.text for a in rest)
    if text.strip() == "-":
        return make_unknown("-Command - reads stdin", adapter=NAME, canonical=raw)
    return classify_script_text(text)


def _file(path: Arg, ctx: AdapterContext, raw: str) -> Result:
    if path.expands:
        return make_unknown("script path is expanded at run time", adapter=NAME, canonical=raw)
    p = path.text
    if ctx.cwd_changed and not p.startswith("/"):
        return make_unknown(
            "relative script path after a directory change", adapter=NAME, canonical=raw
        )
    text = ctx.load_script(p) if ctx.load_script is not None else None
    if text is None:
        return make_unknown(f"script could not be read: {p}", adapter=NAME, canonical=raw)
    return classify_script_text(text)


def _squash(text: str) -> str:
    return " ".join(text.split())


def classify_script_text(text: str) -> Result:
    """Classify PowerShell source. Pure; never raises for malformed text.

    Unknown results keep the whole squashed text as canonical, so the core
    critical floor still sees cmdlets such as ``Remove-MgUser`` inside it.
    """
    try:
        statements = _statements(text)
        results = [r for r in (_statement(s) for s in statements) if r is not None]
    except _PSUnknown as exc:
        return make_unknown(f"PowerShell: {exc}", adapter=NAME, canonical=_squash(text))
    if not results:
        return make_not_admin(_squash(text), "PowerShell without admin cmdlets")
    return combine(results, _squash(text))


def _skip_single(text: str, i: int) -> int:
    k = i + 1
    while True:
        j = text.find("'", k)
        if j < 0:
            raise _PSUnknown("unterminated single-quoted string")
        if text[j + 1 : j + 2] == "'":
            k = j + 2
            continue
        return j + 1


def _skip_double(text: str, i: int) -> int:
    k = i + 1
    n = len(text)
    while k < n:
        ch = text[k]
        if ch == "`":
            k += 2
            continue
        if ch == "$" and text[k + 1 : k + 2] == "(":
            raise _PSUnknown("subexpression $( ) inside a string")
        if ch == '"':
            if text[k + 1 : k + 2] == '"':
                k += 2
                continue
            return k + 1
        k += 1
    raise _PSUnknown("unterminated double-quoted string")


def _statements(text: str) -> list[list[str]]:
    stmts: list[list[str]] = []
    cur: list[str] = []
    buf: list[str] = []

    def flush() -> None:
        if buf:
            cur.append("".join(buf))
            buf.clear()

    def end() -> None:
        flush()
        if cur:
            stmts.append(list(cur))
            cur.clear()

    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nx = text[i + 1] if i + 1 < n else ""
        if c in " \t\r\f":
            flush()
            i += 1
        elif c in "\n;":
            end()
            i += 1
        elif c == "|":
            end()
            i += 2 if nx == "|" else 1
        elif c == "&":
            if nx != "&":
                raise _PSUnknown("'&' call or background operator")
            end()
            i += 2
        elif c == "#" and not buf:
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "<" and nx == "#":
            raise _PSUnknown("block comment")
        elif c in "{}":
            end()
            i += 1
        elif c == "(":
            if buf:
                raise _PSUnknown("method call or expression in parentheses")
            end()
            i += 1
        elif c == ")":
            end()
            i += 1
        elif c == "$" and nx == "(":
            raise _PSUnknown("subexpression $( )")
        elif c == "@" and nx == "(":
            raise _PSUnknown("array subexpression @( )")
        elif c == "@" and nx in ("'", '"'):
            raise _PSUnknown("here-string")
        elif c == "@" and nx == "{":
            # Values, nested tables and subexpressions in a hashtable are evaluated
            # when the statement runs; none of it is analysed, so none of it is read.
            raise _PSUnknown("hashtable literal @{ } is not analysed")
        elif c == "'":
            j = _skip_single(text, i)
            buf.append(text[i:j])
            i = j
        elif c == '"':
            j = _skip_double(text, i)
            buf.append(text[i:j])
            i = j
        elif c == "`":
            if nx == "\n":
                i += 2
            elif not nx:
                raise _PSUnknown("trailing backtick")
            else:
                buf.append(text[i : i + 2])
                i += 2
        elif c == "=" and not cur and buf and buf[0].startswith("$"):
            # `$x=Get-Thing` written without spaces
            op = "="
            if buf[-1] in ("+", "-", "*", "/", "%"):
                op = buf.pop() + "="
            flush()
            cur.append(op)
            i += 1
        else:
            buf.append(c)
            i += 1
    end()
    return stmts


def _statement(toks: Sequence[str]) -> Result | None:
    """Result for one statement, or None for a neutral statement."""
    t0 = toks[0]
    if t0.startswith("$"):
        if len(toks) >= 2 and toks[1] in _ASSIGN:
            rest = toks[2:]
            return _statement(rest) if rest else None
        return None  # variable expression; method calls were rejected by the splitter
    if t0[0] in "'\"" or t0[0].isdigit():
        return None
    low = t0.lower()
    if low in DYNAMIC:
        raise _PSUnknown(f"{t0} runs code that is not analysed")
    if low in graph_http.PS_PROGRAMS:
        return graph_http.classify_ps(toks)
    if low in FOREACH and any(not tok.startswith("-") for tok in toks[1:]):
        raise _PSUnknown(f"{t0} with a member name invokes a method on each object")
    if low in NEUTRAL:
        return None
    if low in KEYWORDS:
        raise _PSUnknown(f"control flow ({t0}) is not analysed")
    m = _VERB_NOUN.match(t0)
    if not m:
        raise _PSUnknown(f"unrecognised statement starting with {t0!r}")
    verb = m.group(1).lower()
    flags = set()
    for tok in toks[1:]:
        tl = tok.lower()
        if tl == "-whatif" or tl.startswith("-whatif:"):
            flags.add(FLAG_WHATIF)
        if tl == "-all" or tl.startswith("-all:"):
            flags.add(FLAG_ALL_SWITCH)
    canonical = " ".join(toks)
    if verb in READ_VERBS:
        return make_read(NAME, t0, canonical, flags=flags, reason=f"{t0} is a read verb")
    reason = f"{t0} is not a read verb"
    if FLAG_WHATIF in flags:
        reason += "; -WhatIf does not lower the classification"
    return make_write(NAME, t0, canonical, flags=flags, reason=reason)


def scan_text(text: str) -> list[Result]:
    """Verb-Noun cmdlets in opaque text. Results are always unknown-admin."""
    out: list[Result] = []
    for line in text.splitlines():
        for m in _SCAN_RE.finditer(line):
            if m.group(1).lower() not in _APPROVED:
                continue
            tail = re.split(r"[\"';|]", line[m.start() :], maxsplit=1)[0]
            out.append(
                make_unknown(
                    "cmdlet in text that is not parsed",
                    adapter=NAME,
                    verb=m.group(0),
                    canonical=_squash(tail),
                )
            )
    return out


__all__ = [
    "HOSTS",
    "NAME",
    "READ_VERBS",
    "classify",
    "classify_script_text",
    "matches",
    "scan_text",
]
