"""Azure CLI adapter (classification only).

The verb is the last *command word*: the leading lowercase words before the
first command-specific option. It is never taken from the last token, so an
option value such as ``--name show`` or ``--query list`` cannot turn
``delete`` into a read. Read: ``list``, ``show`` and ``get-*`` with at least a
group word before them. Everything else, including ``login``, is write.

``az rest`` is read only with an explicit literal ``--method GET``, a literal
URL and no body; the rest of its options must be known.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Sequence

from ..classification_types import (
    FLAG_WHATIF,
    AdapterContext,
    Arg,
    Result,
    make_not_admin,
    make_read,
    make_unknown,
    make_write,
)
from . import graph_http

NAME = "azure-cli"
READ_VERBS = frozenset({"list", "show"})
GLOBAL_FLAGS = frozenset({"--debug", "--verbose", "--only-show-errors"})
GLOBAL_VALUED = frozenset({"--output", "-o", "--query", "--subscription"})

_WORD_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_OPTION_RE = re.compile(r"^(--[a-z0-9][a-z0-9-]*(=.*)?|-[A-Za-z])$", re.DOTALL)
_SCAN_WORD_RE = re.compile(r"[^\s\"',\[\]()]+")

_REST_SINGLE = frozenset({"--method", "-m", "--url", "--uri", "-u"})
_REST_BODY = frozenset({"--body", "-b"})
_REST_PASS = frozenset(
    {
        "--uri-parameters",
        "--url-parameters",
        "--resource",
        "--output-file",
        "--query",
        "--output",
        "-o",
        "--subscription",
    }
)
_REST_FLAGS = frozenset({"--skip-authorization-header"}) | GLOBAL_FLAGS


def matches(argv: Sequence[Arg], ctx: AdapterContext) -> bool:
    return bool(argv) and posixpath.basename(argv[0].text).lower() == "az"


def classify(argv: Sequence[Arg], ctx: AdapterContext) -> Result:
    args = list(argv[1:])
    canonical = " ".join(["az", *(shlex.quote(a.text) for a in args)])

    def unk(reason: str) -> Result:
        return make_unknown(f"az: {reason}", adapter=NAME, canonical=canonical)

    if not args:
        return make_not_admin(canonical, "az without a command prints help")

    words: list[str] = []
    other_opts: list[str] = []
    help_seen = version_seen = False
    collecting = True
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if t.startswith("-") and len(t) > 1:
            if a.expands:
                return unk("option name is expanded at run time")
            if not _OPTION_RE.match(t):
                return unk(f"malformed option {t!r}")
            name = t.split("=", 1)[0]
            if name in ("--help", "-h"):
                help_seen = True
            elif name == "--version":
                version_seen = True
            elif name in GLOBAL_FLAGS:
                pass
            elif name in GLOBAL_VALUED:
                if "=" not in t:
                    i += 1  # skip the value
            else:
                collecting = False
                other_opts.append(name)
            i += 1
            continue
        if collecting:
            if a.expands:
                return unk("command word is expanded at run time")
            if not _WORD_RE.match(t):
                return unk(f"unrecognised command word {t!r}")
            words.append(t)
        i += 1

    if help_seen:
        if other_opts:
            return unk("--help mixed with command options")
        return make_not_admin(canonical, "az help")
    if version_seen and not words and not other_opts:
        return make_not_admin(canonical, "az --version")
    if not words:
        return unk("options without a command")
    if words[0] == "rest":
        return _rest(args, canonical)

    verb = words[-1]
    flags = set()
    if "--what-if" in other_opts or verb == "what-if":
        flags.add(FLAG_WHATIF)
    if len(words) >= 2 and (verb in READ_VERBS or verb.startswith("get-")):
        return make_read(
            NAME, verb, canonical, flags=flags, reason=f"az {verb} in command position"
        )
    return make_write(
        NAME, verb, canonical, flags=flags, reason=f"az verb {verb!r} is not a known read"
    )


def _rest(args: Sequence[Arg], canonical: str) -> Result:
    def unk(reason: str) -> Result:
        return make_unknown(f"az rest: {reason}", adapter=NAME, canonical=canonical)

    method = url = None
    body = override = opaque = False
    seen_rest = False
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if not seen_rest and t == "rest" and not a.expands:
            seen_rest = True
            i += 1
            continue
        if not (t.startswith("-") and len(t) > 1):
            return unk(f"unexpected argument {t!r}")
        if a.expands:
            return unk("option name is expanded at run time")
        name, eq, inline = t.partition("=")
        if eq:
            values = [Arg(inline, a.expands, a.quoted, inline)]
            j = i + 1
        else:
            j = i + 1
            while j < len(args) and not (args[j].text.startswith("-") and len(args[j].text) > 1):
                j += 1
            values = list(args[i + 1 : j])
        if name in _REST_SINGLE:
            if len(values) != 1:
                return unk(f"{name} needs exactly one value")
            if name in ("--method", "-m"):
                if method is not None:
                    return unk("repeated --method")
                method = values[0]
            else:
                if url is not None:
                    return unk("repeated --url")
                url = values[0]
        elif name in _REST_BODY:
            body = True
        elif name == "--headers":
            for v in values:
                hname = re.split(r"[=:]", v.text, maxsplit=1)[0].strip().lower()
                if hname in graph_http.OVERRIDE_HEADERS or hname in graph_http.ROUTING_HEADERS:
                    override = True
                elif v.expands and hname != "authorization":
                    opaque = True
                if v.text.startswith("@"):
                    opaque = True
        elif name in _REST_PASS:
            pass
        elif name in _REST_FLAGS:
            if values:
                return unk(f"{name} takes no value")
        else:
            return unk(f"unsupported option {name}")
        i = j

    if url is None:
        return unk("no --url")
    if url.expands:
        return unk("URL is expanded at run time")
    if method is None:
        return unk("no explicit --method (only --method GET is a read)")
    if method.expands or not re.match(r"^[A-Za-z]+$", method.text):
        return unk("method is not a literal")
    target = url.text
    if target.startswith("/"):
        target = "https://management.azure.com" + target
    return graph_http.http_result(
        NAME,
        method.text,
        [target],
        body=body,
        override=override,
        opaque_header=opaque,
        raw=canonical,
        any_host=True,
    )


def scan_text(text: str) -> list[Result]:
    """``az ...`` in opaque text. Results are always unknown-admin."""
    out: list[Result] = []
    for line in text.splitlines():
        words = _SCAN_WORD_RE.findall(line)
        for k, w in enumerate(words):
            if w == "az" and k + 1 < len(words) and re.match(r"^[a-z]", words[k + 1]):
                out.append(
                    make_unknown(
                        "az reference in text that is not parsed",
                        adapter=NAME,
                        canonical="az " + " ".join(words[k + 1 :]),
                    )
                )
                break
    return out


__all__ = ["NAME", "READ_VERBS", "classify", "matches", "scan_text"]
