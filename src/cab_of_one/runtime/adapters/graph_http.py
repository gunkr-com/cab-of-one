"""Graph / ARM HTTP adapter (classification only, no target extraction).

Handles ``curl`` and ``wget`` from the shell and, through ``classify_ps``,
``Invoke-RestMethod``/``Invoke-WebRequest``/``Invoke-MgGraphRequest`` inside
PowerShell. A request is read only when the method is a literal GET or HEAD,
there is no body, upload, form, batch, method-override header or run-time
header value, and the URL is a literal. The canonical form is
``http METHOD host/normalised/path`` (query dropped, percent-decoding and
``..`` resolved) so that critical patterns see the real path.

Not-admin is given only after a complete, successful parse whose literal URLs
are all non-admin hosts and that has no hidden request part. Any option this
adapter does not model, a config file (``-K``/``--config``), header files
(``-H @file``), a ``Host:`` or method-override header, a repeated method and
run-time values are unknown-admin whatever the URL, because they can hide the
real request.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from ..classification_types import (
    AdapterContext,
    Arg,
    Result,
    combine,
    make_not_admin,
    make_read,
    make_unknown,
    make_write,
)

NAME = "graph-http"

ADMIN_HOSTS = frozenset(
    {
        "graph.microsoft.com",
        "graph.microsoft.us",
        "dod-graph.microsoft.us",
        "microsoftgraph.chinacloudapi.cn",
        "management.azure.com",
        "management.core.windows.net",
        "management.usgovcloudapi.net",
        "management.chinacloudapi.cn",
        "outlook.office365.com",
        "outlook.office.com",
        "login.microsoftonline.com",
        "manage.office.com",
        "api.security.microsoft.com",
        "api.securitycenter.microsoft.com",
    }
)
ADMIN_SUFFIXES = (".sharepoint.com", ".vault.azure.net")
_MARKERS = tuple(sorted(ADMIN_HOSTS)) + ("sharepoint.com", "vault.azure.net")

OVERRIDE_HEADERS = frozenset({"x-http-method-override", "x-http-method", "x-method-override"})
# Headers that change where the request goes; treated like a hidden request.
ROUTING_HEADERS = frozenset({"host", ":authority"})
READ_METHODS = frozenset({"GET", "HEAD"})
_METHOD_RE = re.compile(r"^[A-Za-z]+$")
_URL_SCAN_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
_METHOD_SCAN_RE = re.compile(r"\b(GET|HEAD|POST|PUT|PATCH|DELETE)\b", re.IGNORECASE)

SHELL_PROGRAMS = frozenset({"curl", "wget"})
PS_PROGRAMS = frozenset(
    {
        "invoke-restmethod",
        "irm",
        "invoke-webrequest",
        "iwr",
        "curl",
        "wget",
        "invoke-mggraphrequest",
    }
)


class _Unknown(Exception):
    pass


def is_admin_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in ADMIN_HOSTS or any(host.endswith(s) for s in ADMIN_SUFFIXES)


def mentions_admin_host(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _MARKERS)


def normalize_url(url: str) -> tuple[str, str] | None:
    """Return (host, path) or None when the URL cannot be read unambiguously."""
    u = url.strip()
    if not u or any(ord(ch) < 0x20 for ch in u) or "\\" in u:
        return None
    if "://" not in u:
        u = "https://" + u
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    path = unquote(parts.path) or "/"
    if "\\" in path or any(ord(ch) < 0x20 for ch in path):
        return None
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    path = posixpath.normpath(path)
    return host, path


def _is_batch(path: str) -> bool:
    return any(seg.lower() == "$batch" for seg in path.split("/"))


def http_result(
    adapter: str,
    method: str,
    urls: Sequence[str],
    *,
    body: bool,
    override: bool = False,
    opaque_header: bool = False,
    raw: str,
    any_host: bool = False,
) -> Result:
    """Classify literal URLs. Non-admin hosts are skipped unless ``any_host``.

    A hidden header (override, routing, file or run-time value) is unknown-admin
    even on a non-admin host: it can change what the request really does.
    """
    method = method.upper()
    out: list[Result] = []
    for url in urls:
        norm = normalize_url(url)
        if norm is None:
            out.append(
                make_unknown(
                    "URL could not be parsed unambiguously", adapter=adapter, canonical=raw
                )
            )
            continue
        host, path = norm
        canon = f"http {method} {host}{path}"
        if not any_host and not is_admin_host(host):
            if override or opaque_header:
                out.append(
                    make_unknown(
                        "hidden header on a request; the target is not certain",
                        adapter=adapter,
                        verb=method,
                        canonical=canon,
                    )
                )
            continue
        if _is_batch(path):
            out.append(
                make_unknown(
                    "$batch request bodies are not analysed",
                    adapter=adapter,
                    verb=method,
                    canonical=canon,
                )
            )
        elif override:
            out.append(
                make_unknown(
                    "method-override header hides the real method",
                    adapter=adapter,
                    verb=method,
                    canonical=canon,
                )
            )
        elif opaque_header:
            out.append(
                make_unknown(
                    "header comes from a file or is expanded at run time",
                    adapter=adapter,
                    verb=method,
                    canonical=canon,
                )
            )
        elif method in READ_METHODS and not body:
            out.append(make_read(adapter, method, canon, reason="HTTP GET/HEAD without body"))
        elif method in READ_METHODS:
            out.append(
                make_unknown(
                    "request body on a read method", adapter=adapter, verb=method, canonical=canon
                )
            )
        else:
            out.append(make_write(adapter, method, canon, reason=f"HTTP {method}"))
    if not out:
        return make_not_admin(raw, "HTTP request to a non-admin host")
    return combine(out, raw)


# ---------------------------------------------------------------- curl

_CURL_SHORT_VALUED = {
    "X": "--request",
    "H": "--header",
    "d": "--data",
    "F": "--form",
    "T": "--upload-file",
    "o": "--output",
    "u": "--user",
    "A": "--user-agent",
    "e": "--referer",
    "b": "--cookie",
    "c": "--cookie-jar",
    "r": "--range",
    "m": "--max-time",
    "w": "--write-out",
    "x": "--proxy",
    "y": "--speed-time",
    "Y": "--speed-limit",
    "z": "--time-cond",
    "K": "--config",
    "E": "--cert",
    "C": "--continue-at",
    "D": "--dump-header",
    "U": "--proxy-user",
    "Q": "--quote",
    "t": "--telnet-option",
}
_CURL_SHORT_FLAGS = frozenset("sSLfkivIGOnNqjJlMpRVZ0123456#")
# --location-trusted is left out on purpose: it forwards credentials to any redirect host.
_CURL_LONG_FLAGS = frozenset(
    {
        "--silent",
        "--show-error",
        "--location",
        "--fail",
        "--fail-with-body",
        "--fail-early",
        "--insecure",
        "--include",
        "--verbose",
        "--head",
        "--get",
        "--compressed",
        "--globoff",
        "--http1.0",
        "--http1.1",
        "--http2",
        "--http2-prior-knowledge",
        "--http3",
        "--no-progress-meter",
        "--progress-bar",
        "--remote-name",
        "--remote-name-all",
        "--remote-header-name",
        "--ipv4",
        "--ipv6",
        "--no-buffer",
        "--no-keepalive",
        "--tlsv1.2",
        "--tlsv1.3",
        "--raw",
        "--path-as-is",
        "--retry-connrefused",
        "--retry-all-errors",
        "--create-dirs",
    }
)
_CURL_LONG_VALUED = frozenset(
    {
        "--request",
        "--header",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--data-ascii",
        "--json",
        "--form",
        "--form-string",
        "--upload-file",
        "--output",
        "--user",
        "--user-agent",
        "--referer",
        "--cookie",
        "--cookie-jar",
        "--range",
        "--max-time",
        "--connect-timeout",
        "--write-out",
        "--proxy",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "--cert",
        "--key",
        "--cacert",
        "--capath",
        "--resolve",
        "--connect-to",
        "--url",
        "--oauth2-bearer",
        "--limit-rate",
        "--dump-header",
        "--trace",
        "--trace-ascii",
        "--stderr",
        "--max-filesize",
        "--max-redirs",
        "--interface",
        "--proxy-user",
        "--cert-type",
        "--key-type",
        "--expect100-timeout",
        "--keepalive-time",
        "--output-dir",
        "--aws-sigv4",
        "--config",
    }
)
_CURL_BODY = frozenset(
    {
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--data-ascii",
        "--json",
        "--form",
        "--form-string",
        "--upload-file",
    }
)


@dataclass
class _Request:
    method: Arg | None = None
    head: bool = False
    get: bool = False
    body: bool = False
    upload: bool = False
    override: bool = False
    opaque_header: bool = False
    urls: list[Arg] = field(default_factory=list)


def _header(req: _Request, val: Arg) -> None:
    text = val.text
    if text.startswith("@"):
        req.opaque_header = True  # headers read from a file or stdin
        return
    name, sep, _ = text.partition(":")
    hname = name.strip().lower()
    if val.expands and ("$" in name or not sep):
        req.opaque_header = True
    elif hname in OVERRIDE_HEADERS:
        req.override = True
    elif hname in ROUTING_HEADERS:
        req.opaque_header = True
    elif val.expands and hname != "authorization":
        req.opaque_header = True


def _set_method(req: _Request, val: Arg) -> None:
    if req.method is not None:
        raise _Unknown("method is given more than once")
    req.method = val


def _curl_apply(req: _Request, name: str, val: Arg) -> None:
    if name == "--config":
        raise _Unknown("curl reads options from a config file")
    if name == "--request":
        _set_method(req, val)
    elif name == "--header":
        _header(req, val)
    elif name in _CURL_BODY:
        req.body = True
        req.upload |= name == "--upload-file"
    elif name == "--url":
        req.urls.append(val)


def _parse_curl(args: Sequence[Arg]) -> _Request:
    req = _Request()
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if t == "--":
            req.urls.extend(args[i + 1 :])
            break
        if t.startswith("--"):
            if a.expands:
                raise _Unknown("option name is expanded at run time")
            if "=" in t:
                raise _Unknown(f"curl does not take {t.split('=', 1)[0]}=VALUE")
            if t in _CURL_LONG_FLAGS:
                req.head |= t == "--head"
                req.get |= t == "--get"
                i += 1
                continue
            if t in _CURL_LONG_VALUED:
                if i + 1 >= len(args):
                    raise _Unknown(f"{t} without a value")
                _curl_apply(req, t, args[i + 1])
                i += 2
                continue
            raise _Unknown(f"unsupported curl option {t}")
        if t.startswith("-") and len(t) > 1:
            if a.expands:
                raise _Unknown("option is expanded at run time")
            consumed = 1
            j = 1
            while j < len(t):
                ch = t[j]
                if ch in _CURL_SHORT_VALUED:
                    rest = t[j + 1 :]
                    if rest:
                        val = Arg(rest, a.expands, a.quoted, rest)
                    else:
                        if i + 1 >= len(args):
                            raise _Unknown(f"-{ch} without a value")
                        val = args[i + 1]
                        consumed = 2
                    _curl_apply(req, _CURL_SHORT_VALUED[ch], val)
                    break
                if ch in _CURL_SHORT_FLAGS:
                    req.head |= ch == "I"
                    req.get |= ch == "G"
                    j += 1
                    continue
                raise _Unknown(f"unsupported curl option -{ch}")
            i += consumed
            continue
        req.urls.append(a)
        i += 1
    return req


# ---------------------------------------------------------------- wget

_WGET_FLAGS = frozenset(
    {
        "-q",
        "--quiet",
        "-nv",
        "--no-verbose",
        "-S",
        "--server-response",
        "--no-check-certificate",
        "-c",
        "--continue",
        "--content-on-error",
        "-v",
        "--verbose",
    }
)
_WGET_VALUED = frozenset(
    {
        "-O",
        "--output-document",
        "--header",
        "--method",
        "--body-data",
        "--body-file",
        "--post-data",
        "--post-file",
        "-t",
        "--tries",
        "-T",
        "--timeout",
        "--user-agent",
        "-U",
        "--user",
        "--password",
    }
)


def _parse_wget(args: Sequence[Arg]) -> _Request:
    req = _Request()
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if t.startswith("-") and len(t) > 1:
            if a.expands:
                raise _Unknown("option is expanded at run time")
            if t in _WGET_FLAGS:
                i += 1
                continue
            name, eq, inline = t.partition("=")
            if t.startswith("-O") and not t.startswith("--") and len(t) > 2:
                i += 1
                continue
            if name in _WGET_VALUED:
                if eq:
                    val = Arg(inline, a.expands, a.quoted, inline)
                    i += 1
                else:
                    if i + 1 >= len(args):
                        raise _Unknown(f"{name} without a value")
                    val = args[i + 1]
                    i += 2
                if name == "--method":
                    _set_method(req, val)
                elif name == "--header":
                    _header(req, val)
                elif name in ("--post-data", "--post-file"):
                    req.body = True
                    if req.method is None:
                        req.method = Arg("POST", False, False, "POST")
                elif name in ("--body-data", "--body-file"):
                    req.body = True
                continue
            raise _Unknown(f"unsupported wget option {name}")
        req.urls.append(a)
        i += 1
    return req


def _shell_request(req: _Request, adapter: str, raw: str) -> Result:
    if req.method is not None:
        if req.method.expands or not _METHOD_RE.match(req.method.text):
            return make_unknown("HTTP method is not a literal", adapter=adapter, canonical=raw)
        method = req.method.text.upper()
    elif req.head:
        method = "HEAD"
    elif req.upload:
        method = "PUT"
    elif req.body and not req.get:
        method = "POST"
    else:
        method = "GET"
    if not req.urls:
        return make_unknown("no URL found", adapter=adapter, canonical=raw)
    for u in req.urls:
        if u.expands:
            return make_unknown("URL is expanded at run time", adapter=adapter, canonical=raw)
        if any(ch in u.text for ch in "{}[]"):
            return make_unknown(
                "URL globbing can send several requests", adapter=adapter, canonical=raw
            )
    return http_result(
        adapter,
        method,
        [u.text for u in req.urls],
        body=req.body,
        override=req.override,
        opaque_header=req.opaque_header,
        raw=raw,
    )


def matches(argv: Sequence[Arg], ctx: AdapterContext) -> bool:
    return bool(argv) and posixpath.basename(argv[0].text).lower() in SHELL_PROGRAMS


def classify(argv: Sequence[Arg], ctx: AdapterContext) -> Result:
    raw = " ".join(shlex.quote(a.text) for a in argv)
    prog = posixpath.basename(argv[0].text).lower()
    args = list(argv[1:])
    try:
        req = _parse_curl(args) if prog == "curl" else _parse_wget(args)
    except _Unknown as exc:
        # Never fall back to not-admin: an option that was not understood can
        # carry the real URL, method or headers.
        return make_unknown(f"{prog}: {exc}", adapter=NAME, canonical=raw)
    return _shell_request(req, NAME, raw)


# ---------------------------------------------------------------- PowerShell

_PS_VALUED = frozenset(
    {
        "-contenttype",
        "-outfile",
        "-erroraction",
        "-ea",
        "-timeoutsec",
        "-maximumredirection",
        "-token",
        "-authentication",
        "-sessionvariable",
        "-websession",
        "-useragent",
        "-outputtype",
        "-outputfilepath",
        "-statuscodevariable",
        "-responseheaderstvariable",
        "-certificatethumbprint",
        "-maximumretrycount",
        "-retryintervalsec",
    }
)
_PS_FLAGS = frozenset(
    {
        "-usebasicparsing",
        "-usedefaultcredentials",
        "-skipcertificatecheck",
        "-skiphttperrorcheck",
        "-passthru",
        "-disablekeepalive",
        "-verbose",
        "-skipheadervalidation",
    }
)


def _ps_literal(tok: str) -> str | None:
    """Literal value of a PowerShell token, or None when it is evaluated at run time."""
    if len(tok) >= 2 and tok[0] == tok[-1] == "'":
        return tok[1:-1].replace("''", "'")
    if len(tok) >= 2 and tok[0] == tok[-1] == '"':
        inner = tok[1:-1]
        return None if ("$" in inner or "`" in inner) else inner
    if "$" in tok or tok.startswith("@") or "`" in tok:
        return None
    return tok


def classify_ps(toks: Sequence[str]) -> Result:
    """Classify an Invoke-RestMethod-style PowerShell statement (tokens are raw text)."""
    raw = " ".join(toks)
    graph_default = toks[0].lower() == "invoke-mggraphrequest"
    method_tok: str | None = None
    uri_tok: str | None = None
    body = override = opaque = False
    i = 1
    while i < len(toks):
        t = toks[i]
        tl = t.lower()
        if tl.startswith("-") and len(tl) > 1 and not tl[1].isdigit():
            pname, colon, inline = t.partition(":")
            pname = pname.lower()
            if pname in _PS_FLAGS:
                i += 1
                continue
            if colon:
                val, step = inline, 1
            elif i + 1 < len(toks):
                val, step = toks[i + 1], 2
            else:
                return make_unknown(f"{pname} without a value", adapter=NAME, canonical=raw)
            if pname in ("-method", "-custommethod"):
                if method_tok is not None:
                    return make_unknown(
                        "method is given more than once", adapter=NAME, canonical=raw
                    )
                method_tok = val
            elif pname == "-uri":
                if uri_tok is not None:
                    return make_unknown("URI is given more than once", adapter=NAME, canonical=raw)
                uri_tok = val
            elif pname in ("-body", "-infile", "-form", "-inputfilepath"):
                body = True
            elif pname == "-headers":
                low = val.lower()
                if _ps_literal(val) is None:
                    opaque = True
                elif any(h in low for h in OVERRIDE_HEADERS | ROUTING_HEADERS):
                    override = True
            elif pname not in _PS_VALUED:
                return make_unknown(
                    f"unsupported {toks[0]} parameter {pname}", adapter=NAME, canonical=raw
                )
            i += step
            continue
        if uri_tok is None:
            uri_tok = t
            i += 1
            continue
        return make_unknown(
            f"unexpected positional argument to {toks[0]}", adapter=NAME, canonical=raw
        )

    if uri_tok is None:
        return make_unknown("no -Uri", adapter=NAME, canonical=raw)
    uri = _ps_literal(uri_tok)
    if uri is None:
        return make_unknown("URI is evaluated at run time", adapter=NAME, canonical=raw)
    if method_tok is None:
        method = "GET"
    else:
        m = _ps_literal(method_tok)
        if m is None or not _METHOD_RE.match(m):
            return make_unknown("HTTP method is evaluated at run time", adapter=NAME, canonical=raw)
        method = "GET" if m.lower() == "default" else m.upper()
    if graph_default and "://" not in uri:
        uri = "https://graph.microsoft.com/" + uri.lstrip("/")
    return http_result(
        NAME, method, [uri], body=body, override=override, opaque_header=opaque, raw=raw
    )


# ---------------------------------------------------------------- opaque text


def scan_text(text: str) -> list[Result]:
    """Admin URLs in opaque text. Results are always unknown-admin."""
    out: list[Result] = []
    for line in text.splitlines():
        methods = sorted({m.upper() for m in _METHOD_SCAN_RE.findall(line)}) or ["UNKNOWN"]
        for m in _URL_SCAN_RE.finditer(line):
            norm = normalize_url(m.group(0))
            if norm is None or not is_admin_host(norm[0]):
                continue
            host, path = norm
            for method in methods:
                out.append(
                    make_unknown(
                        "admin URL in text that is not parsed",
                        adapter=NAME,
                        verb=method,
                        canonical=f"http {method} {host}{path}",
                    )
                )
    return out


__all__ = [
    "ADMIN_HOSTS",
    "NAME",
    "classify",
    "classify_ps",
    "http_result",
    "is_admin_host",
    "matches",
    "mentions_admin_host",
    "normalize_url",
    "scan_text",
]
