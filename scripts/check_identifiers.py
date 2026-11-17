#!/usr/bin/env python3
"""Pre-publication identifier scanner for a cab-of-one checkout (stdlib only, Python 3.11+).

Generic rules (public, used in CI): GUIDs, IPv4 addresses (private, CGNAT, public and other
reserved ranges), e-mail addresses, absolute local home paths, long Discord-style numeric IDs
and ``*.onmicrosoft.com`` tenants other than Contoso. Private rule (local only): with
``--denylist FILE`` every non-empty line of FILE is a literal term matched case-insensitively.

Reports carry rule, path and line only. They never contain the matched text, a source
snippet, a denylist term, a hash of a term or the denylist file name. A path that itself
matches a rule is shown as ``[redacted path #N]`` (N is its 1-based position in the sorted
candidate list).

Candidate sets
  default         tracked + untracked files that Git does not ignore. Works before the first
                  commit. Files are read from the working tree; symlinks are never followed.
                  Tracked files that match an ignore rule and private paths (``.local/``,
                  ``.build-inputs/``, ``CLAUDE.md``...) are errors and are never read.
  --rev REV       the tree of a commit, read from Git objects (repeatable). With
                  ``--check-commit-metadata`` also the commit message and the author and
                  committer identity (which must be a GitHub noreply address).
  --ref REF       also scan a pushed ref name (repeatable, ``refs/...`` only). Hits are
                  reported as ``[pushed ref #N]``; invalid refs are a fatal ``ref_invalid``.
  --export DIR    copy the candidate (default set, or exactly one ``--rev``) into a new DIR
                  outside the repository, for other scanners such as gitleaks. No rules run.

gitleaks fingerprint files (``.gitleaksignore``, any case) are refused in every mode: as a
candidate or commit path at any depth, and as any root directory entry even when Git-ignored,
a symlink or dangling. They are never read, followed or exported (code ``suppression_file``).

Narrow exceptions live in ``EXCEPTIONS``: one rule, one exact repo-relative path, one exact
value. Each is a fictional fixture or a reviewed, deliberately public contact. There is no
baseline file, no domain-wide allowance and no path-wide suppression.

Exit codes: 0 clean, 1 findings or file errors, 2 usage, Git, bound or denylist error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILES = 20_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PATH_CHARS = 1024
MAX_DENYLIST_BYTES = 256 * 1024
MAX_DENYLIST_TERMS = 5_000
MAX_REVS = 1_000
MAX_REV_CHARS = 256
MAX_COMMIT_BYTES = 256 * 1024
MAX_REPORTED = 1_000
MAX_REFS = 64
MAX_REF_CHARS = 1024
GIT_TIMEOUT_S = 300

PRIVATE_DIRS = (".local/", ".build-inputs/")
PRIVATE_FILES = frozenset({"CLAUDE.md", "AGENTS.md", ".claude/settings.local.json"})
# gitleaks always loads <scan source>/.gitleaksignore in addition to --gitleaks-ignore-path
# (v8.30.1 cmd/root.go), so a fingerprint file anywhere in the candidate or at the work-tree
# root would silently suppress findings. Such files are refused, matched without case, and
# never read or exported.
SUPPRESSION_NAME = ".gitleaksignore"
NOREPLY_SUFFIX = "@users.noreply.github.com"
TRAILER_PREFIXES = ("Signed-off-by:", "Co-authored-by:")

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_HEX_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
# Characters and sequences that git check-ref-format rejects, plus control characters.
_REF_BAD = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{|//|/\.|\.lock(?:/|$)")

# --- generic rules ----------------------------------------------------------------------

GUID_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
    r"-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
# Documentation placeholders of the form 00000000-0000-0000-0000-xxxxxxxxxxxx: the first 20
# hex digits are zero, which a generated tenant, object or subscription ID never has.
PLACEHOLDER_GUID_RE = re.compile(r"(?:0{8}-0{4}-0{4}-0{4}-)[0-9A-Fa-f]{12}")
IPV4_RE = re.compile(
    r"(?<![0-9A-Za-z_.])([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})"
    r"(?![0-9A-Za-z_]|\.[0-9])"
)
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8})(?![A-Za-z0-9-])"
)
LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.~-])/(?:Users|home)/[A-Za-z0-9._-]+"
    r"|(?<![A-Za-z0-9_])[A-Za-z]:(?:\\{1,2}|/)Users(?:\\{1,2}|/)[A-Za-z0-9._-]+"
)
LONG_ID_RE = re.compile(r"(?<![0-9A-Za-z])[0-9]{17,20}(?![0-9A-Za-z])")
ONMICROSOFT_RE = re.compile(
    r"(?<![A-Za-z0-9.-])((?:[A-Za-z0-9-]{1,63}\.){1,4})onmicrosoft\.com(?![A-Za-z0-9-])",
    re.IGNORECASE | re.ASCII,
)
CONTOSO_TENANT_LABELS = frozenset({("contoso",), ("contoso", "mail")})

# Networks are built from integers so this file does not match its own IPv4 rule.
_PRIVATE_NETS = tuple(
    ipaddress.IPv4Network(net)
    for net in ((0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16))  # RFC 1918
)
_CGNAT_NET = ipaddress.IPv4Network((0x64400000, 10))  # RFC 6598 shared address space

# RFC 2606 / RFC 6761 reserved names: an address under them cannot belong to anyone.
_RESERVED_TLDS = ("example", "invalid", "test", "localhost")
_RESERVED_SLDS = ("example.com", "example.net", "example.org")


def _j(*parts: str) -> str:
    return "".join(parts)


# Narrow exceptions: (rule, exact repo-relative path, exact matched value). Values are written
# in pieces so this table does not match its own rules; they are compared whole and
# case-sensitively. Every entry is either a fictional fixture or a reviewed, deliberately
# public contact, and needs a review note saying which and why.
EXCEPTIONS: frozenset[tuple[str, str, str]] = frozenset(
    {
        # Not fictional: the public code-of-conduct reporting address, explicitly provided by
        # the maintainer for publication. Allowed only in this exact file; the same address
        # anywhere else, or any other address in this file, is still a finding.
        ("email", "CODE_OF_CONDUCT.md", _j("bay.forest3307", "@", "eagereverest", ".com")),
        # Fictional Claude Code session IDs in hook-event fixtures.
        ("guid", "tests/test_hookevents.py", _j("5e2b41ed-28d8-4bbd", "-aa16-f6c9a90088c4")),
        ("guid", "tests/test_hookevents.py", _j("6241ac13-e01c-436b", "-bf54-755193937b55")),
        # Fictional session IDs in transcript fixtures.
        ("guid", "tests/test_transcripts.py", _j("0b6c1d2e-1111-4a4a", "-9b9b-000000000001")),
        ("guid", "tests/test_transcripts.py", _j("0b6c1d2e-1111-4a4a", "-9b9b-000000000099")),
        # RFC 5737 documentation address (TEST-NET-3) in a classifier test.
        ("ipv4-reserved", "tests/test_classify.py", _j("203.0", ".113.7")),
        # Fictional home folders in fixtures and path-scrubbing tests.
        ("local-path", "tests/test_setup_cli.py", _j("/ho", "me/contoso")),
        ("local-path", "tests/test_terminal.py", _j("/ho", "me/x")),
        ("local-path", "tests/test_evals.py", _j("/Us", "ers/someone")),
    }
)


class FatalError(Exception):
    """A usage, Git, bound or denylist problem. Only the fixed code is ever printed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Hit:
    rule: str
    line: int
    value: str  # compared against EXCEPTIONS; never printed


def ipv4_rule(octets: list[int]) -> str:
    addr = ipaddress.IPv4Address(bytes(octets))
    if any(addr in net for net in _PRIVATE_NETS):
        return "ipv4-private"
    if addr in _CGNAT_NET:
        return "ipv4-cgnat"
    if addr.is_global:
        return "ipv4-public"
    return "ipv4-reserved"


def email_domain_allowed(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    labels = d.split(".")
    if labels[-1] in _RESERVED_TLDS:
        return True
    if any(d == s or d.endswith("." + s) for s in _RESERVED_SLDS):
        return True
    return labels[-2:] == ["onmicrosoft", "com"] and tuple(labels[:-2]) in CONTOSO_TENANT_LABELS


def scan_line(line: str, number: int, *, trailer: bool = False) -> Iterator[Hit]:
    """Generic rules on one line. ``trailer`` allows noreply e-mails in commit trailers."""
    for m in GUID_RE.finditer(line):
        if not PLACEHOLDER_GUID_RE.fullmatch(m.group(0)):
            yield Hit("guid", number, m.group(0))
    for m in IPV4_RE.finditer(line):
        octets = [int(g) for g in m.groups()]
        if all(o <= 255 for o in octets):
            yield Hit(ipv4_rule(octets), number, m.group(0))
    for m in EMAIL_RE.finditer(line):
        domain = m.group(1)
        tld = domain.rstrip(".").rsplit(".", 1)[-1]
        if not (tld.isascii() and tld.isalpha() and len(tld) >= 2):
            continue
        if email_domain_allowed(domain):
            continue
        if trailer and m.group(0).lower().endswith(NOREPLY_SUFFIX):
            continue
        yield Hit("email", number, m.group(0))
    for m in LOCAL_PATH_RE.finditer(line):
        yield Hit("local-path", number, m.group(0))
    for m in LONG_ID_RE.finditer(line):
        yield Hit("long-numeric-id", number, m.group(0))
    for m in ONMICROSOFT_RE.finditer(line):
        labels = tuple(m.group(1).lower().rstrip(".").split("."))
        if labels not in CONTOSO_TENANT_LABELS:
            yield Hit("onmicrosoft-tenant", number, m.group(0))


def denylist_hit(text: str, terms: tuple[str, ...]) -> bool:
    low = text.casefold()
    return any(term in low for term in terms)


def scan_text(text: str, terms: tuple[str, ...]) -> list[Hit]:
    hits: list[Hit] = []
    for number, line in enumerate(text.split("\n"), start=1):
        if line.endswith("\r"):
            line = line[:-1]
        hits.extend(scan_line(line, number))
        if terms and denylist_hit(line, terms):
            hits.append(Hit("private-denylist", number, ""))
    return hits


def decode_candidate(data: bytes) -> str:
    """UTF-8 text or a fixed error code via FileProblem."""
    if b"\0" in data:
        raise FileProblem("binary")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise FileProblem("invalid_utf8") from None


class FileProblem(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def is_private_path(rel: str) -> bool:
    return rel in PRIVATE_FILES or rel.startswith(PRIVATE_DIRS)


def is_suppression_path(rel: str) -> bool:
    return rel.rsplit("/", 1)[-1].casefold() == SUPPRESSION_NAME


def root_suppression_present(root: Path) -> bool:
    """A root entry named .gitleaksignore of any type (ignored, symlink, dangling, dir).

    Only directory entry names are listed; nothing is followed, opened or read."""
    try:
        names = os.listdir(root)
    except OSError:
        raise FatalError("root_unreadable") from None
    return any(name.casefold() == SUPPRESSION_NAME for name in names)


def is_within(child: str, parent: str) -> bool:
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:
        return False


# --- Git ----------------------------------------------------------------------------------


def git_env() -> dict[str, str]:
    """Inherited GIT_* variables (GIT_DIR from a hook, injected config) are dropped."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    return env


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    exe = shutil.which("git")
    if exe is None:
        raise FatalError("git_not_found")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [exe, "-c", "core.fsmonitor=false", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=git_env(),
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise FatalError("git_failed") from None
    if check and proc.returncode != 0:
        raise FatalError("git_failed")
    return proc


def resolve_root(arg: str | None) -> Path:
    start = Path(os.path.abspath(arg)) if arg else Path.cwd()
    if arg:
        try:
            st = os.lstat(start)
        except OSError:
            raise FatalError("root_missing") from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise FatalError("root_not_directory")
    out = git(start, "rev-parse", "--show-toplevel").stdout.rstrip(b"\n")
    if not out:
        raise FatalError("root_not_worktree")
    real = os.path.realpath(os.fsdecode(out))
    if arg and real != os.path.realpath(start):
        raise FatalError("root_not_toplevel")
    return Path(real)


def split_z(data: bytes) -> list[bytes]:
    return [item for item in data.split(b"\0") if item]


def resolve_commit(root: Path, rev: str) -> str:
    if not rev or len(rev) > MAX_REV_CHARS or rev.startswith("-"):
        raise FatalError("rev_invalid")
    if any(ch in rev for ch in "\0\n\r") or not rev.isprintable():
        raise FatalError("rev_invalid")
    proc = git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}", check=False)
    sha = proc.stdout.decode("ascii", "replace").strip()
    if proc.returncode != 0 or not _HEX_OID.fullmatch(sha):
        raise FatalError("rev_unknown")
    return sha


def validate_ref(ref: str) -> str:
    """A full Git ref name (``refs/...``). Anything else is a fixed error; never echoed."""
    if not 5 < len(ref) <= MAX_REF_CHARS or not ref.startswith("refs/"):
        raise FatalError("ref_invalid")
    if ref.endswith(("/", ".")) or _REF_BAD.search(ref) or not ref.isprintable():
        raise FatalError("ref_invalid")
    return ref


def read_object(root: Path, oid: str, kind: str, limit: int) -> bytes:
    if not _HEX_OID.fullmatch(oid):
        raise FileProblem("object_invalid")
    size_out = git(root, "cat-file", "-s", oid, check=False)
    try:
        size = int(size_out.stdout.strip())
    except ValueError:
        raise FileProblem("unreadable") from None
    if size_out.returncode != 0:
        raise FileProblem("unreadable")
    if size > limit:
        raise FileProblem("too_large")
    proc = git(root, "cat-file", kind, oid, check=False)
    if proc.returncode != 0 or len(proc.stdout) != size:
        raise FileProblem("unreadable")
    return proc.stdout


def read_worktree_file(root: Path, rel: str) -> bytes:
    """Read ``root/rel`` without following a symlink in any component."""
    parts = rel.split("/")
    if rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise FileProblem("path_invalid")
    cur = root
    st: os.stat_result | None = None
    for index, part in enumerate(parts):
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            raise FileProblem("missing") from None
        except OSError:
            raise FileProblem("unreadable") from None
        if stat.S_ISLNK(st.st_mode):
            raise FileProblem("symlink")
        if index < len(parts) - 1 and not stat.S_ISDIR(st.st_mode):
            raise FileProblem("not_regular_file")
    assert st is not None
    if not stat.S_ISREG(st.st_mode):
        raise FileProblem("not_regular_file")
    if st.st_size > MAX_FILE_BYTES:
        raise FileProblem("too_large")
    try:
        fd = os.open(cur, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK)
    except OSError:
        raise FileProblem("unreadable") from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise FileProblem("changed_during_scan")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise FileProblem("unreadable") from None
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_FILE_BYTES:
        raise FileProblem("too_large")
    return data


# --- denylist -----------------------------------------------------------------------------


def _stat_key(st: os.stat_result) -> tuple[int, int, int, int, int]:
    """Identity and change markers; any difference means the file changed under us."""
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def load_denylist(path_arg: str, root: Path) -> tuple[str, ...]:
    """Private literal terms. Every failure is a fixed code; no path or content is shown."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise FatalError("denylist_refused_in_ci")
    path = os.path.abspath(path_arg)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise FatalError("denylist_missing") from None
    except OSError:
        raise FatalError("denylist_unreadable") from None
    if stat.S_ISLNK(st.st_mode):
        raise FatalError("denylist_symlink")
    if not stat.S_ISREG(st.st_mode):
        raise FatalError("denylist_not_regular_file")
    if is_within(os.path.realpath(path), str(root)):
        raise FatalError("denylist_inside_repository")
    if st.st_size > MAX_DENYLIST_BYTES:
        raise FatalError("denylist_too_large")
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK)
    except OSError:
        raise FatalError("denylist_unreadable") from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or _stat_key(fst) != _stat_key(st):
            raise FatalError("denylist_changed")
        # os.read may return fewer bytes than asked; loop to EOF with a fixed upper bound.
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_DENYLIST_BYTES:
            chunk = os.read(fd, min(MAX_DENYLIST_BYTES + 1 - total, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
    except OSError:
        raise FatalError("denylist_unreadable") from None
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_DENYLIST_BYTES:
        raise FatalError("denylist_too_large")
    if _stat_key(after) != _stat_key(fst):
        raise FatalError("denylist_changed")
    if len(data) != fst.st_size:
        raise FatalError("denylist_unreadable")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FatalError("denylist_not_utf8") from None
    terms: dict[str, None] = {}
    for line in text.split("\n"):
        term = line.strip()
        if term:
            terms[term.casefold()] = None
    if not terms:
        raise FatalError("denylist_empty")
    if len(terms) > MAX_DENYLIST_TERMS:
        raise FatalError("denylist_too_many_terms")
    return tuple(terms)


# --- report -------------------------------------------------------------------------------


@dataclass
class Report:
    files: int = 0
    commits: int = 0
    findings: list[dict[str, object]] = field(default_factory=list)
    errors: list[dict[str, object]] = field(default_factory=list)
    finding_count: int = 0
    error_count: int = 0

    def finding(self, rule: str, path: str, line: int, commit: str | None = None) -> None:
        self.finding_count += 1
        if len(self.findings) < MAX_REPORTED:
            item: dict[str, object] = {"rule": rule, "path": path, "line": line}
            if commit:
                item["commit"] = commit
            self.findings.append(item)

    def error(self, code: str, path: str, commit: str | None = None) -> None:
        self.error_count += 1
        if len(self.errors) < MAX_REPORTED:
            item: dict[str, object] = {"code": code, "path": path}
            if commit:
                item["commit"] = commit
            self.errors.append(item)

    @property
    def clean(self) -> bool:
        return self.finding_count == 0 and self.error_count == 0

    def to_json(self) -> dict[str, object]:
        return {
            "schema": 1,
            "result": "clean" if self.clean else "blocked",
            "files": self.files,
            "commits": self.commits,
            "finding_count": self.finding_count,
            "error_count": self.error_count,
            "findings": self.findings,
            "errors": self.errors,
            "truncated": len(self.findings) < self.finding_count
            or len(self.errors) < self.error_count,
        }


# --- scanner ------------------------------------------------------------------------------


@dataclass
class Entry:
    """One candidate file: a working-tree path or a blob in a commit tree."""

    rel: str
    oid: str | None = None  # blob id in rev mode
    problem: str | None = None  # known before reading (symlink, submodule, ...)


class Scanner:
    def __init__(self, root: Path, terms: tuple[str, ...], report: Report) -> None:
        self.root = root
        self.terms = terms
        self.report = report
        self.total_bytes = 0
        self.blob_cache: dict[str, list[Hit] | str] = {}

    # candidate sets

    def worktree_entries(self) -> list[Entry]:
        listed = split_z(
            git(self.root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout
        )
        ignored = set(
            split_z(
                git(
                    self.root, "ls-files", "-z", "--cached", "--ignored", "--exclude-standard"
                ).stdout
            )
        )
        entries = self._decode_paths(sorted(set(listed)))
        for entry, raw in entries:
            if entry.problem is None and raw in ignored:
                entry.problem = "tracked_ignored"
        return [e for e, _ in entries]

    def rev_entries(self, sha: str) -> list[Entry]:
        out = git(self.root, "ls-tree", "-r", "-z", "--full-tree", sha).stdout
        records: list[tuple[bytes, str, str, str]] = []
        for rec in split_z(out):
            meta, sep, raw_path = rec.partition(b"\t")
            fields = meta.decode("ascii", "replace").split(" ")
            if not sep or len(fields) != 3:
                raise FatalError("git_failed")
            records.append((raw_path, fields[0], fields[1], fields[2]))
        records.sort(key=lambda r: r[0])
        entries = self._decode_paths([r[0] for r in records])
        for (entry, _raw), (_p, mode, kind, oid) in zip(entries, records, strict=True):
            if entry.problem is not None:
                continue
            if mode == "120000":
                entry.problem = "symlink"
            elif mode == "160000" or kind != "blob":
                entry.problem = "not_regular_file"
            else:
                entry.oid = oid
        return entries_only(entries)

    def _decode_paths(self, raws: list[bytes]) -> list[tuple[Entry, bytes]]:
        if len(raws) > MAX_FILES:
            raise FatalError("too_many_files")
        out: list[tuple[Entry, bytes]] = []
        for index, raw in enumerate(raws, start=1):
            try:
                rel = raw.decode("utf-8")
            except UnicodeDecodeError:
                out.append((Entry(f"[undecodable path #{index}]", problem="path_not_utf8"), raw))
                continue
            entry = Entry(rel)
            # Git object trees may be malformed even when a normal checkout would reject
            # them. Reject traversal before either blob reads or candidate export.
            if rel.startswith("/") or any(p in ("", ".", "..") for p in rel.split("/")):
                entry.problem = "path_invalid"
            elif len(rel) > MAX_PATH_CHARS:
                entry.problem = "path_too_long"
            elif is_suppression_path(rel):
                entry.problem = "suppression_file"
            elif is_private_path(rel):
                entry.problem = "private_path"
            out.append((entry, raw))
        return out

    # reading

    def read(self, entry: Entry) -> bytes:
        if entry.problem is not None:
            raise FileProblem(entry.problem)
        if entry.oid is not None:
            data = read_object(self.root, entry.oid, "blob", MAX_FILE_BYTES)
        else:
            data = read_worktree_file(self.root, entry.rel)
        self.total_bytes += len(data)
        if self.total_bytes > MAX_TOTAL_BYTES:
            raise FatalError("candidate_too_large")
        return data

    def content_hits(self, entry: Entry) -> list[Hit]:
        if entry.oid is not None and entry.oid in self.blob_cache:
            cached = self.blob_cache[entry.oid]
            if isinstance(cached, str):
                raise FileProblem(cached)
            return cached
        try:
            hits = scan_text(decode_candidate(self.read(entry)), self.terms)
        except FileProblem as exc:
            if entry.oid is not None:
                self.blob_cache[entry.oid] = exc.code
            raise
        if entry.oid is not None:
            self.blob_cache[entry.oid] = hits
        return hits

    # scanning

    def scan_entries(self, entries: list[Entry], commit: str | None = None) -> None:
        for index, entry in enumerate(entries, start=1):
            self.report.files += 1
            path_hits = self._path_hits(entry.rel)
            shown = f"[redacted path #{index}]" if path_hits else entry.rel
            for hit in path_hits:
                self.report.finding(hit.rule, shown, 0, commit)
            if entry.problem == "path_not_utf8":
                self.report.error(entry.problem, entry.rel, commit)
                continue
            try:
                hits = self.content_hits(entry)
            except FileProblem as exc:
                self.report.error(exc.code, shown, commit)
                continue
            for hit in hits:
                if (hit.rule, entry.rel, hit.value) in EXCEPTIONS:
                    continue
                self.report.finding(hit.rule, shown, hit.line, commit)

    def scan_refs(self, refs: list[str]) -> None:
        """Ref names are published by a push; report them only as ``[pushed ref #N]``."""
        for index, ref in enumerate(refs, start=1):
            label = f"[pushed ref #{index}]"
            for hit in scan_line(ref, 0):
                self.report.finding(hit.rule, label, 0)
            if self.terms and denylist_hit(ref, self.terms):
                self.report.finding("private-denylist", label, 0)

    def _path_hits(self, rel: str) -> list[Hit]:
        if rel.startswith("[undecodable path"):
            return []
        hits = [h for h in scan_line(rel, 0) if (h.rule, rel, h.value) not in EXCEPTIONS]
        if self.terms and denylist_hit(rel, self.terms):
            hits.append(Hit("private-denylist", 0, ""))
        return hits

    def scan_commit_metadata(self, sha: str) -> None:
        label = sha[:12]
        try:
            raw = read_object(self.root, sha, "commit", MAX_COMMIT_BYTES)
        except FileProblem as exc:
            self.report.error(exc.code, "commit object", label)
            return
        header, _sep, body = raw.partition(b"\n\n")
        for line in header.split(b"\n"):
            for field_name in ("author", "committer"):
                if not line.startswith(field_name.encode() + b" "):
                    continue
                text = line.decode("utf-8", "replace")
                m = re.fullmatch(rf"{field_name} (.*) <([^<>]*)> [0-9]+ [+-][0-9]{{4}}", text)
                if m is None:
                    self.report.error("identity_unparsed", f"commit {field_name}", label)
                    continue
                name, email = m.group(1), m.group(2)
                if not email.lower().endswith(NOREPLY_SUFFIX):
                    self.report.finding(
                        "commit-identity-not-noreply", f"commit {field_name}", 0, label
                    )
                if self.terms and (
                    denylist_hit(name, self.terms) or denylist_hit(email, self.terms)
                ):
                    self.report.finding("private-denylist", f"commit {field_name}", 0, label)
        try:
            message = decode_candidate(body)
        except FileProblem as exc:
            self.report.error(exc.code, "commit message", label)
            return
        for number, line in enumerate(message.split("\n"), start=1):
            line = line.rstrip("\r")
            for hit in scan_line(line, number, trailer=line.startswith(TRAILER_PREFIXES)):
                self.report.finding(hit.rule, "commit message", hit.line, label)
            if self.terms and denylist_hit(line, self.terms):
                self.report.finding("private-denylist", "commit message", number, label)


def entries_only(pairs: list[tuple[Entry, bytes]]) -> list[Entry]:
    return [entry for entry, _ in pairs]


# --- export -------------------------------------------------------------------------------


def export_candidate(scanner: Scanner, entries: list[Entry], dest_arg: str) -> None:
    """Copy readable candidate files into a new directory outside the repository.

    Everything is read and checked first; nothing is written if any entry has a problem.
    """
    dest = Path(os.path.abspath(dest_arg))
    try:
        parent_st = os.lstat(dest.parent)
    except OSError:
        raise FatalError("export_parent_missing") from None
    if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode):
        raise FatalError("export_parent_not_directory")
    if os.path.lexists(dest):
        raise FatalError("export_target_exists")
    real_dest = os.path.join(os.path.realpath(dest.parent), dest.name)
    if is_within(real_dest, str(scanner.root)):
        raise FatalError("export_inside_repository")
    files: list[tuple[str, bytes]] = []
    for index, entry in enumerate(entries, start=1):
        scanner.report.files += 1
        try:
            data = scanner.read(entry)
            decode_candidate(data)
        except FileProblem as exc:
            shown = f"[redacted path #{index}]" if scanner._path_hits(entry.rel) else entry.rel
            scanner.report.error(exc.code, shown)
            continue
        files.append((entry.rel, data))
    if not scanner.report.clean:
        return
    os.mkdir(real_dest, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
    for rel, data in files:
        target = Path(real_dest).joinpath(*rel.split("/"))
        os.makedirs(target.parent, mode=0o700, exist_ok=True)
        fd = os.open(target, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)


# --- CLI ----------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_identifiers.py",
        description="Scan the publication candidate for identifiers (rule/path/line only).",
        allow_abbrev=False,
    )
    parser.add_argument("--root", help="Git work tree top level (default: from the cwd)")
    parser.add_argument("--rev", action="append", default=[], help="scan this commit's tree")
    parser.add_argument(
        "--check-commit-metadata",
        action="store_true",
        help="with --rev: also scan messages; identities must be GitHub noreply",
    )
    parser.add_argument(
        "--ref", action="append", default=[], help="also scan this pushed ref name (repeatable)"
    )
    parser.add_argument("--denylist", help="private literal terms, outside the repository")
    parser.add_argument("--export", metavar="DIR", help="copy the candidate into new DIR")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def run(args: argparse.Namespace, report: Report) -> None:
    if args.export and args.denylist:
        raise FatalError("export_with_denylist")
    if args.export and (len(args.rev) > 1 or args.check_commit_metadata or args.ref):
        raise FatalError("export_needs_single_candidate")
    if args.check_commit_metadata and not args.rev:
        raise FatalError("metadata_needs_rev")
    if len(args.rev) > MAX_REVS:
        raise FatalError("too_many_revs")
    if len(args.ref) > MAX_REFS:
        raise FatalError("too_many_refs")
    refs = [validate_ref(ref) for ref in args.ref]
    root = resolve_root(args.root)
    terms = load_denylist(args.denylist, root) if args.denylist is not None else ()
    scanner = Scanner(root, terms, report)
    if root_suppression_present(root):
        report.error("suppression_file", SUPPRESSION_NAME)
    scanner.scan_refs(refs)
    shas = list(dict.fromkeys(resolve_commit(root, rev) for rev in args.rev))
    if args.export:
        entries = scanner.rev_entries(shas[0]) if shas else scanner.worktree_entries()
        export_candidate(scanner, entries, args.export)
        return
    if not shas:
        scanner.scan_entries(scanner.worktree_entries())
        return
    for sha in shas:
        report.commits += 1
        scanner.scan_entries(scanner.rev_entries(sha), commit=sha[:12])
        if args.check_commit_metadata:
            scanner.scan_commit_metadata(sha)


def emit(report: Report, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.to_json(), sort_keys=True, ensure_ascii=True))
        return
    for item in report.findings:
        where = f" commit={item['commit']}" if "commit" in item else ""
        print(
            f"identifier-scan: finding rule={item['rule']}{where} "
            f"path={json.dumps(item['path'], ensure_ascii=True)} line={item['line']}"
        )
    for item in report.errors:
        where = f" commit={item['commit']}" if "commit" in item else ""
        print(
            f"identifier-scan: error code={item['code']}{where} "
            f"path={json.dumps(item['path'], ensure_ascii=True)}"
        )
    if report.finding_count > len(report.findings) or report.error_count > len(report.errors):
        print(f"identifier-scan: output truncated at {MAX_REPORTED} items per kind")
    state = "clean" if report.clean else "blocked"
    print(
        f"identifier-scan: {state} files={report.files} commits={report.commits} "
        f"findings={report.finding_count} errors={report.error_count}"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = Report()
    try:
        run(args, report)
    except FatalError as exc:
        if args.json:
            print(json.dumps({"schema": 1, "result": "fatal", "code": exc.code}, sort_keys=True))
        else:
            print(f"identifier-scan: fatal code={exc.code}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - never print a traceback that may quote data
        code = f"internal_error:{type(exc).__name__}"
        if args.json:
            print(json.dumps({"schema": 1, "result": "fatal", "code": code}, sort_keys=True))
        else:
            print(f"identifier-scan: fatal code={code}", file=sys.stderr)
        return 2
    emit(report, args.json)
    return 0 if report.clean else 1


if __name__ == "__main__":
    sys.exit(main())
