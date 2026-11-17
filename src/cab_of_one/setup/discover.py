"""Read-only, local-only discovery for the setup generator (S10, DESIGN §10-4-1 step 1).

``discover(project_root, *, finder=None)`` walks one explicit project root and returns an
immutable ``Discovery``. It never connects to a tenant, starts a process or uses the
network. It records only project-relative paths, line numbers and fixed surface codes:
no file content, no matched text, no MCP configuration values, no CLI install paths.

Walk rules
- The root must be an absolute, existing, non-symlink directory. The walk uses the
  resolved root and never follows a symlink (directory or file); symlinks are counted.
- Skipped directories: ``.git``, ``.cab`` (with ``staged``), ``.claude``, dependency and
  cache folders (``SKIP_DIRS``). Depth, entry, file and size limits bound the work; a
  hit limit is reported in ``limits_hit``, never silently.
- Only script and document suffixes (``SCAN_SUFFIXES``) are opened, with O_NOFOLLOW, as
  regular single-link files at most ``MAX_FILE_BYTES``. A NUL byte marks a binary file,
  which is skipped.
- Credential-like files (``.pfx``, ``.pem``, ``.env`` ...; anything under a ``secrets``
  folder) are recorded as *path candidates only* and are never opened.
- ``.mcp.json`` at the root is parsed strictly; only server *names* that match the
  runtime server pattern are kept.
- CLI availability comes only from an injected ``finder(name) -> bool``. Without one the
  status is ``unchecked``.

``write_discovery(discovery, project_root)`` is the only writer: it atomically replaces
``<root>/.cab/setup/discovery.json`` and refuses symlinked or non-directory parents.

Inferred profile values carry ``source`` ``discovered`` or ``default``. Nothing is ever
labelled as a person's answer; answers come from the interview.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ..runtime import fsutil
from ..runtime.schema import Invalid, canonical_bytes, strict_json

__all__ = [
    "CLI_NAMES",
    "SCAN_SUFFIXES",
    "SKIP_DIRS",
    "SURFACE_CODES",
    "CliStatus",
    "Discovery",
    "DiscoveryError",
    "Evidence",
    "Inferred",
    "discover",
    "to_json_bytes",
    "write_discovery",
]

SCHEMA_VERSION = 1
MAX_DEPTH = 12
MAX_ENTRIES = 20_000
MAX_FILES = 2_000
MAX_FILE_BYTES = 512 * 1024
MAX_LINE_CHARS = 4096
MAX_EVIDENCE = 1_000
MAX_CANDIDATES = 200
MAX_MCP_BYTES = 256 * 1024
MAX_MCP_SERVERS = 64
MAX_REL_CHARS = 512

CLI_NAMES = ("pwsh", "az", "gam", "aws")
SKIP_DIRS = frozenset(
    {
        ".git", ".cab", ".claude", ".hg", ".svn", "node_modules", ".venv", "venv",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist",
        "build", "staged",
    }
)  # fmt: skip
SCAN_SUFFIXES = frozenset(
    {
        ".ps1", ".psm1", ".psd1", ".sh", ".bash", ".zsh", ".py", ".md", ".markdown",
        ".txt", ".rst", ".adoc",
    }
)  # fmt: skip
_CREDENTIAL_SUFFIXES = frozenset(
    {".pfx", ".p12", ".pem", ".key", ".cer", ".crt", ".der", ".jks", ".keystore", ".kdbx",
     ".ppk", ".asc", ".gpg", ".publishsettings"}
)  # fmt: skip
_CREDENTIAL_NAMES = re.compile(
    r"(?i)^(?:\.env(?:\..*)?|.*\.env|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|\.netrc|\.npmrc"
    r"|\.pypirc|credentials(?:\..*)?|.*secret.*|.*password.*|.*token.*|clientsecret.*)$"
)
_CREDENTIAL_DIRS = frozenset({"secrets", "secret", ".secrets", "credentials", ".ssh", ".aws"})

# (code, pattern). Patterns run on one bounded line; only the code and line are kept.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ps_connect_mggraph", re.compile(r"(?i)\bConnect-MgGraph\b")),
    ("ps_mg_cmdlet", re.compile(r"(?i)\b(?:Get|New|Set|Update|Remove|Invoke)-Mg[A-Z]\w*")),
    ("ps_connect_exchange", re.compile(r"(?i)\bConnect-ExchangeOnline\b")),
    ("ps_exchange_cmdlet", re.compile(
        r"(?i)\b(?:Set|New|Remove|Enable|Disable)-(?:Mailbox|TransportRule|InboundConnector"
        r"|OutboundConnector|DistributionGroup|MailboxPermission)\b")),
    ("ps_intune_cmdlet", re.compile(
        r"(?i)\b(?:Get|New|Set|Update|Remove|Invoke)-MgDeviceManagement\w*"
        r"|\bInvoke-MgRetireDeviceManagementManagedDevice\b|\bIntune\w*Device\b")),
    ("ps_connect_azaccount", re.compile(r"(?i)\bConnect-AzAccount\b")),
    ("ps_az_cmdlet", re.compile(r"(?i)\b(?:Get|New|Set|Remove|Update)-Az[A-Z]\w*")),
    ("az_cli", re.compile(r"(?:^|[\s;|&(`$])az\s+[a-z][a-z-]*")),
    ("graph_http", re.compile(r"(?i)graph\.microsoft\.com")),
    ("ps_connect_sharepoint_teams", re.compile(
        r"(?i)\bConnect-(?:PnPOnline|SPOService|MicrosoftTeams)\b")),
    ("gam_cli", re.compile(r"(?:^|[\s;|&(`$])gam\s+[a-z]")),
    ("aws_cli", re.compile(r"(?:^|[\s;|&(`$])aws\s+[a-z]")),
    ("ps_ad_cmdlet", re.compile(
        r"(?i)\b(?:Get|New|Set|Remove|Add|Enable|Disable|Unlock)-AD(?:User|Group|Computer"
        r"|GroupMember|OrganizationalUnit|Account\w*)\b")),
)  # fmt: skip
SURFACE_CODES = tuple(code for code, _ in _PATTERNS)

# Which codes support which profile field. Unsupported v0.1 surfaces only make notices.
_SYSTEM_EVIDENCE: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "systems.entra": ("ps_connect_mggraph", "ps_mg_cmdlet", "graph_http"),
        "systems.exchange_online": ("ps_connect_exchange", "ps_exchange_cmdlet"),
        "systems.intune": ("ps_intune_cmdlet",),
        "systems.sharepoint_teams": ("ps_connect_sharepoint_teams",),
        "systems.azure": ("ps_connect_azaccount", "ps_az_cmdlet", "az_cli"),
    }
)
_MODULE_EVIDENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Az", ("ps_connect_azaccount", "ps_az_cmdlet")),
    ("ExchangeOnlineManagement", ("ps_connect_exchange", "ps_exchange_cmdlet")),
    ("Microsoft.Graph", ("ps_connect_mggraph", "ps_mg_cmdlet", "ps_intune_cmdlet")),
)
_UNSUPPORTED = (("gam_cli", "gam"), ("aws_cli", "aws"), ("ps_ad_cmdlet", "active-directory"))

_SERVER = re.compile(r"[A-Za-z0-9_-]{1,64}")
_DENY_PART = r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}"
_DENY_PATH = re.compile(rf"\./(?:{_DENY_PART}/){{0,7}}{_DENY_PART}")
_SAFE_REL = re.compile(r"[^\x00-\x1f\x7f\\]+")
_SYNC_MARKERS = ("/library/cloudstorage/", "/onedrive", "/dropbox", "/google drive")
_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_SETUP_PARTS = (".cab", "setup")
DISCOVERY_FILE = "discovery.json"


class DiscoveryError(Exception):
    """Discovery refused. ``code`` is fixed and never contains a path or content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Evidence:
    path: str  # project-relative, POSIX separators
    line: int  # 1-based
    code: str  # one of SURFACE_CODES


@dataclass(frozen=True)
class CliStatus:
    name: str
    status: str  # "available", "missing" or "unchecked"


@dataclass(frozen=True)
class Inferred:
    """A draft profile value. ``source`` is ``discovered`` or ``default``, never an answer."""

    field: str
    value: Any  # bool, str or tuple[str, ...]
    source: str
    evidence: tuple[str, ...]  # surface codes or fixed fact names, never content


@dataclass(frozen=True)
class Discovery:
    schema: int
    surfaces: tuple[Evidence, ...]
    credential_candidates: tuple[str, ...]
    cli: tuple[CliStatus, ...]
    mcp_servers: tuple[str, ...]
    mcp_status: str  # "absent", "parsed" or "refused:<code>"
    git: bool
    sync_folder: bool
    inferred: tuple[Inferred, ...]
    notices: tuple[str, ...]
    counts: Mapping[str, int]
    limits_hit: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "surfaces": [{"code": e.code, "line": e.line, "path": e.path} for e in self.surfaces],
            "credential_candidates": list(self.credential_candidates),
            "cli": [{"name": c.name, "status": c.status} for c in self.cli],
            "mcp_servers": list(self.mcp_servers),
            "mcp_status": self.mcp_status,
            "git": self.git,
            "sync_folder": self.sync_folder,
            "inferred": [
                {
                    "field": i.field,
                    "value": list(i.value) if isinstance(i.value, tuple) else i.value,
                    "source": i.source,
                    "evidence": list(i.evidence),
                }
                for i in self.inferred
            ],
            "notices": list(self.notices),
            "counts": dict(sorted(self.counts.items())),
            "limits_hit": list(self.limits_hit),
        }


# --------------------------------------------------------------------------- helpers


def _root(project_root: Any) -> str:
    if not isinstance(project_root, str) or not project_root or "\x00" in project_root:
        raise DiscoveryError("root_invalid")
    if not os.path.isabs(project_root):
        raise DiscoveryError("root_not_absolute")
    try:
        st = os.lstat(project_root)
    except OSError:
        raise DiscoveryError("root_missing") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise DiscoveryError("root_not_directory")
    real = os.path.realpath(project_root)
    if real == "/":
        raise DiscoveryError("root_invalid")
    return real


def _rel_ok(rel: str) -> bool:
    return len(rel) <= MAX_REL_CHARS and bool(_SAFE_REL.fullmatch(rel))


def _credential_like(name: str, in_credential_dir: bool) -> bool:
    if in_credential_dir:
        return True
    lower = name.lower()
    _, suffix = os.path.splitext(lower)
    if suffix in _CREDENTIAL_SUFFIXES:
        return True
    if suffix in SCAN_SUFFIXES and suffix not in (".txt",):
        # Script/doc files named "token-rotation.md" are scanned, not hidden.
        return lower.startswith(".env")
    return bool(_CREDENTIAL_NAMES.fullmatch(name))


def _read_bounded(path: str, limit: int) -> bytes | None:
    """Regular single-link file without following a final symlink; None if refused."""
    try:
        fd = os.open(path, _OPEN_READ)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
            return None
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, limit + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    if total > limit:
        return None
    return b"".join(chunks)


def _scan_text(rel: str, data: bytes, out: list[Evidence], limits: set[str]) -> None:
    text = data.decode("utf-8", errors="replace")
    for lineno, line in enumerate(text.split("\n"), start=1):
        if len(out) >= MAX_EVIDENCE:
            limits.add("evidence")
            return
        piece = line[:MAX_LINE_CHARS]
        for code, pattern in _PATTERNS:
            if pattern.search(piece):
                out.append(Evidence(rel, lineno, code))


# --------------------------------------------------------------------------- MCP


def _mcp_servers(root: str) -> tuple[tuple[str, ...], str, int]:
    path = os.path.join(root, ".mcp.json")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return (), "absent", 0
    except OSError:
        return (), "refused:unreadable", 0
    if stat.S_ISLNK(st.st_mode):
        return (), "refused:symlink", 0
    data = _read_bounded(path, MAX_MCP_BYTES)
    if data is None:
        return (), "refused:unsafe_file", 0
    try:
        doc = strict_json(data, max_bytes=MAX_MCP_BYTES)
    except Invalid as exc:
        return (), f"refused:{exc.code}", 0
    servers = doc.get("mcpServers")
    if servers is None:
        return (), "parsed", 0
    if not isinstance(servers, dict):
        return (), "refused:servers_not_object", 0
    names = sorted(name for name in servers if _SERVER.fullmatch(name))
    dropped = len(servers) - len(names)
    if len(names) > MAX_MCP_SERVERS:
        return tuple(names[:MAX_MCP_SERVERS]), "parsed", dropped + len(names) - MAX_MCP_SERVERS
    return tuple(names), "parsed", dropped


# --------------------------------------------------------------------------- inference


def _inferred(
    codes: set[str], mcp: tuple[str, ...], creds: tuple[str, ...], git: bool, sync: bool
) -> tuple[tuple[Inferred, ...], tuple[str, ...]]:
    items: list[Inferred] = []
    notices: list[str] = []
    for fld, supporting in _SYSTEM_EVIDENCE.items():
        hits = tuple(c for c in supporting if c in codes)
        items.append(Inferred(fld, bool(hits), "discovered" if hits else "default", hits))
    items.append(Inferred("systems.demo_simtenant", False, "default", ()))

    modules = tuple(m for m, supporting in _MODULE_EVIDENCE if any(c in codes for c in supporting))
    module_hits = tuple(sorted({c for _, s in _MODULE_EVIDENCE for c in s if c in codes}))
    items.append(
        Inferred(
            "surfaces.powershell_modules",
            tuple(sorted(modules)),
            "discovered" if modules else "default",
            module_hits,
        )
    )
    az = "az_cli" in codes
    items.append(Inferred("surfaces.azure_cli", az, "discovered" if az else "default",
                          ("az_cli",) if az else ()))  # fmt: skip
    graph = "graph_http" in codes
    items.append(Inferred("surfaces.graph_http", graph, "discovered" if graph else "default",
                          ("graph_http",) if graph else ()))  # fmt: skip
    # Write tools are not inspected offline: every named server is treated as a write
    # surface (the stricter reading) until a person says otherwise in the interview.
    items.append(
        Inferred(
            "surfaces.mcp_write_servers",
            mcp,
            "discovered" if mcp else "default",
            ("mcp_json_server_names",) if mcp else (),
        )
    )
    deny = tuple(sorted({"./" + c for c in creds if _DENY_PATH.fullmatch("./" + c)}))
    items.append(
        Inferred(
            "identity.deny_read_paths",
            deny,
            "discovered" if deny else "default",
            ("credential_path_candidates",) if deny else (),
        )
    )
    if len(deny) < len(creds):
        notices.append("credential_candidates_not_expressible_as_deny_paths")
    # DESIGN §10-4-2 defaults for questions discovery cannot answer.
    items.append(Inferred("identity.agent_identity", "admin", "default", ()))
    items.append(Inferred("approval.approvers", "self", "default", ()))
    items.append(Inferred("org.it_team", "solo", "default", ()))
    items.append(Inferred("session.permission_mode", "manual", "default", ()))
    items.append(Inferred("session.git", git, "discovered", ("git_marker",)))
    items.append(Inferred("session.sync_folder", sync, "discovered", ("root_path_marker",)))
    items.append(Inferred("session.multi_machine", sync, "discovered", ("root_path_marker",)))
    items.append(Inferred("session.ticketing", "none", "default", ()))
    items.append(Inferred("changes.routine", (), "default", ()))
    items.append(Inferred("changes.extra_critical", ("break-glass",), "default", ()))

    for code, name in _UNSUPPORTED:
        if code in codes:
            notices.append(f"unsupported_surface:{name}")
    if not git:
        notices.append("no_git_repository")
    if sync:
        notices.append("sync_folder_ledger_warning")
    items.sort(key=lambda i: i.field)
    return tuple(items), tuple(sorted(notices))


# --------------------------------------------------------------------------- walk


def discover(project_root: str, *, finder: Callable[[str], bool] | None = None) -> Discovery:
    """Read-only discovery of one explicit project root. See the module doc."""
    root = _root(project_root)
    counts = dict.fromkeys(
        (
            "dirs_skipped", "symlinks_skipped", "files_scanned", "files_not_scanned",
            "binary_skipped", "unsafe_skipped", "unsafe_names", "mcp_names_dropped",
        ),
        0,
    )  # fmt: skip
    limits: set[str] = set()
    evidence: list[Evidence] = []
    creds: list[str] = []
    entries = 0

    stack: list[tuple[str, str, int, bool]] = [(root, "", 0, False)]
    while stack:
        folder, rel_folder, depth, cred_dir = stack.pop()
        try:
            with os.scandir(folder) as it:
                listing = sorted(it, key=lambda e: e.name)
        except OSError:
            counts["unsafe_skipped"] += 1
            continue
        subdirs: list[tuple[str, str, int, bool]] = []
        for entry in listing:
            entries += 1
            if entries > MAX_ENTRIES:
                limits.add("entries")
                stack.clear()
                break
            rel = f"{rel_folder}/{entry.name}" if rel_folder else entry.name
            if not _rel_ok(rel):
                counts["unsafe_names"] += 1
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                counts["unsafe_skipped"] += 1
                continue
            if stat.S_ISLNK(st.st_mode):
                counts["symlinks_skipped"] += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                if entry.name in SKIP_DIRS:
                    counts["dirs_skipped"] += 1
                    continue
                if depth + 1 > MAX_DEPTH:
                    limits.add("depth")
                    continue
                child_cred = cred_dir or entry.name.lower() in _CREDENTIAL_DIRS
                subdirs.append((entry.path, rel, depth + 1, child_cred))
                continue
            if not stat.S_ISREG(st.st_mode):
                counts["unsafe_skipped"] += 1
                continue
            if _credential_like(entry.name, cred_dir):
                if len(creds) < MAX_CANDIDATES:
                    creds.append(rel)
                else:
                    limits.add("credential_candidates")
                continue  # never opened
            suffix = os.path.splitext(entry.name)[1].lower()
            if suffix not in SCAN_SUFFIXES:
                counts["files_not_scanned"] += 1
                continue
            if st.st_size > MAX_FILE_BYTES or st.st_nlink != 1:
                counts["unsafe_skipped"] += 1
                continue
            if counts["files_scanned"] >= MAX_FILES:
                limits.add("files")
                continue
            data = _read_bounded(entry.path, MAX_FILE_BYTES)
            if data is None:
                counts["unsafe_skipped"] += 1
                continue
            if b"\x00" in data:
                counts["binary_skipped"] += 1
                continue
            counts["files_scanned"] += 1
            _scan_text(rel, data, evidence, limits)
        stack.extend(reversed(subdirs))

    mcp, mcp_status, dropped = _mcp_servers(root)
    counts["mcp_names_dropped"] = dropped
    git = os.path.lexists(os.path.join(root, ".git"))
    probe = root.lower() + "/"
    sync = any(marker in probe for marker in _SYNC_MARKERS)

    cli: list[CliStatus] = []
    for name in CLI_NAMES:
        if finder is None:
            cli.append(CliStatus(name, "unchecked"))
            continue
        try:
            found = finder(name)
        except Exception:
            found = None
        if found is True:
            cli.append(CliStatus(name, "available"))
        elif found is False:
            cli.append(CliStatus(name, "missing"))
        else:
            cli.append(CliStatus(name, "unchecked"))

    evidence.sort(key=lambda e: (e.path, e.line, e.code))
    cred_tuple = tuple(sorted(creds))
    codes = {e.code for e in evidence}
    inferred, notices = _inferred(codes, mcp, cred_tuple, git, sync)
    if any(c.status == "available" for c in cli if c.name in ("gam", "aws")):
        notices = tuple(sorted({*notices, "unsupported_cli_installed"}))
    return Discovery(
        schema=SCHEMA_VERSION,
        surfaces=tuple(evidence),
        credential_candidates=cred_tuple,
        cli=tuple(cli),
        mcp_servers=mcp,
        mcp_status=mcp_status,
        git=git,
        sync_folder=sync,
        inferred=inferred,
        notices=notices,
        counts=MappingProxyType(counts),
        limits_hit=tuple(sorted(limits)),
    )


# --------------------------------------------------------------------------- writer


def to_json_bytes(discovery: Discovery) -> bytes:
    """Canonical JSON (sorted keys, ASCII) plus LF."""
    if not isinstance(discovery, Discovery):
        raise DiscoveryError("not_discovery")
    return canonical_bytes(discovery.as_dict())


def _setup_dir(root: str) -> str:
    cursor = root
    for part in _SETUP_PARTS:
        cursor = os.path.join(cursor, part)
        try:
            st = os.lstat(cursor)
        except FileNotFoundError:
            try:
                os.mkdir(cursor, 0o700)
            except FileExistsError:
                pass
            st = os.lstat(cursor)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise DiscoveryError("setup_dir_unsafe")
    return cursor


def write_discovery(discovery: Discovery, project_root: str) -> str:
    """Atomically write ``<root>/.cab/setup/discovery.json``; returns the relative path."""
    data = to_json_bytes(discovery)
    root = _root(project_root)
    folder = _setup_dir(root)
    target = os.path.join(folder, DISCOVERY_FILE)
    try:
        fsutil.atomic_write(target, data)
    except fsutil.SymlinkRefused:
        raise DiscoveryError("target_symlink") from None
    except (fsutil.FsError, OSError):
        raise DiscoveryError("write_failed") from None
    return "/".join((*_SETUP_PARTS, DISCOVERY_FILE))
