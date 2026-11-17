"""``cab setup render`` staging and the person-only ``cab setup apply`` (S9, DESIGN §10-3).

Render (preview, G5)
    ``render_project`` loads a profile (an explicit file, or a reference profile through
    ``profile.load_reference_profile``), renders the bundle, plans the merge read-only and
    writes **only** below ``<project>/.cab/setup/``: ``staged/`` (exact bundle bytes),
    ``render.json`` (profile and bundle provenance), ``render-profile.toml`` (canonical copy
    of a file profile) and ``PLAN.md`` (redacted plan and diff summary).

Apply (a person, in their own terminal)
    1. take the bounded setup lock ``.cab/setup/apply.lock`` (a second apply is refused);
    2. read provenance, reload the profile, re-render with this generator version, check the
       floor again, and compare the re-rendered bundle with every staged byte;
    3. inspect every target, ``.cab-new`` sibling and parent with ``lstat`` (never following
       links; hard links and specials are not regular), read the manifest strictly, measure
       the preflight scopes (``measure_preflight``), the runtime state and Git tracking of
       private state, and plan the merge; ``--take-new`` must name exact resolvable paths;
    4. show the summary and require the exact project folder name on a genuine TTY
       (``confirm_project_name``; stdin and stdout TTY, ``uid == euid``, bounded read);
    5. re-do step 2-3 completely and refuse if anything changed while the prompt was open;
    6. back up only affected live files to ``.cab/backups/<UTC>/`` (bytes and mode), write
       each target by temp file + fsync + rename after a compare-and-swap check of the target
       and its parents, set the pinned ``cab`` executable bit, create ``.cab/state/`` and write
       ``.cab/manifest.json`` last;
    7. verify: every written path holds the planned bytes, the static doctor reports no FAIL
       on a floor check, and the real isolated guard self test (C-main
       ``audithook.run_guard_selftest``) returns PASS. FAIL or UNKNOWN is never success:
       the apply is rolled back. The one scoped exception (G7): the doctor's
       ``manifest_mismatch`` for a person's kept edit that this plan itself reported as
       ``owned_modified``, with the proposal written, the edit unchanged since the prompt
       and unable to change a tool, hook or trusted script (``_known_conflicts``). It is
       reported as a known conflict, not as PASS.
    On any failure every journalled change is undone in reverse (exact bytes and modes;
    created files and empty directories removed only when they still hold what apply
    wrote) and the manifest stays old or absent. A failed restoration is reported path by
    path; nothing claims a rollback that did not happen.

Nothing here writes user, local or managed settings, the Git index or anything outside the
project. Commands run only through the injected bounded runner with fixed argv and no shell.
"""

from __future__ import annotations

import datetime
import difflib
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from .. import __version__
from ..runtime import doctor as doctor_mod
from ..runtime import fsutil
from ..runtime.config_lock import manifest_verifier
from ..runtime.terminal import TerminalOS, _bounded_run, sanitize
from . import merge, render
from . import profile as profile_mod
from . import session as session_mod
from .manifest import (
    CLAUDE_PATH,
    GITIGNORE_PATH,
    OWNED_FILES,
    PROPOSAL_SUFFIX,
    SETTINGS_LOCAL_PATH,
    SETTINGS_PATH,
    Manifest,
    ManifestError,
    SetupDataError,
    check_rel_path,
    dump_manifest,
    load_manifest,
    loads_strict,
    sha256_hex,
)

__all__ = [
    "EXIT_BLOCKED",
    "EXIT_NOT_CONFIRMED",
    "EXIT_OK",
    "EXIT_REFUSED",
    "EXIT_ROLLBACK_FAILED",
    "EXIT_ROLLED_BACK",
    "EXIT_USAGE",
    "FAIL",
    "GENERATOR_VERSION",
    "MIN_CLAUDE_CODE",
    "PASS",
    "UNKNOWN",
    "ApplyError",
    "Check",
    "FileOps",
    "Node",
    "Outcome",
    "Preflight",
    "Services",
    "apply_project",
    "confirm_project_name",
    "default_runtime_probe",
    "edit_can_be_kept",
    "git_check",
    "guard_selftest",
    "inspect_tree",
    "manifest_verifier",
    "measure_preflight",
    "merge_bundle",
    "project_root",
    "render_project",
    "selftest_not_wired",
]

GENERATOR_VERSION = __version__
MIN_CLAUDE_CODE = "2.1.295"  # documented minimum (HOOK_S10_FACTS_2026-11-11)

EXIT_OK = 0
EXIT_NOT_CONFIRMED = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3
EXIT_BLOCKED = 4
EXIT_ROLLED_BACK = 5
EXIT_ROLLBACK_FAILED = 6

PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"

MANIFEST_REL = ".cab/manifest.json"
SETUP_REL = ".cab/setup"
STAGED_REL = ".cab/setup/staged"
PROVENANCE_REL = ".cab/setup/render.json"
PROFILE_COPY_REL = ".cab/setup/render-profile.toml"
PLAN_REL = ".cab/setup/PLAN.md"
DEFAULT_PROFILE_REL = ".cab/setup/profile.toml"
LOCK_NAME = "apply.lock"
BACKUPS_REL = ".cab/backups"
STATE_REL = ".cab/state"
PRIVATE_RELS = (".cab/state", ".cab/backups", ".cab/setup")
EXECUTABLE_PATHS = frozenset({".claude/hooks/cab/cab"})
PRUNE_ROOTS = (".claude/agents", ".claude/skills", ".claude/hooks/cab")

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_STAGED_FILES = 4000
MAX_STAGED_DEPTH = 12
MAX_CONFIRM_BYTES = 512
MAX_NAME_CHARS = 128
MAX_SUMMARY_LINES = 600
MAX_MANAGED_FRAGMENTS = 64
COMMAND_TIMEOUT = 5.0
VERSION_MAX_BYTES = 256
GIT_MAX_BYTES = 64 * 1024
LOCK_TIMEOUT = 0.5

CLAUDE_VERSION_ARGV = ("claude", "--version")
GIT_TOPLEVEL_ARGV = ("git", "-c", "core.fsmonitor=false", "rev-parse", "--is-inside-work-tree")
GIT_TRACKED_ARGV = (
    "git", "-c", "core.fsmonitor=false", "ls-files", "-z", "--", *PRIVATE_RELS,
)  # fmt: skip

#: File-based managed settings directories (official docs, SETTINGS_PATH_FACTS_2026-11-12).
MANAGED_DIRS: Mapping[str, str] = {
    "darwin": "/Library/Application Support/ClaudeCode",
    "linux": "/etc/claude-code",
}
MANAGED_FILE = "managed-settings.json"
MANAGED_FRAGMENTS = "managed-settings.d"
#: Sources this tool can never measure. Shown as UNKNOWN on every plan, never as PASS.
ALWAYS_UNMEASURED = (
    "managed: OS policy (macOS managed preferences, Windows registry) not measured",
    "managed: server- or host-delivered policy not measured",
    "cli: launch flags such as --settings are per session and not measured",
    "local: worktree/main-checkout and older starting-directory settings not measured",
)
#: Doctor checks whose FAIL means the installed floor is not intact (apply rolls back).
FLOOR_CHECKS = frozenset(
    {
        "settings_layers",
        "disable_all_hooks",
        "managed_masking",
        "hooks",
        "hook_target",
        "hook_matcher",
        "on_failure",
        "on_failure_field",
        "plugin_root",
        "deny_rules",
        "allow_gate",
        "safety_reviewer",
        "policy",
        "version",
        "manifest",
    }
)
FAIL_CLOSED_EVENTS = ("PreToolUse", "Stop", "ConfigChange")
#: G7 known conflicts (see ``_known_conflicts``). Owned files that are executable or trusted
#: code: a person's edit there is never kept next to an apply (restore it or --take-new).
KNOWN_CONFLICT_NEVER = frozenset({"simtenant/simtenant.py"})
#: Markdown below these folders carries capability in its frontmatter (tools,
#: allowed-tools, hooks, model) and may run shell through "!`...`": only a body edit that
#: keeps the generated frontmatter byte for byte and adds no such line can be kept.
FRONTMATTER_PREFIXES = (".claude/agents/", ".claude/skills/")
SHELL_INJECTION = b"!`"

_OPEN_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_TYPABLE = re.compile(r"[^\x00-\x1f\x7f-\x9f/  ]{1,128}")
_VERSION = re.compile(rb"\s*v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,6})(?![0-9])")
_SHA = re.compile(r"[0-9a-f]{64}")
_PROVENANCE_KEYS = frozenset(
    {"bundle_sha256", "generator_version", "kind", "modules", "profile", "profile_sha256", "schema"}
)
PROVENANCE_KIND = "cab-of-one-render"


# --------------------------------------------------------------------------- data


class ApplyError(Exception):
    """A refusal. ``code`` is fixed; ``detail`` is a project-relative path or hint."""

    def __init__(self, code: str, detail: str = "", exit_code: int = EXIT_REFUSED) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.exit_code = exit_code


@dataclass(frozen=True)
class Check:
    """``status`` is PASS, FAIL or UNKNOWN. UNKNOWN is never success."""

    status: str
    code: str
    detail: str = ""


@dataclass(frozen=True)
class Outcome:
    exit: int
    code: str
    lines: tuple[str, ...] = ()


@dataclass(frozen=True)
class Node:
    """One project path as ``lstat`` saw it. ``kind``: absent, file, dir, symlink, other,
    or unreached (an ancestor is not a real directory, so it was not looked at)."""

    kind: str
    data: bytes | None = None
    mode: int | None = None


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def selftest_not_wired(project_root: str) -> Check:
    """A self test that was deliberately not run: UNKNOWN, never success."""
    return Check(UNKNOWN, "selftest_not_wired")


def _installed_roots(project_root: str, home: str | None) -> Any:
    """Runtime ``Roots`` of an installed project (C-main ``paths.resolve_roots``)."""
    from ..runtime import paths

    entry = os.path.join(project_root, ".claude", "hooks", "cab", "guard.py")
    return paths.resolve_roots(entry, {"CLAUDE_PROJECT_DIR": project_root}, home)


def guard_selftest(project_root: str, *, home: str | None) -> Check:
    """The real isolated guard self test (``audithook.run_guard_selftest``, C-main).

    It runs the source runtime's ``guard.decide`` (byte-identical to the pinned copy whose
    hashes the doctor checks) on a synthetic administrative write inside a fresh fictional
    fixture under ``.cab/state/selftest/``; PASS means the guard denied it for having no open
    change and the real ``active.json`` did not change. Synthetic, not an L2 measurement of
    the live hook registration. Any failure to run it is FAIL, never PASS.
    """
    try:
        from ..runtime import audithook

        result = audithook.run_guard_selftest(_installed_roots(project_root, home))
    except Exception as exc:
        code = getattr(exc, "code", None)
        return Check(FAIL, "selftest_unavailable", code if isinstance(code, str) else "")
    ok = getattr(result, "ok", None) is True
    code = getattr(result, "code", "selftest_invalid")
    return Check(PASS if ok else FAIL, str(code), "synthetic source self test, not L2")


def default_runtime_probe(project_root: str, *, home: str | None) -> Check:
    """Is a change active (or in flight)? Read through the C-main/A runtime Store.

    No ``.cab/state`` (or an empty one) is measured idle. Otherwise the installed runtime is
    opened (``audithook.open_runtime``) and ``Store.load().active`` decides: None is PASS,
    a change ID is FAIL (``change_active``). Anything that cannot be read is UNKNOWN, and
    apply refuses to replace or remove controls on UNKNOWN.
    """
    path = os.path.join(project_root, ".cab", "state")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return Check(PASS, "no_runtime_state")
    except OSError:
        return Check(FAIL, "runtime_state_unreadable")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return Check(FAIL, "runtime_state_unsafe")
    try:
        with os.scandir(path) as entries:
            if next(entries, None) is None:
                return Check(PASS, "runtime_state_empty")
    except OSError:
        return Check(FAIL, "runtime_state_unreadable")
    try:
        from ..runtime import audithook

        view = audithook.open_runtime(_installed_roots(project_root, home)).store.load()
        active = view.active
    except Exception:
        return Check(UNKNOWN, "runtime_state_unmeasured")
    if active is None:
        return Check(PASS, "no_active_change")
    shown = active if isinstance(active, str) and re.fullmatch(r"CHG-[0-9]{4}", active) else ""
    return Check(FAIL, "change_active", shown)


class FileOps:
    """Every live mutation goes through here so tests can inject failures."""

    def write(self, path: str, data: bytes, mode: int) -> None:
        fsutil.atomic_write(path, data, mode=mode)

    def unlink(self, path: str) -> None:
        os.unlink(path)

    def mkdir(self, path: str, mode: int) -> None:
        os.mkdir(path, mode)

    def rmdir(self, path: str) -> None:
        os.rmdir(path)


@dataclass
class Services:
    """Injectable environment. Defaults are the real ones; tests replace them.

    ``runner(argv, *, cwd, env, timeout, max_bytes) -> bytes | None`` runs a fixed argv
    without a shell (``terminal._bounded_run``). ``selftest`` and ``runtime_probe`` take the
    absolute project root and return a ``Check``; ``None`` means the real ones
    (``guard_selftest``, ``default_runtime_probe``). There is no PASS default; callbacks
    that tests inject must say they are unit-only in ``Check.detail``.
    """

    stdin: Any = None
    stdout: Any = None
    stderr: Any = None
    cwd: Callable[[], str] = os.getcwd
    environ: Mapping[str, str] | None = None
    home: str | None = None
    platform: str = sys.platform
    managed_dir: str | None = None
    runner: Callable[..., bytes | None] = _bounded_run
    osx: TerminalOS = field(default_factory=TerminalOS)
    clock: Callable[[], datetime.datetime] = _utc_now
    fileops: FileOps = field(default_factory=FileOps)
    runtime_probe: Callable[[str], Check] | None = None
    selftest: Callable[[str], Check] | None = None
    finder: Callable[[str], bool] | None = _which
    lock_timeout: float = LOCK_TIMEOUT

    def probe_runtime(self, root: str) -> Check:
        try:
            if self.runtime_probe is None:
                return default_runtime_probe(root, home=self.user_home())
            result = self.runtime_probe(root)
        except Exception:
            return Check(UNKNOWN, "runtime_probe_error")
        return result if isinstance(result, Check) else Check(UNKNOWN, "runtime_probe_invalid")

    def run_selftest(self, root: str) -> Check:
        try:
            if self.selftest is None:
                return guard_selftest(root, home=self.user_home())
            result = self.selftest(root)
        except Exception:
            return Check(FAIL, "selftest_error")
        return result if isinstance(result, Check) else Check(UNKNOWN, "selftest_invalid")

    def env(self) -> Mapping[str, str]:
        return os.environ if self.environ is None else self.environ

    def out(self) -> Any:
        return sys.stdout if self.stdout is None else self.stdout

    def inp(self) -> Any:
        return sys.stdin if self.stdin is None else self.stdin

    def err(self) -> Any:
        return sys.stderr if self.stderr is None else self.stderr

    def user_home(self) -> str | None:
        if self.home is not None:
            return self.home
        try:
            import pwd

            return pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OverflowError, ImportError):
            return None


# --------------------------------------------------------------------------- paths and reads


def project_root(path: object) -> str:
    """The real absolute project folder. The folder itself must not be a symlink."""
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        raise ApplyError("project_root_invalid")
    try:
        st = os.lstat(path)
    except OSError:
        raise ApplyError("project_root_missing") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ApplyError("project_root_unsafe")
    real = os.path.realpath(path)
    if real == "/" or not os.path.isabs(real):
        raise ApplyError("project_root_invalid")
    return real


def _abs(root: str, rel: str) -> str:
    return os.path.join(root, *rel.split("/"))


def _ancestors(rel: str) -> list[str]:
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def _lstat(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None


def _read_node(path: str) -> Node:
    """Never follows a link. A hard-linked, special or oversized file is ``other``."""
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return Node("absent")
    except OSError:
        return Node("other")
    if stat.S_ISLNK(st.st_mode):
        return Node("symlink")
    if stat.S_ISDIR(st.st_mode):
        return Node("dir", None, stat.S_IMODE(st.st_mode))
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_FILE_BYTES:
        return Node("other")
    try:
        fd = os.open(path, _OPEN_READ)
    except OSError:
        return Node("other")
    try:
        fst = os.fstat(fd)
        if (
            not stat.S_ISREG(fst.st_mode)
            or fst.st_nlink != 1
            or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino)
        ):
            return Node("other")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_FILE_BYTES:
            chunk = os.read(fd, MAX_FILE_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return Node("other")
    finally:
        os.close(fd)
    if total > MAX_FILE_BYTES:
        return Node("other")
    return Node("file", b"".join(chunks), stat.S_IMODE(fst.st_mode))


def inspect_tree(root: str, rels: Iterable[str]) -> dict[str, Node]:
    """``lstat`` view of ``rels`` and all their parents, shallowest first. Below a parent
    that is absent the child is absent; below anything else it is ``unreached``."""
    wanted: set[str] = set()
    for rel in rels:
        wanted.add(rel)
        wanted.update(_ancestors(rel))
    out: dict[str, Node] = {}
    for rel in sorted(wanted, key=lambda r: (r.count("/"), r)):
        parent = rel.rsplit("/", 1)[0] if "/" in rel else None
        if parent is not None:
            above = out[parent]
            if above.kind == "absent":
                out[rel] = Node("absent")
                continue
            if above.kind != "dir":
                out[rel] = Node("unreached")
                continue
        out[rel] = _read_node(_abs(root, rel))
    return out


def _existing(nodes: Mapping[str, Node]) -> dict[str, bytes | merge.NodeKind]:
    kinds = {
        "dir": merge.NodeKind.DIRECTORY,
        "symlink": merge.NodeKind.SYMLINK,
        "other": merge.NodeKind.OTHER,
    }
    out: dict[str, bytes | merge.NodeKind] = {}
    for rel, node in nodes.items():
        if node.kind == "file":
            out[rel] = node.data  # type: ignore[assignment]
        elif node.kind in kinds:
            out[rel] = kinds[node.kind]
    return out


def _real_dir_chain(root: str, rel: str) -> bool:
    """Every component of ``rel`` below ``root`` is a real directory (no links)."""
    cursor = root
    for part in rel.split("/"):
        cursor = os.path.join(cursor, part)
        st = _lstat(cursor)
        if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return False
    return True


def _ensure_private_dir(root: str, rel: str) -> str:
    """Create ``rel`` (below the root, 0700 each) if missing; refuse links and files."""
    cursor = root
    for part in rel.split("/"):
        cursor = os.path.join(cursor, part)
        st = _lstat(cursor)
        if st is None:
            try:
                os.mkdir(cursor, 0o700)
            except FileExistsError:
                pass
            st = _lstat(cursor)
        if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise ApplyError("setup_dir_unsafe", rel)
    return cursor


def _setup_write(root: str, rel: str, data: bytes) -> None:
    """Atomic 0600 write of a file directly below ``.cab/setup``."""
    parent = rel.rsplit("/", 1)[0]
    if not _real_dir_chain(root, parent):
        raise ApplyError("setup_dir_unsafe", parent)
    try:
        fsutil.atomic_write(_abs(root, rel), data, mode=0o600)
    except (fsutil.FsError, OSError):
        raise ApplyError("setup_write_failed", rel) from None


def _setup_unlink(root: str, rel: str) -> None:
    node = _read_node(_abs(root, rel))
    if node.kind == "absent":
        return
    if node.kind not in ("file", "symlink", "other") or not _real_dir_chain(
        root, rel.rsplit("/", 1)[0]
    ):
        raise ApplyError("setup_dir_unsafe", rel)
    try:
        os.unlink(_abs(root, rel))
    except OSError:
        raise ApplyError("setup_write_failed", rel) from None


def _remove_tree(path: str) -> None:
    """Remove a tree without ever following a link (links are unlinked themselves)."""
    st = _lstat(path)
    if st is None:
        return
    if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
        with os.scandir(path) as entries:
            names = [e.name for e in entries]
        for name in names:
            _remove_tree(os.path.join(path, name))
        os.rmdir(path)
    else:
        os.unlink(path)


def read_staged(root: str) -> dict[str, bytes]:
    """Every staged file (``.cab/setup/staged``), refusing links, hard links and specials."""
    if not _real_dir_chain(root, STAGED_REL):
        if _lstat(_abs(root, STAGED_REL)) is None:
            raise ApplyError("staged_missing", STAGED_REL)
        raise ApplyError("staged_unsafe", STAGED_REL)
    out: dict[str, bytes] = {}

    def walk(folder: str, prefix: str, depth: int) -> None:
        if depth > MAX_STAGED_DEPTH:
            raise ApplyError("staged_unsafe", prefix or STAGED_REL)
        with os.scandir(folder) as entries:
            names = sorted(e.name for e in entries)
        for name in names:
            rel = prefix + name
            node = _read_node(os.path.join(folder, name))
            if node.kind == "dir":
                walk(os.path.join(folder, name), rel + "/", depth + 1)
            elif node.kind == "file":
                out[rel] = node.data  # type: ignore[assignment]
                if len(out) > MAX_STAGED_FILES:
                    raise ApplyError("staged_unsafe", "too_many_files")
            else:
                raise ApplyError("staged_unsafe", rel)

    try:
        walk(_abs(root, STAGED_REL), "", 0)
    except OSError:
        raise ApplyError("staged_unsafe", STAGED_REL) from None
    return out


def merge_bundle(bundle: Mapping[str, bytes]) -> dict[str, bytes]:
    """The renderer's bundle as ``merge.plan_merge`` input: ``CLAUDE.md`` and ``.gitignore``
    without their single trailing LF (merge adds its own separators)."""
    out = dict(bundle)
    for path in (CLAUDE_PATH, GITIGNORE_PATH):
        data = out.get(path)
        if data is None:
            continue
        if not data.endswith(b"\n") or data.endswith(b"\n\n"):
            raise ApplyError("bundle_block_shape", path)
        out[path] = data[:-1]
    return out


# --------------------------------------------------------------------------- provenance


@dataclass(frozen=True)
class Provenance:
    source: str  # "reference" or "file"
    name: str | None
    profile_sha256: str
    generator_version: str
    bundle_sha256: str
    modules: tuple[str, ...]

    def to_bytes(self) -> bytes:
        profile: dict[str, Any] = {"source": self.source}
        if self.name is not None:
            profile["name"] = self.name
        obj = {
            "kind": PROVENANCE_KIND,
            "schema": 1,
            "generator_version": self.generator_version,
            "profile": profile,
            "profile_sha256": self.profile_sha256,
            "bundle_sha256": self.bundle_sha256,
            "modules": list(self.modules),
        }
        return (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode("ascii")


def parse_provenance(data: bytes) -> Provenance:
    try:
        doc = loads_strict(data)
    except SetupDataError:
        raise ApplyError("provenance_invalid", PROVENANCE_REL) from None
    if type(doc) is not dict or set(doc) != _PROVENANCE_KEYS:
        raise ApplyError("provenance_invalid", PROVENANCE_REL)
    prof = doc["profile"]
    ok = (
        doc["kind"] == PROVENANCE_KIND
        and type(doc["schema"]) is int
        and doc["schema"] == 1
        and type(doc["generator_version"]) is str
        and type(doc["profile_sha256"]) is str
        and _SHA.fullmatch(doc["profile_sha256"]) is not None
        and type(doc["bundle_sha256"]) is str
        and _SHA.fullmatch(doc["bundle_sha256"]) is not None
        and type(doc["modules"]) is list
        and all(type(m) is str for m in doc["modules"])
        and type(prof) is dict
    )
    if not ok:
        raise ApplyError("provenance_invalid", PROVENANCE_REL)
    if prof == {"source": "file"}:
        source, name = "file", None
    elif set(prof) == {"source", "name"} and prof["source"] == "reference":
        source, name = "reference", prof["name"]
        if type(name) is not str or name not in profile_mod.REFERENCE_PROFILES:
            raise ApplyError("provenance_invalid", PROVENANCE_REL)
    else:
        raise ApplyError("provenance_invalid", PROVENANCE_REL)
    return Provenance(
        source,
        name,
        doc["profile_sha256"],
        doc["generator_version"],
        doc["bundle_sha256"],
        tuple(doc["modules"]),
    )


# --------------------------------------------------------------------------- preflight


@dataclass(frozen=True)
class Preflight:
    """Read-only measurement of what can switch the harness off.

    ``scopes`` feeds ``merge.plan_merge`` (inspected for blockers, never written).
    ``blockers`` stop the apply. ``unknown`` are explicitly unmeasured sources, always shown
    and never counted as PASS. ``measured`` are human lines of what was actually read.
    """

    scopes: merge.SettingsScopes
    blockers: tuple[str, ...]
    unknown: tuple[str, ...]
    measured: tuple[str, ...]
    version: str | None
    user_layer: doctor_mod.SettingsLayer | None
    managed_layer: doctor_mod.SettingsLayer | None


def _version_tuple(text: str) -> tuple[int, int, int] | None:
    m = _VERSION.match(text.encode("ascii", "replace"))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _command_env(services: Services) -> dict[str, str]:
    env = {"PATH": services.env().get("PATH") or os.defpath, "LC_ALL": "C"}
    home = services.user_home()
    if home:
        env["HOME"] = home
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def _run(services: Services, argv: Sequence[str], cwd: str | None, max_bytes: int) -> bytes | None:
    try:
        out = services.runner(
            tuple(argv),
            cwd=cwd,
            env=_command_env(services),
            timeout=COMMAND_TIMEOUT,
            max_bytes=max_bytes,
        )
    except Exception:
        return None
    return out if type(out) is bytes and len(out) <= max_bytes else None


def _layer(source: str, node: Node) -> doctor_mod.SettingsLayer:
    if node.kind == "absent":
        return doctor_mod.SettingsLayer(source, None, "missing")
    if node.kind != "file":
        return doctor_mod.SettingsLayer(source, None, "unsafe")
    try:
        doc = loads_strict(node.data)  # type: ignore[arg-type]
    except SetupDataError:
        return doctor_mod.SettingsLayer(source, None, "invalid")
    if type(doc) is not dict:
        return doctor_mod.SettingsLayer(source, None, "invalid")
    return doctor_mod.SettingsLayer(source, doc, "ok")


def _read_outside(base: str, parts: Sequence[str]) -> Node:
    """``base/parts...`` without following links in the named components."""
    cursor = base
    for part in parts[:-1]:
        cursor = os.path.join(cursor, part)
        node = _read_node(cursor)
        if node.kind == "absent":
            return Node("absent")
        if node.kind != "dir":
            return Node("unreached")
    return _read_node(os.path.join(cursor, parts[-1]))


def measure_preflight(
    root: str,
    nodes: Mapping[str, Node],
    services: Services,
    *,
    with_commands: bool = True,
) -> Preflight:
    """Measure version, user, local and file-based managed settings (read-only)."""
    blockers: list[str] = []
    unknown: list[str] = list(ALWAYS_UNMEASURED)
    measured: list[str] = []
    version: str | None = None

    if with_commands:
        out = _run(services, CLAUDE_VERSION_ARGV, None, VERSION_MAX_BYTES)
        text = out.decode("utf-8", "replace") if out is not None else ""
        have = _version_tuple(text) if out is not None else None
        need = _version_tuple(MIN_CLAUDE_CODE)
        if have is None:
            blockers.append("claude_version_unknown: run `claude --version` in this terminal")
        else:
            version = ".".join(str(x) for x in have)
            if need is not None and have < need:
                blockers.append(f"claude_version_too_old: {version} < {MIN_CLAUDE_CODE}")
            else:
                measured.append(f"claude code: {version} (minimum {MIN_CLAUDE_CODE})")
    else:
        unknown.append("claude code version: checked at apply")

    # local (project) settings: .claude/settings.local.json
    local_node = nodes.get(SETTINGS_LOCAL_PATH, Node("absent"))
    local: bytes | None = None
    if local_node.kind == "file":
        local = local_node.data
        measured.append("local: .claude/settings.local.json read")
    elif local_node.kind == "absent":
        measured.append("local: .claude/settings.local.json absent")
    else:
        blockers.append("local_settings_unsafe: .claude/settings.local.json is not a regular file")

    # user settings
    user: bytes | None = None
    user_layer: doctor_mod.SettingsLayer | None = None
    if services.env().get("CLAUDE_CONFIG_DIR"):
        unknown.append("user: CLAUDE_CONFIG_DIR relocates user settings; not measured")
    else:
        home = services.user_home()
        if not home or not os.path.isabs(home):
            unknown.append("user: home folder unknown; ~/.claude/settings.json not measured")
        else:
            node = _read_outside(home, (".claude", "settings.json"))
            if node.kind == "file":
                user = node.data
                user_layer = _layer("user", node)
                measured.append("user: ~/.claude/settings.json read")
            elif node.kind == "absent":
                user_layer = _layer("user", node)
                measured.append("user: ~/.claude/settings.json absent")
            else:
                unknown.append("user: ~/.claude/settings.json is a link or not regular")
                blockers.append(
                    "user_settings_unmeasured: ~/.claude/settings.json (or ~/.claude) is a "
                    "symlink or not a regular file; it was not followed"
                )

    # managed settings (file-based sources only)
    managed: list[bytes] = []
    managed_layer: doctor_mod.SettingsLayer | None = None
    folder = services.managed_dir
    if folder is None:
        folder = MANAGED_DIRS.get(services.platform)
    if folder is None:
        unknown.append("managed files: platform not supported; not measured")
    else:
        dir_node = _read_node(folder)
        if dir_node.kind == "absent":
            measured.append("managed files: none in the system folder")
        elif dir_node.kind != "dir":
            unknown.append("managed files: system folder is a link or not a folder")
            blockers.append("managed_settings_unmeasured: managed settings folder not followed")
        else:
            main = _read_node(os.path.join(folder, MANAGED_FILE))
            if main.kind == "file":
                managed.append(main.data)  # type: ignore[arg-type]
            elif main.kind != "absent":
                blockers.append(f"managed_settings_unmeasured: {MANAGED_FILE} not followed")
            frag_dir = os.path.join(folder, MANAGED_FRAGMENTS)
            frag_node = _read_node(frag_dir)
            fragments = 0
            if frag_node.kind == "dir":
                try:
                    with os.scandir(frag_dir) as entries:
                        names = sorted(e.name for e in entries)
                except OSError:
                    names = None
                if names is None:
                    blockers.append(f"managed_settings_unmeasured: {MANAGED_FRAGMENTS} unreadable")
                elif len(names) > MAX_MANAGED_FRAGMENTS:
                    blockers.append(f"managed_settings_unmeasured: {MANAGED_FRAGMENTS} too large")
                else:
                    for name in names:
                        node = _read_node(os.path.join(frag_dir, name))
                        if node.kind == "file":
                            managed.append(node.data)  # type: ignore[arg-type]
                            fragments += 1
                        else:
                            blockers.append(
                                f"managed_settings_unmeasured: {MANAGED_FRAGMENTS} entry not "
                                "a regular file"
                            )
            elif frag_node.kind != "absent":
                blockers.append(f"managed_settings_unmeasured: {MANAGED_FRAGMENTS} not followed")
            measured.append(
                f"managed files: {'1' if main.kind == 'file' else '0'} main file, "
                f"{fragments} fragment(s) read"
            )
            if main.kind == "file" and fragments == 0:
                managed_layer = _layer("managed", main)
    return Preflight(
        merge.SettingsScopes(local=local, user=user, managed=tuple(managed)),
        tuple(blockers),
        tuple(unknown),
        tuple(measured),
        version,
        user_layer,
        managed_layer,
    )


def git_check(root: str, services: Services) -> Check:
    """Is private state (``.cab/state``, ``backups``, ``setup``) tracked by Git?

    Ignore rules never untrack committed files, so tracked private state refuses the apply.
    Nothing here edits the Git index.
    """
    dotgit = _lstat(os.path.join(root, ".git"))
    top = _run(services, GIT_TOPLEVEL_ARGV, root, 64)
    if top is None:
        if dotgit is not None:
            return Check(FAIL, "git_unmeasured", "this folder has .git but git could not run")
        return Check(UNKNOWN, "git_not_measured", "not a git work tree, or git unavailable")
    if top.strip() != b"true":
        return Check(PASS, "not_a_work_tree")
    listed = _run(services, GIT_TRACKED_ARGV, root, GIT_MAX_BYTES)
    if listed is None:
        return Check(FAIL, "git_unmeasured", "git ls-files failed or printed too much")
    names = [n for n in listed.split(b"\0") if n]
    if names:
        shown = ", ".join(n.decode("utf-8", "replace") for n in names[:3])
        more = f" and {len(names) - 3} more" if len(names) > 3 else ""
        return Check(FAIL, "private_state_tracked", f"{shown}{more}")
    return Check(PASS, "private_state_untracked")


# --------------------------------------------------------------------------- summaries


def _text_lines(data: bytes | None) -> list[str] | None:
    if data is None:
        return []
    try:
        return data.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        return None


def diffstat(old: bytes | None, new: bytes | None) -> str:
    """``+a -b lines`` between two byte strings (content is never shown)."""
    a, b = _text_lines(old), _text_lines(new)
    if a is None or b is None:
        return "binary"
    added = removed = 0
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            removed += i2 - i1
        if tag in ("replace", "insert"):
            added += j2 - j1
    return f"+{added} -{removed} lines"


def _action_lines(actions: Iterable[merge.Action], nodes: Mapping[str, Node]) -> list[str]:
    lines = []
    for action in actions:
        old = nodes.get(action.path, Node("absent"))
        before = old.data if old.kind == "file" else None
        after = action.data if action.kind != "remove" else None
        lines.append(
            f"  {action.kind:<7} {action.path}  ({diffstat(before, after)}; {action.reason})"
        )
    return lines


def _issue_lines(label: str, issues: Iterable[merge.Issue]) -> list[str]:
    out = []
    for issue in issues:
        detail = f" [{issue.detail}]" if issue.detail else ""
        out.append(f"  {label}: {issue.code} {issue.path}{detail}")
    return out


def _profile_lines(prov: Provenance, prof: profile_mod.Profile) -> list[str]:
    where = (
        f"reference profile {prov.name}"
        if prov.source == "reference"
        else f"profile file (canonical copy {PROFILE_COPY_REL})"
    )
    lines = [
        f"generator: cab-of-one {prov.generator_version}",
        f"profile: {where}, sha256 {prov.profile_sha256}",
        f"bundle: sha256 {prov.bundle_sha256}, modules {', '.join(prov.modules)}",
        "profile values:",
    ]
    for key in sorted(prof.values):
        value = prof.values[key]
        shown = ", ".join(value) if isinstance(value, tuple) else str(value).lower()
        lines.append(f"  {key} = {shown}")
    return lines


def _preflight_lines(pre: Preflight, runtime: Check | None, git: Check | None) -> list[str]:
    lines = ["preflight (read-only):"]
    lines += [f"  measured: {m}" for m in pre.measured]
    lines += [f"  UNKNOWN: {u}" for u in pre.unknown]
    if runtime is not None:
        lines.append(f"  runtime state: {runtime.status} {runtime.code}")
    if git is not None:
        extra = f" ({git.detail})" if git.detail else ""
        lines.append(f"  git private state: {git.status} {git.code}{extra}")
    return lines


# --------------------------------------------------------------------------- confirmation


def _genuine_tty(stream: Any, osx: TerminalOS) -> bool:
    try:
        if stream.isatty() is not True:
            return False
        fd = stream.fileno()
        return type(fd) is int and fd >= 0 and osx.isatty(fd) is True
    except Exception:
        return False


def _say(stream: Any, text: str) -> None:
    try:
        stream.write(text + "\n")
        stream.flush()
    except Exception:
        pass


def confirm_project_name(
    name: str,
    summary: Sequence[str],
    *,
    stdin: Any,
    stdout: Any,
    stderr: Any = None,
    osx: TerminalOS | None = None,
    verb: str = "apply",
) -> Check:
    """Person-only confirmation: type the exact project folder name.

    Same checks as ``terminal.require_human`` (genuine TTY on stdin and stdout, ``uid ==
    euid``, OS user from the password database), but for a folder name rather than a change
    ID; ``require_human`` is untouched. Nothing is shown or read when a check fails. One
    bounded line is read from the binary layer; only its trailing LF is stripped. No termios,
    no echo control, no retry. A pseudo-terminal wrapper can satisfy this (DESIGN §3-6).
    Returns PASS ``confirmed``; FAIL ``mismatch``/``input_error``; or UNKNOWN with a refusal
    code (``project_name_untypable``, ``not_a_tty``, ``uid_mismatch``, ``os_user_unknown``,
    ``output_error``).
    """
    osx = osx or TerminalOS()
    if type(name) is not str or not _TYPABLE.fullmatch(name) or name != name.strip():
        return Check(UNKNOWN, "project_name_untypable")
    if not (_genuine_tty(stdin, osx) and _genuine_tty(stdout, osx)):
        return Check(UNKNOWN, "not_a_tty")
    try:
        uid, euid = osx.getuid(), osx.geteuid()
    except Exception:
        return Check(UNKNOWN, "uid_mismatch")
    if type(uid) is not int or type(euid) is not int or uid != euid:
        return Check(UNKNOWN, "uid_mismatch")
    try:
        user = osx.username(uid)
    except Exception:
        user = None
    if type(user) is not str or not user or any(ord(c) < 32 or ord(c) == 127 for c in user):
        return Check(UNKNOWN, "os_user_unknown")
    shown = list(summary)
    try:
        for line in shown[:MAX_SUMMARY_LINES]:
            stdout.write(sanitize(line) + "\n")
        if len(shown) > MAX_SUMMARY_LINES:
            stdout.write(
                f"... {len(shown) - MAX_SUMMARY_LINES} more lines in {PLAN_REL} (render)\n"
            )
        stdout.write(
            sanitize(
                f"Type the project folder name ({name}) and press Enter to {verb}; "
                "anything else cancels."
            )
            + "\n> "
        )
        stdout.flush()
    except Exception:
        return Check(UNKNOWN, "output_error")
    source = getattr(stdin, "buffer", stdin)
    try:
        raw = source.readline(MAX_CONFIRM_BYTES + 1)
    except Exception:
        return Check(FAIL, "input_error")
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return Check(FAIL, "input_error")
    if type(raw) is not str or not raw.endswith("\n"):
        return Check(FAIL, "mismatch")
    typed = raw[:-1]
    if len(typed) > MAX_NAME_CHARS or typed != name:
        return Check(FAIL, "mismatch")
    return Check(PASS, "confirmed")


_CONFIRM_TEXT = {
    "project_name_untypable": "the project folder name cannot be typed safely; rename it.",
    "not_a_tty": "this command needs a person at a real terminal (stdin and stdout must be a "
    "TTY). Run it yourself in your own terminal.",
    "uid_mismatch": "real and effective user IDs differ.",
    "os_user_unknown": "the OS user could not be determined.",
    "output_error": "the summary could not be shown.",
    "input_error": "the confirmation could not be read. Nothing was written.",
    "mismatch": "not confirmed: the typed text did not match the project folder name. "
    "Nothing was written.",
}


def _confirm_outcome(check: Check) -> Outcome:
    text = _CONFIRM_TEXT.get(check.code, check.code)
    exit_code = EXIT_NOT_CONFIRMED if check.status == FAIL else EXIT_REFUSED
    return Outcome(exit_code, check.code, (f"cab setup: {text}",))


# --------------------------------------------------------------------------- transaction


@dataclass
class _Entry:
    op: str  # write | remove | mkdir | rmdir
    rel: str
    prior: Node | None = None
    new: bytes | None = None
    mode: int | None = None


class _Transaction:
    """Journalled mutations with exact rollback. Rollback never removes what it did not make."""

    def __init__(self, root: str, ops: FileOps) -> None:
        self.root = root
        self.ops = ops
        self.journal: list[_Entry] = []
        self.backup_rel: str | None = None

    # -- checks

    def _parents_ok(self, rel: str) -> bool:
        parent = rel.rsplit("/", 1)[0] if "/" in rel else None
        return parent is None or _real_dir_chain(self.root, parent)

    def cas(self, rel: str, expected: Node) -> None:
        """The live target still is exactly what was confirmed (kind, bytes, mode)."""
        if not self._parents_ok(rel) and expected.kind != "absent":
            raise ApplyError("target_changed", rel, EXIT_ROLLED_BACK)
        current = _read_node(_abs(self.root, rel)) if self._parents_ok(rel) else Node("absent")
        if current != expected:
            raise ApplyError("target_changed", rel, EXIT_ROLLED_BACK)

    # -- operations

    def make_parents(self, rel: str) -> None:
        for parent in _ancestors(rel):
            path = _abs(self.root, parent)
            node = _read_node(path)
            if node.kind == "dir":
                continue
            if node.kind != "absent":
                raise ApplyError("parent_unsafe", parent, EXIT_ROLLED_BACK)
            mode = 0o700 if parent == ".cab" or parent.startswith(".cab/") else 0o755
            self.ops.mkdir(path, mode)
            self.journal.append(_Entry("mkdir", parent))
            if _read_node(path).kind != "dir":
                raise ApplyError("parent_unsafe", parent, EXIT_ROLLED_BACK)

    def write(self, rel: str, data: bytes, mode: int, prior: Node) -> None:
        self.make_parents(rel)
        self.journal.append(_Entry("write", rel, prior, data, mode))
        self.ops.write(_abs(self.root, rel), data, mode)

    def remove(self, rel: str, prior: Node) -> None:
        self.journal.append(_Entry("remove", rel, prior))
        self.ops.unlink(_abs(self.root, rel))

    def prune(self, rels: Iterable[str]) -> None:
        """Remove now-empty owned folders left by removals (deepest first)."""
        dirs: set[str] = set()
        for rel in rels:
            for parent in _ancestors(rel):
                if any(parent.startswith(r + "/") for r in PRUNE_ROOTS):
                    dirs.add(parent)
        for rel in sorted(dirs, key=lambda r: -r.count("/")):
            path = _abs(self.root, rel)
            node = _read_node(path)
            if node.kind != "dir":
                continue
            try:
                with os.scandir(path) as entries:
                    if next(entries, None) is not None:
                        continue
            except OSError:
                continue
            self.journal.append(_Entry("rmdir", rel, mode=node.mode))
            self.ops.rmdir(path)

    def backup(self, stamp: str, rels: Iterable[str], nodes: Mapping[str, Node], op: str) -> str:
        """Copy affected live files (bytes and mode) into ``.cab/backups/<stamp>/``."""
        _ensure_private_dir(self.root, BACKUPS_REL)
        base = None
        for n in range(100):
            name = stamp if n == 0 else f"{stamp}-{n}"
            rel = f"{BACKUPS_REL}/{name}"
            try:
                os.mkdir(_abs(self.root, rel), 0o700)
            except FileExistsError:
                continue
            base = rel
            break
        if base is None:
            raise ApplyError("backup_failed", BACKUPS_REL)
        index: dict[str, Any] = {}
        for rel in sorted(set(rels)):
            node = nodes.get(rel)
            if node is None or node.kind != "file":
                continue
            target = f"{base}/files/{rel}"
            _ensure_private_dir(self.root, target.rsplit("/", 1)[0])
            fsutil.atomic_write(_abs(self.root, target), node.data, mode=node.mode)  # type: ignore[arg-type]
            index[rel] = {"sha256": sha256_hex(node.data), "mode": oct(node.mode or 0)}  # type: ignore[arg-type]
        doc = {"kind": "cab-of-one-backup", "schema": 1, "operation": op, "files": index}
        data = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("ascii")
        fsutil.atomic_write(_abs(self.root, f"{base}/index.json"), data, mode=0o600)
        self.backup_rel = base
        return base

    # -- rollback

    def _drop_selftest_residue(self, state_dir: str) -> None:
        """The self test leaves an empty ``selftest`` folder in a state folder that this
        apply created; only that exact empty folder is removed."""
        residue = os.path.join(state_dir, "selftest")
        if _read_node(residue).kind != "dir":
            return
        with os.scandir(residue) as entries:
            if next(entries, None) is not None:
                return
        self.ops.rmdir(residue)

    def rollback(self) -> list[str]:
        """Undo the journal in reverse. Returns the paths that could not be restored."""
        failed: list[str] = []
        for entry in reversed(self.journal):
            path = _abs(self.root, entry.rel)
            try:
                if entry.op == "write":
                    if entry.prior is not None and entry.prior.kind == "file":
                        if not self._parents_ok(entry.rel):
                            raise OSError("parent")
                        current = _read_node(path)
                        if current.kind not in ("file", "absent"):
                            raise OSError("target")
                        if current != entry.prior:
                            self.ops.write(path, entry.prior.data, entry.prior.mode)  # type: ignore[arg-type]
                    else:
                        current = _read_node(path)
                        if current.kind == "absent":
                            continue
                        if current.kind != "file" or current.data != entry.new:
                            raise OSError("changed")
                        self.ops.unlink(path)
                elif entry.op == "remove":
                    if entry.prior is None or entry.prior.kind != "file":
                        raise OSError("prior")
                    if not self._parents_ok(entry.rel):
                        raise OSError("parent")
                    current = _read_node(path)
                    if current != entry.prior:
                        if current.kind != "absent":
                            raise OSError("target")
                        self.ops.write(path, entry.prior.data, entry.prior.mode)  # type: ignore[arg-type]
                elif entry.op == "mkdir":
                    node = _read_node(path)
                    if node.kind == "absent":
                        continue
                    if node.kind != "dir":
                        raise OSError("target")
                    if entry.rel == STATE_REL:
                        self._drop_selftest_residue(path)
                    self.ops.rmdir(path)
                elif entry.op == "rmdir":
                    if _read_node(path).kind == "absent":
                        self.ops.mkdir(path, entry.mode or 0o755)
                after = _read_node(path)
                if entry.op in ("write", "remove") and entry.prior is not None:
                    expect = entry.prior if entry.prior.kind == "file" else Node("absent")
                    if after != expect:
                        raise OSError("verify")
            except Exception:
                failed.append(entry.rel)
        return failed


def _stamp(services: Services) -> tuple[str, str]:
    now = services.clock()
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.UTC)
    now = now.astimezone(datetime.UTC)
    return now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mode_for(rel: str, prior: Node) -> int:
    mode = prior.mode if prior.kind == "file" and prior.mode is not None else 0o644
    if rel in EXECUTABLE_PATHS:
        mode = (mode | 0o700 | ((mode & 0o044) >> 2)) if prior.kind == "file" else 0o755
    return mode


def _failure_lines(code: str, failed: list[str], backup: str | None) -> list[str]:
    if not failed:
        return [
            f"cab setup: {code}. Every change was rolled back to the exact earlier bytes and "
            "modes; the manifest is unchanged.",
            f"  backup kept at {backup}" if backup else "  no backup was needed",
        ]
    lines = [f"cab setup: {code}. ROLLBACK FAILED for {len(failed)} path(s):"]
    lines += [f"  not restored: {rel}" for rel in failed]
    lines.append(
        f"  restore these by hand from {backup}/files/ (index.json holds hashes and modes)."
        if backup
        else "  no backup folder was created."
    )
    lines.append("  The manifest was not updated. Do not start a Claude Code session here yet.")
    return lines


# --------------------------------------------------------------------------- apply


@dataclass(frozen=True)
class _Prepared:
    root: str
    name: str
    provenance: Provenance
    provenance_raw: bytes
    profile: profile_mod.Profile
    bundle: render.Bundle
    manifest: Manifest | None
    manifest_node: Node
    nodes: Mapping[str, Node]
    preflight: Preflight
    plan: merge.MergePlan
    take_new: tuple[str, ...]
    runtime: Check
    git: Check

    def fingerprint(self) -> tuple[Any, ...]:
        p = self.preflight
        return (
            dict(self.nodes),
            self.manifest_node,
            self.provenance_raw,
            self.bundle.digest(),
            self.plan.actions,
            self.plan.blockers,
            self.plan.conflicts,
            self.plan.manifest,
            (p.scopes, p.blockers, p.version),
            self.runtime,
            self.git,
        )


def _load_manifest(root: str) -> tuple[Manifest | None, Node]:
    nodes = inspect_tree(root, [MANIFEST_REL])
    node = nodes[MANIFEST_REL]
    if nodes[".cab"].kind not in ("dir", "absent"):
        raise ApplyError("manifest_unsafe", ".cab")
    if node.kind == "absent":
        return None, node
    if node.kind != "file":
        raise ApplyError("manifest_unsafe", MANIFEST_REL)
    try:
        return load_manifest(node.data), node  # type: ignore[arg-type]
    except ManifestError as exc:
        raise ApplyError("manifest_invalid", exc.code) from None


def _load_render_profile(root: str, source_root: str, prov: Provenance) -> profile_mod.Profile:
    if prov.source == "reference":
        prof = profile_mod.load_reference_profile(prov.name, source_root)  # type: ignore[arg-type]
    else:
        node = inspect_tree(root, [PROFILE_COPY_REL])[PROFILE_COPY_REL]
        if node.kind != "file":
            raise ApplyError("profile_copy_missing", PROFILE_COPY_REL)
        prof = profile_mod.load_profile(node.data)  # type: ignore[arg-type]
    if prof.sha256 != prov.profile_sha256:
        raise ApplyError("profile_changed", "re-run cab setup render")
    return prof


def _prepare(
    root: str, source_root: str, services: Services, take_new: tuple[str, ...]
) -> _Prepared:
    head = inspect_tree(root, [PROVENANCE_REL])
    raw_node = head[PROVENANCE_REL]
    if raw_node.kind == "absent":
        raise ApplyError("render_missing", "run cab setup render first")
    if raw_node.kind != "file":
        raise ApplyError("provenance_unsafe", PROVENANCE_REL)
    prov = parse_provenance(raw_node.data)  # type: ignore[arg-type]
    if prov.generator_version != GENERATOR_VERSION:
        raise ApplyError("generator_version_changed", "re-run cab setup render")
    prof = _load_render_profile(root, source_root, prov)
    bundle = render.render_bundle(prof, source_root)
    render.verify_floor(bundle)
    if bundle.digest() != prov.bundle_sha256 or bundle.modules != prov.modules:
        raise ApplyError("bundle_changed", "re-run cab setup render")
    if read_staged(root) != dict(bundle):
        raise ApplyError("staged_mismatch", STAGED_REL)
    data = merge_bundle(bundle)
    manifest, manifest_node = _load_manifest(root)
    nodes = inspect_tree(root, [*merge.paths_to_inspect(data, manifest), SETTINGS_LOCAL_PATH])
    pre = measure_preflight(root, nodes, services)
    common = {
        "manifest": manifest,
        "generator_version": GENERATOR_VERSION,
        "profile_sha256": prof.sha256,
        "scopes": pre.scopes,
    }
    existing = _existing(nodes)
    plan = merge.plan_merge(data, existing, **common)
    if take_new:
        for path in take_new:
            try:
                check_rel_path(path)
            except SetupDataError:
                raise ApplyError("take_new_invalid", path[:200]) from None
            if path not in plan.resolvable:
                raise ApplyError("take_new_not_resolvable", path)
        plan = merge.plan_merge(data, existing, take_new=take_new, **common)
    return _Prepared(
        root=root,
        name=os.path.basename(root),
        provenance=prov,
        provenance_raw=raw_node.data,  # type: ignore[arg-type]
        profile=prof,
        bundle=bundle,
        manifest=manifest,
        manifest_node=manifest_node,
        nodes=nodes,
        preflight=pre,
        plan=plan,
        take_new=take_new,
        runtime=services.probe_runtime(root),
        git=git_check(root, services),
    )


def _blockers(prep: _Prepared) -> list[str]:
    out = [f"  blocked: {b}" for b in prep.preflight.blockers]
    out += _issue_lines("blocked", prep.plan.blockers)
    if prep.git.status == FAIL:
        out.append(f"  blocked: {prep.git.code} ({prep.git.detail})")
        if prep.git.code == "private_state_tracked":
            out.append(
                "  next: untrack them yourself (for example `git rm -r --cached .cab/state "
                ".cab/backups .cab/setup`, which keeps the files), commit, then apply again. "
                "Setup never edits the Git index."
            )
    if prep.plan.actions and prep.runtime.status != PASS:
        out.append(
            f"  blocked: runtime {prep.runtime.code}: a change may be active or in flight; "
            "close it (or check `cab status`) before controls are replaced."
        )
    return out


def _plan_summary(prep: _Prepared, verb: str = "apply") -> list[str]:
    lines = [f"cab-of-one setup {verb}: project {prep.name}", f"  folder: {prep.root}"]
    lines += _profile_lines(prep.provenance, prep.profile)
    lines += _preflight_lines(prep.preflight, prep.runtime, prep.git)
    plan = prep.plan
    lines.append(f"plan: {len(plan.actions)} action(s)")
    lines += _action_lines(plan.actions, prep.nodes)
    lines += _issue_lines("conflict", plan.conflicts)
    for path in plan.resolvable:
        lines.append(f"  resolvable with --take-new {path} (see {path}.cab-new)")
    for path in prep.take_new:
        lines.append(f"  take-new selected: {path} (replaces your version; it is backed up)")
    lines += _issue_lines("note", plan.notes)
    lines += [f"  notice: {n}" for n in prep.bundle.notices]
    return lines


def _ordered(actions: Iterable[merge.Action]) -> list[merge.Action]:
    """Files first, settings (which registers the hooks) last."""
    return sorted(actions, key=lambda a: (a.path == SETTINGS_PATH, a.path))


def _end_session(root: str) -> str:
    lookup = session_mod.load(root)
    if lookup.status == "absent":
        return "setup session: none bound"
    if lookup.status != "bound" or lookup.session_id is None:
        return f"setup session: marker {lookup.code or 'malformed'}; left for a person to check"
    try:
        session_mod.end(root, lookup.session_id)
    except session_mod.SessionError as exc:
        return f"setup session: not ended ({exc.code})"
    return "setup session: ended (start a new Claude Code session)"


def _frontmatter(data: bytes) -> bytes | None:
    """The leading ``---`` block with both fences, exactly as written; None when the file
    does not start with a fence line or the block is never closed."""
    lines = data.splitlines(keepends=True)
    if not lines or lines[0] not in (b"---\n", b"---\r\n"):
        return None
    for index, line in enumerate(lines[1:], start=1):
        if line.rstrip(b"\r\n") == b"---":
            return b"".join(lines[: index + 1])
    return None


def _injection_lines(body: bytes) -> set[bytes]:
    return {line.strip() for line in body.splitlines() if SHELL_INJECTION in line}


def edit_can_be_kept(rel: str, edited: bytes, generated: bytes) -> bool:
    """True only when a person's edit of the owned file ``rel`` cannot change a tool,
    hook, permission or trusted script, so that it may stay beside a ``.cab-new`` proposal.

    - agents and skills: a ``.md`` file whose edited bytes start with the generated
      frontmatter, byte for byte, and whose body adds no ``!`...``` line;
    - the exact owned non-code files (``docs/identity.md``, the demo seed);
    - everything else (pinned hooks and runtime, other files in a skill folder, the
      trusted demo script): never.
    """
    if rel.startswith(FRONTMATTER_PREFIXES):
        front = _frontmatter(generated)
        if not rel.endswith(".md") or front is None or not edited.startswith(front):
            return False
        added = _injection_lines(edited[len(front) :]) - _injection_lines(generated[len(front) :])
        return not added
    return rel in OWNED_FILES and rel not in KNOWN_CONFLICT_NEVER


def _known_conflicts(root: str, prep: _Prepared, manifest: Manifest) -> dict[str, str]:
    """Owned paths whose doctor ``manifest_mismatch`` is this plan's own G7 conflict.

    Evidence, all required per path: the plan reports ``owned_modified`` for it; the old
    and the new manifest record the same SHA-256 (the generator's last bytes); the bytes
    confirmed before the prompt differ from that hash and are still exactly on disk (apply
    did not touch them and nobody changed them since); ``<path>.cab-new`` holds exactly
    the generated bytes; and ``edit_can_be_kept`` allows the edit. Anything else stays a
    floor failure.
    """
    previous = prep.manifest
    if previous is None:
        return {}
    generated_all = merge_bundle(prep.bundle)
    known: dict[str, str] = {}
    for issue in prep.plan.conflicts:
        rel = issue.path
        if issue.code != "owned_modified":
            continue
        digest = manifest.files.get(rel)
        before = prep.nodes.get(rel)
        generated = generated_all.get(rel)
        if digest is None or previous.files.get(rel) != digest or generated is None:
            continue
        if before is None or before.kind != "file" or before.data is None:
            continue
        if sha256_hex(before.data) == digest:
            continue
        now = _read_node(_abs(root, rel))
        proposal = _read_node(_abs(root, rel + PROPOSAL_SUFFIX))
        if now.kind != "file" or now.data != before.data:
            continue
        if proposal.kind != "file" or proposal.data != generated:
            continue
        if edit_can_be_kept(rel, before.data, generated):
            known[rel] = rel + PROPOSAL_SUFFIX
    return known


def _doctor(
    root: str, prep: _Prepared, manifest: Manifest
) -> tuple[list[str], list[str], doctor_mod.DoctorReport]:
    """Run the static doctor on the written project. Returns (fatal, other, report).

    A FAIL on a floor check is fatal, with one exception: ``manifest`` /
    ``manifest_mismatch`` for a path in ``_known_conflicts`` (a person's kept edit with the
    proposal written). It is reported, never counted as PASS. Every other manifest FAIL
    (missing, unsafe, a mismatch anywhere else) stays fatal.
    """
    known = _known_conflicts(root, prep, manifest)
    layers = list(doctor_mod.read_project_layers(root))
    if prep.preflight.user_layer is not None:
        layers.append(prep.preflight.user_layer)
    if prep.preflight.managed_layer is not None:
        layers.append(prep.preflight.managed_layer)
    report = doctor_mod.inspect_project(
        root,
        layers,
        version=prep.preflight.version,
        min_version=MIN_CLAUDE_CODE,
        manifest=dict(manifest.files),
        required_deny=render.FLOOR_DENY,
        fail_closed_events=FAIL_CLOSED_EVENTS,
    )
    fatal, other = [], []
    for issue in report.issues:
        if issue.status == doctor_mod.PASS:
            continue
        subject = f" ({issue.subject})" if issue.subject else ""
        line = f"  doctor {issue.status}: {issue.check} {issue.code}{subject}"
        if (
            issue.status == doctor_mod.FAIL
            and issue.check == "manifest"
            and issue.code == "manifest_mismatch"
            and issue.subject in known
        ):
            other.append(
                f"  doctor known conflict: {issue.subject} differs from its manifest hash "
                f"(your edit is kept; proposal {known[issue.subject]}; adopt it with "
                f"--take-new {issue.subject})"
            )
        elif issue.status == doctor_mod.FAIL and issue.check in FLOOR_CHECKS:
            fatal.append(line)
        else:
            other.append(line)
    return fatal, other, report


def _verify_written(
    root: str, actions: Iterable[merge.Action], extra: Mapping[str, bytes]
) -> list[str]:
    bad = []
    for action in actions:
        node = _read_node(_abs(root, action.path))
        if action.kind == "remove":
            if node.kind != "absent":
                bad.append(action.path)
        elif node.kind != "file" or node.data != action.data:
            bad.append(action.path)
    for rel, data in extra.items():
        node = _read_node(_abs(root, rel))
        if node.kind != "file" or node.data != data:
            bad.append(rel)
    return bad


def _execute_apply(prep: _Prepared, services: Services) -> Outcome:
    root = prep.root
    stamp, iso = _stamp(services)
    plan = prep.plan
    assert plan.manifest is not None
    manifest = replace(plan.manifest, applied_at=iso)
    manifest_bytes = dump_manifest(manifest)
    tx = _Transaction(root, services.fileops)
    affected = [a.path for a in plan.actions if a.kind != "create"] + [MANIFEST_REL]
    nodes = dict(prep.nodes)
    nodes[MANIFEST_REL] = prep.manifest_node
    verify_lines: list[str] = []
    other: list[str] = []
    try:
        tx.backup(stamp, affected, nodes, "apply")
        removed: list[str] = []
        for action in _ordered(plan.actions):
            prior = prep.nodes.get(action.path, Node("absent"))
            tx.cas(action.path, prior)
            if action.kind == "remove":
                tx.remove(action.path, prior)
                removed.append(action.path)
            else:
                tx.write(action.path, action.data, _mode_for(action.path, prior), prior)  # type: ignore[arg-type]
        tx.prune(removed)
        state = inspect_tree(root, [STATE_REL])[STATE_REL]
        if state.kind == "absent":
            tx.make_parents(STATE_REL + "/x")
        elif state.kind != "dir":
            raise ApplyError("runtime_state_unsafe", STATE_REL, EXIT_ROLLED_BACK)
        tx.cas(MANIFEST_REL, prep.manifest_node)
        tx.write(
            MANIFEST_REL, manifest_bytes, _mode_for(MANIFEST_REL, prep.manifest_node),
            prep.manifest_node,
        )  # fmt: skip
        bad = _verify_written(root, plan.actions, {MANIFEST_REL: manifest_bytes})
        if bad:
            verify_lines += [f"  written bytes differ: {rel}" for rel in bad]
        fatal, other, _ = _doctor(root, prep, manifest)
        verify_lines += fatal
        check = services.run_selftest(root)
        if check.status != PASS:
            verify_lines.append(
                f"  guard self test: {check.status} {check.code} (success requires PASS)"
            )
            selftest_line = ""
        else:
            selftest_line = f"guard self test: PASS {check.code}" + (
                f" [{check.detail}]" if check.detail else ""
            )
        if verify_lines:
            raise ApplyError("verification_failed", "", EXIT_ROLLED_BACK)
    except BaseException as exc:
        failed = tx.rollback()
        code = exc.code if isinstance(exc, ApplyError) else type(exc).__name__
        lines = _failure_lines(f"apply failed ({code})", failed, tx.backup_rel)
        lines += verify_lines
        if isinstance(exc, ApplyError) and exc.detail:
            lines.append(f"  at: {exc.detail}")
        if not isinstance(exc, Exception):
            err = services.err()
            for line in lines:
                _say(err, sanitize(line))
            raise
        return Outcome(
            EXIT_ROLLBACK_FAILED if failed else EXIT_ROLLED_BACK, "rolled_back", tuple(lines)
        )
    lines = [
        f"applied: {len(plan.actions)} change(s); manifest written {MANIFEST_REL}",
        f"  backup: {tx.backup_rel}",
        "  doctor: no failing floor check",
        f"  {selftest_line}",
    ]
    lines += other
    lines += [f"  UNKNOWN (not measured): {u}" for u in prep.preflight.unknown]
    lines += _issue_lines("conflict (proposal written)", plan.conflicts)
    lines.append("  " + _end_session(root))
    return Outcome(EXIT_OK, "applied", tuple(lines))


def apply_project(
    project: str,
    *,
    source_root: str,
    services: Services,
    take_new: Sequence[str] = (),
) -> Outcome:
    """Person-only apply of the staged render (see module doc).

    Stale or unsafe inputs (render missing, staged/profile/version/bundle changed, unsafe
    manifest or staged tree, invalid ``--take-new``, lock held) raise ``ApplyError`` before
    any project write. Plans that are blocked, not confirmed, applied or rolled back are
    returned as an ``Outcome``.
    """
    root = project_root(project)
    picks = tuple(dict.fromkeys(take_new))
    setup = inspect_tree(root, [SETUP_REL])
    if setup[".cab"].kind != "dir" or setup[SETUP_REL].kind != "dir":
        if setup[SETUP_REL].kind == "absent":
            raise ApplyError("render_missing", "run cab setup render first")
        raise ApplyError("setup_dir_unsafe", SETUP_REL)
    try:
        with fsutil.locked(_abs(root, f"{SETUP_REL}/{LOCK_NAME}"), services.lock_timeout):
            prep = _prepare(root, source_root, services, picks)
            summary = _plan_summary(prep)
            blocked = _blockers(prep)
            if blocked:
                return Outcome(EXIT_BLOCKED, "blocked", tuple(summary + ["BLOCKED:"] + blocked))
            if prep.plan.nothing_to_do:
                lines = summary + ["nothing to do: the project already matches this render."]
                lines.append("  " + _end_session(root))
                return Outcome(EXIT_OK, "nothing_to_do", tuple(lines))
            check = confirm_project_name(
                prep.name,
                summary,
                stdin=services.inp(),
                stdout=services.out(),
                stderr=services.err(),
                osx=services.osx,
            )
            if check.status != PASS:
                return _confirm_outcome(check)
            again = _prepare(root, source_root, services, picks)
            if again.fingerprint() != prep.fingerprint() or _blockers(again):
                return Outcome(
                    EXIT_REFUSED,
                    "changed_during_prompt",
                    ("cab setup: refused: the project, staged files, profile or settings "
                     "changed while the prompt was open. Nothing was written. Run render "
                     "and apply again.",),
                )  # fmt: skip
            return _execute_apply(again, services)
    except fsutil.LockTimeout:
        raise ApplyError(
            "apply_in_progress", "another setup command holds the lock", EXIT_BLOCKED
        ) from None
    except fsutil.SymlinkRefused:
        raise ApplyError("setup_dir_unsafe", f"{SETUP_REL}/{LOCK_NAME}") from None


# --------------------------------------------------------------------------- render


def render_project(
    project: str,
    *,
    source_root: str,
    services: Services,
    profile_path: str | None = None,
    reference: str | None = None,
) -> Outcome:
    """Render, plan read-only, and stage under ``.cab/setup`` only (G5)."""
    root = project_root(project)
    if reference is not None and profile_path is not None:
        raise ApplyError("profile_source_ambiguous", "", EXIT_USAGE)
    if reference is not None:
        prof = profile_mod.load_reference_profile(reference, source_root)
        prov_source, prov_name = "reference", reference
    else:
        path = profile_path if profile_path is not None else _abs(root, DEFAULT_PROFILE_REL)
        prof = profile_mod.load_profile(path)
        prov_source, prov_name = "file", None
    bundle = render.render_bundle(prof, source_root)
    render.verify_floor(bundle)
    data = merge_bundle(bundle)
    try:
        manifest, _ = _load_manifest(root)
        manifest_note = None
    except ApplyError as exc:
        manifest, manifest_note = None, f"  blocked: {exc.code} ({exc.detail})"
    nodes = inspect_tree(root, [*merge.paths_to_inspect(data, manifest), SETTINGS_LOCAL_PATH])
    pre = measure_preflight(root, nodes, services, with_commands=False)
    plan = merge.plan_merge(
        data,
        _existing(nodes),
        manifest=manifest,
        generator_version=GENERATOR_VERSION,
        profile_sha256=prof.sha256,
        scopes=pre.scopes,
    )
    prov = Provenance(
        prov_source, prov_name, prof.sha256, GENERATOR_VERSION, bundle.digest(), bundle.modules
    )
    lines = [f"cab-of-one setup render: project {os.path.basename(root)}"]
    lines += _profile_lines(prov, prof)
    lines += _preflight_lines(pre, None, None)
    lines.append(f"plan preview: {len(plan.actions)} action(s) (apply re-checks everything)")
    lines += _action_lines(plan.actions, nodes)
    lines += _issue_lines("conflict", plan.conflicts)
    lines += _issue_lines("note", plan.notes)
    lines += [f"  notice: {n}" for n in bundle.notices]
    blocked = [f"  blocked: {b}" for b in pre.blockers] + _issue_lines("blocked", plan.blockers)
    if manifest_note:
        blocked.append(manifest_note)

    # Stage: only .cab/setup is written, under the same lock as apply. Old provenance goes
    # first, new provenance last, so a crash in between leaves a staged tree that apply
    # refuses (no provenance).
    _ensure_private_dir(root, SETUP_REL)
    try:
        with fsutil.locked(_abs(root, f"{SETUP_REL}/{LOCK_NAME}"), services.lock_timeout):
            _stage(root, bundle, prof, prov, lines, blocked)
    except fsutil.LockTimeout:
        raise ApplyError(
            "apply_in_progress", "another setup command holds the lock", EXIT_BLOCKED
        ) from None
    except fsutil.SymlinkRefused:
        raise ApplyError("setup_dir_unsafe", f"{SETUP_REL}/{LOCK_NAME}") from None
    lines.append(f"staged: {STAGED_REL} ({len(bundle)} files), plan: {PLAN_REL}")
    if blocked:
        lines += ["BLOCKED (apply will refuse until this is fixed):"] + blocked
        return Outcome(EXIT_BLOCKED, "rendered_blocked", tuple(lines))
    lines.append(
        "next: in your own terminal, in this folder, run the setup apply command of this "
        "plugin (python3 <plugin folder>/scripts/cab setup apply)."
    )
    return Outcome(EXIT_OK, "rendered", tuple(lines))


def _stage(
    root: str,
    bundle: render.Bundle,
    prof: profile_mod.Profile,
    prov: Provenance,
    lines: list[str],
    blocked: list[str],
) -> None:
    _setup_unlink(root, PROVENANCE_REL)
    staged = _abs(root, STAGED_REL)
    old = None
    if _lstat(staged) is not None:
        if not _real_dir_chain(root, STAGED_REL):
            raise ApplyError("staged_unsafe", STAGED_REL)
        for n in range(100):
            candidate = _abs(root, f"{SETUP_REL}/staged.old-{n}")
            if _lstat(candidate) is None:
                os.rename(staged, candidate)
                old = candidate
                break
        if old is None:
            raise ApplyError("staged_unsafe", "too many old staged folders")
    try:
        render.stage_bundle(bundle, root)
    except BaseException:
        if old is not None and _lstat(staged) is None:
            os.rename(old, staged)
        raise
    if old is not None:
        _remove_tree(old)
    if prov.source == "file":
        _setup_write(root, PROFILE_COPY_REL, prof.canonical_toml())
    else:
        _setup_unlink(root, PROFILE_COPY_REL)
    plan_text = ["# cab-of-one setup plan (generated by render; redacted)", ""]
    plan_text += [sanitize(line) for line in lines]
    if blocked:
        plan_text += ["", "BLOCKED (apply will refuse):"] + [sanitize(b) for b in blocked]
    _setup_write(root, PLAN_REL, ("\n".join(plan_text) + "\n").encode("utf-8"))
    _setup_write(root, PROVENANCE_REL, prov.to_bytes())


# --------------------------------------------------------------------------- config verifier

# ``manifest_verifier`` (exported above) is ``runtime.config_lock.manifest_verifier`` itself,
# imported, not wrapped: one implementation of the ConfigChange contract
# ``(project_root, rel) -> bool``. It checks the settings floor against the file itself
# (``floor_gap``: deny rules and every floor hook, also ones a person had before the first
# apply and so never recorded), then the manifest records, and reads every component with
# ``dir_fd`` + ``O_NOFOLLOW`` (no parent swap race). The earlier S9 copy here checked only
# recorded contributions and opened by path after ``lstat``; it was removed (S10 §4).
