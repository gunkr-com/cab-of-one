"""S5 read runner: validate a ``[[verify]]`` probe, run it bounded, observe and compare.

DESIGN §3-7 layer 1 and S5_IMPLEMENT_CONTRACT §3 (with the S5_CONTRACT_ACCEPTANCE
corrections). Standard library only.

Only one probe form is ever executed: a literal ``simtenant get`` of exactly the planned
target and state scope, through a policy-trusted script inside the project. Everything
else (bare commands, pwsh, az, Graph, writes, lists, other targets or scopes, unsafe
scripts) is ``Unmeasured`` and the runner is never called for it.

Execution (``SubprocessRunner``):

- ``[sys.executable, "-I", <script realpath>, *args]``, ``shell=False``, ``cwd`` = project,
  stdin and stderr ``/dev/null``, a new session (own process group), ``close_fds``, and a
  fixed minimal environment, so no credentials or ``PYTHON*`` settings are inherited.
- stdout is collected with ``select`` + ``os.read`` against a deadline and a byte cap
  *while it is read*; on either limit the whole process group is killed. ``communicate()``
  is never used.

Observation and comparison:

- stdout must be exactly one non-empty line holding one strict JSON object (no NaN,
  Infinity, out-of-range floats or duplicate keys); anything else is ``output_shape``.
- exit 0 + ``ok: true`` + matching ``get`` response -> ``active`` / ``soft_deleted``;
  exit 3 + ``not_found`` for exactly the target -> ``absent``; anything else is
  ``unexpected_response``.
- Checks run on the raw response; ``eq``/``ne``/membership compare canonical JSON, so
  ``true != 1`` and ``1 != 1.0``. Only redacted values leave this module.

Public values (argv, human command, ``checked`` texts, snapshot objects, hashes) always pass
through the project redactor (``redact_value``). There is no unredacted fallback: if the
redactor cannot be found, ``RedactionUnavailable`` is raised and callers fail closed.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import math
import os
import posixpath
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from . import fsutil, schema
from .adapters import simtenant as simtenant_adapter
from .classification_types import KIND_READ, leaves
from .classify import MAX_SCRIPT_BYTES, classify_tool_call

__all__ = [
    "CHILD_ENV",
    "DEFAULT_RETRY_SECONDS",
    "MATCH",
    "MAX_STDOUT",
    "MISMATCH",
    "RUN_TIMEOUT",
    "TOTAL_BUDGET",
    "UNMEASURABLE",
    "Clock",
    "ExecSpec",
    "RedactionUnavailable",
    "RunResult",
    "Runner",
    "SubprocessRunner",
    "SystemClock",
    "Unmeasured",
    "compare",
    "display_command",
    "observe",
    "project_root",
    "recheck",
    "redact",
    "state_file_safe",
    "unmeasured_observation",
    "validate",
]

RUN_TIMEOUT = 5.0
MAX_STDOUT = 1 << 20
TOTAL_BUDGET = 100.0
DEFAULT_RETRY_SECONDS: tuple[int, ...] = (2, 5, 10, 20, 40)

MAX_ARGV = 32
MAX_ARG_CHARS = 512
MAX_HUMAN_COMMAND = 2048
MAX_CHECKS = 16
MAX_CHECKED_CHARS = 1024
MAX_VALUE_JSON_BYTES = 1024
MAX_VALUE_DEPTH = 8
MAX_POINTER_TOKENS = 8
MAX_POINTER_TOKEN_CHARS = 64
MAX_POINTER_CHARS = MAX_POINTER_TOKENS * (MAX_POINTER_TOKEN_CHARS + 1)
MAX_RESPONSE_DEPTH = 64

CHILD_ENV: Mapping[str, str] = {"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC"}
_READ_CHUNK = 64 * 1024
_REAP_TIMEOUT = 5.0

STATUS_ACTIVE = "active"
STATUS_SOFT_DELETED = "soft_deleted"
STATUS_ABSENT = "absent"
STATUS_UNMEASURED = "unmeasured"
EXPECTS = frozenset({STATUS_ACTIVE, STATUS_SOFT_DELETED, STATUS_ABSENT})
OPS = frozenset({"eq", "ne", "contains", "not_contains"})

MATCH = "match"
MISMATCH = "mismatch"
UNMEASURABLE = "unmeasurable"

# Reason codes (UNMEASURED never folds into PASS or FAIL).
R_PROBE_NOT_READ = "probe_not_read"
R_PROBE_TARGET_MISMATCH = "probe_target_mismatch"
R_PROBE_INVALID = "probe_invalid"
R_SCOPE_MISMATCH = "scope_mismatch"
R_SCOPE_UNSAFE = "scope_unsafe"
R_RUNNER_UNSUPPORTED = "runner_unsupported"
R_NO_RUNNER = "no_runner"
R_SCRIPT_UNSAFE = "script_unsafe"
R_SCRIPT_CHANGED = "script_changed"
R_POLICY_INVALID = "policy_invalid"
R_OUTPUT_SHAPE = "output_shape"
R_UNEXPECTED_RESPONSE = "unexpected_response"
R_PATH_MISSING = "path_missing"
R_NOT_A_LIST = "not_a_list"
R_CHECK_INVALID = "check_invalid"
R_TIMEOUT = "timeout"
R_OUTPUT_TOO_LARGE = "output_too_large"
R_SPAWN_ERROR = "spawn_error"
RUNNER_ERRORS = frozenset({R_TIMEOUT, R_OUTPUT_TOO_LARGE, R_SPAWN_ERROR})

# Top-level project folders a probe script may never live in (harness state, evidence,
# controls). Integration note: replace with the paths module's protected set once A lands.
PROTECTED_TOP = frozenset({".cab", ".claude", ".git", "audit", "changes", "policy"})

_PYTHON_RE = re.compile(r"^python(\d+(\.\d+)?)?$")
_PY_FLAGS = frozenset(
    {"-I", "-B", "-u", "-E", "-s", "-S", "-O", "-OO", "-q", "-b", "-bb", "-d", "-v", "-x", "-R"}
)
_PY_VALUED = frozenset({"-W", "-X"})
_INDEX_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_CTL_RE = re.compile(r"[\x00-\x1f\x7f]")


class RedactionUnavailable(RuntimeError):
    """The project redactor is missing; nothing public may be produced."""


# --------------------------------------------------------------------------- data


@dataclass(frozen=True)
class ExecSpec:
    """A validated probe, ready to run. ``vector`` is the exact argv given to the runner."""

    vector: tuple[str, ...]
    script_real: str
    script_id: tuple[int, int]
    scope: str
    target: str
    display_argv: tuple[str, ...]
    human_command: str
    script_sha256: str


@dataclass(frozen=True)
class Unmeasured:
    """A probe that is not run. ``human_command`` is the exact redacted command to give a
    person; ``display_argv`` is its redacted argv (``human_command == shlex.join``)."""

    reason: str
    human_command: str
    display_argv: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunResult:
    """``error`` is ``timeout``, ``output_too_large`` or ``spawn_error`` (then ``stdout`` is
    None). ``exit`` is None when the process ended by a signal or never ran."""

    exit: int | None
    stdout: bytes | None
    error: str | None


class Runner(Protocol):
    def run(
        self, vector: Sequence[str], *, cwd: str, timeout: float, max_stdout: int
    ) -> RunResult: ...


class Clock(Protocol):
    def now(self) -> float: ...

    def monotonic(self) -> float: ...

    def sleep(self, s: float) -> None: ...


class SystemClock:
    """Wall clock for real runs (epoch ``now``, monotonic deadlines, real sleeps)."""

    def now(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, s: float) -> None:
        time.sleep(s)


# --------------------------------------------------------------------------- integration seams


def _resolve_redactor() -> Callable[[Any], Any]:
    for name in ("schema", "ledger"):
        try:
            module = importlib.import_module(f"{__package__}.{name}")
        except Exception:  # noqa: BLE001 - a broken module is simply not a redactor
            continue
        fn = getattr(module, "redact_value", None)
        if callable(fn):
            return fn
    raise RedactionUnavailable("redact_value is not available")


def redact(value: Any) -> Any:
    """Redact ``value`` with the project redactor. Never returns the input unredacted."""
    return _resolve_redactor()(value)


def project_root(roots: Any) -> str:
    """Absolute project root of ``roots`` (assumed attribute ``project``)."""
    value = getattr(roots, "project", None)
    text = os.fspath(value) if value is not None else ""
    if not isinstance(text, str) or not text or not os.path.isabs(text):
        raise ValueError("roots.project is not an absolute path")
    return text


def state_file_safe(roots: Any, scope: str) -> bool:
    """``paths.state_file_safe(roots, scope)``; any error or a missing function is unsafe."""
    try:
        from . import paths

        fn = getattr(paths, "state_file_safe", None)
        if not callable(fn):
            return False
        return bool(fn(roots, scope))
    except Exception:  # noqa: BLE001 - fail closed
        return False


# --------------------------------------------------------------------------- public text


def _clean(text: str, limit: int) -> str:
    text = _CTL_RE.sub(" ", text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def display_command(argv: Sequence[Any]) -> tuple[tuple[str, ...], str]:
    """Redacted display argv and ``shlex.join`` of it, both within the observation bounds."""
    words = [w if isinstance(w, str) else repr(w) for w in list(argv)[:MAX_ARGV]]
    if not words:
        words = ["(no probe command)"]
    red = redact(words)
    if not isinstance(red, list | tuple) or not all(isinstance(w, str) for w in red):
        raise RedactionUnavailable("redactor did not return a list of strings")
    shown = tuple(_clean(w, MAX_ARG_CHARS) or "''" for w in red)
    human = _clean(shlex.join(shown), MAX_HUMAN_COMMAND)
    return shown, human


def public_json(value: Any) -> str:
    """Canonical JSON of the redacted value (ASCII)."""
    return schema.canonical_json(redact(value))


def public_sha256(value: Any) -> str:
    return hashlib.sha256(public_json(value).encode("ascii")).hexdigest()


def _utc(clock: Clock) -> str:
    return schema.utc_text(clock.now())


def unmeasured_observation(
    reason: str,
    display_argv: Sequence[str],
    human_command: str,
    observed_at: str,
    exit_code: int | None = None,
) -> dict[str, Any]:
    """An ``unmeasured`` observation (S3 shape; same for snapshot and verify variants)."""
    return {
        "status": STATUS_UNMEASURED,
        "observed_at": observed_at,
        "argv": list(display_argv),
        "exit": exit_code,
        "object": None,
        "object_sha256": None,
        "reason": reason,
        "human_command": human_command,
    }


# --------------------------------------------------------------------------- validation


def _project_reader(project: str) -> Callable[[str], bytes | None]:
    """``read_file`` for the classifier: project-relative, no symlinks, bounded."""

    def read(path: str) -> bytes | None:
        try:
            full = fsutil.safe_child(project, path)
            fd = os.open(str(full), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except (OSError, fsutil.FsError, TypeError, ValueError):
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            data = _read_bounded(fd, MAX_SCRIPT_BYTES + 1)
        except OSError:
            return None
        finally:
            os.close(fd)
        return None if len(data) > MAX_SCRIPT_BYTES else data

    return read


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        chunk = os.read(fd, min(_READ_CHUNK, limit - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _inside(root_real: str, real: str) -> bool:
    return real != root_real and os.path.commonpath([root_real, real]) == root_real


def _protected(root_real: str, real: str) -> bool:
    rel = os.path.relpath(real, root_real)
    return rel.split(os.sep, 1)[0] in PROTECTED_TOP


def _file_sha256(path: str) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = _read_bounded(fd, MAX_SCRIPT_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > MAX_SCRIPT_BYTES:
        return None
    return hashlib.sha256(data).hexdigest()


def _script_form(argv: Sequence[str]) -> tuple[str, tuple[str, ...]] | str:
    """(script word, simtenant args) for ``python[3] [flags] SCRIPT ...`` or ``SCRIPT ...``."""
    first = argv[0]
    base = posixpath.basename(first).lower()
    if _PYTHON_RE.match(base):
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            if argv[i] in _PY_FLAGS:
                i += 1
            elif argv[i] in _PY_VALUED:
                i += 2
            else:
                return R_RUNNER_UNSUPPORTED
        if i >= len(argv):
            return R_PROBE_NOT_READ
        return argv[i], tuple(argv[i + 1 :])
    if "/" in first:
        return first, tuple(argv[1:])
    return R_RUNNER_UNSUPPORTED  # a bare trusted command word has no checkable script


def _locate_script(project: str, word: str) -> tuple[str, tuple[int, int], str] | None:
    root_real = os.path.realpath(project)
    if word.startswith("/"):
        path = word
    else:
        path = os.path.join(project, simtenant_adapter.strip_dot(word))
    try:
        given = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(given.st_mode):
        return None
    real = os.path.realpath(path)
    if not _inside(root_real, real) or _protected(root_real, real):
        return None
    try:
        st = os.lstat(real)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return None
    digest = _file_sha256(real)
    if digest is None:
        return None
    return real, (st.st_dev, st.st_ino), digest


def _argv_ok(argv: Sequence[Any]) -> bool:
    return 0 < len(argv) <= MAX_ARGV and all(
        isinstance(a, str) and a and len(a) <= MAX_ARG_CHARS and not _CTL_RE.search(a) for a in argv
    )


def validate(spec: Any, plan: Any, policy: Any, roots: Any) -> ExecSpec | Unmeasured:
    """Classify the probe and accept only a literal trusted ``simtenant get`` of the target.

    Never runs anything. Every refusal is ``Unmeasured`` with the exact redacted command.
    """
    target = getattr(spec, "target", None)
    argv = tuple(getattr(spec, "argv", ()) or ())
    shown, human = display_command(argv)

    def no(reason: str) -> Unmeasured:
        return Unmeasured(reason, human, shown)

    if not isinstance(target, str) or not target or not _argv_ok(argv):
        return no(R_PROBE_INVALID)
    try:
        project = project_root(roots)
        s3 = policy.s3_for(True)
    except Exception:  # noqa: BLE001 - unusable policy or roots: nothing runs
        return no(R_POLICY_INVALID)
    if not isinstance(sys.executable, str) or not os.path.isabs(sys.executable or ""):
        return no(R_NO_RUNNER)

    result = classify_tool_call(
        "Bash", {"command": shlex.join(argv)}, policy=s3, read_file=_project_reader(project)
    )
    parts = leaves(result)
    if len(parts) != 1:
        return no(R_PROBE_NOT_READ)
    leaf = parts[0]
    if leaf.kind != KIND_READ or leaf.unknown:
        return no(R_PROBE_NOT_READ)
    if leaf.adapter != simtenant_adapter.NAME:
        return no(R_RUNNER_UNSUPPORTED)
    if leaf.verb != "get" or leaf.targets != (target,) or not leaf.targets_complete:
        return no(R_PROBE_TARGET_MISMATCH)
    if leaf.flags:
        return no(R_PROBE_NOT_READ)
    tenant = getattr(plan, "tenant", None)
    if leaf.scope is None or not isinstance(tenant, str) or leaf.scope != tenant:
        return no(R_SCOPE_MISMATCH)
    if not state_file_safe(roots, leaf.scope):
        return no(R_SCOPE_UNSAFE)

    form = _script_form(argv)
    if isinstance(form, str):
        return no(form)
    word, rest = form
    located = _locate_script(project, word)
    if located is None:
        return no(R_SCRIPT_UNSAFE)
    real, ident, digest = located
    return ExecSpec(
        vector=(sys.executable, "-I", real, *rest),
        script_real=real,
        script_id=ident,
        scope=leaf.scope,
        target=target,
        display_argv=shown,
        human_command=human,
        script_sha256=digest,
    )


def recheck(ex: ExecSpec, roots: Any) -> str | None:
    """Run immediately before every attempt. ``script_changed`` / ``scope_unsafe`` / None."""
    try:
        project = project_root(roots)
        st = os.lstat(ex.script_real)
    except (OSError, ValueError):
        return R_SCRIPT_CHANGED
    if (
        stat.S_ISLNK(st.st_mode)
        or not stat.S_ISREG(st.st_mode)
        or st.st_nlink != 1
        or (st.st_dev, st.st_ino) != tuple(ex.script_id)
    ):
        return R_SCRIPT_CHANGED
    root_real = os.path.realpath(project)
    real = os.path.realpath(ex.script_real)
    if real != ex.script_real or not _inside(root_real, real) or _protected(root_real, real):
        return R_SCRIPT_CHANGED
    if _file_sha256(real) != ex.script_sha256:
        return R_SCRIPT_CHANGED
    if not state_file_safe(roots, ex.scope):
        return R_SCOPE_UNSAFE
    return None


# --------------------------------------------------------------------------- runner


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait(timeout=_REAP_TIMEOUT)


class SubprocessRunner:
    """Bounded real subprocess. Kills the whole process group on timeout or output cap."""

    def run(self, vector: Sequence[str], *, cwd: str, timeout: float, max_stdout: int) -> RunResult:
        argv = list(vector)
        if not argv or not all(isinstance(a, str) and a for a in argv):
            return RunResult(None, None, R_SPAWN_ERROR)
        if (
            isinstance(max_stdout, bool)
            or not isinstance(max_stdout, int)
            or max_stdout < 0
            or isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not math.isfinite(timeout)
        ):
            return RunResult(None, None, R_SPAWN_ERROR)
        if timeout <= 0:
            return RunResult(None, None, R_TIMEOUT)
        deadline = time.monotonic() + float(timeout)
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False
                argv,
                shell=False,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                env=dict(CHILD_ENV),
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            return RunResult(None, None, R_SPAWN_ERROR)
        stdout = proc.stdout
        assert stdout is not None
        fd = stdout.fileno()
        buf = bytearray()
        reaped = False
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _kill_group(proc)
                    reaped = True
                    return RunResult(None, None, R_TIMEOUT)
                try:
                    ready, _, _ = select.select([fd], [], [], remaining)
                except InterruptedError:
                    continue
                if not ready:
                    continue
                chunk = os.read(fd, min(_READ_CHUNK, max_stdout + 1 - len(buf)))
                if not chunk:
                    break
                buf += chunk
                if len(buf) > max_stdout:
                    _kill_group(proc)
                    reaped = True
                    return RunResult(None, None, R_OUTPUT_TOO_LARGE)
            try:
                rc = proc.wait(timeout=max(deadline - time.monotonic(), 0.001))
            except subprocess.TimeoutExpired:
                _kill_group(proc)
                reaped = True
                return RunResult(None, None, R_TIMEOUT)
            reaped = True
            # The leader is reaped; also end anything it left in its process group.
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            exit_code = rc if isinstance(rc, int) and 0 <= rc <= 255 else None
            return RunResult(exit_code, bytes(buf), None)
        finally:
            with contextlib.suppress(OSError):
                stdout.close()
            if not reaped:
                _kill_group(proc)


# --------------------------------------------------------------------------- strict JSON


class _Bad(ValueError):
    pass


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Bad("duplicate key")
        out[key] = value
    return out


def _no_constant(_name: str) -> Any:
    raise _Bad("non-finite constant")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise _Bad("non-finite number")
    return value


def _depth(value: Any, limit: int) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, d = stack.pop()
        if isinstance(item, dict | list):
            if d > limit:
                return False
            children = item.values() if isinstance(item, dict) else item
            stack.extend((c, d + 1) for c in children)
    return True


def _strict_loads(text: str, max_depth: int) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_dupes,
            parse_constant=_no_constant,
            parse_float=_finite_float,
        )
    except (ValueError, RecursionError) as exc:
        raise _Bad("not strict JSON") from exc
    if not _depth(value, max_depth):
        raise _Bad("too deep")
    return value


def _response_object(stdout: bytes) -> dict[str, Any] | None:
    """Exactly one non-empty line holding one strict JSON object, else None."""
    if not isinstance(stdout, bytes | bytearray) or len(stdout) > MAX_STDOUT:
        return None
    body = bytes(stdout[:-1]) if stdout.endswith(b"\n") else bytes(stdout)
    if not body.strip() or b"\n" in body or b"\r" in body:
        return None
    try:
        text = body.decode("utf-8")
        value = _strict_loads(text, MAX_RESPONSE_DEPTH)
    except (UnicodeDecodeError, _Bad):
        return None
    return value if isinstance(value, dict) else None


def _canon(value: Any) -> str:
    """Comparison form: canonical JSON keeping int/float/bool distinct."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


# --------------------------------------------------------------------------- observe


def _split_target(target: str) -> tuple[str, str]:
    resource, _, obj_id = target.partition("/")
    return resource, obj_id


def _status_of(target: str, exit_code: int | None, resp: Mapping[str, Any]) -> str | None:
    resource, obj_id = _split_target(target)
    if exit_code == 0:
        obj = resp.get("object")
        status = resp.get("status")
        if (
            resp.get("ok") is True
            and resp.get("verb") == "get"
            and resp.get("resource") == resource
            and resp.get("id") == obj_id
            and status in (STATUS_ACTIVE, STATUS_SOFT_DELETED)
            and isinstance(obj, dict)
            and obj.get("id") == obj_id
        ):
            return status
        return None
    if exit_code == 3:
        err = resp.get("error")
        if (
            resp.get("ok") is False
            and isinstance(err, dict)
            and err.get("code") == "not_found"
            and err.get("resource") == resource
            and err.get("id") == obj_id
        ):
            return STATUS_ABSENT
    return None


def _exit_value(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        return None
    return value


def observe(
    ex: ExecSpec,
    runner: Runner,
    clock: Clock,
    roots: Any,
    *,
    with_object: bool,
    timeout: float = RUN_TIMEOUT,
) -> tuple[dict[str, Any], Mapping[str, Any] | None]:
    """One attempt: recheck, run, map. Returns (observation, raw response or None).

    The fourth argument (``extra`` in the contract sketch) is the roots used by the
    per-attempt ``recheck``; nothing runs when it fails.
    """
    code = recheck(ex, roots)
    if code is not None:
        return unmeasured_observation(code, ex.display_argv, ex.human_command, _utc(clock)), None
    project = project_root(roots)
    result = runner.run(
        ex.vector, cwd=project, timeout=min(float(timeout), RUN_TIMEOUT), max_stdout=MAX_STDOUT
    )
    observed_at = _utc(clock)
    exit_code = _exit_value(getattr(result, "exit", None))
    error = getattr(result, "error", None)

    def unmeasured(reason: str) -> tuple[dict[str, Any], None]:
        obs = unmeasured_observation(
            reason, ex.display_argv, ex.human_command, observed_at, exit_code
        )
        return obs, None

    if error is not None:
        return unmeasured(error if error in RUNNER_ERRORS else R_SPAWN_ERROR)
    stdout = getattr(result, "stdout", None)
    resp = _response_object(stdout) if isinstance(stdout, bytes | bytearray) else None
    if resp is None:
        return unmeasured(R_OUTPUT_SHAPE)
    status = _status_of(ex.target, exit_code, resp)
    if status is None:
        return unmeasured(R_UNEXPECTED_RESPONSE)
    obj = resp.get("object") if status != STATUS_ABSENT else None
    obs = {
        "status": status,
        "observed_at": observed_at,
        "argv": list(ex.display_argv),
        "exit": exit_code,
        "object": redact(obj) if (with_object and obj is not None) else None,
        "object_sha256": public_sha256(obj) if obj is not None else None,
        "reason": None,
        "human_command": ex.human_command,
    }
    return obs, resp


# --------------------------------------------------------------------------- compare


_BAD_VALUE: Any = object()


def _pointer_tokens(pointer: Any) -> list[str] | None:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return None
    raw = pointer[1:].split("/")
    if not 1 <= len(raw) <= MAX_POINTER_TOKENS:
        return None
    out = []
    for tok in raw:
        if len(tok) > MAX_POINTER_TOKEN_CHARS or re.search(r"~(?![01])", tok):
            return None
        out.append(tok.replace("~1", "/").replace("~0", "~"))
    return out


def _resolve(doc: Any, tokens: Sequence[str]) -> tuple[bool, Any]:
    cur = doc
    for tok in tokens:
        if isinstance(cur, dict):
            if tok not in cur:
                return False, None
            cur = cur[tok]
        elif isinstance(cur, list):
            if not _INDEX_RE.match(tok) or int(tok) >= len(cur):
                return False, None
            cur = cur[int(tok)]
        else:
            return False, None
    return True, cur


def _expected(value_json: Any) -> Any:
    """``Check.value_json`` is the JSON text of the expected value (assumption, see report)."""
    if not isinstance(value_json, str) or len(value_json.encode("utf-8")) > MAX_VALUE_JSON_BYTES:
        return _BAD_VALUE
    try:
        return _strict_loads(value_json, MAX_VALUE_DEPTH)
    except _Bad:
        return _BAD_VALUE


def _checked_text(value: Any) -> str | None:
    try:
        text = public_json(value)
    except RedactionUnavailable:
        raise
    except Exception:  # noqa: BLE001 - not representable: shown as null
        return None
    return text if len(text) <= MAX_CHECKED_CHARS else None


def _evaluate(op: str, actual: Any, expected: Any) -> bool:
    want = _canon(expected)
    if op == "eq":
        return _canon(actual) == want
    if op == "ne":
        return _canon(actual) != want
    present = any(_canon(item) == want for item in actual)
    return present if op == "contains" else not present


def compare(
    spec: Any, observation: Mapping[str, Any], response: Mapping[str, Any] | None
) -> tuple[str, str | None, dict[str, str | None]]:
    """(``match`` | ``mismatch`` | ``unmeasurable``, reason, checked).

    ``checked`` maps each pointer to the redacted canonical JSON of the observed value
    (None when missing or longer than 1 KiB). Exit status alone never matches ``active``.
    """
    status = observation.get("status")
    if status == STATUS_UNMEASURED:
        return UNMEASURABLE, observation.get("reason") or R_UNEXPECTED_RESPONSE, {}
    expect = getattr(spec, "expect", None)
    checks = tuple(getattr(spec, "checks", ()) or ())
    if (
        expect not in EXPECTS
        or len(checks) > MAX_CHECKS
        or (expect == STATUS_ACTIVE and not checks)
        or (expect == STATUS_ABSENT and checks)
    ):
        return UNMEASURABLE, R_CHECK_INVALID, {}
    if status != expect:
        return MISMATCH, None, {}
    if not checks:
        return MATCH, None, {}
    if response is None:
        return UNMEASURABLE, R_UNEXPECTED_RESPONSE, {}

    checked: dict[str, str | None] = {}
    reason: str | None = None
    all_ok = True
    for check in checks:
        pointer = getattr(check, "pointer", None)
        op = getattr(check, "op", None)
        tokens = _pointer_tokens(pointer)
        expected = _expected(getattr(check, "value_json", None))
        if tokens is None or op not in OPS or expected is _BAD_VALUE:
            reason = reason or R_CHECK_INVALID
            if isinstance(pointer, str) and len(pointer) <= MAX_POINTER_CHARS:
                checked[pointer] = None
            continue
        found, actual = _resolve(response, tokens)
        if not found:
            checked[pointer] = None
            reason = reason or R_PATH_MISSING
            continue
        checked[pointer] = _checked_text(actual)
        if op in ("contains", "not_contains") and not isinstance(actual, list):
            reason = reason or R_NOT_A_LIST
            continue
        if not _evaluate(op, actual, expected):
            all_ok = False
    if reason is not None:
        return UNMEASURABLE, reason, checked
    return (MATCH if all_ok else MISMATCH), None, checked
