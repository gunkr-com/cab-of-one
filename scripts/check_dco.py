#!/usr/bin/env python3
"""DCO sign-off check for the commits a push or pull request adds (stdlib only, Python 3.11+).

Every commit in the range, merge commits included, needs a line

    Signed-off-by: Name <email>

whose e-mail equals the commit author's e-mail (case-insensitive), as ``git commit -s``
writes it. Output is the short commit ID and a fixed code only; no names, e-mails or message
text are printed.

Range inputs (CLI flags win over the environment):
  --head / DCO_HEAD   the newest commit (required)
  --base / DCO_BASE   commits reachable from base are excluded (``head --not base``)

In CI the event data arrives through environment variables, never through shell
interpolation, and must be full hexadecimal commit IDs. On the CLI a simple ref name such as
``HEAD`` or ``origin/main`` is also accepted.

Initial push and unknown base: when the base is empty or all zeros (a new branch or the very
first push, where GitHub sends ``before`` = 000...0), or the base commit is not in the local
history (for example after a force push), every commit reachable from head is checked. The
project requires a sign-off on every commit, so this is a stricter re-check, not a gap. The
range is bounded by ``--max-commits``; above it the check fails closed.

Exit codes: 0 all signed off, 1 a commit is missing a valid sign-off or the range is too
large, 2 usage or Git error.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

DEFAULT_MAX_COMMITS = 500
MAX_COMMIT_BYTES = 256 * 1024
GIT_TIMEOUT_S = 120

HEX_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
ZERO_SHA = re.compile(r"0+")
CLI_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
SIGNOFF = re.compile(r"Signed-off-by: (?P<name>\S(?:[^<>\n]*\S)?) <(?P<email>[^<>\s@]+@[^<>\s@]+)>")
AUTHOR = re.compile(r"author (?:.*) <(?P<email>[^<>]*)> [0-9]+ [+-][0-9]{4}")


class DcoError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Verdict:
    sha: str
    code: str  # "ok" | "dco_missing" | "dco_malformed" | "dco_author_mismatch" | ...


def git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    return env


def git(root: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    exe = shutil.which("git")
    if exe is None:
        raise DcoError("git_not_found")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [exe, "-c", "core.fsmonitor=false", "-C", root, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=git_env(),
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise DcoError("git_failed") from None
    if check and proc.returncode != 0:
        raise DcoError("git_failed")
    return proc


def validate_rev(value: str, *, from_env: bool, allow_empty: bool) -> str:
    """Return the value if it is a safe revision; raise a fixed error otherwise."""
    if value == "":
        if allow_empty:
            return value
        raise DcoError("rev_missing")
    if HEX_SHA.fullmatch(value) or (allow_empty and ZERO_SHA.fullmatch(value)):
        return value
    if from_env:
        raise DcoError("rev_invalid")
    if CLI_REF.fullmatch(value) and ".." not in value and not value.endswith((".", "/")):
        return value
    raise DcoError("rev_invalid")


def resolve(root: str, rev: str) -> str | None:
    proc = git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}", check=False)
    sha = proc.stdout.decode("ascii", "replace").strip()
    if proc.returncode != 0 or not HEX_SHA.fullmatch(sha):
        return None
    return sha


def commit_range(root: str, base: str, head: str, max_commits: int) -> tuple[list[str], bool]:
    """Commits to check (newest first) and whether the whole history of head is used."""
    head_sha = resolve(root, head)
    if head_sha is None:
        raise DcoError("head_unknown")
    base_sha = None
    if base and not ZERO_SHA.fullmatch(base):
        base_sha = resolve(root, base)
    args = ["rev-list", f"--max-count={max_commits + 1}", head_sha]
    if base_sha is not None:
        args += ["--not", base_sha]
    shas = [s for s in git(root, *args).stdout.decode("ascii", "replace").split() if s]
    if any(not HEX_SHA.fullmatch(s) for s in shas):
        raise DcoError("git_failed")
    if len(shas) > max_commits:
        raise DcoError("range_too_large")
    return shas, base_sha is None


def check_message(raw: bytes) -> str:
    header, _sep, body = raw.partition(b"\n\n")
    author_email = None
    for line in header.split(b"\n"):
        if line.startswith(b"author "):
            m = AUTHOR.fullmatch(line.decode("utf-8", "replace"))
            if m is None:
                return "author_unparsed"
            author_email = m.group("email").casefold()
            break
    if author_email is None:
        return "author_unparsed"
    signoffs: list[str] = []
    malformed = False
    for line in body.decode("utf-8", "replace").split("\n"):
        line = line.rstrip("\r ")
        m = SIGNOFF.fullmatch(line)
        if m is not None:
            signoffs.append(m.group("email").casefold())
        elif line.lower().lstrip().startswith(("signed-off-by", "signed off by")):
            malformed = True
    if author_email in signoffs:
        return "ok"
    if signoffs:
        return "dco_author_mismatch"
    return "dco_malformed" if malformed else "dco_missing"


def check_commit(root: str, sha: str) -> Verdict:
    size = git(root, "cat-file", "-s", sha, check=False)
    try:
        n = int(size.stdout.strip())
    except ValueError:
        return Verdict(sha, "commit_unreadable")
    if size.returncode != 0:
        return Verdict(sha, "commit_unreadable")
    if n > MAX_COMMIT_BYTES:
        return Verdict(sha, "commit_too_large")
    proc = git(root, "cat-file", "commit", sha, check=False)
    if proc.returncode != 0 or len(proc.stdout) != n:
        return Verdict(sha, "commit_unreadable")
    return Verdict(sha, check_message(proc.stdout))


def run(root: str, base: str, head: str, max_commits: int) -> tuple[list[Verdict], bool]:
    shas, whole_history = commit_range(root, base, head, max_commits)
    return [check_commit(root, sha) for sha in shas], whole_history


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_dco.py", description="Check DCO sign-off lines.", allow_abbrev=False
    )
    parser.add_argument("--root", default=".", help="Git work tree (default: cwd)")
    parser.add_argument("--base", help="exclude commits reachable from this (env DCO_BASE)")
    parser.add_argument("--head", help="newest commit (env DCO_HEAD)")
    parser.add_argument("--max-commits", type=int, default=DEFAULT_MAX_COMMITS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not 1 <= args.max_commits <= 10_000:
            raise DcoError("max_commits_invalid")
        head_env = args.head is None
        base_env = args.base is None
        head = validate_rev(
            os.environ.get("DCO_HEAD", "") if head_env else args.head,
            from_env=head_env,
            allow_empty=False,
        )
        base = validate_rev(
            os.environ.get("DCO_BASE", "") if base_env else args.base,
            from_env=base_env,
            allow_empty=True,
        )
        verdicts, whole_history = run(args.root, base, head, args.max_commits)
    except DcoError as exc:
        print(f"dco: fatal code={exc.code}", file=sys.stderr)
        return 1 if exc.code == "range_too_large" else 2
    if whole_history:
        print("dco: no usable base; checking every commit reachable from head")
    bad = [v for v in verdicts if v.code != "ok"]
    for verdict in bad:
        print(f"dco: commit={verdict.sha[:12]} code={verdict.code}")
    state = "signed" if not bad else "blocked"
    print(f"dco: {state} commits={len(verdicts)} failing={len(bad)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
