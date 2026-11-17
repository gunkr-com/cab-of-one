"""Tests for cab_of_one.runtime.terminal (S5 C0).

Only injected streams, injected OS facts, mock runners, owned pipes and one owned
pseudo-terminal pair are used. The real terminal, real git and real configuration are
never touched.
"""

from __future__ import annotations

import inspect
import io
import os
import unittest
from typing import Any

from cab_of_one.runtime import terminal
from cab_of_one.runtime.terminal import TerminalOS, require_human

CID = "CHG-0007"
SECRET = "sk-FICTIONAL-SECRET-0123456789"


class FakeTTY(io.StringIO):
    def __init__(self, text: str = "", *, tty: bool = True, fd: int = 90) -> None:
        super().__init__(text)
        self._tty = tty
        self._fd = fd
        self.reads = 0

    def isatty(self) -> bool:
        return self._tty

    def fileno(self) -> int:
        return self._fd

    def readline(self, size: int = -1) -> str:  # type: ignore[override]
        self.reads += 1
        return super().readline(size)


class CountingGit:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        return "Contoso Admin"


def osx(
    *,
    ttys: frozenset[int] = frozenset({90, 91}),
    uid: int = 501,
    euid: int = 501,
    user: str | None = "contoso-admin",
) -> TerminalOS:
    return TerminalOS(
        isatty=lambda fd: fd in ttys,
        getuid=lambda: uid,
        geteuid=lambda: euid,
        username=lambda _uid: user,
    )


class RequireHumanTests(unittest.TestCase):
    def run_check(self, typed: str, **kw: Any) -> tuple[Any, FakeTTY, FakeTTY, io.StringIO]:
        stdin = kw.pop("stdin", None) or FakeTTY(typed, fd=90)
        stdout = kw.pop("stdout", None) or FakeTTY(fd=91)
        stderr = io.StringIO()
        result = require_human(
            kw.pop("change_id", CID),
            kw.pop("summary", ["Approve CHG-0007"]),
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            osx=kw.pop("osx", osx()),
            git_lookup=kw.pop("git_lookup", None),
        )
        return result, stdin, stdout, stderr

    def test_exact_match_confirms(self) -> None:
        calls: list[int] = []

        def git() -> str:
            calls.append(1)
            return "Contoso Admin"

        result, _, stdout, _ = self.run_check(f"{CID}\n", git_lookup=git)
        self.assertTrue(result.confirmed)
        self.assertEqual(result.exit, 0)
        self.assertEqual(result.os_user, "contoso-admin")
        self.assertEqual(result.git_user, "Contoso Admin")
        self.assertEqual(calls, [1])
        self.assertIn("Approve CHG-0007", stdout.getvalue())

    def test_refusals_happen_before_any_output_or_read(self) -> None:
        cases = {
            "stdin_not_tty": dict(stdin=FakeTTY(f"{CID}\n", tty=False, fd=90)),
            "stdout_not_tty": dict(stdout=FakeTTY(tty=False, fd=91)),
            "stream_lies": dict(osx=osx(ttys=frozenset({91}))),
            "stdout_fd_lies": dict(osx=osx(ttys=frozenset({90}))),
            "uid_mismatch": dict(osx=osx(euid=0)),
            "no_os_user": dict(osx=osx(user=None)),
            "bad_os_user": dict(osx=osx(user="a\nb")),
            "bad_change_id": dict(change_id="CHG-7"),
        }
        for name, kw in cases.items():
            with self.subTest(name=name):
                git = CountingGit()
                kw["git_lookup"] = git
                result, stdin, stdout, stderr = self.run_check(f"{CID}\n", **kw)
                self.assertFalse(result.confirmed)
                self.assertEqual(result.exit, 3)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stdin.reads, 0)
                self.assertEqual(git.calls, 0)
                self.assertTrue(stderr.getvalue().startswith("cab: "))

    def test_mismatches_exit_1(self) -> None:
        for typed in (
            "chg-0007\n",
            "CHG-0007 \n",
            " CHG-0007\n",
            "CHG-0007\r\n",
            "CHG-0007",
            "CHG-0008\n",
            "",
            "\n",
            "x" * 70 + "\n",
            CID + "\x00\n",
        ):
            with self.subTest(typed=typed):
                git = CountingGit()
                result, _, _, stderr = self.run_check(typed, git_lookup=git)
                self.assertFalse(result.confirmed)
                self.assertEqual(result.exit, 1)
                self.assertEqual(git.calls, 0)
                self.assertIn("Nothing was written", stderr.getvalue())

    def test_read_is_bounded(self) -> None:
        stdin = FakeTTY("A" * 10_000 + "\n", fd=90)
        result, _, _, _ = self.run_check("", stdin=stdin)
        self.assertEqual(result.exit, 1)
        self.assertEqual(stdin.tell(), terminal.MAX_CONFIRM_CHARS + 1)

    def test_git_failure_is_empty_not_invented(self) -> None:
        def broken() -> str:
            raise OSError("no git")

        for lookup in (broken, lambda: "", lambda: "a\x1bb", lambda: 5):
            result, _, _, _ = self.run_check(f"{CID}\n", git_lookup=lookup)
            self.assertTrue(result.confirmed)
            self.assertEqual(result.git_user, "")
        result, _, _, _ = self.run_check(f"{CID}\n")
        self.assertEqual(result.git_user, "")

    def test_summary_is_redacted_and_sanitized(self) -> None:
        summary = [
            f"step: simtenant --client-secret {SECRET} disable user/u1",
            "evil\x1b[2Jline",
        ]
        result, _, stdout, _ = self.run_check(f"{CID}\n", summary=summary)
        shown = stdout.getvalue()
        self.assertTrue(result.confirmed)
        self.assertNotIn(SECRET, shown)
        self.assertNotIn("\x1b", shown)
        self.assertIn("[REDACTED]", shown)

    def test_output_failure_refuses(self) -> None:
        class BadOut(FakeTTY):
            def write(self, _s: str) -> int:  # type: ignore[override]
                raise OSError("closed")

        result, stdin, _, _ = self.run_check(f"{CID}\n", stdout=BadOut(fd=91))
        self.assertEqual((result.confirmed, result.exit), (False, 3))
        self.assertEqual(stdin.reads, 0)


class OwnedPtyTests(unittest.TestCase):
    """A genuine pseudo-terminal pair owned by the test; uid facts injected."""

    def test_genuine_pty_path(self) -> None:
        try:
            master, slave = os.openpty()
        except OSError:
            self.skipTest("no pty available")
        facts = TerminalOS(
            getuid=lambda: 501, geteuid=lambda: 501, username=lambda _u: "contoso-admin"
        )
        try:
            with (
                os.fdopen(os.dup(slave), "rb", buffering=0) as raw_in,
                os.fdopen(os.dup(slave), "w", encoding="utf-8") as out,
            ):
                stdin = io.TextIOWrapper(io.BufferedReader(raw_in), encoding="utf-8")
                os.write(master, f"{CID}\n".encode())
                result = require_human(
                    CID,
                    ["Resume CHG-0007"],
                    stdin=stdin,
                    stdout=out,
                    stderr=io.StringIO(),
                    osx=facts,
                )
                stdin.detach().close()
                self.assertTrue(result.confirmed, result)
        finally:
            os.close(master)
            os.close(slave)


class SummaryTests(unittest.TestCase):
    def test_clear_inflight_warns_old_call(self) -> None:
        change = {
            "id": CID,
            "state": "halted",
            "halted": {"code": "write_unknown"},
            "units": [{"n": 1, "outcome": None, "verify": None}],
            "inflight": {"token": "toolu_0001", "unit": 1},
        }
        text = "\n".join(terminal.resume_summary(change, clear_inflight=True))
        self.assertIn("make sure that old call has stopped", text)
        self.assertIn("may have written", text)
        self.assertIn("does not stop it", text)
        self.assertIn("cannot detect every result", text)
        for promise in ("will stop", "killed", "terminated", "safe to"):
            self.assertNotIn(promise, text)
        plain = "\n".join(terminal.resume_summary(change, clear_inflight=False))
        self.assertNotIn("WARNING", plain)

    def test_approve_summary(self) -> None:
        targets = [f"user/u{i}" for i in range(1, 8)]
        lines = terminal.approve_summary(
            change_id=CID,
            tier="critical",
            plan_hash="a" * 64,
            targets=targets,
            review_verdict="PASS",
            snapshot_taken_at="2026-11-12T00:00:00.000Z",
        )
        text = "\n".join(lines)
        self.assertIn("targets: 7", text)
        self.assertIn("user/u5", text)
        self.assertNotIn("user/u6", text)
        self.assertIn("snapshot complete at 2026-11-12T00:00:00.000Z", text)

    def test_no_termios(self) -> None:
        source = inspect.getsource(terminal)
        self.assertNotIn("import termios", source)
        self.assertNotIn("tcsetattr", source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)


class GitLookupTests(unittest.TestCase):
    def test_fixed_argv_and_minimal_env(self) -> None:
        seen: dict[str, Any] = {}

        def runner(argv: Any, **kw: Any) -> bytes:
            seen["argv"] = argv
            seen.update(kw)
            return b"Contoso Admin\n"

        name = terminal.git_user_name("/work", home="/home/x", runner=runner)
        self.assertEqual(name, "Contoso Admin")
        self.assertEqual(seen["cwd"], "/work")
        self.assertEqual(seen["argv"], ("git", "config", "--get", "user.name"))
        self.assertEqual(set(seen["env"]), {"PATH", "LC_ALL", "HOME"})
        self.assertEqual(seen["timeout"], 2.0)
        self.assertEqual(seen["max_bytes"], 256)

    def test_failures_are_empty(self) -> None:
        for out in (None, b"", b"\n", b"a\x1bb\n", b"\xff\n", b"x" * 257, "str"):
            with self.subTest(out=out):
                self.assertEqual(
                    terminal.git_user_name(home="/h", runner=lambda *_a, _o=out, **_k: _o), ""
                )

        def boom(*_a: Any, **_k: Any) -> bytes:
            raise OSError("x")

        self.assertEqual(terminal.git_user_name(home="/h", runner=boom), "")


class FakeProc:
    def __init__(self, rfd: int, code: int = 0) -> None:
        self.stdout = os.fdopen(rfd, "rb", buffering=0)
        self.code = code
        self.killed = False

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        return self.code


class BoundedRunTests(unittest.TestCase):
    """The bounded reader against owned pipes; no process is started."""

    def run_with(
        self, data: bytes | None, *, close: bool = True, code: int = 0, timeout: float = 1.0
    ) -> tuple[bytes | None, FakeProc]:
        r, w = os.pipe()
        procs: list[FakeProc] = []

        def popen(argv: Any, **kw: Any) -> FakeProc:
            assert kw["shell"] is False
            procs.append(FakeProc(r, code))
            return procs[0]

        try:
            if data:
                os.write(w, data)
            if close:
                os.close(w)
            out = terminal._bounded_run(
                ["git"], cwd=None, env={}, timeout=timeout, max_bytes=256, popen=popen
            )
        finally:
            if not close:
                os.close(w)
        return out, procs[0]

    def test_normal(self) -> None:
        out, proc = self.run_with(b"Contoso Admin\n")
        self.assertEqual(out, b"Contoso Admin\n")
        self.assertFalse(proc.killed)

    def test_overflow_killed_while_reading(self) -> None:
        out, proc = self.run_with(b"x" * 300)
        self.assertIsNone(out)
        self.assertTrue(proc.killed)

    def test_timeout_killed(self) -> None:
        out, proc = self.run_with(b"partial", close=False, timeout=0.05)
        self.assertIsNone(out)
        self.assertTrue(proc.killed)

    def test_nonzero_exit(self) -> None:
        out, _ = self.run_with(b"name\n", code=1)
        self.assertIsNone(out)

    def test_spawn_error(self) -> None:
        def popen(*_a: Any, **_k: Any) -> Any:
            raise FileNotFoundError("git")

        self.assertIsNone(
            terminal._bounded_run(["git"], cwd=None, env={}, timeout=1, max_bytes=8, popen=popen)
        )


if __name__ == "__main__":
    unittest.main()
