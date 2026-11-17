"""Terminal intake: ``cab intake CHG-NNNN`` at a terminal (no ``--from-file``).

Fixture: ``test_cli.CabProject`` (``test_guard.Project``) under <repo>/.local/test-tmp with a
fixture home. All answers are fictional Contoso data. Nothing here is a person's answer or
approval:

- "real PTY": the test opens its own pseudo-terminal pair (``os.openpty``) and types the
  fixture answers into the master side. ``os.isatty``, ``getuid`` and ``geteuid`` are the
  real ones; only the OS user *name* is replaced by a fictional one. A PTY owned by a test
  satisfies the TTY check, which is exactly why that check is not proof of a person.
- "fake TTY": injected streams that claim to be terminals plus an injected
  ``TerminalOS``; used for the cancel/validation matrix and the race cases.
- "Store only": ledger rows and state are inspected through the real Store and ledger.

The real terminal of whoever runs the tests is never read or written.

    python3 -m unittest discover -s tests -p test_intake.py
"""

from __future__ import annotations

import hashlib
import io
import os
import select
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import cli, intake, terminal  # noqa: E402
from cab_of_one.runtime.ledger import Ledger, LedgerError  # noqa: E402
from test_cli import CabProject, CliCase, FakeTTY, tty_os  # noqa: E402
from test_guard import CHANGE_ID, JWT, SLUG, leaks  # noqa: E402

try:  # POSIX only, like the runtime
    import termios
except ImportError:  # pragma: no cover
    termios = None  # type: ignore[assignment]

FICTIONAL_USER = "contoso-operator"
ANSWERS = (
    "Move the fictional Contoso user u-1007 to Sales",
    "users/u-1007 only (listed in targets.csv)",
    "every other fictional user, including u-1070",
    "any weekday before 17:00 fixture time",
    "the fictional Sales distribution group",
    "department reads Sales for u-1007",
)
KEYS = tuple(key for key, _ in cli.INTAKE_FIELDS)


def typed(*lines: str, confirm: str | None = CHANGE_ID) -> bytes:
    text = "".join(line + "\n" for line in lines)
    if confirm is not None:
        text += confirm + "\n"
    return text.encode("utf-8")


class BytesTTY(io.BytesIO):
    """A byte stream that claims to be a terminal (paired with an injected TerminalOS)."""

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


class InterruptTTY(BytesTTY):
    """Raises KeyboardInterrupt (Ctrl-C) on read number ``at`` (1-based)."""

    def __init__(self, data: bytes, at: int) -> None:
        super().__init__(data)
        self.at = at
        self.reads = 0

    def readline(self, size: int | None = -1) -> bytes:  # type: ignore[override]
        self.reads += 1
        if self.reads >= self.at:
            raise KeyboardInterrupt
        return super().readline(size)


class FileTTY(io.FileIO):
    """A real regular file that *claims* to be a terminal; os.isatty on it is False."""

    def isatty(self) -> bool:
        return True


class Pty:
    """A pseudo-terminal pair owned by one test. Echo is turned off so the master side
    reads only what the CLI printed."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.master, self.slave = os.openpty()
        case.addCleanup(self.close)
        if termios is not None:
            attrs = termios.tcgetattr(self.slave)
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
        self.stdin = open(self.slave, "rb", buffering=0, closefd=False)  # noqa: SIM115
        self.stdout = open(self.slave, "w", encoding="utf-8", closefd=False)  # noqa: SIM115

    def close(self) -> None:
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass

    def run(self, p: CabProject, argv: list[str], keys: bytes, **deps: Any) -> tuple[int, str, str]:
        """Run ``cab`` in a thread with the PTY slave as stdin/stdout; type ``keys`` into
        the master and collect what the CLI printed (bounded by a deadline)."""
        err = io.StringIO()
        result: dict[str, Any] = {}
        deps.setdefault("terminal_os", terminal.TerminalOS(username=lambda uid: FICTIONAL_USER))

        def target() -> None:
            try:
                result["code"] = cli.main(
                    argv, entry=p.cab_entry, env={}, home=str(p.home), stdin=self.stdin,
                    stdout=self.stdout, stderr=err, deps=p.deps(**deps),
                )  # fmt: skip
            except BaseException as exc:  # pragma: no cover - main never raises
                result["exc"] = exc

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        os.write(self.master, keys)
        out = bytearray()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(self.master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            elif not thread.is_alive():
                break
        thread.join(5)
        if thread.is_alive():
            raise AssertionError("cab intake did not finish within the fixture deadline")
        if "exc" in result:
            raise result["exc"]
        return result["code"], out.decode("utf-8", "replace").replace("\r\n", "\n"), err.getvalue()


class IntakeCase(CliCase):
    def setUp(self) -> None:
        super().setUp()
        p = self.p
        self.assertEqual(p.cab("new", CHANGE_ID, SLUG)[0], 0)
        p.write_plan("normal")
        self.intake_md = p.folder / "intake.md"

    def fake(self, data: bytes, *, osx: terminal.TerminalOS | None = None,
             stdin: Any = None, **deps: Any) -> tuple[int, str, str]:  # fmt: skip
        out = FakeTTY()
        code, _, err = self.p.cab(
            "intake", CHANGE_ID, stdin=stdin if stdin is not None else BytesTTY(data),
            stdout=out, terminal_os=osx or tty_os(), **deps,
        )  # fmt: skip
        return code, out.getvalue(), err

    def assert_nothing_written(self, before: bytes) -> None:
        self.assertFalse(self.intake_md.exists(), "intake.md must not exist")
        self.assertEqual(self.p.rows("intake"), [])
        self.assertEqual(self.p.state_bytes(), before)
        leftovers = [n for n in os.listdir(self.p.folder) if n.startswith(".intake.md.")]
        self.assertEqual(leftovers, [])


# --------------------------------------------------------------------------- happy path


class TerminalHappyPathTests(IntakeCase):
    def test_real_pty_intake_then_plan_check(self) -> None:
        """real PTY: six answers and the typed ID -> intake.md, one exact ledger row, no
        state change and no approval; plan check then counts it as terminal evidence."""
        p = self.p
        before_state = p.state_bytes()
        code, out, err = Pty(self).run(p, ["intake", CHANGE_ID], typed(*ANSWERS))
        self.assertEqual(code, 0, out + err)
        self.assertEqual(err, "")
        for index, key in enumerate(KEYS, 1):
            self.assertIn(f"[{index}/6] {intake.QUESTIONS[key]}", out)
        self.assertIn(f"Type {CHANGE_ID} and press Enter to write intake.md", out)
        self.assertIn("It approves nothing.", out)
        self.assertIn(f"source=terminal, OS user {FICTIONAL_USER}", out)
        self.assertIn("not proof of who typed them", out)

        data = self.intake_md.read_bytes()
        expected = [f"# Intake: {CHANGE_ID}"]
        expected += [
            f"{label} {answer}"
            for (_, label), answer in zip(cli.INTAKE_FIELDS, ANSWERS, strict=True)
        ]
        expected += ["- Unanswered: none (each question was answered at a terminal)",
                     cli.TERMINAL_SOURCE_LINE]  # fmt: skip
        self.assertEqual(data.decode("utf-8"), "\n".join(expected) + "\n")
        self.assertEqual(os.stat(self.intake_md).st_nlink, 1)
        self.assertEqual(cli.intake_md_source(data), "terminal")

        rows = p.rows("intake")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(
            set(row),
            {"v", "event", "change_id", "ts", "source", "reason_code", "actor", "response_sha256"},
        )
        self.assertEqual(
            {k: row[k] for k in ("event", "change_id", "source", "reason_code", "actor")},
            {"event": "intake", "change_id": CHANGE_ID, "source": "terminal",
             "reason_code": "terminal_answers", "actor": "cab-cli-terminal"},
        )  # fmt: skip
        self.assertEqual(row["response_sha256"], hashlib.sha256(data).hexdigest())
        ledger_text = p.ledger_bytes().decode("utf-8")
        for answer in ANSWERS:  # the interview stays in intake.md, never in the ledger
            self.assertNotIn(answer, ledger_text)
        self.assertNotIn(FICTIONAL_USER, ledger_text)

        self.assertEqual(p.state_bytes(), before_state)  # intake changes no state
        doc = p.doc()
        self.assertEqual((doc["state"], doc["approval_nonce"]), ("draft", None))
        self.assertFalse((p.folder / "approval.json").exists())

        code, out, err = p.cab("plan", "check", CHANGE_ID)
        self.assertEqual(code, 0, err)
        self.assertIn("interview evidence: terminal 1 (", out)
        self.assertNotIn("not counted", out)
        self.assertEqual(p.doc()["state"], "planned")
        self.assertIsNone(p.doc()["approval_nonce"])

    def test_secret_like_text_is_redacted_before_confirmation(self) -> None:
        """fake TTY: the summary, intake.md and the output never hold the raw token."""
        answers = list(ANSWERS)
        answers[3] = f"after the token {JWT} rotates"
        code, out, err = self.fake(typed(*answers))
        self.assertEqual(code, 0, err)
        text = self.intake_md.read_text("utf-8")
        for blob in (text, out, err, self.p.ledger_bytes().decode("utf-8")):
            self.assertEqual(leaks(JWT, blob), [])
        self.assertIn("[REDACTED]", text)
        self.assertIn("secret-looking text in 1 answer(s) was replaced", out)
        row = self.p.rows("intake")[0]
        self.assertEqual(row["response_sha256"], hashlib.sha256(text.encode("utf-8")).hexdigest())

    def test_answer_at_the_byte_limit_is_accepted(self) -> None:
        answers = list(ANSWERS)
        answers[0] = "x" * cli.MAX_INTAKE_VALUE
        code, _, err = self.fake(typed(*answers))
        self.assertEqual(code, 0, err)
        self.assertIn("x" * cli.MAX_INTAKE_VALUE, self.intake_md.read_text("utf-8"))

    def test_questions_match_the_intake_fields(self) -> None:
        self.assertEqual(tuple(intake.QUESTIONS), KEYS)


# --------------------------------------------------------------------------- TTY refusals


class TerminalPreflightTests(IntakeCase):
    def test_pipe_is_refused_before_any_prompt(self) -> None:
        """real pipe for stdin, real PTY for stdout: refused, nothing shown, nothing read."""
        p = self.p
        before = p.state_bytes()
        pty_pair = Pty(self)
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        payload = typed(*ANSWERS)
        os.write(write_fd, payload)
        os.close(write_fd)
        stdin = open(read_fd, "rb", buffering=0, closefd=False)  # noqa: SIM115
        err = io.StringIO()
        code = cli.main(
            ["intake", CHANGE_ID], entry=p.cab_entry, env={}, home=str(p.home), stdin=stdin,
            stdout=pty_pair.stdout, stderr=err, deps=p.deps(),
        )  # fmt: skip
        self.assertEqual(code, cli.EXIT_REFUSED)
        self.assertEqual(err.getvalue(), f"cab: not_a_tty: {intake.MESSAGES['not_a_tty']}\n")
        ready, _, _ = select.select([pty_pair.master], [], [], 0.1)
        self.assertEqual(ready, [], "nothing may be printed before the TTY check")
        self.assertEqual(os.read(read_fd, len(payload) + 1), payload)  # nothing was read
        self.assert_nothing_written(before)

    def test_pty_stdin_with_piped_stdout_is_refused(self) -> None:
        p = self.p
        before = p.state_bytes()
        pty_pair = Pty(self)
        out = io.StringIO()  # not a terminal
        err = io.StringIO()
        code = cli.main(
            ["intake", CHANGE_ID], entry=p.cab_entry, env={}, home=str(p.home),
            stdin=pty_pair.stdin, stdout=out, stderr=err, deps=p.deps(),
        )  # fmt: skip
        self.assertEqual((code, out.getvalue()), (cli.EXIT_REFUSED, ""))
        self.assertIn("not_a_tty", err.getvalue())
        self.assert_nothing_written(before)

    def test_stream_that_only_claims_to_be_a_tty_is_refused(self) -> None:
        """isatty() says True, the real os.isatty on its descriptor says False."""
        p = self.p
        before = p.state_bytes()
        fake_path = p.tmp / "not-a-terminal"
        fake_path.write_bytes(typed(*ANSWERS))
        stdin = FileTTY(str(fake_path), "rb")
        self.addCleanup(stdin.close)
        out = FakeTTY()
        code, _, err = p.cab("intake", CHANGE_ID, stdin=stdin, stdout=out,
                             terminal_os=terminal.TerminalOS())  # fmt: skip
        self.assertEqual((code, out.getvalue()), (cli.EXIT_REFUSED, ""))
        self.assertIn("not_a_tty", err)
        self.assertEqual(stdin.tell(), 0)
        # and an injected isatty that says no is refused the same way
        code, out_text, err = self.fake(typed(*ANSWERS), osx=terminal.TerminalOS(
            isatty=lambda fd: False, username=lambda uid: FICTIONAL_USER))  # fmt: skip
        self.assertEqual((code, out_text), (cli.EXIT_REFUSED, ""))
        self.assert_nothing_written(before)

    def test_uid_mismatch_and_unknown_user_are_refused_before_prompts(self) -> None:
        before = self.p.state_bytes()
        cases = (
            (tty_os(501, 0), "uid_mismatch"),
            (terminal.TerminalOS(isatty=lambda fd: True, getuid=lambda: 501,
                                 geteuid=lambda: 501, username=lambda uid: None),
             "os_user_unknown"),
        )  # fmt: skip
        for osx, refusal in cases:
            with self.subTest(refusal):
                code, out, err = self.fake(typed(*ANSWERS), osx=osx)
                self.assertEqual((code, out), (cli.EXIT_REFUSED, ""))
                self.assertEqual(err, f"cab: {refusal}: {intake.MESSAGES[refusal]}\n")
        self.assert_nothing_written(before)


# --------------------------------------------------------------------------- cancel matrix


class TerminalCancelTests(IntakeCase):
    def test_cancel_and_invalid_answers_write_nothing(self) -> None:
        """fake TTY: each case stops at the first unusable answer; no retry, no partial
        intake.md, no row; typed text is never echoed in the error."""
        before = self.p.state_bytes()
        secret = "TypedSENTINELq7"
        over = "y" * (cli.MAX_INTAKE_VALUE + 1)
        cases: list[tuple[str, bytes, int, str]] = [
            ("eof at question 3", typed(*ANSWERS[:2], confirm=None), 1, "intake_cancelled"),
            ("eof mid-line", typed(*ANSWERS[:2], confirm=None) + secret.encode(), 1,
             "intake_cancelled"),
            ("nothing typed", b"", 1, "intake_cancelled"),
            ("empty answer", typed(ANSWERS[0], "", *ANSWERS[2:]), 1, "answer_empty"),
            ("spaces only", typed(ANSWERS[0], "   ", *ANSWERS[2:]), 1, "answer_empty"),
            ("overlong", typed(over + secret, *ANSWERS[1:]), 1, "answer_too_long"),
            ("escape", typed(f"a\x1b[2J{secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("tab", typed(f"a\t{secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("crlf", typed(f"{secret}\r", *ANSWERS[1:]), 1, "answer_invalid"),
            ("nul", typed(f"a\x00{secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("delete", typed(f"a\x7f{secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("c1", typed(f"a\x85{secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("bidi override", typed(f"a‮{secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("line separator", typed(f"a {secret}", *ANSWERS[1:]), 1, "answer_invalid"),
            ("not utf-8", b"\xff\xfe" + secret.encode() + b"\n" + typed(*ANSWERS[1:]), 1,
             "answer_invalid"),
            ("wrong id", typed(*ANSWERS, confirm="CHG-0002"), 1, "mismatch"),
            ("id with crlf", typed(*ANSWERS, confirm=CHANGE_ID + "\r"), 1, "mismatch"),
            ("eof at confirmation", typed(*ANSWERS, confirm=None), 1, "mismatch"),
        ]  # fmt: skip
        for label, data, exit_code, refusal in cases:
            with self.subTest(label):
                code, out, err = self.fake(data)
                self.assertEqual(code, exit_code, out + err)
                text = (intake.MESSAGES | terminal.MESSAGES)[refusal]
                self.assertEqual(err, f"cab: {refusal}: {text}\n")
                self.assertNotIn(secret, err)
                self.assertNotIn("written from answers", out)
                self.assert_nothing_written(before)

    def test_interrupt_writes_nothing(self) -> None:
        """Ctrl-C while answering (read 3) or at the confirmation (read 7)."""
        before = self.p.state_bytes()
        for at in (1, 3, 7):
            with self.subTest(read=at):
                stdin = InterruptTTY(typed(*ANSWERS), at)
                code, _, err = self.fake(b"", stdin=stdin)
                self.assertEqual(code, 130)
                self.assertEqual(err, f"cab: interrupted: {cli.MESSAGES['interrupted']}\n")
                self.assert_nothing_written(before)

    def test_usage_and_state_refusals(self) -> None:
        before = self.p.state_bytes()
        for argv, expected in (
            (["intake", "CHG-1"], cli.EXIT_USAGE),
            (["intake", CHANGE_ID, "--from-file"], cli.EXIT_USAGE),
            (["intake", CHANGE_ID, "--interactive"], cli.EXIT_USAGE),
            (["intake", "CHG-0999"], cli.EXIT_REFUSED),  # not the active change
        ):
            with self.subTest(argv=argv):
                code, _, _ = self.p.cab(*argv, stdin=BytesTTY(typed(*ANSWERS)),
                                        stdout=FakeTTY(), terminal_os=tty_os())  # fmt: skip
                self.assertEqual(code, expected)
        self.assert_nothing_written(before)


# --------------------------------------------------------------------------- duplicates and races


class TerminalRaceTests(IntakeCase):
    def test_existing_intake_is_refused_before_prompts_and_kept(self) -> None:
        p = self.p
        p.write("work/intake.toml", "\n".join(f'{k} = "fixture {k}"' for k in KEYS) + "\n")
        self.assertEqual(p.cab("intake", CHANGE_ID, "--from-file", "work/intake.toml")[0], 0)
        original = self.intake_md.read_bytes()
        rows = p.rows("intake")
        code, out, err = self.fake(typed(*ANSWERS))
        self.assertEqual((code, out), (cli.EXIT_REFUSED, ""))
        self.assertIn("intake_exists", err)
        self.assertEqual(self.intake_md.read_bytes(), original)
        self.assertEqual(p.rows("intake"), rows)
        # a second terminal intake after a successful one is refused the same way
        self.intake_md.unlink()
        self.assertEqual(self.fake(typed(*ANSWERS))[0], 0)
        written = self.intake_md.read_bytes()
        code, _, err = self.fake(typed(*reversed(ANSWERS)))
        self.assertEqual((code, "intake_exists" in err), (cli.EXIT_REFUSED, True))
        self.assertEqual(self.intake_md.read_bytes(), written)

    def meanwhile(self, action: Any) -> Any:
        """git_lookup runs after the typed ID matched and before the locked commit."""

        def lookup(project: str) -> str:
            action()
            return ""

        return lookup

    def test_intake_md_created_meanwhile_is_never_overwritten(self) -> None:
        p = self.p
        racer = b"# written by someone else meanwhile\n"
        code, _, err = self.fake(typed(*ANSWERS), git_lookup=self.meanwhile(
            lambda: self.intake_md.write_bytes(racer)))  # fmt: skip
        self.assertEqual((code, "intake_exists" in err), (cli.EXIT_REFUSED, True))
        self.assertEqual(self.intake_md.read_bytes(), racer)
        self.assertEqual(p.rows("intake"), [])

    def test_symlink_planted_meanwhile_is_not_followed(self) -> None:
        p = self.p
        outside = p.tmp / "outside-intake.md"
        outside.write_bytes(b"outside\n")
        code, _, _ = self.fake(typed(*ANSWERS), git_lookup=self.meanwhile(
            lambda: p.symlink(outside, self.intake_md)))  # fmt: skip
        self.assertNotEqual(code, 0)
        self.assertTrue(self.intake_md.is_symlink())
        self.assertEqual(outside.read_bytes(), b"outside\n")
        self.assertEqual(p.rows("intake"), [])

    def test_state_change_meanwhile_is_a_conflict(self) -> None:
        """Store only: the change is planned (seq moves) while the person confirms."""
        p = self.p

        def plan() -> None:
            store = p.store()
            _, _, current = store.load_plan(CHANGE_ID)
            store.mark_planned(CHANGE_ID, "normal", current, "fixture-actor")

        before_rows = p.rows("intake")
        code, _, err = self.fake(typed(*ANSWERS), git_lookup=self.meanwhile(plan))
        self.assertEqual((code, "state_changed" in err), (cli.EXIT_CONFLICT, True))
        self.assertFalse(self.intake_md.exists())
        self.assertEqual(p.rows("intake"), before_rows)
        self.assertEqual(p.doc()["state"], "planned")  # the other writer's state stays

    def test_ledger_failure_removes_only_the_file_this_call_created(self) -> None:
        p = self.p
        before = p.state_bytes()
        with mock.patch.object(Ledger, "append", side_effect=LedgerError("append_failed")):
            code, out, err = self.fake(typed(*ANSWERS))
        self.assertEqual((code, "ledger_error" in err), (cli.EXIT_ERROR, True))
        self.assertNotIn("written from answers", out)
        self.assert_nothing_written(before)

    def test_interrupt_after_the_file_is_created_removes_it(self) -> None:
        p = self.p
        before = p.state_bytes()
        with mock.patch.object(Ledger, "append", side_effect=KeyboardInterrupt):
            code, _, err = self.fake(typed(*ANSWERS))
        self.assertEqual((code, "interrupted" in err), (130, True))
        self.assert_nothing_written(before)


# --------------------------------------------------------------------------- helpers


class PublishNewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.p = CabProject(self)
        self.folder = self.p.tmp / "publish"
        self.folder.mkdir()

    def test_creates_once_and_never_replaces(self) -> None:
        ident = intake.publish_new(str(self.folder), "intake.md", b"first\n")
        target = self.folder / "intake.md"
        st = os.lstat(target)
        self.assertEqual((st.st_dev, st.st_ino, st.st_nlink), (*ident, 1))
        with self.assertRaises(FileExistsError):
            intake.publish_new(str(self.folder), "intake.md", b"second\n")
        self.assertEqual(target.read_bytes(), b"first\n")
        self.assertEqual(sorted(os.listdir(self.folder)), ["intake.md"])

    def test_existing_symlink_or_directory_is_not_replaced(self) -> None:
        outside = self.p.tmp / "outside.md"
        outside.write_bytes(b"outside\n")
        link = self.folder / "intake.md"
        self.p.symlink(outside, link)
        with self.assertRaises(FileExistsError):
            intake.publish_new(str(self.folder), "intake.md", b"new\n")
        self.assertEqual(outside.read_bytes(), b"outside\n")
        self.assertTrue(link.is_symlink())
        link.unlink()
        link.mkdir()
        with self.assertRaises(FileExistsError):
            intake.publish_new(str(self.folder), "intake.md", b"new\n")
        self.assertEqual(sorted(os.listdir(self.folder)), ["intake.md"])

    def test_unpublish_only_removes_the_same_file(self) -> None:
        ident = intake.publish_new(str(self.folder), "intake.md", b"first\n")
        target = self.folder / "intake.md"
        other = self.folder / "other.md"
        other.write_bytes(b"someone else\n")  # created while ours exists: another inode
        os.replace(other, target)
        self.assertFalse(intake.unpublish(str(target), ident))
        self.assertEqual(target.read_bytes(), b"someone else\n")

    def test_check_answer_rules(self) -> None:
        self.assertEqual(intake.check_answer(b"  ok answer \n", 16), ("ok answer", "ok"))
        self.assertEqual(intake.check_answer(b"", 16), (None, "intake_cancelled"))
        self.assertEqual(intake.check_answer(b"partial", 16), (None, "intake_cancelled"))
        self.assertEqual(intake.check_answer(b"x" * 17, 16), (None, "answer_too_long"))
        self.assertEqual(intake.check_answer(b"x" * 16 + b"\n", 16), ("x" * 16, "ok"))
        self.assertEqual(intake.check_answer(b"\xc3\n", 16), (None, "answer_invalid"))
        self.assertEqual(intake.check_answer(None, 16), (None, "input_error"))


if __name__ == "__main__":
    unittest.main()
