"""S4 shellscan: protected paths and human-only cab commands in Bash text.

The scan context is built from the public ``paths`` functions over a fixture project in
<repo>/.local/test-tmp; nothing is executed. Strings such as curl/wget URLs are only
scanned, never fetched.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import paths, shellscan  # noqa: E402
from cab_of_one.runtime.schema import DEFAULT_SUBAGENT_BASH_ALLOW  # noqa: E402
from test_guard import (  # noqa: E402
    APPROVAL_COMMANDS,
    CHANGE_DIR,
    PROTECTED_COMMANDS,
    SAFE_COMMANDS,
    S4Case,
)

APPROVAL = shellscan.APPROVAL
PROTECTED = shellscan.PROTECTED
OPAQUE_WRITE = shellscan.OPAQUE_WRITE
OPAQUE_SCRIPT = shellscan.OPAQUE_SCRIPT


class ScanCase(S4Case):
    def setUp(self) -> None:
        super().setUp()
        p = self.p
        p.path(CHANGE_DIR).mkdir(parents=True)
        p.write(f"{CHANGE_DIR}/plan.md", "# plan\n")
        p.write("work/approval.json", "{}\n")
        p.write("work/s.sed", "s/a/b/\n")
        p.write("work/bad.sed", "w policy/policy.toml\n")
        p.write("scripts/touch-policy.sh", "echo x > policy/policy.toml\n")
        p.write("scripts/harmless.sh", "echo hello\n")
        roots = p.roots

        def protected(path: str, cwd: str | None, ancestors: bool) -> bool | None:
            return paths.protected_match(path, cwd, roots, ancestors=ancestors)

        def read_text(path: str, cwd: str | None) -> str | None:
            data = paths.read_project_file(roots, cwd, path, 256 * 1024)
            return None if data is None else data.decode("utf-8")

        def is_dir(path: str, cwd: str | None) -> bool:
            if not os.path.isabs(path):
                if cwd is None:
                    return False
                path = os.path.join(cwd, path)
            return os.path.isdir(path)

        self.ctx = shellscan.ScanContext(protected, read_text, is_dir)

    def scan(self, command: str, cwd: str = "", *, strict: bool = False) -> str | None:
        base = str(self.p.path(cwd)) if cwd else str(self.p.project)
        return shellscan.scan(command, base, self.ctx, strict=strict)


class ApprovalTextTests(unittest.TestCase):
    def test_human_only_verbs(self) -> None:
        for text in (
            "cab approve CHG-0001",
            "cab ack CHG-0001",
            "cab resume CHG-0001",
            "CAB Resume",
            "cab setup apply",
            "cab setup --yes uninstall",
            "./cab.py approve",
            "python3 -m cab_of_one approve",
        ):
            with self.subTest(text=text):
                self.assertTrue(shellscan.approval_text(text))

    def test_other_cab_commands_are_not_approval(self) -> None:
        for text in (
            "cab plan check",
            "cab verify CHG-0001",
            "cab doctor",
            "cabinet approve",
            "echo approve",
            "cab\napprove",
        ):
            with self.subTest(text=text):
                self.assertFalse(shellscan.approval_text(text))


class IntakeTextTests(unittest.TestCase):
    """``cab ... intake`` is human-only text; the exact fixture call never reaches the scan
    (guard step 1a), so the text rule does not look for ``--from-file``."""

    def test_intake_after_cab_on_one_line(self) -> None:
        for text in (
            "cab intake CHG-0001",
            ".claude/hooks/cab/cab intake CHG-0001",
            ".claude/hooks/cab/cab intake CHG-0001 --from-file work/intake.toml",
            "/srv/My Project/.claude/hooks/cab/cab intake CHG-0001",
            "'.claude/hooks/cab/cab' 'intake' CHG-0001",
            "CAB INTAKE CHG-0001",
            "python3 -m cab_of_one intake CHG-0001",
            '[".claude/hooks/cab/cab", "intake", "CHG-0001"]',
        ):
            with self.subTest(text=text):
                self.assertTrue(shellscan.intake_text(text))
                self.assertFalse(shellscan.approval_text(text))  # a separate rule

    def test_other_intake_words_are_not_intake_calls(self) -> None:
        for text in (
            "cat changes/CHG-0001-contoso-fixture/intake.md",
            "grep intake notes.txt",
            "echo intake; ls",
            "ls .claude/skills/change-intake",
            ".claude/hooks/cab/cab plan check CHG-0001",
            "cab status --from-file work/intake.toml",
            "cab-of-one intake",
            "cabinet intake",
            "cab\nintake CHG-0001",
            "intake cab",
        ):
            with self.subTest(text=text):
                self.assertFalse(shellscan.intake_text(text))


class IntakeScanTests(ScanCase):
    def test_every_intake_shape_that_reaches_the_scan_is_approval(self) -> None:
        self.p.write("scripts/run-intake.sh", ".claude/hooks/cab/cab intake CHG-0001\n")
        cli = ".claude/hooks/cab/cab"
        for command in (
            f"{cli} intake CHG-0001",
            f"{cli} in''take CHG-0001",
            f"{cli} intake CHG-0001 --from-file work/intake.toml",  # step 1a allows it first
            f"{cli} intake CHG-0001 --from-file 'work/my answers.toml'",
            f"bash -c '{cli} intake CHG-0001'",
            f"echo $({cli} intake CHG-0001)",
            f"env -S '{cli} intake CHG-0001'",
            f"script -q /dev/null {cli} intake CHG-0001",
            f"script -qc '{cli} intake CHG-0001' /dev/null",
            f"unbuffer {cli} intake CHG-0001",
            f"expect -c 'spawn {cli} intake CHG-0001; interact'",
            f'python3 -c \'import subprocess; subprocess.run(["{cli}", "intake", "CHG-0001"])\'',
            f"xargs {cli} intake < ids.txt",
            f"find . -name x -exec {cli} intake {{}} ;",
            "eval cab intake CHG-0001",
            "bash scripts/run-intake.sh",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.scan(command), APPROVAL)
                self.assertEqual(self.scan(command, strict=True), APPROVAL)

    def test_reading_intake_files_stays_allowed(self) -> None:
        for command in (
            f"cat {CHANGE_DIR}/intake.md",
            f"grep -n Purpose {CHANGE_DIR}/intake.md",
            "cat work/intake.toml",
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.scan(command))


class ScanMatrixTests(ScanCase):
    def test_approval_commands(self) -> None:
        for command in APPROVAL_COMMANDS + (
            "tmux new-session 'cab approve CHG-0001'",
            "socat - EXEC:'cab approve CHG-0001'",
            "python3 -c 'import pty; pty.spawn(\"cab\")'",
            "eval cab approve CHG-0001",
            "xargs cab approve < ids.txt",
            "find . -name x -exec cab approve {} ;",
            "bash scripts/run-approve.sh",
        ):
            with self.subTest(command=command):
                if command == "bash scripts/run-approve.sh":
                    self.p.write("scripts/run-approve.sh", "cab approve CHG-0001\n")
                self.assertEqual(self.scan(command), APPROVAL)

    def test_protected_commands(self) -> None:
        for command, cwd, codes in PROTECTED_COMMANDS:
            with self.subTest(command=command):
                self.assertIn(self.scan(command, cwd), codes)

    def test_more_protected_shapes(self) -> None:
        cases = (
            ("exec 3> audit/ledger/2027-01.jsonl", PROTECTED),
            ("install -m 600 notes.txt audit/ledger/x", PROTECTED),
            ("rsync -a work/ policy/", PROTECTED),
            ("truncate -s 0 .cab/state/active.json", PROTECTED),
            ("unlink .cab/state/inflight", PROTECTED),
            ("rmdir changes", PROTECTED),
            ("git rm -r --cached .claude", PROTECTED),
            ("git -C work checkout -- ../policy/policy.toml", PROTECTED),
            ("perl -pi -e 's/a/b/' policy/policy.toml", PROTECTED),
            ("gawk -i inplace '{print}' policy/policy.toml", PROTECTED),
            ("sed -f work/bad.sed notes.txt", OPAQUE_SCRIPT),
            ("sed -i -f work/missing.sed notes.txt", OPAQUE_SCRIPT),
            ("bash scripts/touch-policy.sh", PROTECTED),
            ("source scripts/touch-policy.sh", PROTECTED),
            ("sudo -u root tee policy/policy.toml < notes.txt", PROTECTED),
            ("timeout 5 cp notes.txt policy/x", PROTECTED),
            ("env -S 'cp notes.txt policy/x'", PROTECTED),
            ("time -o policy/x ls", PROTECTED),
            ("find work -fprint policy/x", PROTECTED),
            ("tree -o policy/x", PROTECTED),
            ("trap 'echo x > .claude/settings.json' INT TERM", PROTECTED),
            ('trap "$CALLBACK" EXIT; echo policy/x', OPAQUE_WRITE),
            ("wget https://example.com/x -P policy", PROTECTED),
            ("wget https://example.com/policy.toml --directory-prefix=policy", PROTECTED),
            ("curl --remote-name --output-dir policy https://example.com/x", PROTECTED),
            ("curl -D policy/headers.txt https://example.com", PROTECTED),
            ("curl -c audit/cookies https://example.com", PROTECTED),
            ("wget -O- https://example.com > policy/x", PROTECTED),
            ("echo x > ~/.local/state/cab-of-one/approvals.jsonl", OPAQUE_WRITE),
            ("echo x > notes.$EXT", OPAQUE_WRITE),
            ("echo x > work/*.json", OPAQUE_WRITE),
            ("echo x > {a,b}.txt", OPAQUE_WRITE),
            ("echo x > `printf policy/x`", OPAQUE_WRITE),
            ("python3 - <<'EOF'\nopen('audit/ledger/x', 'w')\nEOF", OPAQUE_SCRIPT),
            ("pwsh -EncodedCommand ZQBjAGgAbwA=", OPAQUE_SCRIPT),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(self.scan(command), expected)

    def test_external_registry_by_absolute_path(self) -> None:
        registry = os.path.join(self.p.roots.state_home, "approvals.jsonl")
        self.assertEqual(self.scan(f"echo x >> '{registry}'"), PROTECTED)
        self.assertEqual(self.scan(f"rm -rf '{self.p.home}'"), PROTECTED)

    def test_safe_commands(self) -> None:
        for command in SAFE_COMMANDS + (
            "echo x > /dev/null 2>&1",
            "cat notes.txt | sort | uniq -c",
            "bash scripts/harmless.sh",
            "python3 scripts/bulk.py --batch one",
            "trap - EXIT",
            "trap 'echo bye' EXIT",
            "curl -o work/page.html https://example.com",
            "curl -s https://example.com",
            "wget -O work/page.html https://example.com",
            "git status",
            "git checkout -- notes.txt",
            "mkdir -p work/new",
            "ls policy audit .claude",
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.scan(command))

    def test_long_literal_words_are_text_not_errors(self) -> None:
        long_word = "contoso" * 40  # longer than one path component
        for command in (f"pytest -k {long_word}", f"python3 scripts/bulk.py --note {long_word}"):
            with self.subTest(command=command[:30]):
                self.assertIsNone(self.scan(command))

    def test_strict_mode_refuses_every_file_write(self) -> None:
        for command in ("echo x > notes.txt", "tee work/x < notes.txt", "sed -i s/a/b/ notes.txt",
                        "cp notes.txt work/y"):  # fmt: skip
            with self.subTest(command=command):
                self.assertIsNone(self.scan(command))
                self.assertEqual(self.scan(command, strict=True), OPAQUE_WRITE)
        self.assertIsNone(self.scan("cat notes.txt > /dev/null", strict=True))
        self.assertIsNone(self.scan("cat notes.txt", strict=True))

    def test_nested_and_deep_text_fails_closed(self) -> None:
        nested = "cab approve CHG-0001"
        for _ in range(10):
            nested = "bash -c " + repr(nested).replace('"', "'")
        self.assertIn(self.scan(nested), (APPROVAL, OPAQUE_WRITE, OPAQUE_SCRIPT))
        self.assertEqual(self.scan("echo 'unterminated > policy/x"), OPAQUE_WRITE)
        self.assertIsNone(self.scan("echo 'unterminated plain text"))
        self.assertEqual(shellscan.scan(None, None, self.ctx), OPAQUE_WRITE)

    def test_relative_target_without_cwd(self) -> None:
        self.assertEqual(shellscan.scan("echo x > notes.txt", None, self.ctx), OPAQUE_WRITE)
        abs_notes = str(self.p.path("notes.txt"))
        self.assertIsNone(shellscan.scan(f"echo x > '{abs_notes}'", None, self.ctx))


class BindingSafeTests(unittest.TestCase):
    def test_literal_commands(self) -> None:
        for command in (
            "python3 scripts/bulk.py --batch one",
            "python3 simtenant/simtenant.py --state tenant/state.json purge users u-1007",
            "sh -c 'python3 scripts/bulk.py --batch one'",
            "a && b; c",
        ):
            with self.subTest(command=command):
                self.assertTrue(shellscan.binding_safe(command))

    def test_anything_the_shell_expands_is_not_binding_safe(self) -> None:
        for command in (
            "python3 x.py $BATCH",
            'python3 x.py "${BATCH}"',
            "python3 x.py $(cat ids)",
            "python3 x.py `cat ids`",
            "python3 x.py *.csv",
            "python3 x.py {a,b}",
            "python3 x.py ~/ids",
            "diff <(cat a) b",
            "python3 x.py <<EOF\nids\nEOF",
            "python3 x.py <<< ids",
            "BATCH=1 python3 x.py",
            "eval python3 x.py",
            "source run.sh",
            ". run.sh",
            "xargs python3 x.py",
            "sh -c 'python3 x.py $BATCH'",
            "(python3 x.py $BATCH)",
            "echo 'unterminated",
        ):
            with self.subTest(command=command):
                self.assertFalse(shellscan.binding_safe(command))


class SubagentCommandTests(ScanCase):
    def ok(self, command: str) -> bool:
        return shellscan.subagent_command_ok(
            command, frozenset(DEFAULT_SUBAGENT_BASH_ALLOW), str(self.p.project), self.ctx
        )

    def test_read_only_allow_list(self) -> None:
        for command in (
            "cat notes.txt",
            "grep -rn Contoso changes | wc -l",
            "cat notes.txt 2>/dev/null",
            "ls -la work > /dev/null 2>&1",
            "head -n 5 notes.txt; tail -n 5 notes.txt",
        ):
            with self.subTest(command=command):
                self.assertTrue(self.ok(command))

    def test_everything_else_is_refused(self) -> None:
        for command in (
            "cat notes.txt > work/out.txt",
            "cat notes.txt >> notes.txt",
            "cat notes.txt | tee work/out.txt",
            "bash -c 'cat notes.txt'",
            "python3 -c 'print(1)'",
            "/bin/cat notes.txt",
            "CONTOSO=1 cat notes.txt",
            "cat <<EOF\nx\nEOF",
            "cat <<< x",
            "cat $(ls)",
            "(cat notes.txt)",
            "cat <(ls)",
            "find . -name x",
            "xargs cat < notes.txt",
            "env cat notes.txt",
            "sed -n 1p notes.txt",
            "awk '{print}' notes.txt",
            "git log",
            "curl https://example.com",
            "cab verify CHG-0001",
            "echo cab approve",
            "unknown-tool notes.txt",
        ):
            with self.subTest(command=command):
                self.assertFalse(self.ok(command))


if __name__ == "__main__":
    unittest.main()
