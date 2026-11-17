"""Publication checks: identifier scanner, DCO check, pre-push policy, CI and gitleaks config.

Disposable Git repositories live only under <checkout>/.local/test-tmp, with an isolated HOME
and no system Git config. Every value is fictional except the reviewed public code-of-conduct
contact, and all are assembled at run time, so this file does not itself match the rules it
tests. Real subprocesses run git and the two scripts.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / ".local" / "test-tmp"
SCANNER = ROOT / "scripts" / "check_identifiers.py"
DCO = ROOT / "scripts" / "check_dco.py"
HOOK = ROOT / ".githooks" / "pre-push"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
GITLEAKS = ROOT / ".gitleaks.toml"


def load(name: str, path: Path):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


ci = load("cab_check_identifiers", SCANNER)
dco = load("cab_check_dco", DCO)
hook = load("cab_pre_push", HOOK)


def j(*parts: str) -> str:
    return "".join(parts)


GUID_RANDOM = j("3f2c9a71-5b8e", "-4d0f-9a6c-1e7b2d4c8f90")
GUID_PLACEHOLDER = j("00000000-0000", "-0000-0000-000000000042")
IP_PRIVATE = ".".join(["10", "20", "30", "40"])
IP_CGNAT = ".".join(["100", "64", "1", "2"])
IP_PUBLIC = ".".join(["4", "2", "2", "1"])
IP_DOC = ".".join(["198", "51", "100", "9"])
EMAIL_UNKNOWN = j("jamie", "@", "fabrikam-widgets", ".com")
EMAIL_FICTIONAL = j("jamie", "@", "contoso", ".example")
MAC_HOME = j("/Us", "ers/jamie/work")
WIN_HOME = j("C:", "\\", "Users", "\\", "jamie")
LONG_ID = j("123456789", "0123456789")
TENANT_OTHER = j("fabrikam", ".onmicrosoft", ".com")
TENANT_CONTOSO = j("contoso", ".onmicrosoft", ".com")
NOREPLY = j("1234567+contoso-tester", "@users.noreply", ".github.com")
PRIVATE_TERM = j("Zephyr", "quill")  # stands in for a private denylist term
EXCEPTED_IP = j("203.0", ".113.7")  # EXCEPTIONS entry for tests/test_classify.py
OTHER_DOC_IP = j("203.0", ".113.8")
# Not fictional: the reviewed public code-of-conduct contact, the scanner's only e-mail
# EXCEPTIONS entry. Assembled in pieces so this file does not match the e-mail rule.
CONDUCT_PATH = "CODE_OF_CONDUCT.md"
CONDUCT_EMAIL = j("bay.forest3307", "@", "eagereverest", ".com")

ALL_VALUES = (
    GUID_RANDOM, IP_PRIVATE, IP_CGNAT, IP_PUBLIC, IP_DOC, EMAIL_UNKNOWN, MAC_HOME, WIN_HOME,
    LONG_ID, TENANT_OTHER,
)  # fmt: skip

GIT_ID = (
    "-c", "user.name=Contoso Tester", "-c", "user.email=" + NOREPLY,
    "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
)  # fmt: skip


def clean_env(home: Path) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") and k not in ("GITHUB_ACTIONS", "XDG_CONFIG_HOME")
    }
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
        }
    )
    return env


class RepoCase(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="pubcheck-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.repo = self.tmp / "repo with space"
        self.repo.mkdir()
        self.env = clean_env(self.home)
        self.git("init", "-q")
        self.write(".gitignore", "/.local/\n/.build-inputs/\n/CLAUDE.md\nignored.txt\n")

    # helpers

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            ["git", *GIT_ID, "-C", str(self.repo), *args],
            env=self.env,
            capture_output=True,
            check=check,
        )

    def write(self, rel: str, content: str | bytes, base: Path | None = None) -> Path:
        path = (base or self.repo) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            content = content.encode("utf-8")
        path.write_bytes(content)
        return path

    def commit(self, message: str, author: str | None = None, empty: bool = False) -> str:
        self.git("add", "-A")
        args = ["commit", "-q", "-m", message]
        if author:
            args += ["--author", author]
        if empty:
            args.append("--allow-empty")
        self.git(*args)
        return self.git("rev-parse", "HEAD").stdout.decode().strip()

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")

    def scan(self, *args: str, env: dict[str, str] | None = None) -> tuple[int, str, str]:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(SCANNER), "--root", str(self.repo), *args],
            env=env or self.env,
            capture_output=True,
            check=False,
        )
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    def scan_json(self, *args: str, env: dict[str, str] | None = None) -> tuple[int, dict]:
        code, out, _err = self.scan("--json", *args, env=env)
        return code, json.loads(out)

    def assert_no_values(self, text: str, values: tuple[str, ...] = ALL_VALUES) -> None:
        for value in values:
            self.assertNotIn(value, text)
            self.assertNotIn(value.lower(), text.lower())

    def findings(self, doc: dict) -> set[tuple[str, str, int]]:
        return {(f["rule"], f["path"], f["line"]) for f in doc["findings"]}

    def errors(self, doc: dict) -> set[tuple[str, str]]:
        return {(e["code"], e["path"]) for e in doc["errors"]}


class GenericRuleTests(RepoCase):
    def test_fictional_values_pass_before_first_commit(self) -> None:
        self.write(
            "docs/fictional.md",
            f"mail {EMAIL_FICTIONAL}\nobject {GUID_PLACEHOLDER}\ntenant {TENANT_CONTOSO}\n"
            f"upn admin@{TENANT_CONTOSO}\nversion 2.1.319 and 1.2.3\n",
        )
        self.assertNotEqual(self.git("rev-parse", "--verify", "HEAD", check=False).returncode, 0)
        code, doc = self.scan_json()
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["result"], "clean")
        self.assertEqual(doc["files"], 2)

    def test_each_rule_reports_rule_path_line_and_never_the_value(self) -> None:
        lines = [
            f"id {GUID_RANDOM}",
            f"host {IP_PRIVATE}",
            f"node {IP_CGNAT}.",
            f"edge {IP_PUBLIC}",
            f"doc {IP_DOC}",
            f"mail <{EMAIL_UNKNOWN}>",
            f"path {MAC_HOME}/x",
            f"path {WIN_HOME}\\x",
            f"channel {LONG_ID}",
            f"tenant {TENANT_OTHER}",
        ]
        rel = "notes/file one.md"
        self.write(rel, "\n".join(lines) + "\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        expected = {
            ("guid", rel, 1),
            ("ipv4-private", rel, 2),
            ("ipv4-cgnat", rel, 3),
            ("ipv4-public", rel, 4),
            ("ipv4-reserved", rel, 5),
            ("email", rel, 6),
            ("local-path", rel, 7),
            ("local-path", rel, 8),
            ("long-numeric-id", rel, 9),
            ("onmicrosoft-tenant", rel, 10),
        }
        self.assertEqual(self.findings(doc), expected)
        for item in doc["findings"]:
            self.assertEqual(set(item), {"rule", "path", "line"})
        self.assert_no_values(json.dumps(doc))
        code, out, err = self.scan()
        self.assertEqual(code, 1)
        self.assertIn('rule=guid path="notes/file one.md" line=1', out)
        self.assert_no_values(out + err)

    def test_line_rules_ignore_lookalikes(self) -> None:
        lookalikes = [
            "1.2.3",
            "1.2.3.4.5",
            "300.1.1.1",
            "@decorator",
            "user@localhost",
            j("sha ab", "123456789", "0123456789", "cd"),
            GUID_PLACEHOLDER,
            j("ops", "@", "corp", ".test"),
        ]
        for text in lookalikes:
            with self.subTest(text=text):
                self.assertEqual(list(ci.scan_line(text, 1)), [])

    def test_exception_needs_exact_value_and_exact_path(self) -> None:
        self.write("tests/test_classify.py", f"URL = 'https://{EXCEPTED_IP}/v1.0'\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 0, doc)
        self.write("tests/test_classify.py", f"URL = 'https://{OTHER_DOC_IP}/v1.0'\n")
        self.write("tests/test_other.py", f"URL = 'https://{EXCEPTED_IP}/v1.0'\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(
            self.findings(doc),
            {
                ("ipv4-reserved", "tests/test_classify.py", 1),
                ("ipv4-reserved", "tests/test_other.py", 1),
            },
        )

    def test_conduct_contact_is_the_only_email_exception(self) -> None:
        emails = {e for e in ci.EXCEPTIONS if e[0] == "email"}
        self.assertEqual(emails, {("email", CONDUCT_PATH, CONDUCT_EMAIL)})
        # The rule itself still flags the address; only the exact path/value pair is excused.
        self.assertEqual(
            [h.rule for h in ci.scan_line(f"report to <{CONDUCT_EMAIL}>", 1)], ["email"]
        )

    def test_conduct_contact_passes_only_in_code_of_conduct(self) -> None:
        self.write(CONDUCT_PATH, f"# Code of conduct\n\nReport to <{CONDUCT_EMAIL}>.\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["result"], "clean")

        user, _at, domain = CONDUCT_EMAIL.partition("@")
        self.write(
            CONDUCT_PATH,
            f"Report to <{CONDUCT_EMAIL}>.\n"
            f"Or <{EMAIL_UNKNOWN}>.\n"
            f"Or <{j('other', '@', domain)}>.\n"
            f"Or <{CONDUCT_EMAIL.upper()}>.\n",
        )
        self.write("README.md", f"Contact {CONDUCT_EMAIL}\n")
        self.write(f"docs/{CONDUCT_PATH}", f"Contact {CONDUCT_EMAIL}\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(
            self.findings(doc),
            {
                ("email", CONDUCT_PATH, 2),
                ("email", CONDUCT_PATH, 3),
                ("email", CONDUCT_PATH, 4),
                ("email", "README.md", 1),
                ("email", f"docs/{CONDUCT_PATH}", 1),
            },
        )
        self.assert_no_values(json.dumps(doc), (CONDUCT_EMAIL, user, domain))

    def test_exceptions_table_does_not_match_its_own_rules(self) -> None:
        text = SCANNER.read_text(encoding="utf-8")
        hits = [h for n, line in enumerate(text.split("\n"), 1) for h in ci.scan_line(line, n)]
        self.assertEqual(hits, [])

    def test_root_must_be_the_top_level(self) -> None:
        (self.repo / "docs").mkdir()
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(SCANNER), "--root", str(self.repo / "docs"), "--json"],
            env=self.env,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["code"], "root_not_toplevel")


class CandidateSetTests(RepoCase):
    def test_ignored_files_are_not_read(self) -> None:
        self.write("ignored.txt", f"{EMAIL_UNKNOWN}\n")
        self.write(".local/notes.md", f"{EMAIL_UNKNOWN}\n")
        self.write("docs/ok.md", "fictional Contoso notes\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 0, doc)
        self.assertEqual(doc["files"], 2)

    def test_tracked_ignored_file_is_an_error_and_is_not_read(self) -> None:
        self.write("ignored.txt", f"{EMAIL_UNKNOWN}\n")
        self.git("add", "-f", "ignored.txt")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(self.errors(doc), {("tracked_ignored", "ignored.txt")})
        self.assertEqual(doc["findings"], [])

    def test_private_path_is_never_read_even_when_unignored(self) -> None:
        self.write(".gitignore", "ignored.txt\n")
        self.write(".local/notes.md", f"{EMAIL_UNKNOWN}\n")
        self.write("CLAUDE.md", f"{EMAIL_UNKNOWN}\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(
            self.errors(doc), {("private_path", ".local/notes.md"), ("private_path", "CLAUDE.md")}
        )
        self.assertEqual(doc["findings"], [])

    def test_symlinks_are_rejected_and_never_followed(self) -> None:
        outside = self.write("outside.txt", f"{EMAIL_UNKNOWN}\n", base=self.tmp)
        outside_dir = self.tmp / "outside-dir"
        self.write("inner.md", f"{EMAIL_UNKNOWN}\n", base=outside_dir)
        self.symlink_or_skip(outside, self.repo / "docs" / "link.md")
        self.symlink_or_skip(outside_dir, self.repo / "linkdir")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(self.errors(doc), {("symlink", "docs/link.md"), ("symlink", "linkdir")})
        self.assertEqual(doc["findings"], [])

    def test_binary_and_invalid_utf8_fail_closed(self) -> None:
        self.write("assets/blob.bin", b"GIF89a\x00\x01")
        self.write("docs/latin1.txt", b"caf\xe9\n")
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(
            self.errors(doc),
            {("binary", "assets/blob.bin"), ("invalid_utf8", "docs/latin1.txt")},
        )

    def test_file_size_and_count_bounds(self) -> None:
        self.write("docs/big.md", "x" * 64)
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, self.env, clear=True),
            mock.patch.object(ci, "MAX_FILE_BYTES", 16),
            contextlib.redirect_stdout(out),
        ):
            code = ci.main(["--root", str(self.repo), "--json"])
        self.assertEqual(code, 1)
        self.assertIn(("too_large", "docs/big.md"), self.errors(json.loads(out.getvalue())))
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, self.env, clear=True),
            mock.patch.object(ci, "MAX_FILES", 1),
            contextlib.redirect_stdout(out),
        ):
            code = ci.main(["--root", str(self.repo), "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["code"], "too_many_files")


class DenylistTests(RepoCase):
    def denylist(self, content: str | bytes, name: str = "deny list.txt") -> Path:
        return self.write(name, content, base=self.tmp)

    def assert_private_output_clean(self, text: str, path: Path) -> None:
        low = text.lower()
        self.assertNotIn(PRIVATE_TERM.lower(), low)
        self.assertNotIn(path.name.lower(), low)
        for term in (PRIVATE_TERM, PRIVATE_TERM.casefold()):
            for algo in ("sha256", "sha1", "md5"):
                self.assertNotIn(hashlib.new(algo, term.encode()).hexdigest(), low)

    def test_literal_case_insensitive_match_reports_line_only(self) -> None:
        deny = self.denylist(f"   \n{PRIVATE_TERM.lower()}\n\na.c\n")
        self.write("docs/notes.md", f"Built by {PRIVATE_TERM.upper()} ops\nabc\n")
        code, doc = self.scan_json("--denylist", str(deny))
        self.assertEqual(code, 1)
        self.assertEqual(self.findings(doc), {("private-denylist", "docs/notes.md", 1)})
        self.assert_private_output_clean(json.dumps(doc), deny)
        code, out, err = self.scan("--denylist", str(deny))
        self.assertEqual(code, 1)
        self.assert_private_output_clean(out + err, deny)

    def test_path_matching_a_term_is_redacted(self) -> None:
        deny = self.denylist(PRIVATE_TERM + "\n")
        self.write(f"docs/{PRIVATE_TERM}-notes.md", "fictional Contoso notes\n")
        code, doc = self.scan_json("--denylist", str(deny))
        self.assertEqual(code, 1)
        self.assertEqual(self.findings(doc), {("private-denylist", "[redacted path #2]", 0)})
        self.assert_private_output_clean(json.dumps(doc), deny)

    def test_bad_denylists_fail_closed_without_revealing_anything(self) -> None:
        self.write("docs/notes.md", f"{PRIVATE_TERM}\n")
        good = self.denylist(PRIVATE_TERM + "\n", "target.txt")
        (self.tmp / "denydir").mkdir()
        cases = {
            "denylist_missing": self.tmp / "absent.txt",
            "denylist_empty": self.denylist("", "empty.txt"),
            "denylist_empty ": self.denylist(" \n\t\n", "blank.txt"),
            "denylist_not_utf8": self.denylist(b"\xff\xfe\n", "latin.txt"),
            "denylist_not_regular_file": self.tmp / "denydir",
            "denylist_inside_repository": self.write(".local/deny.txt", PRIVATE_TERM + "\n"),
        }
        link = self.tmp / "link.txt"
        self.symlink_or_skip(good, link)
        cases["denylist_symlink"] = link
        for code_name, path in cases.items():
            with self.subTest(code=code_name.strip()):
                code, out, err = self.scan("--json", "--denylist", str(path))
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(out)["code"], code_name.strip())
                self.assert_private_output_clean(out + err, path)

    def test_denylist_is_refused_under_github_actions(self) -> None:
        deny = self.denylist(PRIVATE_TERM + "\n")
        env = dict(self.env, GITHUB_ACTIONS="true")
        code, doc = self.scan_json("--denylist", str(deny), env=env)
        self.assertEqual(code, 2)
        self.assertEqual(doc["code"], "denylist_refused_in_ci")


class DenylistReadTests(RepoCase):
    """In-process: os.read is replaced to force short reads, early EOF and growth."""

    def setUp(self) -> None:
        super().setUp()
        self.terms = [j("alpha", "term"), j("beta", "term"), PRIVATE_TERM]
        self.path = self.write("deny.txt", "\n".join(self.terms) + "\n", base=self.tmp)
        self.real_read = os.read

    def load(self, fake_read) -> tuple[str, ...]:
        with (
            mock.patch.dict(os.environ, self.env, clear=True),
            mock.patch.object(ci.os, "read", side_effect=fake_read),
        ):
            return ci.load_denylist(str(self.path), self.repo)

    def assert_fatal(self, fake_read, code: str) -> None:
        with self.assertRaises(ci.FatalError) as caught:
            self.load(fake_read)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(PRIVATE_TERM.lower(), str(caught.exception).lower())
        self.assertNotIn(self.path.name, str(caught.exception))

    def test_one_byte_reads_still_load_every_term(self) -> None:
        terms = self.load(lambda fd, n: self.real_read(fd, 1))
        self.assertEqual(terms, tuple(t.casefold() for t in self.terms))

    def test_premature_eof_fails_closed(self) -> None:
        calls = []

        def short(fd: int, n: int) -> bytes:
            calls.append(n)
            return self.real_read(fd, 5) if len(calls) == 1 else b""

        self.assert_fatal(short, "denylist_unreadable")

    def test_file_changing_during_read_fails_closed(self) -> None:
        grown = []

        def grow(fd: int, n: int) -> bytes:
            if not grown:
                grown.append(True)
                with open(self.path, "ab") as handle:
                    handle.write(b"late term\n")
            return self.real_read(fd, n)

        self.assert_fatal(grow, "denylist_changed")

    def test_endless_stream_is_bounded(self) -> None:
        with mock.patch.object(ci, "MAX_DENYLIST_BYTES", 64):
            self.assert_fatal(lambda fd, n: b"x" * n, "denylist_too_large")


class RefScanTests(RepoCase):
    def test_pushed_ref_names_are_scanned_without_echo(self) -> None:
        deny = self.write("deny.txt", PRIVATE_TERM + "\n", base=self.tmp)
        refs = [
            "refs/heads/" + GUID_RANDOM,
            "refs/heads/" + EMAIL_UNKNOWN,
            "refs/heads/wip+" + MAC_HOME,
            f"refs/heads/{PRIVATE_TERM.lower()}-plan",
            "refs/heads/main",
        ]
        args = ["--denylist", str(deny), *(f"--ref={r}" for r in refs)]
        code, doc = self.scan_json(*args)
        self.assertEqual(code, 1)
        self.assertEqual(
            self.findings(doc),
            {
                ("guid", "[pushed ref #1]", 0),
                ("email", "[pushed ref #2]", 0),
                ("local-path", "[pushed ref #3]", 0),
                ("private-denylist", "[pushed ref #4]", 0),
            },
        )
        code, out, err = self.scan(*args)
        self.assertEqual(code, 1)
        for text in (json.dumps(doc), out + err):
            self.assert_no_values(text, (GUID_RANDOM, EMAIL_UNKNOWN, MAC_HOME, PRIVATE_TERM))
            self.assertNotIn("refs/heads", text)
        code, doc = self.scan_json("--ref=refs/heads/main", "--ref=refs/tags/v0.1.0")
        self.assertEqual(code, 0, doc)

    def test_invalid_refs_fail_closed_without_echo(self) -> None:
        bad = [
            "heads/main",
            "refs/heads/a..b",
            f"refs/heads/{PRIVATE_TERM}\x01",
            f"refs/heads/{PRIVATE_TERM} x",
            "refs/heads/x.lock",
            "refs/heads/x@{1}",
            "refs/heads/",
            "refs/heads/" + "a" * 1100,
            "",
        ]
        for ref in bad:
            with self.subTest(ref=ref[:24]):
                code, out, err = self.scan("--json", f"--ref={ref}")
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(out)["code"], "ref_invalid")
                self.assertNotIn(PRIVATE_TERM.lower(), (out + err).lower())


class PrePushEndToEndTests(RepoCase):
    """The real hook main() against a disposable repo, with a stub gitleaks on PATH."""

    def setUp(self) -> None:
        super().setUp()
        self.write("scripts/check_identifiers.py", SCANNER.read_bytes())
        self.write(".gitleaks.toml", GITLEAKS.read_bytes())
        self.write("docs/notes.md", "fictional Contoso notes\n")
        self.head = self.commit(f"Initial\n\nSigned-off-by: Contoso Tester <{NOREPLY}>")
        bin_dir = self.tmp / "bin"
        stub = self.write("gitleaks", '#!/bin/sh\nprintf "%s\\n" "$@" >> "$STUB_LOG"\n', bin_dir)
        stub.chmod(0o755)
        self.log = self.tmp / "gitleaks-argv.log"
        config_dir = self.home / ".config" / "cab-of-one"
        self.denylist = self.write("denylist.txt", PRIVATE_TERM + "\n", config_dir)
        (self.tmp / "tmp").mkdir()
        self.hook_env = dict(
            self.env,
            PATH=f"{bin_dir}{os.pathsep}{self.env.get('PATH', '')}",
            STUB_LOG=str(self.log),
            TMPDIR=str(self.tmp / "tmp"),
        )

    def run_hook(self, remote_ref: str = "refs/heads/main") -> tuple[int, str]:
        line = f"refs/heads/main {self.head} {remote_ref} {'0' * 40}\n"
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(HOOK), "origin", "https://git.example/contoso/x.git"],
            input=line.encode(),
            env=self.hook_env,
            cwd=self.repo,
            capture_output=True,
            check=False,
        )
        return proc.returncode, proc.stdout.decode() + proc.stderr.decode()

    def test_clean_push_runs_gitleaks_without_suppression_channels(self) -> None:
        code, out = self.run_hook()
        self.assertEqual(code, 0, out)
        argv = self.log.read_text(encoding="utf-8").split("\n")
        self.assertEqual(argv.count("--ignore-gitleaks-allow"), 2)
        self.assertEqual(argv.count("--redact"), 2)
        self.assertEqual(argv.count("--log-opts=--all -m"), 1)
        ignore_paths = [argv[i + 1] for i, a in enumerate(argv) if a == "--gitleaks-ignore-path"]
        self.assertEqual(ignore_paths, [os.devnull, os.devnull])
        self.assertEqual(argv.count(str(self.repo / ".gitleaks.toml")), 2)

    def test_private_term_in_remote_ref_blocks_before_gitleaks(self) -> None:
        code, out = self.run_hook(f"refs/heads/{PRIVATE_TERM.lower()}-plan")
        self.assertEqual(code, 1)
        self.assertNotIn(PRIVATE_TERM.lower(), out.lower())
        self.assertFalse(self.log.exists())

    def test_ignored_root_suppression_file_blocks_before_gitleaks(self) -> None:
        self.write(".gitignore", SuppressionFileTests.IGNORE_ROOT)
        self.head = self.commit(f"Ignore\n\nSigned-off-by: Contoso Tester <{NOREPLY}>")
        target = self.repo / ".gitleaksignore"
        for name, make in (
            ("regular", lambda: self.write(".gitleaksignore", "fingerprint\n")),
            ("dangling symlink", lambda: self.symlink_or_skip(self.tmp / "absent", target)),
        ):
            with self.subTest(variant=name):
                if os.path.lexists(target):
                    os.unlink(target)
                make()
                code, out = self.run_hook()
                self.assertEqual(code, 1)
                self.assertIn("suppression file (.gitleaksignore)", out)
                self.assertNotIn("fingerprint", out)
                self.assertFalse(self.log.exists())

    def test_missing_denylist_blocks_before_gitleaks(self) -> None:
        self.denylist.unlink()
        code, out = self.run_hook()
        self.assertEqual(code, 1)
        self.assertIn("denylist_missing", out)
        self.assertFalse(self.log.exists())


class SuppressionFileTests(RepoCase):
    """gitleaks always loads <source>/.gitleaksignore; such files are refused, never read."""

    IGNORE_ROOT = "/.local/\n/.build-inputs/\n/CLAUDE.md\nignored.txt\n/.gitleaksignore\n"

    def test_root_file_is_refused_in_any_form_without_reading(self) -> None:
        self.write(".gitignore", self.IGNORE_ROOT)
        outside = self.write("outside.txt", f"{GUID_RANDOM}\n", base=self.tmp)
        variants = {
            "ignored regular file": lambda p: self.write(p.name, f"{GUID_RANDOM}\n"),
            "case variant": lambda p: self.write(".GitLeaksIgnore", f"{GUID_RANDOM}\n"),
            "symlink": lambda p: self.symlink_or_skip(outside, p),
            "dangling symlink": lambda p: self.symlink_or_skip(self.tmp / "absent", p),
        }
        for name, make in variants.items():
            with self.subTest(variant=name):
                for entry in os.listdir(self.repo):
                    if entry.casefold() == ".gitleaksignore":
                        os.unlink(self.repo / entry)
                make(self.repo / ".gitleaksignore")
                code, doc = self.scan_json()
                self.assertEqual(code, 1)
                self.assertEqual({e["code"] for e in doc["errors"]}, {"suppression_file"})
                self.assertEqual(doc["findings"], [])
                self.assert_no_values(json.dumps(doc), (GUID_RANDOM,))
                dest = self.tmp / f"export-{len(name)}"
                code, doc = self.scan_json("--export", str(dest))
                self.assertEqual(code, 1)
                self.assertFalse(dest.exists())

    def test_nested_tracked_and_committed_files_are_refused(self) -> None:
        self.write("docs/.gitleaksignore", f"{GUID_RANDOM}\n")
        self.write("sub/dir/.GITLEAKSIGNORE", f"{GUID_RANDOM}\n")
        expected = {
            ("suppression_file", "docs/.gitleaksignore"),
            ("suppression_file", "sub/dir/.GITLEAKSIGNORE"),
        }
        code, doc = self.scan_json()
        self.assertEqual(code, 1)
        self.assertEqual(self.errors(doc), expected)
        self.assertEqual(doc["findings"], [])
        sha = self.commit(f"Add\n\nSigned-off-by: Contoso Tester <{NOREPLY}>")
        code, doc = self.scan_json()  # now tracked
        self.assertEqual((code, self.errors(doc)), (1, expected))
        code, doc = self.scan_json("--rev", sha)
        self.assertEqual(code, 1)
        self.assertEqual(
            {(e["code"], e["path"], e["commit"]) for e in doc["errors"]},
            {(c, p, sha[:12]) for c, p in expected},
        )
        self.assertEqual(doc["findings"], [])
        dest = self.tmp / "export"
        code, doc = self.scan_json("--rev", sha, "--export", str(dest))
        self.assertEqual(code, 1)
        self.assertFalse(dest.exists())


class RevisionTests(RepoCase):
    def test_rev_scans_the_committed_tree_not_the_working_tree(self) -> None:
        self.write("data/ids.txt", f"channel {LONG_ID}\n")
        first = self.commit("Add ids\n\nSigned-off-by: Contoso Tester <" + NOREPLY + ">")
        self.git("rm", "-q", "data/ids.txt")
        self.commit("Remove ids\n\nSigned-off-by: Contoso Tester <" + NOREPLY + ">")
        self.assertEqual(self.scan_json()[0], 0)
        code, doc = self.scan_json("--rev", first)
        self.assertEqual(code, 1)
        self.assertEqual(
            doc["findings"],
            [{"rule": "long-numeric-id", "path": "data/ids.txt", "line": 1, "commit": first[:12]}],
        )

    def test_commit_metadata_identity_and_message(self) -> None:
        deny = self.write("deny.txt", PRIVATE_TERM + "\n", base=self.tmp)
        self.write("docs/notes.md", "fictional Contoso notes\n")
        self.commit("Add notes\n\nSigned-off-by: Contoso Tester <" + NOREPLY + ">")
        code, doc = self.scan_json(
            "--denylist", str(deny), "--check-commit-metadata", "--rev", "HEAD"
        )
        self.assertEqual(code, 0, doc)
        self.write("docs/more.md", "more fictional notes\n")
        sha = self.commit(
            f"Mention {PRIVATE_TERM}\n\nSigned-off-by: Contoso Tester <{EMAIL_UNKNOWN}>",
            author=f"Contoso Tester <{EMAIL_FICTIONAL}>",
        )
        code, doc = self.scan_json(
            "--denylist", str(deny), "--check-commit-metadata", "--rev", "HEAD"
        )
        self.assertEqual(code, 1)
        got = {(f["rule"], f["path"], f["line"], f["commit"]) for f in doc["findings"]}
        self.assertEqual(
            got,
            {
                ("commit-identity-not-noreply", "commit author", 0, sha[:12]),
                ("private-denylist", "commit message", 1, sha[:12]),
                ("email", "commit message", 3, sha[:12]),
            },
        )
        text = json.dumps(doc)
        self.assertNotIn(PRIVATE_TERM.lower(), text.lower())
        self.assert_no_values(text, (EMAIL_UNKNOWN, EMAIL_FICTIONAL, NOREPLY))

    def test_rev_rejects_option_like_and_unknown_revisions(self) -> None:
        for rev, expected in (("--output=x", "rev_invalid"), ("f" * 40, "rev_unknown")):
            with self.subTest(rev=rev):
                code, doc = self.scan_json(f"--rev={rev}")
                self.assertEqual(code, 2)
                self.assertEqual(doc["code"], expected)


class ExportTests(RepoCase):
    def test_malformed_tree_paths_never_escape_export(self) -> None:
        for raw in (b"../escape", b"a/../../escape", b"/outside", b"a//b", b"./a"):
            with self.subTest(raw=raw):
                report = ci.Report()
                scanner = ci.Scanner(self.repo, (), report)
                entries = [entry for entry, _ in scanner._decode_paths([raw])]
                dest = self.tmp / "blocked-export"
                ci.export_candidate(scanner, entries, str(dest))
                self.assertFalse(dest.exists())
                self.assertEqual(report.errors[0]["code"], "path_invalid")

    def exported(self, dest: Path) -> set[str]:
        return {
            str(Path(d, f).relative_to(dest)).replace(os.sep, "/")
            for d, _dirs, files in os.walk(dest)
            for f in files
        }

    def test_export_copies_only_the_candidate(self) -> None:
        self.write("docs/a b.md", "fictional Contoso notes\n")
        self.write("ignored.txt", "not for publication\n")
        self.write(".local/private.md", "not for publication\n")
        dest = self.tmp / "export dir"
        code, doc = self.scan_json("--export", str(dest))
        self.assertEqual(code, 0, doc)
        self.assertEqual(self.exported(dest), {".gitignore", "docs/a b.md"})

    def test_export_of_a_revision_ignores_uncommitted_files(self) -> None:
        self.write("docs/a.md", "fictional Contoso notes\n")
        self.commit("Add a\n\nSigned-off-by: Contoso Tester <" + NOREPLY + ">")
        self.write("docs/draft.md", "uncommitted\n")
        dest = self.tmp / "export"
        code, doc = self.scan_json("--rev", "HEAD", "--export", str(dest))
        self.assertEqual(code, 0, doc)
        self.assertEqual(self.exported(dest), {".gitignore", "docs/a.md"})

    def test_export_refuses_unsafe_targets_and_bad_files(self) -> None:
        (self.tmp / "exists").mkdir()
        for dest, expected in (
            (self.repo / "out", "export_inside_repository"),
            (self.tmp / "exists", "export_target_exists"),
        ):
            with self.subTest(expected=expected):
                code, doc = self.scan_json("--export", str(dest))
                self.assertEqual(code, 2)
                self.assertEqual(doc["code"], expected)
        self.write("assets/blob.bin", b"\x00")
        dest = self.tmp / "never"
        code, doc = self.scan_json("--export", str(dest))
        self.assertEqual(code, 1)
        self.assertFalse(dest.exists())


class DcoTests(RepoCase):
    def signed(self, subject: str) -> str:
        return f"{subject}\n\nSigned-off-by: Contoso Tester <{NOREPLY}>"

    def run_dco(self, *args: str, env: dict[str, str] | None = None) -> tuple[int, str]:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(DCO), "--root", str(self.repo), *args],
            env=env or self.env,
            capture_output=True,
            check=False,
            cwd=self.tmp,
        )
        return proc.returncode, proc.stdout.decode() + proc.stderr.decode()

    def make_history(self) -> tuple[str, str, str]:
        base = self.commit("Old unsigned", empty=True)
        self.commit(self.signed("New one"), empty=True)
        bad = self.commit("New unsigned", empty=True)
        head = self.commit(self.signed("New two"), empty=True)
        return base, bad, head

    def test_missing_and_wrong_signoff_lines(self) -> None:
        def raw(author: str, message: str) -> bytes:
            ident = f"Contoso Tester <{author}> 1700000000 +0000"
            return f"tree {'0' * 40}\nauthor {ident}\ncommitter {ident}\n\n{message}".encode()

        good = f"Signed-off-by: Contoso Tester <{NOREPLY}>"
        cases = {
            "ok": good,
            "dco_missing": "No trailer at all",
            "dco_malformed": f"Signed-off-by Contoso Tester <{NOREPLY}>",
            "dco_malformed ": f"signed-off-by: Contoso Tester <{NOREPLY}>",
            "dco_malformed  ": "Signed-off-by: Contoso Tester",
            "dco_author_mismatch": f"Signed-off-by: Someone Else <{EMAIL_FICTIONAL}>",
        }
        for expected, trailer in cases.items():
            with self.subTest(expected=expected, trailer=trailer):
                verdict = dco.check_message(raw(NOREPLY, f"Change\n\n{trailer}\n"))
                self.assertEqual(verdict, expected.strip())
        upper = raw(NOREPLY.upper(), f"Change\n\n{good}\n")
        self.assertEqual(dco.check_message(upper), "ok")

    def test_range_checks_only_new_commits(self) -> None:
        base, bad, head = self.make_history()
        code, out = self.run_dco("--base", base, "--head", head)
        self.assertEqual(code, 1)
        self.assertEqual(re.findall(r"commit=([0-9a-f]+)", out), [bad[:12]])
        self.assertIn("commits=3 failing=1", out)
        self.assertNotIn("Contoso Tester", out)
        self.assertNotIn(NOREPLY, out)
        self.assertNotIn("unsigned", out)

    def test_zero_or_unknown_base_checks_every_reachable_commit(self) -> None:
        base, bad, head = self.make_history()
        for value in ("0" * 40, "f" * 40, ""):
            with self.subTest(base=value or "empty"):
                code, out = self.run_dco("--base", value, "--head", head)
                self.assertEqual(code, 1)
                self.assertIn("no usable base", out)
                self.assertEqual(
                    sorted(re.findall(r"commit=([0-9a-f]+)", out)), sorted([base[:12], bad[:12]])
                )

    def test_environment_inputs(self) -> None:
        base, bad, head = self.make_history()
        env = dict(self.env, DCO_BASE=base, DCO_HEAD=head)
        code, out = self.run_dco(env=env)
        self.assertEqual(code, 1)
        self.assertEqual(re.findall(r"commit=([0-9a-f]+)", out), [bad[:12]])
        for bad_env in (
            {"DCO_BASE": "$(touch pwned)", "DCO_HEAD": head},
            {"DCO_BASE": base, "DCO_HEAD": "HEAD"},
            {"DCO_BASE": base, "DCO_HEAD": f"{head} --all"},
            {"DCO_BASE": base},
        ):
            with self.subTest(env=bad_env):
                code, out = self.run_dco(env=dict(self.env, **bad_env))
                self.assertEqual(code, 2)
                self.assertRegex(out, r"code=(rev_invalid|rev_missing)")
        self.assertFalse((self.tmp / "pwned").exists())

    def test_cli_inputs_are_validated_and_bounded(self) -> None:
        _base, bad, head = self.make_history()
        code, out = self.run_dco("--base=--output=x", "--head", head)
        self.assertEqual(code, 2)
        self.assertIn("code=rev_invalid", out)
        code, out = self.run_dco("--head", "HEAD", "--base", "HEAD^")
        self.assertEqual(code, 2)
        self.assertIn("code=rev_invalid", out)
        code, out = self.run_dco("--head", "HEAD", "--base", bad)
        self.assertEqual(code, 0, out)
        code, out = self.run_dco("--head", head, "--base", "", "--max-commits", "2")
        self.assertEqual(code, 1)
        self.assertIn("code=range_too_large", out)


class PrePushTests(RepoCase):
    def test_parse_updates(self) -> None:
        sha = "a" * 40
        ok = hook.parse_updates(f"refs/heads/main {sha} refs/heads/main {'0' * 40}\n".encode())
        self.assertEqual([u.local_sha for u in ok], [sha])
        self.assertEqual(hook.parse_updates(b""), [])
        for bad in (
            b"refs/heads/main abc refs/heads/main 0000\n",
            f"refs/heads/main {sha} refs/heads/main\n".encode(),
            b"\xff\xfe\n",
            b"x" * (hook.MAX_STDIN_BYTES + 1),
        ):
            with self.subTest(bad=bad[:40]), self.assertRaises(hook.Blocked):
                hook.parse_updates(bad)

    def test_policy_allows_only_head_and_refuses_deletes(self) -> None:
        head = "b" * 40
        zero = "0" * 40
        hook.check_policy([hook.Update("refs/heads/main", head, "refs/heads/main", zero)], head)
        for local in (zero, "c" * 40):
            with self.subTest(local=local[:4]), self.assertRaises(hook.Blocked):
                hook.check_policy(
                    [hook.Update("refs/heads/main", local, "refs/heads/main", zero)], head
                )

    def test_pushed_commits_are_new_objects_only(self) -> None:
        first = self.commit(f"One\n\nSigned-off-by: Contoso Tester <{NOREPLY}>", empty=True)
        head = self.commit(f"Two\n\nSigned-off-by: Contoso Tester <{NOREPLY}>", empty=True)
        ref = "refs/heads/main"
        with mock.patch.dict(os.environ, self.env, clear=True):
            initial = hook.pushed_commits(self.repo, [hook.Update(ref, head, ref, "0" * 40)])
            update = hook.pushed_commits(self.repo, [hook.Update(ref, head, ref, first)])
            unknown = hook.pushed_commits(self.repo, [hook.Update(ref, head, ref, "e" * 40)])
        self.assertEqual(set(initial), {first, head})
        self.assertEqual(update, [head])
        self.assertEqual(set(unknown), {first, head})

    def test_stale_tracking_ref_does_not_hide_a_pushed_commit(self) -> None:
        first = self.commit(f"One\n\nSigned-off-by: Contoso Tester <{NOREPLY}>", empty=True)
        head = self.commit(f"Two\n\nSigned-off-by: Contoso Tester <{NOREPLY}>", empty=True)
        # A local tracking ref claims the remote has HEAD; the push line says it has nothing.
        self.git("update-ref", "refs/remotes/origin/main", head)
        self.git("update-ref", "refs/remotes/origin/old", first)
        ref = "refs/heads/main"
        with mock.patch.dict(os.environ, self.env, clear=True):
            shas = hook.pushed_commits(self.repo, [hook.Update(ref, head, ref, "0" * 40)])
        self.assertEqual(set(shas), {first, head})

    def test_hook_source_has_no_install_config_or_bypass(self) -> None:
        text = HOOK.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/usr/bin/env python3\n"))
        self.assertNotRegex(text, r'git\([^)]*"config"')
        self.assertNotIn("hooksPath", text)
        self.assertNotIn("open(", text)
        self.assertNotIn("--no-verify", text)
        self.assertNotRegex(text, r"environ\.get\(\"(?!HOME\")")
        self.assertIn('DENYLIST_PARTS = (".config", "cab-of-one", "denylist.txt")', text)
        self.assertIn('"--log-opts=--all -m"', text)
        self.assertNotIn("--remotes", text)
        refuse = text.index("name.casefold() == SUPPRESSION_NAME for name in os.listdir(root)")
        self.assertLess(refuse, text.index("leak_opts = "))
        self.assertLess(refuse, text.index('"--denylist", denylist, *refs'))
        self.assertIn('"--ignore-gitleaks-allow", "--gitleaks-ignore-path", os.devnull]', text)
        self.assertEqual(text.count("*leak_opts"), 2)


class WorkflowTests(unittest.TestCase):
    text = WORKFLOW.read_text(encoding="utf-8")

    def test_permissions_and_triggers(self) -> None:
        self.assertIn("\npermissions:\n  contents: read\n", self.text)
        self.assertNotIn("pull_request_target", self.text)
        self.assertNotRegex(self.text, r":\s*write\b")
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("upload-artifact", self.text)
        self.assertNotIn("--denylist", self.text)
        self.assertIn("\non:\n  push:\n  pull_request:\n", self.text)

    def test_actions_are_pinned_and_checkouts_are_safe(self) -> None:
        uses = re.findall(r"uses: (\S+)", self.text)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
        checkouts = self.text.count("uses: actions/checkout@")
        self.assertEqual(self.text.count("persist-credentials: false"), checkouts)
        self.assertEqual(self.text.count("fetch-depth: 0"), checkouts)

    def test_matrix(self) -> None:
        self.assertIn("os: [ubuntu-latest, macos-latest]", self.text)
        self.assertIn('python: ["3.11", "3.14"]', self.text)
        self.assertIn("python -m ruff check .", self.text)
        self.assertIn("python -m pytest -q", self.text)

    def test_no_expression_interpolation_inside_run_blocks(self) -> None:
        run_indent = None
        for line in self.text.split("\n"):
            indent = len(line) - len(line.lstrip(" "))
            if run_indent is not None and line.strip() and indent <= run_indent:
                run_indent = None
            if line.strip().startswith(("run:", "- run:")):
                run_indent = indent
            if run_indent is not None:
                self.assertNotIn("${{", line)

    def test_gitleaks_download_is_verified_and_scans_are_redacted(self) -> None:
        verify = self.text.index("sha256sum --check --strict")
        self.assertLess(self.text.index("--output"), verify)
        self.assertLess(verify, self.text.index("tar -xzf"))
        self.assertEqual(self.text.count("--redact"), 2)
        self.assertEqual(self.text.count("--config .gitleaks.toml"), 2)
        self.assertEqual(
            self.text.count("--ignore-gitleaks-allow --gitleaks-ignore-path /dev/null"), 2
        )
        self.assertIn('--log-opts="--all -m"', self.text)
        history = self.text.index("gitleaks git ")
        self.assertLess(self.text.index("-iname .gitleaksignore"), history)
        self.assertLess(self.text.index('--export "$RUNNER_TEMP/candidate"'), history)
        self.assertIn('--export "$RUNNER_TEMP/candidate"', self.text)


class GitleaksConfigTests(unittest.TestCase):
    def test_config_extends_defaults_with_narrow_rule_allowlists(self) -> None:
        doc = tomllib.loads(GITLEAKS.read_text(encoding="utf-8"))
        self.assertIs(doc["extend"]["useDefault"], True)
        self.assertNotIn("allowlist", doc)
        self.assertNotIn("allowlists", doc)
        self.assertTrue(doc["rules"])
        for rule in doc["rules"]:
            self.assertEqual(set(rule), {"id", "allowlists"}, rule.get("id"))
            for allow in rule["allowlists"]:
                with self.subTest(rule=rule["id"], description=allow["description"]):
                    self.assertEqual(allow["condition"], "AND")
                    self.assertNotIn("regexTarget", allow)
                    self.assertTrue(allow["paths"])
                    self.assertTrue(allow["regexes"])
                    for path in allow["paths"]:
                        self.assertRegex(path, r"^\(\?:\^\|/\)(tests/test_\w+|\\\.gitleaks)\\\.")
                        self.assertTrue(path.endswith("$"))
                    for regex in allow["regexes"]:
                        self.assertTrue(regex.startswith("^") and regex.endswith("$"))

    def test_each_exact_value_exists_in_its_test_file(self) -> None:
        doc = tomllib.loads(GITLEAKS.read_text(encoding="utf-8"))
        for rule in doc["rules"]:
            for allow in rule["allowlists"]:
                files = [
                    ROOT / p.removeprefix("(?:^|/)").removesuffix("$").replace("\\.", ".")
                    for p in allow["paths"]
                    if "gitleaks" not in p
                ]
                text = "\n".join(f.read_text(encoding="utf-8") for f in files)
                for regex in allow["regexes"]:
                    with self.subTest(rule=rule["id"], regex=regex[:24]):
                        self.assertIsNotNone(re.search(regex[1:-1], text))


if __name__ == "__main__":
    unittest.main()
