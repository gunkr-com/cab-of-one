"""S4 paths: installed-layout roots, protected matching, safe authority reads.

All files live under <repo>/.local/test-tmp. The approval registry folder is a fixture home
inside that directory, passed explicitly; HOME is never read or set.
"""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import paths  # noqa: E402
from cab_of_one.runtime.paths import Roots, RootsError, UnsafePath  # noqa: E402

CHANGE = "CHG-0001-x"


class _Tmp(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="paths-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = self.tmp / "proj"
        for rel in ("policy", ".cab/state", ".claude/hooks/cab", f"changes/{CHANGE}", "work"):
            (self.project / rel).mkdir(parents=True)
        (self.project / "policy" / "policy.toml").write_text("schema = 1\n")
        (self.project / "policy" / "standard-changes.toml").write_text("schema = 1\n")
        self.entry = self.project / ".claude" / "hooks" / "cab" / "guard.py"
        self.entry.write_text("# entry\n")
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.roots = Roots(str(self.project), str(self.home / ".local" / "state" / "cab-of-one"))

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlinks unsupported: {type(exc).__name__}")

    def link_or_skip(self, source: Path, link: Path) -> None:
        try:
            os.link(source, link)
        except OSError as exc:
            self.skipTest(f"hard links unsupported: {type(exc).__name__}")

    def env(self, value: str | None = None) -> dict[str, str]:
        return {"CLAUDE_PROJECT_DIR": str(self.project) if value is None else value}


class ResolveRootsTests(_Tmp):
    def test_installed_entry_gives_project_and_home_registry(self) -> None:
        roots = paths.resolve_roots(str(self.entry), self.env(), str(self.home))
        self.assertEqual(roots.project, str(self.project))
        self.assertEqual(roots.state_home, str(self.home / ".local/state/cab-of-one"))
        self.assertTrue(roots.state_home.startswith(str(TMP_ROOT)))
        self.assertEqual(roots.approvals_file, os.path.join(roots.state_home, "approvals.jsonl"))

    def test_project_dir_may_be_an_alias_of_the_same_folder(self) -> None:
        alias = self.tmp / "alias"
        self.symlink_or_skip(self.project, alias)
        roots = paths.resolve_roots(str(self.entry), self.env(str(alias)), str(self.home))
        self.assertEqual(roots.project, str(self.project))

    def test_refusals(self) -> None:
        source_checkout = ROOT / "src" / "cab_of_one" / "runtime" / "guard.py"
        cases = {
            "env mismatch": (str(self.entry), self.env(str(self.tmp)), str(self.home)),
            "env missing": (str(self.entry), {}, str(self.home)),
            "env relative": (str(self.entry), self.env("proj"), str(self.home)),
            "source checkout": (str(source_checkout), self.env(str(ROOT)), str(self.home)),
            "entry not in hooks": (str(self.project / "guard.py"), self.env(), str(self.home)),
            "home relative": (str(self.entry), self.env(), "home"),
            "home missing": (str(self.entry), self.env(), None),
            "entry empty": ("", self.env(), str(self.home)),
        }
        for label, (entry, env, home) in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(RootsError):
                    paths.resolve_roots(entry, env, home)

    def test_layout_must_be_real(self) -> None:
        (self.project / ".cab" / "state").rmdir()
        with self.assertRaises(RootsError) as caught:
            paths.resolve_roots(str(self.entry), self.env(), str(self.home))
        self.assertEqual(caught.exception.code, "state_dir_unsafe")
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        self.symlink_or_skip(outside, self.project / ".cab" / "state")
        with self.assertRaises(RootsError):
            paths.resolve_roots(str(self.entry), self.env(), str(self.home))

    def test_missing_catalogue_is_refused(self) -> None:
        (self.project / "policy" / "standard-changes.toml").unlink()
        with self.assertRaises(RootsError) as caught:
            paths.resolve_roots(str(self.entry), self.env(), str(self.home))
        self.assertEqual(caught.exception.code, "catalog_file_unsafe")

    def test_symlinked_policy_dir_is_refused(self) -> None:
        real = self.tmp / "policy-real"
        shutil.move(str(self.project / "policy"), real)
        self.symlink_or_skip(real, self.project / "policy")
        with self.assertRaises(RootsError) as caught:
            paths.resolve_roots(str(self.entry), self.env(), str(self.home))
        self.assertEqual(caught.exception.code, "policy_dir_unsafe")

    def test_entry_through_symlinked_hook_folder_is_not_this_project(self) -> None:
        other = self.tmp / "other" / ".claude" / "hooks" / "cab"
        other.mkdir(parents=True)
        (other / "guard.py").write_text("# other\n")
        shutil.rmtree(self.project / ".claude" / "hooks" / "cab")
        self.symlink_or_skip(other, self.project / ".claude" / "hooks" / "cab")
        entry = str(self.project / ".claude/hooks/cab/guard.py")
        with self.assertRaises(RootsError):
            paths.resolve_roots(entry, self.env(), str(self.home))

    def test_hardlinked_policy_file_is_refused(self) -> None:
        self.link_or_skip(self.project / "policy" / "policy.toml", self.tmp / "policy-copy")
        with self.assertRaises(RootsError):
            paths.resolve_roots(str(self.entry), self.env(), str(self.home))

    def test_roots_must_be_absolute_and_normal(self) -> None:
        for project, home in (
            ("proj", str(self.home)),
            (str(self.project) + "/", str(self.home)),
            (str(self.project) + "/../proj", str(self.home)),
            ("/", str(self.home)),
            (str(self.project), "relative/home"),
        ):
            with self.subTest(project=project, home=home):
                with self.assertRaises(RootsError):
                    Roots(project, home)


class ResolveCliRootsTests(_Tmp):
    """S5: the pinned CLI runs in a person's terminal, usually without CLAUDE_PROJECT_DIR."""

    def cli_entry(self) -> Path:
        entry = self.project / ".claude" / "hooks" / "cab" / "cab"
        entry.write_text("# cli entry\n")
        return entry

    def test_missing_project_dir_is_accepted(self) -> None:
        roots = paths.resolve_cli_roots(str(self.cli_entry()), {}, str(self.home))
        self.assertEqual(roots.project, str(self.project))
        self.assertEqual(roots.state_home, str(self.home / ".local/state/cab-of-one"))

    def test_present_project_dir_must_match(self) -> None:
        entry = str(self.cli_entry())
        self.assertEqual(
            paths.resolve_cli_roots(entry, self.env(), str(self.home)).project, str(self.project)
        )
        for value in (str(self.tmp), "proj", ""):
            with self.subTest(value=value):
                with self.assertRaises(RootsError):
                    paths.resolve_cli_roots(entry, self.env(value), str(self.home))

    def test_shared_layout_checks_still_apply(self) -> None:
        entry = str(self.cli_entry())
        cases = {
            "not installed": (str(self.project / "cab"), str(self.home)),
            "home relative": (entry, "home"),
            "home missing": (entry, None),
        }
        for label, (path, home) in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(RootsError):
                    paths.resolve_cli_roots(path, {}, home)
        (self.project / "policy" / "standard-changes.toml").unlink()
        with self.assertRaises(RootsError) as caught:
            paths.resolve_cli_roots(entry, {}, str(self.home))
        self.assertEqual(caught.exception.code, "catalog_file_unsafe")
        with self.assertRaises(RootsError):
            paths.resolve_cli_roots(entry, None, str(self.home))  # type: ignore[arg-type]


class StateFileSafeTests(_Tmp):
    """S5: ``Store._state_path_safe`` moved to ``paths.state_file_safe`` unchanged."""

    def test_plain_file_and_missing_file_are_safe(self) -> None:
        (self.project / "tenant").mkdir()
        self.assertTrue(paths.state_file_safe(self.roots, "tenant/state.json"))
        (self.project / "tenant" / "state.json").write_text("{}\n")
        self.assertTrue(paths.state_file_safe(self.roots, "tenant/state.json"))

    def test_refusals(self) -> None:
        (self.project / "tenant").mkdir()
        state = self.project / "tenant" / "state.json"
        state.write_text("{}\n")
        scopes = (
            "", "../x.json", "tenant/../tenant/state.json", "/abs.json",
            "missing/state.json", ".cab/state/active.json", "policy/policy.toml",
        )  # fmt: skip
        for scope in scopes:
            with self.subTest(scope=scope):
                self.assertFalse(paths.state_file_safe(self.roots, scope))
        self.assertFalse(paths.state_file_safe(self.roots, None))  # type: ignore[arg-type]
        self.link_or_skip(state, self.tmp / "state-alias.json")
        self.assertFalse(paths.state_file_safe(self.roots, "tenant/state.json"))

    def test_symlinks_are_refused(self) -> None:
        real = self.tmp / "tenant-real"
        real.mkdir()
        (real / "state.json").write_text("{}\n")
        self.symlink_or_skip(real, self.project / "tenant")
        self.assertFalse(paths.state_file_safe(self.roots, "tenant/state.json"))
        (self.project / "t2").mkdir()
        self.symlink_or_skip(real / "state.json", self.project / "t2" / "state.json")
        self.assertFalse(paths.state_file_safe(self.roots, "t2/state.json"))


class ProtectedMatchTests(_Tmp):
    def match(self, path: str, cwd: str | None = None, ancestors: bool = False) -> bool | None:
        base = cwd or str(self.project)
        return paths.protected_match(path, base, self.roots, ancestors=ancestors)

    def test_protected_set(self) -> None:
        for rel in (
            ".claude/settings.json",
            ".claude/hooks/cab/guard.py",
            "policy/policy.toml",
            "policy/standard-changes.toml",
            "audit/ledger/2026-11.jsonl",
            ".cab/state/active.json",
            ".cab/state/inflight",
            ".cab/manifest.json",
            ".cab/backups/2026/x",
            f"changes/{CHANGE}/approval.json",
            f"changes/{CHANGE}/review.json",
            f"changes/{CHANGE}/verify.json",
            f"changes/{CHANGE}/snapshot.json",
            "work/../policy/policy.toml",
            "./policy//policy.toml",
            "./audit",
        ):
            with self.subTest(path=rel):
                self.assertIs(self.match(rel), True)
                self.assertIs(self.match(str(self.project / rel)), True)

    def test_not_protected(self) -> None:
        for rel in (
            f"changes/{CHANGE}/plan.md",
            f"changes/{CHANGE}/change.toml",
            f"changes/{CHANGE}/targets.csv",
            f"changes/{CHANGE}/record.md",
            ".cab/setup/profile.toml",
            "notes.md",
            "work/out.json",
            "policyx/file",
            "my-policy/file",
        ):
            with self.subTest(path=rel):
                self.assertIs(self.match(rel), False)

    def test_case_and_unicode_variants(self) -> None:
        for rel in (
            f"Changes/{CHANGE}/Approval.json",
            f"changes/{CHANGE}/APPROVAL.JSON",
            ".CLAUDE/settings.json",
            "POLICY/x",
            "Audit/ledger/x",
        ):
            with self.subTest(path=rel):
                self.assertIs(self.match(rel), True)
        composed = self.tmp / "café"
        composed.mkdir()
        roots = Roots(str(composed), self.roots.state_home)
        decomposed = str(self.tmp / "café" / "policy" / "policy.toml")
        self.assertIs(paths.protected_match(decomposed, None, roots), True)

    def test_relative_paths_use_cwd(self) -> None:
        work = str(self.project / "work")
        self.assertIs(self.match("../policy/policy.toml", work), True)
        self.assertIs(self.match("policy/policy.toml", work), False)  # work/policy is not
        self.assertIs(self.match("approval.json", str(self.project / "changes" / CHANGE)), True)
        self.assertIsNone(paths.protected_match("policy/x", None, self.roots))

    def test_symlinks_resolve_to_protected_targets(self) -> None:
        folder = self.project / "changes" / CHANGE
        (folder / "approval.json").write_text("{}")
        self.symlink_or_skip(folder / "approval.json", folder / "plan.md")
        self.assertIs(self.match(f"changes/{CHANGE}/plan.md"), True)
        self.symlink_or_skip(self.project / ".cab" / "state", self.project / "work" / "st")
        self.assertIs(self.match("work/st/active.json"), True)
        self.symlink_or_skip(folder / "verify.json", self.project / "dangling")
        self.assertIs(self.match("dangling"), True)
        self.symlink_or_skip(self.home, self.project / "work" / "home-link")
        self.assertIs(self.match("work/home-link/.local/state/cab-of-one/approvals.jsonl"), True)

    def test_hardlinked_file_is_protected(self) -> None:
        a = self.project / "work" / "a.txt"
        a.write_text("x")
        self.assertIs(self.match("work/a.txt"), False)
        self.link_or_skip(a, self.project / "work" / "b.txt")
        self.assertIs(self.match("work/a.txt"), True)
        self.assertIs(self.match("work/b.txt"), True)

    def test_ancestors_only_for_removal(self) -> None:
        for rel in (".", ".cab", "changes", f"changes/{CHANGE}"):
            with self.subTest(path=rel):
                self.assertIs(self.match(rel), False)
                self.assertIs(self.match(rel, ancestors=True), True)
        self.assertIs(self.match("work", ancestors=True), False)

    def test_registry_folder_and_its_ancestors(self) -> None:
        registry = os.path.join(self.roots.state_home, "approvals.jsonl")
        self.assertIs(paths.protected_match(registry, None, self.roots), True)
        lock = os.path.join(self.roots.state_home, "approvals.lock")
        self.assertIs(paths.protected_match(lock, None, self.roots), True)
        self.assertIs(paths.protected_match(str(self.home), None, self.roots), False)
        self.assertIs(paths.protected_match(str(self.home), None, self.roots, ancestors=True), True)

    def test_invalid_input_is_protected(self) -> None:
        for bad in ("", "a\x00b"):
            with self.subTest(path=repr(bad)):
                self.assertIs(paths.protected_match(bad, str(self.project), self.roots), True)

    def test_long_component_is_answered_not_raised(self) -> None:
        # A literal shell word longer than NAME_MAX is ordinary text, not a protected path.
        result = paths.protected_match("x" * 300, str(self.project), self.roots)
        self.assertIs(result, False)
        # ...and a long tail never weakens lexical matching of a protected prefix
        self.assertIs(self.match("policy/" + "x" * 300), True)
        self.assertIs(self.match(".cab/state/" + "y" * 300), True)

    def closed_result(self, path: str) -> object:
        """protected_match's answer, or the errno it raised."""
        try:
            return paths.protected_match(path, str(self.project), self.roots)
        except OSError as exc:
            return exc.errno

    def test_name_too_long_without_proven_name_limit_fails_closed(self) -> None:
        # The same real 300-character literal that test_long_component_is_answered_not_raised
        # passes under the real limit. If PC_NAME_MAX cannot prove the component impossible
        # (unknown/unlimited, larger than the word, or the query itself fails), the
        # ENAMETOOLONG must not become "does not exist" (False).
        word = "x" * 300

        def unlimited(_path: object, _name: object) -> int:
            return -1

        def large(_path: object, _name: object) -> int:
            return 4096

        def denied(_path: object, _name: object) -> int:
            raise OSError(errno.EACCES, "fixture: pathconf denied")

        for label, fake in (("-1", unlimited), ("4096", large), ("EACCES", denied)):
            with self.subTest(pathconf=label):
                with mock.patch.object(paths.os, "pathconf", fake):
                    result = self.closed_result(word)
                self.assertIn(result, (True, errno.ENAMETOOLONG))

    def test_whole_path_too_long_with_short_components_fails_closed(self) -> None:
        # Every component is 200 bytes (below any usual NAME_MAX); only the whole path is
        # over PATH_MAX. Nothing proves a component impossible, so it must not pass as False.
        long_path = "/".join(["d" * 200] * 30)
        self.assertGreater(len(str(self.project)) + len(long_path), 4096)
        self.assertIn(self.closed_result(long_path), (True, errno.ENAMETOOLONG))

    def test_candidate_below_a_regular_file_is_answered_not_raised(self) -> None:
        (self.project / "notes.txt").write_text("x\n")
        self.assertIs(self.match("notes.txt/child"), False)  # ENOTDIR: cannot exist
        self.assertIs(self.match(str(self.project / "notes.txt" / "child")), False)
        (self.project / "policy" / "file").write_text("x\n")
        self.assertIs(self.match("policy/file/child"), True)  # lexically protected

    def test_unexpected_lstat_errors_fail_closed(self) -> None:
        probe = str(self.project / "work" / "out.json")
        real_lstat = os.lstat
        # ENAMETOOLONG here has only short components (a whole-path limit, not a literal
        # word), so it must fail closed like EACCES and EIO.
        for code in (errno.EACCES, errno.EIO, errno.ENAMETOOLONG):
            with self.subTest(errno=errno.errorcode[code]):

                def lstat(path, *args, _code=code, **kwargs):
                    if os.fspath(path) == probe:
                        raise OSError(_code, "fixture: unexpected lstat failure")
                    return real_lstat(path, *args, **kwargs)

                with mock.patch.object(paths.os, "lstat", lstat):
                    try:
                        result: object = paths.protected_match(probe, str(self.project), self.roots)
                    except OSError as exc:
                        result = exc.errno
                # raising (the guard then denies) or answering "protected" are both closed;
                # treating the error as "does not exist" (False) is not
                self.assertIn(result, (True, code))

    def test_same_dir(self) -> None:
        self.assertTrue(paths.same_dir(str(self.project), self.roots.project))
        self.assertFalse(paths.same_dir(str(self.project / "work"), self.roots.project))
        self.assertFalse(paths.same_dir("relative", self.roots.project))
        self.assertFalse(paths.same_dir(None, self.roots.project))


class SafeReadTests(_Tmp):
    def test_read_authority(self) -> None:
        folder = self.project / "changes" / CHANGE
        (folder / "review.json").write_bytes(b"{}")
        self.assertEqual(paths.read_authority(str(folder), "review.json", 10), b"{}")
        self.assertIsNone(paths.read_authority(str(folder), "approval.json", 10))
        (folder / "big.json").write_bytes(b"x" * 11)
        with self.assertRaises(UnsafePath) as caught:
            paths.read_authority(str(folder), "big.json", 10)
        self.assertEqual(caught.exception.code, "too_large")
        for rel in ("../x", "/etc/hosts", "", "a/../b"):
            with self.subTest(rel=rel):
                with self.assertRaises(UnsafePath):
                    paths.read_authority(str(folder), rel, 10)

    def test_read_authority_refuses_links(self) -> None:
        folder = self.project / "changes" / CHANGE
        (self.tmp / "outside.json").write_bytes(b"{}")
        self.symlink_or_skip(self.tmp / "outside.json", folder / "approval.json")
        with self.assertRaises(UnsafePath) as caught:
            paths.read_authority(str(folder), "approval.json", 100)
        self.assertEqual(caught.exception.code, "symlink")
        self.symlink_or_skip(self.tmp, self.project / "changes" / "CHG-0002-y")
        with self.assertRaises(UnsafePath) as caught:
            paths.read_authority(str(self.project), "changes/CHG-0002-y/outside.json", 100)
        self.assertEqual(caught.exception.code, "parent_unsafe")
        (folder / "review.json").write_bytes(b"{}")
        self.link_or_skip(folder / "review.json", self.tmp / "review-link")
        with self.assertRaises(UnsafePath) as caught:
            paths.read_authority(str(folder), "review.json", 100)
        self.assertEqual(caught.exception.code, "hardlink")

    def test_read_project_file(self) -> None:
        (self.project / "work" / "run.sh").write_text("echo hi\n")
        (self.tmp / "outside.sh").write_text("echo out\n")
        root = self.roots
        work = str(self.project / "work")
        project = str(self.project)
        self.assertEqual(paths.read_project_file(root, work, "run.sh", 100), b"echo hi\n")
        self.assertEqual(paths.read_project_file(root, project, "work/run.sh", 100), b"echo hi\n")
        self.assertIsNone(paths.read_project_file(root, work, "../../outside.sh", 100))
        self.assertIsNone(paths.read_project_file(root, work, str(self.tmp / "outside.sh"), 100))
        self.assertIsNone(paths.read_project_file(root, None, "work/run.sh", 100))
        self.assertIsNone(paths.read_project_file(root, work, "run.sh", 3))
        self.assertIsNone(paths.read_project_file(root, work, "missing.sh", 100))
        self.symlink_or_skip(self.tmp / "outside.sh", self.project / "work" / "link.sh")
        self.assertIsNone(paths.read_project_file(root, work, "link.sh", 100))

    def test_role_file_match(self) -> None:
        names = ("change.toml", "plan.md")
        folder = self.project / "changes" / CHANGE

        def ok(path: Path | str, cwd: str | None = None) -> bool:
            return paths.role_file_match(str(path), cwd, self.roots, CHANGE, names)

        self.assertTrue(ok(folder / "change.toml"))
        self.assertTrue(ok("plan.md", str(folder)))
        for bad in (folder / "targets.csv", folder / "approval.json", self.project / "plan.md"):
            with self.subTest(path=str(bad)):
                self.assertFalse(ok(bad))
        self.assertFalse(ok("plan.md", None))
        (folder / "real.md").write_text("x")
        self.symlink_or_skip(folder / "real.md", folder / "plan.md")
        self.assertFalse(ok(folder / "plan.md"))
        (folder / "change.toml").write_text("x")
        self.link_or_skip(folder / "change.toml", self.tmp / "change-alias")
        self.assertFalse(ok(folder / "change.toml"))

    def test_ensure_dir_refuses_symlink(self) -> None:
        self.symlink_or_skip(self.tmp, self.project / "audit")
        with self.assertRaises(UnsafePath):
            paths.ensure_dir(str(self.project), "audit", "ledger")
        self.assertFalse((self.tmp / "ledger").exists())
        for bad in ("..", "a/b", ""):
            with self.subTest(part=bad):
                with self.assertRaises(UnsafePath):
                    paths.ensure_dir(str(self.project), bad)


if __name__ == "__main__":
    unittest.main()
