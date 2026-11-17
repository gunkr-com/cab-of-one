"""S9 apply: render staging, person-only apply, exact rollback (G2 G3 G4 G5 G7 G10).

Everything happens below <repo>/.local/test-tmp: a controlled source tree (test_render's
fixture: real rules, runtime, guard and handoff templates plus stand-ins for other writers'
templates), a fictional Contoso project, an injected home folder, an injected managed
folder and an injected command runner. No real account, configuration, tenant, Git or
Claude Code is touched. Terminal streams are unit-only fakes (an injected TerminalOS says
they are TTYs), except one test that uses an owned pseudo-terminal pair.

The guard self test and the runtime probe are the real C-main/A implementations unless a
test injects a callback; injected callbacks say "unit-only" in their detail.
"""

from __future__ import annotations

import datetime
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import config_lock, fsutil  # noqa: E402
from cab_of_one.runtime.terminal import TerminalOS  # noqa: E402
from cab_of_one.setup import apply as apply_mod  # noqa: E402
from cab_of_one.setup import merge, session  # noqa: E402
from cab_of_one.setup.apply import ApplyError, Check, FileOps, Services  # noqa: E402
from cab_of_one.setup.manifest import (  # noqa: E402
    config_file_matches,
    load_manifest,
    sha256_hex,
)
from cab_of_one.setup.uninstall import uninstall_project  # noqa: E402
from test_profile import encode, user  # noqa: E402
from test_render import build_source  # noqa: E402

PROJECT = "contoso-ops"
# .cab/state belongs to the runtime (the real runtime probe and self test may write there).
PRIVATE = (".cab/setup", ".cab/backups", ".cab/state")
OSX = TerminalOS(
    isatty=lambda fd: True,
    getuid=lambda: 501,
    geteuid=lambda: 501,
    username=lambda uid: "contoso-admin",
)
NOW = datetime.datetime(2026, 11, 12, 8, 0, 0, tzinfo=datetime.UTC)
USER_SETTINGS = {
    "model": "contoso-model-alias",
    "env": {"CONTOSO_REGION": "east"},
    "permissions": {"allow": ["Bash(git status)"]},
    "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "~/bin/contoso-notify.sh"}]}]},
}
USER_CLAUDE = b"# Contoso operations\r\n\r\nNotes for people.\r\n"
USER_GITIGNORE = b"*.log\nsecrets/\n"
SKILL = ".claude/skills/change/SKILL.md"
UNIT_PASS = Check(apply_mod.PASS, "unit_only", "unit-only injected callback")


class FakeTTY:
    """Unit-only terminal stand-in: isatty() is True and fileno() is an int."""

    def __init__(self, answer: bytes = b"", tty: bool = True, on_read: Callable | None = None):
        self.buffer = self
        self._answer = io.BytesIO(answer)
        self._tty = tty
        self._on_read = on_read
        self.text = io.StringIO()

    def isatty(self) -> bool:
        return self._tty

    def fileno(self) -> int:
        return 99

    def readline(self, limit: int = -1) -> bytes:
        if self._on_read is not None:
            self._on_read()
        return self._answer.readline(limit)

    def write(self, text: str) -> int:
        self.text.write(text)
        return len(text)

    def flush(self) -> None:
        pass


class FakeRunner:
    """Injected fixed-argv runner. Never starts a process."""

    def __init__(
        self,
        version: bytes | None = b"2.1.322 (Claude Code)\n",
        git_top: bytes | None = None,
        git_files: bytes | None = b"",
    ) -> None:
        self.version, self.git_top, self.git_files = version, git_top, git_files
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...], *, cwd: Any, env: Any, timeout: Any, max_bytes: int):
        self.calls.append(argv)
        assert "shell" not in env
        if argv == apply_mod.CLAUDE_VERSION_ARGV:
            return self.version
        if argv == apply_mod.GIT_TOPLEVEL_ARGV:
            return self.git_top
        if argv == apply_mod.GIT_TRACKED_ARGV:
            return self.git_files
        return None


def tree(folder: Path, skip: tuple[str, ...] = (".cab/setup", ".cab/backups")) -> dict:
    """Bytes, modes and links below ``folder`` (mtimes excluded), minus ``skip``."""
    out: dict[str, tuple] = {}
    for dirpath, dirnames, filenames in os.walk(folder):
        base = Path(dirpath)
        keep = []
        for name in sorted(dirnames):
            rel = (base / name).relative_to(folder).as_posix()
            if any(rel == s or rel.startswith(s + "/") for s in skip):
                continue
            if (base / name).is_symlink():
                out[rel] = ("link", os.readlink(base / name))
                continue
            out[rel] = ("dir",)
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = base / name
            rel = path.relative_to(folder).as_posix()
            if any(rel.startswith(s + "/") for s in skip):
                continue
            if path.is_symlink():
                out[rel] = ("link", os.readlink(path))
            else:
                st = path.lstat()
                out[rel] = ("file", path.read_bytes(), stat.S_IMODE(st.st_mode))
    return out


class ApplyCase(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s9-apply-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src = build_source(self.tmp / "source")
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.managed = self.tmp / "managed"
        self.project = self.tmp / PROJECT
        (self.project / ".cab" / "setup").mkdir(parents=True)
        (self.project / ".cab/setup/profile.toml").write_bytes(encode(user()))

    # -- helpers

    def svc(self, answer: bytes | None = None, **kw: Any) -> Services:
        stdin = kw.pop("stdin", None) or FakeTTY(
            (PROJECT + "\n").encode() if answer is None else answer
        )
        base: dict[str, Any] = {
            "stdin": stdin,
            "stdout": FakeTTY(),
            "stderr": io.StringIO(),
            "cwd": lambda: str(self.project),
            "environ": {"PATH": "/usr/bin:/bin"},
            "home": str(self.home),
            "platform": "darwin",
            "managed_dir": str(self.managed),
            "runner": FakeRunner(),
            "osx": OSX,
            "clock": lambda: NOW,
            "finder": lambda name: False,
        }
        base.update(kw)
        return Services(**base)

    def render(self, **kw: Any) -> apply_mod.Outcome:
        services = kw.pop("services", None) or self.svc()
        return apply_mod.render_project(
            str(self.project), source_root=str(self.src), services=services, **kw
        )

    def apply(self, answer: bytes | None = None, take_new: tuple[str, ...] = (), **kw: Any):
        services = kw.pop("services", None) or self.svc(answer, **kw)
        return apply_mod.apply_project(
            str(self.project), source_root=str(self.src), services=services, take_new=take_new
        )

    def user_files(self) -> None:
        claude = self.project / ".claude"
        claude.mkdir()
        (claude / "settings.json").write_text(json.dumps(USER_SETTINGS, indent=4))
        (self.project / "CLAUDE.md").write_bytes(USER_CLAUDE)
        (self.project / ".gitignore").write_bytes(USER_GITIGNORE)
        os.chmod(self.project / "CLAUDE.md", 0o640)

    def rendered_bundle(self) -> dict[str, bytes]:
        staged = self.project / ".cab/setup/staged"
        return {
            p.relative_to(staged).as_posix(): p.read_bytes()
            for p in staged.rglob("*")
            if p.is_file()
        }

    def assert_ok(self, outcome: apply_mod.Outcome, code: str = "applied") -> None:
        self.assertEqual((outcome.exit, outcome.code), (0, code), "\n".join(outcome.lines))

    def backups(self) -> list[str]:
        folder = self.project / ".cab/backups"
        return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


# --------------------------------------------------------------------------- happy path


class InstallTests(ApplyCase):
    def test_g3_install_preserves_person_files_and_g2_reapply_is_idempotent(self) -> None:
        self.user_files()
        self.assert_ok(self.render(), "rendered")
        outcome = self.apply()
        self.assert_ok(outcome)
        text = "\n".join(outcome.lines)
        self.assertIn("guard self test: PASS", text)
        self.assertIn("UNKNOWN (not measured)", text)

        settings = json.loads((self.project / ".claude/settings.json").read_bytes())
        self.assertEqual(settings["model"], USER_SETTINGS["model"])
        self.assertEqual(settings["env"], USER_SETTINGS["env"])
        self.assertEqual(settings["permissions"]["allow"], ["Bash(git status)"])
        self.assertEqual(settings["hooks"]["Stop"][0], USER_SETTINGS["hooks"]["Stop"][0])
        self.assertIn("Bash(cab setup apply:*)", settings["permissions"]["deny"])
        claude = (self.project / "CLAUDE.md").read_bytes()
        self.assertTrue(claude.startswith(USER_CLAUDE))
        self.assertIn(merge.BEGIN_MARKER, claude)
        self.assertEqual(stat.S_IMODE((self.project / "CLAUDE.md").stat().st_mode), 0o640)
        ignore = (self.project / ".gitignore").read_bytes()
        self.assertTrue(ignore.startswith(USER_GITIGNORE))
        for pattern in merge.GITIGNORE_PATTERNS:
            self.assertIn(pattern.encode() + b"\n", ignore)

        manifest_bytes = (self.project / ".cab/manifest.json").read_bytes()
        manifest = load_manifest(manifest_bytes)
        self.assertEqual(manifest.applied_at, "2026-11-12T08:00:00Z")
        bundle = self.rendered_bundle()
        for path, digest in manifest.files.items():
            self.assertEqual(sha256_hex(bundle[path]), digest)
        cab = self.project / ".claude/hooks/cab/cab"
        self.assertEqual(stat.S_IMODE(cab.stat().st_mode), 0o755)
        guard = self.project / ".claude/hooks/cab/guard.py"
        self.assertEqual(stat.S_IMODE(guard.stat().st_mode), 0o644)
        self.assertTrue((self.project / ".cab/state").is_dir())

        [stamp] = self.backups()
        self.assertEqual(stamp, "20261112T080000Z")
        index = json.loads((self.project / ".cab/backups" / stamp / "index.json").read_bytes())
        self.assertEqual(set(index["files"]), {".claude/settings.json", ".gitignore", "CLAUDE.md"})
        self.assertEqual(index["files"]["CLAUDE.md"]["mode"], oct(0o640))
        saved = self.project / ".cab/backups" / stamp / "files/CLAUDE.md"
        self.assertEqual(saved.read_bytes(), USER_CLAUDE)

        # G2: the same render applied again is "nothing to do". (.cab/state is the
        # runtime's: the real runtime probe may take its own state lock there.)
        private = (".cab/setup", ".cab/backups", ".cab/state")
        before = tree(self.project, skip=private)
        self.assert_ok(self.render(), "rendered")
        again = self.apply(answer=b"")
        self.assert_ok(again, "nothing_to_do")
        self.assertEqual((self.project / ".cab/manifest.json").read_bytes(), manifest_bytes)
        self.assertEqual(self.backups(), [stamp])
        self.assertEqual(tree(self.project, skip=private), before)

    def test_first_install_into_an_empty_project(self) -> None:
        self.assert_ok(self.render(), "rendered")
        self.assert_ok(self.apply())
        ignore = (self.project / ".gitignore").read_bytes()
        self.assertEqual(ignore, merge.make_gitignore_block() + b"\n")
        manifest = load_manifest((self.project / ".cab/manifest.json").read_bytes())
        self.assertTrue(manifest.gitignore_block.file_created)
        self.assertTrue(manifest.settings.file_created)

    def test_successful_apply_ends_the_setup_session(self) -> None:
        session.begin(str(self.project), "sess-contoso-0001")
        self.render()
        outcome = self.apply()
        self.assert_ok(outcome)
        self.assertIn("setup session: ended", "\n".join(outcome.lines))
        self.assertEqual(session.load(str(self.project)).status, "absent")

    def test_summary_is_shown_before_the_prompt_and_is_redacted(self) -> None:
        self.render()
        out = FakeTTY()
        self.assert_ok(self.apply(stdout=out))
        shown = out.text.getvalue()
        self.assertIn("profile: profile file", shown)
        self.assertIn("create  .claude/settings.json", shown)
        self.assertIn("UNKNOWN: managed: server- or host-delivered policy not measured", shown)
        self.assertIn(f"Type the project folder name ({PROJECT})", shown)
        self.assertNotIn("\x1b", shown)


# --------------------------------------------------------------------------- refusals


class RefusalTests(ApplyCase):
    def test_g5_render_writes_only_below_cab_setup(self) -> None:
        self.user_files()
        before = tree(self.project, skip=(".cab/setup",))
        self.assert_ok(self.render(), "rendered")
        self.assertEqual(tree(self.project, skip=(".cab/setup",)), before)
        names = sorted(p.name for p in (self.project / ".cab/setup").iterdir())
        self.assertEqual(
            names,
            ["PLAN.md", "apply.lock", "profile.toml", "render-profile.toml", "render.json",
             "staged"],
        )  # fmt: skip
        plan = (self.project / ".cab/setup/PLAN.md").read_text()
        self.assertIn("plan preview:", plan)

    def test_g4_unowned_collision_refuses_everything(self) -> None:
        agents = self.project / ".claude/agents"
        agents.mkdir(parents=True)
        (agents / "safety-reviewer.md").write_text("a person's own reviewer\n")
        rendered = self.render()
        self.assertEqual(rendered.exit, apply_mod.EXIT_BLOCKED)
        before = tree(self.project)
        outcome = self.apply(answer=b"")
        self.assertEqual(outcome.exit, apply_mod.EXIT_BLOCKED)
        self.assertIn(
            "unowned_collision .claude/agents/safety-reviewer.md", "\n".join(outcome.lines)
        )
        self.assertEqual(tree(self.project), before)

    def test_g10_dangerous_environments_are_refused(self) -> None:
        cases: list[tuple[str, Callable[[], None], dict[str, Any]]] = [
            ("managed_hooks_only", lambda: self.write_managed({"allowManagedHooksOnly": True}), {}),
            (
                "managed_rules_only",
                lambda: self.write_managed({"allowManagedPermissionRulesOnly": True}),
                {},
            ),
            ("claude_version_too_old", lambda: None, {"runner": FakeRunner(b"2.1.200\n")}),
            ("claude_version_unknown", lambda: None, {"runner": FakeRunner(None)}),
            ("hooks_disabled", lambda: self.write_local({"disableAllHooks": True}), {}),
            ("user_settings_unmeasured", self.link_user_settings, {}),
            ("managed_settings_unmeasured", self.link_managed_fragment, {}),
        ]
        self.render()
        for code, prepare, kw in cases:
            with self.subTest(code=code):
                prepare()
                before = tree(self.project)
                outcome = self.apply(answer=b"", **kw)
                self.assertEqual(outcome.exit, apply_mod.EXIT_BLOCKED, outcome.lines)
                self.assertIn(code, "\n".join(outcome.lines))
                self.assertEqual(tree(self.project), before)
                self.reset_environment()

    def write_managed(self, doc: dict) -> None:
        self.managed.mkdir(exist_ok=True)
        (self.managed / "managed-settings.json").write_text(json.dumps(doc))

    def write_local(self, doc: dict) -> None:
        (self.project / ".claude").mkdir(exist_ok=True)
        (self.project / ".claude/settings.local.json").write_text(json.dumps(doc))

    def link_user_settings(self) -> None:
        elsewhere = self.tmp / "dotfiles"
        elsewhere.mkdir(exist_ok=True)
        (elsewhere / "settings.json").write_text("{}")
        os.symlink(elsewhere, self.home / ".claude")

    def link_managed_fragment(self) -> None:
        frag = self.managed / "managed-settings.d"
        frag.mkdir(parents=True, exist_ok=True)
        target = self.tmp / "policy.json"
        target.write_text("{}")
        os.symlink(target, frag / "10-contoso.json")

    def reset_environment(self) -> None:
        shutil.rmtree(self.managed, ignore_errors=True)
        shutil.rmtree(self.project / ".claude", ignore_errors=True)
        link = self.home / ".claude"
        if link.is_symlink():
            link.unlink()

    def test_concurrent_apply_is_refused(self) -> None:
        self.render()
        lock = self.project / ".cab/setup" / apply_mod.LOCK_NAME
        with fsutil.locked(lock, 1.0):
            with self.assertRaises(ApplyError) as ctx:
                self.apply(lock_timeout=0.0)
        self.assertEqual(ctx.exception.code, "apply_in_progress")
        self.assertEqual(ctx.exception.exit_code, apply_mod.EXIT_BLOCKED)
        self.assertFalse((self.project / ".cab/manifest.json").exists())

    def test_terminal_checks(self) -> None:
        self.render()
        before = tree(self.project)
        not_tty = self.apply(stdin=FakeTTY(b"contoso-ops\n", tty=False))
        self.assertEqual((not_tty.exit, not_tty.code), (3, "not_a_tty"))
        other_uid = TerminalOS(lambda fd: True, lambda: 501, lambda: 0, lambda uid: "x")
        self.assertEqual(self.apply(osx=other_uid).code, "uid_mismatch")
        no_user = TerminalOS(lambda fd: True, lambda: 501, lambda: 501, lambda uid: None)
        self.assertEqual(self.apply(osx=no_user).code, "os_user_unknown")
        for answer in (b"contoso\n", b"CONTOSO-OPS\n", b"contoso-ops\r\n", b"contoso-ops", b""):
            with self.subTest(answer=answer):
                outcome = self.apply(answer=answer)
                self.assertEqual((outcome.exit, outcome.code), (1, "mismatch"))
        self.assertEqual(tree(self.project), before)

    def test_owned_pty_confirmation(self) -> None:
        try:
            master, slave = os.openpty()
        except (AttributeError, OSError):
            self.skipTest("no pseudo-terminal available")
        osx = TerminalOS(os.isatty, lambda: 501, lambda: 501, lambda uid: "contoso-admin")
        stdin = os.fdopen(os.dup(slave), "rb", buffering=0)
        stdout = os.fdopen(os.dup(slave), "w")
        self.addCleanup(stdin.close)
        self.addCleanup(stdout.close)
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        os.write(master, b"contoso-ops\n")
        check = apply_mod.confirm_project_name(
            "contoso-ops", ["short summary"], stdin=stdin, stdout=stdout, osx=osx
        )
        self.assertEqual(check, Check(apply_mod.PASS, "confirmed"))

    def test_untypable_project_name(self) -> None:
        for name in ("bad\x1bname", " lead", "x" * 129, ""):
            with self.subTest(name=repr(name)):
                check = apply_mod.confirm_project_name(
                    name, [], stdin=FakeTTY(), stdout=FakeTTY(), osx=OSX
                )
                self.assertEqual(check.code, "project_name_untypable")

    def test_tracked_private_state_refuses_without_touching_git(self) -> None:
        self.render()
        runner = FakeRunner(git_top=b"true\n", git_files=b".cab/setup/profile.toml\x00")
        before = tree(self.project)
        outcome = self.apply(answer=b"", runner=runner)
        text = "\n".join(outcome.lines)
        self.assertEqual(outcome.exit, apply_mod.EXIT_BLOCKED)
        self.assertIn("private_state_tracked", text)
        self.assertIn("git rm -r --cached", text)
        self.assertEqual(tree(self.project), before)
        for argv in runner.calls:
            self.assertIn(argv, (apply_mod.CLAUDE_VERSION_ARGV, apply_mod.GIT_TOPLEVEL_ARGV,
                                 apply_mod.GIT_TRACKED_ARGV))  # fmt: skip
        (self.project / ".git").mkdir()
        outcome = self.apply(answer=b"", runner=FakeRunner(git_top=None))
        self.assertIn("git_unmeasured", "\n".join(outcome.lines))

    def test_runtime_state_is_checked_before_controls_change(self) -> None:
        self.render()
        state = self.project / ".cab/state"
        state.mkdir()
        (state / "unknown.json").write_text("{}")
        outcome = self.apply(answer=b"")
        self.assertEqual(outcome.exit, apply_mod.EXIT_BLOCKED)
        self.assertIn("runtime_state_unmeasured", "\n".join(outcome.lines))
        active = Check(apply_mod.FAIL, "change_active", "CHG-0007")
        outcome = self.apply(answer=b"", runtime_probe=lambda root: active)
        self.assertIn("runtime change_active", "\n".join(outcome.lines))
        self.assertFalse((self.project / ".cab/manifest.json").exists())


# --------------------------------------------------------------------------- staleness


class StalenessTests(ApplyCase):
    def setUp(self) -> None:
        super().setUp()
        self.user_files()
        self.render()
        self.before = tree(self.project)

    def refused(self, code: str, **kw: Any) -> None:
        with self.assertRaises(ApplyError) as ctx:
            self.apply(answer=b"", **kw)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(tree(self.project), self.before)

    def test_changed_staged_file(self) -> None:
        staged = self.project / ".cab/setup/staged/.claude/agents/verifier.md"
        staged.write_bytes(staged.read_bytes() + b"tools: Bash\n")
        self.refused("staged_mismatch")

    def test_extra_staged_file(self) -> None:
        (self.project / ".cab/setup/staged/.claude/agents/extra.md").write_text("x\n")
        self.refused("staged_mismatch")

    def test_changed_profile(self) -> None:
        copy = self.project / ".cab/setup/render-profile.toml"
        copy.write_bytes(
            copy.read_bytes().replace(b"approval_ttl_hours = 4", b"approval_ttl_hours = 5")
        )
        self.refused("profile_changed")

    def test_changed_generator_version(self) -> None:
        with mock.patch.object(apply_mod, "GENERATOR_VERSION", "0.1.0.dev9"):
            self.refused("generator_version_changed")

    def test_changed_source_template(self) -> None:
        agent = self.src / "templates/core/agents/verifier.md"
        agent.write_bytes(agent.read_bytes() + b"Changed after render.\n")
        self.refused("bundle_changed")

    def test_missing_render(self) -> None:
        (self.project / ".cab/setup/render.json").unlink()
        self.refused("render_missing")

    def test_staged_symlink(self) -> None:
        target = self.tmp / "outside.md"
        target.write_text("x\n")
        os.symlink(target, self.project / ".cab/setup/staged/.claude/agents/linked.md")
        self.refused("staged_unsafe")

    def test_change_while_the_prompt_is_open(self) -> None:
        def edit() -> None:
            (self.project / "CLAUDE.md").write_bytes(USER_CLAUDE + b"late edit\r\n")

        stdin = FakeTTY(b"contoso-ops\n", on_read=edit)
        outcome = self.apply(stdin=stdin)
        self.assertEqual((outcome.exit, outcome.code), (3, "changed_during_prompt"))
        expected = dict(self.before)
        expected["CLAUDE.md"] = ("file", USER_CLAUDE + b"late edit\r\n", 0o640)
        self.assertEqual(tree(self.project), expected)
        self.assertFalse((self.project / ".cab/backups").exists())

    def test_take_new_must_be_exact_and_resolvable(self) -> None:
        for bad, code in (("../x", "take_new_invalid"), (SKILL, "take_new_not_resolvable")):
            with self.subTest(path=bad):
                with self.assertRaises(ApplyError) as ctx:
                    self.apply(answer=b"", take_new=(bad,))
                self.assertEqual(ctx.exception.code, code)
        self.assertEqual(tree(self.project), self.before)


class HostilePathTests(ApplyCase):
    def test_symlinked_claude_folder(self) -> None:
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        os.symlink(outside, self.project / ".claude")
        self.assertEqual(self.render().exit, apply_mod.EXIT_BLOCKED)
        outcome = self.apply(answer=b"")
        self.assertIn("parent_symlink .claude", "\n".join(outcome.lines))
        self.assertEqual(list(outside.iterdir()), [])

    def test_hardlinked_claude_md(self) -> None:
        other = self.tmp / "shared.md"
        other.write_bytes(USER_CLAUDE)
        os.link(other, self.project / "CLAUDE.md")
        self.render()
        outcome = self.apply(answer=b"")
        self.assertIn("target_not_regular CLAUDE.md", "\n".join(outcome.lines))
        self.assertEqual(other.read_bytes(), USER_CLAUDE)

    def test_symlinked_project_root(self) -> None:
        link = self.tmp / "ops-link"
        os.symlink(self.project, link)
        with self.assertRaises(ApplyError) as ctx:
            apply_mod.apply_project(str(link), source_root=str(self.src), services=self.svc())
        self.assertEqual(ctx.exception.code, "project_root_unsafe")

    def test_symlinked_manifest(self) -> None:
        self.render()
        target = self.tmp / "manifest.json"
        target.write_text("{}")
        os.symlink(target, self.project / ".cab/manifest.json")
        with self.assertRaises(ApplyError) as ctx:
            self.apply(answer=b"")
        self.assertEqual(ctx.exception.code, "manifest_unsafe")


# --------------------------------------------------------------------------- G7


AGENT = ".claude/agents/verifier.md"
GUARD_ENTRY = ".claude/hooks/cab/guard.py"


class ModifiedOwnedFileTests(ApplyCase):
    """G7: a person's body edit stays beside a proposal. The doctor's manifest_mismatch for
    it is a reported known conflict, never PASS; every other mismatch and every edit that
    could change a tool, hook or trusted script still rolls the apply back."""

    def manifest_bytes(self) -> bytes:
        return (self.project / ".cab/manifest.json").read_bytes()

    def edit_after_install(self, rel: str, change: Callable[[bytes], bytes]) -> bytes:
        """Install, edit ``rel`` like a person, render again. Returns the edited bytes."""
        self.render()
        self.assert_ok(self.apply())
        target = self.project / rel
        original = target.read_bytes()
        edited = change(original)
        self.assertNotEqual(edited, original)
        target.write_bytes(edited)
        self.render()
        self.installed_manifest = self.manifest_bytes()
        self.before = tree(self.project, skip=PRIVATE)
        return edited

    def assert_edit_refused(self, outcome: apply_mod.Outcome, rel: str) -> None:
        text = "\n".join(outcome.lines)
        self.assertEqual((outcome.exit, outcome.code), (apply_mod.EXIT_ROLLED_BACK, "rolled_back"))
        self.assertIn(f"doctor FAIL: manifest manifest_mismatch ({rel})", text)
        self.assertNotIn("known conflict", text)
        self.assertEqual(tree(self.project, skip=PRIVATE), self.before)
        self.assertEqual(self.manifest_bytes(), self.installed_manifest)
        self.assertFalse((self.project / (rel + ".cab-new")).exists())

    def test_g7_person_edit_gets_a_proposal_then_take_new(self) -> None:
        self.render()
        self.assert_ok(self.apply())
        installed = load_manifest(self.manifest_bytes())
        edited = self.project / SKILL
        mine = edited.read_bytes() + b"My own step.\n"
        edited.write_bytes(mine)
        self.render()
        outcome = self.apply()
        self.assert_ok(outcome)
        text = "\n".join(outcome.lines)
        self.assertEqual(edited.read_bytes(), mine)
        proposal = self.project / (SKILL + ".cab-new")
        self.assertEqual(proposal.read_bytes(), self.rendered_bundle()[SKILL])
        self.assertIn("owned_modified", text)
        self.assertIn(f"doctor known conflict: {SKILL} differs from its manifest hash", text)
        self.assertIn(f"--take-new {SKILL}", text)
        self.assertIn("guard self test: PASS", text)  # the real self test, not a fake
        self.assertNotIn("doctor FAIL: manifest", text)
        # The manifest still records the generator's bytes, not the person's edit.
        after = load_manifest(self.manifest_bytes())
        self.assertEqual(after.files[SKILL], installed.files[SKILL])
        self.assertNotEqual(after.files[SKILL], sha256_hex(mine))

        later = NOW + datetime.timedelta(minutes=5)
        taken = self.apply(take_new=(SKILL,), clock=lambda: later)
        self.assert_ok(taken)
        self.assertNotIn("known conflict", "\n".join(taken.lines))
        self.assertEqual(edited.read_bytes(), self.rendered_bundle()[SKILL])
        backup = self.project / ".cab/backups/20261112T080500Z/files" / SKILL
        self.assertEqual(backup.read_bytes(), mine)

    def test_agent_body_only_edit_is_kept(self) -> None:
        mine = self.edit_after_install(AGENT, lambda b: b + b"Also check Contoso naming.\n")
        outcome = self.apply()
        self.assert_ok(outcome)
        self.assertIn(f"doctor known conflict: {AGENT}", "\n".join(outcome.lines))
        self.assertEqual((self.project / AGENT).read_bytes(), mine)

    def test_skill_frontmatter_edit_is_not_kept(self) -> None:
        head = b"---\nname: change\n"
        widened = head + b"allowed-tools: Bash(*)\n"
        self.edit_after_install(SKILL, lambda b: b.replace(head, widened, 1))
        self.assert_edit_refused(self.apply(), SKILL)

    def test_skill_shell_injection_in_the_body_is_not_kept(self) -> None:
        self.edit_after_install(SKILL, lambda b: b + b"!`curl -s https://contoso.example/x`\n")
        self.assert_edit_refused(self.apply(), SKILL)

    def test_agent_tool_widening_is_not_kept(self) -> None:
        self.edit_after_install(AGENT, lambda b: b.replace(b"\ntools: ", b"\ntools: Write, ", 1))
        self.assert_edit_refused(self.apply(), AGENT)

    def test_edited_hook_code_is_never_kept(self) -> None:
        self.edit_after_install(GUARD_ENTRY, lambda b: b + b"# a person's note\n")
        self.assert_edit_refused(self.apply(), GUARD_ENTRY)

    def test_unplanned_mismatch_stays_fatal(self) -> None:
        self.edit_after_install(SKILL, lambda b: b + b"My own step.\n")
        real = apply_mod._doctor

        def other_file_changed(root: str, prep: Any, manifest: Any):
            path = os.path.join(root, AGENT)
            with open(path, "ab") as handle:
                handle.write(b"changed outside the plan\n")
            return real(root, prep, manifest)

        with mock.patch.object(apply_mod, "_doctor", other_file_changed):
            outcome = self.apply()
        text = "\n".join(outcome.lines)
        self.assertEqual(outcome.exit, apply_mod.EXIT_ROLLED_BACK, text)
        self.assertIn(f"doctor FAIL: manifest manifest_mismatch ({AGENT})", text)
        self.assertEqual(self.manifest_bytes(), self.installed_manifest)
        self.assertFalse((self.project / (SKILL + ".cab-new")).exists())

    def test_known_conflict_needs_unchanged_edit_and_written_proposal(self) -> None:
        proposal = SKILL + ".cab-new"
        for name, interfere, exit_code in (
            ("edit changed after the prompt", lambda root: self.append(root, SKILL),
             apply_mod.EXIT_ROLLED_BACK),
            ("proposal gone", lambda root: os.unlink(os.path.join(root, proposal)),
             apply_mod.EXIT_ROLLED_BACK),
            # Rollback never deletes bytes it did not write: the altered proposal is
            # reported as not restored (exit 6), and the manifest is still the old one.
            ("proposal altered", lambda root: self.append(root, proposal),
             apply_mod.EXIT_ROLLBACK_FAILED),
        ):  # fmt: skip
            with self.subTest(case=name):
                self.fresh_project()
                self.edit_after_install(SKILL, lambda b: b + b"My own step.\n")
                real = apply_mod._doctor

                def doctor(root: str, prep: Any, manifest: Any, act=interfere, real=real):
                    act(root)
                    return real(root, prep, manifest)

                with mock.patch.object(apply_mod, "_doctor", doctor):
                    outcome = self.apply()
                text = "\n".join(outcome.lines)
                self.assertEqual(outcome.exit, exit_code, text)
                self.assertIn(f"doctor FAIL: manifest manifest_mismatch ({SKILL})", text)
                self.assertNotIn("known conflict", text)
                self.assertEqual(self.manifest_bytes(), self.installed_manifest)

    @staticmethod
    def append(root: str, rel: str) -> None:
        with open(os.path.join(root, rel), "ab") as handle:
            handle.write(b"x\n")

    def fresh_project(self) -> None:
        """Fresh project folder for the next sub-case (same source and home)."""
        shutil.rmtree(self.project, ignore_errors=True)
        (self.project / ".cab" / "setup").mkdir(parents=True)
        (self.project / ".cab/setup/profile.toml").write_bytes(encode(user()))


class EditCanBeKeptTests(unittest.TestCase):
    GEN = b"---\nname: change\ndescription: Fixture skill.\n---\nBody.\n"

    def test_rules(self) -> None:
        keep = apply_mod.edit_can_be_kept
        skill, agent = SKILL, AGENT
        cases = [
            (skill, self.GEN + b"More body.\n", True),
            (agent, self.GEN + b"More body.\n", True),
            (skill, self.GEN.replace(b"Body.", b"Shorter."), True),
            (skill, self.GEN.replace(b"Fixture skill.", b"Edited."), False),
            (skill, b"\xef\xbb\xbf" + self.GEN, False),
            (skill, b"\n" + self.GEN, False),
            (skill, self.GEN.replace(b"\n", b"\r\n"), False),
            (skill, self.GEN + b"Run !`ls`\n", False),
            (".claude/skills/change/helper.py", self.GEN + b"x\n", False),
            (GUARD_ENTRY, self.GEN + b"x\n", False),
            ("simtenant/simtenant.py", b"# edited\n", False),
            ("docs/identity.md", b"# edited guide\n", True),
            ("simtenant/seed/contoso.json", b'{"edited": true}\n', True),
        ]
        for rel, edited, expected in cases:
            with self.subTest(rel=rel, edited=edited[:24]):
                self.assertIs(keep(rel, edited, self.GEN), expected)
        self.assertFalse(keep(SKILL, self.GEN + b"x\n", b"no frontmatter\n"))
        self.assertFalse(keep(SKILL, self.GEN + b"x\n", b"---\nname: open\n"))
        kept_injection = self.GEN + b"!`date`\n"
        self.assertTrue(keep(SKILL, kept_injection + b"note\n", kept_injection))


# --------------------------------------------------------------------------- rollback


class FailingOps(FileOps):
    """Unit-only: makes the rename of one target fail, optionally every write after it."""

    def __init__(self, fail_suffix: str, then_all: bool = False) -> None:
        self.fail_suffix = fail_suffix
        self.then_all = then_all
        self.tripped = False

    def write(self, path: str, data: bytes, mode: int) -> None:
        if self.tripped and self.then_all:
            raise OSError("unit-only: restore write refused")
        if path.endswith(self.fail_suffix) and not self.tripped:
            self.tripped = True
            with mock.patch.object(fsutil.os, "replace", side_effect=OSError("unit-only")):
                fsutil.atomic_write(path, data, mode=mode)
        super().write(path, data, mode)


class RollbackTests(ApplyCase):
    def setUp(self) -> None:
        super().setUp()
        self.user_files()
        self.render()
        self.before = tree(self.project)

    def test_rename_failure_after_partial_write_restores_exactly(self) -> None:
        ops = FailingOps(os.sep + os.path.join(".claude", "settings.json"))
        outcome = self.apply(fileops=ops)
        self.assertTrue(ops.tripped)
        self.assertEqual((outcome.exit, outcome.code), (apply_mod.EXIT_ROLLED_BACK, "rolled_back"))
        self.assertIn("rolled back to the exact earlier bytes", "\n".join(outcome.lines))
        self.assertEqual(tree(self.project), self.before)
        self.assertFalse((self.project / ".cab/manifest.json").exists())
        self.assertEqual(len(self.backups()), 1)

    def test_failed_restoration_is_reported_and_fails_closed(self) -> None:
        ops = FailingOps(os.sep + os.path.join(".claude", "settings.json"), then_all=True)
        outcome = self.apply(fileops=ops)
        text = "\n".join(outcome.lines)
        self.assertEqual(outcome.exit, apply_mod.EXIT_ROLLBACK_FAILED)
        self.assertIn("ROLLBACK FAILED", text)
        self.assertIn("not restored: CLAUDE.md", text)
        self.assertIn("not restored: .gitignore", text)
        self.assertFalse((self.project / ".cab/manifest.json").exists())
        # Files that apply created were still removed (unlink is not a write).
        self.assertFalse((self.project / SKILL).exists())

    def test_selftest_failure_or_unknown_rolls_back(self) -> None:
        for check in (
            Check(apply_mod.FAIL, "not_denied", "unit-only injected callback"),
            Check(apply_mod.UNKNOWN, "selftest_not_wired", "unit-only injected callback"),
        ):
            with self.subTest(code=check.code):
                outcome = self.apply(selftest=lambda root, c=check: c)
                self.assertEqual(outcome.exit, apply_mod.EXIT_ROLLED_BACK)
                self.assertIn(
                    f"guard self test: {check.status} {check.code}", "\n".join(outcome.lines)
                )
                self.assertEqual(tree(self.project), self.before)

    def test_unit_only_pass_callback_is_labelled(self) -> None:
        outcome = self.apply(selftest=lambda root: UNIT_PASS)
        self.assert_ok(outcome)
        self.assertIn("[unit-only injected callback]", "\n".join(outcome.lines))

    def test_doctor_floor_failure_rolls_back(self) -> None:
        real = apply_mod._doctor

        def broken(root: str, prep: Any, manifest: Any):
            os.unlink(os.path.join(root, ".claude/hooks/cab/closeout.py"))
            return real(root, prep, manifest)

        with mock.patch.object(apply_mod, "_doctor", broken):
            outcome = self.apply(selftest=lambda root: UNIT_PASS)
        text = "\n".join(outcome.lines)
        self.assertIn("doctor FAIL: hook_target", text)
        self.assertEqual(outcome.exit, apply_mod.EXIT_ROLLED_BACK, text)
        self.assertEqual(tree(self.project), self.before)


# --------------------------------------------------------------------------- verifier


class ConfigVerifierTests(ApplyCase):
    def test_manifest_verifier_for_config_lock(self) -> None:
        self.render()
        self.assert_ok(self.apply())
        root = str(self.project)
        self.assertTrue(apply_mod.manifest_verifier(root, ".claude/settings.json"))
        self.assertTrue(apply_mod.manifest_verifier(root, SKILL))
        self.assertFalse(apply_mod.manifest_verifier(root, ".claude/skills/mine/SKILL.md"))
        skill = self.project / SKILL
        skill.write_bytes(skill.read_bytes() + b"edit\n")
        self.assertFalse(apply_mod.manifest_verifier(root, SKILL))
        path = self.project / ".claude/settings.json"
        doc = json.loads(path.read_bytes())
        doc["permissions"]["deny"].remove("Bash(cab approve:*)")
        path.write_text(json.dumps(doc))
        self.assertFalse(apply_mod.manifest_verifier(root, ".claude/settings.json"))
        doc["permissions"]["deny"].append("Bash(cab approve:*)")
        doc["disableAllHooks"] = True
        path.write_text(json.dumps(doc))
        self.assertFalse(apply_mod.manifest_verifier(root, ".claude/settings.json"))
        self.assertFalse(apply_mod.manifest_verifier("relative", ".claude/settings.json"))
        self.assertFalse(apply_mod.manifest_verifier(root, "../x"))

    def test_one_verifier_implementation(self) -> None:
        # The S9 copy is gone: apply exports the ConfigChange lock's own default verifier,
        # so config_lock reports its specific block codes for it too.
        self.assertIs(apply_mod.manifest_verifier, config_lock.manifest_verifier)

    def test_preexisting_floor_hook_removal_is_not_verified(self) -> None:
        # S10 §4 item 1: a floor hook group a person already had is never recorded by the
        # merge, so a record-only check passes when it is removed. The lock does not.
        self.render()
        staged = self.project / ".cab/setup/staged/.claude/settings.json"
        floor_group = json.loads(staged.read_bytes())["hooks"]["PreToolUse"]
        (self.project / ".claude").mkdir()
        settings = self.project / ".claude/settings.json"
        settings.write_text(json.dumps({"hooks": {"PreToolUse": floor_group}}, indent=2))
        self.render()
        self.assert_ok(self.apply())
        manifest = load_manifest((self.project / ".cab/manifest.json").read_bytes())
        self.assertNotIn("PreToolUse", manifest.settings.hook_groups)  # precondition
        root = str(self.project)
        self.assertTrue(apply_mod.manifest_verifier(root, ".claude/settings.json"))
        doc = json.loads(settings.read_bytes())
        del doc["hooks"]["PreToolUse"]
        settings.write_text(json.dumps(doc, indent=2))
        data = settings.read_bytes()
        record_only = config_file_matches(
            manifest, ".claude/settings.json", data, required_deny=config_lock.FLOOR_DENY
        )
        self.assertTrue(record_only)  # what the removed S9 copy decided
        rel = ".claude/settings.json"
        self.assertFalse(apply_mod.manifest_verifier(root, rel))
        self.assertEqual(config_lock.manifest_check(root, rel), "floor_missing")

    def test_linked_parent_folder_is_not_followed(self) -> None:
        self.render()
        self.assert_ok(self.apply())
        root = str(self.project)
        skills = self.project / ".claude/skills"
        copy = self.tmp / "skills-copy"
        shutil.copytree(skills, copy)
        shutil.rmtree(skills)
        os.symlink(copy, skills)
        # Same bytes behind a linked folder: refused, never followed.
        self.assertEqual((copy / "change/SKILL.md").read_bytes(), self.rendered_bundle()[SKILL])
        self.assertFalse(apply_mod.manifest_verifier(root, SKILL))
        self.assertEqual(config_lock.manifest_check(root, SKILL), "target_unsafe")


DEMO_PY = "simtenant/simtenant.py"
DEMO_SEED = "simtenant/seed/contoso.json"
DEMO_STATE = "simtenant/state.json"  # a person's (or a demo run's) own file


class ReferenceProfileTests(ApplyCase):
    """The reference demo (contoso-solo) renders, applies, keeps person data and uninstalls
    through the real path; only the two exact demo files are generator-owned."""

    def install_reference(self) -> Any:
        (self.src / "profiles").mkdir()
        shutil.copyfile(
            ROOT / "profiles/contoso-solo.toml", self.src / "profiles/contoso-solo.toml"
        )
        (self.project / "simtenant").mkdir()
        (self.project / DEMO_STATE).write_bytes(b'{"run": 1}\n')
        rendered = self.render(reference="contoso-solo")
        self.assert_ok(rendered, "rendered")
        text = "\n".join(rendered.lines)
        self.assertIn("reference profile contoso-solo", text)
        self.assertNotIn("bundle_path_refused", text)
        self.assertFalse((self.project / ".cab/setup/render-profile.toml").exists())
        prov = json.loads((self.project / ".cab/setup/render.json").read_bytes())
        self.assertEqual(prov["profile"], {"source": "reference", "name": "contoso-solo"})
        outcome = self.apply()
        self.assert_ok(outcome)
        self.assertIn("guard self test: PASS", "\n".join(outcome.lines))
        return load_manifest((self.project / ".cab/manifest.json").read_bytes())

    def test_reference_demo_applies_and_owns_exactly_the_demo_files(self) -> None:
        manifest = self.install_reference()
        bundle = self.rendered_bundle()
        for rel in (DEMO_PY, DEMO_SEED, "docs/identity.md"):
            with self.subTest(rel=rel):
                self.assertEqual((self.project / rel).read_bytes(), bundle[rel])
                self.assertEqual(manifest.files[rel], sha256_hex(bundle[rel]))
        for rel in ("changes/README.md", "audit/README.md"):
            self.assertIn(rel, manifest.offered)
            self.assertNotIn(rel, manifest.files)
        simtenant_owned = {p for p in manifest.files if p.startswith("simtenant/")}
        self.assertEqual(simtenant_owned, {DEMO_PY, DEMO_SEED})
        self.assertEqual((self.project / DEMO_STATE).read_bytes(), b'{"run": 1}\n')

    def test_uninstall_removes_unchanged_demo_files_and_keeps_person_data(self) -> None:
        self.install_reference()
        uninstalled = uninstall_project(str(self.project), services=self.svc())
        self.assertEqual((uninstalled.exit, uninstalled.code), (0, "uninstalled"))
        for rel in (DEMO_PY, DEMO_SEED, "docs/identity.md", ".cab/manifest.json"):
            self.assertFalse((self.project / rel).exists(), rel)
        self.assertEqual((self.project / DEMO_STATE).read_bytes(), b'{"run": 1}\n')
        self.assertTrue((self.project / "changes/README.md").is_file())
        self.assertTrue((self.project / "audit/README.md").is_file())

    def test_edited_seed_is_kept_but_the_trusted_demo_script_is_not(self) -> None:
        self.install_reference()
        seed = self.project / DEMO_SEED
        mine = seed.read_bytes() + b"\n"
        seed.write_bytes(mine)
        self.render(reference="contoso-solo")
        kept = self.apply()
        self.assert_ok(kept)
        self.assertIn(f"doctor known conflict: {DEMO_SEED}", "\n".join(kept.lines))
        self.assertEqual(seed.read_bytes(), mine)
        proposal = self.project / (DEMO_SEED + ".cab-new")
        self.assertEqual(proposal.read_bytes(), self.rendered_bundle()[DEMO_SEED])

        script = self.project / DEMO_PY
        script.write_bytes(script.read_bytes() + b"# a person's change\n")
        self.render(reference="contoso-solo")
        installed = (self.project / ".cab/manifest.json").read_bytes()
        refused = self.apply()
        text = "\n".join(refused.lines)
        self.assertEqual(refused.exit, apply_mod.EXIT_ROLLED_BACK, text)
        self.assertIn(f"doctor FAIL: manifest manifest_mismatch ({DEMO_PY})", text)
        self.assertEqual((self.project / ".cab/manifest.json").read_bytes(), installed)
        self.assertFalse((self.project / (DEMO_PY + ".cab-new")).exists())


if __name__ == "__main__":
    unittest.main()
