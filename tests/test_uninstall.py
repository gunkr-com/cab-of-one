"""S9 uninstall (G8): only unchanged owned content goes; person data and private-state
protection stay. Fixture data only, below <repo>/.local/test-tmp (see test_apply)."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cab_of_one.setup import apply as apply_mod  # noqa: E402
from cab_of_one.setup import merge  # noqa: E402
from cab_of_one.setup.apply import ApplyError, Check  # noqa: E402
from cab_of_one.setup.uninstall import uninstall_project  # noqa: E402
from test_apply import (  # noqa: E402
    SKILL,
    USER_CLAUDE,
    USER_GITIGNORE,
    USER_SETTINGS,
    ApplyCase,
    FailingOps,
    FakeTTY,
    tree,
)

# .cab/state belongs to the runtime; the real runtime probe may take its state lock there.
PRIVATE = (".cab/setup", ".cab/backups", ".cab/state")


class UninstallCase(ApplyCase):
    def setUp(self) -> None:
        super().setUp()
        self.user_files()
        self.render()
        self.assert_ok(self.apply())
        (self.project / "changes").mkdir(exist_ok=True)
        (self.project / "changes/CHG-0001").mkdir()
        (self.project / "changes/CHG-0001/record.md").write_text("evidence\n")

    def uninstall(self, answer: bytes | None = None, **kw: Any) -> apply_mod.Outcome:
        return uninstall_project(str(self.project), services=self.svc(answer, **kw))


class UninstallTests(UninstallCase):
    def test_g8_removes_only_unchanged_owned_content(self) -> None:
        skill = self.project / SKILL
        mine = skill.read_bytes() + b"My own step.\n"
        skill.write_bytes(mine)
        policy_before = (self.project / "policy/policy.toml").read_bytes()
        outcome = self.uninstall()
        self.assertEqual((outcome.exit, outcome.code), (0, "uninstalled"), outcome.lines)
        text = "\n".join(outcome.lines)

        self.assertFalse((self.project / ".cab/manifest.json").exists())
        self.assertFalse((self.project / ".claude/agents/verifier.md").exists())
        self.assertFalse((self.project / ".claude/hooks/cab/guard.py").exists())
        self.assertFalse((self.project / ".claude/skills/tiering").exists())
        self.assertEqual(skill.read_bytes(), mine)
        self.assertIn("owned_modified " + SKILL, text)

        settings = json.loads((self.project / ".claude/settings.json").read_bytes())
        self.assertEqual(settings, USER_SETTINGS)
        self.assertEqual((self.project / "CLAUDE.md").read_bytes(), USER_CLAUDE)
        self.assertEqual((self.project / "policy/policy.toml").read_bytes(), policy_before)
        self.assertTrue((self.project / "changes/CHG-0001/record.md").exists())
        self.assertTrue((self.project / "policy/standard-changes.toml").exists())

        # Private-state protection is retained even though the manifest is gone.
        ignore = (self.project / ".gitignore").read_bytes()
        self.assertTrue(ignore.startswith(USER_GITIGNORE))
        self.assertIn(merge.make_gitignore_block(), ignore)
        self.assertIn(".gitignore block kept", text)

        backups = self.backups()
        self.assertEqual(len(backups), 2)
        latest = self.project / ".cab/backups" / backups[-1]
        index = json.loads((latest / "index.json").read_bytes())
        self.assertEqual(index["operation"], "uninstall")
        self.assertIn(".cab/manifest.json", index["files"])
        self.assertIn("CLAUDE.md", index["files"])

    def test_reinstall_after_uninstall_adopts_the_retained_block(self) -> None:
        self.assertEqual(self.uninstall().exit, 0)
        self.render()
        outcome = self.apply()
        self.assert_ok(outcome)
        ignore = (self.project / ".gitignore").read_bytes()
        self.assertEqual(ignore.count(merge.GITIGNORE_BEGIN), 1)

    def test_not_confirmed_or_not_a_tty_removes_nothing(self) -> None:
        before = tree(self.project, skip=PRIVATE)
        self.assertEqual(self.uninstall(answer=b"nope\n").exit, apply_mod.EXIT_NOT_CONFIRMED)
        outcome = self.uninstall(stdin=FakeTTY(b"contoso-ops\n", tty=False))
        self.assertEqual((outcome.exit, outcome.code), (3, "not_a_tty"))
        self.assertEqual(tree(self.project, skip=PRIVATE), before)

    def test_active_change_blocks_uninstall(self) -> None:
        before = tree(self.project, skip=PRIVATE)
        active = Check(apply_mod.FAIL, "change_active", "unit-only injected callback")
        outcome = self.uninstall(answer=b"", runtime_probe=lambda root: active)
        self.assertEqual(outcome.exit, apply_mod.EXIT_BLOCKED)
        self.assertIn("runtime change_active", "\n".join(outcome.lines))
        self.assertEqual(tree(self.project, skip=PRIVATE), before)

    def test_failure_rolls_back_exactly(self) -> None:
        before = tree(self.project, skip=PRIVATE)
        ops = FailingOps(os.sep + "CLAUDE.md")
        outcome = self.uninstall(fileops=ops)
        self.assertTrue(ops.tripped)
        self.assertEqual(outcome.exit, apply_mod.EXIT_ROLLED_BACK, outcome.lines)
        self.assertEqual(tree(self.project, skip=PRIVATE), before)
        self.assertTrue((self.project / ".cab/manifest.json").exists())

    def test_change_while_the_prompt_is_open(self) -> None:
        def edit() -> None:
            (self.project / ".claude/agents/verifier.md").write_text("edited during prompt\n")

        outcome = self.uninstall(stdin=FakeTTY(b"contoso-ops\n", on_read=edit))
        self.assertEqual((outcome.exit, outcome.code), (3, "changed_during_prompt"))
        self.assertTrue((self.project / ".cab/manifest.json").exists())


class NotInstalledTests(ApplyCase):
    def test_uninstall_without_manifest_is_refused(self) -> None:
        with self.assertRaises(ApplyError) as ctx:
            uninstall_project(str(self.project), services=self.svc(b""))
        self.assertEqual(ctx.exception.code, "not_installed")


if __name__ == "__main__":
    unittest.main()
