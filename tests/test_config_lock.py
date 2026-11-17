"""S10 ConfigChange lock. Settings, home and project are temp fixtures; no real config.

``evaluate`` takes the verifier explicitly (``None`` holds every controlled change);
``main`` uses the default manifest verifier unless a test injects one. ``decision: block``
is checked as output only: no test claims the file on disk was rolled back.

The installed-copy tests render a bundle from a controlled source fixture (the real
runtime, pinned setup manifest module and lock shim), write it to a temp project and run
the pinned shim with ``python3 -I``: no source tree, no plugin, no inherited Python path.
"""

from __future__ import annotations

import ast
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import config_lock  # noqa: E402
from cab_of_one.setup import manifest as manifest_mod  # noqa: E402
from cab_of_one.setup import profile, render  # noqa: E402

SID = "sess-contoso-0001"
SETTINGS = ".claude/settings.json"
SKILL = ".claude/skills/change/SKILL.md"
SKILL_BYTES = b"---\nname: change\ndescription: Contoso change skill.\n---\nBody.\n"
ZERO = "0" * 64


def msg(code: str) -> str:
    return config_lock._MESSAGES[code]


def floor_doc() -> dict:
    """A settings document holding exactly the lock's floor (built from its constants)."""
    hooks: dict[str, list] = {}
    for event, matcher, entry, arg, timeout, closed in config_lock.FLOOR_HOOKS:
        hook = {"type": "command", "command": config_lock.hook_command(entry, arg),
                "timeout": timeout}  # fmt: skip
        if closed:
            hook["onFailure"] = "block"
        group: dict = {"hooks": [hook]}
        if matcher is not None:
            group["matcher"] = matcher
        hooks.setdefault(event, []).append(group)
    return {"hooks": hooks, "permissions": {"deny": list(config_lock.FLOOR_DENY)}}


def recorded(doc: dict) -> manifest_mod.SettingsContribution:
    """The contribution a first apply into an empty project would record for ``doc``."""
    groups = {
        event: tuple(manifest_mod.canon(g) for g in items) for event, items in doc["hooks"].items()
    }
    scalars = tuple(
        (("permissions", key), manifest_mod.canon(value))
        for key, value in doc["permissions"].items()
        if key != "deny" and type(value) in (str, int, bool)
    )
    return manifest_mod.SettingsContribution(
        lists={"permissions.deny": tuple(doc["permissions"]["deny"])},
        hook_groups=groups,
        scalars=scalars,
        file_created=True,
    )


def manifest_bytes(files: dict, settings: manifest_mod.SettingsContribution) -> bytes:
    record = manifest_mod.Manifest(
        generator_version="0.1.0", profile_sha256=ZERO, files=files, settings=settings
    )
    return manifest_mod.dump_manifest(record)


class Rows:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict]] = []

    def __call__(self, _roots):
        return self

    def append(self, event: str, **fields) -> None:
        self.rows.append((event, fields))


class Base(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s10-lock-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = self.tmp / "ops"
        self.home = self.tmp / "home"
        (self.home / ".claude").mkdir(parents=True)
        for folder in (".claude/hooks/cab", ".claude/skills/change", "policy", ".cab/state"):
            (self.proj / folder).mkdir(parents=True)
        (self.proj / "policy" / "policy.toml").write_text("# fixture\n", encoding="utf-8")
        (self.proj / "policy" / "standard-changes.toml").write_text("# fixture\n",
                                                                    encoding="utf-8")  # fmt: skip
        (self.proj / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
        self.entry = str(self.proj / ".claude" / "hooks" / "cab" / "config_lock.py")
        Path(self.entry).write_text("# fixture entry\n", encoding="utf-8")

    def event(self, source: object, file_path: object = None, **extra) -> dict:
        data = {"hook_event_name": "ConfigChange", "session_id": SID}
        if source is not None:
            data["source"] = source
        if file_path is not None:
            data["file_path"] = file_path
        data.update(extra)
        return data

    def decide(self, data: dict, verifier=None) -> config_lock.Verdict:
        return config_lock.evaluate(
            data, project=str(self.proj), home=str(self.home), verifier=verifier
        )


class EvaluateTests(Base):
    def test_project_settings_need_verifier_true(self) -> None:
        path = str(self.proj / ".claude" / "settings.json")
        self.assertEqual(self.decide(self.event("project_settings", path)).code,
                         "manifest_verifier_pending")  # fmt: skip
        seen = []

        def verifier(project: str, rel: str):
            seen.append((project, rel))
            return True

        verdict = self.decide(self.event("project_settings", path), verifier)
        self.assertFalse(verdict.block)
        self.assertEqual(seen, [(str(self.proj), ".claude/settings.json")])
        for result, code in ((False, "manifest_mismatch"), (1, "verifier_error"),
                             ("yes", "verifier_error"), (None, "verifier_error")):  # fmt: skip
            with self.subTest(result=result):
                verdict = self.decide(
                    self.event("project_settings", path), lambda p, r, result=result: result
                )
                self.assertTrue(verdict.block)
                self.assertEqual(verdict.code, code)

        def boom(project: str, rel: str) -> bool:
            raise RuntimeError("x")

        self.assertEqual(self.decide(self.event("project_settings", path), boom).code,
                         "verifier_error")  # fmt: skip

    def test_skills_inside_project_only(self) -> None:
        inside = str(self.proj / ".claude" / "skills" / "change" / "SKILL.md")
        self.assertFalse(self.decide(self.event("skills", inside), lambda p, r: True).block)
        for path in (
            str(self.home / ".claude" / "skills" / "x" / "SKILL.md"),
            str(self.proj / ".claude" / "agents" / "x.md"),
            str(self.proj / ".claude" / "skills"),
            "relative/SKILL.md",
        ):
            with self.subTest(path=path):
                verdict = self.decide(self.event("skills", path), lambda p, r: True)
                self.assertTrue(verdict.block)
                self.assertEqual(verdict.code, "path_unexpected")

    def test_policy_settings_cannot_be_blocked(self) -> None:
        for verifier in (None, config_lock.manifest_verifier, lambda p, r: False):
            verdict = self.decide(self.event("policy_settings", "/etc/managed.json"), verifier)
            self.assertFalse(verdict.block)
            self.assertEqual(verdict.code, "policy_settings_unblockable")

    def test_unknown_source_or_missing_path_blocks(self) -> None:
        for source in (None, "", "plugin_settings", 5):
            with self.subTest(source=source):
                self.assertTrue(self.decide(self.event(source, "/x")).block)
        verdict = self.decide(self.event("project_settings"), lambda p, r: True)
        self.assertEqual((verdict.block, verdict.code), (True, "path_missing"))

    def test_wrong_path_for_source_blocks(self) -> None:
        other = str(self.proj / ".claude" / "settings.local.json")
        verdict = self.decide(self.event("project_settings", other), lambda p, r: True)
        self.assertEqual(verdict.code, "path_unexpected")
        verdict = self.decide(self.event("project_settings", "/elsewhere/.claude/settings.json"),
                              lambda p, r: True)  # fmt: skip
        self.assertEqual(verdict.code, "path_unexpected")

    def test_personal_settings_only_block_hook_disabling(self) -> None:
        local = self.proj / ".claude" / "settings.local.json"
        user = self.home / ".claude" / "settings.json"
        for source, path in (("local_settings", local), ("user_settings", user)):
            with self.subTest(source=source):
                path.write_text(json.dumps({"model": "x"}), encoding="utf-8")
                self.assertFalse(self.decide(self.event(source, str(path))).block)
                path.write_text(json.dumps({"disableAllHooks": True}), encoding="utf-8")
                self.assertEqual(self.decide(self.event(source, str(path))).code, "hooks_disabled")
                path.write_text("{not json", encoding="utf-8")
                self.assertEqual(self.decide(self.event(source, str(path))).code,
                                 "settings_unreadable")  # fmt: skip
                path.unlink()
                self.assertFalse(self.decide(self.event(source, str(path))).block)
        before = user.exists(), local.exists()
        self.assertEqual(before, (False, False))  # the lock never writes personal files

    def test_symlinked_personal_settings_blocks(self) -> None:
        local = self.proj / ".claude" / "settings.local.json"
        target = self.tmp / "t.json"
        target.write_text("{}", encoding="utf-8")
        os.symlink(target, local)
        self.assertEqual(self.decide(self.event("local_settings", str(local))).code,
                         "settings_unreadable")  # fmt: skip

    def test_user_settings_path_must_be_home(self) -> None:
        other = str(self.tmp / "settings.json")
        self.assertEqual(self.decide(self.event("user_settings", other)).code, "path_unexpected")


# --------------------------------------------------------------------------- default verifier


class ManifestBase(Base):
    """A fixture project with floor settings, one generator skill and a schema-1 manifest."""

    def setUp(self) -> None:
        super().setUp()
        self.doc = floor_doc()
        self.doc["permissions"]["deny"].append("Read(./secrets/**)")
        self.doc["permissions"]["disableBypassPermissionsMode"] = "disable"
        self.write_settings(self.doc)
        (self.proj / SKILL).write_bytes(SKILL_BYTES)
        self.files = {SKILL: manifest_mod.sha256_hex(SKILL_BYTES)}
        self.write_manifest(recorded(self.doc))

    def write_settings(self, doc: object) -> None:
        (self.proj / SETTINGS).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    def write_manifest(self, settings: manifest_mod.SettingsContribution) -> None:
        (self.proj / ".cab" / "manifest.json").write_bytes(manifest_bytes(self.files, settings))

    def check(self, rel: str = SETTINGS) -> str:
        return config_lock.manifest_check(str(self.proj), rel)

    def settings_verdict(self) -> config_lock.Verdict:
        path = str(self.proj / SETTINGS)
        return self.decide(self.event("project_settings", path), config_lock.manifest_verifier)


class DefaultVerifierTests(ManifestBase):
    def test_intact_settings_and_skill_are_verified(self) -> None:
        self.assertEqual(self.check(), "verified")
        self.assertEqual(self.check(SKILL), "verified")
        self.assertTrue(config_lock.manifest_verifier(str(self.proj), SETTINGS))
        verdict = self.settings_verdict()
        self.assertEqual((verdict.block, verdict.code), (False, "verified"))
        skill = self.decide(self.event("skills", str(self.proj / SKILL)),
                            config_lock.manifest_verifier)  # fmt: skip
        self.assertEqual((skill.block, skill.code), (False, "verified"))
        # A person's own additions are allowed; only the floor and records are checked.
        self.doc["permissions"]["allow"] = ["Bash(git status)"]
        self.doc["model"] = "contoso-model"
        self.write_settings(self.doc)
        self.assertEqual(self.check(), "verified")

    def test_recorded_contribution_drift(self) -> None:
        for change in (
            lambda d: d["permissions"]["deny"].remove("Read(./secrets/**)"),
            lambda d: d["permissions"].pop("disableBypassPermissionsMode"),
            lambda d: d["hooks"]["SessionStart"][0]["hooks"][0].__setitem__("timeout", 99),
        ):
            with self.subTest(change=change):
                doc = json.loads(json.dumps(self.doc))
                change(doc)
                self.write_settings(doc)
                self.assertEqual(self.check(), "manifest_mismatch")
                verdict = self.settings_verdict()
                self.assertEqual((verdict.block, verdict.code), (True, "manifest_mismatch"))

    def test_floor_is_checked_even_when_the_manifest_records_nothing(self) -> None:
        # The floor was already in the person's file before the first apply, so the merge
        # recorded nothing. A recorded contribution alone would not notice its removal.
        self.write_manifest(manifest_mod.SettingsContribution())
        self.assertEqual(self.check(), "verified")
        empty = manifest_mod.load_manifest((self.proj / ".cab/manifest.json").read_bytes())
        cases = (
            lambda d: d["permissions"]["deny"].remove("Bash(cab approve:*)"),
            lambda d: d["permissions"]["deny"].remove("Edit(./.cab/manifest.json)"),
            lambda d: d["hooks"]["Stop"][0]["hooks"][0].pop("onFailure"),
            lambda d: d["hooks"].pop("ConfigChange"),
            lambda d: d["hooks"]["PreToolUse"][0].__setitem__("matcher", "Bash"),
            lambda d: d["hooks"]["PostToolUse"][0]["hooks"][0].__setitem__("command", "true"),
            lambda d: d.__setitem__("disableAllHooks", True),
            lambda d: d.__setitem__("hooks", []),
        )
        for change in cases:
            with self.subTest(change=change):
                doc = json.loads(json.dumps(self.doc))
                change(doc)
                self.write_settings(doc)
                self.assertEqual(self.check(), "floor_missing")
                data = (self.proj / SETTINGS).read_bytes()
                if "disableAllHooks" not in doc:
                    # The record-only check passes here; the lock's own floor check does not.
                    self.assertTrue(manifest_mod.config_file_matches(empty, SETTINGS, data))
        (self.proj / SETTINGS).unlink()
        self.assertEqual(self.check(), "floor_missing")

    def test_disable_all_hooks_false_is_not_a_gap(self) -> None:
        self.doc["disableAllHooks"] = False
        self.write_settings(self.doc)
        self.assertEqual(self.check(), "verified")

    def test_unreadable_settings(self) -> None:
        for raw in (b"{not json", b'{"a":1,"a":2}', b"\xef\xbb\xbf{}", b"[]"):
            with self.subTest(raw=raw):
                (self.proj / SETTINGS).write_bytes(raw)
                self.assertIn(self.check(), ("settings_unreadable", "floor_missing"))
                self.assertTrue(self.settings_verdict().block)

    def test_skill_drift_unowned_and_deleted(self) -> None:
        (self.proj / SKILL).write_bytes(SKILL_BYTES + b"edited\n")
        self.assertEqual(self.check(SKILL), "manifest_mismatch")
        (self.proj / SKILL).unlink()
        self.assertEqual(self.check(SKILL), "manifest_mismatch")
        mine = self.proj / ".claude/skills/mine/SKILL.md"
        mine.parent.mkdir()
        mine.write_bytes(SKILL_BYTES)
        self.assertEqual(self.check(".claude/skills/mine/SKILL.md"), "manifest_mismatch")

    def test_missing_or_corrupt_manifest(self) -> None:
        target = self.proj / ".cab" / "manifest.json"
        target.unlink()
        self.assertEqual(self.check(), "manifest_missing")
        self.assertEqual(self.check(SKILL), "manifest_missing")
        for raw in (b"{", b"{}", b'{"schema":2}', b"\x00", b""):
            with self.subTest(raw=raw):
                target.write_bytes(raw)
                self.assertEqual(self.check(), "manifest_invalid")
        target.write_bytes(b" " * (config_lock.MAX_FILE_BYTES + 1))
        self.assertEqual(self.check(), "manifest_unsafe")
        verdict = self.settings_verdict()
        self.assertEqual((verdict.block, verdict.code), (True, "manifest_unsafe"))

    def test_symlinked_hardlinked_or_special_manifest(self) -> None:
        target = self.proj / ".cab" / "manifest.json"
        good = target.read_bytes()
        outside = self.tmp / "outside.json"
        outside.write_bytes(good)
        target.unlink()
        os.symlink(outside, target)
        self.assertEqual(self.check(), "manifest_unsafe")
        target.unlink()
        os.link(outside, target)
        self.assertEqual(self.check(), "manifest_unsafe")
        target.unlink()
        os.mkfifo(target)
        self.assertEqual(self.check(), "manifest_unsafe")
        target.unlink()
        target.mkdir()
        self.assertEqual(self.check(), "manifest_unsafe")
        target.rmdir()
        # The .cab folder itself replaced by a link to a folder holding a valid manifest.
        moved = self.tmp / "cab-elsewhere"
        (self.proj / ".cab").rename(moved)
        (moved / "manifest.json").write_bytes(good)
        os.symlink(moved, self.proj / ".cab")
        self.assertEqual(self.check(), "manifest_unsafe")

    def test_unsafe_target(self) -> None:
        settings = self.proj / SETTINGS
        outside = self.tmp / "outside-settings.json"
        outside.write_bytes(settings.read_bytes())
        settings.unlink()
        os.symlink(outside, settings)
        self.assertEqual(self.check(), "target_unsafe")
        settings.unlink()
        os.link(outside, settings)
        self.assertEqual(self.check(), "target_unsafe")
        skill = self.proj / SKILL
        hard = self.tmp / "skill-copy.md"
        os.link(skill, hard)
        self.assertEqual(self.check(SKILL), "target_unsafe")
        hard.unlink()
        self.assertEqual(self.check(SKILL), "verified")
        folder = self.proj / ".claude/skills/change"
        folder.rename(self.tmp / "change-elsewhere")
        os.symlink(self.tmp / "change-elsewhere", folder)
        self.assertEqual(self.check(SKILL), "target_unsafe")

    def test_unexpected_rel_and_errors_never_raise(self) -> None:
        for rel in ("../x", "/etc/passwd", "", ".claude/agents/x.md", ".claude/skills",
                    ".claude/skills/../settings.json", None):  # fmt: skip
            with self.subTest(rel=rel):
                self.assertNotEqual(config_lock.manifest_check(str(self.proj), rel), "verified")
                self.assertFalse(config_lock.manifest_verifier(str(self.proj), rel))
        for project in ("relative", "", str(self.tmp / "missing"), None):
            with self.subTest(project=project):
                self.assertNotEqual(config_lock.manifest_check(project, SETTINGS), "verified")


class ReadProjectFileTests(ManifestBase):
    def test_reader(self) -> None:
        root = str(self.proj)
        self.assertEqual(config_lock.read_project_file(root, SKILL), SKILL_BYTES)
        self.assertIsNone(config_lock.read_project_file(root, "missing/dir/file"))
        self.assertIsNone(config_lock.read_project_file(root, ".claude/none.json"))
        for rel in ("../x", "/abs", "", "a//b", "./a", "a/../b"):
            with self.subTest(rel=rel), self.assertRaises(config_lock.UnsafeFile):
                config_lock.read_project_file(root, rel)
        with self.assertRaises(config_lock.UnsafeFile):
            config_lock.read_project_file(root, ".claude")  # a folder, not a file
        with self.assertRaises(config_lock.UnsafeFile):
            config_lock.read_project_file(root, SKILL, limit=4)
        with self.assertRaises(config_lock.UnsafeFile):
            config_lock.read_project_file(root, SKILL + "/below")  # parent is a file
        with self.assertRaises(config_lock.UnsafeFile):
            config_lock.read_project_file("relative", SKILL)


# --------------------------------------------------------------------------- main


class MainTests(Base):
    def run_main(self, text: str, *, env=None, verifier=None, rows=None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = config_lock.main(
            self.entry,
            stdin=io.StringIO(text),
            stdout=out,
            stderr=err,
            env={"CLAUDE_PROJECT_DIR": str(self.proj)} if env is None else env,
            home=str(self.home),
            verifier=verifier,
            ledger_factory=rows if rows is not None else Rows(),
            exit_process=False,
        )
        return code, out.getvalue(), err.getvalue()

    def test_block_output_and_ledger_row(self) -> None:
        # main's default verifier: this fixture has no .cab/manifest.json.
        rows = Rows()
        path = str(self.proj / ".claude" / "settings.json")
        code, out, err = self.run_main(json.dumps(self.event("project_settings", path)), rows=rows)
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["decision"], "block")
        self.assertIn(msg("manifest_missing"), doc["reason"])
        self.assertNotIn(path, out + err)
        self.assertEqual(rows.rows[0][0], "config_change")
        self.assertEqual(rows.rows[0][1]["decision"], "block")
        self.assertEqual(rows.rows[0][1]["reason_code"], "manifest_missing")
        self.assertEqual(rows.rows[0][1]["session_id"], SID)

    def test_verified_change_allowed(self) -> None:
        path = str(self.proj / ".claude" / "settings.json")
        code, out, _ = self.run_main(json.dumps(self.event("project_settings", path)),
                                     verifier=lambda p, r: True)  # fmt: skip
        self.assertEqual((code, out), (0, "{}\n"))

    def test_injected_verifier_overrides_default(self) -> None:
        rows = Rows()
        path = str(self.proj / ".claude" / "settings.json")
        code, out, _ = self.run_main(json.dumps(self.event("project_settings", path)),
                                     verifier=lambda p, r: False, rows=rows)  # fmt: skip
        self.assertEqual(json.loads(out)["decision"], "block")
        self.assertEqual(rows.rows[0][1]["reason_code"], "manifest_mismatch")

    def test_ledger_failure_keeps_decision(self) -> None:
        class Broken:
            def __init__(self, _roots) -> None:
                raise OSError("x")

        path = str(self.proj / ".claude" / "settings.json")
        code, out, _ = self.run_main(json.dumps(self.event("project_settings", path)), rows=Broken)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["decision"], "block")

    def test_real_ledger_row(self) -> None:
        from cab_of_one.runtime.ledger import Ledger

        path = str(self.proj / ".claude" / "settings.json")
        self.run_main(json.dumps(self.event("project_settings", path)), rows=Ledger)
        files = list((self.proj / "audit" / "ledger").glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        row = json.loads(files[0].read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(row["event"], "config_change")
        self.assertEqual(row["source"], "project_settings")

    def test_policy_settings_allowed_even_without_roots(self) -> None:
        text = json.dumps(self.event("policy_settings", "/etc/x.json"))
        for env in ({}, None):
            code, out, _ = self.run_main(text, env=env)
            self.assertEqual((code, out), (0, "{}\n"))

    def test_roots_failure_blocks(self) -> None:
        path = str(self.proj / ".claude" / "settings.json")
        text = json.dumps(self.event("project_settings", path))
        for env in ({}, {"CLAUDE_PROJECT_DIR": str(self.tmp)}):
            with self.subTest(env=env):
                code, out, _ = self.run_main(text, env=env, verifier=lambda p, r: True)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["decision"], "block")

    def test_malformed_event_blocks_exit_2(self) -> None:
        for text in (
            "",
            "{",
            '{"hook_event_name":"PreToolUse"}',
            '{"hook_event_name":"ConfigChange","source":"skills","source":"x"}',
        ):
            with self.subTest(text=text):
                code, out, _ = self.run_main(text)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(out)["decision"], "block")


class MainDefaultVerifierTests(ManifestBase):
    run_main = MainTests.run_main

    def test_default_verifier_allows_intact_and_blocks_drift(self) -> None:
        path = str(self.proj / SETTINGS)
        rows = Rows()
        code, out, _ = self.run_main(json.dumps(self.event("project_settings", path)), rows=rows)
        self.assertEqual((code, out), (0, "{}\n"))
        self.assertEqual(rows.rows[0][1]["reason_code"], "verified")
        doc = json.loads(json.dumps(self.doc))
        doc["permissions"]["deny"].remove("Bash(cab setup apply:*)")
        self.write_settings(doc)
        code, out, _ = self.run_main(json.dumps(self.event("project_settings", path)))
        self.assertIn(msg("floor_missing"), json.loads(out)["reason"])
        skill = str(self.proj / SKILL)
        code, out, _ = self.run_main(json.dumps(self.event("skills", skill)))
        self.assertEqual((code, out), (0, "{}\n"))

    def test_injected_verifier_still_wins_with_a_manifest(self) -> None:
        path = str(self.proj / SETTINGS)
        rows = Rows()
        _, out, _ = self.run_main(json.dumps(self.event("project_settings", path)),
                                  verifier=lambda p, r: False, rows=rows)  # fmt: skip
        self.assertEqual(json.loads(out)["decision"], "block")
        self.assertEqual(rows.rows[0][1]["reason_code"], "manifest_mismatch")
        text = json.dumps(self.event("policy_settings", "/etc/x.json"))
        self.assertEqual(self.run_main(text)[:2], (0, "{}\n"))


# --------------------------------------------------------------------------- shim and pins


class TemplateTests(unittest.TestCase):
    def test_entry_shim_fails_closed_and_has_no_plugin_reference(self) -> None:
        data = (ROOT / "templates" / "core" / "hooks" / "config_lock.py").read_bytes()
        needle = ("CLAUDE_" + "PLUGIN_ROOT").encode()
        self.assertNotIn(needle, data)
        for rel in ("src/cab_of_one/runtime/config_lock.py", "src/cab_of_one/setup/manifest.py",
                    "src/cab_of_one/setup/__init__.py"):  # fmt: skip
            self.assertNotIn(needle, (ROOT / rel).read_bytes(), rel)
        self.assertIn(b"config_lock.main(__file__)", data)
        self.assertIn(b'"decision":"block"', data)
        self.assertIn(b"SystemExit(2)", data)
        self.assertNotIn(b"\r", data)

    def test_pinned_setup_modules_need_only_the_standard_library(self) -> None:
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        for rel, _dst in render.PINNED_SETUP:
            tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertEqual(node.level, 0, f"relative import in {rel}")
                    self.assertIn(node.module.split(".")[0], allowed, rel)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertIn(alias.name.split(".")[0], allowed, rel)


# --------------------------------------------------------------------------- real apply


def _applied_case():
    import test_apply  # S9 fixture harness (read only): real render + apply into a temp dir

    class AppliedProjectTests(test_apply.ApplyCase):
        def test_default_verifier_on_a_real_apply(self) -> None:
            self.render()
            self.assert_ok(self.apply())
            root = str(self.project)
            self.assertEqual(config_lock.manifest_check(root, SETTINGS), "verified")
            self.assertEqual(config_lock.manifest_check(root, test_apply.SKILL), "verified")
            self.assertEqual(
                config_lock.manifest_check(root, ".claude/skills/mine/SKILL.md"),
                "manifest_mismatch",
            )
            for src, dst in render.PINNED_SETUP:
                self.assertEqual((self.project / dst).read_bytes(), (ROOT / src).read_bytes())
            path = self.project / SETTINGS
            doc = json.loads(path.read_bytes())
            doc["hooks"].pop("Stop")
            path.write_text(json.dumps(doc, indent=2) + "\n")
            self.assertEqual(config_lock.manifest_check(root, SETTINGS), "floor_missing")

    return AppliedProjectTests


AppliedProjectTests = _applied_case()


# --------------------------------------------------------------------------- installed copy


class InstalledCopyTests(unittest.TestCase):
    """The pinned lock runs alone: no source checkout, no plugin, ``python3 -I``."""

    def setUp(self) -> None:
        from test_profile import encode, user
        from test_render import build_source

        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s10-installed-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        source = build_source(self.tmp / "source")
        shim = "templates/core/hooks/config_lock.py"
        (source / shim).write_bytes((ROOT / shim).read_bytes())  # the real shim, not a stand-in
        bundle = render.render_bundle(profile.load_profile(encode(user())), source)
        shutil.rmtree(source)  # nothing of the source tree remains next to the project
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.proj = self.tmp / "installed"
        for rel, data in bundle.items():
            target = self.proj / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (self.proj / ".cab" / "state").mkdir(parents=True)
        self.doc = json.loads(bundle[SETTINGS])
        self.assertEqual(self.doc["permissions"].get("disableBypassPermissionsMode"), "disable")
        owned = {
            rel: manifest_mod.sha256_hex(data)
            for rel, data in bundle.items()
            if rel.startswith(manifest_mod.OWNED_PREFIXES)
        }
        (self.proj / ".cab" / "manifest.json").write_bytes(
            manifest_bytes(owned, recorded(self.doc))
        )
        self.hooks = self.proj / ".claude" / "hooks" / "cab"

    def env(self) -> dict[str, str]:
        env = {"CLAUDE_PROJECT_DIR": str(self.proj), "HOME": str(self.home), "PATH": os.defpath}
        self.assertNotIn("CLAUDE_" + "PLUGIN_ROOT", env)
        return env

    def run_lock(self, source: str, rel: str) -> tuple[int, str]:
        event = {"hook_event_name": "ConfigChange", "session_id": SID, "source": source,
                 "file_path": str(self.proj / rel)}  # fmt: skip
        proc = subprocess.run(
            [sys.executable, "-I", "-B", str(self.hooks / "config_lock.py")],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=self.env(),
            cwd=str(self.tmp),
            timeout=60,
            check=False,
        )
        return proc.returncode, proc.stdout

    def blocked_with(self, result: tuple[int, str], code: str) -> None:
        self.assertEqual(result[0], 0, result)
        self.assertIn(msg(code), json.loads(result[1])["reason"])

    def write_settings(self, doc: dict) -> None:
        (self.proj / SETTINGS).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    def test_modules_load_from_the_pinned_copy_only(self) -> None:
        probe = (
            "import sys; sys.path.insert(0, sys.argv[1]);"
            "import cab_of_one.setup.manifest as m, cab_of_one.runtime.config_lock as c;"
            "print(m.__file__); print(c.__file__)"
        )
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-c", probe, str(self.hooks)],
            capture_output=True, text=True, env=self.env(), cwd=str(self.tmp), timeout=60,
            check=True,
        )  # fmt: skip
        lines = proc.stdout.splitlines()
        self.assertEqual(len(lines), 2, proc.stderr)
        for line in lines:
            self.assertTrue(os.path.realpath(line).startswith(str(self.hooks) + os.sep), line)
            self.assertNotIn(str(ROOT / "src"), line)

    def test_settings_and_skill_changes(self) -> None:
        self.assertEqual(self.run_lock("project_settings", SETTINGS), (0, "{}\n"))
        self.assertEqual(self.run_lock("skills", SKILL), (0, "{}\n"))
        self.assertEqual(self.run_lock("policy_settings", "managed.json"), (0, "{}\n"))

        floor = json.loads(json.dumps(self.doc))
        floor["permissions"]["deny"].remove("Bash(cab approve:*)")
        self.write_settings(floor)
        self.blocked_with(self.run_lock("project_settings", SETTINGS), "floor_missing")

        drift = json.loads(json.dumps(self.doc))
        drift["permissions"].pop("disableBypassPermissionsMode")
        self.write_settings(drift)
        self.blocked_with(self.run_lock("project_settings", SETTINGS), "manifest_mismatch")
        self.write_settings(self.doc)

        skill = self.proj / SKILL
        skill.write_bytes(skill.read_bytes() + b"edited\n")
        self.blocked_with(self.run_lock("skills", SKILL), "manifest_mismatch")

    def test_missing_corrupt_or_linked_manifest(self) -> None:
        target = self.proj / ".cab" / "manifest.json"
        good = target.read_bytes()
        target.write_bytes(b"{")
        self.blocked_with(self.run_lock("project_settings", SETTINGS), "manifest_invalid")
        target.unlink()
        self.blocked_with(self.run_lock("project_settings", SETTINGS), "manifest_missing")
        outside = self.tmp / "manifest-elsewhere.json"
        outside.write_bytes(good)
        os.symlink(outside, target)
        self.blocked_with(self.run_lock("project_settings", SETTINGS), "manifest_unsafe")

    def test_without_the_pinned_setup_package_every_change_is_held(self) -> None:
        shutil.rmtree(self.hooks / "cab_of_one" / "setup")
        self.blocked_with(self.run_lock("project_settings", SETTINGS), "verifier_unavailable")
        self.blocked_with(self.run_lock("skills", SKILL), "verifier_unavailable")
        self.assertEqual(self.run_lock("policy_settings", "managed.json"), (0, "{}\n"))

    def test_without_the_runtime_the_shim_fails_closed(self) -> None:
        shutil.rmtree(self.hooks / "cab_of_one")
        code, out = self.run_lock("project_settings", SETTINGS)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["decision"], "block")


if __name__ == "__main__":
    unittest.main()
