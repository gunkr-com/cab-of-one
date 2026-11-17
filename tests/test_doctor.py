"""S6 static doctor (E8, E10): hooks, fail-closed entries, deny floor, agents, layers.

Every project is a fixture under <repo>/.local/test-tmp. User and managed settings are
fixture ``SettingsLayer`` values passed in; no real settings file, HOME or tenant is read.
The hook scripts are placeholder files; nothing is executed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import doctor  # noqa: E402
from cab_of_one.runtime.doctor import (  # noqa: E402
    DEFAULT_REQUIRED_DENY,
    FAIL,
    PASS,
    UNKNOWN,
    WARN,
    SettingsLayer,
    inspect_project,
    parse_frontmatter,
    read_project_layers,
)

POLICY = b"""schema = 1

[harness]
approval_ttl_hours = 4
one_active_change = true
min_claude_code = "2.1.295"

[adapters]
enabled = ["simtenant"]

[tiers]
critical_patterns = []

[execution]
canary_tiers = ["critical"]
halt_on_failure = true
"""
CATALOG = b"schema = 1\n"
# Assembled so that no S6 file holds the literal token the S8 render floor refuses.
PLUGIN_ROOT_NAME = "_".join(("CLAUDE", "PLUGIN", "ROOT"))
SCRIPTS = ("guard.py", "audit.py", "closeout.py", "config_lock.py")
AGENTS = {
    "safety-reviewer.md": "---\nname: safety-reviewer\ndescription: Finds the reason a "
    "change should not run.\ntools: Read, Grep, Glob\nskills: [blocker-catalog]\n---\n\nBody.\n",
    "verifier.md": "---\nname: verifier\ndescription: >\n  Re-reads the system.\ntools:\n"
    "  - Read\n  - Grep\n  - Glob\n  - Bash\n---\n\nBody.\n",
}


def cmd(script: str, arg: str = "") -> str:
    tail = f" {arg}" if arg else ""
    return f'python3 "$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/{script}{tail}'


def good_settings() -> dict:
    def entry(script: str, arg: str = "", matcher: str | None = None, block: bool = False):
        handler: dict = {"type": "command", "command": cmd(script, arg)}
        if block:
            handler.update({"timeout": 10, "onFailure": "block"})
        group: dict = {"hooks": [handler]}
        if matcher is not None:
            group["matcher"] = matcher
        return [group]

    return {
        "permissions": {
            "allow": ["Bash(git status)"],
            "deny": ["Read(./secrets/**)", *DEFAULT_REQUIRED_DENY],
        },
        "hooks": {
            "PreToolUse": entry("guard.py", matcher="*", block=True),
            "PostToolUse": entry("audit.py", "post", matcher="*"),
            "PostToolUseFailure": entry("audit.py", "fail", matcher="*"),
            "SubagentStart": entry("audit.py", "substart"),
            "SubagentStop": entry("audit.py", "substop"),
            "SessionStart": entry("audit.py", "start"),
            "SessionEnd": entry("audit.py", "end"),
            "Stop": entry("closeout.py"),
            "ConfigChange": entry("config_lock.py"),
        },
        "env": {"CONTOSO_FIXTURE": "1"},
    }


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="doctor-", dir=TMP_ROOT)).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = self.tmp / "contoso-ops"
        hooks = self.project / ".claude" / "hooks" / "cab"
        hooks.mkdir(parents=True)
        for name in SCRIPTS:
            (hooks / name).write_text("# fixture placeholder, never executed\n")
        agents = self.project / ".claude" / "agents"
        agents.mkdir()
        for name, text in AGENTS.items():
            (agents / name).write_text(text)
        (self.project / "policy").mkdir()
        (self.project / "policy" / "policy.toml").write_bytes(POLICY)
        (self.project / "policy" / "standard-changes.toml").write_bytes(CATALOG)
        self.write_settings(good_settings())

    def write_settings(self, data: dict, name: str = "settings.json") -> None:
        (self.project / ".claude" / name).write_text(json.dumps(data, indent=2))

    def manifest(self) -> dict[str, str]:
        out = {}
        for rel in [f".claude/hooks/cab/{s}" for s in SCRIPTS] + [
            f".claude/agents/{a}" for a in AGENTS
        ]:
            out[rel] = hashlib.sha256((self.project / rel).read_bytes()).hexdigest()
        return out

    def layers(self, *, managed: SettingsLayer | None = None, user: dict | None = None):
        project, local = read_project_layers(str(self.project))
        return [
            managed or SettingsLayer("managed", None, "missing"),
            SettingsLayer("user", user if user is not None else {}),
            project,
            local,
        ]

    def run_doctor(self, **kw):
        layers = kw.pop("layers", None) or self.layers()
        kw.setdefault("version", "2.1.319")
        if "manifest" not in kw:
            kw["manifest"] = self.manifest()
        kw.setdefault("mods", [])
        return inspect_project(str(self.project), layers, **kw)

    def codes(self, report, status: str | None = None) -> set[str]:
        return {i.code for i in report.issues if status is None or i.status == status}


class HealthyProjectTests(Fixture):
    def test_generated_layout_passes_every_check(self) -> None:
        report = self.run_doctor()
        bad = [i for i in report.issues if i.status != PASS]
        self.assertEqual(bad, [])
        self.assertTrue(report.passed)
        self.assertEqual(report.overall, PASS)
        self.assertIn("allow_with_guard", self.codes(report))
        self.assertIn("doctor: PASS", report.lines()[-1])

    def test_unmeasured_inputs_are_unknown_never_pass(self) -> None:
        project, local = read_project_layers(str(self.project))
        report = inspect_project(str(self.project), [project, local])
        unknown = self.codes(report, UNKNOWN)
        for code in ("layer_not_supplied", "managed_masking_unmeasured", "version_not_supplied",
                     "manifest_unmeasured", "mods_unmeasured"):  # fmt: skip
            self.assertIn(code, unknown)
        self.assertEqual(report.overall, UNKNOWN)
        self.assertFalse(report.passed)

    def test_doctor_is_read_only(self) -> None:
        def snapshot() -> dict:
            out = {}
            for base, _dirs, files in os.walk(self.tmp):
                for name in files:
                    p = os.path.join(base, name)
                    out[p] = (Path(p).read_bytes(), os.lstat(p).st_mtime_ns)
            return out

        before = snapshot()
        self.run_doctor()
        inspect_project(str(self.project), [])
        self.assertEqual(snapshot(), before)


class E8Tests(Fixture):
    def test_b_allow_list_without_guard_is_reported(self) -> None:
        self.write_settings({"permissions": {"allow": ["Bash(*)"]}})
        report = self.run_doctor()
        issue = report.by_code("allow_not_gate")[0]
        self.assertEqual(issue.status, FAIL)
        self.assertEqual(
            issue.message,
            "allow rules are not a gate in bypass mode; no PreToolUse guard registered",
        )
        missing = {i.subject for i in report.by_code("hook_missing")}
        self.assertEqual(missing, set(doctor.REQUIRED_EVENTS))
        self.assertEqual(report.overall, FAIL)

    def test_b_managed_hooks_only_silently_disables_project_hooks(self) -> None:
        managed = SettingsLayer("managed", {"allowManagedHooksOnly": True})
        report = self.run_doctor(layers=self.layers(managed=managed))
        masked = report.by_code("hook_masked")
        self.assertEqual({i.subject for i in masked}, set(doctor.REQUIRED_EVENTS))
        self.assertTrue(all(i.status == FAIL for i in masked))
        self.assertIn("project hooks are silently disabled", masked[0].message)
        self.assertIn("allow_not_gate", self.codes(report, FAIL))

    def test_managed_hooks_only_with_the_guard_in_managed_settings(self) -> None:
        managed = SettingsLayer(
            "managed", {"allowManagedHooksOnly": True, "hooks": good_settings()["hooks"]}
        )
        report = self.run_doctor(layers=self.layers(managed=managed))
        self.assertEqual(report.by_code("hook_masked"), [])
        self.assertEqual(report.by_code("managed_hooks_only")[0].status, WARN)

    def test_managed_rules_only_masks_project_deny_rules(self) -> None:
        managed = SettingsLayer("managed", {"allowManagedPermissionRulesOnly": True})
        report = self.run_doctor(layers=self.layers(managed=managed))
        masked = report.by_code("deny_masked")
        self.assertEqual(len(masked), len(DEFAULT_REQUIRED_DENY))
        self.assertIn("project permission rules are ignored", masked[0].message)

    def test_c_mod_handling_tool_check_is_a_warning(self) -> None:
        mods = [{"name": "contoso-helper", "enabled": True, "handles": ["tool.check"]},
                {"name": "quiet", "enabled": True, "handles": ["session.start"]},
                {"name": "off", "enabled": False, "handles": ["tool.call"]}]  # fmt: skip
        report = self.run_doctor(mods=mods)
        warned = report.by_code("mod_tool_check")
        self.assertEqual([(i.status, i.subject) for i in warned], [(WARN, "contoso-helper")])
        self.assertEqual(report.overall, WARN)

    def test_c_unrecognised_mod_metadata_is_unknown(self) -> None:
        report = self.run_doctor(mods=[{"id": "x", "events": ["tool.check"]}])
        self.assertEqual(report.by_code("mod_metadata_unknown")[0].status, UNKNOWN)
        self.assertEqual(report.by_code("mods_ok"), [])

    def test_d_disable_all_hooks_in_settings_local_is_reported(self) -> None:
        self.write_settings({"disableAllHooks": True}, "settings.local.json")
        report = self.run_doctor()
        issue = report.by_code("disable_all_hooks")[0]
        self.assertEqual((issue.status, issue.source), (FAIL, "local"))

    def test_disable_all_hooks_anywhere_including_user_and_managed(self) -> None:
        managed = SettingsLayer("managed", {"disableAllHooks": True})
        report = self.run_doctor(layers=self.layers(managed=managed,
                                                    user={"disableAllHooks": "yes"}))  # fmt: skip
        self.assertEqual(report.by_code("disable_all_hooks")[0].source, "managed")
        self.assertEqual(report.by_code("disable_all_hooks_unknown")[0].source, "user")


class E10Tests(Fixture):
    def test_guard_without_on_failure_block_fails(self) -> None:
        data = good_settings()
        del data["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"]
        self.write_settings(data)
        issue = self.run_doctor().by_code("on_failure_missing")[0]
        self.assertEqual((issue.status, issue.subject), (FAIL, "PreToolUse"))

    def test_on_failure_on_the_group_is_unverified(self) -> None:
        data = good_settings()
        group = data["hooks"]["PreToolUse"][0]
        group["onFailure"] = group["hooks"][0].pop("onFailure")
        self.write_settings(data)
        issue = self.run_doctor().by_code("on_failure_location")[0]
        self.assertEqual(issue.status, UNKNOWN)

    def test_other_value_than_block_fails(self) -> None:
        data = good_settings()
        data["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"] = "continue"
        self.write_settings(data)
        self.assertIn("on_failure_missing", self.codes(self.run_doctor(), FAIL))

    def test_fail_closed_events_are_configurable(self) -> None:
        report = self.run_doctor(fail_closed_events=("PreToolUse", "ConfigChange"))
        issue = report.by_code("on_failure_missing")[0]
        self.assertEqual(issue.subject, "ConfigChange")

    def test_stop_on_failure_field_is_checked_but_never_called_fail_closed(self) -> None:
        events = ("PreToolUse", "Stop", "SubagentStop")
        data = good_settings()
        for event in ("Stop", "SubagentStop"):
            data["hooks"][event][0]["hooks"][0]["onFailure"] = "block"
        self.write_settings(data)
        report = self.run_doctor(fail_closed_events=events)
        present = report.by_code("on_failure_field_no_effect")
        self.assertEqual({(i.status, i.subject) for i in present},
                         {(PASS, "Stop"), (PASS, "SubagentStop")})  # fmt: skip
        self.assertIn("not blocked", present[0].message)
        self.assertIn("not fail-closed", present[0].message)
        ok = {i.subject for i in report.by_code("on_failure_ok")}
        self.assertEqual(ok, {"PreToolUse"})  # Stop is never reported as fail-closed
        self.assertTrue(any("no effect on Stop/SubagentStop" in n for n in report.notes))

    def test_stop_without_prescribed_field_is_drift_not_a_lost_guarantee(self) -> None:
        report = self.run_doctor(fail_closed_events=("PreToolUse", "Stop"))
        issue = report.by_code("on_failure_field_missing")[0]
        self.assertEqual((issue.status, issue.subject), (FAIL, "Stop"))
        self.assertIn("not a fail-closed guarantee", issue.message)
        self.assertEqual(report.by_code("on_failure_missing"), [])


class HookTests(Fixture):
    def test_missing_event_and_wrong_script_are_missing(self) -> None:
        data = good_settings()
        del data["hooks"]["ConfigChange"]
        data["hooks"]["Stop"][0]["hooks"][0]["command"] = cmd("audit.py", "stop")
        self.write_settings(data)
        missing = {i.subject for i in self.run_doctor().by_code("hook_missing")}
        self.assertEqual(missing, {"ConfigChange", "Stop"})

    def test_hook_script_missing_or_symlinked_fails(self) -> None:
        hooks = self.project / ".claude" / "hooks" / "cab"
        (hooks / "closeout.py").unlink()
        real = self.tmp / "elsewhere.py"
        real.write_text("# outside\n")
        (hooks / "config_lock.py").unlink()
        try:
            os.symlink(real, hooks / "config_lock.py")
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")
        report = self.run_doctor(manifest=None)
        self.assertEqual(report.by_code("hook_target_missing")[0].subject, "Stop: closeout.py")
        self.assertEqual(report.by_code("hook_target_unsafe")[0].subject,
                         "ConfigChange: config_lock.py")  # fmt: skip

    def test_narrow_guard_matcher_fails(self) -> None:
        data = good_settings()
        data["hooks"]["PreToolUse"][0]["matcher"] = "Bash"
        data["hooks"]["PostToolUse"][0]["matcher"] = "Bash|Write"
        self.write_settings(data)
        report = self.run_doctor()
        narrow = {(i.subject, i.status) for i in report.by_code("hook_matcher_narrow")}
        self.assertEqual(narrow, {("PreToolUse", FAIL), ("PostToolUse", WARN)})

    def test_plugin_root_reference_fails_for_cab_hooks(self) -> None:
        var = "${" + PLUGIN_ROOT_NAME + "}"
        data = good_settings()
        data["hooks"]["Stop"][0]["hooks"][0]["command"] = (
            f'python3 "{var}"/.claude/hooks/cab/closeout.py'
        )
        data["hooks"]["SessionEnd"].append(
            {"hooks": [{"type": "command", "command": f"{var}/notify.sh"}]}
        )
        self.write_settings(data)
        report = self.run_doctor()
        self.assertEqual(report.by_code("hook_plugin_root")[0].status, FAIL)
        self.assertEqual(report.by_code("hook_plugin_root_other")[0].status, WARN)
        blob = json.dumps(report.to_dict()) + "\n".join(report.lines())
        self.assertNotIn(PLUGIN_ROOT_NAME, blob)

    def test_doctor_source_never_holds_the_literal_plugin_root_name(self) -> None:
        # S8 render.verify_floor refuses rendered bytes containing the literal name, and
        # this module is copied into generated projects.
        source = Path(doctor.__file__).read_bytes()
        self.assertNotIn(PLUGIN_ROOT_NAME.encode(), source)
        code = compile(source, doctor.__file__, "exec")
        consts: list = []
        stack = [code]
        while stack:
            c = stack.pop()
            for k in c.co_consts:
                if hasattr(k, "co_consts"):
                    stack.append(k)
                else:
                    consts.append(k)
        self.assertFalse(any(isinstance(k, str) and PLUGIN_ROOT_NAME in k for k in consts))
        self.assertEqual(doctor._PLUGIN_ROOT_NAME, PLUGIN_ROOT_NAME)

    def test_unknown_hooks_schema_is_not_counted_as_safe(self) -> None:
        self.write_settings({**good_settings(), "hooks": [{"PreToolUse": "guard"}]})
        report = self.run_doctor()
        self.assertEqual(report.by_code("hooks_schema_unknown")[0].status, UNKNOWN)
        self.assertIn("hook_missing", self.codes(report, FAIL))
        self.assertIn("allow_not_gate", self.codes(report, FAIL))

    def test_hook_only_in_user_settings_is_a_warning(self) -> None:
        data = good_settings()
        user_hooks = {"SessionEnd": data["hooks"].pop("SessionEnd")}
        self.write_settings(data)
        report = self.run_doctor(layers=self.layers(user={"hooks": user_hooks}))
        issue = report.by_code("hook_not_shared")[0]
        self.assertEqual((issue.status, issue.source, issue.subject), (WARN, "user", "SessionEnd"))

    def test_user_hooks_are_preserved_and_ignored(self) -> None:
        data = good_settings()
        data["hooks"]["PreToolUse"].insert(
            0, {"matcher": "Write", "hooks": [{"type": "command", "command": "./lint.sh"}]}
        )
        self.write_settings(data)
        report = self.run_doctor()
        self.assertTrue(report.passed, [i for i in report.issues if i.status != PASS])


class DenyAndLayerTests(Fixture):
    def test_missing_deny_rule_is_named(self) -> None:
        data = good_settings()
        data["permissions"]["deny"].remove("Bash(cab approve:*)")
        data["permissions"]["deny"].remove("Write(./audit/**)")
        self.write_settings(data)
        missing = {i.subject for i in self.run_doctor().by_code("deny_missing")}
        self.assertEqual(missing, {"Bash(cab approve:*)", "Write(./audit/**)"})

    def test_deny_rules_merge_across_layers(self) -> None:
        data = good_settings()
        data["permissions"]["deny"].remove("Bash(cab resume:*)")
        self.write_settings(data)
        report = self.run_doctor(
            layers=self.layers(user={"permissions": {"deny": ["Bash(cab resume:*)"]}})
        )
        self.assertEqual(report.by_code("deny_missing"), [])

    def test_required_deny_list_is_injectable(self) -> None:
        report = self.run_doctor(required_deny=("Edit(.claude/**)",))
        self.assertEqual([i.subject for i in report.by_code("deny_missing")], ["Edit(.claude/**)"])

    def test_human_command_in_allow_is_a_warning(self) -> None:
        data = good_settings()
        data["permissions"]["allow"].append("Bash(cab approve:*)")
        self.write_settings(data)
        issue = self.run_doctor().by_code("human_command_allowed")[0]
        self.assertEqual((issue.status, issue.subject), (WARN, "Bash(cab approve:*)"))

    def test_invalid_project_settings_fail(self) -> None:
        (self.project / ".claude" / "settings.json").write_text(
            '{"hooks": {}, "hooks": {"PreToolUse": []}}'
        )
        report = self.run_doctor()
        issue = report.by_code("layer_invalid")[0]
        self.assertEqual((issue.status, issue.source), (FAIL, "project"))

    def test_symlinked_project_settings_are_not_read(self) -> None:
        real = self.tmp / "real-settings.json"
        real.write_text(json.dumps(good_settings()))
        target = self.project / ".claude" / "settings.json"
        target.unlink()
        try:
            os.symlink(real, target)
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")
        project, _ = read_project_layers(str(self.project))
        self.assertEqual((project.status, project.data), ("unsafe", None))

    def test_unknown_source_label_and_bad_project_root(self) -> None:
        report = self.run_doctor(layers=[*self.layers(), SettingsLayer("plugin", {})])
        self.assertEqual(report.by_code("layer_source_unknown")[0].subject, "plugin")
        for bad in ("relative", str(self.project) + "/", str(self.tmp / "missing")):
            with self.subTest(bad=bad):
                r = inspect_project(bad, [])
                self.assertEqual([i.code for i in r.issues], ["project_root_invalid"])

    def test_managed_layer_unreadable_is_unknown(self) -> None:
        report = self.run_doctor(
            layers=self.layers(managed=SettingsLayer("managed", None, "unreadable"))
        )
        self.assertIn("managed_masking_unmeasured", self.codes(report, UNKNOWN))
        self.assertIn("layer_unmeasured", self.codes(report, UNKNOWN))


class AgentTests(Fixture):
    def agent(self, name: str, text: str) -> None:
        (self.project / ".claude" / "agents" / name).write_text(text)

    def test_agent_without_tools_fails(self) -> None:
        self.agent("recorder.md", "---\nname: recorder\ndescription: Writes record.md\n---\n")
        issue = self.run_doctor(manifest=None).by_code("agent_tools_missing")[0]
        self.assertEqual((issue.status, issue.subject), (FAIL, "recorder"))

    def test_safety_reviewer_with_more_tools_fails(self) -> None:
        self.agent(
            "safety-reviewer.md",
            "---\nname: safety-reviewer\ntools: [Read, Grep, Glob, Bash]\n---\n",
        )
        report = self.run_doctor(manifest=None)
        self.assertEqual(report.by_code("safety_reviewer_tools")[0].status, FAIL)

    def test_safety_reviewer_missing_fails(self) -> None:
        (self.project / ".claude" / "agents" / "safety-reviewer.md").unlink()
        report = self.run_doctor(manifest=None)
        self.assertEqual(report.by_code("safety_reviewer_missing")[0].status, FAIL)

    def test_unreadable_frontmatter_is_unknown(self) -> None:
        self.agent("odd.md", "---\nname: odd\ntools: Read\n\tBash\n---\n")
        report = self.run_doctor(manifest=None)
        issue = report.by_code("agent_frontmatter_unknown")[0]
        self.assertEqual((issue.status, issue.subject), (UNKNOWN, "odd"))

    def test_wildcard_tools_fail(self) -> None:
        self.agent("wide.md", "---\nname: wide\ntools: '*'\n---\n")
        self.assertIn("agent_tools_wildcard", self.codes(self.run_doctor(manifest=None), FAIL))

    def test_symlinked_agent_file_fails(self) -> None:
        real = self.tmp / "agent.md"
        real.write_text(AGENTS["safety-reviewer.md"])
        target = self.project / ".claude" / "agents" / "safety-reviewer.md"
        target.unlink()
        try:
            os.symlink(real, target)
        except OSError as exc:
            self.skipTest(f"symlinks unsupported here: {exc.__class__.__name__}")
        report = self.run_doctor(manifest=None)
        self.assertEqual(report.by_code("agent_file_unsafe")[0].status, FAIL)
        self.assertEqual(report.by_code("safety_reviewer_missing")[0].status, UNKNOWN)


class FrontmatterTests(unittest.TestCase):
    def test_supported_forms(self) -> None:
        fm = parse_frontmatter(
            "---\nname: a\ntools: Read, Grep, Bash(git log:*, x)\nskills: [one, two]\n"
            "list:\n  - x\n  - 'y'\nnested:\n  key: value\ntext: |\n  line\n# c\n---\nbody\n"
        )
        self.assertEqual(fm["name"], "a")
        self.assertEqual(fm["tools"], "Read, Grep, Bash(git log:*, x)")
        self.assertEqual(doctor._tools(fm["tools"]), ["Read", "Grep", "Bash(git log:*, x)"])
        self.assertEqual(fm["skills"], ["one", "two"])
        self.assertEqual(fm["list"], ["x", "y"])
        self.assertIs(fm["nested"], Ellipsis)
        self.assertIs(fm["text"], Ellipsis)

    def test_refusals(self) -> None:
        for text in (
            "name: a\n",  # no opening fence
            "---\nname: a\n",  # no closing fence
            "---\r\nname: a\r\n---\r\n",  # CR line ends
            "---\nname: a\nname: b\n---\n",  # duplicate key
            "---\nname: 'a\n---\n",  # broken quote
            "---\n  indented: first\n---\n",  # continuation without a key
            "---\ntools: [Read, Grep\n---\n",  # unclosed flow list
        ):
            with self.subTest(text=text):
                self.assertIsNone(parse_frontmatter(text))


class VersionPolicyManifestTests(Fixture):
    def test_version_against_policy_minimum(self) -> None:
        old = self.run_doctor(version="2.1.200").by_code("version_too_old")[0]
        self.assertEqual((old.status, old.subject), (FAIL, "2.1.200 < 2.1.295"))
        self.assertEqual(self.run_doctor(version="2.1.295").by_code("version_ok")[0].status, PASS)
        self.assertEqual(self.run_doctor(version="2.1.300", min_version="2.2.0")
                         .by_code("version_too_old")[0].subject, "2.1.300 < 2.2.0")  # fmt: skip
        self.assertEqual(self.run_doctor(version="soon").by_code("version_unparsed")[0].status,
                         UNKNOWN)  # fmt: skip

    def test_invalid_policy_fails_and_minimum_becomes_unknown(self) -> None:
        (self.project / "policy" / "policy.toml").write_bytes(POLICY.replace(
            b"halt_on_failure = true", b"halt_on_failure = false"))  # fmt: skip
        report = self.run_doctor(manifest=None)
        self.assertEqual(report.by_code("policy_invalid")[0].subject, "policy_floor")
        self.assertEqual(report.by_code("min_version_unknown")[0].status, UNKNOWN)

    def test_manifest_mismatch_missing_and_bad_entries(self) -> None:
        manifest = self.manifest()
        (self.project / ".claude" / "agents" / "verifier.md").write_text("---\ntools: Read\n---\n")
        manifest["CLAUDE.md"] = "0" * 64
        manifest["../outside"] = "0" * 64
        report = self.run_doctor(manifest=manifest)
        self.assertEqual(
            report.by_code("manifest_mismatch")[0].subject, ".claude/agents/verifier.md"
        )
        self.assertEqual(report.by_code("manifest_file_missing")[0].subject, "CLAUDE.md")
        self.assertEqual(report.by_code("manifest_entry_invalid")[0].status, UNKNOWN)
        self.assertEqual(report.by_code("manifest_ok"), [])

    def test_report_serialises_without_hook_commands(self) -> None:
        blob = json.dumps(self.run_doctor().to_dict())
        self.assertNotIn("CLAUDE_PROJECT_DIR", blob)
        self.assertNotIn("CONTOSO_FIXTURE", blob)


class NoMutationOfInputsTests(Fixture):
    def test_layers_are_not_modified(self) -> None:
        data = good_settings()
        layer = SettingsLayer("user", data)
        frozen = copy.deepcopy(data)
        self.run_doctor(layers=[SettingsLayer("managed", None, "missing"), layer,
                                *read_project_layers(str(self.project))])  # fmt: skip
        self.assertEqual(data, frozen)


if __name__ == "__main__":
    unittest.main()
