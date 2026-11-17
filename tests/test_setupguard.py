"""S10 setup-session hooks (G6 L1, synthesised hook inputs). Temp files only.

No Claude Code, shell, network or real plugin install is used. The plugin root is a
fixture folder; ``CLAUDE_PROJECT_DIR`` and the plugin root are passed explicitly.
"""

from __future__ import annotations

import io
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

from cab_of_one.setup import session, setupguard  # noqa: E402

SID = "sess-contoso-0001"
OTHER = "sess-contoso-0002"
PLUGIN_ENV = "CLAUDE_" + "PLUGIN_ROOT"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s10-guard-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = self.tmp / "ops"
        self.proj.mkdir()
        self.plugin = self.tmp / "plugin"
        (self.plugin / "scripts").mkdir(parents=True)
        (self.plugin / "scripts" / "cab").write_text("# fixture\n", encoding="utf-8")
        self.cab = str(self.plugin / "scripts" / "cab")
        self.marker = self.proj / ".cab" / "setup" / "session.json"

    def expand(self, name: object = "cab-of-one", mode: object = "default", **extra):
        data = {"hook_event_name": "UserPromptExpansion", "session_id": SID}
        if name is not None:
            data["command_name"] = name
        if mode is not None:
            data["permission_mode"] = mode
        data.update(extra)
        return setupguard.expansion_decision(data, project_dir=str(self.proj))

    def pre(self, tool: str, tool_input: dict, *, sid: object = SID, mode: object = "default"):
        data = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}
        if sid is not None:
            data["session_id"] = sid
        if mode is not None:
            data["permission_mode"] = mode
        return setupguard.pretool_decision(
            data, project_dir=str(self.proj), plugin_root=str(self.plugin)
        )

    def bash(self, command: str, **kw):
        return self.pre("Bash", {"command": command}, **kw)


class ExpansionTests(Base):
    def test_refused_modes_never_bind(self) -> None:
        for mode in ("bypassPermissions", "auto", "dontAsk", "plan", "weird", "", None, 3):
            with self.subTest(mode=mode):
                result = self.expand(mode=mode)
                self.assertTrue(result.blocked)
                self.assertIn("Manual or Accept edits", result.reason)
                self.assertFalse(self.marker.exists())

    def test_both_exact_spellings_bind(self) -> None:
        for name in ("cab-of-one", "cab-of-one:cab-of-one"):
            with self.subTest(name=name):
                result = self.expand(name=name, mode="acceptEdits")
                self.assertFalse(result.blocked)
                self.assertEqual(session.load(str(self.proj)).session_id, SID)

    def test_other_commands_untouched(self) -> None:
        for name in ("deploy", "other:cab-of-one", "cab-of-one-x", "CAB-OF-ONE"):
            with self.subTest(name=name):
                self.assertFalse(self.expand(name=name, mode="bypassPermissions").blocked)
        self.assertFalse(self.marker.exists())

    def test_command_source_is_not_authority(self) -> None:
        for source in ("plugin", "user", "skill", None):
            with self.subTest(source=source):
                result = self.expand(mode="bypassPermissions", command_source=source)
                self.assertTrue(result.blocked)

    def test_missing_name_or_project_blocks(self) -> None:
        self.assertTrue(self.expand(name=None).blocked)
        data = {"hook_event_name": "UserPromptExpansion", "session_id": SID,
                "command_name": "cab-of-one", "permission_mode": "default"}  # fmt: skip
        self.assertTrue(setupguard.expansion_decision(data, project_dir=None).blocked)
        self.assertTrue(setupguard.expansion_decision(data, project_dir="rel").blocked)
        bad_sid = dict(data, session_id="a b")
        self.assertTrue(setupguard.expansion_decision(bad_sid, project_dir=str(self.proj)).blocked)
        self.assertFalse(self.marker.exists())

    def test_conflict_blocks_and_keeps_binding(self) -> None:
        session.begin(str(self.proj), OTHER)
        before = self.marker.read_bytes()
        result = self.expand()
        self.assertTrue(result.blocked)
        self.assertIn("another setup session", result.reason)
        self.assertEqual(self.marker.read_bytes(), before)

    def test_bind_failure_blocks(self) -> None:
        def broken(_project: str, _sid: str) -> None:
            raise OSError("disk")

        data = {"hook_event_name": "UserPromptExpansion", "session_id": SID,
                "command_name": "cab-of-one", "permission_mode": "default"}  # fmt: skip
        result = setupguard.expansion_decision(data, project_dir=str(self.proj), bind=broken)
        self.assertTrue(result.blocked)


class PreToolTests(Base):
    def bind(self) -> None:
        session.begin(str(self.proj), SID)

    def test_unregistered_project_is_not_constrained(self) -> None:
        self.assertTrue(self.bash("curl https://example.invalid").allowed)
        self.assertTrue(self.pre("Write", {"file_path": str(self.proj / "x")}).allowed)

    def test_other_session_is_not_constrained(self) -> None:
        self.bind()
        self.assertTrue(self.bash("rm -rf build", sid=OTHER).allowed)

    def test_read_tools_allowed(self) -> None:
        self.bind()
        for tool in ("Read", "Grep", "Glob", "AskUserQuestion"):
            self.assertTrue(self.pre(tool, {}).allowed)

    def test_writes_only_inside_setup(self) -> None:
        self.bind()
        ok = [".cab/setup/profile.toml", ".cab/setup/interview.jsonl", ".cab/setup/notes/a.md"]
        for rel in ok:
            with self.subTest(rel=rel):
                self.assertTrue(self.pre("Write", {"file_path": str(self.proj / rel)}).allowed)
        bad = [
            ".cab/setup/session.json",
            ".cab/setup/session.lock",
            ".cab/setup/.session.json.abc.tmp",
            ".cab/setup/discovery.json",
            ".cab/setup/staged/.claude/settings.json",
            ".cab/setup",
            ".cab/manifest.json",
            ".claude/settings.json",
            "CLAUDE.md",
            ".CAB/setup/profile.toml",
            ".cab/SETUP/profile.toml",
            ".cab/setup/../manifest.json",
            ".cab/setup/SESSION.json",
        ]
        for rel in bad:
            for tool in ("Write", "Edit"):
                with self.subTest(rel=rel, tool=tool):
                    path = str(self.proj) + "/" + rel
                    self.assertFalse(self.pre(tool, {"file_path": path}).allowed)
        self.assertFalse(self.pre("Write", {"file_path": ".cab/setup/profile.toml"}).allowed)

    def test_symlink_or_hardlink_in_setup_refused(self) -> None:
        self.bind()
        setup = self.proj / ".cab" / "setup"
        os.symlink(self.proj, setup / "up")
        self.assertFalse(self.pre("Write", {"file_path": str(setup / "up" / "x")}).allowed)
        os.symlink(self.proj / "CLAUDE.md", setup / "link.md")
        self.assertFalse(self.pre("Edit", {"file_path": str(setup / "link.md")}).allowed)
        (self.proj / "real.md").write_text("x", encoding="utf-8")
        os.link(self.proj / "real.md", setup / "hard.md")
        self.assertFalse(self.pre("Edit", {"file_path": str(setup / "hard.md")}).allowed)

    def test_bash_allowed_forms(self) -> None:
        self.bind()
        for command in (
            "ls -la",
            "cat scripts/users.ps1 | grep -n Connect",
            "git status && git log --oneline -5",
            "command -v pwsh az gam aws",
            f'python3 "{self.cab}" setup discover',
            f'python3 "{self.cab}" setup render',
            f'"{self.cab}" setup discover',
        ):
            with self.subTest(command=command):
                self.assertTrue(self.bash(command).allowed)

    def test_bash_marker_and_human_paths_refused(self) -> None:
        self.bind()
        for command in (
            f'python3 "{self.cab}" setup begin --session-id {OTHER}',
            f'python3 "{self.cab}" setup end',
            f'python3 "{self.cab}" setup apply',
            f'python3 "{self.cab}" setup uninstall',
            f'script -q /dev/null python3 "{self.cab}" setup apply',
            f'python3 "{self.cab}" setup render --out /somewhere',
            f'python3 "{self.cab}" setup render --out=/somewhere',
            "cab setup discover",
            "echo '{}' > .cab/setup/session.json",
            "rm .cab/setup/session.json",
            "mv .cab/setup/session.json /dev/null",
            "cat .cab/setup/session.json > x",
        ):
            with self.subTest(command=command):
                self.assertFalse(self.bash(command).allowed)
        self.assertEqual(session.load(str(self.proj)).session_id, SID)

    def test_bash_wrappers_nesting_and_opaque_refused(self) -> None:
        self.bind()
        for command in (
            "bash -c 'ls'",
            "sh -c ls",
            "env ls",
            "sudo ls",
            "xargs ls",
            "eval ls",
            "alias ll=ls",
            "FOO=1 ls",
            "ls $(pwd)",
            "ls `pwd`",
            "ls *.ps1",
            "ls ~",
            "ls &",
            "(ls)",
            "ls <(pwd)",
            "rg --pre cat x",
            "tree -o out.txt",
            "git diff --output=x",
            "git -c core.pager=x log",
            "python3 -c 'print(1)'",
            f'python3 "{self.cab}/../cab" setup discover',
            "find . -delete",
            "",
            "ls 'unterminated",
        ):
            with self.subTest(command=command):
                self.assertFalse(self.bash(command).allowed)

    def test_tenant_and_network_message(self) -> None:
        self.bind()
        for command in (
            "curl https://graph.microsoft.com/v1.0/users",
            "az login",
            "pwsh -Command Connect-MgGraph",
            "gam info domain",
            "ls && wget http://example.invalid",
        ):
            with self.subTest(command=command):
                decision = self.bash(command)
                self.assertFalse(decision.allowed)
                self.assertIn("No tenant access during setup.", decision.reason)

    def test_mode_and_identity_fail_closed(self) -> None:
        self.bind()
        for mode in ("bypassPermissions", "auto", "dontAsk", None):
            with self.subTest(mode=mode):
                path = str(self.proj / ".cab/setup/profile.toml")
                self.assertFalse(self.pre("Write", {"file_path": path}, mode=mode).allowed)
                self.assertFalse(self.bash("ls", mode=mode).allowed)
                self.assertTrue(self.pre("Read", {}, mode=mode).allowed)
        # A call without a usable session ID cannot prove it is unrelated: it gets the
        # bound session's limits (read-only commands still pass, writes outside do not).
        for sid in (None, "", "a b", 7):
            with self.subTest(sid=sid):
                outside = str(self.proj / "CLAUDE.md")
                self.assertFalse(self.pre("Write", {"file_path": outside}, sid=sid).allowed)
                self.assertFalse(self.bash("curl https://example.invalid", sid=sid).allowed)
                self.assertFalse(self.pre("WebFetch", {}, sid=sid).allowed)

    def test_unlisted_tools_denied(self) -> None:
        self.bind()
        for tool in ("WebFetch", "WebSearch", "NotebookEdit", "Task", "mcp__x__y", "TodoWrite"):
            with self.subTest(tool=tool):
                self.assertFalse(self.pre(tool, {}).allowed)

    def test_malformed_marker_fails_closed_for_every_session(self) -> None:
        self.marker.parent.mkdir(parents=True)
        self.marker.write_bytes(b"{broken")
        for sid in (SID, OTHER, None):
            with self.subTest(sid=sid):
                self.assertFalse(self.bash("ls", sid=sid).allowed)
                self.assertTrue(self.pre("Read", {}, sid=sid).allowed)
        decision = self.bash("ls")
        self.assertIn("session.json", decision.reason)

    def test_unknown_project_dir_fails_closed_for_writes(self) -> None:
        data = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": SID,
                "permission_mode": "default", "tool_input": {"command": "ls"}}  # fmt: skip
        decision = setupguard.pretool_decision(data, project_dir=None, plugin_root=None)
        self.assertFalse(decision.allowed)


class MainTests(Base):
    def run_main(self, event: dict | str) -> tuple[int, str, str]:
        text = event if isinstance(event, str) else json.dumps(event)
        out, err = io.StringIO(), io.StringIO()
        env = {"CLAUDE_PROJECT_DIR": str(self.proj), PLUGIN_ENV: str(self.plugin)}
        code = setupguard.main(
            stdin=io.StringIO(text), stdout=out, stderr=err, env=env, exit_process=False
        )
        return code, out.getvalue(), err.getvalue()

    def test_expansion_block_shape(self) -> None:
        code, out, _ = self.run_main({"hook_event_name": "UserPromptExpansion",
                                      "session_id": SID, "command_name": "cab-of-one",
                                      "permission_mode": "bypassPermissions"})  # fmt: skip
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["decision"], "block")
        self.assertIn("Manual or Accept edits", doc["reason"])

    def test_pretool_deny_shape(self) -> None:
        session.begin(str(self.proj), SID)
        code, out, err = self.run_main({"hook_event_name": "PreToolUse", "session_id": SID,
                                        "tool_name": "Bash", "permission_mode": "default",
                                        "tool_input": {"command": "az login"}})  # fmt: skip
        self.assertEqual(code, 2)
        spec = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(spec["permissionDecision"], "deny")
        self.assertIn("No tenant access", err)
        self.assertNotIn("az login", out + err)

    def test_allow_shape(self) -> None:
        code, out, _ = self.run_main({"hook_event_name": "PreToolUse", "session_id": SID,
                                      "tool_name": "Bash", "permission_mode": "default",
                                      "tool_input": {"command": "ls"}})  # fmt: skip
        self.assertEqual((code, out), (0, "{}\n"))

    def test_malformed_input_blocks(self) -> None:
        for text in ("", "{", "[]", '{"hook_event_name":"Stop"}',
                     '{"hook_event_name":"PreToolUse","a":1,"a":2}'):  # fmt: skip
            with self.subTest(text=text):
                code, out, _ = self.run_main(text)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(out)["decision"], "block")


if __name__ == "__main__":
    unittest.main()
