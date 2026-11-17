"""S9 ``cab setup`` CLI: dispatch, fixed errors, no abbreviations, read-only commands.

Fixture data only, below <repo>/.local/test-tmp (see test_apply). The C-main source entry
(``runtime.cli.source_main``) is exercised in process with the same injected services.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cab_of_one.setup import apply as apply_mod  # noqa: E402
from cab_of_one.setup import cli, session  # noqa: E402
from test_apply import PROJECT, ApplyCase, FakeTTY, tree  # noqa: E402


class CliCase(ApplyCase):
    def run_cli(self, *argv: str, source: bool = True, **kw: Any) -> tuple[int, str, str]:
        services = self.svc(kw.pop("answer", None), **kw)
        services.stderr = io.StringIO()
        code = cli.main(
            list(argv), source_root=str(self.src) if source else None, services=services
        )
        out = services.stdout.text.getvalue() if isinstance(services.stdout, FakeTTY) else ""
        return code, out, services.stderr.getvalue()


class UsageTests(CliCase):
    def test_usage_errors_are_fixed_and_never_echo_input(self) -> None:
        for argv in (
            [],
            ["nonsense"],
            ["apply", "--take", "x"],
            ["render", "--prof", "p.toml"],
            ["render", "--profile", "a", "--reference", "contoso-solo"],
            ["begin"],
            ["apply", "--secret-token-abc123"],
        ):
            with self.subTest(argv=argv):
                code, out, err = self.run_cli(*argv)
                self.assertEqual(code, apply_mod.EXIT_USAGE)
                self.assertIn("cab setup: usage error", err)
                self.assertNotIn("Traceback", err)
                self.assertNotIn("secret-token-abc123", err + out)

    def test_help_exits_zero(self) -> None:
        code, out, _ = self.run_cli("render", "--help")
        self.assertEqual(code, 0)
        self.assertIn("--reference", out)

    def test_internal_errors_have_no_traceback(self) -> None:
        with mock.patch.object(apply_mod, "render_project", side_effect=RuntimeError("boom x")):
            code, out, err = self.run_cli("render")
        self.assertEqual(code, cli.EXIT_INTERNAL)
        self.assertIn("internal error (RuntimeError)", err)
        self.assertNotIn("boom x", err + out)
        self.assertNotIn("Traceback", err)

    def test_source_root_is_required_for_render_and_apply(self) -> None:
        for command in ("render", "apply"):
            code, _, err = self.run_cli(command, source=False)
            self.assertEqual(code, apply_mod.EXIT_REFUSED)
            self.assertIn("source_root_unavailable", err)

    def test_c_main_source_entry_dispatches_here(self) -> None:
        from cab_of_one.runtime import cli as runtime_cli

        with mock.patch.object(cli, "main", return_value=7) as called:
            code = runtime_cli.source_main(
                ["setup", "render", "--reference", "contoso-solo"],
                source_root=str(self.src),
                entry=str(self.src / "scripts/cab"),
            )
        self.assertEqual(code, 7)
        called.assert_called_once()
        self.assertEqual(called.call_args.args[0], ["render", "--reference", "contoso-solo"])
        self.assertEqual(called.call_args.kwargs, {"source_root": str(self.src)})


class CommandTests(CliCase):
    def test_render_then_apply_through_the_cli(self) -> None:
        before = tree(self.project, skip=(".cab/setup",))
        code, out, err = self.run_cli("render")
        self.assertEqual(code, 0, err)
        self.assertIn("staged: .cab/setup/staged", out)
        self.assertEqual(tree(self.project, skip=(".cab/setup",)), before)  # G5
        code, out, err = self.run_cli("apply", "--project", str(self.project))
        self.assertEqual(code, 0, err + out)
        self.assertIn("applied:", out)
        self.assertIn("Type the project folder name", out)

    def test_answers_is_the_profile_option_and_out_is_the_project(self) -> None:
        answers = self.tmp / "answers.toml"
        answers.write_bytes((self.project / ".cab/setup/profile.toml").read_bytes())
        other = self.tmp / "other-cwd"
        other.mkdir()
        code, out, err = self.run_cli(
            "render", "--answers", str(answers), "--out", str(self.project),
            cwd=lambda: str(other),
        )  # fmt: skip
        self.assertEqual(code, 0, err)
        self.assertTrue((self.project / ".cab/setup/staged").is_dir())
        self.assertEqual(list(other.iterdir()), [])

    def test_apply_from_a_non_terminal_is_refused(self) -> None:
        self.run_cli("render")
        code, _, err = self.run_cli("apply", stdin=FakeTTY(b"contoso-ops\n", tty=False))
        self.assertEqual(code, 3)
        self.assertIn("real terminal", err)
        self.assertFalse((self.project / ".cab/manifest.json").exists())

    def test_profile_errors_are_fixed_codes(self) -> None:
        (self.project / ".cab/setup/profile.toml").write_text("schema = 2\n")
        code, _, err = self.run_cli("render")
        self.assertEqual(code, 3)
        self.assertIn("cab setup: profile refused:", err)
        self.assertNotIn("Traceback", err)

    def test_discover_writes_only_discovery_json(self) -> None:
        (self.project / "scripts").mkdir()
        (self.project / "scripts/users.ps1").write_text("Connect-MgGraph -Scopes User.Read\n")
        before = tree(self.project, skip=(".cab/setup",))
        code, out, err = self.run_cli("discover")
        self.assertEqual(code, 0, err)
        self.assertIn(".cab/setup/discovery.json", out)
        self.assertNotIn("User.Read", out)
        self.assertEqual(tree(self.project, skip=(".cab/setup",)), before)
        self.assertTrue((self.project / ".cab/setup/discovery.json").is_file())

    def test_begin_binds_once(self) -> None:
        code, out, err = self.run_cli("begin", "--session-id", "sess-contoso-0001")
        self.assertEqual(code, 0, err)
        self.assertEqual(session.load(str(self.project)).session_id, "sess-contoso-0001")
        code, _, err = self.run_cli("begin", "--session-id", "sess-contoso-0002")
        self.assertEqual(code, 3)
        self.assertIn("session_conflict", err)

    def test_uninstall_without_install_is_refused(self) -> None:
        code, _, err = self.run_cli("uninstall")
        self.assertEqual(code, 3)
        self.assertIn("not_installed", err)

    def test_shape_reports_no_names_or_content(self) -> None:
        self.run_cli("render")
        self.assertEqual(self.run_cli("apply")[0], 0)
        code, out, err = self.run_cli("shape", str(self.project))
        self.assertEqual(code, 0, err)
        shape = json.loads(out)
        self.assertTrue(shape["manifest"])
        self.assertTrue(shape["bypass_disabled"])
        self.assertEqual(shape["deny"]["human_only_commands"], 5)
        events = {h["event"] for h in shape["hooks"]}
        self.assertIn("ConfigChange", events)
        self.assertIn({"tools": ["Glob", "Grep", "Read"], "read_only": True,
                       "writes_files": False, "runs_commands": False}, shape["agents"])  # fmt: skip
        for word in ("safety-reviewer", "verifier", "Contoso", PROJECT, "Fixture"):
            self.assertNotIn(word, out)

    def test_shape_is_one_valid_json_line_beyond_the_display_limit(self) -> None:
        self.run_cli("render")
        self.assertEqual(self.run_cli("apply")[0], 0)
        agents = self.project / ".claude/agents"
        for n in range(40):
            (agents / f"contoso-extra-{n:02d}.md").write_text(
                f"---\nname: contoso-extra-{n:02d}\ntools: Read, Grep, Bash(ls:*), "
                f"mcp__contoso-prod__delete_user, ContosoSecretTool{n}\n---\nBody.\n"
            )
        settings = self.project / ".claude/settings.json"
        doc = json.loads(settings.read_bytes())
        doc["hooks"]["ContosoPrivateEvent"] = [
            {"hooks": [{"type": "command", "command": "/home/contoso/secret-token-abc123.sh"}]}
        ]
        settings.write_text(json.dumps(doc, indent=2))
        code, out, err = self.run_cli("shape", str(self.project))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count("\n"), 1)
        self.assertGreater(len(out), 512)  # the old sanitize cut made this invalid JSON
        self.assertTrue(out.isascii())
        shape = json.loads(out)
        self.assertEqual(shape["other_hook_events"], 1)
        extra = {"tools": ["Bash", "Grep", "Read", "mcp", "other"], "read_only": False,
                 "writes_files": False, "runs_commands": True}  # fmt: skip
        self.assertEqual(shape["agents"].count(extra), 40)
        for word in ("contoso", "Contoso", "secret-token", "mcp__", "/home", "Private"):
            self.assertNotIn(word, out)

    def test_oversized_shape_is_a_fixed_valid_json_object(self) -> None:
        self.run_cli("render")
        self.assertEqual(self.run_cli("apply")[0], 0)
        with mock.patch.object(cli, "MAX_SHAPE_CHARS", 64):
            code, out, err = self.run_cli("shape", str(self.project))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), cli.SHAPE_UNAVAILABLE)

    def test_shape_json_refuses_unprintable_or_unserialisable_values(self) -> None:
        for value in ({"x": "\x7f"}, {"x": float("nan")}, {"x": object()}):
            with self.subTest(value=repr(value)[:20]):
                self.assertEqual(json.loads(cli.shape_json(value)), cli.SHAPE_UNAVAILABLE)
        self.assertEqual(json.loads(cli.shape_json({"x": "café"})), {"x": "café"})

    def test_shape_of_hostile_settings_never_crashes(self) -> None:
        (self.project / ".claude").mkdir()
        settings = self.project / ".claude/settings.json"
        for raw in (
            '{"hooks": {"PreToolUse": [{"hooks": 7}]}, "permissions": {"deny": "x"}}',
            '{"a": 1, "a": 2}',
            "[" * 5000,
        ):
            with self.subTest(raw=raw[:30]):
                settings.write_text(raw)
                code, out, err = self.run_cli("shape", str(self.project))
                self.assertEqual(code, 0, err)
                self.assertIsInstance(json.loads(out), dict)


if __name__ == "__main__":
    unittest.main()
