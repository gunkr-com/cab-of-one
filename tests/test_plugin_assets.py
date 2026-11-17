"""S10 plugin assets: manifests, setup hooks, generator skill. Static checks only.

``claude plugin validate`` is the authoritative schema check and is run by Codex, not
here. These tests pin the cab-of-one names, the two setup hooks, the human-only skill and
the absence of personal data and of runtime gates in the plugin.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cab_of_one.setup import setupguard  # noqa: E402

PLUGIN_FILES = (
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
    "hooks/hooks.json",
    "hooks/setup_guard.py",
    "skills/cab-of-one/SKILL.md",
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PERSONAL_PATH = re.compile(r"/Users/|/home/[a-z]|CloudStorage|Google ?Drive|C:\\\\Users")


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def front_matter(text: str) -> dict[str, str]:
    lines = text.split("\n")
    assert lines[0] == "---"
    end = lines.index("---", 1)
    out: dict[str, str] = {}
    for line in lines[1:end]:
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


class ManifestTests(unittest.TestCase):
    def test_plugin_manifest(self) -> None:
        doc = load(".claude-plugin/plugin.json")
        self.assertEqual(doc["name"], "cab-of-one")
        self.assertNotIn("author", doc)
        self.assertNotIn("version", doc)  # no invented release

    def test_marketplace_manifest(self) -> None:
        doc = load(".claude-plugin/marketplace.json")
        self.assertEqual(doc["name"], "cab-of-one")
        self.assertIsInstance(doc["owner"]["name"], str)
        self.assertNotIn("email", doc["owner"])
        self.assertEqual([p["name"] for p in doc["plugins"]], ["cab-of-one"])
        self.assertTrue(all("source" in p for p in doc["plugins"]))


class HookTests(unittest.TestCase):
    def test_exactly_the_two_setup_hooks(self) -> None:
        hooks = load("hooks/hooks.json")["hooks"]
        self.assertEqual(sorted(hooks), ["PreToolUse", "UserPromptExpansion"])
        for event, groups in hooks.items():
            self.assertEqual(len(groups), 1, event)
            (hook,) = groups[0]["hooks"]
            self.assertEqual(hook["type"], "command")
            self.assertEqual(hook["onFailure"], "block")
            self.assertEqual(
                hook["command"], 'python3 "${CLAUDE_PLUGIN_ROOT}/hooks/setup_guard.py"'
            )
        self.assertEqual(hooks["PreToolUse"][0]["matcher"], "*")

    def test_no_runtime_gate_in_plugin(self) -> None:
        text = (ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8")
        for name in ("hooks/cab", "audit.py", "closeout.py", "config_lock.py", "Stop",
                     "ConfigChange", "SessionStart"):  # fmt: skip
            self.assertNotIn(name, text)

    def test_fallback_names_match_guard(self) -> None:
        tree = ast.parse((ROOT / "hooks" / "setup_guard.py").read_text(encoding="utf-8"))
        names = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_NAMES" for t in node.targets
            ):
                names = ast.literal_eval(node.value)
        self.assertEqual(names, set(setupguard.COMMAND_NAMES))
        self.assertIn("cab-of-one", names)
        self.assertIn("cab-of-one:cab-of-one", names)


class SkillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (ROOT / "skills" / "cab-of-one" / "SKILL.md").read_text(encoding="utf-8")
        self.meta = front_matter(self.text)

    def test_human_only_generator(self) -> None:
        self.assertEqual(self.meta["name"], "cab-of-one")
        self.assertEqual(self.meta["disable-model-invocation"], "true")

    def test_allowed_tools_only_pinned_setup_commands(self) -> None:
        allowed = self.meta["allowed-tools"]
        self.assertIn("setup discover", allowed)
        self.assertIn("setup render", allowed)
        for word in ("apply", "uninstall", "begin", "Write", "Edit"):
            self.assertNotIn(word, allowed)

    def test_flow_and_limits(self) -> None:
        for phrase in ("Preflight", "Discovery", "Interview", "Profile", "Render and preview",
                       "At most 3 rounds and at most 10 questions", "is **not** an answer",
                       "own terminal"):  # fmt: skip
            self.assertIn(phrase, self.text)


class PrivacyTests(unittest.TestCase):
    def test_no_personal_data(self) -> None:
        for rel in PLUGIN_FILES:
            with self.subTest(rel=rel):
                text = (ROOT / rel).read_text(encoding="utf-8")
                self.assertIsNone(EMAIL.search(text))
                self.assertIsNone(PERSONAL_PATH.search(text))
                self.assertNotIn("\r", text)


if __name__ == "__main__":
    unittest.main()
