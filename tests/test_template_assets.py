"""Static checks for the S7 template assets (agents, skills, CLAUDE block, probe references).

Read only: every path is derived from this repository and nothing is written. Standard
library plus the runtime package, so template text is checked against the real runtime
vocabulary (role files, plan files, tiers, verdicts, verify values, change.toml schema,
classifier).
"""

from __future__ import annotations

import json
import re
import string
import unittest
from pathlib import Path

from cab_of_one.runtime import cli as runtime_cli
from cab_of_one.runtime import paths, planhash, schema
from cab_of_one.runtime.classification_types import KIND_READ, KIND_WRITE, leaves
from cab_of_one.runtime.classify import classify_tool_call

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = REPO_ROOT / "templates"
CORE = TEMPLATES / "core"

AGENT_TOOLS: dict[str, tuple[str, ...]] = {
    "impact-analyst": ("Read", "Grep", "Glob", "Bash"),
    "runbook-author": ("Read", "Grep", "Glob", "Write"),
    "safety-reviewer": ("Read", "Grep", "Glob"),
    "verifier": ("Read", "Grep", "Glob", "Bash"),
    "recorder": ("Read", "Grep", "Glob", "Write"),
}
AGENT_SKILLS: dict[str, tuple[str, ...]] = {"safety-reviewer": ("blocker-catalog",)}
SKILLS = ("change", "change-intake", "tiering", "blocker-catalog", "readonly-probes")
PROBE_REFS = (
    TEMPLATES / "m365" / "readonly-probes" / "entra-id.md",
    TEMPLATES / "m365" / "readonly-probes" / "exchange-online.md",
    TEMPLATES / "m365" / "readonly-probes" / "intune.md",
    TEMPLATES / "azure" / "readonly-probes" / "azure-cli.md",
)
HANDOFF = (TEMPLATES / "handoff" / "HANDOFF.md", TEMPLATES / "handoff" / "PROGRESS.md")
FORBIDDEN_AGENT_TOOLS = {"Edit", "MultiEdit", "NotebookEdit", "Task", "Agent", "WebFetch"}
AGENT_KEYS = {"name", "description", "tools", "skills"}
SKILL_KEYS = {"name", "description"}
ALLOWED_PLACEHOLDERS: frozenset[str] = frozenset()  # core assets need none today
FICTIONAL_DOMAINS = ("contoso.example", "example.net", "example.com", "example.org")
FINDING_CODE = re.compile(r"[A-Za-z0-9_.-]{1,32}")

S3_POLICY = {
    "adapters": {"enabled": ["simtenant", "m365-powershell", "azure-cli", "graph-http"]},
    "tiers": {"critical_patterns": []},
    "classifier": {"trusted_simtenant_commands": ["simtenant"]},
}


def agent_path(name: str) -> Path:
    return CORE / "agents" / f"{name}.md"


def skill_path(name: str) -> Path:
    return CORE / "skills" / name / "SKILL.md"


def all_assets() -> list[Path]:
    files = [CORE / "CLAUDE.md"]
    files += [agent_path(n) for n in AGENT_TOOLS]
    files += [skill_path(n) for n in SKILLS]
    files += list(PROBE_REFS) + list(HANDOFF)
    return files


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def flat(text: str) -> str:
    """Lower case with whitespace collapsed, for phrase checks."""
    return " ".join(text.split()).lower()


def split_frontmatter(text: str) -> tuple[dict[str, object], str]:
    """Minimal parser for the frontmatter subset these assets use.

    Supports ``key: scalar`` and ``key:`` followed by ``  - item`` lines. Anything else
    fails, so a construct a YAML reader might read differently cannot slip through.
    """
    if not text.startswith("---\n"):
        raise ValueError("no frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("unterminated frontmatter")
    meta: dict[str, object] = {}
    last: str | None = None
    for line in text[4:end].split("\n"):
        item = re.fullmatch(r"  - ([A-Za-z0-9-]+)", line)
        if item:
            if last is None or not isinstance(meta[last], list):
                raise ValueError("list item without a list key")
            meta[last].append(item.group(1))  # type: ignore[union-attr]
            continue
        pair = re.fullmatch(r"([a-z][a-z-]*):(?: (.*))?", line)
        if not pair:
            raise ValueError(f"unsupported frontmatter line: {line!r}")
        key, value = pair.group(1), pair.group(2)
        if key in meta:
            raise ValueError(f"duplicate key {key}")
        meta[key] = [] if value is None or value == "" else value
        last = key
    return meta, text[end + 5 :]


def fenced_blocks(text: str, lang: str) -> list[str]:
    return re.findall(r"```" + re.escape(lang) + r"\n(.*?)```", text, flags=re.DOTALL)


def bash(command: str):
    return classify_tool_call("Bash", {"command": command}, policy=S3_POLICY, read_file=None)


class AssetSetTests(unittest.TestCase):
    def test_every_owned_asset_exists_and_is_utf8_lf(self) -> None:
        for path in all_assets():
            with self.subTest(path=path.relative_to(REPO_ROOT)):
                self.assertTrue(path.is_file())
                data = path.read_bytes()
                data.decode("utf-8")
                self.assertNotIn(b"\r", data)
                self.assertTrue(data.endswith(b"\n"))

    def test_core_agents_and_skills_are_exactly_the_design_set(self) -> None:
        agents = sorted(p.stem for p in (CORE / "agents").glob("*.md"))
        self.assertEqual(agents, sorted(AGENT_TOOLS))
        skills = sorted(p.parent.name for p in (CORE / "skills").glob("*/SKILL.md"))
        self.assertEqual(skills, sorted(SKILLS))


class AgentToolTests(unittest.TestCase):
    def meta(self, name: str) -> tuple[dict[str, object], str]:
        return split_frontmatter(read(agent_path(name)))

    def test_frontmatter_keys_name_and_description(self) -> None:
        for name in AGENT_TOOLS:
            with self.subTest(agent=name):
                meta, body = self.meta(name)
                self.assertLessEqual(set(meta), AGENT_KEYS)
                self.assertEqual(meta["name"], name)
                desc = meta["description"]
                self.assertIsInstance(desc, str)
                self.assertTrue(desc)
                self.assertNotIn(": ", desc)  # would change meaning for a YAML reader
                self.assertLess(len(desc), 1024)
                self.assertTrue(body.strip())

    def test_tools_are_explicit_and_exact(self) -> None:
        for name, expected in AGENT_TOOLS.items():
            with self.subTest(agent=name):
                meta, _ = self.meta(name)
                tools = meta.get("tools")
                self.assertIsInstance(tools, str, "every agent needs an explicit tools: line")
                parsed = tuple(t.strip() for t in tools.split(","))
                self.assertEqual(parsed, expected)
                self.assertFalse(FORBIDDEN_AGENT_TOOLS & set(parsed))
                for tool in parsed:
                    self.assertRegex(tool, r"^[A-Z][A-Za-z]+$")  # no Bash(...) style scoping

    def test_safety_reviewer_is_strictly_read_only_with_blocker_catalog(self) -> None:
        meta, _ = self.meta("safety-reviewer")
        self.assertEqual(meta["tools"], "Read, Grep, Glob")
        self.assertEqual(meta["skills"], ["blocker-catalog"])

    def test_skills_field_only_where_designed(self) -> None:
        for name in AGENT_TOOLS:
            with self.subTest(agent=name):
                meta, _ = self.meta(name)
                expected = list(AGENT_SKILLS.get(name, ()))
                self.assertEqual(meta.get("skills", []), expected)
                for skill in expected:
                    self.assertTrue(skill_path(skill).is_file())

    def test_bash_only_for_read_only_investigators(self) -> None:
        with_bash = {n for n, t in AGENT_TOOLS.items() if "Bash" in t}
        self.assertEqual(with_bash, {"impact-analyst", "verifier"})
        for name in sorted(with_bash):
            with self.subTest(agent=name):
                body = flat(self.meta(name)[1])
                self.assertIn("limited by the project guard", body)
                self.assertIn("read-only programs", body)
                self.assertIn("denies any administrative write", body)
                self.assertIn("never put secrets", body)

    def test_write_agents_match_runtime_role_files(self) -> None:
        with_write = {n for n, t in AGENT_TOOLS.items() if "Write" in t}
        self.assertEqual(with_write, set(paths.ROLE_FILES))
        for name, files in paths.ROLE_FILES.items():
            with self.subTest(agent=name):
                body = self.meta(name)[1]
                for file in files:
                    self.assertIn(f"`{file}`", body)
                self.assertIn(f"exactly {'one file' if len(files) == 1 else 'two files'}", body)

    def test_runtime_role_files_never_include_authority_or_targets(self) -> None:
        for files in paths.ROLE_FILES.values():
            self.assertFalse(set(files) & set(paths.AUTHORITY_FILES))
            self.assertNotIn("targets.csv", files)

    def test_verifier_never_fixes(self) -> None:
        body = flat(self.meta("verifier")[1])
        self.assertIn("you do not fix, retry or undo anything", body)
        self.assertIn("the main session runs `cab verify`, not you", body)


class ExampleContractTests(unittest.TestCase):
    def test_runbook_change_toml_example_parses_with_runtime_schema(self) -> None:
        body = read(agent_path("runbook-author"))
        blocks = fenced_blocks(body, "toml")
        self.assertEqual(len(blocks), 1)
        plan = schema.load_change(blocks[0].encode("utf-8"), "CHG-0007")
        self.assertEqual(set(plan.answers), {"reversible", "has_dependents", "targets_enumerated"})
        self.assertTrue(plan.steps)
        for step in plan.steps:
            self.assertIsNotNone(step.command)

    def test_runbook_example_commands_match_scope_targets_and_kind(self) -> None:
        plan = schema.load_change(
            fenced_blocks(read(agent_path("runbook-author")), "toml")[0].encode(), "CHG-0007"
        )
        for step in plan.steps:
            r = bash(step.command)
            self.assertEqual(r.kind, KIND_WRITE)
            self.assertFalse(r.unknown)
            self.assertTrue(r.targets_complete)
            self.assertEqual(tuple(r.targets), step.targets)
            for leaf in leaves(r):
                if leaf.kind == KIND_WRITE:
                    self.assertEqual(leaf.scope, plan.tenant)

    def test_runbook_probe_example_is_a_read(self) -> None:
        text = read(agent_path("runbook-author"))
        probe = re.search(r'^probe = "(.*?)\s+->', text, flags=re.MULTILINE)
        self.assertIsNotNone(probe)
        self.assertEqual(bash(probe.group(1)).kind, KIND_READ)

    def test_safety_reviewer_verdict_example_matches_runtime_schema(self) -> None:
        blocks = fenced_blocks(read(agent_path("safety-reviewer")), "json")
        self.assertEqual(len(blocks), 1)
        doc = json.loads(blocks[0])
        self.assertEqual(set(doc), {"verdict", "findings"})
        self.assertIn(doc["verdict"], schema.VERDICTS)
        for finding in doc["findings"]:
            self.assertEqual(set(finding), {"code", "detail"})
            self.assertRegex(finding["code"], FINDING_CODE)
            self.assertLessEqual(len(finding["detail"]), 2000)

    def test_safety_reviewer_names_every_verdict(self) -> None:
        body = read(agent_path("safety-reviewer"))
        for verdict in schema.VERDICTS:
            self.assertIn(f"`{verdict}`", body)

    def test_verifier_example_uses_runtime_verify_values(self) -> None:
        body = read(agent_path("verifier"))
        blocks = fenced_blocks(body, "json")
        self.assertEqual(len(blocks), 1)
        doc = json.loads(blocks[0])
        self.assertTrue(schema.is_change_id(doc["change_id"]))
        for row in doc["results"]:
            self.assertIn(row["result"], schema.VERIFY_VALUES)
            self.assertEqual(bash(row["probe"]).kind, KIND_READ)
        for value in schema.VERIFY_VALUES:
            self.assertIn(f"`{value}`", body)

    def test_tiering_uses_runtime_tier_and_answer_names(self) -> None:
        body = read(skill_path("tiering"))
        for tier in schema.TIER_RANK:
            self.assertIn(f"`{tier}`", body)
        for key in ("reversible", "has_dependents", "targets_enumerated"):
            self.assertIn(f"`{key}`", body)


class SkillTests(unittest.TestCase):
    def test_skill_frontmatter(self) -> None:
        for name in SKILLS:
            with self.subTest(skill=name):
                meta, body = split_frontmatter(read(skill_path(name)))
                self.assertLessEqual(set(meta), SKILL_KEYS)  # no allowed-tools pre-approval
                self.assertEqual(meta["name"], name)
                desc = meta["description"]
                self.assertIsInstance(desc, str)
                self.assertTrue(desc)
                self.assertNotIn(": ", desc)
                self.assertLess(len(desc), 1024)
                self.assertTrue(body.strip())

    def test_blocker_catalog_has_b1_to_b12_once(self) -> None:
        body = read(skill_path("blocker-catalog"))
        rows = re.findall(r"^\| (B\d+) \|", body, flags=re.MULTILINE)
        self.assertEqual(rows, [f"B{i}" for i in range(1, 13)])

    def test_probe_references_are_reads_for_the_real_classifier(self) -> None:
        for path in PROBE_REFS:
            # Probe commands sit in table rows ("| question | `cmd` |") or on an indented
            # line under a list item; prose mentions such as "az ... delete" are excluded.
            lines = [
                ln for ln in read(path).split("\n") if ln.startswith("| ") or ln.startswith("  `")
            ]
            commands = [
                c
                for ln in lines
                for c in re.findall(r"`([^`\n]+)`", ln)
                if c.startswith(("pwsh ", "az "))
            ]
            with self.subTest(path=path.name):
                self.assertTrue(commands)
            for command in commands:
                with self.subTest(path=path.name, command=command):
                    r = bash(command)
                    self.assertEqual(r.kind, KIND_READ, r.reasons)
                    self.assertFalse(r.unknown)


class MechanismTests(unittest.TestCase):
    """Required control explanations (the brief's list), checked as phrases."""

    def test_core_claude_block_explains_every_mechanism(self) -> None:
        text = flat(read(CORE / "CLAUDE.md"))
        for file in planhash.PLAN_FILES:
            self.assertIn(f"`{file}`", text)
        for phrase in (
            "invalidates the check, the review, any acknowledgement, the approval and the snapshot",
            "immutable ids",
            "exact tenant state scope",
            "byte for byte",
            "each step runs once",
            "counts as a write, at least `normal`",
            "snapshot, every tier",
            "including `standard` changes",
            "first unit first",
            "gets `cab verify` pass",
            "stop at the first failure",
            "subagents never write the tenant",
            "it is verification debt until its targets are re-read",
            "unmeasured is never pass and never a successful close",
            'an exit code or "success" is never verification',
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_core_claude_block_names_every_human_gate_and_protected_file(self) -> None:
        text = read(CORE / "CLAUDE.md")
        for gate in (
            "`cab approve`",
            "`cab ack`",
            "`cab resume`",
            "the interactive `cab intake CHG-NNNN`",
            "`cab setup apply`",
            "`cab setup uninstall`",
            "`script`",
            "`expect`",
            "Python `pty`",
        ):
            self.assertIn(gate, text)
        for name in sorted(paths.AUTHORITY_FILES):
            self.assertIn(f"`{name}`", text)
        for top in (".claude/", "policy/", "audit/", ".cab/state/", ".cab/manifest.json"):
            self.assertIn(f"`{top}`", text)

    def test_core_claude_is_a_block_body_without_markers(self) -> None:
        text = read(CORE / "CLAUDE.md")
        self.assertNotIn("cab-of-one:begin", text)
        self.assertNotIn("cab-of-one:end", text)
        self.assertNotIn("<!--", text)
        self.assertFalse(text.startswith("---"))
        self.assertTrue(text.startswith("## "))  # nests under the user's own top heading

    def test_change_skill_walks_every_gate(self) -> None:
        text = flat(read(skill_path("change")))
        for phrase in (
            "plan hash invalidation",
            "snapshot (every tier)",
            "at least `normal`",
            "first unit first",
            "first failure stops",
            "`cab approve chg-nnnn`",
            "`cab ack`",
            "`cab resume`",
            "verification debt",
            "it is never pass",
            "unmeasured leaves it open-unverified",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)

    def test_unmeasured_is_never_described_as_pass(self) -> None:
        bad = re.compile(
            r"unmeasured (is|counts as|means) (a )?(pass|passed|success|done|closed)\b"
        )
        for path in all_assets():
            with self.subTest(path=path.name):
                self.assertIsNone(bad.search(flat(read(path))))


class IntakeInstructionTests(unittest.TestCase):
    """The person answers with ``cab intake CHG-NNNN`` in their own terminal. The main
    session never writes intake.md from a conversation, and fixtures stay fixtures."""

    SELF_WRITE = re.compile(
        r"(save|write|record|put)\b[^.]*\banswers\b[^.]*\bto `?intake\.md"
        r"|ask the person with `askuserquestion` and save"
    )

    def test_intake_skill_lists_exactly_the_runtime_questions(self) -> None:
        body = split_frontmatter(read(skill_path("change-intake")))[1]
        numbered = re.findall(r"^\d+\. \*\*(.+?):\*\*", body, flags=re.MULTILINE)
        labels = [label.removeprefix("- ").removesuffix(":") for _, label in
                  runtime_cli.INTAKE_FIELDS]  # fmt: skip
        self.assertEqual(numbered, labels)

    def test_no_asset_tells_the_agent_to_write_intake_from_a_conversation(self) -> None:
        for path in all_assets():
            with self.subTest(path=path.name):
                text = flat(read(path))
                self.assertIsNone(self.SELF_WRITE.search(text))
                self.assertNotIn("source: person", text)  # the old self-written template


class RenderSafetyTests(unittest.TestCase):
    def test_string_template_valid_and_placeholders_known(self) -> None:
        for path in all_assets():
            with self.subTest(path=path.relative_to(REPO_ROOT)):
                text = read(path)
                tpl = string.Template(text)
                self.assertTrue(tpl.is_valid())
                self.assertLessEqual(set(tpl.get_identifiers()), ALLOWED_PLACEHOLDERS)
                # A literal dollar must be written as $$ (the renderer substitutes whole text).
                self.assertNotIn("$", text.replace("$$", ""))
                tpl.substitute({k: "x" for k in ALLOWED_PLACEHOLDERS})


class HygieneTests(unittest.TestCase):
    def test_no_local_paths_or_personal_identifiers(self) -> None:
        local = re.compile(r"/Users/|/home/|[A-Za-z]:\\|~/|CloudStorage|OneDrive|Google Drive")
        email = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
        for path in all_assets():
            with self.subTest(path=path.name):
                text = read(path)
                self.assertIsNone(local.search(text))
                for match in email.finditer(text):
                    self.assertTrue(match.group(0).lower().endswith(FICTIONAL_DOMAINS))


if __name__ == "__main__":
    unittest.main()
