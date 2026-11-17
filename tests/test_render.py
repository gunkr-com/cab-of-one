"""S8 rendering: G1 (determinism) and G9 (floor invariant over profile combinations).

The renderer reads a *controlled source fixture* built under <repo>/.local/test-tmp: the
real rules file, runtime package, guard entry template and simtenant demo files, plus
fixture stand-ins for templates other writers own (agents, skills, CLAUDE.md, and the
S5/S10 hook entries). The stand-ins exist only to exercise the renderer. They are not the
product, and these tests are not acceptance of generated content. The fixture hook
entries exit 2 if run; they are never run here.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.runtime import config_lock, schema  # noqa: E402
from cab_of_one.setup import profile, render, rules  # noqa: E402
from cab_of_one.setup.profile import ProfileError  # noqa: E402
from cab_of_one.setup.render import RenderError  # noqa: E402
from test_profile import encode, user  # noqa: E402

AGENTS = {
    "impact-analyst": "Read, Grep, Glob, Bash",
    "recorder": "Read, Grep, Glob, Write",
    "runbook-author": "Read, Grep, Glob, Write",
    "safety-reviewer": "Read, Grep, Glob",
    "verifier": "Read, Grep, Glob, Bash",
}
SKILLS = ("blocker-catalog", "change", "change-intake", "readonly-probes", "tiering")
FIXTURE_HOOK = (
    '"""Test fixture stand-in for a hook entry owned by another stage. Blocks if run."""\n'
    "import sys\n\n"
    'sys.stderr.write("fixture hook entry, not the real hook\\n")\n'
    "raise SystemExit(2)\n"
)
CLAUDE_TEMPLATE = (
    "## Change control for $org_name\n\n"
    "Approvals expire after $approval_ttl_hours hours. Mode: $permission_mode. Cost: $$0.\n"
)
SEP = "\n[[module]]\n"


def agent_text(name: str, tools: str | None) -> str:
    line = "" if tools is None else f"tools: {tools}\n"
    return f"---\nname: {name}\ndescription: Fixture agent.\n{line}---\nFixture body.\n"


def build_source(dest: Path) -> Path:
    """A controlled source tree: real repo inputs + fixture stand-ins (see module doc)."""

    def copy(rel: str) -> None:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)

    for rel in (
        "rules/modules.toml",
        "src/cab_of_one/__init__.py",
        "src/cab_of_one/setup/__init__.py",  # pinned for the ConfigChange manifest check
        "src/cab_of_one/setup/manifest.py",
        "templates/core/hooks/guard.py",
        "templates/handoff/HANDOFF.md",
        "templates/handoff/PROGRESS.md",
        "docs/identity.md",  # S12 docs: identity guide and evidence READMEs (rules map them)
        "changes/README.md",
        "audit/README.md",
        "simtenant/simtenant.py",
        "simtenant/seed/contoso.json",
    ):
        copy(rel)
    shutil.copytree(
        ROOT / "src/cab_of_one/runtime",
        dest / "src/cab_of_one/runtime",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    hooks = dest / "templates/core/hooks"
    for name in ("audit.py", "closeout.py", "config_lock.py", "cab"):
        (hooks / name).write_text(FIXTURE_HOOK)
    agents = dest / "templates/core/agents"
    agents.mkdir(parents=True)
    for name, tools in AGENTS.items():
        (agents / f"{name}.md").write_text(agent_text(name, tools))
    (agents / ".DS_Store").write_bytes(b"\x00junk")
    (agents / "__pycache__").mkdir()
    (agents / "__pycache__" / "x.pyc").write_bytes(b"junk")
    for name in SKILLS:
        folder = dest / "templates/core/skills" / name
        folder.mkdir(parents=True)
        (folder / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Fixture skill.\n---\nCopied verbatim: $ARGUMENTS\n"
        )
    (dest / "templates/core/CLAUDE.md").write_text(CLAUDE_TEMPLATE)
    return dest


def snapshot(folder: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            rel = str(path.relative_to(folder))
            if path.is_symlink():
                out[rel] = ("link", os.readlink(path))
            elif path.is_dir():
                out[rel] = ("dir",)
            else:
                st = path.stat()
                out[rel] = ("file", path.read_bytes(), st.st_mtime_ns, st.st_mode)
    return out


def rules_text(source: Path) -> str:
    return (source / "rules/modules.toml").read_text()


def without_module(text: str, module_id: str) -> bytes:
    head, *blocks = text.split(SEP)
    kept = [b for b in blocks if not b.startswith(f'id = "{module_id}"\n')]
    assert len(kept) == len(blocks) - 1, module_id
    return (head + "".join(SEP + b for b in kept)).encode()


class Case(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s8-render-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src = build_source(self.tmp / "source")
        self.solo = profile.load_reference_profile("contoso-solo", ROOT)

    def refused(self, code: str, *args: Any, **kwargs: Any) -> RenderError:
        with self.assertRaises(RenderError) as ctx:
            render.render_bundle(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code, str(ctx.exception))
        return ctx.exception


class DeterminismTests(Case):
    def test_g1_same_profile_same_bytes(self) -> None:
        a = render.render_bundle(self.solo, self.src)
        b = render.render_bundle(self.solo, self.src)
        other = render.render_bundle(self.solo, build_source(self.tmp / "source-2"))
        self.assertEqual(dict(a), dict(b))
        self.assertEqual(dict(a), dict(other))
        self.assertEqual(a.digest(), b.digest())
        self.assertEqual(a.digest(), other.digest())
        self.assertEqual(a.modules, other.modules)
        self.assertEqual(list(a), sorted(a))

    def test_g1_reloaded_profile_same_bytes(self) -> None:
        again = profile.load_reference_profile("contoso-solo", ROOT)
        self.assertEqual(
            render.render_bundle(self.solo, self.src).digest(),
            render.render_bundle(again, self.src).digest(),
        )

    def test_different_profile_different_bytes(self) -> None:
        manual = profile.load_profile(encode(user()))
        self.assertNotEqual(
            render.render_bundle(self.solo, self.src).digest(),
            render.render_bundle(manual, self.src).digest(),
        )

    def test_render_writes_nothing(self) -> None:
        before = snapshot(self.tmp)
        render.render_bundle(self.solo, self.src)
        render.render_bundle(profile.load_profile(encode(user())), self.src)
        self.assertEqual(before, snapshot(self.tmp))

    def test_lf_only_and_no_volatile_content(self) -> None:
        bundle = render.render_bundle(self.solo, self.src)
        generated = (render.SETTINGS_PATH, render.POLICY_PATH, render.CATALOG_PATH, "CLAUDE.md")
        for path in generated:
            data = bundle[path]
            self.assertNotIn(b"\r", data)
            self.assertTrue(data.endswith(b"\n"))
            for marker in (b"2026-", b"2027-", b"uuid", str(os.getpid()).encode() + b"\n"):
                self.assertNotIn(marker, data, path)
            self.assertNotIn(str(self.tmp).encode(), data, path)


class ContentTests(Case):
    def setUp(self) -> None:
        super().setUp()
        self.bundle = render.render_bundle(self.solo, self.src)

    def test_selected_modules_and_notices(self) -> None:
        self.assertEqual(
            self.bundle.modules,
            (
                "azure-cli",
                "bypass-guarded",
                "core",
                "graph-http",
                "handoff",
                "identity-admin",
                "m365-powershell",
                "read-deny",
                "simtenant-demo",
            ),
        )
        self.assertEqual(len(self.bundle.notices), 4)
        self.assertEqual(self.bundle.profile_sha256, self.solo.sha256)

    def test_files_and_ownership(self) -> None:
        for path in render.REQUIRED_FILES:
            self.assertIn(path, self.bundle)
        self.assertEqual(
            self.bundle[".claude/hooks/cab/guard.py"],
            (ROOT / "templates/core/hooks/guard.py").read_bytes(),
        )
        runtime = self.src / "src/cab_of_one/runtime"
        for path in runtime.rglob("*.py"):
            rel = path.relative_to(runtime).as_posix()
            self.assertEqual(
                self.bundle[".claude/hooks/cab/cab_of_one/runtime/" + rel], path.read_bytes()
            )
        self.assertNotIn(".claude/hooks/cab/cab_of_one/setup/profile.py", self.bundle)
        pinned = {p for p in self.bundle if p.startswith(".claude/hooks/cab/cab_of_one/setup/")}
        self.assertEqual(
            pinned,
            {
                ".claude/hooks/cab/cab_of_one/setup/__init__.py",
                ".claude/hooks/cab/cab_of_one/setup/manifest.py",
            },
        )
        for src, dst in render.PINNED_SETUP:
            self.assertEqual(self.bundle[dst], (ROOT / src).read_bytes())
        for path in self.bundle:
            self.assertNotIn("__pycache__", path)
            self.assertFalse(path.endswith((".pyc", ".DS_Store")), path)
        self.assertIn("simtenant/simtenant.py", self.bundle)
        kinds = {path: render.artifact_kind(path) for path in self.bundle}
        self.assertEqual(kinds[".claude/settings.json"], "settings-merge")
        self.assertEqual(kinds["CLAUDE.md"], "claude-md-block")
        self.assertEqual(kinds["policy/policy.toml"], "create-once")
        self.assertEqual(kinds["policy/standard-changes.toml"], "create-once")
        self.assertEqual(kinds[".claude/agents/safety-reviewer.md"], "generator-owned")
        self.assertEqual(kinds[".gitignore"], "gitignore-block")
        self.assertEqual(kinds["HANDOFF.md"], "create-once")
        self.assertEqual(kinds["PROGRESS.md"], "create-once")
        readmes = {"changes/README.md", "audit/README.md"}  # evidence READMEs only (S12)
        self.assertFalse(
            any(p.startswith((".cab/", "changes/", "audit/")) and p not in readmes
                for p in self.bundle)
        )  # fmt: skip

    def test_gitignore_block_protects_private_state(self) -> None:
        from cab_of_one.setup import merge

        data = self.bundle[".gitignore"]
        self.assertEqual(data, merge.make_gitignore_block() + b"\n")
        for pattern in merge.GITIGNORE_PATTERNS:
            self.assertIn(pattern.encode() + b"\n", data)

    def test_handoff_assets_follow_multi_machine(self) -> None:
        self.assertEqual(
            self.bundle["HANDOFF.md"], (ROOT / "templates/handoff/HANDOFF.md").read_bytes()
        )
        self.assertEqual(
            self.bundle["PROGRESS.md"], (ROOT / "templates/handoff/PROGRESS.md").read_bytes()
        )
        single = render.render_bundle(profile.load_profile(encode(user())), self.src)
        self.assertNotIn("HANDOFF.md", single)
        self.assertNotIn("PROGRESS.md", single)

    def test_settings_shape(self) -> None:
        raw = self.bundle[".claude/settings.json"]
        doc = json.loads(raw)
        self.assertEqual(
            raw, (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
        )
        self.assertIn(b'"python3 \\"$CLAUDE_PROJECT_DIR\\"/.claude/hooks/cab/guard.py"', raw)
        self.assertEqual(set(doc), {"hooks", "permissions"})
        deny = doc["permissions"]["deny"]
        self.assertEqual(deny[: len(render.FLOOR_DENY)], list(render.FLOOR_DENY))
        self.assertIn("Read(./secrets/**)", deny)
        self.assertIn("Bash(cab approve:*)", deny)
        self.assertIn("Write(./changes/*/review.json)", deny)
        self.assertNotIn("disableBypassPermissionsMode", doc["permissions"])
        self.assertNotIn("allow", doc["permissions"])
        expected_events = {event for event, *_ in render.HOOKS}
        self.assertEqual(set(doc["hooks"]), expected_events)
        prefix = 'python3 "$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/'
        for event, groups in doc["hooks"].items():
            for group in groups:
                for hook in group["hooks"]:
                    self.assertTrue(hook["command"].startswith(prefix), hook["command"])
                    entry = hook["command"][len(prefix) :].split(" ")[0]
                    self.assertIn(".claude/hooks/cab/" + entry, self.bundle)
                    closed = event in ("PreToolUse", "Stop", "ConfigChange")
                    self.assertEqual(hook.get("onFailure") == "block", closed, event)

    def test_evidence_readmes_and_identity_guide(self) -> None:
        # Final rules (t14p): core maps both evidence READMEs; the identity guide comes
        # only with the identity-admin module. Bytes are the S12 sources, unchanged.
        manual = render.render_bundle(profile.load_profile(encode(user())), self.src)
        for bundle in (self.bundle, manual):
            for rel in ("changes/README.md", "audit/README.md"):
                self.assertEqual(bundle[rel], (ROOT / rel).read_bytes(), rel)
                self.assertEqual(render.artifact_kind(rel), "create-once")
            has_guide = "docs/identity.md" in bundle
            self.assertEqual(has_guide, "identity-admin" in bundle.modules)
            if has_guide:
                guide = (ROOT / "docs/identity.md").read_bytes()
                self.assertEqual(bundle["docs/identity.md"], guide)
        self.assertIn("docs/identity.md", self.bundle)  # contoso-solo selects identity-admin
        self.assertEqual(render.artifact_kind("docs/identity.md"), "generator-owned")
        self.assertFalse(any(p.startswith(("changes/", "audit/")) and not p.endswith("README.md")
                             for p in self.bundle))  # fmt: skip

    def test_floor_is_the_pinned_lock_floor(self) -> None:
        # One definition: what render writes is what the installed ConfigChange lock checks.
        self.assertIs(render.FLOOR_DENY, config_lock.FLOOR_DENY)
        self.assertIs(render.HOOKS, config_lock.FLOOR_HOOKS)
        self.assertEqual(render.HOOK_DIR, config_lock.HOOK_DIR)
        self.assertIsNone(config_lock.floor_gap(json.loads(self.bundle[".claude/settings.json"])))
        self.assertEqual(
            self.bundle[".claude/hooks/cab/cab_of_one/runtime/config_lock.py"],
            (ROOT / "src/cab_of_one/runtime/config_lock.py").read_bytes(),
        )

    def test_policy_matches_runtime_schema(self) -> None:
        policy = schema.load_policy(self.bundle["policy/policy.toml"])
        self.assertEqual(
            policy.s3["adapters"]["enabled"],
            ["simtenant", "m365-powershell", "azure-cli", "graph-http"],
        )
        self.assertEqual(policy.ttl_hours, 4)
        self.assertEqual(policy.canary_tiers, frozenset({"critical"}))
        self.assertEqual(
            policy.s3["classifier"]["trusted_simtenant_scripts"], ["simtenant/simtenant.py"]
        )
        text = self.bundle["policy/policy.toml"].decode()
        self.assertIn("# - break-glass:", text)
        self.assertIn("# - executive-mailboxes:", text)
        self.assertEqual(schema.load_catalog(self.bundle["policy/standard-changes.toml"]), ())
        catalog = self.bundle["policy/standard-changes.toml"].decode()
        self.assertIn("# - forwarding-removal:", catalog)
        self.assertNotIn("entry", tomllib.loads(catalog))

    def test_claude_block_and_verbatim_copies(self) -> None:
        block = self.bundle["CLAUDE.md"].decode()
        self.assertTrue(block.startswith(render.BLOCK_BEGIN + "\n"))
        self.assertTrue(block.endswith(render.BLOCK_END + "\n"))
        self.assertIn("Change control for Contoso", block)
        self.assertIn("after 4 hours. Mode: bypass-guarded. Cost: $0.", block)
        skill = self.bundle[".claude/skills/change/SKILL.md"].decode()
        self.assertIn("$ARGUMENTS", skill)

    def test_manual_profile(self) -> None:
        bundle = render.render_bundle(profile.load_profile(encode(user())), self.src)
        doc = json.loads(bundle[".claude/settings.json"])
        self.assertEqual(doc["permissions"]["disableBypassPermissionsMode"], "disable")
        policy = schema.load_policy(bundle["policy/policy.toml"])
        self.assertEqual(policy.s3["adapters"]["enabled"], ["m365-powershell", "graph-http"])
        self.assertNotIn("classifier", policy.s3)
        self.assertFalse(any(p.startswith("simtenant/") for p in bundle))

    def test_session_profile_metadata(self) -> None:
        # contoso-solo: admin identity, bypass-guarded (DESIGN §10-4-3 fixture values)
        data = self.bundle[render.SESSION_PROFILE_PATH]
        self.assertEqual(data, b'{\n  "admin_identity": true,\n  "bypass_guarded": true\n}\n')
        self.assertEqual(render.artifact_kind(render.SESSION_PROFILE_PATH), "generator-owned")
        self.assertTrue(render.SESSION_PROFILE_PATH.startswith(render.HOOK_DIR))
        self.assertIn(render.SESSION_PROFILE_PATH, render.REQUIRED_FILES)
        for ident in ("read-only", "admin"):
            for mode in ("manual", "bypass-guarded", "auto"):
                with self.subTest(identity=ident, mode=mode):
                    p = profile.load_profile(encode(user(
                        identity__agent_identity=ident, session__permission_mode=mode,
                    )))  # fmt: skip
                    meta = render.render_bundle(p, self.src)[render.SESSION_PROFILE_PATH]
                    self.assertEqual(
                        json.loads(meta),
                        {"admin_identity": ident == "admin",
                         "bypass_guarded": mode == "bypass-guarded"},
                    )  # fmt: skip
                    self.assertEqual(set(json.loads(meta)), {"admin_identity", "bypass_guarded"})

    def test_mcp_write_servers(self) -> None:
        p = profile.load_profile(encode(user(surfaces__mcp_write_servers=["contosoadmin"])))
        policy = schema.load_policy(render.render_bundle(p, self.src)["policy/policy.toml"])
        self.assertEqual(policy.s3["surfaces"]["mcp_write_servers"], ["contosoadmin"])


class FloorInvariantTests(Case):
    """G9: every combination renders the whole floor. Not acceptance of real templates."""

    SYSTEMS = (
        {"entra": True},
        {"exchange_online": True},
        {"intune": True},
        {"sharepoint_teams": True},
        {"azure": True},
        {"entra": True, "exchange_online": True, "intune": True, "azure": True},
    )

    def profiles(self) -> list[profile.Profile]:
        out = []
        product = itertools.product(
            self.SYSTEMS,
            (False, True),  # MCP write server
            ("read-only", "admin"),
            ((), ("./secrets/**", "./.env")),
            ("manual", "bypass-guarded", "auto"),
            (False, True),  # git/multi-machine/sync flags flipped together
        )
        for systems, mcp, ident, paths, mode, flags in product:
            doc = user(
                identity__agent_identity=ident,
                identity__deny_read_paths=list(paths),
                session__permission_mode=mode,
                session__git=not flags,
                session__multi_machine=flags,
                session__sync_folder=flags,
                surfaces__powershell_modules=[],
                surfaces__graph_http=False,
                surfaces__mcp_write_servers=["contosoadmin"] if mcp else [],
                changes__routine=["leaver-block-signin"] if flags else [],
            )
            doc["systems"] = {key: False for key in doc["systems"]}
            doc["systems"].update(systems)
            out.append(profile.load_profile(encode(doc)))
        return out

    def test_g9_floor_in_every_combination(self) -> None:
        loaded = rules.load_rules(self.src / "rules/modules.toml")
        combos = self.profiles()
        self.assertGreaterEqual(len(combos), 200)
        for p in combos:
            bundle = render.render_bundle(p, self.src, rules=loaded)
            render.verify_floor(bundle)
            self.assertIn("core", bundle.modules)
            self.assertNotIn("simtenant-demo", bundle.modules)
            tools = render.agent_tools(bundle[".claude/agents/safety-reviewer.md"])
            self.assertEqual(sorted(tools), ["Glob", "Grep", "Read"])
            settings = json.loads(bundle[".claude/settings.json"])
            self.assertTrue(set(render.FLOOR_DENY) <= set(settings["permissions"]["deny"]))
            self.assertIsNone(config_lock.floor_gap(settings))
            for _src, dst in render.PINNED_SETUP:
                self.assertIn(dst, bundle)
            pre = settings["hooks"]["PreToolUse"][0]["hooks"][0]
            stop = settings["hooks"]["Stop"][0]["hooks"][0]
            self.assertEqual((pre["onFailure"], stop["onFailure"]), ("block", "block"))
            bypass_off = settings["permissions"].get("disableBypassPermissionsMode")
            self.assertEqual(bypass_off == "disable", p["session.permission_mode"] == "manual")
            meta = json.loads(bundle[render.SESSION_PROFILE_PATH])
            self.assertEqual(
                meta,
                {
                    "admin_identity": p["identity.agent_identity"] == "admin",
                    "bypass_guarded": p["session.permission_mode"] == "bypass-guarded",
                },
            )
            policy = schema.load_policy(bundle["policy/policy.toml"])
            self.assertIn("critical", policy.canary_tiers)
            self.assertNotIn("simtenant", policy.s3["adapters"]["enabled"])


class RefusalTests(Case):
    def write(self, rel: str, text: str | bytes) -> None:
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text)

    def test_blocked_profile_values_are_refused_not_dropped(self) -> None:
        named = profile.load_profile(encode(user(approval__approvers="named")))
        self.refused("blocked_named_approvers", named, self.src)
        jira = profile.load_profile(encode(user(session__ticketing="jira")))
        self.refused("blocked_ticketing", jira, self.src)

    def test_hand_built_demo_profile(self) -> None:
        values = dict(profile.load_profile(encode(user())).values)
        values["systems.demo_simtenant"] = True
        with self.assertRaises(ProfileError) as ctx:
            render.render_bundle(profile.Profile(values, None), self.src)
        self.assertEqual(ctx.exception.code, "demo_requires_reference")

    def test_missing_hook_entries_are_refused_not_stubbed(self) -> None:
        for name in ("audit.py", "closeout.py", "config_lock.py", "cab"):
            path = self.src / "templates/core/hooks" / name
            saved = path.read_bytes()
            path.unlink()
            err = self.refused("floor_missing", self.solo, self.src)
            self.assertEqual(err.detail, ".claude/hooks/cab/" + name)
            path.write_bytes(saved)

    def test_missing_template_folders(self) -> None:
        shutil.rmtree(self.src / "templates/core/agents")
        err = self.refused("source_missing", self.solo, self.src)
        self.assertEqual(err.detail, "templates/core/agents/")

    def test_missing_agent_or_skill(self) -> None:
        (self.src / "templates/core/agents/verifier.md").unlink()
        self.refused("floor_missing", self.solo, self.src)
        self.write("templates/core/agents/verifier.md", agent_text("verifier", AGENTS["verifier"]))
        (self.src / "templates/core/skills/tiering/SKILL.md").unlink()
        self.refused("floor_missing", self.solo, self.src)

    def test_agent_tool_limits(self) -> None:
        rel = "templates/core/agents/{}.md"
        cases = [
            ("safety-reviewer", "Read, Grep, Glob, Bash", "floor_agent_tools"),
            ("safety-reviewer", "Read, Grep", "floor_agent_tools"),
            ("safety-reviewer", "Read, Grep, Glob, Edit", "floor_agent_tools"),
            ("verifier", "Read, Grep, Glob, Bash, Write", "floor_agent_tools"),
            ("impact-analyst", "Read, Grep, Glob, Bash, Edit", "floor_agent_tools"),
            ("recorder", None, "agent_tools_missing"),
            ("recorder", "", "agent_tools_missing"),
        ]
        for name, tools, code in cases:
            self.write(rel.format(name), agent_text(name, tools))
            self.refused(code, self.solo, self.src)
            self.write(rel.format(name), agent_text(name, AGENTS[name]))
        self.write(rel.format("helper"), agent_text("helper", "Read, Bash"))
        self.refused("floor_agent_tools", self.solo, self.src)
        self.write(rel.format("helper"), agent_text("helper", None))
        self.refused("agent_tools_missing", self.solo, self.src)
        self.write(rel.format("helper"), agent_text("helper", "Read, Grep"))
        render.render_bundle(self.solo, self.src)
        listed = "---\nname: safety-reviewer\ntools:\n  - Read\n  - Grep\n  - Glob\n---\nBody\n"
        self.write(rel.format("safety-reviewer"), listed)
        bundle = render.render_bundle(self.solo, self.src)
        tools = render.agent_tools(bundle[".claude/agents/safety-reviewer.md"])
        self.assertEqual(tools, ("Read", "Grep", "Glob"))
        dup = "---\ntools: Read\ntools: Read, Grep, Glob\n---\n"
        self.write(rel.format("safety-reviewer"), dup)
        self.refused("agent_tools_duplicate", self.solo, self.src)
        self.write(rel.format("safety-reviewer"), "no front matter\ntools: Read, Grep, Glob\n")
        self.refused("agent_frontmatter", self.solo, self.src)

    def test_templates(self) -> None:
        self.write("templates/core/CLAUDE.md", "Hello $unknown_variable\n")
        self.refused("template_variable", self.solo, self.src)
        self.write("templates/core/CLAUDE.md", "Stray $ sign\n")
        self.refused("template_variable", self.solo, self.src)
        self.write("templates/core/CLAUDE.md", "x\n" + render.BLOCK_END + "\n")
        self.refused("block_marker", self.solo, self.src)
        self.write("templates/core/CLAUDE.md", b"\xff\xfe")
        self.refused("template_encoding", self.solo, self.src)
        self.write("templates/core/CLAUDE.md", CLAUDE_TEMPLATE)
        self.write("templates/core/skills/change/SKILL.md", b"---\r\nname: change\r\n---\r\n")
        self.refused("not_lf", self.solo, self.src)
        self.write("templates/core/skills/change/SKILL.md", "Run ${CLAUDE_PLUGIN_ROOT}/x\n")
        err = self.refused("plugin_root_reference", self.solo, self.src)
        self.assertEqual(err.detail, ".claude/skills/change/SKILL.md")

    def test_unsafe_source_entries(self) -> None:
        outside = self.tmp / "outside.md"
        outside.write_text("outside the source tree\n")
        link = self.src / "templates/core/skills/change/linked.md"
        os.symlink(outside, link)
        self.refused("source_symlink", self.solo, self.src)
        link.unlink()
        self.write("templates/core/skills/change/bad name.md", "x\n")
        self.refused("source_name", self.solo, self.src)
        (self.src / "templates/core/skills/change/bad name.md").unlink()
        real_claude = self.src / "templates/core/CLAUDE.md"
        real_claude.rename(self.tmp / "CLAUDE.md")
        os.symlink(self.tmp / "CLAUDE.md", real_claude)
        self.refused("source_symlink", self.solo, self.src)
        real_claude.unlink()
        shutil.move(self.src / "templates/core", self.tmp / "core")
        os.symlink(self.tmp / "core", self.src / "templates/core")
        self.refused("source_symlink", self.solo, self.src)
        link_root = self.tmp / "source-link"
        os.symlink(self.src, link_root)
        self.refused("source_root", self.solo, link_root)

    def test_rules_drift_is_refused(self) -> None:
        text = rules_text(self.src)
        manual = profile.load_profile(encode(user()))
        for module_id, code, p in (
            ("read-deny", "rules_missing_feature", self.solo),
            ("bypass-lock", "rules_missing_feature", manual),
            ("simtenant-demo", "rules_missing_feature", self.solo),
            ("azure-cli", "rules_missing_adapter", self.solo),
            ("graph-http", "rules_missing_adapter", manual),
        ):
            changed = rules.load_rules(without_module(text, module_id))
            self.refused(code, p, self.src, rules=changed)
        widened = text.replace(
            'when_any = ["systems.demo_simtenant"]', 'when_any = ["systems.entra"]'
        )
        self.assertNotEqual(widened, text)
        loaded = rules.load_rules(widened.encode())
        self.refused("demo_not_requested", manual, self.src, rules=loaded)

    def test_module_outputs_cannot_collide_or_shadow_generated_files(self) -> None:
        extra = (
            '\n[[module]]\nid = "zz-extra"\nwhen_any = ["systems.entra"]\n'
            'files = [{ src = "extra/", dst = ".claude/" }]\n'
        )
        loaded = rules.load_rules((rules_text(self.src) + extra).encode())
        manual = profile.load_profile(encode(user()))
        self.write("extra/settings.json", "{}\n")
        self.refused("reserved_output", manual, self.src, rules=loaded)
        (self.src / "extra/settings.json").unlink()
        self.write("extra/agents/safety-reviewer.md", agent_text("safety-reviewer", "Read"))
        self.refused("output_conflict", manual, self.src, rules=loaded)

    def test_session_profile_is_generated_not_mapped(self) -> None:
        extra = (
            '\n[[module]]\nid = "zz-extra"\nwhen_any = ["systems.entra"]\n'
            'files = [{ src = "extra/session-profile.json", '
            'dst = ".claude/hooks/cab/session-profile.json" }]\n'
        )
        loaded = rules.load_rules((rules_text(self.src) + extra).encode())
        manual = profile.load_profile(encode(user()))
        self.write("extra/session-profile.json", '{"admin_identity": false}\n')
        err = self.refused("reserved_output", manual, self.src, rules=loaded)
        self.assertEqual(err.detail, render.SESSION_PROFILE_PATH)

    def test_pinned_setup_is_reserved_and_required(self) -> None:
        extra = (
            '\n[[module]]\nid = "zz-extra"\nwhen_any = ["systems.entra"]\n'
            'files = [{ src = "extra/", dst = ".claude/hooks/cab/cab_of_one/setup/" }]\n'
        )
        loaded = rules.load_rules((rules_text(self.src) + extra).encode())
        manual = profile.load_profile(encode(user()))
        self.write("extra/profile.py", "# not pinned\n")
        err = self.refused("reserved_output", manual, self.src, rules=loaded)
        self.assertEqual(err.detail, ".claude/hooks/cab/cab_of_one/setup/profile.py")
        source = self.src / "src/cab_of_one/setup/manifest.py"
        saved = source.read_bytes()
        source.unlink()
        err = self.refused("source_missing", self.solo, self.src)
        self.assertEqual(err.detail, "src/cab_of_one/setup/manifest.py")
        source.write_bytes(saved)
        render.render_bundle(self.solo, self.src)


class VerifyFloorTests(Case):
    def setUp(self) -> None:
        super().setUp()
        self.files = dict(render.render_bundle(self.solo, self.src))

    def mutate_settings(self, change: Any) -> None:
        doc = json.loads(self.files[render.SETTINGS_PATH])
        change(doc)
        self.files[render.SETTINGS_PATH] = (json.dumps(doc) + "\n").encode()

    def expect(self, code: str) -> None:
        with self.assertRaises(RenderError) as ctx:
            render.verify_floor(self.files)
        self.assertEqual(ctx.exception.code, code)

    def test_intact(self) -> None:
        render.verify_floor(self.files)

    def test_deny_rule_removed(self) -> None:
        self.mutate_settings(lambda d: d["permissions"]["deny"].remove("Bash(cab approve:*)"))
        self.expect("floor_settings")

    def test_fail_closed_removed(self) -> None:
        self.mutate_settings(lambda d: d["hooks"]["Stop"][0]["hooks"][0].pop("onFailure"))
        self.expect("floor_hook")

    def test_hook_event_removed(self) -> None:
        self.mutate_settings(lambda d: d["hooks"].pop("ConfigChange"))
        self.expect("floor_hook")

    def test_disable_all_hooks(self) -> None:
        self.mutate_settings(lambda d: d.__setitem__("disableAllHooks", True))
        self.expect("floor_settings")

    def test_policy_weakened(self) -> None:
        text = self.files[render.POLICY_PATH].decode()
        self.files[render.POLICY_PATH] = text.replace(
            'canary_tiers = ["critical"]', 'canary_tiers = ["normal"]'
        ).encode()
        self.expect("floor_policy")

    def test_enabled_standard_change(self) -> None:
        self.files[render.CATALOG_PATH] += (
            b'\n[[entry]]\nid = "contoso-x"\nenabled = true\nadapter = "simtenant"\n'
            b'command_pattern = "simtenant set users *"\ntarget_scope = ["users/u-1007"]\n'
            b'state_scope = "tenant/state.json"\n'
        )
        self.expect("floor_catalog")

    def test_block_markers(self) -> None:
        self.files["CLAUDE.md"] = b"no markers\n"
        self.expect("floor_block")

    def test_pinned_setup_is_floor(self) -> None:
        saved = self.files.pop(".claude/hooks/cab/cab_of_one/setup/manifest.py")
        self.expect("floor_missing")
        self.files[".claude/hooks/cab/cab_of_one/setup/manifest.py"] = saved
        self.files[".claude/hooks/cab/cab_of_one/setup/profile.py"] = b"# not pinned\n"
        self.expect("floor_pinned_setup")

    def test_hook_group_with_bad_hooks_value(self) -> None:
        self.mutate_settings(lambda d: d["hooks"]["Stop"][0].__setitem__("hooks", 5))
        self.expect("floor_hook")

    def test_session_profile_is_floor(self) -> None:
        path = render.SESSION_PROFILE_PATH
        saved = self.files.pop(path)
        self.expect("floor_missing")
        for bad in (
            b"{}\n",
            saved.replace(b"true", b"1"),
            saved.replace(b"true", b'"true"'),
            b'{"admin_identity":true,"bypass_guarded":true}\n',  # not the canonical bytes
            saved.rstrip(b"\n"),
            saved[:-2] + b',\n  "org": "Contoso"\n}\n',  # an extra (profile string) key
        ):
            with self.subTest(bad=bad):
                self.files[path] = bad
                self.expect("floor_session_profile")
        self.files[path] = saved
        render.verify_floor(self.files)
        # settings that disable bypass mode contradict a bypass-guarded claim
        self.mutate_settings(
            lambda d: d["permissions"].__setitem__("disableBypassPermissionsMode", "disable")
        )
        self.expect("floor_session_profile")

    def test_gitignore_block_is_floor(self) -> None:
        saved = self.files.pop(".gitignore")
        self.expect("floor_missing")
        self.files[".gitignore"] = saved.replace(b".cab/state/\n", b"")
        self.expect("floor_gitignore")


class StageTests(Case):
    def setUp(self) -> None:
        super().setUp()
        self.bundle = render.render_bundle(self.solo, self.src)
        self.project = self.tmp / "project"
        self.project.mkdir()
        (self.project / "notes.md").write_text("a person's file\n")

    def test_stage_writes_only_the_staged_tree(self) -> None:
        before = snapshot(self.project)
        staged = render.stage_bundle(self.bundle, self.project)
        self.assertEqual(staged, str(self.project / ".cab/setup/staged"))
        after = snapshot(self.project)
        added = set(after) - set(before)
        for rel in added:
            self.assertTrue(rel == ".cab" or rel.startswith(".cab/setup"), rel)
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)
        for path, data in self.bundle.items():
            self.assertEqual((Path(staged) / path).read_bytes(), data)
        self.assertFalse((self.project / ".cab/setup/staged.partial").exists())

    def test_refusals(self) -> None:
        render.stage_bundle(self.bundle, self.project)
        with self.assertRaises(RenderError) as ctx:
            render.stage_bundle(self.bundle, self.project)
        self.assertEqual(ctx.exception.code, "staged_exists")
        with self.assertRaises(RenderError) as ctx:
            render.stage_bundle(dict(self.bundle), self.project)  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, "not_bundle")
        with self.assertRaises(RenderError) as ctx:
            render.stage_bundle(self.bundle, "relative/project")
        self.assertEqual(ctx.exception.code, "project_root")
        other = self.tmp / "other"
        other.mkdir()
        (self.tmp / "elsewhere").mkdir()
        os.symlink(self.tmp / "elsewhere", other / ".cab")
        with self.assertRaises(RenderError) as ctx:
            render.stage_bundle(self.bundle, other)
        self.assertEqual(ctx.exception.code, "stage_unsafe")
        self.assertEqual(list((self.tmp / "elsewhere").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
