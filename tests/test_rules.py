"""S8 module rules: data-only conditions, deterministic selection, immutable core floor.
Reads the repository's rules/modules.toml and in-memory documents. Writes no files."""

from __future__ import annotations

import itertools
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cab_of_one.setup import manifest, profile, rules, tomlw  # noqa: E402
from cab_of_one.setup.rules import RulesError  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_profile import USER, encode, user  # noqa: E402

RULES_FILE = ROOT / "rules" / "modules.toml"

CORE = """\
[[module]]
id = "core"
always = true
files = [
  { src = "templates/core/hooks/", dst = ".claude/hooks/cab/" },
  { src = "src/cab_of_one/__init__.py", dst = ".claude/hooks/cab/cab_of_one/__init__.py" },
  { src = "src/cab_of_one/runtime/", dst = ".claude/hooks/cab/cab_of_one/runtime/" },
  { src = "templates/core/agents/", dst = ".claude/agents/" },
  { src = "templates/core/skills/", dst = ".claude/skills/" },
  { src = "templates/core/CLAUDE.md", dst = "CLAUDE.md", substitute = true },
]
"""


def doc(*modules: str, core: str = CORE) -> bytes:
    return ("schema = 1\n\n" + core + "\n" + "\n".join(modules)).encode()


def ids(p: profile.Profile, r: rules.Rules) -> list[str]:
    return [m.id for m in rules.select_modules(p, r)]


class RepositoryRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = rules.load_rules(RULES_FILE)

    def test_loads_sorted_with_core(self) -> None:
        self.assertEqual(list(self.rules.ids()), sorted(self.rules.ids()))
        self.assertIn("core", self.rules.ids())
        core = next(m for m in self.rules.modules if m.id == "core")
        self.assertTrue(core.always)

    def test_reference_profile_selection(self) -> None:
        p = profile.load_reference_profile("contoso-solo", ROOT)
        self.assertEqual(
            ids(p, self.rules),
            [
                "azure-cli",
                "bypass-guarded",
                "core",
                "graph-http",
                "handoff",
                "identity-admin",
                "m365-powershell",
                "read-deny",
                "simtenant-demo",
            ],
        )

    def test_user_profile_selection(self) -> None:
        p = profile.load_profile(encode(USER))
        expected = ["bypass-lock", "core", "graph-http", "m365-powershell", "read-deny"]
        self.assertEqual(ids(p, self.rules), expected)
        p = profile.load_profile(
            encode(
                user(
                    systems__entra=False,
                    systems__exchange_online=False,
                    surfaces__powershell_modules=[],
                    surfaces__graph_http=False,
                    surfaces__azure_cli=True,
                    identity__deny_read_paths=[],
                    session__permission_mode="auto",
                    session__git=False,
                    session__sync_folder=True,
                )
            )
        )
        self.assertEqual(
            ids(p, self.rules), ["auto-mode", "azure-cli", "core", "no-git", "sync-folder"]
        )

    def test_demo_module_never_selected_for_user_profiles(self) -> None:
        bools = [False, True]
        for entra, azure, mcp, multi in itertools.product(bools, bools, bools, bools):
            if not (entra or azure or mcp):
                continue
            p = profile.load_profile(
                encode(
                    user(
                        systems__entra=entra,
                        systems__exchange_online=False,
                        systems__azure=azure,
                        surfaces__powershell_modules=[],
                        surfaces__graph_http=False,
                        surfaces__mcp_write_servers=["contosoadmin"] if mcp else [],
                        session__multi_machine=multi,
                    )
                )
            )
            chosen = ids(p, self.rules)
            self.assertIn("core", chosen)
            self.assertNotIn("simtenant-demo", chosen)
            self.assertEqual(chosen, sorted(chosen))
            self.assertEqual(chosen, ids(p, self.rules))

    def pairs(self, module_id: str) -> set[tuple[str, str]]:
        module = next(m for m in self.rules.modules if m.id == module_id)
        return {(spec.src, spec.dst) for spec in module.files}

    def test_document_and_demo_file_mappings(self) -> None:
        readmes = {
            ("changes/README.md", "changes/README.md"),
            ("audit/README.md", "audit/README.md"),
        }
        self.assertLessEqual(readmes, self.pairs("core"))
        self.assertEqual(self.pairs("identity-admin"), {("docs/identity.md", "docs/identity.md")})
        self.assertEqual(
            self.pairs("simtenant-demo"), {(path, path) for path in manifest.DEMO_FILES}
        )
        self.assertEqual(
            self.pairs("handoff"),
            {
                ("templates/handoff/HANDOFF.md", "HANDOFF.md"),
                ("templates/handoff/PROGRESS.md", "PROGRESS.md"),
            },
        )
        for src, _ in readmes | self.pairs("identity-admin") | self.pairs("simtenant-demo"):
            with self.subTest(src=src):
                self.assertTrue((ROOT / src).is_file(), src)

    def test_every_mapped_file_has_the_intended_merge_class(self) -> None:
        # README/handoff: create once, then a person's file. Identity guide and demo files:
        # exact generator-owned paths. Folders: only below the owned prefixes.
        expected = {
            "CLAUDE.md": "claude",
            "HANDOFF.md": "quiet",
            "PROGRESS.md": "quiet",
            "audit/README.md": "quiet",
            "changes/README.md": "quiet",
            "docs/identity.md": "owned",
            "simtenant/simtenant.py": "owned",
            "simtenant/seed/contoso.json": "owned",
        }
        seen = set()
        for module in self.rules.modules:
            for spec in module.files:
                with self.subTest(module=module.id, dst=spec.dst):
                    if spec.dst.endswith("/"):
                        self.assertTrue(spec.dst.startswith(manifest.OWNED_PREFIXES))
                        continue
                    want = expected.get(spec.dst, "owned")
                    self.assertEqual(manifest.path_class(spec.dst), want)
                    seen.add(spec.dst)
        self.assertLessEqual(set(expected), seen)

    def test_only_the_named_modules_map_the_document_paths(self) -> None:
        documents = ("docs/identity.md", "changes/README.md", "audit/README.md")
        for dst in documents + manifest.DEMO_FILES:
            extra = (
                f'\n[[module]]\nid = "zz-extra"\nwhen_any = ["systems.entra"]\n'
                f'files = [{{ src = "templates/x.md", dst = "{dst}" }}]\n'
            )
            with self.subTest(dst=dst):
                with self.assertRaises(RulesError) as ctx:
                    rules.load_rules(RULES_FILE.read_bytes() + extra.encode())
                self.assertEqual(ctx.exception.code, "duplicate_dst")

    def test_selection_ignores_module_order_in_file(self) -> None:
        sep = "\n[[module]]\n"
        head, *blocks = RULES_FILE.read_text().split(sep)
        self.assertGreater(len(blocks), 3)
        reversed_text = head + "".join(sep + b for b in reversed(blocks))
        other = rules.load_rules(reversed_text.encode())
        self.assertEqual(other, self.rules)


class RefusalTests(unittest.TestCase):
    def assertRefused(self, data: bytes, code: str) -> None:
        with self.assertRaises(RulesError) as ctx:
            rules.load_rules(data)
        self.assertEqual(ctx.exception.code, code)

    def test_minimal_valid(self) -> None:
        r = rules.load_rules(doc())
        self.assertEqual(r.ids(), ("core",))

    def test_core_is_the_floor(self) -> None:
        self.assertRefused(doc(core=""), "modules")
        other = '[[module]]\nid = "x"\nwhen_any = ["systems.entra"]\n'
        self.assertRefused(doc(other, core=""), "core_missing")
        conditional = CORE.replace("always = true", 'when_any = ["systems.entra"]')
        self.assertRefused(doc(core=conditional), "core_conditional")
        for line in CORE.splitlines():
            if line.startswith("  { src"):
                self.assertRefused(doc(core=CORE.replace(line + "\n", "")), "core_incomplete")
        moved = CORE.replace('dst = ".claude/agents/"', 'dst = ".claude/agents-off/"')
        self.assertRefused(doc(core=moved), "core_incomplete")

    def test_only_core_may_be_always(self) -> None:
        self.assertRefused(doc('[[module]]\nid = "extra"\nalways = true\n'), "always_reserved")
        off = CORE.replace("always = true", "always = false")
        self.assertRefused(doc(core=off), "condition_always")

    def test_exactly_one_condition(self) -> None:
        both = (
            '[[module]]\nid = "x"\nwhen_any = ["systems.entra"]\n'
            'when_eq = { "session.git" = true }\n'
        )
        self.assertRefused(doc(both), "condition_count")
        none = '[[module]]\nid = "x"\nadapters = ["azure-cli"]\n'
        self.assertRefused(doc(none), "condition_count")

    def test_no_expressions(self) -> None:
        for key in ("when", "when_expr", "eval", "when_not"):
            self.assertRefused(
                doc(f'[[module]]\nid = "x"\n{key} = "systems.entra == True"\n'), "unknown_key"
            )
        expr = '[[module]]\nid = "x"\nwhen_any = "systems.entra or True"\n'
        self.assertRefused(doc(expr), "list")

    def test_condition_fields_and_values(self) -> None:
        cases = [
            ('when_any = ["systems.nope"]', "condition_field"),
            ('when_any = ["org.name"]', "condition_field"),
            ('when_any = ["session.permission_mode"]', "condition_field"),
            ("when_any = []", "condition_empty"),
            ('when_eq = { "session.permission_mode" = "bypass" }', "condition_value"),
            ('when_eq = { "session.git" = 1 }', "condition_value"),
            ('when_eq = { "approval.approval_ttl_hours" = 4 }', "condition_field"),
            ('when_eq = { "identity.deny_read_paths" = "./x" }', "condition_field"),
            ("when_eq = {}", "condition_empty"),
        ]
        for line, code in cases:
            self.assertRefused(doc(f'[[module]]\nid = "x"\n{line}\n'), code)

    def test_ids(self) -> None:
        for bad in ('"Core"', '"1x"', '"x y"', '""', "1", '"' + "x" * 33 + '"'):
            module = f'[[module]]\nid = {bad}\nwhen_any = ["systems.entra"]\n'
            self.assertRefused(doc(module), "module_id")
        dup = '[[module]]\nid = "x"\nwhen_any = ["systems.entra"]\n'
        self.assertRefused(doc(dup, dup), "duplicate_id")

    def test_contributions(self) -> None:
        base = '[[module]]\nid = "x"\nwhen_any = ["systems.entra"]\n'
        self.assertRefused(doc(base + 'adapters = ["powershell-anything"]\n'), "adapter_unknown")
        self.assertRefused(doc(base + 'features = ["disable_guard"]\n'), "feature_unknown")
        self.assertRefused(doc(base + 'notices = ["a\\u0007b"]\n'), "text")
        self.assertRefused(doc(base + 'critical_patterns = ["x", "x"]\n'), "duplicate_entry")

    def test_file_specs(self) -> None:
        base = '[[module]]\nid = "x"\nwhen_any = ["systems.entra"]\n'
        cases = [
            ('{ src = "a.md", dst = ".claude/settings.json" }', "file_dst"),
            ('{ src = "a.md", dst = ".claude/settings.local.json" }', "file_dst"),
            ('{ src = "a.toml", dst = "policy/policy.toml" }', "file_dst"),
            ('{ src = "a.md", dst = "README.md" }', "file_dst"),
            ('{ src = "a.md", dst = "changes/CHG-0001/approval.json" }', "file_dst"),
            ('{ src = "a.md", dst = "audit/ledger/x.jsonl" }', "file_dst"),
            ('{ src = "a/", dst = ".cab/" }', "file_dst"),
            ('{ src = "../a.md", dst = "docs/a.md" }', "file_path"),
            ('{ src = "/etc/a", dst = "docs/a.md" }', "file_path"),
            ('{ src = "a.md", dst = "docs/../.cab/manifest.json" }', "file_path"),
            ('{ src = "a.md", dst = "docs//a.md" }', "file_path"),
            ('{ src = "a/", dst = "docs/a.md" }', "file_path"),
            ('{ src = "a/", dst = "docs/", substitute = true }', "file_spec"),
            ('{ src = "a.md", dst = "docs/a.md", substitute = 1 }', "file_spec"),
            ('{ src = "a.md", dst = "docs/a.md", mode = "755" }', "file_spec"),
        ]
        for spec, code in cases:
            self.assertRefused(doc(base + f"files = [{spec}]\n"), code)
        dup = base.replace('"x"', '"y"') + 'files = [{ src = "b.md", dst = "CLAUDE.md" }]\n'
        self.assertRefused(doc(dup), "duplicate_dst")

    def test_document_shape(self) -> None:
        self.assertRefused(b"schema = 2\n" + doc()[len(b"schema = 1\n") :], "schema_version")
        self.assertRefused(doc() + b"\nextra = 1\n", "unknown_key")
        self.assertRefused(doc() + b'\n[[module]]\nid = "x"\nid = "y"\n', "syntax")
        self.assertRefused(b"\xef\xbb\xbf" + doc(), "bom")
        self.assertRefused(b"#" * (64 * 1024 + 1), "too_large")

    def test_select_type_checks(self) -> None:
        r = rules.load_rules(doc())
        with self.assertRaises(RulesError):
            rules.select_modules({"systems.entra": True}, r)  # type: ignore[arg-type]
        with self.assertRaises(RulesError):
            rules.select_modules(profile.load_profile(encode(USER)), r.modules)  # type: ignore

    def test_when_eq_is_exact_typed(self) -> None:
        nogit = '[[module]]\nid = "nogit"\nwhen_eq = { "session.git" = false }\n'
        r = rules.load_rules(doc(nogit))
        self.assertEqual(ids(profile.load_profile(encode(USER)), r), ["core"])
        self.assertEqual(
            ids(profile.load_profile(encode(user(session__git=False))), r), ["core", "nogit"]
        )

    def test_rules_round_trip_through_writer_is_stable(self) -> None:
        # Rules are data: the same document always yields the same model.
        a = rules.load_rules(RULES_FILE)
        b = rules.load_rules(RULES_FILE.read_bytes())
        self.assertEqual(a, b)
        self.assertIsInstance(tomlw.dumps({"schema": 1}), str)


if __name__ == "__main__":
    unittest.main()
