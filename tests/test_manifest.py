"""Schema-1 manifest validation and conservative uninstall planning (G8). Pure, no files.

All data is fictional Contoso data.
"""

from __future__ import annotations

import copy
import json
import re
import unittest
from dataclasses import replace
from typing import Any

from cab_of_one.setup import merge
from cab_of_one.setup.manifest import (
    CREATE_ONCE,
    DEMO_FILES,
    OWNED_FILES,
    ClaudeBlockRecord,
    Manifest,
    ManifestError,
    SettingsContribution,
    SetupDataError,
    config_file_matches,
    dump_manifest,
    load_manifest,
    path_class,
    sha256_hex,
)
from cab_of_one.setup.merge import Issue, NodeKind

VERSION = "0.1.0.dev0"
PROFILE = sha256_hex(b"contoso-solo fixture profile")
GUARD = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/guard.py'
H = "a" * 64

SETTINGS = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"
CLAUDE = "CLAUDE.md"
AGENT = ".claude/agents/safety-reviewer.md"
SKILL = ".claude/skills/change/SKILL.md"
GUARD_FILE = ".claude/hooks/cab/guard.py"
POLICY = "policy/policy.toml"
GITIGNORE = ".gitignore"

OURS: dict[str, Any] = {
    "permissions": {
        "deny": ["Edit(.claude/**)", "Write(.claude/**)", "Bash(cab approve:*)"],
        "disableBypassPermissionsMode": "disable",
    },
    "hooks": {
        "PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": GUARD, "onFailure": "block"}]}
        ],
    },
}
USER: dict[str, Any] = {
    "model": "contoso-model-alias",
    "env": {"CONTOSO_REGION": "east"},
    "permissions": {"allow": ["Bash(git status)"], "deny": ["Read(./secrets/**)"]},
    "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "~/bin/contoso-notify.sh"}]}]},
    "contosoUnknownKey": [1, {"x": None}],
}
USER_BYTES = json.dumps(USER, indent=4).encode("utf-8")
LOCAL_BYTES = b'{"permissions": {"allow": ["Bash(make test)"]}}\n'
ORIGINAL_CLAUDE = "# Contoso operations\r\n\r\nNotes: café\r\nno final newline".encode()
BLOCK = merge.make_claude_block(b"## Contoso change control\n")
GI_BLOCK = merge.make_gitignore_block()
USER_GITIGNORE = b"# Contoso build output\n*.log\nsecrets/\n"


def make_bundle() -> dict[str, bytes]:
    return {
        SETTINGS: json.dumps(OURS).encode("utf-8"),
        CLAUDE: BLOCK,
        GITIGNORE: GI_BLOCK,
        AGENT: b"---\nname: safety-reviewer\ntools: Read, Grep, Glob\n---\n",
        SKILL: b"---\nname: change\n---\n",
        GUARD_FILE: b"# pinned guard (fixture)\n",
        POLICY: b"schema = 1\n",
        "policy/standard-changes.toml": b"# disabled proposals only\n",
        "changes/README.md": b"Change folders.\n",
        "audit/README.md": b"Ledger folder.\n",
    }


def install(existing: dict) -> tuple[dict, Manifest]:
    result = merge.plan_merge(
        make_bundle(), existing, manifest=None, generator_version=VERSION, profile_sha256=PROFILE
    )
    assert not result.blockers and not result.conflicts, (result.blockers, result.conflicts)
    tree = dict(existing)
    for action in result.actions:
        tree[action.path] = action.data
    return tree, result.manifest


def applied(tree: dict, result: Any) -> dict:
    out = dict(tree)
    for action in result.actions:
        if action.kind == "remove":
            del out[action.path]
        else:
            out[action.path] = action.data
    return out


def by_path(result: Any) -> dict[str, Any]:
    return {action.path: action for action in result.actions}


START = {
    SETTINGS: USER_BYTES,
    LOCAL: LOCAL_BYTES,
    CLAUDE: ORIGINAL_CLAUDE,
    GITIGNORE: USER_GITIGNORE,
}
_, BASE = install(START)


def as_obj() -> dict[str, Any]:
    return json.loads(dump_manifest(BASE))


def encoded(obj: Any) -> bytes:
    return json.dumps(obj).encode("utf-8")


class SchemaTests(unittest.TestCase):
    def test_round_trip_is_exact_and_deterministic(self) -> None:
        data = dump_manifest(BASE)
        self.assertEqual(load_manifest(data), BASE)
        self.assertEqual(dump_manifest(load_manifest(data)), data)
        self.assertTrue(data.endswith(b"}\n"))
        self.assertNotIn(b"\r", data)
        self.assertEqual(json.loads(data)["schema"], 1)

    def test_contents_record_ownership(self) -> None:
        self.assertEqual(set(BASE.files), {AGENT, SKILL, GUARD_FILE})
        self.assertEqual(BASE.files[GUARD_FILE], sha256_hex(make_bundle()[GUARD_FILE]))
        self.assertEqual(
            set(BASE.offered),
            {POLICY, "policy/standard-changes.toml", "changes/README.md", "audit/README.md"},
        )
        deny = tuple(OURS["permissions"]["deny"])
        self.assertEqual(BASE.settings.lists["permissions.deny"], deny)
        self.assertEqual(len(BASE.settings.hook_groups["PreToolUse"]), 1)
        self.assertEqual(
            BASE.settings.scalars, ((("permissions", "disableBypassPermissionsMode"), '"disable"'),)
        )
        self.assertEqual(BASE.settings.containers, (("hooks", "PreToolUse"),))
        self.assertEqual(BASE.claude_block.sha256, sha256_hex(BLOCK))
        gitignore = BASE.gitignore_block
        self.assertEqual(gitignore.sha256, sha256_hex(GI_BLOCK))
        self.assertEqual(
            (gitignore.lead, gitignore.trail, gitignore.file_created), ("\n", "\n", False)
        )
        self.assertNotIn(GITIGNORE, BASE.files)
        self.assertEqual(
            json.loads(dump_manifest(BASE))["gitignore_block"],
            {"sha256": sha256_hex(GI_BLOCK), "lead": "\n", "trail": "\n", "file_created": False},
        )
        self.assertEqual(BASE.generator_version, VERSION)
        self.assertEqual(BASE.profile_sha256, PROFILE)

    def test_no_timestamp_unless_explicit(self) -> None:
        data = dump_manifest(BASE)
        self.assertIsNone(json.loads(data)["applied_at"])
        self.assertIsNone(re.search(rb"\d{4}-\d{2}-\d{2}T", data))
        stamped = replace(BASE, applied_at="2026-11-11T09:30:00Z")
        self.assertEqual(load_manifest(dump_manifest(stamped)), stamped)
        self.assertTrue(stamped.same_content(BASE))
        self.assertNotEqual(stamped, BASE)

    def test_refused_documents(self) -> None:
        def at(*keys: str) -> tuple[dict, dict, str]:
            obj = as_obj()
            node = obj
            for key in keys[:-1]:
                node = node[key]
            return obj, node, keys[-1]

        def setting(keys: tuple[str, ...], value: Any) -> bytes:
            obj, node, last = at(*keys)
            node[last] = value
            return encoded(obj)

        def dropping(*keys: str) -> bytes:
            obj, node, last = at(*keys)
            del node[last]
            return encoded(obj)

        group = as_obj()["settings"]["hook_groups"]["PreToolUse"][0]
        cases: dict[str, bytes] = {
            "unknown_top_key": setting(("notes",), "x"),
            "unknown_settings_key": setting(("settings", "extra"), []),
            "unknown_generator_key": setting(("generator", "url"), "x"),
            "unknown_block_key": setting(("claude_block", "path"), CLAUDE),
            "missing_files": dropping("files"),
            "missing_offered": dropping("offered"),
            "schema_2": setting(("schema",), 2),
            "schema_true": setting(("schema",), True),
            "schema_text": setting(("schema",), "1"),
            "generator_name": setting(("generator", "name"), "other-tool"),
            "version_empty": setting(("generator", "version"), ""),
            "version_space": setting(("generator", "version"), "0.1 beta"),
            "profile_upper": setting(("profile_sha256",), PROFILE.upper()),
            "file_sha_short": setting(("files", AGENT), "a" * 63),
            "file_sha_int": setting(("files", AGENT), 1),
            "owns_local_settings": setting(("files", LOCAL), H),
            "owns_local_settings_case": setting(("files", ".claude/Settings.Local.json"), H),
            "owns_settings_file": setting(("files", SETTINGS), H),
            "owns_claude_md": setting(("files", CLAUDE), H),
            "owns_evidence_readme": setting(("files", "changes/README.md"), H),
            "owns_ledger": setting(("files", "audit/ledger/2026-11.jsonl"), H),
            "owns_approval": setting(("files", "changes/CHG-0001/approval.json"), H),
            "owns_policy": setting(("files", POLICY), H),
            "owns_state": setting(("files", ".cab/state/active.json"), H),
            "owns_user_settings": setting(("files", "~/.claude/settings.json"), H),
            "owns_absolute": setting(("files", "/etc/passwd"), H),
            "owns_parent": setting(("files", ".claude/agents/../settings.json"), H),
            "owns_proposal": setting(("files", AGENT + ".cab-new"), H),
            "case_collision": setting(("files", ".claude/agents/Safety-Reviewer.md"), H),
            "case_variant_root": setting(("files", ".CLAUDE/agents/x.md"), H),
            "offered_unknown": setting(("offered", "docs/x.md"), H),
            "offered_bad_sha": setting(("offered", POLICY), "XYZ"),
            "list_unknown_key": setting(("settings", "lists", "permissions.other"), ["x"]),
            "list_duplicate": setting(("settings", "lists", "permissions.deny"), ["a", "a"]),
            "list_empty": setting(("settings", "lists", "permissions.deny"), []),
            "list_not_list": setting(("settings", "lists", "permissions.deny"), "a"),
            "list_non_text": setting(("settings", "lists", "permissions.deny"), [1]),
            "hook_foreign_command": setting(
                ("settings", "hook_groups", "PreToolUse"),
                [{"hooks": [{"type": "command", "command": "echo contoso"}]}],
            ),
            "hook_extra_key": setting(
                ("settings", "hook_groups", "PreToolUse"), [dict(group, extra=1)]
            ),
            "hook_bad_event": setting(("settings", "hook_groups", "preToolUse"), [group]),
            "hook_duplicate": setting(("settings", "hook_groups", "PreToolUse"), [group, group]),
            "scalar_under_hooks": setting(
                ("settings", "scalars"), [{"path": ["hooks", "x"], "value": 1}]
            ),
            "scalar_on_list": setting(
                ("settings", "scalars"), [{"path": ["permissions", "deny"], "value": "x"}]
            ),
            "scalar_object": setting(
                ("settings", "scalars"), [{"path": ["model"], "value": {"a": 1}}]
            ),
            "scalar_float": setting(("settings", "scalars"), [{"path": ["model"], "value": 1.5}]),
            "scalar_empty_path": setting(("settings", "scalars"), [{"path": [], "value": 1}]),
            "scalar_extra_key": setting(
                ("settings", "scalars"), [{"path": ["model"], "value": 1, "x": 1}]
            ),
            "scalar_proto": setting(("settings", "scalars"), [{"path": ["__proto__"], "value": 1}]),
            "container_empty": setting(("settings", "containers"), [[]]),
            "file_created_text": setting(("settings", "file_created"), "yes"),
            "block_lead": setting(("claude_block", "lead"), "x"),
            "block_trail": setting(("claude_block", "trail"), "\n\n"),
            "block_sha": setting(("claude_block", "sha256"), "0" * 63),
            "missing_gitignore_block": dropping("gitignore_block"),
            "gitignore_block_extra_key": setting(("gitignore_block", "patterns"), []),
            "gitignore_block_lead": setting(("gitignore_block", "lead"), " "),
            "gitignore_block_created_text": setting(("gitignore_block", "file_created"), "no"),
            "gitignore_block_not_object": setting(("gitignore_block",), "x"),
            "owns_gitignore": setting(("files", GITIGNORE), H),
            "owns_gitignore_case": setting(("files", ".GitIgnore"), H),
            "offers_gitignore": setting(("offered", GITIGNORE), H),
            "applied_date_only": setting(("applied_at",), "2026-11-11"),
            "applied_bad_month": setting(("applied_at",), "2026-13-01T00:00:00Z"),
            "applied_number": setting(("applied_at",), 5),
            "duplicate_json_key": b'{"schema": 1, "schema": 1}',
            "nan": dump_manifest(BASE).replace(b'"schema": 1', b'"schema": NaN'),
            "not_object": b"[]",
            "bom": b"\xef\xbb\xbf" + dump_manifest(BASE),
        }
        for name, data in cases.items():
            with self.subTest(name):
                with self.assertRaises(ManifestError):
                    load_manifest(data)

    def test_constructor_refuses_the_same(self) -> None:
        bad_calls = [
            lambda: Manifest(VERSION, PROFILE, files={LOCAL: H}),
            lambda: Manifest(VERSION, PROFILE, files={"audit/README.md": H}),
            lambda: Manifest(
                VERSION, PROFILE, files={".claude/agents/A.md": H, ".claude/agents/a.md": H}
            ),
            lambda: Manifest(VERSION, PROFILE, offered={".claude/agents/x.md": H}),
            lambda: Manifest(VERSION, "nothex"),
            lambda: Manifest(VERSION, PROFILE, applied_at="yesterday"),
            lambda: Manifest(VERSION, PROFILE, settings={}),
            lambda: SettingsContribution(lists={"permissions.deny": ("a", "a")}),
            lambda: SettingsContribution(hook_groups={"Stop": ('{"hooks":[]}',)}),
            lambda: SettingsContribution(scalars=((("hooks",), "1"),)),
            lambda: SettingsContribution(scalars=((("model",), "1.0"),)),
            lambda: SettingsContribution(file_created=1),
            lambda: ClaudeBlockRecord(H, lead="\t"),
            lambda: Manifest(VERSION, PROFILE, gitignore_block={"sha256": H}),
            lambda: Manifest(VERSION, PROFILE, files={GITIGNORE: H}),
        ]
        for index, call in enumerate(bad_calls):
            with self.subTest(index=index):
                with self.assertRaises(ManifestError):
                    call()

    def test_loader_requires_bytes(self) -> None:
        with self.assertRaises(ManifestError):
            load_manifest(dump_manifest(BASE).decode())  # type: ignore[arg-type]


class UninstallTests(unittest.TestCase):
    """G8: only unchanged generated items go; edits, evidence and person files stay."""

    def setUp(self) -> None:
        self.tree, self.manifest = install(START)

    def test_removes_only_unchanged_generated_items(self) -> None:
        tree = dict(self.tree)
        tree[AGENT] = b"edited by a Contoso admin\n"
        tree[POLICY] = b"# tuned by a person\n"
        tree["changes/CHG-0001-remove-forwarding/record.md"] = b"closed\n"
        tree["audit/ledger/2026-11.jsonl"] = b'{"event": "fixture"}\n'
        plan = merge.plan_uninstall(self.manifest, tree)
        self.assertEqual(plan.blockers, ())
        removed = {a.path for a in plan.actions if a.kind == "remove"}
        self.assertEqual(removed, {SKILL, GUARD_FILE})
        self.assertIn(Issue("owned_modified", AGENT), plan.drift)
        for action in plan.actions:
            self.assertFalse(action.path.startswith(("changes/", "audit/", "policy/")))
            self.assertNotIn(action.path, (LOCAL, "PROGRESS.md", "HANDOFF.md"))
        self.assertIn(Issue("person_file_kept", POLICY), plan.notes)
        after = applied(tree, plan)
        restored = json.loads(after[SETTINGS])
        self.assertEqual(restored, USER)
        self.assertEqual(json.dumps(restored), json.dumps(USER))  # key order too
        self.assertEqual(after[CLAUDE], ORIGINAL_CLAUDE)
        self.assertEqual(after[GITIGNORE], USER_GITIGNORE)
        self.assertEqual(by_path(plan)[GITIGNORE].kind, "update")
        self.assertEqual(after[LOCAL], LOCAL_BYTES)
        self.assertEqual(after[AGENT], b"edited by a Contoso admin\n")
        self.assertEqual(after[POLICY], b"# tuned by a person\n")
        self.assertEqual(after["audit/ledger/2026-11.jsonl"], b'{"event": "fixture"}\n')

    def test_files_the_generator_created_are_removed_when_empty(self) -> None:
        tree, manifest = install({})
        plan = merge.plan_uninstall(manifest, tree)
        self.assertEqual(plan.drift, ())
        kinds = {a.path: a.kind for a in plan.actions}
        self.assertEqual(kinds[SETTINGS], "remove")
        self.assertEqual(kinds[CLAUDE], "remove")
        self.assertEqual(kinds[GITIGNORE], "remove")
        after = applied(tree, plan)
        self.assertEqual(
            set(after),
            {POLICY, "policy/standard-changes.toml", "changes/README.md", "audit/README.md"},
        )

    def test_drifted_settings_entries_are_kept(self) -> None:
        tree = dict(self.tree)
        doc = json.loads(tree[SETTINGS])
        doc["permissions"]["disableBypassPermissionsMode"] = "enable"
        doc["permissions"]["deny"].remove("Write(.claude/**)")
        doc["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 30
        tree[SETTINGS] = json.dumps(doc, indent=2).encode()
        plan = merge.plan_uninstall(self.manifest, tree)
        self.assertEqual(plan.blockers, ())
        drift_codes = {i.code for i in plan.drift}
        self.assertTrue(
            {"settings_scalar_modified", "settings_item_absent", "settings_hook_group_absent"}
            <= drift_codes,
            drift_codes,
        )
        result = json.loads(by_path(plan)[SETTINGS].data)
        self.assertEqual(result["permissions"]["disableBypassPermissionsMode"], "enable")
        self.assertEqual(result["permissions"]["deny"], USER["permissions"]["deny"])
        self.assertEqual(result["hooks"]["PreToolUse"], doc["hooks"]["PreToolUse"])

    def test_duplicate_user_entry_survives(self) -> None:
        tree = dict(self.tree)
        doc = json.loads(tree[SETTINGS])
        doc["permissions"]["deny"].insert(0, "Bash(cab approve:*)")
        tree[SETTINGS] = json.dumps(doc).encode()
        plan = merge.plan_uninstall(self.manifest, tree)
        result = json.loads(by_path(plan)[SETTINGS].data)
        self.assertEqual(
            result["permissions"]["deny"], ["Bash(cab approve:*)"] + USER["permissions"]["deny"]
        )

    def test_edited_claude_block_is_kept(self) -> None:
        tree = dict(self.tree)
        tree[CLAUDE] = tree[CLAUDE].replace(b"change control", b"change control (edited)")
        plan = merge.plan_uninstall(self.manifest, tree)
        self.assertIn(Issue("claude_block_modified", CLAUDE), plan.drift)
        self.assertNotIn(CLAUDE, by_path(plan))

    def test_person_gitignore_edits_are_kept(self) -> None:
        tree = dict(self.tree)
        tree[GITIGNORE] = b"dist/\n" + tree[GITIGNORE] + b"coverage/\n"
        plan = merge.plan_uninstall(self.manifest, tree)
        expected = b"dist/\n" + USER_GITIGNORE + b"coverage/\n"
        self.assertEqual(by_path(plan)[GITIGNORE].data, expected)
        edited = dict(self.tree)
        edited[GITIGNORE] = edited[GITIGNORE].replace(b".cab/backups/\n", b"")
        plan = merge.plan_uninstall(self.manifest, edited)
        self.assertIn(Issue("gitignore_block_modified", GITIGNORE), plan.drift)
        self.assertNotIn(GITIGNORE, by_path(plan))
        linked = dict(self.tree)
        linked[GITIGNORE] = NodeKind.SYMLINK
        plan = merge.plan_uninstall(self.manifest, linked)
        self.assertIn(Issue("target_symlink", GITIGNORE), plan.drift)
        self.assertNotIn(GITIGNORE, by_path(plan))

    def test_unreadable_settings_left_alone(self) -> None:
        tree = dict(self.tree)
        tree[SETTINGS] = b'{"permissions": {}, "permissions": {}}'
        plan = merge.plan_uninstall(self.manifest, tree)
        self.assertIn("settings_unreadable", {i.code for i in plan.drift})
        self.assertNotIn(SETTINGS, by_path(plan))

    def test_non_directory_parent_blocks_every_action(self) -> None:
        tree = dict(self.tree)
        tree[".claude/hooks"] = NodeKind.SYMLINK
        plan = merge.plan_uninstall(self.manifest, tree)
        self.assertIn(Issue("parent_symlink", ".claude/hooks"), plan.blockers)
        self.assertEqual(plan.actions, ())

    def test_symlinked_owned_file_is_not_followed(self) -> None:
        tree = dict(self.tree)
        tree[SKILL] = NodeKind.SYMLINK
        plan = merge.plan_uninstall(self.manifest, tree)
        self.assertIn(Issue("target_symlink", SKILL), plan.drift)
        self.assertNotIn(SKILL, by_path(plan))

    def test_reinstall_over_kept_edit_collides(self) -> None:
        tree = dict(self.tree)
        tree[AGENT] = b"edited\n"
        after = applied(tree, merge.plan_uninstall(self.manifest, tree))
        again = merge.plan_merge(
            make_bundle(), after, manifest=None, generator_version=VERSION, profile_sha256=PROFILE
        )
        self.assertIn(Issue("unowned_collision", AGENT), again.blockers)
        self.assertEqual(again.actions, ())

    def test_rejects_non_manifest(self) -> None:
        with self.assertRaises(SetupDataError):
            merge.plan_uninstall(copy.deepcopy(as_obj()), self.tree)  # type: ignore[arg-type]


class ConfigMatchTests(unittest.TestCase):
    """Pure core of the ConfigChange verifier (S9 -> S10 config_lock)."""

    def setUp(self) -> None:
        self.tree, self.manifest = install(START)

    def settings(self, change: Any = None) -> bytes:
        doc = json.loads(self.tree[SETTINGS])
        if change is not None:
            change(doc)
        return json.dumps(doc).encode("utf-8")

    def test_installed_settings_match(self) -> None:
        self.assertTrue(config_file_matches(self.manifest, SETTINGS, self.tree[SETTINGS]))
        required = ("Bash(cab approve:*)",)
        self.assertTrue(
            config_file_matches(
                self.manifest, SETTINGS, self.tree[SETTINGS], required_deny=required
            )
        )
        self.assertTrue(
            config_file_matches(
                self.manifest,
                SETTINGS,
                self.settings(lambda d: d["permissions"]["allow"].append("Bash(ls)")),
            )
        )

    def test_weakened_settings_do_not_match(self) -> None:
        for change in (
            lambda d: d["permissions"]["deny"].remove("Write(.claude/**)"),
            lambda d: d["hooks"].pop("PreToolUse"),
            lambda d: d["permissions"].pop("disableBypassPermissionsMode"),
            lambda d: d.__setitem__("disableAllHooks", True),
            lambda d: d.__setitem__("sandbox", {"enabled": False}),
            lambda d: d.__setitem__("allowManagedHooksOnly", True),
        ):
            with self.subTest(change=change):
                self.assertFalse(
                    config_file_matches(self.manifest, SETTINGS, self.settings(change))
                )
        missing = ("Bash(cab resume:*)",)
        self.assertFalse(
            config_file_matches(self.manifest, SETTINGS, self.tree[SETTINGS], required_deny=missing)
        )
        for data in (None, b"", b"{", b"[]", b'{"a": 1, "a": 2}'):
            self.assertFalse(config_file_matches(self.manifest, SETTINGS, data))

    def test_skills_match_only_owned_unchanged_files(self) -> None:
        self.assertTrue(config_file_matches(self.manifest, SKILL, self.tree[SKILL]))
        self.assertFalse(config_file_matches(self.manifest, SKILL, self.tree[SKILL] + b"x"))
        self.assertFalse(config_file_matches(self.manifest, SKILL, None))
        self.assertFalse(config_file_matches(self.manifest, ".claude/skills/mine/SKILL.md", b"x"))
        self.assertFalse(config_file_matches(self.manifest, ".claude/skills/../x", b"x"))
        self.assertFalse(config_file_matches(self.manifest, LOCAL, LOCAL_BYTES))
        self.assertFalse(config_file_matches(None, SKILL, self.tree[SKILL]))  # type: ignore[arg-type]

    def test_identity_guide_is_an_owned_path(self) -> None:
        digest = sha256_hex(b"# Identity (fixture)\n")
        record = replace(BASE, files={**BASE.files, "docs/identity.md": digest})
        self.assertEqual(load_manifest(dump_manifest(record)).files["docs/identity.md"], digest)
        with self.assertRaises(ManifestError):
            replace(BASE, files={**BASE.files, "docs/notes.md": digest})


DEMO_PY = "simtenant/simtenant.py"
DEMO_SEED = "simtenant/seed/contoso.json"


class DemoOwnershipTests(unittest.TestCase):
    """R3 reference fix: exactly the two simtenant demo files are generator-owned."""

    NOT_OWNED = {
        "simtenant": "path_not_allowed",
        "simtenant/seed": "path_not_allowed",
        "simtenant/state.json": "path_not_allowed",
        "simtenant/seed/fabrikam.json": "path_not_allowed",
        "simtenant/seed/contoso.json.bak": "path_not_allowed",
        "simtenant/simtenant.py/extra": "path_not_allowed",
        "simtenant/simtenant.pyc": "path_not_allowed",
        "simtenant/__pycache__/simtenant.cpython-312.pyc": "path_not_allowed",
        "simtenant/contoso.json": "path_not_allowed",
        "simtenant/seed/simtenant.py": "path_not_allowed",
        "Simtenant/simtenant.py": "path_not_allowed",
        "simtenant/Simtenant.py": "path_not_allowed",
        "SIMTENANT/SEED/CONTOSO.JSON": "path_not_allowed",
        "docs/simtenant/simtenant.py": "path_not_allowed",
        ".claude/simtenant/simtenant.py": "path_not_allowed",
        "simtenant/seed/contoso.json.cab-new": "path_reserved",
        "simtenant/../docs/identity.md": "path_unsafe",
        "simtenant//simtenant.py": "path_unsafe",
        "./simtenant/simtenant.py": "path_unsafe",
        "simtenant/simtenant.py ": "path_unsafe",
    }

    def test_vocabulary_is_closed_and_exact(self) -> None:
        self.assertEqual(DEMO_FILES, (DEMO_PY, DEMO_SEED))
        self.assertEqual(set(OWNED_FILES), {"docs/identity.md", DEMO_PY, DEMO_SEED})
        self.assertEqual(len(OWNED_FILES), len(set(OWNED_FILES)))
        for path in OWNED_FILES:
            self.assertEqual(path_class(path), "owned")
            self.assertNotIn(path, CREATE_ONCE)

    def test_every_other_simtenant_path_is_refused(self) -> None:
        for path, code in self.NOT_OWNED.items():
            with self.subTest(path=path):
                with self.assertRaises(SetupDataError) as ctx:
                    path_class(path)
                self.assertEqual(ctx.exception.code, code)

    def test_manifest_records_and_round_trips_demo_files(self) -> None:
        digests = {DEMO_PY: sha256_hex(b"# fixture tenant\n"), DEMO_SEED: sha256_hex(b"{}\n")}
        record = replace(BASE, files={**BASE.files, **digests})
        loaded = load_manifest(dump_manifest(record))
        self.assertEqual(loaded, record)
        for path, digest in digests.items():
            self.assertEqual(loaded.files[path], digest)
        self.assertEqual(dump_manifest(loaded), dump_manifest(record))

    def test_manifest_refuses_other_simtenant_paths(self) -> None:
        digest = sha256_hex(b"person state\n")
        for path in self.NOT_OWNED:
            with self.subTest(path=path):
                with self.assertRaises(ManifestError) as ctx:
                    replace(BASE, files={**BASE.files, path: digest})
                self.assertEqual(ctx.exception.code, "owned_path_refused")
        obj = as_obj()
        obj["files"]["simtenant/state.json"] = digest
        with self.assertRaises(ManifestError) as ctx:
            load_manifest(encoded(obj))
        self.assertEqual(ctx.exception.code, "owned_path_refused")

    def test_demo_files_are_never_create_once_records(self) -> None:
        digest = sha256_hex(b"{}\n")
        for path in DEMO_FILES:
            with self.subTest(path=path):
                with self.assertRaises(ManifestError) as ctx:
                    replace(BASE, offered={**BASE.offered, path: digest})
                self.assertEqual(ctx.exception.code, "offered_path_refused")

    def test_demo_files_are_not_configuration_for_the_verifier(self) -> None:
        data = b"{}\n"
        record = replace(BASE, files={**BASE.files, DEMO_SEED: sha256_hex(data)})
        self.assertFalse(config_file_matches(record, DEMO_SEED, data))


if __name__ == "__main__":
    unittest.main()
