"""Merge rules of DESIGN §10-3 (G3, G4, G7, idempotence, hostile input) on fixture bytes.

Pure planning only: every project is an in-memory mapping and nothing is written to disk.
All data is fictional Contoso data.
"""

from __future__ import annotations

import copy
import json
import unittest
from typing import Any

from cab_of_one.setup import merge
from cab_of_one.setup.manifest import (
    ClaudeBlockRecord,
    Manifest,
    SetupDataError,
    dump_manifest,
    sha256_hex,
)
from cab_of_one.setup.merge import Issue, NodeKind, SettingsScopes

VERSION = "0.1.0.dev0"
PROFILE = sha256_hex(b"contoso-solo fixture profile")
GUARD = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/guard.py'
CLOSEOUT = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/closeout.py'

SETTINGS = ".claude/settings.json"
LOCAL = ".claude/settings.local.json"
CLAUDE = "CLAUDE.md"
AGENT = ".claude/agents/safety-reviewer.md"
SKILL = ".claude/skills/change/SKILL.md"
GUARD_FILE = ".claude/hooks/cab/guard.py"
POLICY = "policy/policy.toml"
CATALOG = "policy/standard-changes.toml"
GITIGNORE = ".gitignore"
NEW = ".cab-new"

OURS: dict[str, Any] = {
    "permissions": {
        "deny": ["Edit(.claude/**)", "Write(.claude/**)", "Bash(cab approve:*)"],
        "disableBypassPermissionsMode": "disable",
    },
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "*",
                "hooks": [
                    {"type": "command", "command": GUARD, "onFailure": "block", "timeout": 10}
                ],
            }
        ],
        "Stop": [{"hooks": [{"type": "command", "command": CLOSEOUT, "onFailure": "block"}]}],
    },
}

USER: dict[str, Any] = {
    "model": "contoso-model-alias",
    "env": {"CONTOSO_REGION": "east", "EMPTY": ""},
    "permissions": {
        "allow": ["Bash(git status)", "Read(./docs/**)"],
        "deny": ["Read(./secrets/**)", "Bash(rm -rf:*)"],
        "ask": ["Bash(git push:*)"],
        "additionalDirectories": ["../contoso-shared"],
        "defaultMode": "default",
    },
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/contoso-audit.sh"}]}
        ],
        "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "echo ok"}]}],
    },
    "statusLine": {"type": "command", "command": "contoso-status"},
    "contosoUnknownKey": {"nested": [1, 2, {"x": None}], "flag": True, "ratio": 0.5},
}

LOCAL_BYTES = (
    b'{\n  "permissions": {"allow": ["Bash(make test)"]},\n  "disableAllHooks": false\n}\n'
)
BLOCK = merge.make_claude_block(b"## Contoso change control\n\nStart every change with /change.\n")
GI_BLOCK = merge.make_gitignore_block()


def settings_bytes(doc: Any) -> bytes:
    return json.dumps(doc, indent=4).replace("\n", "\r\n").encode("utf-8")


def make_bundle(
    overrides: dict[str, bytes] | None = None, drop: tuple[str, ...] = ()
) -> dict[str, bytes]:
    bundle = {
        SETTINGS: json.dumps(OURS).encode("utf-8"),
        CLAUDE: BLOCK,
        AGENT: b"---\nname: safety-reviewer\ntools: Read, Grep, Glob\n---\nFind the reason.\n",
        SKILL: b"---\nname: change\n---\nOrchestrate one Contoso change.\n",
        GUARD_FILE: b"# pinned guard (fixture bytes)\n",
        POLICY: b"schema = 1\n",
        CATALOG: b"# disabled proposals only\n",
        "changes/README.md": b"Change folders live here.\n",
        "audit/README.md": b"The ledger lives in audit/ledger/.\n",
    }
    bundle.update(overrides or {})
    for path in drop:
        del bundle[path]
    return bundle


def plan(bundle: dict, existing: dict, manifest: Manifest | None = None, **kw: Any):
    return merge.plan_merge(
        bundle,
        existing,
        manifest=manifest,
        generator_version=VERSION,
        profile_sha256=PROFILE,
        **kw,
    )


def applied(existing: dict, result: Any) -> dict:
    """What the project would hold after the plan's actions (in memory only)."""
    tree = dict(existing)
    for action in result.actions:
        if action.kind == "remove":
            del tree[action.path]
        else:
            tree[action.path] = action.data
    return tree


def by_path(result: Any) -> dict[str, Any]:
    return {action.path: action for action in result.actions}


def codes(issues: tuple[Issue, ...]) -> set[str]:
    return {issue.code for issue in issues}


class MergeTestCase(unittest.TestCase):
    def assert_blocked(self, result: Any, code: str, path: str | None = None) -> None:
        self.assertIn(code, codes(result.blockers), result.blockers)
        if path is not None:
            self.assertIn(path, {i.path for i in result.blockers if i.code == code})
        self.assertEqual(result.actions, ())
        self.assertIsNone(result.manifest)
        self.assertFalse(result.manifest_changed)

    def assert_clean(self, result: Any) -> None:
        self.assertEqual(result.blockers, ())
        self.assertEqual(result.conflicts, ())

    def assert_subset(self, small: Any, big: Any, where: str = "$") -> None:
        """Every user value survives: objects by key, lists as an unchanged prefix."""
        self.assertIs(type(big), type(small), where)
        if type(small) is dict:
            self.assertEqual(list(big)[: len(small)], list(small), f"key order at {where}")
            for key, value in small.items():
                self.assert_subset(value, big[key], f"{where}.{key}")
        elif type(small) is list:
            self.assertEqual(big[: len(small)], small, f"list prefix at {where}")
        else:
            self.assertEqual(big, small, where)


class SettingsPreservationTests(MergeTestCase):
    """G3: user allow/deny/ask/additionalDirectories, hooks, env, model and unknown keys."""

    def setUp(self) -> None:
        self.existing = {SETTINGS: settings_bytes(USER), LOCAL: LOCAL_BYTES}

    def test_user_entries_kept_and_ours_appended(self) -> None:
        result = plan(make_bundle(), self.existing)
        self.assert_clean(result)
        action = by_path(result)[SETTINGS]
        self.assertEqual(action.kind, "update")
        merged = json.loads(action.data)
        self.assert_subset(USER, merged)
        self.assertEqual(list(merged), list(USER))
        perms = merged["permissions"]
        for key in ("allow", "ask", "additionalDirectories", "defaultMode"):
            self.assertEqual(perms[key], USER["permissions"][key])
        self.assertEqual(perms["deny"], USER["permissions"]["deny"] + OURS["permissions"]["deny"])
        self.assertEqual(perms["disableBypassPermissionsMode"], "disable")
        self.assertEqual(list(perms)[-1], "disableBypassPermissionsMode")
        hooks = merged["hooks"]
        self.assertEqual(list(hooks), ["PreToolUse", "PostToolUse", "Stop"])
        self.assertEqual(
            hooks["PreToolUse"], USER["hooks"]["PreToolUse"] + OURS["hooks"]["PreToolUse"]
        )
        self.assertEqual(hooks["PostToolUse"], USER["hooks"]["PostToolUse"])
        self.assertEqual(hooks["Stop"], OURS["hooks"]["Stop"])
        for key in ("model", "env", "statusLine", "contosoUnknownKey"):
            self.assertEqual(merged[key], USER[key])
        record = result.manifest.settings
        self.assertFalse(record.file_created)
        self.assertEqual(record.lists["permissions.deny"], tuple(OURS["permissions"]["deny"]))
        self.assertEqual(record.containers, (("hooks", "Stop"),))

    def test_local_user_and_managed_scopes_are_never_output(self) -> None:
        scopes = SettingsScopes(
            local=LOCAL_BYTES,
            user=b'{"model": "contoso-user-model", "sandbox": {"enabled": true}}',
            managed=(b'{"allowManagedHooksOnly": false}',),
        )
        result = plan(make_bundle(), self.existing, scopes=scopes)
        self.assert_clean(result)
        self.assertNotIn(LOCAL, by_path(result))
        self.assertFalse(any(a.path.startswith("~") for a in result.actions))
        self.assertEqual(applied(self.existing, result)[LOCAL], LOCAL_BYTES)
        self.assertNotIn(LOCAL, result.manifest.files)

    def test_bundle_may_not_write_local_settings(self) -> None:
        result = plan(make_bundle({LOCAL: b"{}"}), self.existing)
        self.assert_blocked(result, "bundle_path_refused", LOCAL)

    def test_item_already_present_is_neither_duplicated_nor_claimed(self) -> None:
        user = copy.deepcopy(USER)
        user["permissions"]["deny"].append("Bash(cab approve:*)")
        result = plan(make_bundle(), {SETTINGS: settings_bytes(user)})
        merged = json.loads(by_path(result)[SETTINGS].data)
        self.assertEqual(merged["permissions"]["deny"].count("Bash(cab approve:*)"), 1)
        self.assertEqual(
            result.manifest.settings.lists["permissions.deny"],
            ("Edit(.claude/**)", "Write(.claude/**)"),
        )

    def test_settings_created_when_absent(self) -> None:
        result = plan(make_bundle(), {})
        action = by_path(result)[SETTINGS]
        self.assertEqual(action.kind, "create")
        self.assertEqual(json.loads(action.data), OURS)
        self.assertTrue(action.data.endswith(b"}\n"))
        self.assertNotIn(b"\r", action.data)
        self.assertTrue(result.manifest.settings.file_created)

    def test_stale_contributions_withdrawn_user_items_kept(self) -> None:
        first = plan(make_bundle(), self.existing)
        tree = applied(self.existing, first)
        ours = copy.deepcopy(OURS)
        ours["permissions"]["deny"] = ours["permissions"]["deny"][:2]
        del ours["hooks"]["Stop"]
        second = plan(make_bundle({SETTINGS: json.dumps(ours).encode()}), tree, first.manifest)
        self.assert_clean(second)
        merged = json.loads(by_path(second)[SETTINGS].data)
        self.assertEqual(
            merged["permissions"]["deny"], USER["permissions"]["deny"] + ours["permissions"]["deny"]
        )
        self.assertNotIn("Stop", merged["hooks"])
        self.assert_subset(USER, merged)
        self.assertNotIn("Stop", second.manifest.settings.hook_groups)
        self.assertEqual(second.manifest.settings.containers, ())


class IdempotenceTests(MergeTestCase):
    """G2: same bundle, same manifest -> nothing to do, manifest unchanged."""

    def test_second_run_has_nothing_to_do(self) -> None:
        start = {
            SETTINGS: settings_bytes(USER),
            LOCAL: LOCAL_BYTES,
            CLAUDE: b"# Contoso operations\n\nKeep notes here.\n",
        }
        first = plan(make_bundle(), start)
        self.assert_clean(first)
        self.assertTrue(first.manifest_changed)
        tree = applied(start, first)
        second = plan(make_bundle(), tree, first.manifest, applied_at="2026-11-11T09:00:00Z")
        self.assertTrue(second.nothing_to_do, (second.actions, second.notes))
        self.assertEqual(second.actions, ())
        self.assertFalse(second.manifest_changed)
        self.assertTrue(second.manifest.same_content(first.manifest))
        self.assertEqual(tree[LOCAL], LOCAL_BYTES)

    def test_same_input_same_plan_and_manifest_bytes(self) -> None:
        start = {SETTINGS: settings_bytes(USER)}
        one = plan(make_bundle(), start)
        two = plan(dict(reversed(list(make_bundle().items()))), dict(start))
        self.assertEqual(one, two)
        self.assertEqual(dump_manifest(one.manifest), dump_manifest(two.manifest))
        self.assertEqual([a.path for a in one.actions], sorted(a.path for a in one.actions))


class ClaudeBlockTests(MergeTestCase):
    ORIGINAL = "﻿# Contoso ops\r\n\r\nNotes: café, 한국어\r\nno final newline".encode()

    def test_append_keeps_every_original_byte(self) -> None:
        result = plan({CLAUDE: BLOCK}, {CLAUDE: self.ORIGINAL})
        self.assert_clean(result)
        action = by_path(result)[CLAUDE]
        self.assertEqual(action.kind, "update")
        self.assertTrue(action.data.startswith(self.ORIGINAL))
        self.assertEqual(action.data, self.ORIGINAL + b"\r\n\r\n" + BLOCK + b"\r\n")
        record = result.manifest.claude_block
        self.assertEqual(
            (record.lead, record.trail, record.file_created), ("\r\n\r\n", "\r\n", False)
        )

    def test_existing_pair_replaced_outside_bytes_identical(self) -> None:
        old = merge.make_claude_block(b"older generated text\n")
        before = b"top\r\n\xe2\x80\x94 Contoso notes \xff raw byte\r\n"
        after = b"\r\nbottom caf\xc3\xa9, no final newline"
        manifest = Manifest(VERSION, PROFILE, claude_block=ClaudeBlockRecord(sha256_hex(old)))
        result = plan({CLAUDE: BLOCK}, {CLAUDE: before + old + after}, manifest)
        self.assert_clean(result)
        self.assertEqual(by_path(result)[CLAUDE].data, before + BLOCK + after)

    def test_edited_block_is_proposed_not_overwritten(self) -> None:
        edited = merge.make_claude_block(b"a person edited this\n")
        existing = {CLAUDE: b"intro\n" + edited + b"\noutro\n"}
        result = plan({CLAUDE: BLOCK}, existing)
        self.assertEqual(result.blockers, ())
        self.assertEqual(result.conflicts, (Issue("claude_block_modified", CLAUDE),))
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("propose", CLAUDE + NEW)])
        self.assertEqual(by_path(result)[CLAUDE + NEW].data, b"intro\n" + BLOCK + b"\noutro\n")
        self.assertEqual(result.resolvable, (CLAUDE,))
        taken = plan({CLAUDE: BLOCK}, existing, take_new={CLAUDE})
        self.assert_clean(taken)
        self.assertEqual(by_path(taken)[CLAUDE].data, b"intro\n" + BLOCK + b"\noutro\n")

    def test_bad_markers_stop_the_whole_merge(self) -> None:
        begin, end = merge.BEGIN_MARKER, merge.END_MARKER
        cases = {
            "nested": begin + b"\n" + begin + b"\nx\n" + end + b"\n" + end + b"\n",
            "unmatched_begin": b"notes\n" + begin + b"\nno end\n",
            "unmatched_end": b"notes\n" + end + b"\n",
            "out_of_order": end + b"\nx\n" + begin + b"\n",
            "two_pairs": begin + b"\na\n" + end + b"\n" + begin + b"\nb\n" + end + b"\n",
            "lookalike_spacing": b"<!--cab-of-one:begin-->\nx\n" + end + b"\n",
            "lookalike_case": b"<!-- CAB-OF-ONE:BEGIN -->\nx\n" + end + b"\n",
            "prose_mention": begin + b"\nsee cab-of-one:end below\n" + end + b"\n",
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assert_blocked(plan(make_bundle(), {CLAUDE: data}), "claude_markers_invalid")

    def test_unsupported_encodings_refused(self) -> None:
        for data in ("# notes\n".encode("utf-16"), b"a\x00b\n", "x".encode("utf-32")):
            with self.subTest(data=data[:4]):
                result = plan({CLAUDE: BLOCK}, {CLAUDE: data})
                self.assert_blocked(result, "claude_encoding_unsupported")

    def test_symlinked_or_special_claude_md_refused(self) -> None:
        self.assert_blocked(
            plan(make_bundle(), {CLAUDE: NodeKind.SYMLINK}), "target_symlink", CLAUDE
        )
        self.assert_blocked(
            plan(make_bundle(), {CLAUDE: NodeKind.OTHER}), "target_not_regular", CLAUDE
        )

    def test_created_when_absent(self) -> None:
        result = plan({CLAUDE: BLOCK}, {})
        self.assertEqual(by_path(result)[CLAUDE].data, BLOCK + b"\n")
        self.assertTrue(result.manifest.claude_block.file_created)

    def test_make_claude_block_refuses_marker_text_in_body(self) -> None:
        for body in (b"x cab-of-one:end\n", b"CAB-OF-ONE:BEGIN\n", b"no newline", b"a\x00\n"):
            with self.subTest(body=body):
                with self.assertRaises(SetupDataError):
                    merge.make_claude_block(body)

    def test_malformed_bundle_block_refused(self) -> None:
        result = plan({CLAUDE: b"## no markers\n"}, {})
        self.assert_blocked(result, "bundle_claude_invalid", CLAUDE)


class GitignoreBlockTests(MergeTestCase):
    """S5/S9: .cab/state/ (exact-input HMAC/salt), backups and setup staging stay out of VCS
    through one marker block; the person's .gitignore is never overwritten whole."""

    USER_GI = b"# Contoso\r\n*.log\r\nsecrets/\r\n!keep.log"  # CRLF, no final newline

    def installed(self) -> tuple[dict, Manifest]:
        first = plan({GITIGNORE: GI_BLOCK}, {GITIGNORE: self.USER_GI})
        self.assert_clean(first)
        return applied({GITIGNORE: self.USER_GI}, first), first.manifest

    def test_block_lists_the_required_paths(self) -> None:
        lines = GI_BLOCK.split(b"\n")
        self.assertEqual(lines[0], merge.GITIGNORE_BEGIN)
        self.assertEqual(lines[-1], merge.GITIGNORE_END)
        self.assertEqual([line.decode() for line in lines[1:-1]], list(merge.GITIGNORE_PATTERNS))
        self.assertEqual(merge.GITIGNORE_PATTERNS, (".cab/state/", ".cab/backups/", ".cab/setup/"))

    def test_appended_and_user_bytes_kept(self) -> None:
        result = plan({GITIGNORE: GI_BLOCK}, {GITIGNORE: self.USER_GI})
        self.assert_clean(result)
        action = by_path(result)[GITIGNORE]
        self.assertEqual(action.kind, "update")
        self.assertEqual(action.data, self.USER_GI + b"\r\n\r\n" + GI_BLOCK + b"\r\n")
        record = result.manifest.gitignore_block
        self.assertEqual(record.sha256, sha256_hex(GI_BLOCK))
        self.assertEqual(
            (record.lead, record.trail, record.file_created), ("\r\n\r\n", "\r\n", False)
        )
        self.assertNotIn(GITIGNORE, result.manifest.files)
        self.assertNotIn(GITIGNORE, result.manifest.offered)

    def test_created_when_absent_idempotent_and_removed(self) -> None:
        first = plan({GITIGNORE: GI_BLOCK}, {})
        self.assertEqual(by_path(first)[GITIGNORE].data, GI_BLOCK + b"\n")
        self.assertTrue(first.manifest.gitignore_block.file_created)
        tree = applied({}, first)
        self.assertTrue(plan({GITIGNORE: GI_BLOCK}, tree, first.manifest).nothing_to_do)
        undo = merge.plan_uninstall(first.manifest, tree)
        self.assertEqual([(a.kind, a.path) for a in undo.actions], [("remove", GITIGNORE)])

    def test_uninstall_removes_only_the_exact_block(self) -> None:
        tree, manifest = self.installed()
        clean = merge.plan_uninstall(manifest, tree)
        self.assertEqual(by_path(clean)[GITIGNORE].data, self.USER_GI)
        tree[GITIGNORE] = tree[GITIGNORE] + b"build/\r\n"
        kept = merge.plan_uninstall(manifest, tree)
        self.assertEqual(kept.drift, ())
        self.assertEqual(by_path(kept)[GITIGNORE].data, self.USER_GI + b"\r\nbuild/\r\n")

    def test_edited_block_is_a_conflict_and_survives_uninstall(self) -> None:
        tree, manifest = self.installed()
        installed_bytes = tree[GITIGNORE]
        tree[GITIGNORE] = tree[GITIGNORE].replace(b".cab/setup/\n", b"")
        result = plan({GITIGNORE: GI_BLOCK}, tree, manifest)
        self.assertEqual(result.conflicts, (Issue("gitignore_block_modified", GITIGNORE),))
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("propose", GITIGNORE + NEW)])
        taken = plan({GITIGNORE: GI_BLOCK}, tree, manifest, take_new={GITIGNORE})
        self.assertEqual(by_path(taken)[GITIGNORE].data, installed_bytes)
        undo = merge.plan_uninstall(manifest, tree)
        self.assertIn(Issue("gitignore_block_modified", GITIGNORE), undo.drift)
        self.assertNotIn(GITIGNORE, by_path(undo))

    def test_removed_block_is_reported_missing(self) -> None:
        _, manifest = self.installed()
        result = plan({GITIGNORE: GI_BLOCK}, {GITIGNORE: self.USER_GI}, manifest)
        self.assertEqual(result.conflicts, (Issue("gitignore_block_missing", GITIGNORE),))
        self.assertEqual(result.resolvable, (GITIGNORE,))
        self.assertNotIn(GITIGNORE, by_path(result))

    def test_damaged_markers_block(self) -> None:
        begin, end = merge.GITIGNORE_BEGIN, merge.GITIGNORE_END
        body = b".cab/state/\n"
        cases = {
            "two_pairs": GI_BLOCK + b"\n" + GI_BLOCK + b"\n",
            "unmatched_begin": b"*.log\n" + begin + b"\n" + body,
            "unmatched_end": b"*.log\n" + end + b"\n",
            "out_of_order": end + b"\n" + body + begin + b"\n",
            "nested": begin + b"\n" + begin + b"\n" + body + end + b"\n" + end + b"\n",
            "not_whole_line": b"x " + GI_BLOCK + b"\n",
            "suffix_after_end": GI_BLOCK + b" extra\n",
            "case_variant": b"# CAB-OF-ONE:BEGIN\n" + body + end + b"\n",
            "claude_style_marker": merge.make_claude_block(b"") + b"\n",
        }
        for name, data in cases.items():
            with self.subTest(name):
                result = plan({GITIGNORE: GI_BLOCK}, {GITIGNORE: data})
                self.assert_blocked(result, "gitignore_markers_invalid", GITIGNORE)

    def test_symlinked_special_or_utf16_gitignore_blocks(self) -> None:
        for kind, code in (
            (NodeKind.SYMLINK, "target_symlink"),
            (NodeKind.DIRECTORY, "target_is_directory"),
            (NodeKind.OTHER, "target_not_regular"),
        ):
            with self.subTest(kind=kind):
                result = plan({GITIGNORE: GI_BLOCK}, {GITIGNORE: kind})
                self.assert_blocked(result, code, GITIGNORE)
        result = plan({GITIGNORE: GI_BLOCK}, {GITIGNORE: "*.log\n".encode("utf-16")})
        self.assert_blocked(result, "gitignore_encoding_unsupported", GITIGNORE)

    def test_person_negating_cab_paths_blocks(self) -> None:
        for line in (b"!.cab/state/", b"!/.cab/state/salt", b"!**/.cab/", b"  !.CAB/backups/  "):
            with self.subTest(line=line):
                existing = {GITIGNORE: b"*.log\n" + line + b"\n"}
                self.assert_blocked(plan({GITIGNORE: GI_BLOCK}, existing), "gitignore_negates_cab")
        after_block = {GITIGNORE: GI_BLOCK + b"\n!.cab/state/hmac\n"}
        self.assert_blocked(plan({GITIGNORE: GI_BLOCK}, after_block), "gitignore_negates_cab")
        harmless = {GITIGNORE: b"!*.cab-new\n!keep.log\n"}
        self.assert_clean(plan({GITIGNORE: GI_BLOCK}, harmless))

    def test_bundle_block_must_ignore_the_required_paths(self) -> None:
        required = list(merge.GITIGNORE_PATTERNS)
        for patterns in (
            [".cab/state/"],
            required + ["!.cab/state/x"],
            required + ["#comment"],
            required + [" padded"],
            required + [".cab/state/"],
            required + ["two\nlines"],
        ):
            with self.subTest(patterns=patterns):
                with self.assertRaises(SetupDataError):
                    merge.make_gitignore_block(patterns)
        begin, end = merge.GITIGNORE_BEGIN, merge.GITIGNORE_END
        weak = begin + b"\n.cab/state/\n" + end
        negating = begin + b"\n.cab/state/\n.cab/backups/\n.cab/setup/\n!.cab/state/x\n" + end
        for block in (weak, negating, b"*.log\n"):
            with self.subTest(block=block):
                result = plan({GITIGNORE: block}, {})
                self.assert_blocked(result, "bundle_gitignore_invalid", GITIGNORE)
        extra = merge.make_gitignore_block(required + ["*.tmp"])
        self.assert_clean(plan({GITIGNORE: extra}, {}))

    def test_stale_block_withdrawn_when_bundle_drops_it(self) -> None:
        tree, manifest = self.installed()
        result = plan({}, tree, manifest)
        self.assert_clean(result)
        self.assertEqual(by_path(result)[GITIGNORE].data, self.USER_GI)
        self.assertIsNone(result.manifest.gitignore_block)


class OwnedFileTests(MergeTestCase):
    """G4 collisions and G7 preservation of a person's edits."""

    def installed(self) -> tuple[dict, Manifest]:
        first = plan(make_bundle(), {})
        self.assert_clean(first)
        return applied({}, first), first.manifest

    def test_unowned_collision_stops_entire_merge(self) -> None:
        existing = {AGENT: b"Contoso's own reviewer\n", SETTINGS: settings_bytes(USER)}
        self.assert_blocked(plan(make_bundle(), existing), "unowned_collision", AGENT)

    def test_identical_unowned_file_still_collides(self) -> None:
        existing = {SKILL: make_bundle()[SKILL]}
        self.assert_blocked(plan(make_bundle(), existing), "unowned_collision", SKILL)

    def test_user_modified_owned_file_gets_proposal_only(self) -> None:
        tree, manifest = self.installed()
        tree[SKILL] = b"edited by a Contoso admin\n"
        result = plan(make_bundle(), tree, manifest)
        self.assertEqual(result.blockers, ())
        self.assertEqual(result.conflicts, (Issue("owned_modified", SKILL),))
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("propose", SKILL + NEW)])
        self.assertEqual(by_path(result)[SKILL + NEW].data, make_bundle()[SKILL])
        self.assertEqual(result.manifest.files[SKILL], manifest.files[SKILL])
        self.assertEqual(result.resolvable, (SKILL,))
        self.assertEqual(applied(tree, result)[SKILL], b"edited by a Contoso admin\n")

    def test_take_new_resolves_only_the_named_path(self) -> None:
        tree, manifest = self.installed()
        tree[SKILL] = b"edited\n"
        tree[AGENT] = b"also edited\n"
        result = plan(make_bundle(), tree, manifest, take_new={SKILL})
        self.assertEqual(result.blockers, ())
        self.assertEqual(result.conflicts, (Issue("owned_modified", AGENT),))
        actions = {(a.kind, a.path) for a in result.actions}
        self.assertEqual(actions, {("update", SKILL), ("propose", AGENT + NEW)})
        self.assertEqual(result.manifest.files[SKILL], sha256_hex(make_bundle()[SKILL]))
        self.assertEqual(result.manifest.files[AGENT], manifest.files[AGENT])

    def test_take_new_unknown_or_unsafe_paths_block(self) -> None:
        tree, manifest = self.installed()
        tree[SKILL] = b"edited\n"
        for wanted, code in (
            ({AGENT}, "take_new_unexpected"),
            ({"../escape"}, "take_new_invalid"),
            ({SKILL + NEW}, "take_new_invalid"),
            ({POLICY}, "take_new_unexpected"),
        ):
            with self.subTest(wanted=wanted):
                self.assert_blocked(plan(make_bundle(), tree, manifest, take_new=wanted), code)
        with self.assertRaises(SetupDataError):
            plan(make_bundle(), tree, manifest, take_new=SKILL)

    def test_unchanged_owned_file_is_updated(self) -> None:
        tree, manifest = self.installed()
        result = plan(make_bundle({GUARD_FILE: b"# pinned guard v2\n"}), tree, manifest)
        self.assert_clean(result)
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("update", GUARD_FILE)])
        self.assertEqual(result.manifest.files[GUARD_FILE], sha256_hex(b"# pinned guard v2\n"))

    def test_deleted_owned_file_is_a_conflict(self) -> None:
        tree, manifest = self.installed()
        del tree[AGENT]
        result = plan(make_bundle(), tree, manifest)
        self.assertEqual(result.conflicts, (Issue("owned_missing", AGENT),))
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("propose", AGENT + NEW)])
        taken = plan(make_bundle(), tree, manifest, take_new=[AGENT])
        self.assertEqual([(a.kind, a.path) for a in taken.actions], [("create", AGENT)])

    def test_stale_owned_file_removed_only_when_unchanged(self) -> None:
        tree, manifest = self.installed()
        result = plan(make_bundle(drop=(SKILL,)), tree, manifest)
        self.assert_clean(result)
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("remove", SKILL)])
        self.assertNotIn(SKILL, result.manifest.files)
        tree[SKILL] = b"edited\n"
        kept = plan(make_bundle(drop=(SKILL,)), tree, manifest)
        self.assertEqual(kept.actions, ())
        self.assertIn(Issue("stale_owned_released", SKILL, "modified"), kept.notes)
        self.assertNotIn(SKILL, kept.manifest.files)

    def test_symlinked_proposal_path_blocks(self) -> None:
        tree, manifest = self.installed()
        tree[SKILL] = b"edited\n"
        tree[SKILL + NEW] = NodeKind.SYMLINK
        self.assert_blocked(plan(make_bundle(), tree, manifest), "target_symlink", SKILL + NEW)

    def test_existing_identical_proposal_not_rewritten(self) -> None:
        tree, manifest = self.installed()
        tree[SKILL] = b"edited\n"
        tree[SKILL + NEW] = make_bundle()[SKILL]
        result = plan(make_bundle(), tree, manifest)
        self.assertEqual(result.conflicts, (Issue("owned_modified", SKILL),))
        self.assertEqual(result.actions, ())


class PersonFileTests(MergeTestCase):
    """Policy and catalogue are created once; evidence is never generated or deleted."""

    def installed(self) -> tuple[dict, Manifest]:
        first = plan(make_bundle(), {})
        return applied({}, first), first.manifest

    def test_policy_created_once_then_only_proposed(self) -> None:
        tree, manifest = self.installed()
        tree[POLICY] = b"# tuned by the Contoso admin\n"
        same = plan(make_bundle(), tree, manifest)
        self.assertTrue(same.nothing_to_do, same.conflicts)
        self.assertIn(Issue("person_file_kept", POLICY), same.notes)
        newer = plan(make_bundle({POLICY: b"schema = 1\n# v2\n"}), tree, manifest)
        self.assertEqual(newer.conflicts, (Issue("person_file_differs", POLICY),))
        self.assertEqual([(a.kind, a.path) for a in newer.actions], [("propose", POLICY + NEW)])
        self.assertEqual(applied(tree, newer)[POLICY], b"# tuned by the Contoso admin\n")
        self.assertEqual(newer.resolvable, ())
        self.assert_blocked(
            plan(make_bundle({POLICY: b"v2\n"}), tree, manifest, take_new={POLICY}),
            "take_new_unexpected",
        )

    def test_pre_existing_policy_is_never_overwritten(self) -> None:
        result = plan(make_bundle(), {CATALOG: b"[[change]]\nname = 'contoso'\n"})
        self.assertEqual(result.conflicts, (Issue("person_file_differs", CATALOG),))
        self.assertNotIn(CATALOG, by_path(result))
        self.assertEqual(by_path(result)[CATALOG + NEW].kind, "propose")

    def test_missing_policy_after_handover_is_a_conflict(self) -> None:
        tree, manifest = self.installed()
        del tree[POLICY]
        result = plan(make_bundle(), tree, manifest)
        self.assertEqual(result.conflicts, (Issue("person_file_missing", POLICY),))
        self.assertNotIn(POLICY, by_path(result))

    def test_evidence_is_untouched(self) -> None:
        tree, manifest = self.installed()
        tree["audit/README.md"] = b"Contoso keeps its own notes here.\n"
        tree["changes/CHG-0001-remove-forwarding/record.md"] = b"closed\n"
        tree["audit/ledger/2026-11.jsonl"] = b'{"event": "fixture"}\n'
        del tree["changes/README.md"]
        result = plan(make_bundle(), tree, manifest)
        self.assertEqual(result.actions, ())
        self.assertIn(Issue("person_file_kept", "audit/README.md"), result.notes)
        self.assertIn(Issue("person_file_absent", "changes/README.md"), result.notes)
        for bad in ("changes/CHG-0001/approval.json", "audit/ledger/2026-11.jsonl"):
            with self.subTest(bad=bad):
                refused = plan(make_bundle({bad: b"{}"}), tree, manifest)
                self.assert_blocked(refused, "bundle_path_refused", bad)


class SafetyBlockerTests(MergeTestCase):
    def test_hooks_disabled_in_any_scope(self) -> None:
        user = dict(USER, disableAllHooks=True)
        self.assert_blocked(plan(make_bundle(), {SETTINGS: settings_bytes(user)}), "hooks_disabled")
        for scopes in (
            SettingsScopes(local=b'{"disableAllHooks": true}'),
            SettingsScopes(user=b'{"disableAllHooks": true}'),
            SettingsScopes(managed=(b"{}", b'{"disableAllHooks": "yes"}')),
        ):
            with self.subTest(scopes=scopes):
                self.assert_blocked(plan(make_bundle(), {}, scopes=scopes), "hooks_disabled")

    def test_sandbox_disabled_is_not_accepted(self) -> None:
        user = dict(USER, sandbox={"enabled": False})
        result = plan(make_bundle(), {SETTINGS: settings_bytes(user)})
        self.assert_blocked(result, "sandbox_disabled", SETTINGS)
        result = plan(make_bundle(), {}, scopes=SettingsScopes(user=b'{"sandbox": {"enabled": 0}}'))
        self.assert_blocked(result, "sandbox_disabled", "~/.claude/settings.json")

    def test_managed_only_flags_block(self) -> None:
        for raw, code in (
            (b'{"allowManagedHooksOnly": true}', "managed_hooks_only"),
            (b'{"allowManagedPermissionRulesOnly": true}', "managed_rules_only"),
        ):
            with self.subTest(code=code):
                result = plan(make_bundle(), {}, scopes=SettingsScopes(managed=(raw,)))
                self.assert_blocked(result, code)

    def test_unreadable_scope_blocks(self) -> None:
        result = plan(make_bundle(), {}, scopes=SettingsScopes(local=b'{"x": 1, "x": 2}'))
        self.assert_blocked(result, "scope_unreadable", LOCAL)

    def test_explicit_safe_values_pass(self) -> None:
        scopes = SettingsScopes(
            local=b'{"disableAllHooks": false, "sandbox": {"enabled": true}}',
            managed=(b'{"allowManagedHooksOnly": false}',),
        )
        self.assert_clean(plan(make_bundle(), {}, scopes=scopes))

    def test_different_safety_scalar_is_a_blocker(self) -> None:
        user = copy.deepcopy(USER)
        user["permissions"]["disableBypassPermissionsMode"] = "enable"
        result = plan(make_bundle(), {SETTINGS: settings_bytes(user)})
        self.assert_blocked(result, "settings_safety_conflict", SETTINGS)

    def test_different_plain_scalar_is_a_conflict(self) -> None:
        ours = dict(copy.deepcopy(OURS), cleanupPeriodDays=30)
        user = dict(USER, cleanupPeriodDays=10)
        result = plan(
            make_bundle({SETTINGS: json.dumps(ours).encode()}), {SETTINGS: settings_bytes(user)}
        )
        self.assert_blocked(result, "settings_scalar_conflict", SETTINGS)

    def test_type_conflicts_block(self) -> None:
        for mutate in (
            lambda u: u.__setitem__("permissions", ["Bash(ls)"]),
            lambda u: u["permissions"].__setitem__("deny", "Bash(rm:*)"),
            lambda u: u.__setitem__("hooks", []),
        ):
            user = copy.deepcopy(USER)
            mutate(user)
            with self.subTest(user=user.get("permissions"), hooks=user.get("hooks")):
                result = plan(make_bundle(), {SETTINGS: settings_bytes(user)})
                self.assert_blocked(result, "settings_type_conflict", SETTINGS)

    def test_bundle_settings_cannot_switch_controls_off(self) -> None:
        for extra in (
            {"disableAllHooks": True},
            {"sandbox": {"enabled": False}},
            {"sandbox": False},
            {"allowManagedHooksOnly": False},
        ):
            with self.subTest(extra=extra):
                ours = dict(copy.deepcopy(OURS), **extra)
                result = plan(make_bundle({SETTINGS: json.dumps(ours).encode()}), {})
                self.assert_blocked(result, "bundle_settings_invalid", SETTINGS)


class StrictJsonTests(MergeTestCase):
    HOSTILE = [
        b'{"model": "a", "model": "b"}',
        b'{"x": NaN}',
        b'{"x": Infinity}',
        b'{"x": -Infinity}',
        b'{"x": 1e400}',
        b'{"x": 1.50}',
        b'{"x": -0}',
        b"\xef\xbb\xbf{}",
        b'{"\\ud800": 1}',
        b'{"x": "\\udfff"}',
        b'{"x": "a\\u0000b"}',
        b'{"__proto__": {"polluted": true}}',
        b'{"": 1}',
        b"{} trailing",
        b"[]",
        b"\xff\xfe{}",
        b'{"x": "\xff"}',
        b'{"a": ' * 100 + b"1" + b"}" * 100,
    ]

    def test_hostile_project_settings_refused(self) -> None:
        for raw in self.HOSTILE:
            with self.subTest(raw=raw[:40]):
                self.assert_blocked(plan(make_bundle(), {SETTINGS: raw}), "settings_invalid")

    def test_hostile_bundle_settings_refused(self) -> None:
        for raw in self.HOSTILE + [b'{"permissions": {"deny": ["a", "a"]}}', b'{"x": 1.5}']:
            with self.subTest(raw=raw[:40]):
                result = plan(make_bundle({SETTINGS: raw}), {})
                self.assert_blocked(result, "bundle_settings_invalid", SETTINGS)


class HookOwnershipTests(MergeTestCase):
    def with_user_group(self, group: dict) -> Any:
        user = copy.deepcopy(USER)
        user["hooks"]["PreToolUse"].append(group)
        return plan(make_bundle(), {SETTINGS: settings_bytes(user)})

    def test_group_mixing_our_command_with_a_user_command_blocks(self) -> None:
        group = {
            "hooks": [
                {"type": "command", "command": GUARD},
                {"type": "command", "command": "echo contoso"},
            ]
        }
        self.assert_blocked(self.with_user_group(group), "hook_group_mixed", SETTINGS)

    def test_unrecorded_group_at_our_path_blocks(self) -> None:
        group = {"matcher": "*", "hooks": [{"type": "command", "command": GUARD, "timeout": 99}]}
        self.assert_blocked(self.with_user_group(group), "hook_group_unowned", SETTINGS)

    def test_lookalike_commands_are_user_hooks_and_stay(self) -> None:
        lookalikes = [
            "bash -c '\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/cab/guard.py'",
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/../../tmp/contoso.sh',
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cabinet/contoso.py',
            '"$CLAUDE_PROJECT_DIR"/.claude/hooks/cab/guard.py\nrm -rf /',
            "$CLAUDE_PROJECT_DIR/.claude/hooks/cab/guard.py",
        ]
        group = {"hooks": [{"type": "command", "command": c} for c in lookalikes]}
        result = self.with_user_group(group)
        self.assert_clean(result)
        merged = json.loads(by_path(result)[SETTINGS].data)
        self.assertEqual(merged["hooks"]["PreToolUse"][1], group)
        self.assertEqual(merged["hooks"]["PreToolUse"][2], OURS["hooks"]["PreToolUse"][0])

    def test_bundle_hook_must_be_an_owned_command(self) -> None:
        ours = copy.deepcopy(OURS)
        ours["hooks"]["Stop"][0]["hooks"][0]["command"] = "python3 /tmp/contoso.py"
        result = plan(make_bundle({SETTINGS: json.dumps(ours).encode()}), {})
        self.assert_blocked(result, "bundle_settings_invalid", SETTINGS)


DEMO_PY = "simtenant/simtenant.py"
DEMO_SEED = "simtenant/seed/contoso.json"
DEMO_STATE = "simtenant/state.json"  # a person's (or the demo run's) own file: never owned
DEMO = {
    DEMO_PY: b"# fictional Contoso tenant (fixture bytes)\n",
    DEMO_SEED: b'{"tenant": "contoso.example", "users": []}\n',
}


class DemoFileTests(MergeTestCase):
    """R3 reference fix: the two simtenant demo files are exact generator-owned paths with
    the same G4/G7/G8 rules as every owned file; nothing else below simtenant/ is touched."""

    def installed(self, extra: dict | None = None) -> tuple[dict, Manifest]:
        start = dict(extra or {})
        first = plan(make_bundle(DEMO), start)
        self.assert_clean(first)
        return applied(start, first), first.manifest

    def test_created_owned_and_idempotent(self) -> None:
        state = {DEMO_STATE: b'{"run": 1}\n', "simtenant/seed/fabrikam.json": b"{}\n"}
        result = plan(make_bundle(DEMO), state)
        self.assert_clean(result)
        actions = by_path(result)
        for path, data in DEMO.items():
            self.assertEqual((actions[path].kind, actions[path].data), ("create", data))
            self.assertEqual(result.manifest.files[path], sha256_hex(data))
            self.assertNotIn(path, result.manifest.offered)
        for path in state:
            self.assertNotIn(path, actions)
            self.assertNotIn(path, result.manifest.files)
        tree = applied(state, result)
        again = plan(make_bundle(DEMO), tree, result.manifest)
        self.assertTrue(again.nothing_to_do, (again.actions, again.notes))
        self.assertFalse(again.manifest_changed)

    def test_other_simtenant_paths_refused_in_the_bundle(self) -> None:
        for bad in (
            DEMO_STATE,
            "simtenant/seed/fabrikam.json",
            "simtenant/seed/contoso.json.bak",
            "simtenant/Simtenant.py",
            "Simtenant/simtenant.py",
            "simtenant/__pycache__/simtenant.cpython-312.pyc",
            "simtenant/seed/contoso.json.cab-new",
        ):
            with self.subTest(bad=bad):
                result = plan(make_bundle({**DEMO, bad: b"x"}), {})
                self.assert_blocked(result, "bundle_path_refused", bad)

    def test_unowned_existing_demo_file_collides(self) -> None:
        for path in DEMO:
            for data in (DEMO[path], b"a person's own copy\n"):
                with self.subTest(path=path, same=data == DEMO[path]):
                    result = plan(make_bundle(DEMO), {path: data})
                    self.assert_blocked(result, "unowned_collision", path)

    def test_case_variant_existing_demo_path_blocks(self) -> None:
        for variant, path in (
            ("Simtenant/simtenant.py", DEMO_PY),
            ("simtenant/Seed/Contoso.json", DEMO_SEED),
        ):
            with self.subTest(variant=variant):
                result = plan(make_bundle(DEMO), {variant: b"Contoso file\n"})
                self.assert_blocked(result, "case_collision", path)

    def test_symlinked_or_special_demo_targets_and_parents_block(self) -> None:
        for existing, code, where in (
            ({"simtenant": NodeKind.SYMLINK}, "parent_symlink", None),
            ({"simtenant/seed": NodeKind.SYMLINK}, "parent_symlink", None),
            ({"simtenant": b"not a folder\n"}, "parent_not_directory", "simtenant"),
            ({DEMO_SEED: NodeKind.SYMLINK}, "target_symlink", DEMO_SEED),
            ({DEMO_PY: NodeKind.DIRECTORY}, "target_is_directory", DEMO_PY),
            ({DEMO_PY: NodeKind.OTHER}, "target_not_regular", DEMO_PY),
        ):
            with self.subTest(existing=existing):
                self.assert_blocked(plan(make_bundle(DEMO), existing), code, where)

    def test_unchanged_demo_file_is_updated(self) -> None:
        tree, manifest = self.installed()
        newer = b'{"tenant": "contoso.example", "users": [{"upn": "adele@contoso.example"}]}\n'
        result = plan(make_bundle({**DEMO, DEMO_SEED: newer}), tree, manifest)
        self.assert_clean(result)
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("update", DEMO_SEED)])
        self.assertEqual(result.manifest.files[DEMO_SEED], sha256_hex(newer))
        self.assertEqual(result.manifest.files[DEMO_PY], manifest.files[DEMO_PY])

    def test_edited_demo_file_drifts_to_a_proposal(self) -> None:
        tree, manifest = self.installed()
        tree[DEMO_SEED] = b'{"tenant": "contoso.example", "users": ["edited"]}\n'
        result = plan(make_bundle(DEMO), tree, manifest)
        self.assertEqual(result.blockers, ())
        self.assertEqual(result.conflicts, (Issue("owned_modified", DEMO_SEED),))
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("propose", DEMO_SEED + NEW)])
        self.assertEqual(by_path(result)[DEMO_SEED + NEW].data, DEMO[DEMO_SEED])
        self.assertEqual(result.manifest.files[DEMO_SEED], manifest.files[DEMO_SEED])
        self.assertEqual(result.resolvable, (DEMO_SEED,))
        taken = plan(make_bundle(DEMO), tree, manifest, take_new={DEMO_SEED})
        self.assert_clean(taken)
        self.assertEqual(by_path(taken)[DEMO_SEED].data, DEMO[DEMO_SEED])

    def test_deleted_demo_file_is_a_conflict(self) -> None:
        tree, manifest = self.installed()
        del tree[DEMO_PY]
        result = plan(make_bundle(DEMO), tree, manifest)
        self.assertEqual(result.conflicts, (Issue("owned_missing", DEMO_PY),))
        self.assertEqual([(a.kind, a.path) for a in result.actions], [("propose", DEMO_PY + NEW)])

    def test_dropping_the_demo_module_removes_only_unchanged_demo_files(self) -> None:
        tree, manifest = self.installed({DEMO_STATE: b'{"run": 1}\n'})
        result = plan(make_bundle(), tree, manifest)
        self.assert_clean(result)
        removed = {(a.kind, a.path) for a in result.actions}
        self.assertEqual(removed, {("remove", DEMO_PY), ("remove", DEMO_SEED)})
        for path in DEMO:
            self.assertNotIn(path, result.manifest.files)
        self.assertEqual(applied(tree, result)[DEMO_STATE], b'{"run": 1}\n')
        tree[DEMO_SEED] = b"edited seed\n"
        kept = plan(make_bundle(), tree, manifest)
        self.assertEqual([(a.kind, a.path) for a in kept.actions], [("remove", DEMO_PY)])
        self.assertIn(Issue("stale_owned_released", DEMO_SEED, "modified"), kept.notes)
        self.assertNotIn(DEMO_SEED, kept.manifest.files)

    def test_uninstall_removes_only_unchanged_demo_files(self) -> None:
        tree, manifest = self.installed({DEMO_STATE: b'{"run": 1}\n'})
        tree["simtenant/seed/fabrikam.json"] = b"{}\n"
        tree[DEMO_SEED] = b"edited seed\n"
        undo = merge.plan_uninstall(manifest, tree)
        self.assertEqual(undo.blockers, ())
        removed = {a.path for a in undo.actions if a.kind == "remove"}
        self.assertIn(DEMO_PY, removed)
        self.assertNotIn(DEMO_SEED, removed)
        self.assertIn(Issue("owned_modified", DEMO_SEED), undo.drift)
        after = applied(tree, undo)
        self.assertNotIn(DEMO_PY, after)
        self.assertEqual(after[DEMO_SEED], b"edited seed\n")
        self.assertEqual(after[DEMO_STATE], b'{"run": 1}\n')
        self.assertEqual(after["simtenant/seed/fabrikam.json"], b"{}\n")
        for action in undo.actions:
            self.assertNotIn(action.path, (DEMO_STATE, "simtenant/seed/fabrikam.json"))

    def test_uninstall_does_not_follow_or_remove_unsafe_demo_nodes(self) -> None:
        tree, manifest = self.installed()
        linked = dict(tree, **{DEMO_PY: NodeKind.SYMLINK})
        undo = merge.plan_uninstall(manifest, linked)
        self.assertIn(Issue("target_symlink", DEMO_PY), undo.drift)
        self.assertNotIn(DEMO_PY, by_path(undo))
        del tree[DEMO_SEED]
        undo = merge.plan_uninstall(manifest, tree)
        self.assertIn(Issue("owned_absent", DEMO_SEED), undo.drift)
        parent = dict(tree, simtenant=NodeKind.SYMLINK)
        undo = merge.plan_uninstall(manifest, parent)
        self.assertIn(Issue("parent_symlink", "simtenant"), undo.blockers)
        self.assertEqual(undo.actions, ())

    def test_reinstall_over_a_kept_demo_edit_collides(self) -> None:
        tree, manifest = self.installed()
        tree[DEMO_SEED] = b"edited seed\n"
        after = applied(tree, merge.plan_uninstall(manifest, tree))
        again = plan(make_bundle(DEMO), after)
        self.assert_blocked(again, "unowned_collision", DEMO_SEED)


class PathSafetyTests(MergeTestCase):
    BAD_PATHS = [
        "../escape.md",
        "/abs/x.md",
        ".claude/agents/x.md.cab-new",
        ".cab/manifest.json",
        ".claude/settings.local.json",
        ".claude/SETTINGS.LOCAL.JSON",
        ".git/hooks/pre-commit",
        "changes/CHG-0001/approval.json",
        "audit/ledger/2026-11.jsonl",
        ".claude/agents//x.md",
        ".claude/agents/./x.md",
        "docs/notes.md",
        ".Claude/agents/x.md",
        "CLAUDE.MD",
        ".claude/agents/café.md",
        ".claude/agents/x md",
        ".claude/agents/",
        "",
        ".claude/agents/x\x00.md",
        "~/.claude/settings.json",
    ]

    def test_unsafe_bundle_paths_refused(self) -> None:
        for bad in self.BAD_PATHS:
            with self.subTest(bad=bad):
                self.assert_blocked(plan(make_bundle({bad: b"x"}), {}), "bundle_path_refused")

    def test_identity_guide_is_the_only_owned_docs_path(self) -> None:
        result = plan(make_bundle({"docs/identity.md": b"# Identity (fixture)\n"}), {})
        self.assertFalse(result.blockers, result.blockers)
        self.assertIn("docs/identity.md", result.manifest.files)
        for bad in ("docs/identity.md.bak", "docs/Identity.md", "docs/other.md", "docs"):
            with self.subTest(bad=bad):
                self.assert_blocked(plan(make_bundle({bad: b"x"}), {}), "bundle_path_refused")

    def test_case_colliding_bundle_paths_refused(self) -> None:
        bundle = {".claude/agents/Reviewer.md": b"a", ".claude/agents/reviewer.md": b"b"}
        self.assert_blocked(plan(bundle, {}), "bundle_case_collision")

    def test_file_and_directory_at_same_path_refused(self) -> None:
        bundle = {".claude/hooks/cab/x": b"1", ".claude/hooks/cab/x/y.py": b"2"}
        self.assert_blocked(plan(bundle, {}), "bundle_path_prefix")

    def test_non_bytes_values_raise(self) -> None:
        for value in ("text", bytearray(b"x"), None):
            with self.subTest(value=value):
                with self.assertRaises(SetupDataError):
                    plan({AGENT: value}, {})

    def test_symlinked_or_file_parents_block(self) -> None:
        self.assert_blocked(plan(make_bundle(), {".claude": NodeKind.SYMLINK}), "parent_symlink")
        self.assert_blocked(
            plan(make_bundle(), {".claude/hooks": b"x"}), "parent_not_directory", ".claude/hooks"
        )
        self.assert_blocked(plan(make_bundle(), {"policy": NodeKind.SYMLINK}), "parent_symlink")

    def test_non_regular_targets_block(self) -> None:
        for path, kind, code in (
            (AGENT, NodeKind.SYMLINK, "target_symlink"),
            (AGENT, NodeKind.OTHER, "target_not_regular"),
            (GUARD_FILE, NodeKind.DIRECTORY, "target_is_directory"),
            (SETTINGS, NodeKind.SYMLINK, "target_symlink"),
            (POLICY, NodeKind.SYMLINK, "target_symlink"),
        ):
            with self.subTest(path=path, kind=kind):
                self.assert_blocked(plan(make_bundle(), {path: kind}), code, path)

    def test_case_variant_existing_path_blocks(self) -> None:
        existing = {".Claude/Agents/Safety-Reviewer.md": b"Contoso file\n"}
        self.assert_blocked(plan(make_bundle(), existing), "case_collision", AGENT)

    def test_paths_to_inspect_covers_parents_and_proposals(self) -> None:
        paths = merge.paths_to_inspect([AGENT, "../bad"], None)
        for expected in (
            ".claude",
            ".claude/agents",
            AGENT,
            AGENT + NEW,
            SETTINGS,
            CLAUDE,
            CLAUDE + NEW,
        ):
            self.assertIn(expected, paths)
        self.assertNotIn("../bad", paths)
        self.assertEqual(list(paths), sorted(paths))


if __name__ == "__main__":
    unittest.main()
