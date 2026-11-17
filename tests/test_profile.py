"""S8 profile schema: strict types, unknown/duplicate keys, bounds, safe list entries, demo
only in an explicit reference context. Files are created only under <repo>/.local/test-tmp.
All data is fictional Contoso data."""

from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.setup import profile, tomlw  # noqa: E402
from cab_of_one.setup.profile import ProfileError  # noqa: E402

USER = {
    "schema": 1,
    "org": {"name": "Contoso", "it_team": "small"},
    "systems": {
        "entra": True,
        "exchange_online": True,
        "intune": False,
        "sharepoint_teams": False,
        "azure": False,
        "demo_simtenant": False,
    },
    "surfaces": {
        "powershell_modules": ["Microsoft.Graph"],
        "azure_cli": False,
        "graph_http": True,
        "mcp_write_servers": [],
    },
    "identity": {"agent_identity": "read-only", "deny_read_paths": ["./secrets/**"]},
    "approval": {"approvers": "self", "approval_ttl_hours": 4},
    "session": {
        "permission_mode": "manual",
        "git": True,
        "multi_machine": False,
        "sync_folder": False,
        "ticketing": "none",
    },
    "changes": {"routine": [], "extra_critical": ["break-glass"]},
}


def user(**changes: Any) -> dict[str, Any]:
    """A copy of USER with ``{"table.key": value}`` changes (``...`` deletes the key)."""
    doc = copy.deepcopy(USER)
    for path, value in changes.items():
        table, key = path.split("__")
        if value is ...:
            del doc[table][key]
        else:
            doc[table][key] = value
    return doc


def encode(doc: dict[str, Any]) -> bytes:
    return tomlw.dumps(doc).encode("utf-8")


class LoadTests(unittest.TestCase):
    def assertRefused(self, data: bytes, code: str, field: str | None = None) -> None:
        with self.assertRaises(ProfileError) as ctx:
            profile.load_profile(data)
        self.assertEqual(ctx.exception.code, code)
        if field is not None:
            self.assertEqual(ctx.exception.field, field)

    def test_valid_user_profile(self) -> None:
        p = profile.load_profile(encode(USER))
        self.assertIsNone(p.reference)
        self.assertIs(p["systems.entra"], True)
        self.assertEqual(p["approval.approval_ttl_hours"], 4)
        self.assertEqual(p["identity.deny_read_paths"], ("./secrets/**",))

    def test_reference_profile_from_repo(self) -> None:
        p = profile.load_reference_profile("contoso-solo", ROOT)
        self.assertEqual(p.reference, "contoso-solo")
        self.assertIs(p["systems.demo_simtenant"], True)
        self.assertEqual(p["changes.routine"], ("forwarding-removal", "group-add-allowlisted"))
        self.assertEqual(p["session.permission_mode"], "bypass-guarded")

    def test_same_file_without_reference_context_is_refused(self) -> None:
        data = (ROOT / "profiles" / "contoso-solo.toml").read_bytes()
        self.assertRefused(data, "demo_requires_reference", "systems.demo_simtenant")

    def test_demo_in_any_user_profile_is_refused(self) -> None:
        self.assertRefused(encode(user(systems__demo_simtenant=True)), "demo_requires_reference")

    def test_unknown_reference_name(self) -> None:
        for name in ("contoso-team", "../profiles/contoso-solo", "", None):
            with self.assertRaises(ProfileError) as ctx:
                profile.load_reference_profile(name, ROOT)  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "reference_unknown")

    def test_unknown_keys(self) -> None:
        doc = user()
        doc["core"] = {"enabled": False}
        self.assertRefused(encode(doc), "unknown_key", "<top level>")
        doc = user()
        doc["session"]["disable_guard"] = True
        self.assertRefused(encode(doc), "unknown_key", "session")
        doc = user()
        doc["systems"]["floor"] = False
        self.assertRefused(encode(doc), "unknown_key", "systems")

    def test_missing_keys(self) -> None:
        self.assertRefused(encode(user(session__git=...)), "missing_key", "session.git")
        doc = user()
        del doc["changes"]
        self.assertRefused(encode(doc), "missing_key", "changes")
        doc = user()
        del doc["schema"]
        self.assertRefused(encode(doc), "missing_key", "schema")

    def test_duplicate_keys_and_tables(self) -> None:
        text = encode(USER).decode()
        dup_key = text.replace("git = true\n", "git = true\ngit = true\n")
        self.assertRefused(dup_key.encode(), "syntax")
        dup_table = text + '\n[org]\nname = "Contoso"\n'
        self.assertRefused(dup_table.encode(), "syntax")

    def test_schema_version_exact_int(self) -> None:
        for value in (2, 0, True, "1", 1.0):
            doc = user()
            doc["schema"] = value
            self.assertRefused(encode(doc), "schema_version")

    def test_booleans_are_exact(self) -> None:
        for value in (1, 0, "true", 1.0):
            self.assertRefused(encode(user(systems__entra=value)), "type_bool", "systems.entra")

    def test_integers_are_exact_and_bounded(self) -> None:
        self.assertRefused(encode(user(approval__approval_ttl_hours=True)), "type_int")
        self.assertRefused(encode(user(approval__approval_ttl_hours=4.0)), "type_int")
        self.assertRefused(encode(user(approval__approval_ttl_hours="4")), "type_int")
        for value in (0, 25, -1, 2**40):
            self.assertRefused(encode(user(approval__approval_ttl_hours=value)), "out_of_range")
        for value in (1, 24):
            p = profile.load_profile(encode(user(approval__approval_ttl_hours=value)))
            self.assertEqual(p["approval.approval_ttl_hours"], value)

    def test_enums(self) -> None:
        cases = {
            "session__permission_mode": ("bypass", "Manual", "", "dontAsk"),
            "identity__agent_identity": ("unknown", "ADMIN"),
            "org__it_team": ("large", "6+"),
            "approval__approvers": ("cab",),
            "session__ticketing": ("email",),
        }
        for key, values in cases.items():
            for value in values:
                self.assertRefused(encode(user(**{key: value})), "bad_choice")
        self.assertRefused(encode(user(session__permission_mode=True)), "bad_choice")

    def test_org_name(self) -> None:
        for name in ("Contoso Ltd.", "A", "Contoso & Partners", "O'Neil-IT, Contoso"):
            self.assertEqual(profile.load_profile(encode(user(org__name=name)))["org.name"], name)
        for name in ("", " Contoso", "Contoso ", "$org", "Con\ntoso", "<b>", "x" * 65, "Café"):
            self.assertRefused(encode(user(org__name=name)), "bad_name", "org.name")

    def test_deny_read_paths_must_be_safe(self) -> None:
        good = ["./secrets/**", "./.env", "./certs/*.pfx", "./a-b/c_d/e.pem"]
        p = profile.load_profile(encode(user(identity__deny_read_paths=good)))
        self.assertEqual(p["identity.deny_read_paths"], tuple(sorted(good)))
        bad = [
            "/etc/passwd",
            "~/secrets/**",
            "secrets/**",
            "./",
            "./../x",
            "./a/../b",
            "./a/./b",
            "./a//b",
            "./a b",
            "./x)",
            "./x(",
            './x"',
            "./a\\b",
            "./a\nb",
            "//x",
            "./" + "a/" * 16 + "b",
            "./" + "a" * 199,
        ]
        for value in bad:
            self.assertRefused(
                encode(user(identity__deny_read_paths=[value])),
                "bad_entry",
                "identity.deny_read_paths",
            )

    def test_list_entries(self) -> None:
        self.assertRefused(
            encode(user(changes__routine=["forwarding-removal", "forwarding-removal"])),
            "duplicate_entry",
        )
        self.assertRefused(encode(user(changes__routine=["delete-everything"])), "bad_entry")
        self.assertRefused(encode(user(changes__extra_critical=[1])), "bad_entry")
        self.assertRefused(encode(user(changes__routine="forwarding-removal")), "type_list")
        self.assertRefused(encode(user(surfaces__mcp_write_servers=["contoso admin"])), "bad_entry")
        self.assertRefused(
            encode(user(surfaces__mcp_write_servers=[f"s{i}" for i in range(65)])), "too_many"
        )
        self.assertRefused(encode(user(surfaces__powershell_modules=["Az;rm"])), "bad_entry")

    def test_lists_are_sorted_so_order_does_not_matter(self) -> None:
        a = profile.load_profile(
            encode(user(changes__extra_critical=["finance-groups", "break-glass"]))
        )
        b = profile.load_profile(
            encode(user(changes__extra_critical=["break-glass", "finance-groups"]))
        )
        self.assertEqual(a.canonical_toml(), b.canonical_toml())
        self.assertEqual(a.sha256, b.sha256)

    def test_profile_needs_a_write_surface(self) -> None:
        doc = user()
        for key in doc["systems"]:
            doc["systems"][key] = False
        doc["surfaces"].update(
            powershell_modules=[], azure_cli=False, graph_http=False, mcp_write_servers=[]
        )
        self.assertRefused(encode(doc), "no_write_surface")

    def test_no_field_names_a_floor_switch(self) -> None:
        # The behavioural check is G9 in test_render; this guards the schema surface.
        words = {"core", "floor", "guard", "hook", "hooks", "disable", "disabled", "enabled"}
        for path in profile.FIELDS:
            self.assertFalse(words & set(path.replace(".", "_").split("_")), path)

    def test_encoding_and_size(self) -> None:
        self.assertRefused(b"\xef\xbb\xbf" + encode(USER), "bom")
        self.assertRefused(b"\xff\xfe", "encoding")
        self.assertRefused(encode(USER) + b"#" * (64 * 1024), "too_large")
        self.assertRefused(b"schema = ", "syntax")
        dated = encode(USER).replace(b"approval_ttl_hours = 4", b"approval_ttl_hours = 1979-05-27")
        self.assertRefused(dated, "type_int")

    def test_source_type(self) -> None:
        for value in (None, 1, ["x"]):
            with self.assertRaises(ProfileError) as ctx:
                profile.load_profile(value)  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "source_type")


class ModelTests(unittest.TestCase):
    def test_immutable(self) -> None:
        p = profile.load_profile(encode(USER))
        with self.assertRaises(TypeError):
            p.values["systems.entra"] = False  # type: ignore[index]
        with self.assertRaises(AttributeError):
            p.reference = "contoso-solo"  # type: ignore[misc]
        self.assertIsInstance(p["identity.deny_read_paths"], tuple)

    def test_canonical_round_trip(self) -> None:
        p = profile.load_profile(encode(USER))
        again = profile.load_profile(p.canonical_toml())
        self.assertEqual(dict(p.values), dict(again.values))
        self.assertEqual(p.sha256, again.sha256)

    def test_revalidate_refuses_hand_built_models(self) -> None:
        p = profile.load_profile(encode(USER))
        values = dict(p.values)
        values["systems.demo_simtenant"] = True
        with self.assertRaises(ProfileError) as ctx:
            profile.revalidate(profile.Profile(values, None))
        self.assertEqual(ctx.exception.code, "demo_requires_reference")
        with self.assertRaises(ProfileError) as ctx:
            profile.revalidate(profile.Profile(values, "made-up"))
        self.assertEqual(ctx.exception.code, "reference_unknown")
        values = dict(p.values)
        values["systems.entra"] = 1
        with self.assertRaises(ProfileError) as ctx:
            profile.revalidate(profile.Profile(values, None))
        self.assertEqual(ctx.exception.code, "type_bool")
        with self.assertRaises(ProfileError) as ctx:
            profile.revalidate({"systems.entra": True})
        self.assertEqual(ctx.exception.code, "not_profile")


class FileTests(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s8-profile-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_path_load(self) -> None:
        path = self.tmp / "profile.toml"
        path.write_bytes(encode(USER))
        self.assertEqual(profile.load_profile(path)["org.name"], "Contoso")
        self.assertEqual(profile.load_profile(str(path))["org.name"], "Contoso")

    def test_symlink_and_missing_and_directory(self) -> None:
        real = self.tmp / "real.toml"
        real.write_bytes(encode(USER))
        link = self.tmp / "link.toml"
        os.symlink(real, link)
        for path, code in (
            (link, "profile_symlink"),
            (self.tmp / "missing.toml", "profile_missing"),
            (self.tmp, "profile_not_regular"),
        ):
            with self.assertRaises(ProfileError) as ctx:
                profile.load_profile(path)
            self.assertEqual(ctx.exception.code, code)

    def test_reference_folder_must_be_real(self) -> None:
        (self.tmp / "elsewhere").mkdir()
        shutil.copy(ROOT / "profiles" / "contoso-solo.toml", self.tmp / "elsewhere")
        os.symlink(self.tmp / "elsewhere", self.tmp / "profiles")
        with self.assertRaises(ProfileError) as ctx:
            profile.load_reference_profile("contoso-solo", self.tmp)
        self.assertEqual(ctx.exception.code, "reference_missing")


if __name__ == "__main__":
    unittest.main()
