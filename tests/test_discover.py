"""S10 discovery: read-only, bounded, paths/lines/codes only. Fictional Contoso fixtures.

Files are created only under <repo>/.local/test-tmp and removed afterwards. No process,
network, tenant, home directory or real CLI lookup is used: the CLI finder is injected.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
TMP_ROOT = ROOT / ".local" / "test-tmp"

from cab_of_one.setup import discover  # noqa: E402

SECRET = "contoso-fixture-secret-value-0001"


def tree_digest(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not path.is_symlink():
                out[str(path.relative_to(root))] = path.read_bytes()
    return out


class DiscoverTests(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="s10-disc-", dir=TMP_ROOT)))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = self.tmp / "ops"
        (self.proj / "scripts").mkdir(parents=True)
        (self.proj / "docs").mkdir()
        (self.proj / "scripts" / "users.ps1").write_text(
            "# Contoso joiner script\n"
            "Connect-MgGraph -Scopes User.Read.All\n"
            "Get-MgUser -All\n"
            "Connect-ExchangeOnline\n",
            encoding="utf-8",
        )
        (self.proj / "scripts" / "rg.sh").write_text(
            "#!/bin/sh\naz group list\ncurl https://graph.microsoft.com/v1.0/users\n",
            encoding="utf-8",
        )
        (self.proj / "docs" / "runbook.md").write_text(
            "Use Invoke-MgRetireDeviceManagementManagedDevice with care.\n", encoding="utf-8"
        )

    def run_discover(self, **kw):
        return discover.discover(str(self.proj), **kw)

    def test_surfaces_paths_lines_codes_only(self) -> None:
        d = self.run_discover()
        got = {(e.path, e.line, e.code) for e in d.surfaces}
        self.assertIn(("scripts/users.ps1", 2, "ps_connect_mggraph"), got)
        self.assertIn(("scripts/users.ps1", 3, "ps_mg_cmdlet"), got)
        self.assertIn(("scripts/users.ps1", 4, "ps_connect_exchange"), got)
        self.assertIn(("scripts/rg.sh", 2, "az_cli"), got)
        self.assertIn(("scripts/rg.sh", 3, "graph_http"), got)
        self.assertIn(("docs/runbook.md", 1, "ps_intune_cmdlet"), got)
        blob = discover.to_json_bytes(d).decode("ascii")
        self.assertNotIn("Scopes", blob)
        self.assertNotIn("User.Read", blob)
        self.assertNotIn(str(self.tmp), blob)

    def test_inferred_sources_are_discovered_or_default(self) -> None:
        d = self.run_discover()
        by = {i.field: i for i in d.inferred}
        self.assertEqual(by["systems.entra"].value, True)
        self.assertEqual(by["systems.entra"].source, "discovered")
        self.assertEqual(by["systems.intune"].value, True)
        self.assertEqual(by["systems.sharepoint_teams"].source, "default")
        self.assertEqual(by["identity.agent_identity"].value, "admin")
        self.assertEqual(by["identity.agent_identity"].source, "default")
        self.assertIn("Microsoft.Graph", by["surfaces.powershell_modules"].value)
        for item in d.inferred:
            self.assertIn(item.source, ("discovered", "default"))

    def test_credentials_are_path_candidates_never_opened(self) -> None:
        (self.proj / ".env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        (self.proj / "secrets").mkdir()
        (self.proj / "secrets" / "notes.md").write_text(
            f"Connect-MgGraph {SECRET}\n", encoding="utf-8"
        )
        (self.proj / "cert.pfx").write_bytes(b"\x00\x01" + SECRET.encode())
        d = self.run_discover()
        self.assertIn(".env", d.credential_candidates)
        self.assertIn("secrets/notes.md", d.credential_candidates)
        self.assertIn("cert.pfx", d.credential_candidates)
        self.assertFalse(any(e.path.startswith("secrets/") for e in d.surfaces))
        self.assertNotIn(SECRET, discover.to_json_bytes(d).decode("ascii"))
        deny = {i.field: i for i in d.inferred}["identity.deny_read_paths"].value
        self.assertIn("./secrets/notes.md", deny)

    def test_skips_git_cab_claude_symlinks_and_binary(self) -> None:
        for folder in (".git", ".cab/setup/staged", ".claude"):
            (self.proj / folder).mkdir(parents=True, exist_ok=True)
            (self.proj / folder / "x.ps1").write_text("Connect-AzAccount\n", encoding="utf-8")
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "o.ps1").write_text("Connect-AzAccount\n", encoding="utf-8")
        os.symlink(outside, self.proj / "linked")
        os.symlink(outside / "o.ps1", self.proj / "scripts" / "l.ps1")
        (self.proj / "scripts" / "bin.ps1").write_bytes(b"Connect-AzAccount\x00\n")
        d = self.run_discover()
        self.assertFalse(any(e.code == "ps_connect_azaccount" for e in d.surfaces))
        self.assertGreaterEqual(d.counts["symlinks_skipped"], 2)
        self.assertEqual(d.counts["binary_skipped"], 1)
        self.assertTrue(d.git)

    def test_mcp_names_only(self) -> None:
        (self.proj / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "contoso-admin": {"command": "x", "env": {"API_KEY": SECRET}},
                        "bad name!": {},
                    }
                }
            ),
            encoding="utf-8",
        )
        d = self.run_discover()
        self.assertEqual(d.mcp_servers, ("contoso-admin",))
        self.assertEqual(d.mcp_status, "parsed")
        self.assertEqual(d.counts["mcp_names_dropped"], 1)
        self.assertNotIn(SECRET, discover.to_json_bytes(d).decode("ascii"))

    def test_mcp_duplicate_keys_refused(self) -> None:
        (self.proj / ".mcp.json").write_text('{"mcpServers": {"a": {}, "a": {}}}', encoding="utf-8")
        d = self.run_discover()
        self.assertEqual(d.mcp_servers, ())
        self.assertTrue(d.mcp_status.startswith("refused:"))

    def test_cli_finder_injected(self) -> None:
        seen: list[str] = []

        def finder(name: str) -> bool:
            seen.append(name)
            if name == "aws":
                raise RuntimeError("boom")
            return name == "az"

        d = self.run_discover(finder=finder)
        status = {c.name: c.status for c in d.cli}
        self.assertEqual(status, {"pwsh": "missing", "az": "available", "gam": "missing",
                                  "aws": "unchecked"})  # fmt: skip
        self.assertEqual(seen, list(discover.CLI_NAMES))
        unchecked = self.run_discover()
        self.assertTrue(all(c.status == "unchecked" for c in unchecked.cli))

    def test_read_only_and_deterministic(self) -> None:
        before = tree_digest(self.proj)
        a = discover.to_json_bytes(self.run_discover())
        b = discover.to_json_bytes(self.run_discover())
        self.assertEqual(a, b)
        self.assertEqual(before, tree_digest(self.proj))
        self.assertFalse((self.proj / ".cab").exists())

    def test_writer_only_discovery_json(self) -> None:
        d = self.run_discover()
        rel = discover.write_discovery(d, str(self.proj))
        self.assertEqual(rel, ".cab/setup/discovery.json")
        self.assertEqual((self.proj / rel).read_bytes(), discover.to_json_bytes(d))
        self.assertEqual(sorted(p.name for p in (self.proj / ".cab" / "setup").iterdir()),
                         ["discovery.json"])  # fmt: skip

    def test_writer_refuses_symlinked_setup(self) -> None:
        target = self.tmp / "elsewhere"
        target.mkdir()
        (self.proj / ".cab").mkdir()
        os.symlink(target, self.proj / ".cab" / "setup")
        with self.assertRaises(discover.DiscoveryError) as ctx:
            discover.write_discovery(self.run_discover(), str(self.proj))
        self.assertEqual(ctx.exception.code, "setup_dir_unsafe")
        self.assertEqual(list(target.iterdir()), [])

    def test_root_refusals(self) -> None:
        for bad in ("relative/path", "", str(self.proj / "missing")):
            with self.assertRaises(discover.DiscoveryError):
                discover.discover(bad)
        link = self.tmp / "link"
        os.symlink(self.proj, link)
        with self.assertRaises(discover.DiscoveryError) as ctx:
            discover.discover(str(link))
        self.assertEqual(ctx.exception.code, "root_not_directory")

    def test_unsupported_surfaces_are_notices(self) -> None:
        (self.proj / "scripts" / "g.sh").write_text("gam print users\naws s3 ls\n",
                                                     encoding="utf-8")  # fmt: skip
        d = self.run_discover()
        self.assertIn("unsupported_surface:gam", d.notices)
        self.assertIn("unsupported_surface:aws", d.notices)

    def test_result_is_immutable(self) -> None:
        d = self.run_discover()
        with self.assertRaises(FrozenInstanceError):
            d.git = False  # type: ignore[misc]
        with self.assertRaises(TypeError):
            d.counts["files_scanned"] = 0  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
