"""Behavioural tests for simtenant (stdlib unittest; also collectable by pytest).

    python3 -m unittest discover -s tests -p test_simtenant.py

Tests observe resulting state (via reads and the raw state file) and time
boundaries through an injected clock. Temporary files live only under
<project>/.local/test-tmp/. No network, no user files.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "simtenant" / "simtenant.py"
SEED = ROOT / "simtenant" / "seed" / "contoso.json"
TMP_ROOT = ROOT / ".local" / "test-tmp"
DAY = 24 * 60 * 60
T0 = 1_800_000_000.0


def _load_module():
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # do not drop __pycache__ next to the module
    try:
        spec = importlib.util.spec_from_file_location("simtenant_under_test", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


st = _load_module()


class FakeClock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def set(self, now: float) -> None:
        self.now = now


def user_record(n: int, **overrides):
    record = {
        "display_name": f"Test User {n}",
        "given_name": "Test",
        "surname": f"User{n}",
        "user_principal_name": f"test.user{n}@contoso.example",
        "mail": None,
        "department": None,
        "job_title": None,
        "account_enabled": True,
        "usage_location": "US",
        "manager_id": None,
    }
    record.update(overrides)
    return record


def group_record(**overrides):
    record = {
        "display_name": "Project Falcon",
        "description": None,
        "mail_nickname": "project-falcon",
        "mail": None,
        "group_type": "security",
        "mail_enabled": False,
        "security_enabled": True,
    }
    record.update(overrides)
    return record


def _norm(text: str) -> str:
    return re.sub(r"[^0-9a-z]", "", text.casefold())


class SimTenantCase(unittest.TestCase):
    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="simtenant-", dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state.json"
        self.clock = FakeClock(T0)
        self.tenant = st.Tenant(self.state, clock=self.clock)
        self.tenant.reset(SEED)

    # -- observation helpers

    def raw(self) -> bytes:
        return self.state.read_bytes()

    def backend(self) -> dict:
        return json.loads(self.raw())

    def fingerprint(self):
        info = os.stat(self.state)
        return hashlib.sha256(self.raw()).hexdigest(), info.st_mtime_ns, info.st_ino

    def get(self, resource, obj_id):
        return self.tenant.get_object(resource, obj_id)

    def obj(self, resource, obj_id):
        return self.get(resource, obj_id)["object"]

    def status(self, resource, obj_id) -> str:
        try:
            return self.get(resource, obj_id)["status"]
        except st.SimTenantError as exc:
            if exc.exit_code == st.EXIT_NOT_FOUND:
                return "not_found"
            raise

    def ids(self, resource, deleted=False):
        return [item["id"] for item in self.tenant.list_objects(resource, deleted=deleted)["items"]]

    def write(self, *args, **kwargs):
        return self.tenant.write(*args, **kwargs)

    def assertRefused(self, fn, *args, **kwargs):
        before = self.fingerprint()
        with self.assertRaises(st.SimTenantError) as ctx:
            fn(*args, **kwargs)
        self.assertNotEqual(ctx.exception.exit_code, 0)
        self.assertEqual(
            self.fingerprint(), before, "a refused command must leave the state file untouched"
        )
        return ctx.exception

    def cli(self, *args, state=None, cwd=None):
        cmd = [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            "--state",
            str(state if state is not None else self.state),
            *args,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=str(cwd or self.tmp)
        )
        try:
            payload = json.loads(proc.stdout)
        except ValueError:
            self.fail(f"stdout is not JSON: {proc.stdout!r} (stderr {proc.stderr!r})")
        self.assertIsInstance(payload, dict)
        return proc.returncode, payload


class TestSeed(SimTenantCase):
    def test_seed_is_fictional_contoso_with_immutable_ids(self):
        id_pattern = re.compile(r"^(u|g|mbx|pol|lic)-[0-9]+$")
        for resource in ("users", "groups", "mailboxes", "policies", "licenses"):
            ids = self.ids(resource)
            self.assertTrue(ids, resource)
            for obj_id in ids:
                self.assertRegex(obj_id, id_pattern)
        self.assertIn("u-1042", self.ids("users"))
        for item in self.tenant.list_objects("users")["items"]:
            self.assertTrue(item["object"]["user_principal_name"].endswith("@contoso.example"))

    def test_seed_contains_lookalike_groups_with_different_ids(self):
        buckets = {}
        for item in self.tenant.list_objects("groups")["items"]:
            buckets.setdefault(_norm(item["object"]["display_name"]), set()).add(item["id"])
        self.assertTrue(any(len(ids) >= 2 for ids in buckets.values()), buckets)

    def test_reset_restores_seed_after_changes(self):
        original = self.obj("users", "u-1142")
        self.write("set", "users", "u-1142", field="job_title", value="Changed")
        self.write("purge", "users", "u-1042")
        self.tenant.reset(SEED)
        self.assertEqual(self.obj("users", "u-1142")["job_title"], original["job_title"])
        self.assertEqual(self.status("users", "u-1042"), "active")


class TestIdentity(SimTenantCase):
    def test_display_names_are_never_resolved_to_a_target(self):
        for text in ("Finance Approvers", "finance-approvers"):
            with self.subTest(text=text):
                err = self.assertRefused(
                    self.write, "set", "groups", text, field="description", value="x"
                )
                candidate_ids = {c["id"] for c in err.details.get("candidates", [])}
                self.assertLessEqual({"g-2001", "g-2017"}, candidate_ids)
                self.assertIsNone(err.details.get("selected"))

    def test_duplicate_user_names_and_addresses_are_refused(self):
        err = self.assertRefused(self.write, "delete", "users", "Jordan Reyes")
        candidate_ids = {c["id"] for c in err.details.get("candidates", [])}
        self.assertLessEqual({"u-1042", "u-1142"}, candidate_ids)
        self.assertRefused(self.tenant.get_object, "users", "jordan.reyes@contoso.example")
        self.assertRefused(self.write, "add", "licenses", "lic-5003", member="Jordan Reyes")
        self.assertEqual(self.status("users", "u-1042"), "active")
        self.assertEqual(self.status("users", "u-1142"), "active")

    def test_write_to_lookalike_changes_only_that_id(self):
        g2001 = self.obj("groups", "g-2001")
        self.write("add", "groups", "g-2017", member="u-1050")
        self.assertIn("u-1050", self.obj("groups", "g-2017")["members"])
        self.assertEqual(self.obj("groups", "g-2001"), g2001)

        u1042 = self.obj("users", "u-1042")
        self.write("set", "users", "u-1142", field="department", value="Marketing")
        self.assertEqual(self.obj("users", "u-1142")["department"], "Marketing")
        self.assertEqual(self.obj("users", "u-1042"), u1042)

    def test_ids_of_another_resource_or_case_are_refused(self):
        self.assertRefused(self.tenant.get_object, "groups", "u-1042")
        self.assertRefused(self.write, "delete", "users", "g-2001")
        self.assertRefused(self.write, "add", "groups", "g-2001", member="g-2017")
        self.assertRefused(self.write, "add", "licenses", "lic-5003", member="mbx-1042")
        self.assertRefused(self.write, "set", "users", "U-1042", field="job_title", value="x")


class TestCrud(SimTenantCase):
    def test_list_and_get_return_seeded_active_objects(self):
        seed = json.loads(SEED.read_text(encoding="utf-8"))
        ids = self.ids("users")
        self.assertEqual(set(ids), {u["id"] for u in seed["objects"]["users"]})
        self.assertEqual(ids, sorted(ids, key=lambda i: int(i.split("-")[1])))
        got = self.get("users", "u-1042")
        self.assertEqual(got["status"], "active")
        self.assertEqual(got["object"]["id"], "u-1042")
        self.assertEqual(self.get("user", "u-1042")["object"], got["object"])  # singular alias

    def test_set_string_and_json_values_persist(self):
        self.assertTrue(
            self.write("set", "users", "u-1142", field="job_title", value="Senior AE")["changed"]
        )
        self.write("set", "users", "u-1142", field="account_enabled", value=False)
        self.write("set", "users", "u-1142", field="manager_id", value=None)
        self.write("set", "policies", "pol-4004", field="state", value="enabled")
        self.write(
            "set",
            "policies",
            "pol-4001",
            field="controls",
            value=["require_mfa", "compliant_device"],
        )
        user = self.obj("users", "u-1142")
        self.assertEqual(user["job_title"], "Senior AE")
        self.assertIs(user["account_enabled"], False)
        self.assertIsNone(user["manager_id"])
        self.assertEqual(self.obj("policies", "pol-4004")["state"], "enabled")
        self.assertEqual(
            self.obj("policies", "pol-4001")["controls"], ["require_mfa", "compliant_device"]
        )
        fresh = st.Tenant(self.state, clock=self.clock)  # persisted, not cached
        self.assertEqual(fresh.get_object("users", "u-1142")["object"]["job_title"], "Senior AE")

    def test_set_same_value_reports_no_change_and_keeps_file(self):
        before = self.fingerprint()
        current = self.obj("users", "u-1142")["job_title"]
        result = self.write("set", "users", "u-1142", field="job_title", value=current)
        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])
        self.assertEqual(self.fingerprint(), before)

    def test_set_rejects_bad_fields_types_and_references(self):
        bad = [
            ("users", "u-1142", "no_such_field", "x"),
            ("users", "u-1142", "id", "u-1999"),
            ("users", "u-1142", "created_at", "2020-01-01T00:00:00+00:00"),
            ("groups", "g-2001", "members", ["u-1007"]),
            ("groups", "g-2001", "group_type", "distribution"),
            ("users", "u-1142", "account_enabled", "yes"),
            ("users", "u-1142", "display_name", ""),
            ("users", "u-1142", "usage_location", None),
            ("licenses", "lic-5001", "seats_total", -1),
            ("licenses", "lic-5001", "seats_total", True),
            ("policies", "pol-4001", "state", "maybe"),
            ("users", "u-1142", "manager_id", "u-9999"),
            ("users", "u-1142", "manager_id", "u-1142"),
            ("users", "u-1142", "manager_id", "g-2001"),
            ("users", "u-1142", "user_principal_name", "sam.okafor@contoso.example"),
            ("users", "u-1142", "mail", "not-an-address"),
        ]
        for resource, obj_id, field, value in bad:
            with self.subTest(field=field, value=value):
                self.assertRefused(self.write, "set", resource, obj_id, field=field, value=value)

    def test_set_missing_target_is_not_found(self):
        err = self.assertRefused(self.write, "set", "users", "u-9999", field="job_title", value="x")
        self.assertEqual(err.exit_code, st.EXIT_NOT_FOUND)

    def test_add_record_creates_object_under_new_id(self):
        result = self.write("add", "users", "u-1200", record=user_record(1200))
        self.assertTrue(result["ok"])
        self.assertIn("u-1200", self.ids("users"))
        created = datetime.fromisoformat(self.obj("users", "u-1200")["created_at"]).timestamp()
        self.assertEqual(created, T0)
        self.write("add", "groups", "g-2100", record=group_record())
        self.assertEqual(self.obj("groups", "g-2100")["members"], [])

    def test_add_record_rejects_invalid_records(self):
        missing = user_record(1201)
        del missing["usage_location"]
        cases = [
            ("users", "u-1201", missing),
            ("users", "u-1201", user_record(1201, favourite_colour="blue")),
            ("users", "u-1201", user_record(1201, id="u-1202")),
            (
                "users",
                "u-1201",
                user_record(1201, user_principal_name="sam.okafor@contoso.example"),
            ),
            ("users", "u-1201", ["not", "an", "object"]),
            ("users", "g-2100", user_record(2100)),
            ("groups", "g-2100", group_record(members=["u-1007"])),
            ("groups", "g-2100", group_record(mail_nickname="finance-approvers")),
            (
                "mailboxes",
                "mbx-2100",
                {
                    "display_name": "Orphan",
                    "owner_id": "u-9999",
                    "primary_smtp_address": "orphan@contoso.example",
                    "recipient_type": "user",
                    "forwarding_smtp_address": None,
                    "deliver_to_mailbox_and_forward": False,
                    "litigation_hold_enabled": False,
                    "archive_enabled": False,
                },
            ),
        ]
        for resource, obj_id, record in cases:
            with self.subTest(resource=resource, obj_id=obj_id):
                self.assertRefused(self.write, "add", resource, obj_id, record=record)

    def test_reads_never_modify_state(self):
        self.write("delete", "users", "u-1042")
        before = self.fingerprint()
        for resource in ("users", "groups", "mailboxes", "policies", "licenses"):
            self.tenant.list_objects(resource)
            self.tenant.list_objects(resource, deleted=True)
        self.get("users", "u-1042")
        self.get("groups", "g-2001")
        self.clock.set(T0 + 31 * DAY)  # expiry is visible to reads but not persisted by them
        self.assertEqual(self.status("users", "u-1042"), "not_found")
        self.assertNotIn("u-1042", self.ids("users", deleted=True))
        with self.assertRaises(st.SimTenantError):
            self.get("users", "Jordan Reyes")
        rc, _ = self.cli("list", "users")
        self.assertEqual(rc, 0)
        rc, _ = self.cli("get", "groups", "g-2017")
        self.assertEqual(rc, 0)
        self.assertEqual(self.fingerprint(), before)


class TestMembership(SimTenantCase):
    def test_add_and_remove_group_member(self):
        self.write("add", "groups", "g-2005", member="u-1023")
        self.assertIn("u-1023", self.obj("groups", "g-2005")["members"])
        self.write("remove", "groups", "g-2005", member="u-1023")
        self.assertNotIn("u-1023", self.obj("groups", "g-2005")["members"])
        self.assertEqual(self.obj("groups", "g-2005")["members"], ["u-1007"])

    def test_duplicate_add_and_missing_remove_are_refused(self):
        self.assertRefused(self.write, "add", "groups", "g-2001", member="u-1042")
        self.assertRefused(self.write, "remove", "groups", "g-2005", member="u-1042")
        self.assertRefused(self.write, "add", "groups", "g-2001")
        self.assertRefused(
            self.write, "add", "groups", "g-2001", member="u-1050", record=group_record()
        )

    def test_member_must_be_an_active_user(self):
        self.assertRefused(self.write, "add", "groups", "g-2005", member="u-9999")
        self.write("delete", "users", "u-1050")
        self.assertRefused(self.write, "add", "groups", "g-2005", member="u-1050")
        self.assertNotIn("u-1050", self.obj("groups", "g-2005")["members"])

    def test_policy_scope_and_mailbox_delegates(self):
        self.write("add", "policies", "pol-4001", member="g-2001")
        self.assertIn("g-2001", self.obj("policies", "pol-4001")["include"])
        self.write("add", "mailboxes", "mbx-1142", member="u-1023")
        self.assertIn("u-1023", self.obj("mailboxes", "mbx-1142")["delegates"])
        self.write("remove", "mailboxes", "mbx-1042", member="u-1023")
        self.assertEqual(self.obj("mailboxes", "mbx-1042")["delegates"], [])

    def test_users_have_no_member_list(self):
        self.assertRefused(self.write, "add", "users", "u-1042", member="u-1007")


class TestLicenses(SimTenantCase):
    def test_assign_and_unassign_with_seat_limit(self):
        self.write("add", "licenses", "lic-5003", member="u-1142")
        self.assertEqual(self.obj("licenses", "lic-5003")["assigned_to"], ["u-1142"])
        self.assertRefused(self.write, "add", "licenses", "lic-5003", member="u-1015")
        self.assertEqual(self.obj("licenses", "lic-5003")["assigned_to"], ["u-1142"])
        self.write("remove", "licenses", "lic-5003", member="u-1142")
        self.assertEqual(self.obj("licenses", "lic-5003")["assigned_to"], [])

    def test_seat_total_cannot_drop_below_assignments(self):
        assigned = len(self.obj("licenses", "lic-5001")["assigned_to"])
        self.assertRefused(
            self.write, "set", "licenses", "lic-5001", field="seats_total", value=assigned - 1
        )
        self.write("set", "licenses", "lic-5001", field="seats_total", value=assigned)
        self.assertEqual(self.obj("licenses", "lic-5001")["seats_total"], assigned)


class TestLie(SimTenantCase):
    def test_lie_reports_success_without_touching_state(self):
        before = self.fingerprint()
        old = self.obj("users", "u-1142")
        result = self.write(
            "set", "users", "u-1142", field="job_title", value="Lied Title", lie=True
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["changed"])
        self.assertEqual(result["object"]["job_title"], "Lied Title")
        self.assertEqual(self.fingerprint(), before)
        self.assertEqual(self.obj("users", "u-1142"), old)

    def test_lie_applies_to_every_write_verb(self):
        self.write("delete", "users", "u-1050")
        cases = [
            ("delete", "users", "u-1042", {}),
            ("purge", "users", "u-1042", {}),
            ("purge", "users", "u-1042", {"dry_run": True}),
            ("restore", "users", "u-1050", {}),
            ("add", "groups", "g-2005", {"member": "u-1023"}),
            ("remove", "groups", "g-2001", {"member": "u-1042"}),
            ("add", "users", "u-1300", {"record": user_record(1300)}),
            ("set", "users", "u-1142", {"field": "job_title", "value": "x", "delay_seconds": 60}),
        ]
        for verb, resource, obj_id, extra in cases:
            with self.subTest(verb=verb, extra=extra):
                before = self.fingerprint()
                self.assertTrue(self.write(verb, resource, obj_id, lie=True, **extra)["ok"])
                self.assertEqual(self.fingerprint(), before)
        self.assertEqual(self.status("users", "u-1042"), "active")
        self.assertEqual(self.status("users", "u-1050"), "soft_deleted")
        self.assertEqual(self.status("users", "u-1300"), "not_found")
        self.assertNotIn("u-1023", self.obj("groups", "g-2005")["members"])
        self.assertIn("u-1042", self.obj("groups", "g-2001")["members"])

    def test_lie_does_not_hide_invalid_input(self):
        self.assertRefused(
            self.write, "set", "users", "u-9999", field="job_title", value="x", lie=True
        )

    def test_cli_lie_exits_zero_and_changes_nothing(self):
        before = self.fingerprint()
        rc, payload = self.cli("purge", "users", "u-1042", "--lie")
        self.assertEqual(rc, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(self.fingerprint(), before)
        rc, payload = self.cli("get", "users", "u-1042")
        self.assertEqual((rc, payload["status"]), (0, "active"))


class TestReplicationDelay(SimTenantCase):
    def test_reads_see_old_value_until_delay_elapses(self):
        old = self.obj("users", "u-1142")["job_title"]
        self.assertTrue(
            self.write(
                "set",
                "users",
                "u-1142",
                field="job_title",
                value="Regional Manager",
                delay_seconds=120,
            )["ok"]
        )
        self.assertEqual(
            self.backend()["objects"]["users"]["u-1142"]["job_title"], "Regional Manager"
        )
        self.assertEqual(self.obj("users", "u-1142")["job_title"], old)
        self.clock.set(T0 + 119.5)
        before = self.fingerprint()
        self.assertEqual(self.obj("users", "u-1142")["job_title"], old)
        self.assertEqual(self.fingerprint(), before)
        self.clock.set(T0 + 120)
        self.assertEqual(self.obj("users", "u-1142")["job_title"], "Regional Manager")

    def test_delayed_delete_and_purge(self):
        self.write("delete", "users", "u-1050", delay_seconds=60)
        self.assertEqual(self.status("users", "u-1050"), "active")
        self.assertIn("u-1050", self.ids("users"))
        self.clock.set(T0 + 60)
        self.assertEqual(self.status("users", "u-1050"), "soft_deleted")

        self.write("purge", "users", "u-1142", delay_seconds=30)
        self.assertEqual(self.status("users", "u-1142"), "active")
        self.assertIn("u-1142", self.obj("groups", "g-2010")["members"])
        self.clock.set(T0 + 90)
        self.assertEqual(self.status("users", "u-1142"), "not_found")
        self.assertNotIn("u-1142", self.obj("groups", "g-2010")["members"])

    def test_cli_delay_observed_without_sleep(self):
        old = self.obj("users", "u-1142")["job_title"]
        rc, payload = self.cli(
            "set",
            "users",
            "u-1142",
            "--field",
            "job_title",
            "--value",
            "Delayed Title",
            "--delay-seconds",
            "3600",
        )
        self.assertEqual((rc, payload["ok"]), (0, True))
        rc, payload = self.cli("get", "users", "u-1142")
        self.assertEqual(payload["object"]["job_title"], old)
        later = st.Tenant(self.state, clock=lambda: time.time() + 3601)
        self.assertEqual(
            later.get_object("users", "u-1142")["object"]["job_title"], "Delayed Title"
        )

    def test_invalid_delay_is_refused(self):
        for bad in (-1, "soon", "nan", "inf", 10**9, True):
            with self.subTest(delay=bad):
                self.assertRefused(
                    self.write,
                    "set",
                    "users",
                    "u-1142",
                    field="job_title",
                    value="x",
                    delay_seconds=bad,
                )


class TestSoftDelete(SimTenantCase):
    def test_delete_is_soft_and_restorable_inside_30_days(self):
        self.write("delete", "users", "u-1042")
        got = self.get("users", "u-1042")
        self.assertEqual(got["status"], "soft_deleted")
        window = datetime.fromisoformat(got["purge_after"]) - datetime.fromisoformat(
            got["deleted_at"]
        )
        self.assertEqual(window.total_seconds(), 30 * DAY)
        self.assertNotIn("u-1042", self.ids("users"))
        self.assertIn("u-1042", self.ids("users", deleted=True))
        self.clock.set(T0 + 30 * DAY - 1)
        self.write("restore", "users", "u-1042")
        self.assertEqual(self.status("users", "u-1042"), "active")
        self.assertIn("u-1042", self.obj("groups", "g-2001")["members"])

    def test_restore_fails_at_exactly_30_days(self):
        self.write("delete", "users", "u-1042")
        self.clock.set(T0 + 30 * DAY)
        self.assertEqual(self.status("users", "u-1042"), "not_found")
        self.assertNotIn("u-1042", self.ids("users", deleted=True))
        self.assertRefused(self.write, "restore", "users", "u-1042")
        self.assertRefused(
            self.write,
            "add",
            "users",
            "u-1042",
            record=user_record(1042, user_principal_name="new.person@contoso.example"),
        )

    def test_invalid_soft_delete_transitions_are_refused(self):
        self.assertRefused(self.write, "restore", "users", "u-1042")
        self.write("delete", "users", "u-1042")
        self.assertRefused(self.write, "delete", "users", "u-1042")
        self.assertRefused(self.write, "set", "users", "u-1042", field="job_title", value="x")
        self.assertRefused(self.write, "add", "groups", "g-2005", member="u-1042")
        self.assertRefused(
            self.write,
            "add",
            "users",
            "u-1042",
            record=user_record(1042, user_principal_name="new.person@contoso.example"),
        )
        self.assertRefused(self.write, "delete", "users", "u-9999")


class TestPurge(SimTenantCase):
    def test_purge_active_object_is_irreversible(self):
        self.write("purge", "users", "u-1042")
        self.assertEqual(self.status("users", "u-1042"), "not_found")
        self.assertNotIn("u-1042", self.ids("users", deleted=True))
        self.assertRefused(self.write, "restore", "users", "u-1042")
        self.assertRefused(self.write, "purge", "users", "u-1042")
        self.assertRefused(
            self.write,
            "add",
            "users",
            "u-1042",
            record=user_record(1042, user_principal_name="new.person@contoso.example"),
        )
        self.assertNotIn("u-1042", self.obj("groups", "g-2001")["members"])
        self.assertNotIn("u-1042", self.obj("licenses", "lic-5001")["assigned_to"])
        self.clock.set(T0 + 365 * DAY)
        self.assertRefused(self.write, "restore", "users", "u-1042")

    def test_purge_soft_deleted_object(self):
        self.write("delete", "users", "u-1050")
        self.clock.set(T0 + DAY)
        self.write("purge", "users", "u-1050")
        self.assertEqual(self.status("users", "u-1050"), "not_found")
        self.assertRefused(self.write, "restore", "users", "u-1050")

    def test_purge_unknown_is_refused(self):
        err = self.assertRefused(self.write, "purge", "users", "u-9999")
        self.assertEqual(err.exit_code, st.EXIT_NOT_FOUND)


class TestDryRun(SimTenantCase):
    def test_purge_ignores_dry_run_and_says_so(self):
        result = self.write("purge", "users", "u-1042", dry_run=True)
        self.assertTrue(result["dry_run"]["requested"])
        self.assertFalse(result["dry_run"]["honored"])
        self.assertEqual(result.get("fault"), "dry_run_ignored")
        self.assertEqual(self.status("users", "u-1042"), "not_found")
        self.assertRefused(self.write, "restore", "users", "u-1042")

    def test_other_writes_honour_dry_run(self):
        self.write("delete", "users", "u-1050")
        cases = [
            ("set", "users", "u-1142", {"field": "job_title", "value": "x"}),
            ("add", "groups", "g-2005", {"member": "u-1023"}),
            ("remove", "groups", "g-2001", {"member": "u-1042"}),
            ("delete", "users", "u-1042", {}),
            ("restore", "users", "u-1050", {}),
            ("add", "users", "u-1300", {"record": user_record(1300)}),
        ]
        for verb, resource, obj_id, extra in cases:
            with self.subTest(verb=verb):
                before = self.fingerprint()
                result = self.write(verb, resource, obj_id, dry_run=True, **extra)
                self.assertTrue(result["ok"])
                self.assertFalse(result["changed"])
                self.assertTrue(result["dry_run"]["honored"])
                self.assertEqual(self.fingerprint(), before)
        self.assertEqual(self.status("users", "u-1050"), "soft_deleted")
        self.assertEqual(self.status("users", "u-1042"), "active")

    def test_dry_run_still_validates(self):
        self.assertRefused(
            self.write, "set", "users", "u-9999", field="job_title", value="x", dry_run=True
        )

    def test_cli_purge_dry_run_really_purges(self):
        rc, payload = self.cli("purge", "users", "u-1050", "--dry-run")
        self.assertEqual(rc, 0)
        self.assertEqual(payload.get("fault"), "dry_run_ignored")
        rc, payload = self.cli("get", "users", "u-1050")
        self.assertEqual((rc, payload["ok"]), (st.EXIT_NOT_FOUND, False))


class TestCliContract(SimTenantCase):
    def test_exit_codes_and_json(self):
        rc, payload = self.cli("get", "users", "u-1042")
        self.assertEqual((rc, payload["ok"], payload["id"]), (0, True, "u-1042"))
        rc, payload = self.cli("get", "users", "u-9999")
        self.assertEqual((rc, payload["ok"]), (st.EXIT_NOT_FOUND, False))
        self.assertIn("code", payload["error"])
        rc, payload = self.cli("restore", "users", "u-1042")
        self.assertEqual((rc, payload["ok"]), (st.EXIT_CONFLICT, False))
        rc, payload = self.cli("get", "users", "Jordan Reyes")
        self.assertEqual((rc, payload["ok"]), (st.EXIT_USAGE, False))
        rc, payload = self.cli(
            "set", "users", "u-1142", "--field", "job_title", "--value", "CLI Title"
        )
        self.assertEqual((rc, payload["ok"], payload["changed"]), (0, True, True))
        self.assertEqual(self.obj("users", "u-1142")["job_title"], "CLI Title")
        rc, payload = self.cli(
            "set", "users", "u-1142", "--field", "account_enabled", "--value", "false"
        )
        self.assertEqual(rc, 0)
        self.assertIs(self.obj("users", "u-1142")["account_enabled"], False)

    def test_missing_state_is_an_error_and_creates_nothing(self):
        missing = self.tmp / "missing.json"
        for args in (
            ("get", "users", "u-1042"),
            ("set", "users", "u-1042", "--field", "job_title", "--value", "x"),
        ):
            with self.subTest(args=args):
                rc, payload = self.cli(*args, state=missing)
                self.assertEqual((rc, payload["ok"]), (st.EXIT_STATE, False))
                self.assertFalse(missing.exists())
                self.assertFalse(Path(str(missing) + ".lock").exists())

    def test_invalid_input_is_refused_without_state_change(self):
        cases = [
            [],
            ["frobnicate", "users", "u-1042"],
            ["get", "widgets", "w-100"],
            ["get", "users"],
            ["list", "users", "u-1042"],
            ["get", "users", "u-1042", "extra"],
            ["get", "users", "u-1042", "--lie"],
            ["get", "users", "u-1042", "--bogus"],
            ["set", "users", "u-1042", "--field", "job_title"],
            ["set", "users", "u-1042", "--field", "account_enabled", "--value", "yes"],
            ["set", "users", "u-1042", "--field", "id", "--value", "u-9999"],
            ["set", "policies", "pol-4001", "--field", "state", "--value", "maybe"],
            ["set", "users", "Jordan Reyes", "--field", "job_title", "--value", "x"],
            ["add", "groups", "g-2001"],
            ["add", "groups", "g-2001", "--member", "u-1050", "--record", "{}"],
            ["add", "users", "u-1999", "--record", "{not json"],
            ["add", "users", "u-1999", "--record", '{"display_name": "Only Name"}'],
            [
                "add",
                "users",
                "u-1042",
                "--record",
                json.dumps(user_record(1042, user_principal_name="a.b@contoso.example")),
            ],
            ["delete", "users", "u-1042", "--delay-seconds", "-1"],
            ["delete", "users", "u-1042", "--delay-seconds", "soon"],
            ["delete", "users", "u-1042", "--field", "job_title"],
            ["delete", "users", "u-9999"],
            ["restore", "users", "u-1042"],
            ["remove", "groups", "g-2001", "--member", "u-1007"],
            ["purge", "users", "u-9999", "--dry-run"],
            ["reset", "--lie"],
            ["reset", "users"],
        ]
        for args in cases:
            with self.subTest(args=args):
                before = self.fingerprint()
                rc, payload = self.cli(*args)
                self.assertNotEqual(rc, 0)
                self.assertIs(payload.get("ok"), False)
                self.assertIn("code", payload.get("error", {}))
                self.assertEqual(self.fingerprint(), before)

    def test_singular_alias_and_relative_state_path(self):
        rc, payload = self.cli("get", "user", "u-1042", state="state.json", cwd=self.tmp)
        self.assertEqual((rc, payload["resource"]), (0, "users"))
        rc, payload = self.cli("list", "group", state="state.json", cwd=self.tmp)
        self.assertEqual((rc, payload["count"]), (0, len(self.ids("groups"))))

    def test_cli_reset_uses_bundled_seed(self):
        fresh = self.tmp / "fresh.json"
        rc, payload = self.cli("reset", state=fresh)
        self.assertEqual((rc, payload["ok"]), (0, True))
        rc, payload = self.cli("list", "users", state=fresh)
        seed = json.loads(SEED.read_text(encoding="utf-8"))
        self.assertEqual((rc, payload["count"]), (0, len(seed["objects"]["users"])))

    def test_run_api_returns_exit_code_and_payload(self):
        code, payload = st.run(["--state", str(self.state), "list", "groups"], clock=self.clock)
        self.assertEqual((code, payload["ok"]), (0, True))
        code, payload = st.run(
            ["--state", str(self.state), "get", "groups", "Finance Approvers"], clock=self.clock
        )
        self.assertEqual((code, payload["ok"]), (st.EXIT_USAGE, False))


class TestAtomicConcurrency(SimTenantCase):
    def test_concurrent_cli_writers_lose_no_updates(self):
        base = self.backend()["revision"]
        procs = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(SCRIPT),
                    "--state",
                    str(self.state),
                    "add",
                    "users",
                    f"u-19{n:02d}",
                    "--record",
                    json.dumps(user_record(1900 + n)),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.tmp),
            )
            for n in range(8)
        ]
        outputs = [(p.communicate(timeout=120), p.returncode) for p in procs]
        for (out, err), rc in outputs:
            self.assertEqual(rc, 0, (out, err))
            self.assertTrue(json.loads(out)["ok"])
        users = set(self.ids("users"))
        self.assertLessEqual({f"u-19{n:02d}" for n in range(8)}, users)
        self.assertEqual(self.backend()["revision"], base + 8)

    def test_concurrent_api_writers_and_readers(self):
        base = self.backend()["revision"]
        errors, parse_failures = [], []
        done = threading.Event()

        def reader():
            while not done.is_set():
                try:
                    json.loads(self.state.read_bytes())
                except Exception as exc:  # noqa: BLE001
                    parse_failures.append(repr(exc))

        def writer(n):
            try:
                st.Tenant(self.state, clock=self.clock).write(
                    "add", "users", f"u-18{n:02d}", record=user_record(1800 + n)
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

        read_thread = threading.Thread(target=reader)
        read_thread.start()
        writers = [threading.Thread(target=writer, args=(n,)) for n in range(16)]
        for thread in writers:
            thread.start()
        for thread in writers:
            thread.join(timeout=120)
        done.set()
        read_thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(parse_failures, [])
        self.assertLessEqual({f"u-18{n:02d}" for n in range(16)}, set(self.ids("users")))
        self.assertEqual(self.backend()["revision"], base + 16)

    def test_failed_replace_keeps_previous_state_and_no_temp_files(self):
        with mock.patch.object(st.os, "replace", side_effect=OSError("simulated failure")):
            self.assertRefused(
                self.write, "set", "users", "u-1142", field="job_title", value="Never"
            )
        self.assertNotEqual(self.obj("users", "u-1142")["job_title"], "Never")
        self.assertEqual([p.name for p in self.tmp.iterdir() if p.name.endswith(".tmp")], [])


if __name__ == "__main__":
    unittest.main()
