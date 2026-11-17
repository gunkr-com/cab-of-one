"""S4 strict schema: JSON/TOML decoding, policy, catalogue, plan files, events, authority files.

Pure parsing tests; no files are written. Fixture documents are fictional Contoso data.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cab_of_one.runtime import schema  # noqa: E402
from cab_of_one.runtime.schema import Invalid  # noqa: E402
from test_guard import (  # noqa: E402
    CATALOG_TOML,
    POLICY_TOML,
    T0,
    change_toml,
    observation,
    targets_csv,
)

HEX = "a" * 64


def code(fn: Any, *args: Any) -> str | None:
    try:
        fn(*args)
    except Invalid as exc:
        return exc.code
    return None


class StrictDecodingTests(unittest.TestCase):
    def test_json_refusals(self) -> None:
        cases = {
            b'{"a":1,"a":2}': "duplicate_key",
            b'{"a":NaN}': "non_finite",
            b'{"a":Infinity}': "non_finite",
            b'{"a":-Infinity}': "non_finite",
            "﻿{}".encode(): "bom",
            b"[1,2]": "not_object",
            b'"text"': "not_object",
            b"\xff\xfe": "encoding",
            b'{"a":': "syntax",
            b'{"a":' + b"[" * 40 + b"]" * 40 + b"}": "too_deep",
        }
        for data, expected in cases.items():
            with self.subTest(data=data[:20]):
                self.assertEqual(code(lambda d: schema.strict_json(d, max_bytes=4096), data),
                                 expected)  # fmt: skip
        small = lambda d: schema.strict_json(d, max_bytes=3)  # noqa: E731
        self.assertEqual(code(small, b"{ }  "), "too_large")
        self.assertEqual(code(small, "{}"), "not_bytes")

    def test_toml_refusals(self) -> None:
        cases = {
            b"a = 1\na = 2\n": "syntax",
            b"a = nan\n": "non_finite",
            b"a = inf\n": "non_finite",
            b"a = 2027-01-15\n": "value_type",
            b"a = 2027-01-15T08:00:00Z\n": "value_type",
            "﻿a = 1\n".encode(): "bom",
            b"a = [\n": "syntax",
        }
        for data, expected in cases.items():
            with self.subTest(data=data):
                self.assertEqual(code(lambda d: schema.strict_toml(d, max_bytes=4096), data),
                                 expected)  # fmt: skip

    def test_canonical_bytes_escape_line_separators(self) -> None:
        data = schema.canonical_bytes({"b": "x y z", "a": 1})
        self.assertEqual(data, b'{"a":1,"b":"x\\u2028y\\u2029z"}\n')
        self.assertEqual(data.count(b"\n"), 1)

    def test_utc_parse_is_exact(self) -> None:
        self.assertEqual(schema.utc_parse("2027-01-15T08:00:00.000Z"), 1_800_000_000.0)
        for bad in ("2027-01-15T08:00:00+00:00", "2027-01-15 08:00:00Z", 1_800_000_000, ""):
            with self.subTest(value=bad):
                self.assertEqual(code(schema.utc_parse, bad), "time")

    def test_identifier_shapes(self) -> None:
        self.assertTrue(schema.is_change_id("CHG-0001"))
        for bad in ("CHG-1", "chg-0001", "../CHG-0001", "CHG-0001\n", 1):
            self.assertFalse(schema.is_change_id(bad), bad)
        self.assertTrue(schema.is_slug("contoso-fixture"))
        for bad in ("Contoso", "-x", "a/b", "a" * 49, ""):
            self.assertFalse(schema.is_slug(bad), bad)
        self.assertTrue(schema.is_token("toolu_01:ab.c-d"))
        for bad in ("a b", "a/b", "", "x" * 129, None):
            self.assertFalse(schema.is_token(bad), bad)


def replace(text: str, old: str, new: str) -> str:
    assert old in text, old
    return text.replace(old, new, 1)


class PolicyTests(unittest.TestCase):
    def test_fixture_policy_loads(self) -> None:
        policy = schema.load_policy(POLICY_TOML.encode())
        self.assertEqual(policy.ttl_hours, 4)
        self.assertEqual(policy.canary_tiers, frozenset({"critical"}))
        self.assertEqual(policy.extra_patterns, ("CONTOSO-SECRET-[0-9]{4}",))
        self.assertNotIn("bash", policy.subagent_bash_allow)

    def test_policy_refusals(self) -> None:
        p = POLICY_TOML
        ttl = "approval_ttl_hours = 4"
        cases = {
            "unknown table": (p + "\n[mystery]\nx = 1\n", "policy_keys"),
            "missing table": (replace(p, "[tiers]\ncritical_patterns = []\n", ""), "policy_keys"),
            "unknown harness key": (replace(p, ttl, ttl + "\nmystery = 1"), "policy_harness"),
            "schema 2": (replace(p, "schema = 1", "schema = 2"), "schema_version"),
            "schema string": (replace(p, "schema = 1", 'schema = "1"'), "schema_version"),
            "schema bool": (replace(p, "schema = 1", "schema = true"), "schema_version"),
            "ttl bool": (replace(p, ttl, "approval_ttl_hours = true"), "policy_ttl"),
            "ttl 0": (replace(p, ttl, "approval_ttl_hours = 0"), "policy_ttl"),
            "ttl 25": (replace(p, ttl, "approval_ttl_hours = 25"), "policy_ttl"),
            "ttl float": (replace(p, ttl, "approval_ttl_hours = 4.0"), "policy_ttl"),
            "one active false": (
                replace(p, "one_active_change = true", "one_active_change = false"),
                "policy_floor",
            ),
            "one active string": (
                replace(p, "one_active_change = true", 'one_active_change = "true"'),
                "policy_floor",
            ),
            "canary without critical": (
                replace(p, 'canary_tiers = ["critical"]', 'canary_tiers = ["normal"]'),
                "policy_floor",
            ),
            "canary unknown tier": (
                replace(p, 'canary_tiers = ["critical"]', 'canary_tiers = ["critical", "x"]'),
                "policy_floor",
            ),
            "halt false": (
                replace(p, "halt_on_failure = true", "halt_on_failure = false"),
                "policy_floor",
            ),
            "unknown adapter": (
                replace(p, 'enabled = ["simtenant"]', 'enabled = ["contoso-cli"]'),
                "policy_adapters",
            ),
            "bad version": (
                replace(p, ttl, ttl + '\nmin_claude_code = "2.1"'),
                "policy_version",
            ),
            "redaction matches empty": (
                replace(p, '"CONTOSO-SECRET-[0-9]{4}"', '"a*"'),
                "policy_redaction",
            ),
            "redaction bad regex": (
                replace(p, '"CONTOSO-SECRET-[0-9]{4}"', '"("'),
                "policy_redaction",
            ),
            "subagent shell": (p + '\n[guard]\nsubagent_bash_allow = ["bash"]\n', "policy_guard"),
            "subagent python": (
                p + '\n[guard]\nsubagent_bash_allow = ["python3.12"]\n',
                "policy_guard",
            ),
            "subagent env": (p + '\n[guard]\nsubagent_bash_allow = ["env"]\n', "policy_guard"),
            "verify retry bool": (p + "\n[verify]\nretry_seconds = [true]\n", "policy_verify"),
            "not-admin Bash": (
                replace(p, "[classifier]\n", '[classifier]\nnot_admin_tools = ["Bash"]\n'),
                "policy_s3",
            ),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.load_policy, text.encode()), expected)

    def test_safe_subagent_allow_list_is_accepted(self) -> None:
        text = POLICY_TOML + '\n[guard]\nsubagent_bash_allow = ["cat", "wc", "["]\n'
        policy = schema.load_policy(text.encode())
        self.assertEqual(policy.subagent_bash_allow, frozenset({"cat", "wc", "["}))


class CatalogTests(unittest.TestCase):
    def test_fixture_catalogue_loads_without_description(self) -> None:
        entries = schema.load_catalog(CATALOG_TOML.encode())
        self.assertEqual(len(entries), 1)
        self.assertNotIn("description", entries[0])
        self.assertEqual(entries[0]["state_scope"], "tenant/state.json")

    def test_catalogue_refusals(self) -> None:
        c = CATALOG_TOML
        scope = 'state_scope = "tenant/state.json"'
        cases = {
            "missing state_scope": (replace(c, scope + "\n", ""), "catalog_entry"),
            "dot state_scope": (replace(c, scope, 'state_scope = "./tenant/state.json"'),
                                "catalog_scope"),
            "absolute state_scope": (replace(c, scope, 'state_scope = "/tmp/state.json"'),
                                     "catalog_scope"),
            "pattern state_scope": (replace(c, scope, 'state_scope = "tenant/*.json"'),
                                    "catalog_scope"),
            "unknown key": (c + 'owner = "contoso"\n', "catalog_entry"),
            "enabled string": (replace(c, "enabled = true", 'enabled = "yes"'), "catalog_enabled"),
            "unknown adapter": (replace(c, 'adapter = "simtenant"', 'adapter = "x"'),
                                "catalog_adapter"),
            "bad target": (replace(c, '"users/u-1015"', '"users/*"'), "catalog_targets"),
            "duplicate id": (c + "\n" + c.split("\n", 2)[2], "catalog_id"),
            "schema missing": (replace(c, "schema = 1\n", ""), "catalog_keys"),
            "unknown top key": ("mystery = 1\n" + c, "catalog_keys"),
        }  # fmt: skip
        for label, (text, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.load_catalog, text.encode()), expected)


STEP_CMD = {"id": "s1", "command": "python3 scripts/bulk.py", "targets": ["users/u-1007"]}
STEP_MCP = {"id": "m1", "tool": "mcp__contosoadmin__set_user", "input_sha256": HEX,
            "targets": ["users/u-1007"]}  # fmt: skip


class ChangePlanTests(unittest.TestCase):
    def load(self, text: str) -> schema.ChangePlan:
        return schema.load_change(text.encode(), "CHG-0001")

    def test_fixture_change_loads(self) -> None:
        plan = self.load(change_toml("CHG-0001", "critical", [STEP_CMD, STEP_MCP]))
        self.assertTrue(plan.irreversible)
        self.assertEqual(plan.tenant, "tenant/state.json")
        self.assertEqual([s.id for s in plan.steps], ["s1", "m1"])
        self.assertEqual(plan.steps[1].input_sha256, HEX)

    def test_change_refusals(self) -> None:
        base = change_toml("CHG-0001", "critical")

        def step(**fields: Any) -> str:
            return change_toml("CHG-0001", "critical", [fields])

        cases = {
            "other id": (change_toml("CHG-0002", "critical"), "change_id"),
            "unknown key": ("owner = 1\n" + base, "change_keys"),
            "answers int": (replace(base, "reversible = false", "reversible = 0"),
                            "change_answers"),
            "answers missing": (replace(base, "targets_enumerated = true\n", ""),
                                "change_answers"),
            "irreversible string": (replace(base, "irreversible = true", 'irreversible = "y"'),
                                    "change_irreversible"),
            "scope extra": (base + 'region = "x"\n', "change_scope"),
            "command and tool": (step(id="s", command="x", tool="t", input_sha256=HEX,
                                      targets=["users/u-1007"]), "change_step"),
            "tool without hash": (step(id="s", tool="t", targets=["users/u-1007"]),
                                  "change_step"),
            "bad hash": (step(id="s", tool="t", input_sha256="ABC", targets=["users/u-1007"]),
                         "change_step"),
            "empty targets": (step(id="s", command="x", targets=[]), "change_step"),
            "bad target": (step(id="s", command="x", targets=["users/*"]), "change_step"),
            "unsafe step id": (step(id="../s", command="x", targets=["users/u-1007"]),
                               "change_step"),
            "unknown step key": (step(id="s", command="x", targets=["users/u-1007"],
                                      shell="bash"), "change_step"),
            "schema 2": (replace(base, "schema = 1", "schema = 2"), "schema_version"),
        }  # fmt: skip
        for label, (text, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(self.load, text), expected)
        dup = change_toml("CHG-0001", "critical", [STEP_CMD, STEP_CMD])
        self.assertEqual(code(self.load, dup), "change_step")

    def test_targets_csv(self) -> None:
        self.assertEqual(
            schema.parse_targets(targets_csv(["users/u-1007", "groups/g-2001"]).encode()),
            ("users/u-1007", "groups/g-2001"),
        )
        cases = {
            b"users/u-1007\n": "targets_header",
            b"target\r\nusers/u-1007\r\n": "targets_crlf",
            "﻿target\nusers/u-1007\n".encode(): "bom",
            b"target\n": "targets_rows",
            b"target\nusers/u-1007\nusers/u-1007\n": "targets_duplicate",
            b"target\nusers/u-1007\n\n": "targets_row",
            b"target\nusers/*\n": "targets_row",
            b"target\nusers/u 1007\n": "targets_row",
        }
        for data, expected in cases.items():
            with self.subTest(data=data):
                self.assertEqual(code(schema.parse_targets, data), expected)


class EventTests(unittest.TestCase):
    BASE = {
        "hook_event_name": "PreToolUse",
        "session_id": "sess-1",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_use_id": "toolu_1",
        "cwd": "/tmp/contoso",
    }

    def event(self, **changes: Any) -> dict[str, Any]:
        ev = copy.deepcopy(self.BASE)
        ev.update(changes)
        return ev

    def test_added_metadata_is_ignored(self) -> None:
        extra = {"transcript_path": "/x", "permission_mode": "plan", "future_field": [1]}
        ev = schema.parse_event(self.event(**extra))
        self.assertFalse(ev.is_subagent)
        self.assertEqual(ev.tool_use_id, "toolu_1")

    def test_agent_id_key_always_marks_a_subagent(self) -> None:
        for value in ("agent-1", "", None, 42, "bad id", "x" * 200, ["a"]):
            with self.subTest(agent_id=value):
                ev = schema.parse_event(self.event(agent_id=value, agent_type="runbook-author"))
                self.assertTrue(ev.is_subagent)
                if value != "agent-1":
                    self.assertIsNone(ev.agent_id)

    def test_agent_type_alone_is_main(self) -> None:
        ev = schema.parse_event(self.event(agent_type="runbook-author"))
        self.assertFalse(ev.is_subagent)
        self.assertEqual(ev.agent_type, "runbook-author")

    def test_event_refusals(self) -> None:
        cases = {
            "relative cwd": (self.event(cwd="proj"), "cwd"),
            "tool_use_id spaces": (self.event(tool_use_id="a b"), "tool_use_id"),
            "session int": (self.event(session_id=1), "session_id"),
            "input list": (self.event(tool_input=["echo"]), "tool_input"),
            "tool empty": (self.event(tool_name=""), "tool_name"),
        }
        for label, (ev, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_event, ev), expected)


APPROVAL = {
    "schema": 1,
    "change_id": "CHG-0001",
    "project": "/tmp/contoso",
    "plan_hash": HEX,
    "review_sha256": "b" * 64,
    "tier": "critical",
    "approver": {"os_user": "contoso-approver", "git_user": ""},
    "approved_at": "2027-01-15T08:00:00.000Z",
    "expires_at": "2027-01-15T12:00:00.000Z",
    "nonce": "c" * 32,
}
REVIEW = {
    "schema": 1,
    "change_id": "CHG-0001",
    "verdict": "PASS",
    "findings": [{"code": "F-1", "detail": "fictional"}],
    "plan_hash_start": HEX,
    "plan_hash_end": HEX,
    "agent_id": "agent-1",
    "session_id": "sess-1",
    "started_at": "2027-01-15T08:00:00.000Z",
    "stopped_at": "2027-01-15T08:01:00.000Z",
}


def mutated(doc: dict[str, Any], **changes: Any) -> bytes:
    out = copy.deepcopy(doc)
    for key, value in changes.items():
        if value is KeyError:
            out.pop(key)
        else:
            out[key] = value
    return json.dumps(out).encode()


class AuthorityTests(unittest.TestCase):
    def test_approval(self) -> None:
        self.assertEqual(schema.parse_approval(json.dumps(APPROVAL).encode())["tier"], "critical")
        cases = {
            "extra key": (mutated(APPROVAL, extra=1), "approval_keys"),
            "missing nonce": (mutated(APPROVAL, nonce=KeyError), "approval_keys"),
            "schema bool": (mutated(APPROVAL, schema=True), "schema_version"),
            "schema 2": (mutated(APPROVAL, schema=2), "schema_version"),
            "relative project": (mutated(APPROVAL, project="proj"), "approval_project"),
            "unknown tier": (mutated(APPROVAL, tier="emergency"), "approval_tier"),
            "expires first": (mutated(APPROVAL, expires_at="2027-01-15T07:00:00.000Z"),
                              "approval_time"),
            "bad nonce": (mutated(APPROVAL, nonce="C" * 32), "approval_nonce"),
            "approver extra": (mutated(APPROVAL, approver={"os_user": "a", "git_user": "",
                                                           "role": "x"}), "approval_approver"),
            "duplicate key": (b'{"schema":1,"schema":1}', "duplicate_key"),
        }  # fmt: skip
        for label, (data, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_approval, data), expected)

    def test_review(self) -> None:
        self.assertEqual(schema.parse_review(json.dumps(REVIEW).encode())["verdict"], "PASS")
        cases = {
            "verdict": (mutated(REVIEW, verdict="OK"), "review_verdict"),
            "extra": (mutated(REVIEW, score=1), "review_keys"),
            "time order": (mutated(REVIEW, stopped_at="2027-01-15T07:00:00.000Z"),
                           "review_time"),
            "bad hash": (mutated(REVIEW, plan_hash_end="x"), "review_hash"),
            "finding extra": (mutated(REVIEW, findings=[{"code": "F", "detail": "", "x": 1}]),
                              "review_finding"),
        }  # fmt: skip
        for label, (data, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_review, data), expected)

    def test_snapshot(self) -> None:
        obs = observation("users/u-1007", T0)
        snap = {
            "schema": 1,
            "change_id": "CHG-0001",
            "plan_hash": HEX,
            "taken_at": "2027-01-15T08:00:00.000Z",
            "targets": {"users/u-1007": obs},
        }
        self.assertIn("users/u-1007", schema.parse_snapshot(json.dumps(snap).encode())["targets"])
        self.assertEqual(code(schema.parse_snapshot, mutated(snap, targets={})),
                         "snapshot_targets")  # fmt: skip
        self.assertEqual(code(schema.parse_snapshot, mutated(snap, targets={"users/*": obs})),
                         "snapshot_targets")  # fmt: skip
        self.assertEqual(code(schema.parse_snapshot, mutated(snap, extra=1)), "snapshot_keys")
        # S5: arbitrary JSON is no longer a snapshot value
        for value in (None, 1, {"fixture": "before"}):
            with self.subTest(value=value):
                bad = mutated(snap, targets={"users/u-1007": value})
                self.assertEqual(code(schema.parse_snapshot, bad), "snapshot_values")

    def test_active(self) -> None:
        self.assertIsNone(schema.parse_active(b'{"schema":1,"change_id":null}'))
        self.assertEqual(schema.parse_active(b'{"schema":1,"change_id":"CHG-0001"}'), "CHG-0001")
        self.assertEqual(code(schema.parse_active, b'{"schema":1,"change_id":"../x"}'),
                         "active_change")  # fmt: skip


CALL = {"session_id": "sess-1", "tool": "Bash", "salt": "d" * 32, "input_hmac": "f" * 64}


def state_doc(**changes: Any) -> dict[str, Any]:
    at = "2027-01-15T08:00:00.000Z"
    doc = {
        "schema": 1, "id": "CHG-0001", "slug": "contoso-fixture", "seq": 3,
        "state": "executing", "tier": "critical", "plan_hash": HEX, "review_start": None,
        "review_sha": HEX, "ack_review_sha": None, "approval_nonce": "c" * 32,
        "snapshot_sha": HEX, "canary": "pending", "canary_unit": None,
        "units": [{"n": 1, "tool_use_id": "toolu_1", "step": None, "targets": ["users/u-1007"],
                   "canary": True, "outcome": None, "verify": None, "at": at,
                   "call": dict(CALL), "receipt": None, "verify_ref": None}],
        "executed_steps": [], "settled_ids": [],
        "inflight": {"token": "toolu_1", "unit": 1, "step": None, "targets": ["users/u-1007"],
                     "canary": True, "input_sha256": HEX, "at": at},
        "halted": None, "created_at": at, "updated_at": at,
    }  # fmt: skip
    doc.update(changes)
    return doc


class StateDocumentTests(unittest.TestCase):
    def test_valid_state_parses(self) -> None:
        self.assertEqual(schema.parse_state(state_doc())["seq"], 3)

    def test_verifying_is_no_longer_a_state(self) -> None:
        self.assertNotIn("verifying", schema.STATES)
        self.assertEqual(code(schema.parse_state, state_doc(state="verifying")), "state_state")

    def test_state_invariants(self) -> None:
        receipt = {"source": "post", "outcome": "ok", "at": "2027-01-15T08:00:00.000Z",
                   "exit": None, "response_sha256": HEX}  # fmt: skip
        ref = {"line": 1, "sha256": HEX}
        settled_unit = dict(state_doc()["units"][0], outcome="ok", receipt=receipt)
        cases = {
            "unit open without reservation": state_doc(inflight=None),
            "settled id missing": state_doc(inflight=None, units=[settled_unit]),
            "halted state without halt": state_doc(state="halted"),
            "halt without halted state": state_doc(
                halted={"code": "write_failed", "at": "2027-01-15T08:00:00.000Z",
                        "tool_use_id": None}),
            "awaiting without unit": state_doc(canary="awaiting"),
            "verify before outcome": state_doc(
                units=[dict(state_doc()["units"][0], verify="PASS", verify_ref=ref)]),
            "in flight after execution ended": state_doc(state="open-unverified"),
            "reservation is not the open unit": state_doc(
                inflight=dict(state_doc()["inflight"], token="toolu_2")),
        }  # fmt: skip
        for label, doc in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_state, doc), "state_invariant")

    def test_state_types(self) -> None:
        cases = {
            "seq bool": (state_doc(seq=True), "state_seq"),
            "unknown state": (state_doc(state="paused"), "state_state"),
            "extra key": (dict(state_doc(), extra=1), "state_keys"),
            "bad canary": (state_doc(canary="maybe"), "state_canary"),
        }
        for label, (doc, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code(schema.parse_state, doc), expected)
        data = schema.canonical_bytes(state_doc())
        dup = data.replace(b'{"ack_review_sha":', b'{"seq":1,"ack_review_sha":', 1)
        self.assertEqual(code(schema.parse_state, dup), "duplicate_key")


if __name__ == "__main__":
    unittest.main()
