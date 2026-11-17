#!/usr/bin/env python3
"""simtenant: a mock, entirely fictional "Contoso" tenant over one local JSON state file.

    python3 simtenant/simtenant.py --state FILE VERB RESOURCE [ID] [options]
    python3 simtenant/simtenant.py --state FILE reset [--seed SEED.json]

RESOURCE: users | groups | mailboxes | policies | licenses (singular aliases accepted).
Read verbs:  list, get          (never modify the state file)
Write verbs: set, add, remove, delete, purge, restore; plus reset.

Targets are selected only by immutable ID (u-1042, g-2001, mbx-1042, pol-4001,
lic-5001). Display names, UPNs and addresses are never resolved to a target.

Every invocation prints exactly one JSON object on stdout. Exit codes:
0 ok, 2 invalid input, 3 not found, 4 conflict, 5 state/seed/lock problem, 70 internal.

Injected faults (for exercising a change-control harness, not for real use):
  --lie               write prints success but the state file is not touched at all
  --delay-seconds N   the backend changes now; reads keep seeing the old value for N s
  --dry-run           honoured by set/add/remove/delete/restore, IGNORED by purge

Python 3.11+ standard library only. POSIX (fcntl) locking. No network, no
credentials, no files other than the state file, its ".lock" sidecar and the seed.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import json
import math
import os
import re
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

STATE_SCHEMA = "simtenant-state/1"
SEED_SCHEMA = "simtenant-seed/1"
SOFT_DELETE_SECONDS = 30 * 24 * 60 * 60
MAX_DELAY_SECONDS = 24 * 60 * 60
LOCK_TIMEOUT_SECONDS = 10.0
DEFAULT_SEED = Path(__file__).resolve().parent / "seed" / "contoso.json"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_CONFLICT = 4
EXIT_STATE = 5
EXIT_INTERNAL = 70

READ_VERBS = ("list", "get")
WRITE_VERBS = ("set", "add", "remove", "delete", "purge", "restore")
ALL_VERBS = READ_VERBS + WRITE_VERBS + ("reset",)
RESOURCES = ("users", "groups", "mailboxes", "policies", "licenses")
RESOURCE_ALIASES = {
    "users": "users",
    "user": "users",
    "groups": "groups",
    "group": "groups",
    "mailboxes": "mailboxes",
    "mailbox": "mailboxes",
    "policies": "policies",
    "policy": "policies",
    "licenses": "licenses",
    "license": "licenses",
}
PREFIX_TO_RESOURCE = {
    "u": "users",
    "g": "groups",
    "mbx": "mailboxes",
    "pol": "policies",
    "lic": "licenses",
}
RESOURCE_TO_PREFIX = {res: prefix for prefix, res in PREFIX_TO_RESOURCE.items()}
ID_RE = re.compile(r"^(u|g|mbx|pol|lic)-([0-9]{3,8})$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CANDIDATE_FIELDS = (
    "display_name",
    "user_principal_name",
    "mail",
    "primary_smtp_address",
    "mail_nickname",
    "sku_part_number",
)

DRY_RUN_NOTE = (
    "simtenant --dry-run is a fault-injection surface, not a read-only guarantee: "
    "set/add/remove/delete/restore honour it, purge ignores it. "
    "Treat every write verb as a write regardless of --dry-run."
)

_MISSING: Any = object()


# --------------------------------------------------------------------------- schema


def _f(
    kind: str,
    *,
    nullable: bool = False,
    mode: str = "mutable",
    enum: tuple[str, ...] | None = None,
    ref: str | None = None,
    unique: bool = False,
    email: bool = False,
) -> dict[str, Any]:
    """Field spec. mode: mutable | create_only | auto | relation."""
    return {
        "kind": kind,
        "nullable": nullable,
        "mode": mode,
        "enum": enum,
        "ref": ref,
        "unique": unique,
        "email": email,
    }


_ID = _f("str", mode="auto")
_CREATED = _f("str", mode="auto")

SCHEMA: dict[str, dict[str, Any]] = {
    "users": {
        "relation": None,
        "member_kinds": (),
        "fields": {
            "id": _ID,
            "created_at": _CREATED,
            "display_name": _f("str"),
            "given_name": _f("str"),
            "surname": _f("str"),
            "user_principal_name": _f("str", unique=True, email=True),
            "mail": _f("str", nullable=True, email=True),
            "department": _f("str", nullable=True),
            "job_title": _f("str", nullable=True),
            "account_enabled": _f("bool"),
            "usage_location": _f("str"),
            "manager_id": _f("str", nullable=True, ref="users"),
        },
    },
    "groups": {
        "relation": "members",
        "member_kinds": ("users",),
        "fields": {
            "id": _ID,
            "created_at": _CREATED,
            "display_name": _f("str"),
            "description": _f("str", nullable=True),
            "mail_nickname": _f("str", unique=True),
            "mail": _f("str", nullable=True, email=True),
            "group_type": _f(
                "str", mode="create_only", enum=("security", "microsoft365", "distribution")
            ),
            "mail_enabled": _f("bool"),
            "security_enabled": _f("bool"),
            "members": _f("list_str", mode="relation"),
        },
    },
    "mailboxes": {
        "relation": "delegates",
        "member_kinds": ("users",),
        "fields": {
            "id": _ID,
            "created_at": _CREATED,
            "display_name": _f("str"),
            "owner_id": _f("str", nullable=True, mode="create_only", ref="users"),
            "primary_smtp_address": _f("str", unique=True, email=True),
            "recipient_type": _f("str", mode="create_only", enum=("user", "shared")),
            "forwarding_smtp_address": _f("str", nullable=True, email=True),
            "deliver_to_mailbox_and_forward": _f("bool"),
            "litigation_hold_enabled": _f("bool"),
            "archive_enabled": _f("bool"),
            "delegates": _f("list_str", mode="relation"),
        },
    },
    "policies": {
        "relation": "include",
        "member_kinds": ("users", "groups"),
        "fields": {
            "id": _ID,
            "created_at": _CREATED,
            "display_name": _f("str"),
            "policy_type": _f(
                "str",
                mode="create_only",
                enum=("conditional_access", "retention", "transport_rule"),
            ),
            "state": _f("str", enum=("enabled", "disabled", "report_only")),
            "description": _f("str", nullable=True),
            "controls": _f("list_str"),
            "include": _f("list_str", mode="relation"),
        },
    },
    "licenses": {
        "relation": "assigned_to",
        "member_kinds": ("users",),
        "fields": {
            "id": _ID,
            "created_at": _CREATED,
            "display_name": _f("str"),
            "sku_part_number": _f("str", mode="create_only", unique=True),
            "seats_total": _f("int"),
            "assigned_to": _f("list_str", mode="relation"),
        },
    },
}


# --------------------------------------------------------------------------- errors


class SimTenantError(Exception):
    """A refused command. The state file is never modified when this is raised."""

    def __init__(self, code: str, message: str, exit_code: int, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.details = details

    def payload(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        error.update(self.details)
        return {"ok": False, "changed": False, "exit_code": self.exit_code, "error": error}


def _usage(message: str, **details: Any) -> SimTenantError:
    return SimTenantError("invalid_argument", message, EXIT_USAGE, **details)


def _not_found(resource: str, obj_id: str, message: str | None = None) -> SimTenantError:
    return SimTenantError(
        "not_found",
        message or f"{resource}/{obj_id} does not exist",
        EXIT_NOT_FOUND,
        resource=resource,
        id=obj_id,
    )


def _conflict(code: str, message: str, **details: Any) -> SimTenantError:
    return SimTenantError(code, message, EXIT_CONFLICT, **details)


def _state_error(code: str, message: str) -> SimTenantError:
    return SimTenantError(code, message, EXIT_STATE)


# --------------------------------------------------------------------------- helpers


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="microseconds")


def _ts(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def _resource_of_id(obj_id: Any) -> str | None:
    if not isinstance(obj_id, str):
        return None
    match = ID_RE.match(obj_id)
    return PREFIX_TO_RESOURCE[match.group(1)] if match else None


def _id_key(obj_id: str) -> tuple[str, int, str]:
    prefix, _, number = obj_id.partition("-")
    return (prefix, int(number) if number.isdigit() else -1, obj_id)


def _norm_resource(resource: Any) -> str:
    if not isinstance(resource, str) or resource.lower() not in RESOURCE_ALIASES:
        raise _usage(f"unknown resource {resource!r}", allowed=list(RESOURCES))
    return RESOURCE_ALIASES[resource.lower()]


def _norm_text(text: str) -> str:
    return re.sub(r"[^0-9a-z]", "", text.casefold())


def _candidates(state: Any, text: Any) -> list[dict[str, Any]]:
    """Objects whose names/addresses resemble `text`. Informational only: never selected."""
    if not isinstance(state, dict) or not isinstance(text, str):
        return []
    key = _norm_text(text)
    if not key:
        return []
    found = []
    for res in RESOURCES:
        objects = state.get("objects", {}).get(res, {})
        for oid in sorted(objects, key=_id_key):
            obj = objects[oid]
            for name in CANDIDATE_FIELDS:
                value = obj.get(name)
                if isinstance(value, str) and _norm_text(value) == key:
                    found.append(
                        {"resource": res, "id": oid, "display_name": obj.get("display_name")}
                    )
                    break
    return found


def _require_target_id(state: Any, resource: str, obj_id: Any) -> None:
    if not isinstance(obj_id, str) or not obj_id:
        raise _usage(f"an immutable {resource} ID is required")
    actual = _resource_of_id(obj_id)
    if actual is None:
        raise SimTenantError(
            "invalid_id",
            f"{obj_id!r} is not an immutable {resource} ID "
            f"(expected {RESOURCE_TO_PREFIX[resource]}-NNNN). "
            "Targets are selected only by immutable ID; display names, UPNs and addresses "
            "are never resolved, so nothing was selected.",
            EXIT_USAGE,
            candidates=_candidates(state, obj_id),
            selected=None,
        )
    if actual != resource:
        raise SimTenantError(
            "id_resource_mismatch",
            f"{obj_id} is a {actual} ID, not a {resource} ID; nothing was selected.",
            EXIT_USAGE,
            selected=None,
        )


def _parse_delay(value: Any) -> int | float:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise _usage("--delay-seconds must be a number of seconds")
    try:
        delay = float(value)
    except (TypeError, ValueError):
        raise _usage("--delay-seconds must be a number of seconds") from None
    if not math.isfinite(delay) or delay < 0 or delay > MAX_DELAY_SECONDS:
        raise _usage(f"--delay-seconds must be between 0 and {MAX_DELAY_SECONDS}")
    return int(delay) if delay.is_integer() else delay


def _iter_all(view: dict[str, Any], resource: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """Active and soft-deleted objects of one resource (mutable references)."""
    for oid, obj in view["objects"][resource].items():
        yield oid, obj
    for oid, entry in view["deleted"][resource].items():
        yield oid, entry["object"]


def _status_of(view: dict[str, Any], resource: str, obj_id: str) -> tuple[str, Any, Any]:
    if obj_id in view["objects"][resource]:
        return "active", view["objects"][resource][obj_id], None
    if obj_id in view["deleted"][resource]:
        entry = view["deleted"][resource][obj_id]
        return "soft_deleted", entry["object"], entry
    if obj_id in view["purged_ids"][resource]:
        return "purged", None, None
    return "absent", None, None


def _locate(view: dict[str, Any], resource: str, obj_id: str) -> str:
    return _status_of(view, resource, obj_id)[0]


def _describe(resource: str, obj_id: str, status: str, obj: Any, entry: Any) -> dict[str, Any]:
    out = {"resource": resource, "id": obj_id, "status": status, "object": copy.deepcopy(obj)}
    if entry is not None:
        out["deleted_at"] = entry["deleted_at"]
        out["purge_after"] = entry["purge_after"]
    return out


def _empty_state(tenant: dict[str, Any], now: float) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "tenant": tenant,
        "revision": 0,
        "seeded_at": _iso(now),
        "objects": {res: {} for res in RESOURCES},
        "deleted": {res: {} for res in RESOURCES},
        "purged_ids": {res: {} for res in RESOURCES},
        "stale": [],
    }


def _check_state_shape(state: Any) -> None:
    ok = (
        isinstance(state, dict)
        and state.get("schema") == STATE_SCHEMA
        and isinstance(state.get("revision"), int)
        and isinstance(state.get("stale"), list)
    )
    if ok:
        for key in ("objects", "deleted", "purged_ids"):
            section = state.get(key)
            ok = (
                ok
                and isinstance(section, dict)
                and all(isinstance(section.get(r), dict) for r in RESOURCES)
            )
    if not ok:
        raise _state_error(
            "state_corrupt", f"state file is not a {STATE_SCHEMA} document; run reset"
        )


# --------------------------------------------------------------------------- validation


def _check_value(resource: str, field: str, spec: dict[str, Any], value: Any) -> None:
    label = f"{resource}.{field}"
    if value is None:
        if spec["nullable"]:
            return
        raise _usage(f"{label} cannot be null", field=field)
    kind = spec["kind"]
    if kind == "str":
        ok = isinstance(value, str)
    elif kind == "bool":
        ok = isinstance(value, bool)
    elif kind == "int":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif kind == "list_str":
        ok = isinstance(value, list) and all(isinstance(item, str) and item for item in value)
    else:  # pragma: no cover - schema bug
        ok = False
    if not ok:
        raise _usage(
            f"{label} expects {kind}, got {type(value).__name__}", field=field, expected=kind
        )
    if kind == "str" and not value.strip():
        raise _usage(f"{label} must not be empty", field=field)
    if kind == "int" and value < 0:
        raise _usage(f"{label} must not be negative", field=field)
    if spec["enum"] and value not in spec["enum"]:
        raise _usage(
            f"{label} must be one of {list(spec['enum'])}", field=field, allowed=list(spec["enum"])
        )
    if spec["email"] and not EMAIL_RE.match(value):
        raise _usage(f"{label} must be an email-style address", field=field)


def _check_refs_unique(
    view: dict[str, Any], resource: str, obj_id: str, field: str, spec: dict[str, Any], value: Any
) -> None:
    if value is None:
        return
    ref = spec["ref"]
    if ref:
        if _resource_of_id(value) != ref:
            raise SimTenantError(
                "invalid_reference",
                f"{resource}.{field} must be an immutable {ref} ID",
                EXIT_USAGE,
                field=field,
            )
        if value == obj_id:
            raise _usage(f"{resource}.{field} cannot reference the object itself", field=field)
        status = _locate(view, ref, value)
        if status == "soft_deleted":
            raise _conflict("reference_soft_deleted", f"{ref}/{value} is soft-deleted", field=field)
        if status != "active":
            raise SimTenantError(
                "reference_not_found", f"{ref}/{value} does not exist", EXIT_NOT_FOUND, field=field
            )
    if spec["unique"]:
        key = value.casefold()
        for oid, obj in _iter_all(view, resource):
            other = obj.get(field)
            if oid != obj_id and isinstance(other, str) and other.casefold() == key:
                raise _conflict(
                    "value_in_use",
                    f"{resource}.{field} {value!r} is already used by {oid}",
                    field=field,
                    used_by=oid,
                )


def _validate_record(
    resource: str, obj_id: str, record: Any, *, now: float, from_seed: bool
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise _usage("--record must be a JSON object")
    fields = SCHEMA[resource]["fields"]
    unknown = sorted(set(record) - set(fields))
    if unknown:
        raise _usage(
            f"unknown field(s) for {resource}: {', '.join(unknown)}", allowed=sorted(fields)
        )
    if "id" in record and record["id"] != obj_id:
        raise _usage("record id does not match the target ID")
    out: dict[str, Any] = {}
    for name, spec in fields.items():
        if name == "id":
            out[name] = obj_id
        elif name == "created_at":
            if "created_at" in record and not from_seed:
                raise _usage("created_at is assigned by simtenant")
            value = record.get("created_at", _iso(now))
            try:
                if not isinstance(value, str):
                    raise ValueError
                _ts(value)
            except ValueError:
                raise _usage("created_at must be an ISO 8601 timestamp") from None
            out[name] = value
        elif spec["mode"] == "relation":
            value = record.get(name, [])
            if not from_seed and value != []:
                raise _usage(f"{name} cannot be given at creation; use add --member afterwards")
            _check_value(resource, name, spec, value)
            out[name] = list(value)
        else:
            if name not in record:
                raise _usage(f"missing required field {name!r} for {resource}", field=name)
            _check_value(resource, name, spec, record[name])
            out[name] = copy.deepcopy(record[name])
    return out


def _check_member(view: dict[str, Any], resource: str, member: Any) -> str:
    if not isinstance(member, str) or not member:
        raise _usage("--member requires an immutable ID")
    member_resource = _resource_of_id(member)
    if member_resource is None:
        raise SimTenantError(
            "invalid_id",
            f"{member!r} is not an immutable ID. Members are selected only by immutable ID; "
            "nothing was selected.",
            EXIT_USAGE,
            candidates=_candidates(view, member),
            selected=None,
        )
    kinds = SCHEMA[resource]["member_kinds"]
    if member_resource not in kinds:
        raise SimTenantError(
            "invalid_member_type",
            f"{resource} members must be {'/'.join(kinds)} IDs; {member} is a {member_resource} ID",
            EXIT_USAGE,
        )
    return member_resource


def _relation(resource: str) -> str:
    rel = SCHEMA[resource]["relation"]
    if rel is None:
        raise _usage(
            f"{resource} has no member list; e.g. assign a license with "
            "'add licenses lic-NNNN --member u-NNNN' or a group with "
            "'add groups g-NNNN --member u-NNNN'"
        )
    return rel


def _check_write_options(verb: str, field: Any, value: Any, member: Any, record: Any) -> None:
    has_field = field is not None
    has_value = value is not _MISSING
    has_member = member is not None
    has_record = record is not None
    if verb == "set":
        if not (isinstance(field, str) and field):
            raise _usage("set requires --field NAME")
        if not has_value:
            raise _usage("set requires --value VALUE (JSON, or a plain string)")
        if has_member or has_record:
            raise _usage("set does not accept --member or --record")
    elif verb == "add":
        if has_field or has_value:
            raise _usage("add does not accept --field/--value")
        if has_member == has_record:
            raise _usage(
                "add requires exactly one of --member ID (add to the member list) "
                "or --record JSON (create an object under this new ID)"
            )
    elif verb == "remove":
        if has_field or has_value or has_record:
            raise _usage("remove accepts only --member ID")
        if not has_member:
            raise _usage("remove requires --member ID")
    elif has_field or has_value or has_member or has_record:
        raise _usage(f"{verb} takes no --field/--value/--member/--record")


# --------------------------------------------------------------------------- state transforms


def _cascade_purge(view: dict[str, Any], purged_resource: str, obj_id: str) -> None:
    """Drop a purged ID from every member list and manager reference."""
    for res, schema in SCHEMA.items():
        rel = schema["relation"]
        if rel and purged_resource in schema["member_kinds"]:
            for _, obj in _iter_all(view, res):
                if obj_id in obj[rel]:
                    obj[rel] = [m for m in obj[rel] if m != obj_id]
    if purged_resource == "users":
        for _, obj in _iter_all(view, "users"):
            if obj.get("manager_id") == obj_id:
                obj["manager_id"] = None


def _expire(view: dict[str, Any], now: float) -> None:
    """Soft-deleted objects whose 30-day window has ended are permanently purged."""
    for res in RESOURCES:
        for oid, entry in list(view["deleted"][res].items()):
            if now >= _ts(entry["purge_after"]):
                del view["deleted"][res][oid]
                _cascade_purge(view, res, oid)
                view["purged_ids"][res][oid] = {
                    "purged_at": entry["purge_after"],
                    "reason": "retention_expired",
                }


def _visible(state: dict[str, Any], now: float) -> dict[str, Any]:
    """What reads see at `now`: backend overlaid with not-yet-replicated old values."""
    view = {
        "objects": copy.deepcopy(state["objects"]),
        "deleted": copy.deepcopy(state["deleted"]),
        "purged_ids": copy.deepcopy(state["purged_ids"]),
    }
    for entry in state["stale"]:
        if now < _ts(entry["visible_at"]):
            res, oid = entry["resource"], entry["id"]
            if entry["active"] is None:
                view["objects"][res].pop(oid, None)
            else:
                view["objects"][res][oid] = copy.deepcopy(entry["active"])
            if entry["deleted"] is None:
                view["deleted"][res].pop(oid, None)
            else:
                view["deleted"][res][oid] = copy.deepcopy(entry["deleted"])
    _expire(view, now)
    return view


def _snapshot(view: dict[str, Any]) -> dict[tuple[str, str], tuple[Any, Any]]:
    snap: dict[tuple[str, str], tuple[Any, Any]] = {}
    for res in RESOURCES:
        for oid, obj in view["objects"][res].items():
            snap[(res, oid)] = (obj, None)
        for oid, entry in view["deleted"][res].items():
            snap[(res, oid)] = (snap.get((res, oid), (None, None))[0], entry)
    return copy.deepcopy(snap)


def _record_staleness(
    state: dict[str, Any],
    before: dict[tuple[str, str], tuple[Any, Any]],
    changed_keys: list[tuple[str, str]],
    now: float,
    delay: float,
) -> None:
    if delay > 0:
        until = now + delay
        index = {(e["resource"], e["id"]): e for e in state["stale"]}
        for key in changed_keys:
            entry = index.get(key)
            if entry is not None:
                # Keep the oldest unreplicated value; extend its window.
                if _ts(entry["visible_at"]) < until:
                    entry["visible_at"] = _iso(until)
                continue
            active, deleted = before.get(key, (None, None))
            entry = {
                "resource": key[0],
                "id": key[1],
                "visible_at": _iso(until),
                "active": active,
                "deleted": deleted,
            }
            state["stale"].append(entry)
            index[key] = entry
    else:
        keys = set(changed_keys)
        state["stale"] = [e for e in state["stale"] if (e["resource"], e["id"]) not in keys]


def _need_active(view: dict[str, Any], resource: str, obj_id: str) -> dict[str, Any]:
    status, obj, _ = _status_of(view, resource, obj_id)
    if status == "active":
        return obj
    if status == "soft_deleted":
        raise _conflict(
            "target_soft_deleted",
            f"{resource}/{obj_id} is soft-deleted; restore it first",
            resource=resource,
            id=obj_id,
        )
    raise _not_found(resource, obj_id)


def _op_set(
    state: dict[str, Any], resource: str, obj_id: str, field: str, value: Any
) -> dict[str, Any]:
    obj = _need_active(state, resource, obj_id)
    fields = SCHEMA[resource]["fields"]
    spec = fields.get(field)
    if spec is None:
        settable = sorted(n for n, s in fields.items() if s["mode"] == "mutable")
        raise _usage(f"unknown field {field!r} for {resource}", allowed=settable)
    if spec["mode"] == "relation":
        raise _usage(f"{resource}.{field} is a member list; use add/remove --member")
    if spec["mode"] != "mutable":
        raise _usage(f"{resource}.{field} is immutable")
    _check_value(resource, field, spec, value)
    _check_refs_unique(state, resource, obj_id, field, spec, value)
    if resource == "licenses" and field == "seats_total" and value < len(obj["assigned_to"]):
        raise _conflict(
            "seats_in_use", f"{len(obj['assigned_to'])} seats are assigned; unassign first"
        )
    obj[field] = copy.deepcopy(value)
    return {"field": field}


def _op_add(
    state: dict[str, Any], resource: str, obj_id: str, member: Any, record: Any, now: float
) -> dict[str, Any]:
    if record is not None:
        status = _locate(state, resource, obj_id)
        if status != "absent":
            raise _conflict(
                "id_reused",
                f"{resource}/{obj_id} exists or existed ({status}); immutable IDs are never reused",
                existing_status=status,
            )
        new = _validate_record(resource, obj_id, record, now=now, from_seed=False)
        for name, spec in SCHEMA[resource]["fields"].items():
            if spec["mode"] in ("mutable", "create_only"):
                _check_refs_unique(state, resource, obj_id, name, spec, new[name])
        state["objects"][resource][obj_id] = new
        return {"created": True}
    obj = _need_active(state, resource, obj_id)
    rel = _relation(resource)
    member_resource = _check_member(state, resource, member)
    member_status = _locate(state, member_resource, member)
    if member_status == "soft_deleted":
        raise _conflict("member_soft_deleted", f"{member_resource}/{member} is soft-deleted")
    if member_status != "active":
        raise _not_found(member_resource, member)
    if member in obj[rel]:
        raise _conflict(
            "already_member", f"{member} is already in {resource}/{obj_id}.{rel}", member=member
        )
    if resource == "licenses" and len(obj[rel]) >= obj["seats_total"]:
        raise _conflict(
            "no_seats_available", f"all {obj['seats_total']} seats of {obj_id} are assigned"
        )
    obj[rel].append(member)
    return {"member": member, "relation": rel}


def _op_remove(state: dict[str, Any], resource: str, obj_id: str, member: Any) -> dict[str, Any]:
    obj = _need_active(state, resource, obj_id)
    rel = _relation(resource)
    _check_member(state, resource, member)
    if member not in obj[rel]:
        raise _conflict(
            "not_member", f"{member} is not in {resource}/{obj_id}.{rel}", member=member
        )
    obj[rel] = [m for m in obj[rel] if m != member]
    return {"member": member, "relation": rel}


def _op_delete(state: dict[str, Any], resource: str, obj_id: str, now: float) -> dict[str, Any]:
    status = _locate(state, resource, obj_id)
    if status == "soft_deleted":
        raise _conflict("already_deleted", f"{resource}/{obj_id} is already soft-deleted")
    if status != "active":
        raise _not_found(resource, obj_id)
    obj = state["objects"][resource].pop(obj_id)
    state["deleted"][resource][obj_id] = {
        "object": obj,
        "deleted_at": _iso(now),
        "purge_after": _iso(now + SOFT_DELETE_SECONDS),
    }
    return {}


def _op_purge(state: dict[str, Any], resource: str, obj_id: str, now: float) -> dict[str, Any]:
    status = _locate(state, resource, obj_id)
    if status == "active":
        state["objects"][resource].pop(obj_id)
    elif status == "soft_deleted":
        state["deleted"][resource].pop(obj_id)
    else:
        raise _not_found(resource, obj_id)
    _cascade_purge(state, resource, obj_id)
    state["purged_ids"][resource][obj_id] = {"purged_at": _iso(now), "reason": "purge"}
    return {"previous_status": status, "irreversible": True}


def _op_restore(state: dict[str, Any], resource: str, obj_id: str) -> dict[str, Any]:
    status = _locate(state, resource, obj_id)
    if status == "soft_deleted":
        entry = state["deleted"][resource].pop(obj_id)
        state["objects"][resource][obj_id] = entry["object"]
        return {}
    if status == "active":
        raise _conflict("not_deleted", f"{resource}/{obj_id} is active; nothing to restore")
    if (
        status == "purged"
        and state["purged_ids"][resource][obj_id].get("reason") == "retention_expired"
    ):
        raise _conflict(
            "restore_window_expired",
            f"{resource}/{obj_id} was soft-deleted more than 30 days ago and is permanently gone",
        )
    raise _not_found(
        resource,
        obj_id,
        f"{resource}/{obj_id} has no soft-deleted copy; purged objects cannot be restored",
    )


def _apply(
    state: dict[str, Any],
    verb: str,
    resource: str,
    obj_id: Any,
    opts: dict[str, Any],
    now: float,
    delay: float,
) -> tuple[dict[str, Any], bool]:
    """Validate and apply one write to `state` in memory. Raises before any persistence."""
    _require_target_id(state, resource, obj_id)
    _expire(state, now)
    state["stale"] = [e for e in state["stale"] if now < _ts(e["visible_at"])]
    before = _snapshot(state)
    if verb == "set":
        extra = _op_set(state, resource, obj_id, opts["field"], opts["value"])
    elif verb == "add":
        extra = _op_add(state, resource, obj_id, opts["member"], opts["record"], now)
    elif verb == "remove":
        extra = _op_remove(state, resource, obj_id, opts["member"])
    elif verb == "delete":
        extra = _op_delete(state, resource, obj_id, now)
    elif verb == "purge":
        extra = _op_purge(state, resource, obj_id, now)
    elif verb == "restore":
        extra = _op_restore(state, resource, obj_id)
    else:  # pragma: no cover - guarded by caller
        raise _usage(f"unknown write verb {verb!r}")
    after = _snapshot(state)
    empty = (None, None)
    changed_keys = sorted(
        k for k in set(before) | set(after) if before.get(k, empty) != after.get(k, empty)
    )
    changed = bool(changed_keys)
    if changed:
        _record_staleness(state, before, changed_keys, now, delay)
        state["revision"] += 1
    status, obj, entry = _status_of(state, resource, obj_id)
    result: dict[str, Any] = {"ok": True, "verb": verb}
    result.update(_describe(resource, obj_id, status, obj, entry))
    result.update(extra)
    result["changed"] = changed
    result["revision"] = state["revision"]
    return result, changed


def _state_from_seed(seed: Any, now: float) -> dict[str, Any]:
    try:
        if not isinstance(seed, dict) or seed.get("schema") != SEED_SCHEMA:
            raise _usage(f"seed must be a {SEED_SCHEMA} document")
        tenant = seed.get("tenant")
        if not (
            isinstance(tenant, dict)
            and isinstance(tenant.get("name"), str)
            and isinstance(tenant.get("domain"), str)
        ):
            raise _usage("seed tenant needs name and domain")
        objects = seed.get("objects")
        if not isinstance(objects, dict) or set(objects) - set(RESOURCES):
            raise _usage(f"seed objects must be keyed by {list(RESOURCES)}")
        state = _empty_state(copy.deepcopy(tenant), now)
        for res in RESOURCES:
            records = objects.get(res, [])
            if not isinstance(records, list):
                raise _usage(f"seed {res} must be a list")
            for record in records:
                oid = record.get("id") if isinstance(record, dict) else None
                if _resource_of_id(oid) != res:
                    raise _usage(f"seed {res} record has a missing or foreign id: {oid!r}")
                if oid in state["objects"][res]:
                    raise _usage(f"duplicate seed id {oid}")
                state["objects"][res][oid] = _validate_record(
                    res, oid, record, now=now, from_seed=True
                )
        for res, schema in SCHEMA.items():
            for oid, obj in state["objects"][res].items():
                for name, spec in schema["fields"].items():
                    if spec["mode"] in ("mutable", "create_only"):
                        _check_refs_unique(state, res, oid, name, spec, obj[name])
                rel = schema["relation"]
                if rel:
                    if len(set(obj[rel])) != len(obj[rel]):
                        raise _usage(f"{oid}.{rel} has duplicates")
                    for member in obj[rel]:
                        member_res = _resource_of_id(member)
                        if (
                            member_res not in schema["member_kinds"]
                            or member not in state["objects"][member_res]
                        ):
                            raise _usage(f"{oid}.{rel} references unknown or wrong-type {member!r}")
                    if res == "licenses" and len(obj[rel]) > obj["seats_total"]:
                        raise _usage(f"{oid} assigns more seats than seats_total")
        return state
    except SimTenantError as exc:
        raise _state_error("seed_invalid", f"seed rejected: {exc.message}") from None


# --------------------------------------------------------------------------- API


class Tenant:
    """File-backed fictional tenant. `clock` returns epoch seconds (inject for tests)."""

    def __init__(
        self, state_path: str | os.PathLike[str], *, clock: Callable[[], float] | None = None
    ) -> None:
        if not str(state_path):
            raise _usage("--state FILE is required")
        self.path = Path(state_path)
        self.clock = clock or time.time

    # -- storage

    def _now(self) -> float:
        return float(self.clock())

    def _read_state(self) -> dict[str, Any]:
        if self.path.is_symlink():
            raise _state_error("state_unavailable", "refusing to use a symlinked state file")
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            raise _state_error("state_missing", "state file not found; run 'reset' first") from None
        except OSError as exc:
            raise _state_error(
                "state_unavailable", f"cannot read state file: {exc.strerror}"
            ) from None
        try:
            state = json.loads(raw)
        except ValueError:
            raise _state_error("state_corrupt", "state file is not valid JSON; run reset") from None
        _check_state_shape(state)
        return state

    @contextlib.contextmanager
    def _locked(self, *, require_existing: bool = True) -> Iterator[None]:
        if fcntl is None:  # pragma: no cover
            raise _state_error("locking_unavailable", "POSIX fcntl.flock is required")
        if self.path.is_symlink():
            raise _state_error("state_unavailable", "refusing to use a symlinked state file")
        if require_existing and not self.path.exists():
            raise _state_error("state_missing", "state file not found; run 'reset' first")
        lock_path = str(self.path) + ".lock"
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as exc:
            raise _state_error(
                "state_unavailable", f"cannot open lock file: {exc.strerror}"
            ) from None
        try:
            deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, InterruptedError):
                    if time.monotonic() >= deadline:
                        raise _state_error(
                            "lock_timeout", "another writer holds the state lock"
                        ) from None
                    time.sleep(0.005)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _save(self, state: dict[str, Any]) -> None:
        """Atomic replace: temp file in the same directory, fsync, os.replace, fsync dir."""
        if self.path.is_symlink():
            raise _state_error("state_unavailable", "refusing to replace a symlinked state file")
        parent = self.path.parent
        data = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8")
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(
                dir=str(parent), prefix="." + self.path.name + ".", suffix=".tmp"
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
            tmp = None
        except OSError as exc:
            raise _state_error(
                "state_write_failed", f"state not written: {exc.strerror or exc}"
            ) from None
        finally:
            if tmp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
        with contextlib.suppress(OSError):
            dir_fd = os.open(str(parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    # -- commands

    def reset(self, seed_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        seed_file = Path(seed_path) if seed_path is not None else DEFAULT_SEED
        try:
            seed = json.loads(seed_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise _state_error("seed_missing", f"seed file {seed_file.name!r} not found") from None
        except (OSError, ValueError):
            raise _state_error(
                "seed_invalid", f"seed file {seed_file.name!r} is not readable JSON"
            ) from None
        state = _state_from_seed(seed, self._now())
        with self._locked(require_existing=False):
            self._save(state)
        return {
            "ok": True,
            "verb": "reset",
            "changed": True,
            "revision": state["revision"],
            "seed": seed_file.name,
            "tenant": state["tenant"],
            "counts": {res: len(state["objects"][res]) for res in RESOURCES},
        }

    def list_objects(self, resource: str, *, deleted: bool = False) -> dict[str, Any]:
        resource = _norm_resource(resource)
        state = self._read_state()
        view = _visible(state, self._now())
        if deleted:
            section = view["deleted"][resource]
            items = [
                _describe(resource, oid, "soft_deleted", section[oid]["object"], section[oid])
                for oid in sorted(section, key=_id_key)
            ]
        else:
            section = view["objects"][resource]
            items = [
                _describe(resource, oid, "active", section[oid], None)
                for oid in sorted(section, key=_id_key)
            ]
        return {
            "ok": True,
            "verb": "list",
            "resource": resource,
            "filter": "soft_deleted" if deleted else "active",
            "count": len(items),
            "items": items,
        }

    def get_object(self, resource: str, obj_id: str) -> dict[str, Any]:
        resource = _norm_resource(resource)
        state = self._read_state()
        _require_target_id(state, resource, obj_id)
        view = _visible(state, self._now())
        status, obj, entry = _status_of(view, resource, obj_id)
        if status not in ("active", "soft_deleted"):
            raise _not_found(resource, obj_id)
        result: dict[str, Any] = {"ok": True, "verb": "get"}
        result.update(_describe(resource, obj_id, status, obj, entry))
        return result

    def write(
        self,
        verb: str,
        resource: str,
        obj_id: str,
        *,
        field: str | None = None,
        value: Any = _MISSING,
        member: str | None = None,
        record: Any = None,
        lie: bool = False,
        delay_seconds: Any = 0,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if verb not in WRITE_VERBS:
            raise _usage(f"unknown write verb {verb!r}", allowed=list(WRITE_VERBS))
        resource = _norm_resource(resource)
        delay = _parse_delay(delay_seconds)
        _check_write_options(verb, field, value, member, record)
        lie, dry_run = bool(lie), bool(dry_run)
        honors_dry_run = dry_run and verb != "purge"
        opts = {"field": field, "value": value, "member": member, "record": record}
        now = self._now()
        if lie or honors_dry_run:
            # Computed on a private copy and discarded: the state file is never touched.
            state = self._read_state()
            base_revision = state["revision"]
            result, changed = _apply(state, verb, resource, obj_id, opts, now, delay)
        else:
            with self._locked():
                state = self._read_state()
                base_revision = state["revision"]
                result, changed = _apply(state, verb, resource, obj_id, opts, now, delay)
                if changed:
                    self._save(state)
        result["dry_run"] = {"requested": dry_run, "honored": honors_dry_run}
        if honors_dry_run:
            result.update(
                changed=False,
                would_change=changed,
                preview=True,
                revision=base_revision,
                note=DRY_RUN_NOTE,
            )
            return result
        if dry_run:  # purge: injected fault, executed for real
            result["fault"] = "dry_run_ignored"
            result["warnings"] = [
                "--dry-run was ignored by purge (injected fault): the object was purged "
                "for real and cannot be restored."
            ]
            result["note"] = DRY_RUN_NOTE
        if changed and delay > 0:
            result["replication_delay_seconds"] = delay
            result["visible_to_reads_at"] = _iso(now + delay)
        return result


# --------------------------------------------------------------------------- CLI


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _usage(message)


def _build_parser() -> _Parser:
    parser = _Parser(
        prog="simtenant",
        allow_abbrev=False,
        description="Mock fictional Contoso tenant over a local JSON state file.",
    )
    parser.add_argument("--state", required=True, help="path to the JSON state file")
    parser.add_argument(
        "words", nargs="*", metavar="ARG", help="VERB RESOURCE ID (list: VERB RESOURCE)"
    )
    parser.add_argument("--field")
    parser.add_argument(
        "--value", help="JSON value; text that is not valid JSON is taken as a string"
    )
    parser.add_argument("--member", help="immutable ID to add to / remove from the member list")
    parser.add_argument("--record", help="JSON object for add --record (creates a new object)")
    parser.add_argument("--deleted", action="store_true", help="list: show soft-deleted objects")
    parser.add_argument("--lie", action="store_true", help="fault: report success, change nothing")
    parser.add_argument(
        "--delay-seconds", dest="delay_seconds", help="fault: reads lag the backend"
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="honoured by most writes; ignored by purge (fault)",
    )
    parser.add_argument("--seed", help="reset: seed file (default: bundled Contoso seed)")
    return parser


def _parse_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _parse_record(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        raise _usage("--record must be valid JSON") from None


def run(
    argv: list[str] | None = None, *, clock: Callable[[], float] | None = None
) -> tuple[int, dict[str, Any]]:
    """Execute one CLI invocation. Returns (exit_code, json_payload); never prints."""
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _build_parser().parse_intermixed_args(argv)
        words = args.words
        if not words:
            raise _usage("missing VERB", allowed=list(ALL_VERBS))
        if len(words) > 3:
            raise _usage("too many positional arguments", extra=words[3:])
        verb = words[0]
        resource = words[1] if len(words) > 1 else None
        obj_id = words[2] if len(words) > 2 else None
        given = {
            "field": args.field is not None,
            "value": args.value is not None,
            "member": args.member is not None,
            "record": args.record is not None,
            "deleted": args.deleted,
            "lie": args.lie,
            "delay_seconds": args.delay_seconds is not None,
            "dry_run": args.dry_run,
            "seed": args.seed is not None,
        }

        def reject_except(*allowed: str) -> None:
            bad = sorted(k for k, v in given.items() if v and k not in allowed)
            if bad:
                raise _usage(
                    f"option(s) not valid for {verb}: "
                    + ", ".join("--" + k.replace("_", "-") for k in bad)
                )

        if verb not in ALL_VERBS:
            raise _usage(f"unknown verb {verb!r}", allowed=list(ALL_VERBS))
        tenant = Tenant(args.state, clock=clock)
        if verb == "reset":
            if resource not in (None, "tenant", "all") or obj_id is not None:
                raise _usage("reset takes no RESOURCE or ID")
            reject_except("seed")
            return EXIT_OK, tenant.reset(args.seed)
        if resource is None:
            raise _usage(f"{verb} requires RESOURCE", allowed=list(RESOURCES))
        if verb == "list":
            if obj_id is not None:
                raise _usage("list takes no ID")
            reject_except("deleted")
            return EXIT_OK, tenant.list_objects(resource, deleted=args.deleted)
        if obj_id is None:
            raise _usage(f"{verb} requires an immutable ID")
        if verb == "get":
            reject_except()
            return EXIT_OK, tenant.get_object(resource, obj_id)
        reject_except("field", "value", "member", "record", "lie", "delay_seconds", "dry_run")
        value = _MISSING if args.value is None else _parse_value(args.value)
        record = None if args.record is None else _parse_record(args.record)
        return EXIT_OK, tenant.write(
            verb,
            resource,
            obj_id,
            field=args.field,
            value=value,
            member=args.member,
            record=record,
            lie=args.lie,
            delay_seconds=args.delay_seconds,
            dry_run=args.dry_run,
        )
    except SimTenantError as exc:
        return exc.exit_code, exc.payload()
    except Exception as exc:  # noqa: BLE001 - always answer in JSON
        return EXIT_INTERNAL, {
            "ok": False,
            "changed": False,
            "exit_code": EXIT_INTERNAL,
            "error": {"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"},
        }


def main(argv: list[str] | None = None) -> int:
    code, payload = run(argv)
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
