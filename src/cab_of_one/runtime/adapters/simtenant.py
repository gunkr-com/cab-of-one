"""simtenant adapter (fictional Contoso demo tenant): classification and targets.

Only programs the policy names in ``trusted_simtenant_commands`` (exact command
word) or ``trusted_simtenant_scripts`` (exact path string, a leading ``./`` is
ignored) are handled here. A file that merely has the basename
``simtenant.py`` is not trusted; classify.py reports it as unknown-admin.

The grammar mirrors the real CLI in ``simtenant/simtenant.py`` (argparse,
``allow_abbrev=False``, options may appear anywhere)::

    PROGRAM --state FILE VERB RESOURCE [ID] [options]
    PROGRAM --state FILE reset [tenant|all] [--seed SEED.json]

    list RESOURCE [--deleted]
    get  RESOURCE ID
    set  RESOURCE ID --field NAME --value VALUE
    add  RESOURCE ID (--member ID | --record JSON)
    remove RESOURCE ID --member ID
    delete | purge | restore  RESOURCE ID
    write verbs also accept --lie, --dry-run, --delay-seconds N

RESOURCE is users, groups, mailboxes, policies or licenses (singular aliases,
case-insensitive as in the real CLI). IDs must be immutable IDs of the
resource's own prefix (u-, g-, mbx-, pol-, lic- followed by 3-8 digits);
members must be of a kind the resource's relation accepts. Anything the real
CLI would reject, and anything this adapter does not model, is unknown-admin.
``--dry-run`` and ``--lie`` never lower the classification.

``Result.scope`` is the normalised project-relative ``--state`` path, or
``None`` when the path is absolute, escapes with ``..``, uses ``~`` or a
directory change happened earlier (then a relative path no longer names a
project file). The guard must still check the real path on disk (safe child,
no symlink) before trusting the scope.
"""

from __future__ import annotations

import json
import math
import posixpath
import re
import shlex
from collections.abc import Sequence

from ..classification_types import (
    FLAG_DRY_RUN,
    FLAG_LIE,
    FLAG_TENANT_WIDE,
    KIND_READ,
    KIND_WRITE,
    AdapterContext,
    Arg,
    Result,
    make_not_admin,
    make_unknown,
)

NAME = "simtenant"
PROGRAM_BASENAMES = frozenset({"simtenant", "simtenant.py"})

READ_VERBS = frozenset({"list", "get"})
WRITE_VERBS = frozenset({"set", "add", "remove", "delete", "purge", "restore", "reset"})
VERBS = READ_VERBS | WRITE_VERBS

RESOURCES = ("users", "groups", "mailboxes", "policies", "licenses")
DEFAULT_RESOURCES = frozenset(RESOURCES)
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
ID_RE = re.compile(r"^(u|g|mbx|pol|lic)-([0-9]{3,8})$")

# Relation (member list) per resource and the member kinds it accepts.
MEMBER_KINDS: dict[str, tuple[str, ...]] = {
    "users": (),
    "groups": ("users",),
    "mailboxes": ("users",),
    "policies": ("users", "groups"),
    "licenses": ("users",),
}
# Fields ``set`` may change (mode "mutable" in the real schema).
MUTABLE_FIELDS: dict[str, frozenset[str]] = {
    "users": frozenset(
        {
            "display_name",
            "given_name",
            "surname",
            "user_principal_name",
            "mail",
            "department",
            "job_title",
            "account_enabled",
            "usage_location",
            "manager_id",
        }
    ),
    "groups": frozenset(
        {
            "display_name",
            "description",
            "mail_nickname",
            "mail",
            "mail_enabled",
            "security_enabled",
        }
    ),
    "mailboxes": frozenset(
        {
            "display_name",
            "primary_smtp_address",
            "forwarding_smtp_address",
            "deliver_to_mailbox_and_forward",
            "litigation_hold_enabled",
            "archive_enabled",
        }
    ),
    "policies": frozenset({"display_name", "state", "description", "controls"}),
    "licenses": frozenset({"display_name", "seats_total"}),
}
# Extra keys ``add --record`` may carry (create-only and relation fields, plus id).
RECORD_EXTRA_FIELDS: dict[str, frozenset[str]] = {
    "users": frozenset({"id"}),
    "groups": frozenset({"id", "group_type", "members"}),
    "mailboxes": frozenset({"id", "owner_id", "recipient_type", "delegates"}),
    "policies": frozenset({"id", "policy_type", "include"}),
    "licenses": frozenset({"id", "sku_part_number", "assigned_to"}),
}
RESET_WORDS = frozenset({"tenant", "all"})
MAX_DELAY_SECONDS = 24 * 60 * 60

_VALUED = frozenset(
    {
        "--state",
        "--field",
        "--value",
        "--member",
        "--record",
        "--delay-seconds",
        "--seed",
    }
)
_SWITCHES = frozenset({"--lie", "--dry-run", "--deleted"})
_WRITE_OPTIONS = frozenset(
    {
        "--field",
        "--value",
        "--member",
        "--record",
        "--lie",
        "--delay-seconds",
        "--dry-run",
    }
)
_ALLOWED = {"reset": frozenset({"--seed"}), "list": frozenset({"--deleted"}), "get": frozenset()}
# argparse treats these as values, not options, because no option looks like a number.
_NEGATIVE_NUMBER_RE = re.compile(r"^-\d+$|^-\d*\.\d+$")
_DELAY_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")
_SCAN_WORD_RE = re.compile(r"[^\s\"',\[\]()]+")


def strip_dot(path: str) -> str:
    while path.startswith("./"):
        path = path[2:]
    return path


def state_scope(path: str) -> str | None:
    """Normalised project-relative state path, or None when it cannot name a project file."""
    if not isinstance(path, str) or not path or "\\" in path:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return None
    if path.startswith(("/", "~")) or ".." in path.split("/"):
        return None
    norm = posixpath.normpath(path)
    if norm in (".", "") or norm.startswith(("/", "..")):
        return None
    return norm


def matches(argv: Sequence[Arg], ctx: AdapterContext) -> bool:
    if not argv or argv[0].expands:
        return False
    word = argv[0].text
    if word in ctx.trusted_simtenant_commands:
        return True
    return strip_dot(word) in ctx.trusted_simtenant_scripts


def _resource(word: str, ctx: AdapterContext) -> str | None:
    plural = RESOURCE_ALIASES.get(word.lower())
    if plural is None:
        return None
    allowed = ctx.simtenant_resources if ctx.simtenant_resources is not None else DEFAULT_RESOURCES
    return plural if plural in allowed else None


def _id_resource(obj_id: str) -> str | None:
    m = ID_RE.match(obj_id)
    return PREFIX_TO_RESOURCE[m.group(1)] if m else None


def _delay_ok(text: str) -> bool:
    if not _DELAY_RE.match(text):
        return False
    value = float(text)
    return math.isfinite(value) and 0 <= value <= MAX_DELAY_SECONDS


def classify(argv: Sequence[Arg], ctx: AdapterContext) -> Result:
    raw = " ".join(a.text for a in argv)

    def unk(reason: str, verb: str | None = None) -> Result:
        return make_unknown(f"simtenant: {reason}", adapter=NAME, verb=verb, canonical=raw)

    if not matches(argv, ctx):
        return unk("program is not listed in trusted_simtenant_commands/trusted_simtenant_scripts")

    args = list(argv[1:])
    opts: dict[str, str] = {}
    switches: set[str] = set()
    pos: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        t = a.text
        if a.expands:
            return unk("run-time expansion in an argument")
        if t.startswith("-") and not _NEGATIVE_NUMBER_RE.match(t):
            name, eq, inline = t.partition("=")
            if name in ("--help", "-h") and not eq:
                if len(args) == 1:
                    return make_not_admin(raw, "simtenant help")
                return unk("--help mixed with other arguments")
            if name in _SWITCHES:
                if eq or name in switches:
                    return unk(f"malformed or repeated {name}")
                switches.add(name)
                i += 1
                continue
            if name in _VALUED:
                if name in opts:
                    return unk(f"repeated {name}")
                if eq:
                    opts[name] = inline
                    i += 1
                    continue
                if i + 1 >= len(args):
                    return unk(f"{name} without a value")
                val = args[i + 1]
                if val.expands:
                    return unk(f"run-time expansion in {name}")
                if val.text.startswith("-") and not _NEGATIVE_NUMBER_RE.match(val.text):
                    return unk(f"{name} value looks like an option")
                opts[name] = val.text
                i += 2
                continue
            return unk(f"unknown option {name!r}")
        pos.append(t)
        i += 1

    if not opts.get("--state"):
        return unk("--state FILE is required")
    if not pos:
        return unk("missing verb")
    verb = pos[0]
    if verb not in VERBS:
        return unk(f"unknown verb {verb!r}")
    given = set(opts) - {"--state"} | switches
    allowed = _ALLOWED.get(verb, _WRITE_OPTIONS)
    if given - allowed:
        return unk(f"option(s) not valid for {verb}: {', '.join(sorted(given - allowed))}", verb)

    scope = None if ctx.cwd_changed else state_scope(opts["--state"])
    flags: set[str] = set()
    if "--lie" in switches:
        flags.add(FLAG_LIE)
    if "--dry-run" in switches:
        flags.add(FLAG_DRY_RUN)
    reasons: list[str] = []
    if switches & {"--lie", "--dry-run"}:
        reasons.append("--dry-run/--lie do not lower the classification")
    if scope is None:
        reasons.append("state path is not a project-relative scope; no catalogue match")

    if verb == "reset":
        if len(pos) > 2 or (len(pos) == 2 and pos[1] not in RESET_WORDS):
            return unk("reset takes no RESOURCE or ID", verb)
        parts = ["simtenant", "reset"]
        if "--seed" in opts:
            if not opts["--seed"]:
                return unk("--seed without a file", verb)
            parts += ["--seed", opts["--seed"]]
        flags.add(FLAG_TENANT_WIDE)
        canonical = " ".join(shlex.quote(p) for p in parts)
        why = ("reset replaces the whole virtual tenant state", *reasons)
        return Result(
            KIND_WRITE, False, NAME, verb, canonical, (), False, frozenset(flags), why, (), scope
        )

    expected = 2 if verb == "list" else 3
    if len(pos) != expected:
        return unk(f"'{verb}' expects {expected - 1} argument(s) after the verb", verb)
    resource = _resource(pos[1], ctx)
    if resource is None:
        return unk(f"unknown or disallowed resource {pos[1]!r}", verb)
    parts = ["simtenant", verb, resource]

    if verb == "list":
        if "--deleted" in switches:
            parts.append("--deleted")
        canonical = " ".join(shlex.quote(p) for p in parts)
        return Result(
            KIND_READ,
            False,
            NAME,
            verb,
            canonical,
            (),
            False,
            frozenset(flags),
            tuple(["simtenant read", *reasons]),
            (),
            scope,
        )

    obj_id = pos[2]
    if _id_resource(obj_id) != resource:
        return unk(
            f"{obj_id!r} is not an immutable {resource} ID "
            "(display names and other prefixes are never targets)",
            verb,
        )
    parts.append(obj_id)

    if "--delay-seconds" in opts and not _delay_ok(opts["--delay-seconds"]):
        return unk(f"--delay-seconds must be between 0 and {MAX_DELAY_SECONDS}", verb)
    has_field = "--field" in opts
    has_value = "--value" in opts
    has_member = "--member" in opts
    has_record = "--record" in opts
    if verb == "set":
        if not (has_field and has_value) or has_member or has_record:
            return unk("set needs --field and --value and no --member/--record", verb)
        field = opts["--field"]
        if field not in MUTABLE_FIELDS[resource]:
            return unk(f"{field!r} is not a settable {resource} field", verb)
        parts += ["--field", field, "--value", opts["--value"]]
    elif verb == "add":
        if has_field or has_value or has_member == has_record:
            return unk("add needs exactly one of --member or --record", verb)
        if has_member:
            bad = _member_problem(resource, opts["--member"])
            if bad:
                return unk(bad, verb)
            parts += ["--member", opts["--member"]]
        else:
            record = _record(resource, obj_id, opts["--record"])
            if record is None:
                return unk("--record is not a JSON object with known fields", verb)
            parts += ["--record", record]
    elif verb == "remove":
        if has_field or has_value or has_record or not has_member:
            return unk("remove needs --member and nothing else", verb)
        bad = _member_problem(resource, opts["--member"])
        if bad:
            return unk(bad, verb)
        parts += ["--member", opts["--member"]]
    elif has_field or has_value or has_member or has_record:
        return unk(f"{verb} takes no --field/--value/--member/--record", verb)

    canonical = " ".join(shlex.quote(p) for p in parts)
    targets = (f"{resource}/{obj_id}",)
    kind = KIND_READ if verb in READ_VERBS else KIND_WRITE
    label = "simtenant read" if kind == KIND_READ else "simtenant write"
    return Result(
        kind,
        False,
        NAME,
        verb,
        canonical,
        targets,
        True,
        frozenset(flags),
        tuple([label, *reasons]),
        (),
        scope,
    )


def _member_problem(resource: str, member: str) -> str | None:
    kinds = MEMBER_KINDS[resource]
    if not kinds:
        return f"{resource} has no member list"
    member_resource = _id_resource(member)
    if member_resource is None:
        return "--member is not an immutable ID"
    if member_resource not in kinds:
        return f"{resource} members must be {'/'.join(kinds)} IDs"
    return None


def _record(resource: str, obj_id: str, text: str) -> str | None:
    """Canonical JSON of an ``add --record`` object, or None when it is not modelled."""
    try:
        record = json.loads(text)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    if set(record) - (MUTABLE_FIELDS[resource] | RECORD_EXTRA_FIELDS[resource]):
        return None
    if "id" in record and record["id"] != obj_id:
        return None
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def scan_text(text: str) -> list[Result]:
    """Find simtenant invocations in opaque text. Results are always unknown-admin."""
    out: list[Result] = []
    for line in text.splitlines():
        words = _SCAN_WORD_RE.findall(line)
        for k, w in enumerate(words):
            if posixpath.basename(w) not in PROGRAM_BASENAMES:
                continue
            rest = words[k + 1 :]
            verb = next((x for x in rest if x in VERBS), None)
            tail = rest[rest.index(verb) :] if verb else rest
            flags = (FLAG_TENANT_WIDE,) if verb == "reset" else ()
            canonical = " ".join(["simtenant", *tail])
            out.append(
                make_unknown(
                    "simtenant reference in text that is not parsed",
                    adapter=NAME,
                    verb=verb,
                    canonical=canonical,
                    flags=flags,
                )
            )
            break
    return out


# Re-exported for tests and classify.py.
__all__ = [
    "DEFAULT_RESOURCES",
    "ID_RE",
    "MEMBER_KINDS",
    "MUTABLE_FIELDS",
    "NAME",
    "PROGRAM_BASENAMES",
    "READ_VERBS",
    "RESOURCES",
    "RESOURCE_ALIASES",
    "WRITE_VERBS",
    "classify",
    "matches",
    "scan_text",
    "state_scope",
    "strip_dot",
]
