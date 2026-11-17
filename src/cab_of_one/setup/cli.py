"""``cab setup`` command line (S9). C-main calls ``main(args_after_setup, source_root=...)``.

Commands (options are never abbreviated: ``allow_abbrev=False``)

    render    [--profile PATH | --answers PATH | --reference NAME] [--project DIR | --out DIR]
    apply     [--project DIR] [--take-new PATH ...]          person only, real terminal
    uninstall [--project DIR]                                person only, real terminal
    discover  [--project DIR]
    begin     --session-id ID [--project DIR]
    shape     DIR                                            one line of bounded JSON

``--project`` defaults to the current folder. ``render`` without a profile option uses
``<project>/.cab/setup/profile.toml`` (the interview output); ``--answers`` is the same as
``--profile`` (DESIGN §10-2 CLI path). ``--reference contoso-solo`` uses the explicit
reference loader (the only path that accepts the fictional demo tenant).

Exit codes: 0 ok, 1 not confirmed, 2 usage, 3 refused, 4 blocked or lock held,
5 failed (nothing kept: rolled back, or stopped before any change; also internal errors),
6 rollback failed (see the listed paths), 130 interrupted.
Errors are fixed codes on one line; no traceback, no argument value is echoed back.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from ..runtime import doctor as doctor_mod
from ..runtime.terminal import sanitize
from . import apply as apply_mod
from . import discover as discover_mod
from . import profile as profile_mod
from . import render as render_mod
from . import rules as rules_mod
from . import session as session_mod
from .apply import (
    EXIT_BLOCKED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_ROLLED_BACK,
    EXIT_USAGE,
    ApplyError,
    Outcome,
    Services,
)
from .manifest import SetupDataError, loads_strict

__all__ = ["EXIT_INTERNAL", "EXIT_INTERRUPTED", "main", "shape_json", "shape_project"]

EXIT_INTERNAL = EXIT_ROLLED_BACK  # 5: failed, nothing kept
EXIT_INTERRUPTED = 130
COMMANDS = ("render", "apply", "uninstall", "discover", "begin", "shape")
SHAPE_CODE = "shape"
#: ``cab setup shape`` prints one line of JSON (not cut at the 512-character display limit
#: of ``sanitize``); larger output is replaced by the fixed ``SHAPE_UNAVAILABLE`` object.
MAX_SHAPE_CHARS = 64 * 1024
MAX_SHAPE_EVENTS = 64
SHAPE_UNAVAILABLE = {"schema": 1, "shape": "unavailable", "reason": "too_large_or_invalid"}
#: Only these names are printed; any other hook event counts as ``other_hook_events`` and
#: any other tool is ``mcp`` (``mcp__...``) or ``other``, so no user-chosen name is shown.
KNOWN_HOOK_EVENTS = frozenset(
    {
        "ConfigChange",
        "Notification",
        "PermissionRequest",
        "PostToolUse",
        "PostToolUseFailure",
        "PreCompact",
        "PreToolUse",
        "SessionEnd",
        "SessionStart",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "UserPromptSubmit",
    }
)
KNOWN_TOOLS = frozenset(
    {
        "Agent",
        "AskUserQuestion",
        "Bash",
        "BashOutput",
        "Edit",
        "ExitPlanMode",
        "Glob",
        "Grep",
        "KillShell",
        "LS",
        "MultiEdit",
        "NotebookEdit",
        "NotebookRead",
        "Read",
        "SlashCommand",
        "Skill",
        "Task",
        "TodoWrite",
        "WebFetch",
        "WebSearch",
        "Write",
    }
)
USAGE = (
    "usage: cab setup {render,apply,uninstall,discover,begin,shape} [options]  "
    "(see `cab setup <command> --help`)"
)


class _Usage(Exception):
    pass


class _Exit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _Parser(argparse.ArgumentParser):
    """No abbreviations, no ``sys.exit``, no echo of a bad argument."""

    def __init__(self, *args: Any, out: Any = None, **kwargs: Any) -> None:
        kwargs["allow_abbrev"] = False
        kwargs["exit_on_error"] = False
        super().__init__(*args, **kwargs)
        self._out = out

    def error(self, message: str) -> Any:  # noqa: ARG002 - the message may echo input
        raise _Usage()

    def exit(self, status: int = 0, message: str | None = None) -> Any:  # noqa: ARG002
        raise _Exit(status)

    def _print_message(self, message: str, file: Any = None) -> None:  # noqa: ARG002
        if message and self._out is not None:
            try:
                self._out.write(message)
            except Exception:
                pass


def _parser(out: Any) -> _Parser:
    root = _Parser(prog="cab setup", out=out, description="cab-of-one generator")
    sub = root.add_subparsers(dest="command", parser_class=_Parser)

    render = sub.add_parser("render", out=out, help="render and stage a preview")
    src = render.add_mutually_exclusive_group()
    src.add_argument("--profile", metavar="PATH")
    src.add_argument("--answers", metavar="PATH")
    src.add_argument("--reference", metavar="NAME")
    render.add_argument("--project", "--out", dest="project", metavar="DIR")

    apply = sub.add_parser("apply", out=out, help="apply the staged render (person only)")
    apply.add_argument("--project", metavar="DIR")
    apply.add_argument("--take-new", dest="take_new", action="append", default=[], metavar="PATH")

    uninstall = sub.add_parser("uninstall", out=out, help="remove generated files (person only)")
    uninstall.add_argument("--project", metavar="DIR")

    discover = sub.add_parser("discover", out=out, help="read-only discovery")
    discover.add_argument("--project", metavar="DIR")

    begin = sub.add_parser("begin", out=out, help="bind a setup session (CLI-only path)")
    begin.add_argument("--session-id", dest="session_id", required=True, metavar="ID")
    begin.add_argument("--project", metavar="DIR")

    shape = sub.add_parser("shape", out=out, help="shape of a generated harness (read-only)")
    shape.add_argument("folder", metavar="DIR")
    return root


def _write(stream: Any, lines: Sequence[str]) -> None:
    try:
        for line in lines:
            stream.write(sanitize(line) + "\n")
        stream.flush()
    except Exception:
        pass


def _write_json(stream: Any, text: str) -> None:
    """Write one ``shape_json`` line unchanged. Anything that is not printable ASCII
    within the size bound is replaced by the fixed ``SHAPE_UNAVAILABLE`` object."""
    if not (isinstance(text, str) and len(text) <= MAX_SHAPE_CHARS and _printable_ascii(text)):
        text = json.dumps(SHAPE_UNAVAILABLE, sort_keys=True)
    try:
        stream.write(text + "\n")
        stream.flush()
    except Exception:
        pass


def _printable_ascii(text: str) -> bool:
    return text.isascii() and text.isprintable()


def _abspath(services: Services, value: str | None) -> str:
    cwd = services.cwd()
    if value is None:
        return cwd
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ApplyError("path_invalid", "", EXIT_USAGE)
    return value if os.path.isabs(value) else os.path.join(cwd, value)


def _source(source_root: str | None) -> str:
    if (
        not isinstance(source_root, str)
        or not os.path.isabs(source_root)
        or "\x00" in source_root
        or not os.path.isdir(source_root)
        or os.path.islink(source_root)
    ):
        raise ApplyError(
            "source_root_unavailable",
            "run this command from the cab-of-one plugin's scripts/cab",
            EXIT_REFUSED,
        )
    return source_root


# --------------------------------------------------------------------------- commands


def _discover(project: str, services: Services) -> Outcome:
    root = apply_mod.project_root(project)
    found = discover_mod.discover(root, finder=services.finder)
    rel = discover_mod.write_discovery(found, root)
    lines = [f"cab-of-one setup discover: project {os.path.basename(root)} (read-only)"]
    lines.append(f"  written: {rel} (paths, line numbers and codes only)")
    for key in sorted(found.counts):
        lines.append(f"  count {key}: {found.counts[key]}")
    for item in found.inferred:
        value = item.value
        shown = ", ".join(value) if isinstance(value, tuple) else str(value).lower()
        lines.append(f"  {item.field} = {shown} [{item.source}]")
    lines += [f"  CLI {c.name}: {c.status}" for c in found.cli]
    lines += [f"  notice: {n}" for n in found.notices]
    lines += [f"  limit hit: {limit}" for limit in found.limits_hit]
    return Outcome(EXIT_OK, "discovered", tuple(lines))


def _begin(project: str, session_id: str) -> Outcome:
    root = apply_mod.project_root(project)
    binding = session_mod.begin(root, session_id)
    state = "bound" if binding.created else "already bound (same session)"
    return Outcome(
        EXIT_OK,
        "begun",
        (f"setup session {state}; this session is now limited to .cab/setup writes",),
    )


def _tools(value: Any) -> list[str] | None:
    if isinstance(value, list):
        items = [v for v in value if isinstance(v, str)]
        if len(items) != len(value):
            return None
    elif isinstance(value, str):
        items = value.split(",")
    else:
        return None
    out = []
    for item in items:
        base = item.split("(", 1)[0].strip().strip("'\"")
        if base:
            out.append(base)
    return out


def _tool_kind(name: str) -> str:
    if name in KNOWN_TOOLS:
        return name
    return "mcp" if name.startswith("mcp__") else "other"


def shape_project(folder: str) -> dict[str, Any]:
    """Shape of a generated harness (DESIGN §10-7-3 step 2). Read-only.

    Gate kinds, agent tool scopes and hook events and roles only: no file content, agent or
    skill names, prose, paths or rule text. Hook events and tool names are printed only
    from the fixed ``KNOWN_HOOK_EVENTS`` / ``KNOWN_TOOLS`` lists; others are counted or
    reported as ``mcp`` / ``other``. Unreadable parts are reported as ``unknown``.
    """
    root = apply_mod.project_root(folder)
    nodes = apply_mod.inspect_tree(root, [".claude/settings.json", ".cab/manifest.json"])
    shape: dict[str, Any] = {"schema": 1}
    settings = nodes[".claude/settings.json"]
    doc: Any = None
    if settings.kind == "file":
        try:
            doc = loads_strict(settings.data)  # type: ignore[arg-type]
        except (ValueError, RecursionError):
            doc = None
    if not isinstance(doc, dict):
        shape["settings"] = "unknown" if settings.kind != "absent" else "absent"
    else:
        hooks_out = []
        other_events = 0
        hooks = doc.get("hooks") if isinstance(doc.get("hooks"), dict) else {}
        for event in sorted(hooks):
            if event not in KNOWN_HOOK_EVENTS or len(hooks_out) >= MAX_SHAPE_EVENTS:
                other_events += 1
                continue
            groups = hooks[event] if isinstance(hooks[event], list) else []
            ours = closed = 0
            for group in groups:
                entries = group.get("hooks") if isinstance(group, dict) else None
                for hook in entries if isinstance(entries, list) else []:
                    command = hook.get("command") if isinstance(hook, dict) else None
                    if isinstance(command, str) and ".claude/hooks/cab/" in command:
                        ours += 1
                        closed += hook.get("onFailure") == "block"
            hooks_out.append({"event": event, "cab_handlers": ours, "on_failure_block": closed})
        perms = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
        raw_deny = perms.get("deny")
        deny = [r for r in raw_deny if isinstance(r, str)] if isinstance(raw_deny, list) else []
        shape["hooks"] = hooks_out
        shape["other_hook_events"] = other_events
        shape["deny"] = {
            "rules": len(deny),
            "protected_path_rules": sum(r.startswith(("Edit(", "Write(")) for r in deny),
            "read_rules": sum(r.startswith("Read(") for r in deny),
            "human_only_commands": sum(r.startswith("Bash(cab ") for r in deny),
        }
        shape["bypass_disabled"] = perms.get("disableBypassPermissionsMode") == "disable"
    agents: list[dict[str, Any]] = []
    folder_rel = ".claude/agents"
    if apply_mod._real_dir_chain(root, folder_rel):
        try:
            with os.scandir(apply_mod._abs(root, folder_rel)) as entries:
                names = sorted(e.name for e in entries if e.name.endswith(".md"))
        except OSError:
            names = []
        for name in names[:256]:
            node = apply_mod._read_node(apply_mod._abs(root, f"{folder_rel}/{name}"))
            text = None
            if node.kind == "file":
                try:
                    text = node.data.decode("utf-8")  # type: ignore[union-attr]
                except UnicodeDecodeError:
                    text = None
            front = doctor_mod.parse_frontmatter(text) if text is not None else None
            tools = _tools(front.get("tools")) if isinstance(front, dict) else None
            if tools is None:
                agents.append({"tools": "unknown"})
                continue
            base = sorted({_tool_kind(t) for t in tools})
            agents.append(
                {
                    "tools": base,
                    "read_only": set(base) <= {"Read", "Grep", "Glob"},
                    "writes_files": bool({"Write", "Edit"} & set(base)),
                    "runs_commands": "Bash" in base,
                }
            )
    agents.sort(key=lambda a: json.dumps(a, sort_keys=True))
    shape["agents"] = agents
    shape["manifest"] = nodes[".cab/manifest.json"].kind == "file"
    return shape


def shape_json(shape: Any) -> str:
    """``shape`` as one line of valid JSON: sorted keys, ASCII only, at most
    ``MAX_SHAPE_CHARS``. Anything else gives the fixed ``SHAPE_UNAVAILABLE`` object."""
    try:
        text = json.dumps(shape, sort_keys=True, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        text = ""
    if not text or len(text) > MAX_SHAPE_CHARS or not _printable_ascii(text):
        return json.dumps(SHAPE_UNAVAILABLE, sort_keys=True)
    # JSON escaping can hide a control character inside otherwise printable output.
    pending = [json.loads(text)]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            if value and not value.isprintable():
                return json.dumps(SHAPE_UNAVAILABLE, sort_keys=True)
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return text


def _shape(folder: str, services: Services) -> Outcome:
    data = shape_project(_abspath(services, folder))
    return Outcome(EXIT_OK, SHAPE_CODE, (shape_json(data),))


# --------------------------------------------------------------------------- main


def _dispatch(args: argparse.Namespace, source_root: str | None, services: Services) -> Outcome:
    command = args.command
    if command == "shape":
        return _shape(args.folder, services)
    project = _abspath(services, getattr(args, "project", None))
    if command == "render":
        profile_path = args.profile if args.profile is not None else args.answers
        return apply_mod.render_project(
            project,
            source_root=_source(source_root),
            services=services,
            profile_path=_abspath(services, profile_path) if profile_path is not None else None,
            reference=args.reference,
        )
    if command == "apply":
        return apply_mod.apply_project(
            project, source_root=_source(source_root), services=services, take_new=args.take_new
        )
    if command == "uninstall":
        from .uninstall import uninstall_project

        return uninstall_project(project, services=services)
    if command == "discover":
        return _discover(project, services)
    if command == "begin":
        return _begin(project, args.session_id)
    raise _Usage()


def _refusal(kind: str, code: str, detail: Any) -> str:
    extra = f" ({detail})" if isinstance(detail, str) and detail else ""
    return f"cab setup: {kind}: {code}{extra}"


def main(
    argv: Sequence[str] | None = None,
    *,
    source_root: str | None,
    services: Services | None = None,
) -> int:
    """Run ``cab setup <command>``. ``argv`` is everything after the word ``setup``
    (``None``: ``sys.argv[1:]`` without a leading ``setup``). Never raises."""
    services = services or Services()
    out, err = services.out(), services.err()
    if argv is None:
        argv = sys.argv[1:]
        if argv[:1] == ["setup"]:
            argv = argv[1:]
    try:
        args_list = [a for a in argv]
        if any(type(a) is not str for a in args_list):
            raise _Usage()
        args = _parser(out).parse_args(args_list)
        if args.command not in COMMANDS:
            raise _Usage()
    except _Exit as done:
        return done.status if type(done.status) is int else EXIT_USAGE
    except (_Usage, argparse.ArgumentError):
        _write(err, ["cab setup: usage error", USAGE])
        return EXIT_USAGE
    except Exception:
        _write(err, ["cab setup: usage error", USAGE])
        return EXIT_USAGE
    try:
        outcome = _dispatch(args, source_root, services)
    except KeyboardInterrupt:
        _write(err, ["cab setup: interrupted"])
        return EXIT_INTERRUPTED
    except ApplyError as exc:
        _write(err, [_refusal("refused", exc.code, exc.detail)])
        return exc.exit_code
    except profile_mod.ProfileError as exc:
        _write(err, [_refusal("profile refused", exc.code, exc.field)])
        return EXIT_REFUSED
    except rules_mod.RulesError as exc:
        _write(err, [_refusal("rules refused", exc.code, exc.where)])
        return EXIT_REFUSED
    except render_mod.RenderError as exc:
        _write(err, [_refusal("render refused", exc.code, exc.detail)])
        return EXIT_REFUSED
    except SetupDataError as exc:
        _write(err, [_refusal("refused", exc.code, "")])
        return EXIT_REFUSED
    except session_mod.SessionError as exc:
        _write(err, [_refusal("session refused", exc.code, "")])
        return EXIT_REFUSED
    except discover_mod.DiscoveryError as exc:
        _write(err, [_refusal("discovery refused", exc.code, "")])
        return EXIT_REFUSED
    except Exception as exc:
        _write(err, [f"cab setup: internal error ({type(exc).__name__}); nothing was applied"])
        return EXIT_INTERNAL
    if args.command == "shape" and outcome.code == SHAPE_CODE and outcome.exit == EXIT_OK:
        _write_json(out, outcome.lines[0] if len(outcome.lines) == 1 else "")
        return EXIT_OK
    _write(out if outcome.exit in (EXIT_OK, EXIT_BLOCKED) else err, outcome.lines)
    return outcome.exit
