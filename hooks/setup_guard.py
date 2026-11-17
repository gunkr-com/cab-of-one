"""cab-of-one plugin setup-session hook (UserPromptExpansion and PreToolUse).

Imports the generator from this plugin's own ``src/``. If that import fails, a small
standard-library fallback still fails closed for the generator: the cab-of-one command
is blocked, and in a project that has a setup marker every tool call except Read, Grep,
Glob and AskUserQuestion is denied. Projects without a marker are not constrained.
"""

import json
import os
import sys

sys.dont_write_bytecode = True
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, _SRC)

_NAMES = {"cab-of-one", "cab-of-one:cab-of-one", "/cab-of-one", "/cab-of-one:cab-of-one"}
_READ = {"Read", "Grep", "Glob", "AskUserQuestion"}
_REASON = "cab-of-one: the setup guard could not start; blocking."


def _fallback():
    def deny(code):
        payload = {
            "decision": "block",
            "reason": _REASON,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": _REASON,
            },
        }
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
        sys.stderr.write(_REASON + "\n")
        raise SystemExit(code)

    try:
        data = json.loads(sys.stdin.buffer.read(16 * 1024 * 1024 + 1))
        if not isinstance(data, dict):
            deny(2)
        event = data.get("hook_event_name")
        if event == "UserPromptExpansion":
            name = data.get("command_name")
            if isinstance(name, str) and name not in _NAMES:
                sys.stdout.write("{}\n")
                raise SystemExit(0)
            deny(2)
        if event == "PreToolUse":
            project = os.environ.get("CLAUDE_PROJECT_DIR")
            if isinstance(project, str) and os.path.isabs(project):
                marker = os.path.join(project, ".cab", "setup", "session.json")
                if not os.path.lexists(marker) or data.get("tool_name") in _READ:
                    sys.stdout.write("{}\n")
                    raise SystemExit(0)
        deny(2)
    except SystemExit:
        raise
    except BaseException:
        deny(2)


try:
    from cab_of_one.setup import setupguard  # noqa: E402
except BaseException:
    _fallback()
else:
    setupguard.main()
