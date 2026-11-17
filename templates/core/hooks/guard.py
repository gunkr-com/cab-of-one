"""cab-of-one PreToolUse guard entry. Generated pinned copy; a person changes it by PR."""

import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from cab_of_one.runtime import guard  # noqa: E402
except BaseException:  # the guard cannot start: block, never fail open
    _REASON = "cab-of-one: tool call blocked: the guard could not start."
    sys.stdout.write(
        '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
        '"permissionDecisionReason":"' + _REASON + '"}}\n'
    )
    sys.stderr.write(_REASON + "\n")
    raise SystemExit(2) from None
guard.main(__file__)
