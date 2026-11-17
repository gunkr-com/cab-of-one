"""cab-of-one Stop hook entry. Generated pinned copy; a person changes it by PR.

If the runtime cannot be imported, the fallback reads the event with stdlib json only:
exactly ``stop_hook_active is True`` exits 0 silently (the continuation escape); anything
else gets an explicit block. onFailure has no effect on Stop, so this fallback is the only
import-failure path; a crash or timeout of this hook is not blocked by Claude Code.
"""

import sys

try:
    import os

    sys.dont_write_bytecode = True
    _HERE = os.path.dirname(os.path.realpath(__file__))
    try:
        _CWD = os.getcwd()
    except OSError:
        _CWD = ""
    sys.path[:] = [p for p in sys.path if p not in ("", _CWD)]
    sys.path.insert(0, _HERE)
    from cab_of_one.runtime import closeout  # noqa: E402
except BaseException:
    import json

    _REASON = "cab-of-one: closeout could not start. Stop writing; ask a person to run cab doctor."
    try:
        _DATA = json.loads(sys.stdin.buffer.read(16 * 1024 * 1024 + 1))
    except BaseException:
        _DATA = None
    if isinstance(_DATA, dict) and _DATA.get("stop_hook_active") is True:
        raise SystemExit(0) from None
    sys.stdout.write(json.dumps({"decision": "block", "reason": _REASON}) + "\n")
    sys.stdout.flush()
    raise SystemExit(0) from None
raise SystemExit(closeout.main(__file__))
