"""cab-of-one ConfigChange lock entry. Generated pinned copy; a person changes it by PR."""

import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from cab_of_one.runtime import config_lock  # noqa: E402
except BaseException:  # the lock cannot start: block, never fail open
    _REASON = "cab-of-one: settings change blocked: the config lock could not start."
    sys.stdout.write('{"decision":"block","reason":"' + _REASON + '"}\n')
    sys.stderr.write(_REASON + "\n")
    raise SystemExit(2) from None
config_lock.main(__file__)
