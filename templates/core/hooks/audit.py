"""cab-of-one audit hook entry (Post, PostFailure, SubagentStart/Stop, SessionStart/End).

Generated pinned copy; a person changes it by PR. Usage: audit.py <mode>.
If the runtime cannot be imported nothing is settled: a reserved write stays in flight,
so the guard keeps refusing writes until a person resumes. The failure is reported on
stderr with a non-zero exit (how Claude Code shows it is unmeasured).
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
    from cab_of_one.runtime import audithook  # noqa: E402
except BaseException:  # the hook cannot start: say so, settle nothing
    sys.stderr.write("cab-of-one: the audit hook could not start; nothing was recorded.\n")
    raise SystemExit(1) from None
raise SystemExit(audithook.main(__file__, sys.argv[1] if len(sys.argv) > 1 else ""))
