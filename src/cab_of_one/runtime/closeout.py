"""Stop hook: no turn ends quietly over unverified writes (S5 C-main, contract section 4.3).

Pinned entry: ``<project>/.claude/hooks/cab/closeout.py``. Order:

1. The event is read with ``hookevents.read_event`` (strict JSON, bounded). Only
   ``stop_hook_active is True`` (the exact boolean) is the continuation escape: exit 0,
   no output, and a best-effort ledger ``stop`` row ``pass_active``. The string ``"true"``
   or any other value is evaluated like a normal Stop.
2. Unreadable event, roots, runtime, state or evidence (including any
   ``ObligationsError``): block with ``state_invalid``.
3. ``obligations.evaluate`` over ``Store.load()`` and ``Store.verify_evidence`` (called
   first, so a mismatched evidence reference blocks), then ``obligations.stop_message``:
   ``block`` -> ``{"decision": "block", "reason": ...}``; ``report`` (only committed FAIL /
   UNMEASURED or ``open-unverified`` remain) -> ``{"systemMessage": ...}``, which never says
   verified or done; ``none`` -> no output. Block and report also write a ledger ``stop``
   row (best effort; the ledger and ``cab status`` stay the record).

Always exit 0. Limits, not hidden: ``onFailure`` has no effect on Stop, so a crash or
timeout of this hook is not blocked by Claude Code; a user interruption skips Stop and
continuations are capped. The shim's import fallback blocks unless the exact escape is
set. How Claude Code displays the block reason and ``systemMessage`` is UNMEASURED (L2).
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any

from . import hookevents, obligations, paths
from .audithook import Runtime, open_runtime
from .hookevents import EventError
from .paths import Roots

__all__ = ["STATE_INVALID_TEXT", "UNREADABLE_TEXT", "evaluate_stop", "main"]

STOP_EVENT = "Stop"
STATE_INVALID_TEXT = (
    "cab-of-one could not read or check the change state [state_invalid]. Stop writing; a "
    "person must run .claude/hooks/cab/cab status and .claude/hooks/cab/cab doctor."
)
UNREADABLE_TEXT = (
    "cab-of-one could not read the Stop event [event_invalid]. Stop writing; a person must "
    "run .claude/hooks/cab/cab status."
)


def _row(rt: Runtime | None, **fields: Any) -> None:
    if rt is None:
        return
    try:
        rt.ledger.append("stop", **fields)
    except Exception:
        pass


def _emit(stream: Any, payload: Mapping[str, Any]) -> None:
    try:
        stream.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")
        stream.flush()
    except Exception:
        pass


def _block_code(ob: obligations.Obligations) -> str:
    if ob.inflight_token is not None:
        return "inflight"
    if ob.unverified_units:
        return "unverified_units"
    if ob.halted_code is not None:
        return "halted"
    return "close_incomplete"


def evaluate_stop(rt: Runtime) -> tuple[str, str, str | None, str | None]:
    """(kind, text, reason_code, change_id). Raises when state or evidence is unusable."""
    view = rt.store.load()
    evidence = rt.store.verify_evidence(view.change) if view.change is not None else {}
    ob = obligations.evaluate(view, evidence)
    msg = obligations.stop_message(ob)
    if msg.kind == "block":
        return "block", msg.text, _block_code(ob), ob.change_id
    if msg.kind == "report":
        return "report", msg.text, "not_verified", ob.change_id
    return "none", "", None, ob.change_id


def main(
    entry: str,
    *,
    stdin: Any = None,
    stdout: Any = None,
    env: Mapping[str, str] | None = None,
    home: str | None = None,
    clock: Callable[[], float] = time.time,
    resolve: Callable[..., Roots] = paths.resolve_roots,
) -> int:
    """Run the Stop hook. Always returns 0."""
    out = sys.stdout if stdout is None else stdout
    session_id = None
    rt: Runtime | None = None
    try:
        try:
            data = hookevents.read_event(sys.stdin if stdin is None else stdin, {STOP_EVENT})
        except EventError:
            _emit(out, {"decision": "block", "reason": UNREADABLE_TEXT})
            return 0
        session_id = hookevents.identity(data).session_id
        env = os.environ if env is None else env
        home = env.get("HOME") if home is None else home
        if data.get("stop_hook_active") is True:
            try:
                rt = open_runtime(resolve(entry, env, home), clock=clock)
            except Exception:
                rt = None
            _row(rt, session_id=session_id, decision="pass_active")
            return 0
        try:
            rt = open_runtime(resolve(entry, env, home), clock=clock)
            kind, text, code, change_id = evaluate_stop(rt)
        except Exception:
            _row(rt, session_id=session_id, decision="block", reason_code="state_invalid")
            _emit(out, {"decision": "block", "reason": STATE_INVALID_TEXT})
            return 0
        if kind == "block":
            _row(rt, session_id=session_id, change_id=change_id, decision="block",
                 reason_code=code)  # fmt: skip
            _emit(out, {"decision": "block", "reason": text})
        elif kind == "report":
            _row(rt, session_id=session_id, change_id=change_id, decision="report",
                 reason_code=code)  # fmt: skip
            _emit(out, {"systemMessage": text})
        return 0
    except BaseException:
        _emit(out, {"decision": "block", "reason": STATE_INVALID_TEXT})
        return 0
