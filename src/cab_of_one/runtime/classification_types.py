"""Shared types for the S3 command classifier.

Kept separate from ``classify.py`` so the adapters can build results without a
circular import. Standard library only, no I/O.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

KIND_READ = "read"
KIND_WRITE = "write"
KIND_NOT_ADMIN = "not-admin"
KINDS = frozenset({KIND_READ, KIND_WRITE, KIND_NOT_ADMIN})

FLAG_TENANT_WIDE = "tenant_wide"
FLAG_ALL_SWITCH = "all_switch"
FLAG_WHATIF = "whatif"
FLAG_DRY_RUN = "dry_run"
FLAG_LIE = "lie"


@dataclass(frozen=True)
class Result:
    """One classification. ``unknown=True`` always comes with ``kind="write"``.

    ``scope`` names the state the command acts on (for simtenant: the
    normalised project-relative ``--state`` path). ``None`` means the scope is
    unknown, absolute, escapes the project or is not applicable; a catalogue
    entry can never match such a write. It is the last field so positional
    construction written before it existed keeps working.
    """

    kind: str
    unknown: bool
    adapter: str | None
    verb: str | None
    canonical: str
    targets: tuple[str, ...] = ()
    targets_complete: bool = False
    flags: frozenset[str] = frozenset()
    reasons: tuple[str, ...] = ()
    segments: tuple[Result, ...] = ()
    scope: str | None = None

    def __post_init__(self) -> None:
        # A malformed result is a bug; raising lets classify_tool_call fail closed.
        if self.kind not in KINDS:
            raise ValueError(f"bad kind {self.kind!r}")
        if not isinstance(self.unknown, bool) or not isinstance(self.targets_complete, bool):
            raise ValueError("unknown/targets_complete must be bool")
        if self.unknown and self.kind != KIND_WRITE:
            raise ValueError("unknown-admin must be kind=write")
        if self.adapter is not None and not isinstance(self.adapter, str):
            raise ValueError("adapter must be str or None")
        if self.verb is not None and not isinstance(self.verb, str):
            raise ValueError("verb must be str or None")
        if not isinstance(self.canonical, str):
            raise ValueError("canonical must be str")
        if not isinstance(self.targets, tuple) or not all(isinstance(t, str) for t in self.targets):
            raise ValueError("targets must be a tuple of str")
        if not isinstance(self.flags, frozenset) or not all(isinstance(f, str) for f in self.flags):
            raise ValueError("flags must be a frozenset of str")
        if not isinstance(self.reasons, tuple) or not all(isinstance(r, str) for r in self.reasons):
            raise ValueError("reasons must be a tuple of str")
        if not isinstance(self.segments, tuple) or not all(
            isinstance(s, Result) for s in self.segments
        ):
            raise ValueError("segments must be a tuple of Result")
        if self.scope is not None and (not isinstance(self.scope, str) or not self.scope):
            raise ValueError("scope must be a non-empty str or None")


@dataclass(frozen=True)
class Arg:
    """One shell word after quote removal.

    ``expands`` is True when the shell would change the word at run time
    (parameter expansion, unquoted glob, brace or tilde). ``raw`` is the source text.
    """

    text: str
    expands: bool = False
    quoted: bool = False
    raw: str = ""


@dataclass(frozen=True)
class AdapterContext:
    """What an adapter may know besides argv. ``load_script`` is the only I/O path.

    ``cwd_changed`` is True when an earlier segment (or an enclosing shell)
    changed the working directory, so relative paths no longer name project files.
    """

    trusted_simtenant_commands: frozenset[str] = frozenset()
    trusted_simtenant_scripts: frozenset[str] = frozenset()
    simtenant_resources: frozenset[str] | None = None
    load_script: Callable[[str], str | None] | None = None
    cwd_changed: bool = False


def make_unknown(
    reason: str,
    *,
    adapter: str | None = None,
    verb: str | None = None,
    canonical: str = "",
    flags: Iterable[str] = (),
) -> Result:
    return Result(
        KIND_WRITE, True, adapter, verb, canonical, (), False, frozenset(flags), (reason,), ()
    )


def make_not_admin(canonical: str, reason: str = "no admin marker") -> Result:
    return Result(
        KIND_NOT_ADMIN, False, None, None, canonical, (), True, frozenset(), (reason,), ()
    )


def make_read(
    adapter: str,
    verb: str | None,
    canonical: str,
    *,
    targets: Sequence[str] = (),
    targets_complete: bool = False,
    flags: Iterable[str] = (),
    reason: str = "known read",
    scope: str | None = None,
) -> Result:
    return Result(
        KIND_READ,
        False,
        adapter,
        verb,
        canonical,
        tuple(targets),
        targets_complete,
        frozenset(flags),
        (reason,),
        (),
        scope,
    )


def make_write(
    adapter: str,
    verb: str | None,
    canonical: str,
    *,
    targets: Sequence[str] = (),
    targets_complete: bool = False,
    flags: Iterable[str] = (),
    reason: str = "known write",
    scope: str | None = None,
) -> Result:
    return Result(
        KIND_WRITE,
        False,
        adapter,
        verb,
        canonical,
        tuple(targets),
        targets_complete,
        frozenset(flags),
        (reason,),
        (),
        scope,
    )


def leaves(r: Result) -> tuple[Result, ...]:
    """Leaf results in order. A result without segments is its own leaf."""
    if not r.segments:
        return (r,)
    out: list[Result] = []
    for s in r.segments:
        out.extend(leaves(s))
    return tuple(out)


def _unique(items: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return tuple(seen)


def combine(results: Sequence[Result], canonical: str) -> Result:
    """Merge segment results: unknown-admin > write > read > not-admin.

    ``targets_complete`` is True only when every write leaf (or, with no
    writes, every read leaf) extracted all of its targets. ``scope`` is kept
    only when every one of those leaves names the same scope.
    """
    flat = [leaf for r in results for leaf in leaves(r)]
    if not flat:
        return make_not_admin(canonical, "empty command")
    if len(flat) == 1:
        return flat[0]
    writes = [x for x in flat if x.kind == KIND_WRITE]
    reads = [x for x in flat if x.kind == KIND_READ]
    if writes:
        kind, chosen = KIND_WRITE, writes
    elif reads:
        kind, chosen = KIND_READ, reads
    else:
        kind, chosen = KIND_NOT_ADMIN, flat
    unknown = any(x.unknown for x in flat)
    adapters = {x.adapter for x in flat if x.kind != KIND_NOT_ADMIN}
    adapter = next(iter(adapters)) if len(adapters) == 1 else None
    verb = chosen[0].verb if len(chosen) == 1 else None
    flags = frozenset().union(*(x.flags for x in flat))
    scopes = {x.scope for x in chosen}
    scope = next(iter(scopes)) if len(scopes) == 1 else None
    return Result(
        kind,
        unknown,
        adapter,
        verb,
        canonical,
        _unique(t for x in chosen for t in x.targets),
        all(x.targets_complete for x in chosen),
        flags,
        _unique(r for x in flat for r in x.reasons),
        tuple(flat),
        scope,
    )
