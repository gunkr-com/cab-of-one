"""Person-only ``cab setup uninstall`` (S9, DESIGN §10-3, G8).

Removes only what the manifest says the generator owns and what is still exactly as the
generator wrote it: unchanged generated files, the recorded ``.claude/settings.json``
contributions, and the exact ``CLAUDE.md`` marker block. A person's edits, policy and
standard-change files, evidence (``changes/``, ``audit/``), handoff notes, ``.cab-new``
proposals and local, user and managed settings are kept; edits are reported as drift.

Private-state protection is retained. Uninstall itself writes a backup under
``.cab/backups/``, and ``.cab/state`` (HMAC salt, ledger receipts) and ``.cab/setup`` usually
remain. While any of them holds data the ``.gitignore`` marker block is **kept** (and
reported), so leftover private state never becomes visible to Git, even though the manifest
is removed. A later apply re-adopts the identical block; ``git rm`` it by hand only once those
folders are gone.

Flow (same guards as apply): setup lock, strict manifest, ``lstat`` inspection of every owned
path and parent, runtime check (no active or in-flight change), summary, exact project
folder name on a genuine TTY, full re-inspection after the prompt, backups, compare-and-swap
per path, settings first (so hook registrations go before their scripts), empty owned
folders pruned, ``.cab/manifest.json`` removed last, verification and exact rollback.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from ..runtime import fsutil
from ..runtime.terminal import sanitize
from . import merge
from .apply import (
    EXIT_BLOCKED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_ROLLBACK_FAILED,
    EXIT_ROLLED_BACK,
    LOCK_NAME,
    MANIFEST_REL,
    PASS,
    PRIVATE_RELS,
    SETUP_REL,
    ApplyError,
    Check,
    Node,
    Outcome,
    Services,
    _abs,
    _action_lines,
    _confirm_outcome,
    _existing,
    _failure_lines,
    _issue_lines,
    _load_manifest,
    _read_node,
    _say,
    _stamp,
    _Transaction,
    confirm_project_name,
    inspect_tree,
    project_root,
)
from .manifest import GITIGNORE_PATH, SETTINGS_PATH, Manifest

__all__ = ["uninstall_project"]


@dataclass(frozen=True)
class _UPrepared:
    root: str
    name: str
    manifest: Manifest
    manifest_node: Node
    nodes: dict[str, Node]
    plan: merge.UninstallPlan
    actions: tuple[merge.Action, ...]
    retained: tuple[str, ...]
    runtime: Check

    def fingerprint(self) -> tuple[Any, ...]:
        return (self.nodes, self.manifest_node, self.actions, self.plan, self.runtime)


def _holds_data(root: str, rel: str) -> bool:
    node = _read_node(_abs(root, rel))
    if node.kind == "absent":
        return False
    if node.kind != "dir":
        return True  # unexpected entry: treat as private data (keep protection)
    try:
        with os.scandir(_abs(root, rel)) as entries:
            return next(entries, None) is not None
    except OSError:
        return True


def _prepare(root: str, services: Services) -> _UPrepared:
    manifest, manifest_node = _load_manifest(root)
    if manifest is None:
        raise ApplyError("not_installed", f"{MANIFEST_REL} is absent")
    nodes = inspect_tree(root, merge.paths_to_inspect((), manifest))
    plan = merge.plan_uninstall(manifest, _existing(nodes))
    actions = plan.actions
    retained: list[str] = []
    gitignore = [a for a in actions if a.path == GITIGNORE_PATH]
    if gitignore:
        # A backup is always written when anything changes, so private data remains.
        private = [rel for rel in PRIVATE_RELS if _holds_data(root, rel)]
        reason = ", ".join(private) if private else ".cab/backups (this uninstall's backup)"
        actions = tuple(a for a in actions if a.path != GITIGNORE_PATH)
        retained.append(
            f".gitignore block kept: private data remains in {reason}; it stays out of Git"
        )
    return _UPrepared(
        root=root,
        name=os.path.basename(root),
        manifest=manifest,
        manifest_node=manifest_node,
        nodes=nodes,
        plan=plan,
        actions=actions,
        retained=tuple(retained),
        runtime=services.probe_runtime(root),
    )


def _summary(prep: _UPrepared) -> list[str]:
    lines = [f"cab-of-one setup uninstall: project {prep.name}", f"  folder: {prep.root}"]
    lines.append(
        f"  manifest: generator {prep.manifest.generator_version}, "
        f"profile sha256 {prep.manifest.profile_sha256}"
    )
    lines.append(f"  runtime state: {prep.runtime.status} {prep.runtime.code}")
    lines.append(f"plan: {len(prep.actions)} action(s), then {MANIFEST_REL} is removed")
    lines += _action_lines(prep.actions, prep.nodes)
    lines += _issue_lines("kept (drift)", prep.plan.drift)
    lines += _issue_lines("kept", prep.plan.notes)
    lines += [f"  {r}" for r in prep.retained]
    lines.append("  kept: changes/, audit/, policy files, .cab-new proposals, .cab/state, "
                 ".cab/setup, local/user/managed settings")  # fmt: skip
    return lines


def _blockers(prep: _UPrepared) -> list[str]:
    out = _issue_lines("blocked", prep.plan.blockers)
    if prep.runtime.status != PASS:
        out.append(
            f"  blocked: runtime {prep.runtime.code}: a change may be active or in flight; "
            "close it (or check `cab status`) before the controls are removed."
        )
    return out


def _ordered(actions: tuple[merge.Action, ...]) -> list[merge.Action]:
    """Settings (hook registrations) first, then files."""
    return sorted(actions, key=lambda a: (a.path != SETTINGS_PATH, a.path))


def _execute(prep: _UPrepared, services: Services) -> Outcome:
    root = prep.root
    stamp, _ = _stamp(services)
    tx = _Transaction(root, services.fileops)
    nodes = dict(prep.nodes)
    nodes[MANIFEST_REL] = prep.manifest_node
    bad: list[str] = []
    try:
        tx.backup(stamp, [a.path for a in prep.actions] + [MANIFEST_REL], nodes, "uninstall")
        removed: list[str] = []
        for action in _ordered(prep.actions):
            prior = prep.nodes.get(action.path, Node("absent"))
            tx.cas(action.path, prior)
            if action.kind == "remove":
                tx.remove(action.path, prior)
                removed.append(action.path)
            elif action.kind == "update":
                mode = prior.mode if prior.kind == "file" and prior.mode is not None else 0o644
                tx.write(action.path, action.data, mode, prior)  # type: ignore[arg-type]
            else:
                raise ApplyError("unexpected_action", action.path, EXIT_ROLLED_BACK)
        tx.prune(removed)
        tx.cas(MANIFEST_REL, prep.manifest_node)
        tx.remove(MANIFEST_REL, prep.manifest_node)
        for action in prep.actions:
            node = _read_node(_abs(root, action.path))
            if action.kind == "remove" and node.kind != "absent":
                bad.append(action.path)
            if action.kind == "update" and (node.kind != "file" or node.data != action.data):
                bad.append(action.path)
        if _read_node(_abs(root, MANIFEST_REL)).kind != "absent":
            bad.append(MANIFEST_REL)
        if bad:
            raise ApplyError("verification_failed", ", ".join(bad), EXIT_ROLLED_BACK)
    except BaseException as exc:
        failed = tx.rollback()
        code = exc.code if isinstance(exc, ApplyError) else type(exc).__name__
        lines = _failure_lines(f"uninstall failed ({code})", failed, tx.backup_rel)
        if isinstance(exc, ApplyError) and exc.detail:
            lines.append(f"  at: {exc.detail}")
        if not isinstance(exc, Exception):
            err = services.err()
            for line in lines:
                _say(err, sanitize(line))
            raise
        return Outcome(
            EXIT_ROLLBACK_FAILED if failed else EXIT_ROLLED_BACK, "rolled_back", tuple(lines)
        )
    lines = [
        f"uninstalled: {len(prep.actions)} change(s); {MANIFEST_REL} removed",
        f"  backup: {tx.backup_rel}",
    ]
    lines += _issue_lines("kept (drift)", prep.plan.drift)
    lines += [f"  {r}" for r in prep.retained]
    lines.append("  start a new Claude Code session: the cab-of-one hooks are no longer registered")
    return Outcome(EXIT_OK, "uninstalled", tuple(lines))


def uninstall_project(project: str, *, services: Services) -> Outcome:
    """Person-only uninstall (see the module doc). Returns an ``Outcome``."""
    root = project_root(project)
    setup = inspect_tree(root, [SETUP_REL])
    if setup[".cab"].kind != "dir":
        raise ApplyError("not_installed", ".cab is absent")
    if setup[SETUP_REL].kind == "absent":
        try:
            os.mkdir(_abs(root, SETUP_REL), 0o700)  # holds only the setup lock
        except FileExistsError:
            pass
    if _read_node(_abs(root, SETUP_REL)).kind != "dir":
        raise ApplyError("setup_dir_unsafe", SETUP_REL)
    try:
        with fsutil.locked(_abs(root, f"{SETUP_REL}/{LOCK_NAME}"), services.lock_timeout):
            prep = _prepare(root, services)
            summary = _summary(prep)
            blocked = _blockers(prep)
            if blocked:
                return Outcome(EXIT_BLOCKED, "blocked", tuple(summary + ["BLOCKED:"] + blocked))
            check = confirm_project_name(
                prep.name,
                summary,
                stdin=services.inp(),
                stdout=services.out(),
                stderr=services.err(),
                osx=services.osx,
                verb="uninstall",
            )
            if check.status != PASS:
                return _confirm_outcome(check)
            again = _prepare(root, services)
            if again.fingerprint() != prep.fingerprint() or _blockers(again):
                return Outcome(
                    EXIT_REFUSED,
                    "changed_during_prompt",
                    ("cab setup: refused: the project changed while the prompt was open. "
                     "Nothing was removed. Run uninstall again.",),
                )  # fmt: skip
            return _execute(again, services)
    except fsutil.LockTimeout:
        raise ApplyError(
            "apply_in_progress", "another setup command holds the lock", EXIT_BLOCKED
        ) from None
    except fsutil.SymlinkRefused:
        raise ApplyError("setup_dir_unsafe", f"{SETUP_REL}/{LOCK_NAME}") from None
