---
name: blocker-catalog
description: The twelve blockers (B1-B12) a safety review checks every IT change plan against. Preloaded into the safety-reviewer subagent; also useful when writing a plan.
---

# Blocker catalogue

For each blocker, decide whether it applies and cite the line in the plan or artifact that shows it. If the evidence to rule a blocker out is missing, it counts as applying.

| ID | Name | It applies when |
|---|---|---|
| B1 | Exit code as proof | A step's verification is the write's exit code or "Success" output instead of a re-read of the target. |
| B2 | Live filter as target | Targets are chosen by a query that is evaluated again at run time, not by the immutable IDs in `targets.csv`. |
| B3 | Dry run that isn't | The plan relies on a dry-run or WhatIf flag that the tool ignores or does not support. |
| B4 | Destroy before preserve | Delete, purge or wipe runs without an export or snapshot first and a check that it can be restored. |
| B5 | Lookalike target | Targets were picked by display name, and an out-of-scope object with a similar name could be hit. |
| B6 | Hidden dependents | Policies, nested groups, delegations, licences or app assignments that depend on a target are missing from the plan. |
| B7 | Expiring undo | Rollback depends on a recovery window (recycle bin, soft-delete retention, licence grace) that the plan does not state. |
| B8 | Blast radius creep | Wildcards, `-All`, tenant-wide scope or a default policy are touched. |
| B9 | Order hazard | Old access is removed before new access works, or an old authentication method is disabled before the new one is registered. |
| B10 | Self-lockout | The operator's own access, break-glass accounts or admin exclusions are affected. |
| B11 | Unobservable success | The success criterion cannot be observed by a read, or propagation delay is ignored. |
| B12 | Scope creep | A step is not required by the intake purpose ("while we are here"). |

## Mechanics to check as well (finding code `MECH`)

- Every target in `change.toml` steps is in `targets.csv`, as immutable `kind/ID` values.
- `[scope] tenant` is the exact state scope the commands use.
- Every step has a read-only probe with an expected value, and a rollback or `irreversible = true`.
- Step commands are literal: no variables, globs, command substitution or here-documents.
- The three answers agree with `impact.md` and `snapshot.json`.
- UNMEASURED evidence is treated as missing, never as safe.

## Contoso examples (fictional)

- B4: "Purge u-1042" with no mailbox export step and no restore check.
- B5: Targets chosen as "the Sales group", while both "Sales" and "Sales-Archive" exist.
- B10: Removing the "Admins excluded" group from a conditional access policy.
