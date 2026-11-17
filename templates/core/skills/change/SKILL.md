---
name: change
description: Run one IT operations change through the cab-of-one lifecycle - terminal intake by the person, impact analysis, plan, tier, snapshot, adversarial review, human approval, execution, re-read verification and record. Use whenever a tenant or admin write is needed, or when the guard says No open change.
---

# /change

You are the main session, the only one that runs writes. Follow the steps in order. Each gate is checked by the guard or by `cab`, not by you. When one refuses, report its message and the next step it names. Do not route around it. If a `cab` subcommand is missing or fails, stop and tell the person.

## 1. Open the change

- `cab new CHG-NNNN <slug>` opens `changes/CHG-NNNN-<slug>/` and makes it the active change. Only one change can be open.
- Before planning, read with the `readonly-probes` skill.

## 2. Intake (main session)

- Use the `change-intake` skill. Ask the person to run `cab intake CHG-NNNN` in their own terminal, then wait until they say it has finished. You never run, wrap or imitate it.
- Never write `intake.md` yourself. `AskUserQuestion` records questions, not answers, so a conversation never counts as interview evidence. A file you write also blocks the person's `cab intake`, which never overwrites one.
- While you wait, you may enumerate targets and draft. Do not run `cab plan check` until the intake has finished. `cab plan check` requires interview evidence linked to this change.
- `cab intake CHG-NNNN --from-file PATH` is for headless tests only. It is recorded as a fixture, never as a person's answers.

## 3. Targets and impact

- Enumerate the targets with read-only probes. Write `targets.csv` yourself: the header `target`, then one immutable `kind/ID` per line (for example `users/u-1042`). Use no display names and no filters.
- For `normal` and `critical` work, or whenever dependents are unclear, start the `impact-analyst` subagent with the change ID. Save its report as `impact.md`.

## 4. Plan

- Start the `runbook-author` subagent with the change ID. It writes `change.toml` and `plan.md` only.
- Run `cab plan check`. It validates the files, records the tier and fixes the plan hash over `change.toml`, `plan.md` and `targets.csv`.
- **Plan hash invalidation:** any later edit to those three files voids the check, the review, any acknowledgement, the approval and the snapshot. After an edit, run `cab plan check` again and redo everything after it.

## 5. Tier

Use the `tiering` skill. The guard computes the effective tier as the highest of the three answers, the standard-change catalogue and the command-pattern floor. An unknown or unreadable admin command counts as a write, at least `normal`. A tier you write down never lowers it.

| tier | needs |
|---|---|
| standard | an enabled catalogue entry that matches the exact command, targets and state scope; plan, snapshot, verify, record |
| normal | plan, snapshot, impact analysis, safety review, a person's approval, verify and record |
| critical | all normal requirements, plus first-unit-first execution |

If the targets are not enumerated, nothing runs at any tier.

## 6. Snapshot (every tier)

`cab snapshot` records every planned target before the first write. The guard refuses writes without a snapshot bound to the current plan hash and target list. If you retake the snapshot after a review, expect to redo the review and the approval.

## 7. Review (normal, critical)

- Start the `safety-reviewer` subagent with the change ID only. A hook records its verdict and the plan hash at the start and end of the review.
- On `BLOCK`, fix the plan through `runbook-author`, run `cab plan check` again and review again.
- On `PASS_WITH_CONDITIONS`, a person confirms the conditions with `cab ack` in their own terminal.

## 8. Approval (normal, critical)

Ask the person to run `cab approve CHG-NNNN` in their own terminal. You never run, wrap (`script`, `expect`, Python `pty`) or imitate it. Approval binds the plan hash, the review and the tier, and it expires. If it expires or the plan changes, ask again.

## 9. Execute

- Run each write exactly as planned. Use step commands byte for byte. Use only targets in `targets.csv` and only the tenant scope in `change.toml`. Run one write at a time.
- **First unit first:** for a `critical` change with more than one target, the first write covers one target only. Run `cab verify` and get PASS for it before the next write.
- **First failure stops:** a failed or unknown write halts the change. Report it. Only a person's `cab resume` continues.

## 10. Verify

- Run `cab verify` after writes. For criteria that need judgement, start the `verifier` subagent.
- Only PASS is success. FAIL means a person decides whether to roll back or fix forward. UNMEASURED is recorded with the exact command a person must run. It is never PASS.
- A failed or unknown write is still verification debt for its targets.
- Do not end your turn with unverified writes. If a write truly cannot be measured, record UNMEASURED with the command instead.

## 11. Record and close

- Start the `recorder` subagent. It writes `record.md` from the artifacts.
- `cab close` closes successfully only when every written target has PASS. FAIL leaves the change failed, and UNMEASURED leaves it open-unverified. Report either one to the person as it is.
