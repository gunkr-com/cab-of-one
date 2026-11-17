# changes/

Each change gets one folder here, named after its ID and a short slug, for example `CHG-0001-block-sign-in/`. Only one change can be open at a time.

This folder is evidence. The generator does not create or delete anything in it, and `cab setup uninstall` leaves it in place. In this repository the folder holds no real changes; all examples are fictional Contoso data.

## Files in a change folder

| File | Written by | Contents |
|---|---|---|
| `intake.md` | `cab intake CHG-NNNN`, run by a person in their own terminal; or `cab intake CHG-NNNN --from-file PATH`, which is recorded as a fixture and is for headless tests only. The main session never writes it. | Purpose, scope, what is out of scope, timing, known dependents and success criteria |
| `change.toml` | `runbook-author` subagent | The machine plan: tier answers, tenant state scope, steps with exact targets, one verify probe per target, rollback commands |
| `plan.md` | `runbook-author` subagent | The plan for people, with reasons |
| `targets.csv` | the main session, from read-only lookups | The exact immutable target IDs, as a list rather than a filter |
| `impact.md` | the main session, from the `impact-analyst` report | Dependents and risks found by read-only probes |
| `snapshot.json` | `cab snapshot` | The current value of every target before any write |
| `review.json` | the SubagentStop hook | The `safety-reviewer` verdict and findings, bound to the plan hash |
| `approval.json` | `cab approve`, run by a person in a terminal | Approval bound to the plan and review, with an expiry |
| `verify.json` | `cab verify` | The observed value for each target, with attempt count and result (PASS, FAIL or UNMEASURED) |
| `record.md` | `recorder` subagent | What changed and why, the verification table, how to undo it, and one lesson |

Deny rules and the guard stop agents from writing `snapshot.json`, `review.json`, `approval.json` and `verify.json`.

## Rules that follow from the files

- **The plan hash covers `change.toml`, `plan.md` and `targets.csv`.** Editing any of them clears the review, approval and snapshot.
- **Targets come only from `targets.csv`.** A write to an ID that is not in `targets.csv` is refused.
- **A change closes as successful only when every written target has a PASS.** FAIL closes it as failed. Any UNMEASURED leaves it open and unverified, with the command a person must run.

The state machine itself lives in `.cab/state/`. It is protected and is not meant to be edited by hand.
