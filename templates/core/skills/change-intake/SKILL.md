---
name: change-intake
description: Prepare the intake for one IT change and hand it to the person, who answers with cab intake CHG-NNNN in their own terminal. Used by /change before any plan is written. Never writes intake.md.
---

# Change intake

The intake answers must come from the person. They give them by running `cab intake CHG-NNNN` in their own terminal. That command asks six questions, shows the answers back, and records them only after the person types the change ID to confirm. You never run it, wrap it (`script`, `expect`, Python `pty`) or imitate it.

## Never write intake.md

- Do not create, edit, move or delete `intake.md` in the change folder.
- `AskUserQuestion` records that a question was asked, never the answer. An `intake.md` written from a conversation is never interview evidence, and `cab plan check` refuses it.
- It also blocks the person: `cab intake` never overwrites an existing `intake.md`, so they would have to remove your file first.
- A question that was not answered, or that timed out, is not an answer. Never describe the intake as done until `cab intake` has finished.

## Before the person runs it

Read first with read-only probes. You may discuss the questions with the person, show what the probes found, and suggest wording. Do not record their replies as answers. The six questions `cab intake` asks are:

1. **Purpose:** what the change should achieve, in one sentence.
2. **In scope:** which objects or systems it changes, and the read-only lookup that lists their immutable IDs. The list is fixed at planning time. It is never a filter that is evaluated again at run time.
3. **Out of scope / lookalikes excluded:** what it must not touch. Show the lookalikes you found.
4. **Timing:** change windows, deadlines, business hours.
5. **Known dependents:** policies, groups, delegations, licences, apps or DNS the person knows about.
6. **Success criteria:** what the person will accept as done, stated as something a read can observe.

Undo expectations, meaning whether the person expects the change to be reversible and within what window, belong in the three tiering answers (`tiering` skill), not in `intake.md`.

## Hand off and wait

Tell the person, in one message:

- the exact command, `cab intake CHG-NNNN` with the real change ID, run from the project folder in their own terminal;
- that every answer must be one line, and that cancelling writes nothing;
- that you will wait until they say it has finished.

Then stop and wait. While you wait you may enumerate targets and draft notes for the plan. Mark anything you draft as a draft until the intake exists. Do not run `cab plan check` before the person confirms the intake has finished.

After they confirm, read `intake.md` and use it. It ends with a `- Source:` line that says the answers were typed at a terminal that passed a TTY check. That check is not proof of who typed them, so do not call it more than that.

## Fixture intake (headless tests only)

`cab intake CHG-NNNN --from-file PATH` loads answers from a file. It exists for headless evaluations, and `intake.md` and the ledger record it as a fixture, not as answers given by a person. Never use it for a real change, never write a fixture file from a conversation, and never describe fixture answers as a person's answers.

Purpose creep is a finding: do not add anything the person did not ask for.
