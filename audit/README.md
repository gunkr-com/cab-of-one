# audit/

The ledger lives in `audit/ledger/`, one JSON Lines file per month (`YYYY-MM.jsonl`). The generator does not create or delete anything here, and `cab setup uninstall` leaves the folder in place. In this repository the folder holds no real ledger.

## Who writes it

Hooks and the `cab` CLI append to the ledger under a file lock. The model does not write it, and deny rules and the guard stop agents from editing anything under `audit/`.

Rows record, among other things:

- **Sessions:** session start, with the result of the guard self test, and session end.
- **Guard decisions:** each decision on an admin call, with its classification and a reason code.
- **Writes:** the settlement of each write after it runs, with the exit status and a hash of the output. The output itself is not stored.
- **Change lifecycle:** intake, review start and stop, approval, acknowledgement, resume, state changes, snapshots and verification results.
- **Configuration:** configuration changes the lock allowed or held.

Known secret patterns (tokens, JWTs, client secrets, connection strings and password arguments) are redacted before a row is written. Redaction is pattern-based and can miss unusual formats.

## What it does not guarantee

- **No hash chain in this version.** Anyone who can write the file can change or remove a line without the harness detecting it.
- **Commit the ledger to a private Git repository** so that history pins it. A cloud-synced folder does not.
- **Absence of rows is ambiguous.** It can mean nothing happened, or that hooks did not run. `cab audit` compares the ledger's session-start rows with Claude Code's transcripts to tell the two apart, within the limits in `docs/threat-model.md` in the source checkout.

## Reading it

- `cab status` summarises the open change.
- `cab audit` reports writes outside the harness and sessions where the hooks did not run.
- `cab audit metrics` counts ledger rows by kind, decision and reason.
