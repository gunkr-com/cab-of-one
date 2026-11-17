## Change control (cab-of-one)

This is an IT operations project. Agents may read freely. Every administrative write (tenant, directory, mail, device or cloud change) runs inside one open change and must get past the PreToolUse guard. The gates are the guard, the deny rules and the hooks, not these notes. These notes explain the gates so you can work with them.

### How a change starts

- Read before you plan. Answer open questions with read-only probes (the `readonly-probes` skill).
- No open change means no write. The guard says `No open change. Start one with /change.` Use the `/change` skill.
- One active change per project, and one write in flight at a time.
- Intake answers come from the person's own terminal. Ask them to run `cab intake CHG-NNNN` there and wait for it to finish. `AskUserQuestion` records the questions, not the answers, so a conversation never completes intake. Never write `intake.md` yourself.
- `cab` means the runtime CLI pinned in `.claude/hooks/cab/`. If a `cab` subcommand is missing or fails, stop and tell the person. Never imitate a `cab` command by writing its files yourself.

### What the guard enforces

- **Plan hash.** `cab plan check` binds the plan to one hash of `change.toml`, `plan.md` and `targets.csv`. A one-byte edit to any of them after the check invalidates the check, the review, any acknowledgement, the approval and the snapshot. Run `cab plan check` again and redo what it asks for.
- **Exact targets.** `targets.csv` lists immutable IDs, never display names or filters. Every write must name only listed targets in the exact tenant state scope in `change.toml`. A command whose targets cannot be read from it must match one approved step byte for byte, and each step runs once.
- **Tier.** The final tier is the highest of the three-question answers, the standard-change catalogue and the policy pattern floor. A command the classifier cannot read with confidence counts as a write, at least `normal`. Writing a lower tier does not lower it.
- **Snapshot, every tier.** `cab snapshot` records every planned target before the first write, including `standard` changes.
- **Review and approval.** `normal` and `critical` changes need a current `safety-reviewer` verdict and a person's `cab approve`. Both are bound to the plan hash.
- **First unit first.** A `critical` change with more than one target runs one write against one target, gets `cab verify` PASS for it, and only then continues.
- **Stop at the first failure.** A failed or unknown write halts the change. Only a person's `cab resume` lifts the halt.
- **Subagents never write the tenant.** They investigate, draft, review, verify and record. The main session runs every write.

### Verification

- PASS, FAIL and UNMEASURED are the only results. An exit code or "Success" is never verification. Only re-reading the real system counts.
- A failed or unknown write still counts as written and unverified. It is verification debt until its targets are re-read.
- UNMEASURED is never PASS and never a successful close. Record it with the exact read-only command a person must run, and leave the change open-unverified.
- Do not end a turn with writes that have no verification after them.

### Human gates (never run, wrap or imitate these)

- `cab approve`, `cab ack`, `cab resume`, the interactive `cab intake CHG-NNNN`, `cab setup apply` and `cab setup uninstall` run only in a person's own terminal. Do not call them through `script`, `expect`, Python `pty` or any other wrapper.
- Do not write, edit, move or delete `.claude/`, `policy/`, `audit/`, `.cab/state/`, `.cab/manifest.json`, `.cab/backups/`, or `approval.json`, `review.json`, `verify.json` and `snapshot.json` in a change folder. Only `cab` and the hooks write them.
- If a gate blocks you, report the guard's message and its next step. Do not look for another route.
