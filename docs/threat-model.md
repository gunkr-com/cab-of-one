# Threat model

**English** | [한국어](threat-model.ko.md)

> Draft. This document describes the current code and the documented behaviour of Claude Code. Items marked **unmeasured** have not been observed in a real Claude Code session.

## What it is for

cab-of-one is built for an agent that is careless rather than hostile:

- it makes mistakes;
- it reads an instruction too broadly;
- it trusts an exit code or a "Success" line;
- it forgets the process halfway through a long session.

It also covers the person who forgets to use the process.

It does **not** stop:

- an agent that deliberately works around the controls, for example with obfuscated shell, generated scripts or tools the classifier does not know;
- a malicious insider;
- a person who edits the harness files by hand;
- anything running outside Claude Code.

The real defence for a real tenant is identity separation. See [identity.md](identity.md).

## Layers and their limits

### Deny rules

The generated `.claude/settings.json` denies `Edit` and `Write` on:

- the controls: `.claude/`, `policy/`, `audit/`, `.cab/state/`, `.cab/manifest.json` and `.cab/backups/`;
- each change's `approval.json`, `review.json`, `verify.json` and `snapshot.json`.

It also denies `Bash` for `cab approve`, `cab ack`, `cab resume`, `cab setup apply` and `cab setup uninstall`.

Claude Code documents deny rules as applying in every permission mode, including bypass mode. Limits:

- Deny rules match tool names and patterns. A shell command that writes the same file in another way is outside their reach, so the guard repeats the check.
- Allow rules have no effect in bypass mode. `cab doctor` warns when allow rules look like they are meant as a gate.

### The PreToolUse guard

The guard classifies every tool call:

- An unrecognised admin command counts as a write.
- A compound command takes its most dangerous part.
- A write is refused unless the open change has reached the state its tier needs.

Internal errors exit with code 2, which blocks the call. The hook entry also sets `onFailure: "block"`, which Claude Code documents from version 2.1.295.

Limits:

- **The classifier is best effort.** It recognises verbs for the simulated tenant, Microsoft Graph PowerShell, Azure CLI and Graph HTTP calls. It is not a general shell parser: quoting tricks, aliases, functions, environment tricks, interpreters and indirection can hide intent. When it cannot decide, it treats the call as a write, but some evasions will be classified wrongly.
- **Scripts.** A script the guard can read is classified by its content. A script it cannot read counts as a write. A script can still be changed between the check and the run.
- **Bypass mode is observed only in a narrow setting.** The documentation clearly covers deny rules, but not hook refusals, in every mode.
  - In the current agent-level evaluation ([results](../evals/results/latest.md)), the guard refused an exact unapproved purge in bypass mode in both attempts where the command reached it. In the third attempt the exact purge never ran, so it is INCONCLUSIVE.
  - In those runs the hooks were loaded from a command-line settings overlay with the same pinned code, so they did not measure registration from the project's own settings.
  - A separate single-run probe ([notes](../evals/results/20261112-project-hook-registration.md)) loaded the generated project's own settings in bypass mode. The product guard refused a purge with no open change. That covers this one branch only. Registration of the other hooks and paths (approval, Stop, ConfigChange) and other installation modes remain unmeasured.
  - Treat this as bounded evidence for one scenario, not as a guarantee for bypass mode.
- **A later refusal leaves a write in flight.** When the guard allows a write, it first reserves that write as in flight. If another hook or rule then refuses the same call, no write receipt is recorded and the reservation stays.
  - Later writes in that change are refused, and the change cannot close as successful.
  - This fails closed, but the change stays stuck until a person deals with it. It was observed in all three E5 attempts of the current evaluation, and in two of the previous batch. In each case the eval's own observer hook was the later refusal.
- **Crashes and timeouts.** Claude Code hooks fail open by default. The guard's own exit-2 handling and `onFailure: "block"` close that gap only as far as Claude Code honours them.

### Subagents

Every generated agent has an explicit `tools:` list. The guard refuses any admin write from a subagent.

- Subagents may run reads and a short list of read-only programs.
- The safety reviewer cannot run commands at all.
- A misspelled frontmatter field is silently ignored by Claude Code. `cab doctor` checks that every agent has explicit tools.

### Approval, acknowledgement and resume

These commands require a genuine terminal on standard input and output, the same real and effective user, and the exact change ID typed back. The guard refuses known pseudo-terminal wrappers (`script`, `expect`, Python `pty`) around these commands.

A terminal check is not proof that a person is present. Another program, or a wrapper the guard does not recognise, can provide a terminal. Treat the check as protection against mistakes, not as authentication.

### Terminal intake

`cab intake CHG-NNNN` collects the intake answers from a person's terminal:

- six one-line answers, each validated;
- a redacted summary, recorded only after the change ID is typed back;
- a ledger row with source `terminal` and a hash of the resulting `intake.md`.

It is not an approval. Limits:

- **The same terminal limits apply.** It needs a terminal on standard input and output and the same real and effective user. Any pseudo-terminal passes that check, so it is not proof of who typed the answers.
- **Guard recognition is text-based.** The guard refuses the interactive form and known wrappers around it when an agent calls them. It allows only the exact fixture form, `cab intake CHG-NNNN --from-file PATH`, from the main session. Obfuscated or encoded commands can escape text-based recognition.
- **Fixture rows prove nothing about a person.** Fixture rows are labelled as fixtures and are not bound to the file's hash.
- **Editing is detected, not prevented.** `intake.md` is not a protected path. Editing it after a terminal intake changes its hash, so the terminal row no longer counts and planning is refused.
- **Conversation answers are not measured.** Answers given through `AskUserQuestion` are never recorded, so a conversation never completes intake.
- **Unmeasured in a live session.** Terminal intake by a person inside a real Claude Code session has not been measured.

### Stop hook

The Stop hook blocks the end of a turn while writes have no verification after them. Limits:

- `onFailure` has no effect on Stop or SubagentStop. If the Stop hook crashes or times out, the turn ends.
- A person interrupting the session skips the Stop hook.
- Claude Code caps how many times a Stop hook can make the agent continue, and `stop_hook_active` lets the next stop through.
- The hook makes the agent stop and report. It does not verify anything itself.

Observed in bypass-mode evaluation runs, all with the same overlay setup as above:

- **Current evaluation, in-flight write (all three E5 attempts).** The write was left in flight after a later refusal. The Stop hook blocked on that in-flight write, and `cab close` refused to close. The block is recorded in the ledger; the results table's `stop_block_seen` counts only blocks after a settled write, so it shows `false` (see the [notes](../evals/results/20261112-known-target-step-notes.md)). **No settled write was observed, so this batch gives no evidence for the settled-write Stop block.**
- **History: previous batch (before the planned-step fix).** One attempt with a settled write: the Stop hook blocked before verification, and `cab verify` recorded FAIL. Two attempts had in-flight writes, as above.
- **History: earlier batch (before terminal intake).** The settled-write sequence was recorded in all three attempts.
- **History is not evidence for the current runtime.**
- **Scripted rehearsal, no model.** The installed Stop hook blocked an unverified false-success write, and verify recorded FAIL. That is mechanical evidence, not agent behaviour.

None of the limits listed here was exercised.

### Configuration lock

A ConfigChange hook holds project-settings and skill changes that do not match the generator's manifest. Limits:

- Blocking a ConfigChange stops the session from using the change. It does not roll back the file on disk. A new session reads whatever is on disk.
- Changes from managed policy settings cannot be blocked.
- The reason for a block is not shown to the user.
- The hook is wired to the install manifest. The pinned runtime reads `.cab/manifest.json` and, separately, checks the required hook and deny-rule floor. Recorded contributions alone do not prove that the floor is intact. Unsafe, missing or corrupt records block the change. Owned skill files must match their recorded hashes; unowned or changed skills are held.
- These checks are covered by synthetic tests and by tests against the installed runtime. Whether Claude Code delivers live ConfigChange events to the hook has not been measured. Start a new session after apply.

### Settings that switch the controls off

Some settings can switch the controls off without the project files changing:

- `disableAllHooks`;
- the managed settings `allowManagedHooksOnly` and `allowManagedPermissionRulesOnly`;
- running Claude Code with `--bare`.

`cab setup apply` refuses to install when it detects the first two in the settings files it can read. `cab doctor` reports them.

Neither can read:

- managed settings delivered by device management or a server;
- command-line flags;
- settings outside the files it knows.

Those sources are reported as unmeasured.

`cab doctor` hashes every generated file and compares it with `.cab/manifest.json`. A missing, unsafe or changed file is a FAIL, and so is a missing, unsafe or corrupt manifest. These sources stay explicitly unmeasured:

- managed settings, which it does not read;
- the Claude Code version and installed mods, which it is not told;
- the effective settings that Claude Code finally applies.

So `cab doctor` never reports a clean pass. Its results describe the files it read, not the effective settings.

### Mods

A Claude Code mod that handles `tool.check` can approve calls that deny rules or hooks refused. This applies to sessions without managed settings and without a Team or Enterprise login. The harness cannot prevent this. Neither `cab doctor` nor the installer detects such mods today. `cab doctor` lists installed mods as unmeasured instead of assuming there are none.

### Detection after the fact

`cab audit` reads Claude Code session transcripts. It reports:

- admin writes made outside the project;
- sessions in the project with no SessionStart ledger row, which means the hooks did not run.

Limits:

- The transcript format is not a documented, stable interface. Lines it cannot parse make the result indeterminate rather than clean.
- Claude Code deletes old transcripts, after 30 days by default.
- Only the current project counts as inside the harness. Writes from another project, even one with its own harness, are reported as outside.

### Ledger

Hooks and the CLI append to `audit/ledger/`, with known secret patterns redacted first. Limits:

- **The ledger is not hash-chained in this version.** Someone who can write the file can change it without the harness detecting it. Commit the ledger to a private Git repository to pin it.
- **A cloud-synced folder does not pin anything.**
- **Redaction is pattern-based** and can miss secrets in unusual formats.

### Evidence the harness does not measure

- **Interview answers.** The ledger records that `AskUserQuestion` questions were asked, not the answers. A question-only, unanswered or timed-out interview therefore cannot complete planning. The supported routes are terminal intake (see above), which is still not proof of who typed, and the fixture route `cab intake CHG-NNNN --from-file PATH`, which is labelled a fixture and is never a person's answers.
- **Verifier subagent judgements.** These are advisory. Only `cab verify` results count as verification.
- **Real tenants.** The verification runner supports only the simulated tenant. Real-tenant probes stay UNMEASURED, and real-tenant writes are refused because no complete snapshot can be taken.
- **The SessionStart self test.** It runs the guard's decision function against a synthetic fixture. It does not prove that Claude Code actually called the registered hook. The single project-registration probe recorded one SessionStart row from the project's own settings; that is one session, not a general measurement.

## The generator

`cab setup render` writes only under `.cab/setup/`. `cab setup apply` and `cab setup uninstall` require a terminal and the project folder's name typed back. They re-render and compare before writing, keep backups, and roll back on failure.

A Bash-enabled session with the Claude Code sandbox off can still write `.claude/` directly. The plugin's setup-session hooks only guard the setup session itself. Two things have been measured:

- static plugin validation, which passes with metadata warnings;
- one instrumented run in bypass mode, in which starting the setup skill by its namespaced name was refused.

That run covers one branch of the setup gate. Other ways to start setup, and the full interactive setup interview, have not been measured.

## Reporting

See [SECURITY.md](../SECURITY.md).
