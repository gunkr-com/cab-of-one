---
name: readonly-probes
description: How to look things up before and after a change without writing - read-only probe rules and per-system probe references. Use before planning, to enumerate targets, for impact analysis and for verification.
---

# Read-only probes

Read first, and read freely. A probe is any command that the guard classifies as a read. The main session's reads are logged. Subagents may run only reads and allow-listed read-only programs.

## Rules

- A probe never changes state. Use read verbs only: PowerShell `Get-`, `Find-`, `Test-`; Azure CLI `list`, `show`, `get-*`; HTTP `GET` or `HEAD` with a literal URL and no body.
- **The guard decides what a read is.** If it classifies a probe as a write or an unknown admin command, it is not a probe. Do not rephrase it to get it past the guard.
- Address objects by immutable ID once you know it. Use display-name searches only to discover IDs, and list every match so lookalikes are visible.
- Keep output small: select the fields you need. Never put secrets or tokens on the command line.
- Propagation delay is real. A value read straight after a write may be stale. Re-read with waits before calling it FAIL.
- If you cannot run a probe, the answer is UNMEASURED. Note the exact read-only command a person can run.

## Probe record

For every observation you rely on, note: target ID, attribute, observed value, the exact probe command and the time. Plans, snapshots and verification use these notes.

## Per-system references

This folder may also contain one reference file per system the project manages, such as Entra ID, Exchange Online, Intune or Azure CLI. Which files are present depends on the project profile. Read the ones that match the system you are probing. If there is none for a system, use read verbs only and let the guard's classification be the judge.
