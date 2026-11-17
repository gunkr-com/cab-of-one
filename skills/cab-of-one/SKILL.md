---
name: cab-of-one
description: Generate change control for this IT operations project by short interview. Reads local scripts and docs only, never a tenant; a person applies the result from their own terminal.
disable-model-invocation: true
allowed-tools: Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cab" setup discover:*), Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cab" setup render:*)
---

# /cab-of-one: interview-led setup

You are running the cab-of-one generator. A person started it. Follow these steps in
order. Do not skip the preview, and never apply anything yourself.

The setup hooks guard this session. Only Read, Grep, Glob, AskUserQuestion, Write or
Edit inside `.cab/setup/`, read-only shell commands and the two setup commands below
are allowed. Never contact a tenant or the network, and never sign in to anything. Do
not edit `.cab/setup/session.json`, `.cab/setup/discovery.json` or `.cab/setup/staged/`.

## 1. Preflight (no questions)

- With Read and Glob, list `.claude/` (settings, agents, skills, hooks) and note any name
  that a generated file would also use.
- Check `.claude/settings.local.json` for `disableAllHooks: true`. If it is set, stop and
  tell the person: project hooks would be switched off.
- If `.cab/manifest.json` exists, this is an update: say so, and keep its answers as the
  starting point.
- Do not open credential files (`.env`, `.pem`, `.pfx`, `.key` and similar).

## 2. Discovery (read-only)

Run:

```
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cab" setup discover
```

It writes `.cab/setup/discovery.json`: project-relative paths, line numbers and surface
codes only. Show the person a table of the draft profile: every field with its value,
its source (`discovered` or `default`) and its evidence codes. Nothing is an answer yet.

## 3. Interview (AskUserQuestion)

- At most 3 rounds and at most 10 questions in total. Round 3 is only for conflicts.
- Multiple choice, preselected from discovery. Do not ask what discovery already shows;
  ask the person to confirm it instead.
- Questions: systems agents may change; who approves irreversible changes; which
  identity agents use; how Claude Code runs for ops work (Manual / bypass inside the
  guardrails / auto); routine changes to pre-approve (written as disabled proposals);
  extra always-critical areas; multiple machines or a synced folder; ticketing; and,
  only on conflict, stop or drop the module.
- Named approver lists and ticketing are not supported yet. Rendering refuses
  `approval.approvers = "named"` and any `session.ticketing` other than `none`. If the
  person needs either one, say so plainly and stop: tell them this version cannot
  generate the controls they asked for. Write `self` or `none` only in two cases: the
  person confirms that this is what they actually use, or the question went unanswered and
  the documented default applies (source `default`). Never substitute it against a stated
  need.
- A question that closes on timeout or is skipped is **not** an answer. Use the
  documented default and record the source as `default`.
- Append each question and answer to `.cab/setup/interview.jsonl`.

## 4. Profile

Write `.cab/setup/profile.toml` (schema 1, every table and key present). The interview
can only make controls stricter or fit them to the systems in use. No field turns a
floor control off. Use only what the person said, what discovery found, and the
documented defaults. Never invent organisation details.

## 5. Render and preview

Run:

```
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cab" setup render
```

It writes the full result to `.cab/setup/staged/` and nothing else. Show the person the
plan: files added, changed and in conflict, settings entries and the control summary.

## 6. Hand-off to the person

Tell the person to run apply in their own terminal, not through Claude:

```
python3 "<absolute plugin path>/scripts/cab" setup apply
```

Give the absolute path of `scripts/cab` in this plugin. Apply checks for a terminal,
renders again and compares with the staged files, asks the person to type the project
folder name, backs up and writes. After apply, open a new Claude Code session.
