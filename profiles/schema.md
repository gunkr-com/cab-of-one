# Profile schema (`profile.toml`, schema 1)

**English** | [한국어](schema.ko.md)

A profile records the setup interview's answers. The generator turns it into project
files. A profile can tighten the controls or fit them to the systems you use. It cannot
switch them off: no field disables the core floor, and the loader refuses unknown keys.

Loader: `cab_of_one.setup.profile.load_profile(path_or_bytes)`.

## General rules

- `schema = 1` and every table and key below are required. Unknown keys, missing keys and
  duplicate keys or tables are refused.
- Booleans must be `true`/`false` and integers must be bare integers. `1` is not `true`,
  and `true` is not `1`.
- Lists must not repeat an entry. Order does not matter: lists are stored sorted.
- The file is UTF-8 without a byte-order mark and at most 64 KiB.
- An error names the field (for example `bad_choice: session.permission_mode`), never
  the value.

## Fields

| Field | Type | Allowed values | Effect |
|---|---|---|---|
| `org.name` | string | 1–64 characters: letters, digits, space, `. & , ' -`; begins with a letter or digit, ends with a letter, digit or `.` | Generated prose only (`$org_name`) |
| `org.it_team` | enum | `solo`, `small` | Prose only |
| `systems.entra` | bool | | M365 PowerShell and Graph adapters |
| `systems.exchange_online` | bool | | M365 PowerShell and Graph adapters |
| `systems.intune` | bool | | M365 PowerShell and Graph adapters |
| `systems.sharepoint_teams` | bool | | M365 PowerShell and Graph adapters |
| `systems.azure` | bool | | Azure CLI adapter |
| `systems.demo_simtenant` | bool | `true` only in a reference profile | simtenant adapter, demo files, trusted demo script |
| `surfaces.powershell_modules` | list of strings, ≤ 16 | dotted module names such as `Microsoft.Graph` | M365 PowerShell adapter |
| `surfaces.azure_cli` | bool | | Azure CLI adapter |
| `surfaces.graph_http` | bool | | Graph HTTP adapter |
| `surfaces.mcp_write_servers` | list of strings, ≤ 64 | `[A-Za-z0-9_-]{1,64}` | Every tool of these MCP servers is classified as an administrative write |
| `identity.agent_identity` | enum | `read-only`, `admin` | `admin` adds a setup notice |
| `identity.deny_read_paths` | list of strings, ≤ 32 | `./` followed by components of `A–Z a–z 0–9 . _ * -`; no `.` or `..` component, no absolute or `~` paths, no spaces, ≤ 200 characters | `Read(<path>)` deny rules |
| `approval.approvers` | enum | `self`, `named` | `named` is refused when rendering (not supported yet) |
| `approval.approval_ttl_hours` | int | 1–24 | Approval lifetime in `policy.toml` |
| `session.permission_mode` | enum | `manual`, `bypass-guarded`, `auto` | `manual` disables bypass permissions mode for the project. The others add a setup notice |
| `session.git` | bool | | `false` adds a notice to run `git init` yourself |
| `session.multi_machine` | bool | | Handoff notice |
| `session.sync_folder` | bool | | Notice that a synced folder cannot pin the ledger |
| `session.ticketing` | enum | `none`, `planner`, `jira`, `servicenow`, `other` | Anything except `none` is refused when rendering (not supported yet) |
| `changes.routine` | list of enums | `forwarding-removal`, `group-add-allowlisted`, `joiner-license-group`, `leaver-block-signin` | Commented proposals in `policy/standard-changes.toml`. Never an enabled entry |
| `changes.extra_critical` | list of enums | `admin-units`, `break-glass`, `executive-mailboxes`, `finance-groups` | Commented placeholders in `policy/policy.toml`. `break-glass` is always listed |

At least one system or write surface must be set. Otherwise the profile is refused
(`no_write_surface`).

## The demo

`systems.demo_simtenant = true` is accepted only when a known reference profile is loaded
with `load_reference_profile(name, source_root)`. Today the only reference profile is
`contoso-solo`. `load_profile` refuses the field for any other profile
(`demo_requires_reference`). The renderer checks the same rule, and also refuses rules that
would add the demo to a profile that did not ask for it.

## What every profile gets (the floor)

The floor is generated whatever the answers are:

- deny rules for protected paths and for human-only `cab` commands;
- PreToolUse and ConfigChange hooks with `onFailure: "block"`, and a Stop hook.
  `onFailure` has no effect on Stop, so a Stop hook crash or timeout ends the turn. See
  the [threat model](../docs/threat-model.md);
- audit hooks and the SessionStart self-test;
- the pinned hook entries and runtime;
- the five agents with explicit tools (`safety-reviewer`: Read, Grep and Glob only);
- the five core skills;
- the `CLAUDE.md` block;
- a policy that keeps one active change, the critical canary and halt-on-failure.

## Reference profiles

- `contoso-solo.toml`: a one-person IT team, Microsoft 365, Intune and Azure, several
  machines, bypass mode inside the guard rails. Fictional.
- `contoso-team.toml`: deferred. It needs named approvers and ticketing, and neither can
  be rendered yet.
