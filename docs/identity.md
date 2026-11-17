# Agent identities and credentials

> Draft. In this version the harness refuses writes to real tenants, because its verification runner supports only the simulated tenant. This guide is for setting up a real environment safely ahead of time, and for running real-tenant reads.

## The principle

Hooks and deny rules guard against an agent's mistakes. They are not a security boundary (see `docs/threat-model.md` in the source checkout). What actually limits an agent is the identity it signs in with. If that identity can only read, a mistake or a bypass cannot change the tenant.

Recommended setup:

| Identity | Who uses it | Rights |
|---|---|---|
| Agent identity | Claude Code and its subagents | Read-only roles and scopes only |
| Write identity | A person, at the time of a change | The smallest admin role the change needs, activated just in time where your platform supports it |
| Break-glass accounts | A person, in an emergency | Never available to agents; treat any change touching them as `critical` |

Do not let an agent sign in as your own administrator account. When the setup interview's identity question is answered "my admin account" or "not sure", the profile records it as the stricter "admin" value. That value has two effects:

- The render preview shows a notice.
- The generated harness adds a warning at the start of every Claude Code session. It says the agent identity is admin and that read-only credentials are preferred.

If the setup metadata behind that warning is missing or corrupt, the session-start message says instead that the identity is UNMEASURED. It never assumes the identity is read-only.

The warning is advisory only. It does not stop an agent from signing in, and the harness does not enforce which identity or credentials an agent uses. The warning is covered by the generated-harness tests. How Claude Code displays it in a live session has not been measured.

## Keep write credentials away from the agent

- **Do not store write credentials in the project.** That includes certificates, `.pfx` or `.pem` files, `.env` files and client secrets.
- **Deny reads of credential paths.** If credentials must live nearby, list their paths in the profile's `identity.deny_read_paths`. The generator adds a `Read(...)` deny rule for each. Paths must be project-relative and start with `./`, for example `./secrets/**`.
- **Block shell reads too.** Deny rules apply to Claude Code's `Read` tool, not to shell commands. To stop `Bash` from reading the same files, also add the paths to the Claude Code sandbox's read-deny settings in your own user settings. The generator never writes user, local or managed settings.
- **Watch for discovered credentials.** Setup discovery lists credential-like file paths it finds as candidates for deny rules. It never opens them.

A gated wrapper that injects write credentials only after approval is planned, not built. Until it exists, the person runs real-tenant writes with the write identity, outside the agent session.

## Signing in for reads

The guard classifies Microsoft Graph PowerShell by verb:

- `Get-`, `Find-` and `Test-` are reads.
- Every other verb is a write, including `Connect-MgGraph`, `Connect-ExchangeOnline` and `Connect-AzAccount`.

Consequences:

- **Signing in is a write.** A command that connects and then reads in one shell call is a write. A subagent cannot run it, and the main session needs an open change to run it.
- **New process, new sign-in.** Each `Bash` call starts a new process, so a PowerShell session does not carry over between calls. Unless a read-only sign-in is already available to the process, for example a cached token for the read-only identity, real-tenant probes will be UNMEASURED.
- **Azure CLI.** `list`, `show` and `get-*` subcommands are reads. `az login` is a write.

Record an unanswerable question as UNMEASURED, together with the exact command a person can run. Do not record it as PASS.

## Checks

- Run `cab doctor` after any settings change. It reports deny rules and hooks that are missing, and the settings sources it could not read.
- Run `cab audit` regularly to find admin writes made outside the project, and sessions where the hooks did not run.
- Review sign-in logs for the agent identity in your tenant. The harness does not read them.
