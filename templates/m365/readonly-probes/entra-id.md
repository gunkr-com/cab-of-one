# Entra ID read-only probes

The guard classifies Microsoft 365 PowerShell by verb: `Get-`, `Find-` and `Test-` are reads, and every other verb is a write, `Connect-` included. Graph HTTP calls are reads only for a literal `GET` or `HEAD` with no body.

**Connection limit (v0.1):** each Bash call starts a new PowerShell process. A probe that needs `Connect-MgGraph` in the same command counts as a write, so a subagent cannot run it. Use an authentication setup the person has prepared outside the agent session. If you have none, record the question as UNMEASURED with the command a person can run.

Examples use fictional Contoso IDs. Replace them with the immutable object IDs you discovered.

| question | probe |
|---|---|
| A user's state | `pwsh -NoProfile -Command "Get-MgUser -UserId 00000000-0000-0000-0000-000000001042 -Property Id,DisplayName,UserPrincipalName,AccountEnabled"` |
| Find IDs by name (discovery only; list every match) | `pwsh -NoProfile -Command "Get-MgUser -Search 'displayName:Jordan' -ConsistencyLevel eventual -Property Id,DisplayName,UserPrincipalName"` |
| A user's group memberships | `pwsh -NoProfile -Command "Get-MgUserMemberOf -UserId 00000000-0000-0000-0000-000000001042"` |
| A group's members | `pwsh -NoProfile -Command "Get-MgGroupMember -GroupId 00000000-0000-0000-0000-000000002001 -All"` |
| Groups nested in a group | `pwsh -NoProfile -Command "Get-MgGroupMemberOf -GroupId 00000000-0000-0000-0000-000000002001"` |
| Conditional access policies (who is included or excluded) | `pwsh -NoProfile -Command "Get-MgIdentityConditionalAccessPolicy -All"` |
| Directory role holders | `pwsh -NoProfile -Command "Get-MgDirectoryRoleMember -DirectoryRoleId 00000000-0000-0000-0000-000000009001"` |
| A user's licences | `pwsh -NoProfile -Command "Get-MgUserLicenseDetail -UserId 00000000-0000-0000-0000-000000001042"` |
| A user's registered authentication methods | `pwsh -NoProfile -Command "Get-MgUserAuthenticationMethod -UserId 00000000-0000-0000-0000-000000001042"` |
| Soft-deleted users (restore window) | `pwsh -NoProfile -Command "Get-MgDirectoryDeletedItemAsUser -All"` |

`-All` on a read returns more data, but it is still a read. On a write, `-All` is a blast-radius blocker (B8).

## Before relying on a probe

- Check the impact on break-glass accounts and admin exclusions (B10) in conditional access before any change to groups those policies use.
- Group-based licences and app assignments are dependents (B6). Look them up for every group target.
