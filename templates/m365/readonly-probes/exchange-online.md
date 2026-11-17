# Exchange Online read-only probes

The guard classifies Exchange Online PowerShell by verb: `Get-`, `Find-` and `Test-` are reads, and every other verb is a write, `Connect-ExchangeOnline` included.

**Connection limit (v0.1):** each Bash call starts a new PowerShell process. A probe that needs `Connect-ExchangeOnline` in the same command counts as a write, so a subagent cannot run it. If no prepared connection exists, record the question as UNMEASURED with the command a person can run.

Examples use fictional Contoso identities. Prefer the mailbox's immutable ID (`ExternalDirectoryObjectId` or `Guid`) over a display name once you know it.

- Forwarding settings:
  `pwsh -NoProfile -Command "Get-Mailbox -Identity 00000000-0000-0000-0000-000000001042 | Select-Object Guid,DisplayName,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward"`
- Inbox rules that forward or redirect:
  `pwsh -NoProfile -Command "Get-InboxRule -Mailbox 00000000-0000-0000-0000-000000001042 | Select-Object Name,Enabled,ForwardTo,RedirectTo"`
- Full Access delegation:
  `pwsh -NoProfile -Command "Get-MailboxPermission -Identity 00000000-0000-0000-0000-000000001042"`
- Send As delegation:
  `pwsh -NoProfile -Command "Get-RecipientPermission -Identity 00000000-0000-0000-0000-000000001042"`
- Litigation hold and retention:
  `pwsh -NoProfile -Command "Get-Mailbox -Identity 00000000-0000-0000-0000-000000001042 | Select-Object LitigationHoldEnabled,InPlaceHolds,RetentionPolicy"`
- Mail flow rules:
  `pwsh -NoProfile -Command "Get-TransportRule | Select-Object Name,State,Priority"`
- Connectors:
  `pwsh -NoProfile -Command "Get-InboundConnector; Get-OutboundConnector"`
- Soft-deleted mailboxes (restore window):
  `pwsh -NoProfile -Command "Get-Mailbox -SoftDeletedMailbox | Select-Object Guid,DisplayName,WhenSoftDeleted"`

Mailbox delegation, holds, mail flow rules and connectors are dependents and critical areas. Releasing a hold or changing mail flow is critical by default.

Settings such as forwarding can take minutes to show up everywhere. Re-read with waits before you call a result FAIL.
