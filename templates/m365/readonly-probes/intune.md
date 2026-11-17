# Intune read-only probes

The guard classifies Microsoft Graph PowerShell by verb: `Get-`, `Find-` and `Test-` are reads, and every other verb is a write, `Connect-MgGraph` included. Device wipe and retire are critical by default.

**Connection limit (v0.1):** each Bash call starts a new PowerShell process. A probe that needs `Connect-MgGraph` in the same command counts as a write, so a subagent cannot run it. If no prepared connection exists, record the question as UNMEASURED with the command a person can run.

Examples use fictional Contoso device IDs.

- A managed device's state:
  `pwsh -NoProfile -Command "Get-MgDeviceManagementManagedDevice -ManagedDeviceId 00000000-0000-0000-0000-000000005001 | Select-Object Id,DeviceName,UserPrincipalName,ComplianceState,ManagementState,LastSyncDateTime"`
- A user's managed devices:
  `pwsh -NoProfile -Command "Get-MgUserManagedDevice -UserId 00000000-0000-0000-0000-000000001042"`
- Compliance policies:
  `pwsh -NoProfile -Command "Get-MgDeviceManagementDeviceCompliancePolicy -All"`
- Configuration profiles:
  `pwsh -NoProfile -Command "Get-MgDeviceManagementDeviceConfiguration -All"`

- A device action (wipe, retire, sync) runs asynchronously. A read straight after the action does not prove the result. Check the device's action state and last sync time, re-read with waits, and record UNMEASURED if the result never becomes observable.
- Before any device action, record who uses the device and whether a backup exists (B4).
