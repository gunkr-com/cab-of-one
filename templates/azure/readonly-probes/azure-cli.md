# Azure CLI read-only probes

The guard classifies Azure CLI by verb: `list`, `show` and `get-*` in command position are reads. Everything else is a write, and `az ... delete` is critical by default. `az rest` is a read only for a literal `GET` with no body.

Use resource IDs (immutable) once you know them. Examples use a fictional Contoso subscription and resource group.

| question | probe |
|---|---|
| Current account and subscription | `az account show --output json` |
| Resources in a group | `az resource list --resource-group rg-contoso-ops --output table` |
| One resource | `az resource show --ids /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-contoso-ops/providers/Microsoft.Storage/storageAccounts/stcontosoops01` |
| Role assignments on a scope | `az role assignment list --scope /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-contoso-ops --output table` |
| Resource locks | `az lock list --resource-group rg-contoso-ops --output table` |
| DNS records in a zone | `az network dns record-set list --resource-group rg-contoso-dns --zone-name contoso.example --output table` |
| Key Vault keys and secret names (no values) | `az keyvault key list --vault-name kv-contoso-ops` and `az keyvault secret list --vault-name kv-contoso-ops` |

- Never read secret values into the conversation or the ledger: `az keyvault secret show` returns the value. List names only.
- Role assignments, locks, DNS records and keys are critical areas. Check dependents (B6) and self-lockout (B10) before any change to them.
- `az login` and changing the default subscription (`az account set`) are not reads. A person does them outside the agent session.
