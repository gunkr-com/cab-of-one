---
name: tiering
description: Reference for the three reversibility questions and the standard, normal and critical tiers, including the pattern floor and the standard-change catalogue. Use when answering [answers] in change.toml or when the guard reports a tier problem.
---

# Tiering

Reversibility and blast radius set the risk. The number of objects does not. Count only changes how the change runs (first unit first), never its tier.

## The three questions

| key in `[answers]` | question | safe answer when unsure |
|---|---|---|
| `reversible` | Can a known command fully undo it, within the recovery window? | `false` |
| `has_dependents` | Do other people or objects depend on these targets (policies, groups, delegation, licences, app assignments, DNS)? | `true` |
| `targets_enumerated` | Are the targets an explicit list of immutable IDs in `targets.csv`? | `false` |

If `targets_enumerated` is false, nothing runs at any tier. Enumerate the targets first. Set `irreversible = true` when no known command undoes the change. That makes it `critical`.

## Tiers

| tier | when | gates |
|---|---|---|
| `standard` | reversible, no dependents, and the command matches an enabled entry in `policy/standard-changes.toml` (exact adapter, command pattern, targets within scope, exact state scope) | plan check, snapshot, verify, record |
| `normal` | reversible, but with dependents or no catalogue match | the above, plus safety review and human approval |
| `critical` | irreversible, or matches an always-critical pattern | the above, plus impact analysis, first unit alone and verified PASS before the rest, stop at first failure |

## The guard decides, not the answers

- Effective tier = max(tier from the answers, catalogue result, pattern floor of the actual command).
- The floor comes from the core always-critical patterns plus `policy/policy.toml`. Examples: permanent delete or purge, conditional access and authentication methods, privileged role assignment, domains and DNS, mail flow rules and connectors, hold or retention release, licence removal, device wipe or retire, key rotation, resource deletion, tenant-wide scope.
- A command the classifier cannot read with confidence is an unknown admin command. It counts as a write with a floor of at least `normal`.
- If the effective tier is above the recorded tier, the guard refuses with `tier_floor`. Re-plan at that tier; do not rephrase the command.
- Standard is never self-declared. Only a person enables catalogue entries.

## Examples (fictional Contoso)

| change | tier |
|---|---|
| Add a user to an allow-listed, non-privileged group, with a matching enabled catalogue entry | standard |
| Remove a user from a group that a conditional access policy uses | normal |
| Change a mailbox setting that is not in the catalogue | normal |
| Purge a soft-deleted user | critical |
| Change a domain or MX record | critical |
