# Contributing

English | [한국어](CONTRIBUTING.ko.md)

Thank you for your interest. This project is a Claude Code simulator preview. Before you start work on a contribution, open an issue to discuss what you propose.

## Sign your commits (DCO)

Every commit needs a `Signed-off-by` line under the [Developer Certificate of Origin](https://developercertificate.org/). Use:

```sh
git commit -s
```

There is no contributor license agreement.

## Before you start

- Open an issue first for a new adapter, a new write surface or any large change.
- Changes to the guard, the tier floor, the policy schema, the hooks, approval, verification or the generator's merge rules need new or updated unit tests in the same pull request.
- A change to a gate (the guard, approval, intake, the Stop hook or verification) also needs the relevant agent-level results from the runner under `evals/` (see [evals/results/latest.md](evals/results/latest.md)).
  - Report every attempt, including FAIL, INCONCLUSIVE and ERROR. Do not retry or drop attempts.
  - State the Claude Code version and model used.
  - Agent-level runs use your own Claude Code sign-in and model usage. They are run locally and are not part of CI.

## Never include real data

Do not put real tenant IDs, domains, user names, email addresses, hostnames, IP addresses, tokens, transcripts or ledger lines in issues, pull requests, tests or fixtures. Use the fictional Contoso data in `simtenant/`, or invent new fictional data in the same style.

## Out of scope

These will not be accepted:

- automatic approval, or any switch that skips approval, review, snapshots or verification;
- profile fields or options that lower or turn off the generated floor of controls;
- treating UNMEASURED as PASS;
- adapters or examples that connect to a real tenant from the generator or from tests.

## Code and tests

- The runtime and the generator use the Python 3.11+ standard library only. `pytest` and `ruff` are development tools.
- Tests must use fixtures and temporary folders inside the checkout. They must not touch the network, a real tenant, real Claude Code settings or real transcripts.
- Before you open a pull request, run:

  ```sh
  python3 -m pytest -q
  ruff check .
  ruff format --check .
  ```

- Do not describe unit tests as end-to-end or agent-level evidence. Say what was actually run.

## AI-assisted contributions

These are welcome. You are responsible for every line you submit, so read and test it as if you had written it yourself.

## Security issues

Do not file a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md). It includes the private reporting contact for conduct concerns.

## Trademarks

Claude and Claude Code are trademarks of Anthropic. Microsoft 365, Entra ID, Exchange Online, Intune and Azure are trademarks of Microsoft. This project is not affiliated with, or endorsed by, Anthropic, Microsoft or Harness Inc.
