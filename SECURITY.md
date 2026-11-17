# Security policy

English | [한국어](SECURITY.ko.md)

This harness is meant to sit in front of systems that matter, so treat it with care. In this draft it runs only against a local simulator, and it refuses writes to real tenants. Before you point any future version at a real tenant, give agents a read-only identity ([docs/identity.md](docs/identity.md)), read [docs/threat-model.md](docs/threat-model.md), and run `cab doctor`.

## Supported versions

There is no release yet. After the first release, only the latest minor version will get security fixes.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting for this repository: the **Report a vulnerability** button under the **Security** tab.

Private vulnerability reporting must be switched on before this repository is made public. If you cannot find the button, do not open a public issue or pull request with the details. Wait until private reporting is available.

Please include:

- the cab-of-one commit or version, the Claude Code version and the operating system;
- the settings layers involved (project, local, user, managed), with any real identifiers removed;
- the smallest set of steps or hook input that reproduces the issue, using fictional data such as Contoso;
- what you expected the guard, hook or CLI to do, and what it did.

Never include real tenant IDs, domains, user names, tokens, transcripts or ledger lines from a real environment.

## In scope

- Getting past the guard, including commands it misclassifies as reads or ignores as non-admin.
- Forging or replaying an approval, review, snapshot or verification record, or making a person-only command (`approve`, `ack`, `resume`, interactive `intake`, `setup apply`, `setup uninstall`) succeed without a person.
- Changing or removing ledger lines without the change being reported.
- Settings combinations that silently switch the hooks or deny rules off without `cab doctor` or the setup checks reporting it.
- Secrets that survive into the ledger, `.cab/state/` or command output.
- Prompt injection that leads an agent around a gate.
- The generator or installer writing outside the paths it reports, or losing a person's settings.

Known limits listed in the threat model are still worth reporting if you find a practical way to exploit them. Classifier evasion is a known limit, and reports are still welcome.

## Response

This project has one maintainer, and responses are best effort. The aim is to acknowledge a report within 7 days. There is no bug bounty.

## No warranty

The software is provided as is, without warranty of any kind. See [LICENSE](LICENSE) for the Apache-2.0 terms.
