# Releasing and publication checks

English | [한국어](releasing.ko.md)

These checks keep secrets, identifiers and private names out of the public repository. CI
runs the public ones on every push and pull request. The maintainer runs the private ones
locally before every push. A human still reviews gate logic, merge rules, public documents
and the first push; nothing here replaces that review.

## What runs where

| Check | CI (public) | Local pre-push (opt-in) |
|---|---|---|
| `pytest`, `ruff check` and `ruff format --check` on Linux and macOS, Python 3.11 and 3.14 | yes | run by hand |
| Identifier scan, generic rules (`scripts/check_identifiers.py`) | working-tree candidate | working tree, every pushed commit and every pushed remote ref name |
| Identifier scan, private denylist | never | yes, required (same scope) |
| Commit message and author/committer identity (GitHub noreply) | no | every pushed commit |
| gitleaks history (`gitleaks git --redact --log-opts="--all -m"`) | yes | yes |
| gitleaks on an exported candidate (`gitleaks dir --redact`) | yes | yes (HEAD tree) |
| DCO sign-off (`scripts/check_dco.py`) | every new commit, merge commits included | run by hand |

Every gitleaks call, in CI and in the hook, also passes `--ignore-gitleaks-allow`, so inline `gitleaks:allow` comments suppress nothing. `-m` in the history scan makes gitleaks read merge-commit diffs as well.

Fingerprint suppression through a `.gitleaksignore` file is prevented by refusing such files, not by a flag. gitleaks 8.30.1 always reads a `.gitleaksignore` at the root of the scan target, even when `--gitleaks-ignore-path /dev/null` is passed. The hook and CI therefore run a preflight that blocks if any `.gitleaksignore` exists:

- in the publication candidate or its export;
- in any commit being pushed or scanned;
- at the physical repository root, even if it is ignored by Git or is a symlink.

The only exceptions are the reviewed rules in `.gitleaks.toml` (below).

### Generic identifier rules

GUIDs, IPv4 addresses (RFC 1918 private, CGNAT, public and other reserved ranges), e-mail
addresses, absolute home paths (macOS, Linux and Windows forms), long Discord-style numeric
IDs, and `*.onmicrosoft.com` tenants other than `contoso`. Two forms are treated as fictional
by the rule itself: GUIDs whose first 20 hex digits are zero (documentation placeholders),
and e-mail addresses under reserved names (`.example`, `.test`, `.invalid`, `.localhost`,
`example.com`/`.net`/`.org`) or the Contoso onmicrosoft domain. Anything else that is a
deliberate fictional fixture needs an entry in `EXCEPTIONS` in the scanner: one rule, one
exact path, one exact value, with a note saying why it is fictional. A reviewed contact that
is deliberately public is not a fixture and is labelled as such: the only one is the
reporting address in `CODE_OF_CONDUCT.md`, allowed in that file alone, so the same address
anywhere else and any other address in that file are still findings. There is no baseline
file, no domain-wide allowance, no path-wide suppression and no inline or fingerprint
suppression.

The scanner reads only files that Git would publish: tracked plus untracked, minus ignored
files. It refuses symlinks, binary or non-UTF-8 files, tracked files that match an ignore
rule, and private paths (`.local/`, `.build-inputs/`, `CLAUDE.md`, `AGENTS.md`,
`.claude/settings.local.json`); none of those are read. It works before the first commit.
Output is rule, path and line only. A path that itself matches a rule is printed as
`[redacted path #N]`, where N is its position in `git ls-files` order.

```sh
python3 -I scripts/check_identifiers.py            # working-tree candidate
python3 -I scripts/check_identifiers.py --json     # machine-readable
python3 -I scripts/check_identifiers.py --rev HEAD --check-commit-metadata
```

### gitleaks configuration

`.gitleaks.toml` extends the gitleaks default rules. It has no global allowlist. Inline
`gitleaks:allow` comments are ignored on every run, and any `.gitleaksignore` file is refused
(see above), so this file is the only place an exception can live. Each
exception belongs to one default rule, names anchored test paths, and lists the exact
fictional values that the redaction tests use on purpose (`condition = "AND"`). Review any
change to it like gate logic.

## Private denylist (local only)

Create it once, outside the repository, readable only by you:

```sh
mkdir -p "$HOME/.config/cab-of-one"
chmod 700 "$HOME/.config/cab-of-one"
$EDITOR "$HOME/.config/cab-of-one/denylist.txt"
chmod 600 "$HOME/.config/cab-of-one/denylist.txt"
```

Each non-empty line is a literal term (no comments, no patterns) matched without regard to
case: employer and client names, brands and domains, people's names, host and tailnet names,
personal system names. Never commit it. The scanner reads the whole list and fails closed if
it cannot. It also fails closed when the list is missing,
empty, a symlink, not UTF-8, or inside the repository, and it refuses to read a list at all
when running under GitHub Actions. It never prints the terms, their hashes or the list's
file name.

```sh
python3 -I scripts/check_identifiers.py --denylist "$HOME/.config/cab-of-one/denylist.txt"
```

## Pre-push hook (opt-in)

Nothing installs the hook or changes Git configuration for you. To opt in for this clone:

```sh
git config --local core.hooksPath .githooks
test -x .githooks/pre-push && echo "hook is executable"
```

Git silently skips a hook that is not executable, so check the second line prints. The file
must be committed with mode 100755.

The hook needs Python 3.11+, `gitleaks` on `PATH`, and the denylist above. It blocks the push
unless:

1. every pushed ref points at the checked-out `HEAD` commit, nothing is being deleted, and
   the working tree is clean (push with `git push <remote> HEAD:<branch>`; push other refs
   by checking them out first);
2. the working-tree scan passes with the generic rules and the denylist;
3. every remote ref name being pushed (for example `refs/heads/<branch>` or
   `refs/tags/<tag>`) passes the generic rules and the denylist, through the scanner's
   repeatable `--ref` option (one exact full ref name each, for example
   `--ref=refs/heads/main`). A branch or tag name is published too;
4. every commit being pushed passes the tree scan, the message scan and the noreply identity
   check. "Being pushed" means reachable from the pushed commit but not from the old object
   IDs that Git reports for the remote refs in this push. Local remote-tracking refs
   (`refs/remotes/...`) are not trusted to say what the remote already has, because they can
   be stale; they never shrink the set of commits scanned;
5. `gitleaks git --redact --log-opts="--all -m"` passes over all local history, merge diffs
   included, and `gitleaks dir --redact` passes over a fresh export of the `HEAD` tree in a
   temporary directory. Both use `.gitleaks.toml` and `--ignore-gitleaks-allow`, after a
   preflight that refuses any `.gitleaksignore` (in the candidate, its export, a pushed commit,
   or at the physical repository root, even if it is ignored or a symlink).

The hook has no bypass switch. Git's own `--no-verify` skips every hook; do not use it for
this repository.

Install gitleaks yourself from the official release page and check the published SHA-256
before extracting it. CI pins gitleaks 8.30.1 and verifies the archive hash the same way.

## DCO

Every commit needs `Signed-off-by: Name <email>` matching the author e-mail
(`git commit -s`). There are no exemptions, and that includes merges:

- a local merge: `git merge --signoff`;
- a squash merge: put an explicit `Signed-off-by:` line for the squash commit's author in its
  message;
- a merge made in a hosting service's interface: only if the resulting commit carries a
  matching sign-off. Otherwise merge locally.

CI checks the commits a push or pull request adds:

- pull request: commits on the head that are not on the base (`head --not base`);
- push: commits after the previous tip (`after --not before`);
- first push or new branch (`before` is all zeros), or a base missing from the history after
  a force push: every commit reachable from the head, up to 500; above that the check fails.

Event data reaches the script through environment variables and must be full commit IDs.
Locally:

```sh
python3 -I scripts/check_dco.py --base origin/main --head HEAD
```

## First publication

1. Start from a clean working tree and make one new commit (no private history), signed off,
   with a GitHub noreply author address.
2. Run the tests, `ruff check .`, `ruff format --check .`, the identifier scan with the denylist, both gitleaks scans
   and the DCO check. All must pass with zero findings.
3. Have the human reviewer approve the first push, then push `HEAD` with the hook enabled.
4. On GitHub, turn on private vulnerability reporting, secret scanning and push protection.
   Protect `main`, keep the default Actions token read-only, and add no Actions secrets.
