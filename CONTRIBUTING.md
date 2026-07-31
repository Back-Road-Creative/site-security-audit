# Contributing

Thanks for taking a look. This is a small, deliberately boring repository: one
bash script, one test suite, no dependencies. Changes that keep it that way are
much easier to accept.

## Reporting

- **Bugs and ideas** — open an issue. For a false positive or false negative,
  include the smallest snippet of HTML or the exact response header that triggers
  it; that snippet usually becomes the test fixture.
- **Security vulnerabilities** — do not open a public issue. Follow
  [SECURITY.md](SECURITY.md).

## Setup

Nothing to install beyond what the script itself needs: `bash` 4+, `curl`,
`openssl`, `grep`, `sed`, `date`, `python3`.

```bash
git clone https://github.com/<owner>/site-security-audit.git
cd site-security-audit
./tests/run-tests.sh
```

## The gates

CI runs these on every push and pull request. Run them locally first.

```bash
bash -n security-audit.sh                     # syntax
./tests/run-tests.sh                          # full suite
shellcheck --severity=warning security-audit.sh tests/run-tests.sh tests/stubs/curl
```

`shellcheck` is not required to *use* the script, only to change it. Install it
from your package manager, or `pip install shellcheck-py`.

## Working on a check

**Write the failing test first.** Add a fixture under `tests/fixtures/`, add a
`test_…` function to `tests/run-tests.sh`, register it in the `main` list at the
bottom, watch it fail, then change the script. Never weaken or delete a test to
get a suite green.

A few conventions that keep the suite useful:

- **One fixture, one reason to fail.** When a fixture exists to prove that a
  particular false positive is suppressed, construct it so that deleting *that*
  rule — and only that rule — makes the test fail. If another rule happens to
  cover the same input, the test is not testing what you think it is.
- **Assert on the finding, not just the exit code.** Exit codes collapse a lot
  of different states into three numbers.
- **No network in tests.** Use the `MOCK_*` variables, or the `curl` stub in
  `tests/stubs/` when you need to assert on the request itself.

## Adding a pattern

New secret patterns are welcome, with two conditions: the pattern must have a
distinctive prefix (so it cannot match ordinary page content), and it must come
with both a positive fixture and a check that a legitimate public identifier of
similar shape is not caught. Every false positive in a deploy gate costs more
trust than the true positive gained.

## Style

- Keep it dependency-free. If a change needs a new binary, it probably belongs in
  a different tool.
- `set -uo pipefail` stays. `set -e` is deliberately not used — checks must all
  run and accumulate findings rather than aborting on the first non-zero grep.
- Comments explain *why*, not *what*. The suppression rules in particular are
  unreadable without the reason attached.
- Update the README in the same change as the behaviour. Docs do not land
  separately.

## Changelog

Add your change under a new heading in `CHANGELOG.md`, or to the unreleased
section if one exists.

## Commits

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
One logical change per pull request.
