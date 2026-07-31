# Test fixtures

Canned responses for the mockable fetchers in `security-audit.sh`. Nothing here
is real: every host is `example.com` or a `.invalid` domain, every phone number
is in the `555-01xx` range reserved for fiction, and every credential-shaped
string is a synthetic placeholder that has never been issued by any provider.

## Naming

| Prefix | Fed to | Via |
|---|---|---|
| `headers-*` | response headers | `MOCK_HEADERS` |
| `html-*` | page body | `MOCK_HTML` |
| `ssl-*` | `openssl x509 -dates` output | `MOCK_SSL` |
| `paths-*` | path-probe statuses | `MOCK_PATH_RESPONSES` |

## The false-positive fixtures

`html-hugo-fingerprint`, `html-asset-hash`, `html-cfemail` and
`html-cfemail-link` all embed the same phone-shaped digit run, `2025550143`,
inside a different construct:

| Fixture | Construct | Suppressed by |
|---|---|---|
| `html-hugo-fingerprint.txt` | `hero_hu_2025550143.webp` | the `_hu_<hex>` strip |
| `html-asset-hash.txt` | `main.2025550143ab.css` | the `.<hex>.<ext>` strip |
| `html-cfemail.txt` | `data-cfemail="ab2025550143"` | the `data-cfemail` strip |
| `html-cfemail-link.txt` | `/cdn-cgi/l/email-protection#abababab2025550143` | the `/cdn-cgi/l/email-protection#…` strip |

Each is built so that removing *its own* rule — and no other — makes the digits
resurface as a bogus "phone number found" warning. The padding in the
`cdn-cgi` fixture is deliberate: a shorter fragment would be absorbed by the
generic `#<hex>` colour-literal strip, and the test would pass for the wrong
reason. Check that property still holds if you edit them.

## Certificates

`ssl-valid.txt` expires in 2035 so it does not rot. The near-expiry and expired
cases are generated relative to the current date by `make_cert` in
`tests/run-tests.sh`, because a fixture with a fixed date would silently stop
exercising the 30-day threshold.

## Synthetic credentials

`html-secrets.txt` contains strings shaped like an AWS access key, a GitHub
personal access token and an OpenAI key. They are keyboard-pattern placeholders
— the AWS one is the literal word EXAMPLE twice with two digits after the `AKIA`
prefix, the GitHub one is the alphabet repeated after `ghp_` — chosen to match
the detection regexes and nothing else.

Do not replace them with anything real, and do not "fix" them to look more
plausible. A fixture that looks like a live credential gets flagged by every
secret scanner that touches the repository. `.gitleaks.toml` at the root already
allowlists this directory for that reason; a pre-commit hook of your own may
still object, and `--no-verify` with an explanation is the right answer when it
does.
