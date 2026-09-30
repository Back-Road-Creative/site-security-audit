# site-security-audit

A single bash script that audits a **live** static site the way a stranger on the
internet sees it, and exits non-zero when something is wrong. Point it at a URL
after a deploy and it tells you whether the site you just published is leaking
anything.

```
$ ./security-audit.sh https://example.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Security Audit: https://example.com
  Version: 1.0.0 | 2026-01-01T12:00:00Z
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

── Security Headers ──
[PASS]  security-headers: content-security-policy present
[PASS]  security-headers: x-frame-options present
[PASS]  security-headers: x-content-type-options present
[PASS]  security-headers: strict-transport-security present
[WARN]  security-headers: Missing advisory header: permissions-policy

── Exposed Paths ──
[CRITICAL] exposed-paths: /.env is publicly accessible (HTTP 200) — text/plain, 143 bytes, digest sha256:3f2a9c81b0de
[PASS]  exposed-paths: probed 30 sensitive paths

── Content Analysis ──
[CRITICAL] js-secrets: Potential secret found matching pattern: AKIAEXAM...LE12
[WARN]  generator: Generator meta tag exposes build tool: <meta name="generator" content="ExampleSSG 1.2.3"

── SSL/TLS ──
[PASS]  ssl: certificate present, expires Dec 31 23:59:59 2026 GMT
[PASS]  ssl: 214 days until expiry

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  RESULT: FAIL — 2 critical, 2 warnings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Why this exists

Static-site security is mostly a deploy-time property, not a build-time one. Your
generator can be perfectly configured and your host can still fail to apply the
headers file, your CDN can still serve `.env` from a cached directory listing, an
API key can still make it into a JS bundle, and the certificate can still be
three weeks from expiry. None of that shows up in a local build.

Existing tools cover pieces of this — an online header grader here, a secret
scanner over your source tree there — but they check the repository, not the
thing on the wire, and they are awkward to run as a blocking step in a deploy
pipeline. This script checks the served response, needs nothing installed, and
returns an exit code a CI job can act on.

## What it checks

| Check | Severity | What it looks at |
|---|---|---|
| Critical security headers | critical | `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` |
| Advisory security headers | warning | `Referrer-Policy`, `Permissions-Policy` |
| Server fingerprinting | warning | `X-Powered-By`, and a `Server` header carrying a version number |
| Exposed paths | critical / warning | 30 commonly-leaked paths — `.env`, `.git/config`, `.git/HEAD`, `wp-config.php`, `backup.zip`, `db.sql`, `.htpasswd`, `phpinfo.php`, `.DS_Store`, `Makefile` and friends. A 200 is critical only when the body is recognisably the file and is not the page the site serves for a path that cannot exist; a 200 that cannot be confirmed is a warning (inconclusive). See [How a path probe is judged](#how-a-path-probe-is-judged) |
| E-mail addresses in HTML | critical | Anything address-shaped in the served page, minus an allowlist |
| Phone numbers in HTML | warning | US-format numbers, minus an allowlist |
| Secrets in bundles | critical | AWS keys, GitHub PATs/OAuth tokens, GitLab PATs, Slack tokens, OpenAI/Stripe keys, webhook secrets, JWTs, Google API keys, and hardcoded `password:` / `secret_key:` assignments inside `<script>` blocks |
| Generator tag | warning | A `<meta name="generator">` advertising your build tool and its version |
| TLS certificate | critical / warning | Unreachable or unparseable certificate is critical; expired is critical; under 30 days to expiry is a warning |
| Internal IPs | warning | `10.x`, `172.16–31.x`, `192.168.x` leaking into the response body |

Analytics and ad identifiers (`ca-pub-…`, `G-…`, `UA-…`, `GTM-…`, `AW-…`) are
allowlisted — they are meant to be public, and flagging them trains people to
ignore the tool.

## Install

No package manager, no build step. Copy one file:

```bash
curl -fsSL -o security-audit.sh \
  https://raw.githubusercontent.com/<owner>/site-security-audit/v0.1.0/security-audit.sh
chmod +x security-audit.sh
```

Or vendor it into a site repo (this is how it is meant to be used in CI):

```bash
mkdir -p .github/scripts
cp security-audit.sh .github/scripts/
```

**Requirements:** `bash` 4+, `curl`, `openssl`, `grep`, `sed`, `date`, and
`python3` (only for `--json`). All present by default on a GitHub Actions
`ubuntu-latest` runner and on any mainstream Linux.

## Usage

```bash
./security-audit.sh https://example.com                        # human report
./security-audit.sh --json https://example.com                 # machine report
./security-audit.sh https://one.example https://two.example    # several sites
./security-audit.sh --help
```

### Exit codes

| Code | Meaning | Suggested CI behaviour |
|---|---|---|
| `0` | Everything passed | proceed |
| `1` | At least one critical finding | fail the job |
| `2` | Warnings only | proceed, annotate the run |

With several URLs the worst result wins, in the order **critical > warning >
clean**.

### Allowlisting your own contact details

A site that publishes a contact address and a phone number is not leaking them.
Tell the script which ones are deliberate, or it will report your own footer:

```bash
export SECURITY_AUDIT_ALLOWED_EMAILS="hello@example.com,@support.example.com"
export SECURITY_AUDIT_ALLOWED_PHONES="15550100000"
./security-audit.sh https://example.com
```

- **Emails** — an entry with a local part (`hello@example.com`) matches that one
  address; an entry starting with `@` (`@example.com`) allows the whole domain.
  Matching is case-insensitive.
- **Phones** — digits only or formatted, either is fine. A detected number is
  allowed when its digits are a substring of an allowlisted number's digits, so
  `15550100000` covers the page rendering `(555) 010-0000`.

Both accept a comma- or whitespace-separated list.

### JSON output

```json
{
  "url": "https://example.com",
  "version": "1.0.0",
  "timestamp": "2026-01-01T12:00:00Z",
  "summary": {
    "status": "FAIL",
    "criticals": 1,
    "warnings": 2,
    "total_checks": 41
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "exposed-paths",
      "message": "/.env is publicly accessible (HTTP 200) — text/plain, 143 bytes, digest sha256:3f2a9c81b0de"
    }
  ]
}
```

`status` is `PASS`, `WARN` or `FAIL`. `--json` takes one URL at a time.

## Using it in CI

[`examples/post-deploy-audit.yml`](examples/post-deploy-audit.yml) is a complete
GitHub Actions workflow that runs the audit after a deploy, fails the job on a
critical finding, annotates on warnings, and uploads the JSON report as an
artifact. It also runs on a daily schedule, which is what actually catches an
expiring certificate on a site nobody has deployed to in a month.

## Hardening starter

[`examples/_headers`](examples/_headers) is a heavily commented Cloudflare Pages
/ Netlify headers file that makes the header checks above pass: a strict CSP
with no `unsafe-inline` or `unsafe-eval` for scripts, HSTS with preload, frame
and object lockdown, an empty-by-default `Permissions-Policy`, and Cache-Control
tiered by whether a filename carries a content hash.

Every line has a comment explaining *why*, including the two decisions most
likely to bite you — `preload` is close to irreversible, and `style-src
'unsafe-inline'` is a deliberate, explained compromise. Read it before shipping
it; it is a starting point, not a drop-in.

## How a path probe is judged

A bare "the server said 200" is not evidence of an exposure: many hosts answer
every URL with a 200 page (single-page apps, soft-404 templates). So each run
first fetches one path that cannot exist (`/audit-missing-<random>`) and
compares every probe with that baseline:

| Probe answer | Verdict |
|---|---|
| 200, same media type and same bytes as the baseline (the probed path is masked out, so a "`/x` was not found" page still matches) | not an exposure; counted as matching the catch-all baseline |
| 200 and the body matches what that file really looks like (`KEY=value` lines for `.env`, `[core]` for `.git/config`, `CREATE TABLE` for a dump, a password form for `/admin`, ...) | **critical** |
| 200 and a non-HTML response over the read limit at a probed path | **critical** (the content cannot be read, so the media type decides) |
| 200 and anything else | **warning: inconclusive**, never promoted to critical |
| 3xx | reported as redirected, not an exposure |
| 401, 403, 407, 429, 503 | reported as restricted (auth wall or challenge), not an exposure |
| anything else | absent |

Reports never contain response bodies. A finding carries the status, media type,
size and a short digest (`sha256:` of the body, `cksum:` where no SHA tool
exists) so two runs can be compared without printing what may be a secret.
Probes do not follow redirects and are bounded to 5 seconds and 64 KiB each.

## Testing and development

The script is mockable end to end, so the test suite makes no network calls:

```bash
./tests/run-tests.sh          # the whole suite
./tests/run-tests.sh pii      # only tests whose name contains "pii"
```

The mock variables are part of the public surface — use them to write your own
checks against your own fixtures:

| Variable | Effect |
|---|---|
| `MOCK_HEADERS` | file served instead of `curl -I` |
| `MOCK_HTML` | file served instead of the page body |
| `MOCK_SSL` | file served instead of `openssl x509 -dates` |
| `MOCK_PATH_STATUS` | one HTTP status returned for every path probe (with no body, a 200 is inconclusive) |
| `MOCK_PATH_RESPONSES` | file of `path:status[:body-file[:content-type]]` lines, unlisted paths default to 404. The line keyed `@baseline` describes the missing-path baseline (default 404). A relative body file is read from the directory of this file |

```bash
MOCK_HEADERS=tests/fixtures/headers-good.txt \
MOCK_HTML=tests/fixtures/html-clean.txt \
MOCK_SSL=tests/fixtures/ssl-valid.txt \
MOCK_PATH_STATUS=404 \
  ./security-audit.sh https://example.com
```

Point the suite at a different copy of the script — for instance one vendored
into a site repo some time ago — to see whether it still has every behaviour:

```bash
AUDIT_SCRIPT=/path/to/other/security-audit.sh ./tests/run-tests.sh
```

## Limits — read this before you trust it

- **It is a smoke test, not a penetration test.** It checks the front page of a
  site. It does not crawl, it does not test authentication, authorisation,
  injection, business logic, or anything behind a login.
- **Only the URL you give it is fetched.** Secrets sitting in a JS bundle that
  the front page does not reference will not be found. Pass the URLs that matter,
  or run a source-level secret scanner as well — this is not a replacement for
  one.
- **Path probing is a fixed list of 30 names.** A confirmed hit is strong
  evidence; a clean run is weak evidence. Content signatures are simple text
  patterns, so an unusual file (a `.env` written as JSON, a dump in a format the
  pattern does not know) that the site serves with a 200 is reported as
  *inconclusive*, not critical, and needs a look by hand.
- **The secret patterns are prefix-based.** They catch credentials that carry a
  recognisable prefix. A bare high-entropy string, a base64 blob, or a
  provider whose format is not listed will pass straight through.
- **PII detection is regex over rendered HTML.** Expect false positives from
  numeric content, and false negatives from anything obfuscated or injected after
  page load. It runs on the initial HTML response — it does not execute
  JavaScript, so client-rendered content is invisible to it.
- **`Content-Security-Policy` is checked for presence, not for strength.** A
  header of `default-src *` passes. Use `examples/_headers` as the baseline for
  what the value should actually say.
- **Certificate checking is expiry and reachability only.** No chain validation,
  no revocation, no cipher or protocol-version assessment.
- **Developed and tested on Linux with bash 5.** There is best-effort BSD/macOS
  support in the date handling, but CI runs on Linux only and macOS is not a
  supported platform.

## Licence

MIT — see [LICENSE](LICENSE).
