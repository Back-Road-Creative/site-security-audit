# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- Exposed-path probes no longer report a critical for every 200. Each run
  fetches a random missing path as a baseline; a 200 that matches it is a
  catch-all page, a 200 whose body is not recognisably the file is a warning
  ("inconclusive"), and only content-confirmed files are critical. Redirects,
  401/403/429/503 answers and oversize responses are classified separately.
  Reports carry status, media type, size and a digest, never the body.

## 0.1.0

First public release.

### Added

- `security-audit.sh` — zero-dependency live-site security auditor covering
  security headers, server fingerprinting, 30 commonly-exposed paths, e-mail and
  phone leaks in served HTML, secret patterns in JS bundles, hardcoded
  credential assignments, the generator meta tag, TLS certificate expiry, and
  internal IP addresses in the response body.
- Exit codes `0` / `1` / `2` (clean / critical / warnings-only) so the script can
  gate a deploy. Across several URLs the worst result wins, ordered
  critical > warning > clean.
- `--json` machine-readable report. Finding text is passed to the JSON encoder
  out of band, so quotes and backslashes in a server banner cannot alter the
  report.
- `SECURITY_AUDIT_ALLOWED_EMAILS` and `SECURITY_AUDIT_ALLOWED_PHONES` to
  allowlist deliberately published contact details, per address, per domain
  (`@example.com`), or per number.
- False-positive suppression for build fingerprints (`_hu_<hash>` image
  derivatives, `name.<hash>.ext` hashed assets), Cloudflare e-mail obfuscation
  (`data-cfemail`, `/cdn-cgi/l/email-protection#…`), analytics and ad
  identifiers, timestamps, colour literals, pixel values and version strings.
- Cache-busting query string on every path probe, so a CDN edge serving a stale
  pre-deploy response cannot produce a false critical.
- Mockable test mode — `MOCK_HEADERS`, `MOCK_HTML`, `MOCK_SSL`,
  `MOCK_PATH_STATUS`, `MOCK_PATH_RESPONSES` — and a 47-test bash suite that runs
  with no network access.
- `examples/_headers` — annotated Cloudflare Pages / Netlify headers starter
  with a strict CSP, HSTS, frame and object lockdown, `Permissions-Policy`, and
  hash-aware Cache-Control tiers.
- `examples/post-deploy-audit.yml` — GitHub Actions workflow that gates a deploy
  on the audit and uploads the JSON report.
