# Security Policy

## Supported versions

Only the latest released tag receives fixes. Pin a `v*` tag rather than tracking
`main`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
issue for a security report.

- Preferred: GitHub's **Security → Report a vulnerability** tab on this
  repository (Private Vulnerability Reporting).
- Fallback: e-mail **joepetjr@gmail.com** with `site-security-audit security` in
  the subject.

Please include the affected version or commit, what the issue is and what it
lets someone do, reproduction steps, and any fix you have in mind.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment and severity triage within 10 business days.
- Coordinated disclosure: a timeline agreed with you before any public write-up,
  and credit if you want it.

## Scope

**In scope** — anything that lets a site being audited affect the machine
running the audit, or corrupt the audit's own output. Concretely: command
injection through a URL argument, a hostile response body or header value
escaping into the shell or into the `--json` report, path traversal through the
`MOCK_*` variables, or a crafted response causing the script to exit `0` when it
should exit `1`. The last one matters most: the script is used as a deploy gate,
so anything that makes it silently pass is a security bug, not a cosmetic one.

**Out of scope** — findings the script reports *about your site*. Those are the
output working as intended; fix them on the site.

Also out of scope, and documented as known limits in the
[README](README.md#limits--read-this-before-you-trust-it) rather than treated as
vulnerabilities:

- Missed secrets that do not match one of the listed prefix patterns.
- Missed content that is rendered by JavaScript after page load; the script
  inspects the initial HTML response and does not execute scripts.
- Exposed paths outside the fixed 30-entry probe list.
- A weak-but-present `Content-Security-Policy`. Presence is checked, strength is
  not.
- Certificate chain, revocation, cipher suite and protocol version. Only expiry
  and reachability are checked.

## A note on running it

The script makes outbound HTTP requests to whatever URL you pass, including
probes for 30 paths that do not usually exist. Run it against hosts you own or
have permission to test. Probing someone else's site with it is your
responsibility, not the project's.
