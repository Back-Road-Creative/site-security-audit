#!/usr/bin/env bash
# =============================================================================
# security-audit.sh — Production Security Audit for Static Sites
#
# Probes a *live* site the way an outsider sees it: response headers, commonly
# exposed paths, the served HTML, and the TLS certificate. Zero dependencies
# beyond bash, curl, openssl, grep, and python3 (JSON output only).
#
# Usage:
#   ./security-audit.sh <url> [url2] [url3]
#   ./security-audit.sh --json <url>
#   ./security-audit.sh --help
#
# Exit codes:
#   0 = all checks passed
#   1 = critical issue(s) found (blocks deploy)
#   2 = warnings only (deploy proceeds with notice)
#
# Environment (allowlists — published contact details are not leaks):
#   SECURITY_AUDIT_ALLOWED_EMAILS  comma/space separated. "user@site.com" for an
#                                  exact address, "@site.com" for a whole domain.
#   SECURITY_AUDIT_ALLOWED_PHONES  comma/space separated. Digits only or
#                                  formatted; a detected number whose digits are
#                                  a substring of an allowlisted number is kept
#                                  quiet (so "(555) 010-1234" is covered by
#                                  "15550101234").
#
# Environment (test mode):
#   MOCK_HEADERS  — file with mock response headers
#   MOCK_HTML     — file with mock HTML source
#   MOCK_SSL      — file with mock openssl cert output
#   MOCK_PATH_STATUS    — fixed HTTP status for all path probes
#   MOCK_PATH_RESPONSES — file with "path:status[:body-file[:content-type]]"
#                         lines; "@baseline" describes the missing-path probe
# =============================================================================
set -uo pipefail

VERSION="1.0.0"
# Kept so `--test-mode` remains a valid flag for existing callers. Mock data is
# driven entirely by the MOCK_* variables, so nothing reads this.
TEST_MODE=false
JSON_MODE=false
URLS=()
# Scratch space for response bodies and headers; created in main, removed on exit.
SCRATCH=""

# ---- Severity tracking ----
CRITICALS=0
WARNINGS=0
FINDINGS=()   # Array of "severity|category|message" strings

# ---- Configuration ----
# Critical headers — missing any = deploy blocker
CRITICAL_HEADERS=(
    "content-security-policy"
    "x-frame-options"
    "x-content-type-options"
    "strict-transport-security"
)

# Advisory headers — missing = warning, not blocker
WARN_HEADERS=(
    "referrer-policy"
    "permissions-policy"
)

# Published contact details (NAP footer, contact page, tel:/mailto: links) are
# intentional content, not PII leaks. Supply them and they stop being findings.
ALLOWED_EMAILS="${SECURITY_AUDIT_ALLOWED_EMAILS:-}"
ALLOWED_PHONES="${SECURITY_AUDIT_ALLOWED_PHONES:-}"

# Paths to probe — any 200 = critical
EXPOSED_PATHS=(
    ".env"
    ".env.local"
    ".env.production"
    ".git/config"
    ".git/HEAD"
    ".gitignore"
    "wp-admin"
    "wp-login.php"
    "xmlrpc.php"
    "admin"
    "login"
    "backup.zip"
    "backup.tar.gz"
    "db.sql"
    "dump.sql"
    "config.json"
    "config.yml"
    "config.toml"
    "package.json"
    ".htaccess"
    ".htpasswd"
    ".DS_Store"
    "debug.log"
    "error_log"
    "server-status"
    "phpinfo.php"
    "wp-config.php"
    "composer.json"
    "Gemfile"
    "Makefile"
)

# Patterns that indicate real secrets (not analytics IDs)
SECRET_PATTERNS=(
    'sk-[a-zA-Z0-9]{20,}'            # OpenAI / Stripe secret keys
    'sk-proj-[a-zA-Z0-9]+'           # OpenAI project keys
    'ghp_[a-zA-Z0-9]{36}'            # GitHub personal access tokens
    'gho_[a-zA-Z0-9]{36}'            # GitHub OAuth tokens
    'github_pat_[a-zA-Z0-9_]+'       # GitHub fine-grained PATs
    'glpat-[a-zA-Z0-9_-]+'           # GitLab PATs
    'xoxb-[0-9]+-[a-zA-Z0-9]+'       # Slack bot tokens
    'xoxp-[0-9]+-[a-zA-Z0-9]+'       # Slack user tokens
    'whsec_[a-zA-Z0-9]+'             # Webhook secrets
    'AKIA[0-9A-Z]{16}'               # AWS access keys
    'eyJ[a-zA-Z0-9_-]{20,}\.eyJ'     # JWT tokens
    'AIza[0-9A-Za-z_-]{35}'          # Google API keys
)

# Allowlisted patterns (analytics, ads — expected in public HTML)
ALLOWLIST_PATTERNS=(
    'ca-pub-[0-9]+'                  # AdSense publisher ID
    'G-[A-Z0-9]+'                    # GA4 measurement ID
    'UA-[0-9]+-[0-9]+'               # Universal Analytics
    'GTM-[A-Z0-9]+'                  # Google Tag Manager
    'AW-[0-9]+'                      # Google Ads conversion
    'pub-[0-9]+'                     # Generic pub IDs
)

# Internal IP patterns
INTERNAL_IP_PATTERNS=(
    '192\.168\.[0-9]+\.[0-9]+'
    '10\.[0-9]+\.[0-9]+\.[0-9]+'
    '172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+'
)

# ---- Logging ----
# Findings are newline-joined into a single record, so a message must stay on
# one line — a header value with an embedded newline would otherwise split one
# finding into two malformed ones in the JSON report.
log_pass()  { echo "[PASS]  $*"; }
log_warn()  {
    local msg="${2//$'\n'/ }"
    WARNINGS=$((WARNINGS + 1))
    FINDINGS+=("WARN|$1|${msg}")
    echo "[WARN]  $1: ${msg}"
}
log_crit()  {
    local msg="${2//$'\n'/ }"
    CRITICALS=$((CRITICALS + 1))
    FINDINGS+=("CRITICAL|$1|${msg}")
    echo "[CRITICAL] $1: ${msg}"
}

# ---- Data fetchers (mockable for testing) ----
# Headers and body come from ONE bounded GET per URL. A separate HEAD for the
# headers doubles the requests against a site we have just deployed to, and can
# describe a different response from the one the body came from: servers and
# CDNs routinely answer HEAD differently (another cache key, a missing
# Content-Security-Policy, a 405). So no HEAD is ever sent, and the report
# describes what a visitor's GET receives.
#
# The cache is filled from run_audit (not from inside a $(...) capture, where an
# assignment would be discarded with the subshell) and keyed by URL so a
# multi-URL run never serves one site's body for another.
PAGE_MAX_TIME=15
PAGE_MAX_REDIRS=5
PAGE_MAX_BYTES=2097152   # 2 MiB
_CACHE_URL=""
_CACHE_HEADERS=""
_CACHE_HTML=""
_CACHE_CHAIN=""          # "url (HTTP 301) -> url (HTTP 200)"; empty under a mock
_CACHE_FINAL=""
_CACHE_RC=0

# Reads a curl -D dump (one header block per redirect hop). Sets _CACHE_HEADERS
# to the LAST block, the response the visitor ends up on, and _CACHE_CHAIN to
# the hop-by-hop chain. A relative Location is recorded as sent.
_parse_header_dump() {
    local file="$1" line block="" code="" cur="$2" next="" chain=""
    while IFS= read -r line; do
        line="${line%$'\r'}"
        if [[ "$line" == HTTP/* ]]; then
            if [[ -n "$code" ]]; then
                chain+="${cur} (HTTP ${code}) -> "
                [[ -n "$next" ]] && cur="$next"
            fi
            block="" next=""
            code="${line#* }"
            code="${code%% *}"
        elif [[ "${line,,}" == location:* ]]; then
            next=$(_trim "${line#*:}")
        fi
        [[ -z "$line" ]] || block+="${line}"$'\n'
    done < "$file"
    _CACHE_HEADERS="${block%$'\n'}"
    [[ -n "$code" ]] && _CACHE_CHAIN="${chain}${cur} (HTTP ${code})"
    return 0
}

prime_response_cache() {
    local url="$1"
    _CACHE_URL="" _CACHE_HEADERS="" _CACHE_HTML="" _CACHE_CHAIN="" _CACHE_FINAL="$url" _CACHE_RC=0
    local mock_h=false mock_b=false
    [[ -n "${MOCK_HEADERS:-}" && -f "${MOCK_HEADERS}" ]] && mock_h=true
    [[ -n "${MOCK_HTML:-}" && -f "${MOCK_HTML}" ]] && mock_b=true

    # No request at all when both halves are mocked.
    if ! { $mock_h && $mock_b; }; then
        local body="${SCRATCH}/page.body" hdr="${SCRATCH}/page.hdr" final
        rm -f "$body" "$hdr"
        final=$(curl -s -L --max-redirs "$PAGE_MAX_REDIRS" --proto-redir =http,https \
            --max-time "$PAGE_MAX_TIME" --max-filesize "$PAGE_MAX_BYTES" \
            -D "$hdr" -o "$body" -w '%{url_effective}' "$url" 2>/dev/null)
        _CACHE_RC=$?
        [[ -n "$final" ]] && _CACHE_FINAL="$final"
        [[ -f "$hdr" ]] && _parse_header_dump "$hdr" "$url"
        [[ -f "$body" ]] && _CACHE_HTML=$(head -c "$PAGE_MAX_BYTES" "$body" 2>/dev/null | tr -d '\0')
    fi
    $mock_h && _CACHE_HEADERS=$(cat "$MOCK_HEADERS")
    $mock_b && _CACHE_HTML=$(cat "$MOCK_HTML")
    _CACHE_URL="$url"
    return 0
}

fetch_headers() { [[ "$_CACHE_URL" == "$1" ]] && printf '%s\n' "$_CACHE_HEADERS"; }
fetch_html()    { [[ "$_CACHE_URL" == "$1" ]] && printf '%s\n' "$_CACHE_HTML"; }

# One path probe. Results land in PROBE_* globals rather than on stdout because
# the caller needs four values and a $(...) capture would run in a subshell.
#   PROBE_STATUS  HTTP status ("000" when curl got no response)
#   PROBE_CTYPE   lower-cased media type, no parameters ("" when absent)
#   PROBE_BODY    at most PROBE_MAX_BYTES of the body, NUL bytes dropped
#   PROBE_LARGE   1 when curl stopped at the size limit, so PROBE_BODY is empty
#                 or partial
PROBE_MAX_BYTES=65536
PROBE_STATUS="" PROBE_CTYPE="" PROBE_BODY="" PROBE_LARGE=0

# Media type only, lower-cased: "Text/HTML; charset=UTF-8\r" -> "text/html".
_norm_ctype() {
    local ct="${1%%;*}"
    ct="${ct//$'\r'/}"
    _trim "$ct" | tr '[:upper:]' '[:lower:]'
}

# Mock lookup for MOCK_PATH_RESPONSES: `path:status[:body-file[:content-type]]`.
# A relative body file is read from the directory the responses file is in.
_mock_path_entry() {
    local key="$1" p s b c dir
    dir=$(dirname "$MOCK_PATH_RESPONSES")
    while IFS=: read -r p s b c; do
        [[ -z "$p" || "$p" == \#* ]] && continue
        if [[ "$p" == "$key" ]]; then
            PROBE_STATUS="${s// /}"
            PROBE_CTYPE=$(_norm_ctype "$c")
            if [[ -n "$b" ]]; then
                [[ "$b" == /* ]] || b="${dir}/${b}"
                PROBE_BODY=$(tr -d '\0' < "$b" 2>/dev/null)
            fi
            return 0
        fi
    done < "$MOCK_PATH_RESPONSES"
    return 1
}

fetch_path_probe() {
    local url="$1" path="$2"
    PROBE_STATUS="" PROBE_CTYPE="" PROBE_BODY="" PROBE_LARGE=0

    if [[ "$path" == "@baseline" ]]; then
        # Under a mock only the responses file can describe the baseline, and
        # a missing entry means the site returns a real 404.
        if [[ -n "${MOCK_PATH_RESPONSES:-}" && -f "${MOCK_PATH_RESPONSES}" ]]; then
            _mock_path_entry "@baseline" || PROBE_STATUS=404
            return
        fi
        if [[ -n "${MOCK_PATH_STATUS:-}" ]]; then
            PROBE_STATUS=404
            return
        fi
    elif [[ -n "${MOCK_PATH_STATUS:-}" ]]; then
        PROBE_STATUS="$MOCK_PATH_STATUS"
        return
    elif [[ -n "${MOCK_PATH_RESPONSES:-}" && -f "${MOCK_PATH_RESPONSES}" ]]; then
        _mock_path_entry "$path" || PROBE_STATUS=404
        return
    fi

    local real="$path"
    [[ "$path" == "@baseline" ]] && real="$PROBE_BASELINE_TOKEN"
    local body="${SCRATCH}/probe.body" hdr="${SCRATCH}/probe.hdr" rc
    rm -f "$body" "$hdr"
    # Cache-busting query: the audit runs seconds after a deploy, and a CDN
    # edge can otherwise serve a stale pre-deploy response for a path the
    # deploy just removed (false CRITICAL). Origin-served files still 200.
    # No -L: a redirect is an answer in its own right. --max-filesize and
    # --max-time bound what a hostile or misconfigured site can make us read.
    PROBE_STATUS=$(curl -s -o "$body" -D "$hdr" -w "%{http_code}" \
        --max-time 5 --max-filesize "$PROBE_MAX_BYTES" \
        "${url}/${real}?audit_cb=$$$(date +%s)" 2>/dev/null)
    rc=$?
    PROBE_STATUS="${PROBE_STATUS:-000}"
    [[ "$rc" -eq 63 ]] && PROBE_LARGE=1
    if [[ -f "$hdr" ]]; then
        PROBE_CTYPE=$(_norm_ctype "$(grep -i '^content-type:' "$hdr" | tail -1 | cut -d: -f2-)")
    fi
    if [[ -f "$body" ]]; then
        PROBE_BODY=$(head -c "$PROBE_MAX_BYTES" "$body" 2>/dev/null | tr -d '\0')
    fi
}

fetch_ssl() {
    local host="$1"
    if [[ -n "${MOCK_SSL:-}" && -f "${MOCK_SSL}" ]]; then
        cat "$MOCK_SSL"
    else
        echo | openssl s_client -connect "${host}:443" -servername "$host" 2>/dev/null \
            | openssl x509 -noout -dates -issuer -subject 2>/dev/null
    fi
}

# ---- Small helpers ----
# Trim leading/trailing whitespace. Deliberately not `xargs`: xargs applies
# shell quote processing, so it would strip the quotes out of a header value on
# its way into the report — and abort outright on an unbalanced one.
_trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# Split on commas and whitespace so both "a@b.com, c@d.com" and a shell array
# pasted into one variable behave the same. The trailing newline matters: a
# `while read` loop drops the final line of a stream that lacks one.
_split_allowlist() {
    printf '%s\n' "$1" | tr ',' '\n' | tr -s '[:space:]' '\n' | sed '/^$/d'
}

# An address is allowed when it matches an entry exactly, or when an entry
# begins with "@" and the address ends with it (whole-domain allow).
is_allowed_email() {
    local email entry
    email=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    [[ -z "$ALLOWED_EMAILS" ]] && return 1
    while IFS= read -r entry; do
        entry=$(printf '%s' "$entry" | tr '[:upper:]' '[:lower:]')
        [[ -z "$entry" ]] && continue
        if [[ "$entry" == @* ]]; then
            [[ "$email" == *"$entry" ]] && return 0
        else
            [[ "$email" == "$entry" ]] && return 0
        fi
    done < <(_split_allowlist "$ALLOWED_EMAILS")
    return 1
}

# A number is allowed when its digits are a substring of an allowlisted
# number's digits: the page may print "(555) 010-1234" while the allowlist
# holds the full E.164 form "15550101234".
is_allowed_phone() {
    local digits entry entry_digits
    digits="${1//[^0-9]/}"
    [[ -z "$digits" || -z "$ALLOWED_PHONES" ]] && return 1
    while IFS= read -r entry; do
        entry_digits="${entry//[^0-9]/}"
        [[ -z "$entry_digits" ]] && continue
        [[ "$entry_digits" == *"$digits"* ]] && return 0
    done < <(_split_allowlist "$ALLOWED_PHONES")
    return 1
}

# ---- Check functions ----

# Report how the one response was obtained: the redirect chain, and any limit
# curl stopped at. Silent under a mock, where there is no request to describe.
check_response() {
    local rc="$_CACHE_RC"
    if [[ -n "$_CACHE_CHAIN" ]]; then
        log_pass "response: ${_CACHE_CHAIN} — final URL ${_CACHE_FINAL}; headers and body from this one GET (no HEAD sent)"
    fi
    case "$rc" in
        0) ;;
        28) log_warn "response" "request timed out after ${PAGE_MAX_TIME}s; results reflect a partial or missing response" ;;
        47) log_warn "response" "more than ${PAGE_MAX_REDIRS} redirects; the chain was not followed to a final page" ;;
        63) log_warn "response" "page is larger than $((PAGE_MAX_BYTES / 1048576)) MiB; content checks ran on a truncated body" ;;
        *)  log_warn "response" "request did not complete cleanly (curl exit ${rc})" ;;
    esac
}

check_headers() {
    local url="$1"
    local headers
    headers=$(fetch_headers "$url" | tr '[:upper:]' '[:lower:]')

    # Critical headers
    for hdr in "${CRITICAL_HEADERS[@]}"; do
        if echo "$headers" | grep -q "^${hdr}:"; then
            log_pass "security-headers: ${hdr} present"
        else
            log_crit "security-headers" "Missing critical header: ${hdr}"
        fi
    done

    # Advisory headers
    for hdr in "${WARN_HEADERS[@]}"; do
        if echo "$headers" | grep -q "^${hdr}:"; then
            log_pass "security-headers: ${hdr} present"
        else
            log_warn "security-headers" "Missing advisory header: ${hdr}"
        fi
    done
}

check_server_fingerprint() {
    local url="$1"
    local headers
    headers=$(fetch_headers "$url" | tr '[:upper:]' '[:lower:]')

    # Check X-Powered-By
    if echo "$headers" | grep -q "^x-powered-by:"; then
        local value
        value=$(_trim "$(echo "$headers" | grep "^x-powered-by:" | head -1 | cut -d: -f2-)")
        log_warn "fingerprint" "X-Powered-By header exposes: ${value}"
    fi

    # Check Server header for version numbers
    local server_header
    server_header=$(_trim "$(echo "$headers" | grep "^server:" | head -1 | cut -d: -f2-)")
    if [[ -n "$server_header" ]] && echo "$server_header" | grep -qE '[0-9]+\.[0-9]+'; then
        log_warn "fingerprint" "Server header exposes version: ${server_header}"
    fi
}

# Short fingerprint of a response body, so a report can show that two responses
# are the same without ever printing the (possibly secret) content.
_digest() {
    local d
    if command -v sha256sum >/dev/null 2>&1; then
        d=$(printf '%s' "$1" | sha256sum | cut -c1-12)
        printf 'sha256:%s' "$d"
    elif command -v shasum >/dev/null 2>&1; then
        d=$(printf '%s' "$1" | shasum -a 256 | cut -c1-12)
        printf 'sha256:%s' "$d"
    else
        d=$(printf '%s' "$1" | cksum | cut -d' ' -f1)
        printf 'cksum:%s' "$d"
    fi
}

# What real content looks like at each probed path. Sets:
#   RULE_SIG      extended regex (case-insensitive) that the real file's body
#                 matches; empty when the path has no text signature
#   RULE_ANYTYPE  1 when the signature is expected inside an HTML page (a login
#                 form, phpinfo output), 0 for a file that is never HTML
#   RULE_OPAQUE   1 for a binary artefact with no text signature; a non-HTML
#                 response is then taken as the file
_path_rule() {
    RULE_SIG="" RULE_ANYTYPE=0 RULE_OPAQUE=0
    case "$1" in
        .env|.env.local|.env.production)
            RULE_SIG='^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=' ;;
        .git/config)   RULE_SIG='^\[(core|remote|branch|user)[^]]*\]' ;;
        .git/HEAD)     RULE_SIG='^ref: refs/|^[0-9a-f]{40}$' ;;
        .gitignore)    RULE_SIG='^[!#/*.A-Za-z0-9_-][^<>]*$' ;;
        wp-config.php) RULE_SIG='DB_NAME|DB_PASSWORD|table_prefix|AUTH_KEY' ;;
        .htpasswd)     RULE_SIG='^[^:[:space:]<>]+:(\$|\{SHA\}|[./A-Za-z0-9]{13})' ;;
        .htaccess)     RULE_SIG='RewriteEngine|RewriteRule|AuthType|<IfModule|ErrorDocument|Require ' ;;
        db.sql|dump.sql)
            RULE_SIG='CREATE TABLE|INSERT INTO|DROP TABLE|MySQL dump|PostgreSQL database dump' ;;
        config.json)   RULE_SIG='^[[:space:]]*[{[]' ;;
        package.json)  RULE_SIG='"(name|version|dependencies|devDependencies|scripts)"[[:space:]]*:' ;;
        composer.json) RULE_SIG='"(name|require|autoload)"[[:space:]]*:' ;;
        config.yml|config.toml)
            RULE_SIG='^[A-Za-z0-9_.-]+[[:space:]]*[:=]|^\[[A-Za-z0-9_.-]+\]' ;;
        Gemfile)       RULE_SIG='^(source|gem|ruby|group)[[:space:]]' ;;
        Makefile)      RULE_SIG='^[A-Za-z0-9_.-]+[[:space:]]*:|^\.PHONY' ;;
        debug.log|error_log)
            RULE_SIG='\[(error|warn|notice)\]|PHP (Warning|Notice|Fatal)|^\[?[0-9]{4}-[0-9]{2}-[0-9]{2}' ;;
        phpinfo.php)   RULE_SIG='phpinfo\(\)|PHP Version'; RULE_ANYTYPE=1 ;;
        server-status) RULE_SIG='Apache Server Status|Server Version:'; RULE_ANYTYPE=1 ;;
        xmlrpc.php)    RULE_SIG='XML-RPC server accepts POST requests only'; RULE_ANYTYPE=1 ;;
        wp-login.php)  RULE_SIG='user_login|wp-submit'; RULE_ANYTYPE=1 ;;
        wp-admin|admin|login)
            RULE_SIG='type=["'"'"']?password'; RULE_ANYTYPE=1 ;;
        backup.zip|backup.tar.gz|.DS_Store) RULE_OPAQUE=1 ;;
    esac
}

_is_html_type() {
    [[ "$1" == text/html || "$1" == application/xhtml+xml ]]
}

# Two page bodies are "the same page" when they match once the path each was
# requested under is masked: a soft-404 that says "/foo was not found" would
# otherwise differ from the baseline in exactly the bytes we vary.
_mask_path() {
    local body="$1" path="$2"
    [[ -n "$path" ]] && body="${body//"$path"/@PATH@}"
    printf '%s' "$body"
}

# Classify the current PROBE_* against the baseline. Sets PROBE_VERDICT to one
# of: absent | redirect | restricted | catchall | exposed | inconclusive.
# Anything not proven to be the real file stays inconclusive; it is never
# promoted to exposed just because the status was 200.
classify_probe() {
    local path="$1"
    PROBE_VERDICT="absent"
    case "$PROBE_STATUS" in
        200) ;;
        3[0-9][0-9]) PROBE_VERDICT="redirect"; return ;;
        401|403|407|429|503) PROBE_VERDICT="restricted"; return ;;
        *) return ;;
    esac

    # Same status, media type and (path-masked) bytes as a path that cannot
    # exist: the site answers everything with one page.
    if [[ "$PROBE_BASELINE_STATUS" == "200" \
          && "$PROBE_CTYPE" == "$PROBE_BASELINE_CTYPE" \
          && "$PROBE_LARGE" == "$PROBE_BASELINE_LARGE" ]]; then
        if [[ "$(_mask_path "$PROBE_BODY" "$path")" \
              == "$(_mask_path "$PROBE_BASELINE_BODY" "$PROBE_BASELINE_TOKEN")" ]]; then
            PROBE_VERDICT="catchall"
            return
        fi
    fi

    _path_rule "$path"
    local html=false
    _is_html_type "$PROBE_CTYPE" && html=true

    if [[ "$PROBE_LARGE" == "1" ]]; then
        # Over the read limit: content cannot be inspected, but a large
        # non-HTML answer at one of these paths is not a page.
        if ! $html && [[ -n "$PROBE_CTYPE" ]]; then
            PROBE_VERDICT="exposed"
        else
            PROBE_VERDICT="inconclusive"
        fi
        return
    fi
    if [[ -n "$RULE_SIG" ]]; then
        if [[ "$RULE_ANYTYPE" == "1" ]] || ! $html; then
            if printf '%s\n' "$PROBE_BODY" | grep -Eiq -- "$RULE_SIG"; then
                PROBE_VERDICT="exposed"
                return
            fi
        fi
    elif [[ "$RULE_OPAQUE" == "1" ]] && ! $html && [[ -n "$PROBE_CTYPE" ]]; then
        PROBE_VERDICT="exposed"
        return
    fi
    PROBE_VERDICT="inconclusive"
}

PROBE_BASELINE_TOKEN="" PROBE_BASELINE_STATUS="" PROBE_BASELINE_CTYPE=""
PROBE_BASELINE_BODY="" PROBE_BASELINE_LARGE=0 PROBE_VERDICT=""

check_exposed_paths() {
    local url="$1" path
    local n_exposed=0 n_inconc=0 n_catchall=0 n_redirect=0 n_restricted=0

    # A path that cannot exist, fetched the same way as the real probes, shows
    # what the site says for "not found". If that is a 200 page, a 200 for
    # /.env proves nothing on its own.
    PROBE_BASELINE_TOKEN="audit-missing-$$-${RANDOM}${RANDOM}"
    fetch_path_probe "$url" "@baseline"
    PROBE_BASELINE_STATUS="$PROBE_STATUS"
    PROBE_BASELINE_CTYPE="$PROBE_CTYPE"
    PROBE_BASELINE_BODY="$PROBE_BODY"
    PROBE_BASELINE_LARGE="$PROBE_LARGE"

    for path in "${EXPOSED_PATHS[@]}"; do
        fetch_path_probe "$url" "$path"
        classify_probe "$path"
        local detail
        detail="${PROBE_CTYPE:-no content-type}, ${#PROBE_BODY} bytes, digest $(_digest "$PROBE_BODY")"
        case "$PROBE_VERDICT" in
            exposed)
                n_exposed=$((n_exposed + 1))
                log_crit "exposed-paths" "/${path} is publicly accessible (HTTP 200) — ${detail}"
                ;;
            inconclusive)
                n_inconc=$((n_inconc + 1))
                log_warn "exposed-paths" "/${path} returned HTTP 200 but the content is not confirmed as the file (${detail}) — inconclusive, check by hand"
                ;;
            catchall)  n_catchall=$((n_catchall + 1)) ;;
            redirect)  n_redirect=$((n_redirect + 1)) ;;
            restricted) n_restricted=$((n_restricted + 1)) ;;
        esac
    done

    local notes=()
    [[ "$n_catchall" -gt 0 ]] && notes+=("${n_catchall} matched the catch-all baseline and were not treated as exposures")
    [[ "$n_redirect" -gt 0 ]] && notes+=("${n_redirect} redirected")
    [[ "$n_restricted" -gt 0 ]] && notes+=("${n_restricted} restricted (401/403/429/503)")
    local suffix=""
    if [[ ${#notes[@]} -gt 0 ]]; then
        local IFS=';'
        suffix=" (${notes[*]})"
    fi
    log_pass "exposed-paths: probed ${#EXPOSED_PATHS[@]} sensitive paths${suffix}"
}

check_pii() {
    local url="$1"
    local html
    html=$(fetch_html "$url")

    # Email addresses (excluding common false positives)
    local emails
    emails=$(echo "$html" | grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
        | grep -viE '(example\.com|placeholder|noreply|no-reply|schema\.org|w3\.org|sitemaps\.org)' \
        || true)
    # Drop addresses the operator publishes on purpose
    if [[ -n "$emails" ]]; then
        local kept_emails="" e
        while IFS= read -r e; do
            [[ -z "$e" ]] && continue
            is_allowed_email "$e" && continue
            kept_emails+="${e}"$'\n'
        done <<< "$emails"
        emails=$(printf '%s' "$kept_emails" | sed '/^$/d')
    fi
    if [[ -n "$emails" ]]; then
        local email_list
        email_list=$(echo "$emails" | sort -u | head -5 | tr '\n' ', ' | sed 's/,$//')
        log_crit "pii" "email address(es) found in source: ${email_list}"
    fi

    # Phone numbers (US format)
    # First strip known non-phone numeric patterns (analytics IDs, ad IDs,
    # obfuscated-email payloads, build fingerprints, timestamps, CSS values).
    local stripped_html
    stripped_html=$(echo "$html" \
        | sed -E 's/data-cfemail="[0-9a-fA-F]+"//g' \
        | sed -E 's|/cdn-cgi/l/email-protection#[0-9a-fA-F]+||g' \
        | sed -E 's/ca-pub-[0-9]+//g' \
        | sed -E 's/G-[A-Z0-9]+//g' \
        | sed -E 's/UA-[0-9]+-[0-9]+//g' \
        | sed -E 's/[0-9]{13,}//g' \
        | sed -E 's/#[0-9a-fA-F]{6,8}//g' \
        | sed -E 's/[0-9]+px//g' \
        | sed -E 's/[0-9]+\.[0-9]+\.[0-9]+//g' \
        | sed -E 's/_hu_[0-9a-f]+//g' \
        | sed -E 's/\.[a-f0-9]{8,}\.(css|js|webp|png|jpg|jpeg|woff2)//g' \
    )
    local phones
    phones=$(echo "$stripped_html" | grep -oE '(\([0-9]{3}\)[[:space:]]*[0-9]{3}[-.]?[0-9]{4}|[0-9]{3}[-.]?[0-9]{3}[-.]?[0-9]{4})' \
        | grep -vE '^0123456789' \
        || true)
    # Drop matches that are (fragments of) a published business number
    if [[ -n "$phones" ]]; then
        local kept="" p
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue
            is_allowed_phone "$p" && continue
            kept+="${p}"$'\n'
        done <<< "$phones"
        phones=$(printf '%s' "$kept" | sed '/^$/d')
    fi
    if [[ -n "$phones" ]]; then
        local phone_list
        phone_list=$(echo "$phones" | sort -u | head -3 | tr '\n' ', ' | sed 's/,$//')
        log_warn "pii" "phone number(s) found in source: ${phone_list}"
    fi
}

check_js_secrets() {
    local url="$1"
    local html
    html=$(fetch_html "$url")

    # Strip allowlisted patterns first
    local filtered="$html"
    for pattern in "${ALLOWLIST_PATTERNS[@]}"; do
        filtered=$(echo "$filtered" | sed -E "s/${pattern}/__ALLOWED__/g")
    done

    # Check for secret patterns
    for pattern in "${SECRET_PATTERNS[@]}"; do
        local matches
        matches=$(echo "$filtered" | grep -oE "$pattern" || true)
        if [[ -n "$matches" ]]; then
            local first_match
            first_match=$(echo "$matches" | head -1)
            # Redact the middle of the secret
            local redacted="${first_match:0:8}...${first_match: -4}"
            log_crit "js-secrets" "Potential secret found matching pattern: ${redacted}"
        fi
    done

    # Generic dangerous assignments (only in <script> blocks)
    local script_content
    script_content=$(echo "$html" | sed -n '/<script/,/<\/script>/p')

    # Check for password/secret/apiSecret assignments. Both quote styles are
    # matched — single quotes are the more common JS convention, and a class
    # written as ["\x27] silently misses them.
    local cred_re="(password|apiSecret|api_secret|secretKey|secret_key)[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"
    if echo "$script_content" | grep -qiE "$cred_re"; then
        local match key
        match=$(echo "$script_content" | grep -oiE "$cred_re" | head -1)
        # Report the key, never the value: this line lands in CI logs.
        key=$(printf '%s' "$match" | grep -oiE '^[a-z_]+')
        log_crit "js-secrets" "Hardcoded credential assignment for key: ${key} (value redacted)"
    fi
}

check_generator_tag() {
    local url="$1"
    local html
    html=$(fetch_html "$url")

    local generator
    generator=$(echo "$html" | grep -oiE "<meta[^>]*name=[\"']?generator[\"']?[^>]*content=[\"']?[^\"'>]*" | head -1 || true)
    if [[ -n "$generator" ]]; then
        log_warn "generator" "Generator meta tag exposes build tool: ${generator}"
    fi
}

check_ssl() {
    local url="$1"
    local host
    host=$(echo "$url" | sed -E 's|https?://||' | cut -d/ -f1)

    local ssl_info
    ssl_info=$(fetch_ssl "$host")

    if [[ -z "$ssl_info" ]]; then
        log_crit "ssl" "Could not retrieve SSL certificate"
        return
    fi

    local not_after
    not_after=$(echo "$ssl_info" | grep "notAfter=" | cut -d= -f2-)
    if [[ -z "$not_after" ]]; then
        log_crit "ssl" "Could not parse SSL certificate expiry"
        return
    fi

    log_pass "ssl: certificate present, expires ${not_after}"

    # Check if expiring within 30 days
    local expiry_epoch now_epoch days_left
    expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo "0")
    now_epoch=$(date +%s)

    if [[ "$expiry_epoch" -gt 0 ]]; then
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        if [[ "$days_left" -lt 0 ]]; then
            log_crit "ssl" "Certificate EXPIRED ${days_left} days ago!"
        elif [[ "$days_left" -lt 30 ]]; then
            log_warn "ssl" "Certificate expires in ${days_left} days (< 30 day threshold)"
        else
            log_pass "ssl: ${days_left} days until expiry"
        fi
    fi
}

check_internal_ips() {
    local url="$1"
    local html
    html=$(fetch_html "$url")

    for pattern in "${INTERNAL_IP_PATTERNS[@]}"; do
        local matches
        matches=$(echo "$html" | grep -oE "$pattern" | sort -u || true)
        if [[ -n "$matches" ]]; then
            local ip_list
            ip_list=$(echo "$matches" | tr '\n' ', ' | sed 's/,$//')
            log_warn "internal-ip" "Internal IP address(es) found: ${ip_list}"
        fi
    done
}

# ---- Report generation ----
# Findings come from the audited site (header values, page content), so they are
# untrusted input. They are streamed to python3 on stdin and the scalars go
# through the environment — never interpolated into the program text, where a
# quote or a backslash in a server banner could rewrite the report.
generate_json_report() {
    local url="$1"
    local status="PASS"
    [[ "$WARNINGS" -gt 0 ]] && status="WARN"
    [[ "$CRITICALS" -gt 0 ]] && status="FAIL"

    local total_checks
    total_checks=$(( ${#CRITICAL_HEADERS[@]} + ${#WARN_HEADERS[@]} + ${#EXPOSED_PATHS[@]} + 5 ))

    printf '%s\n' ${FINDINGS[@]+"${FINDINGS[@]}"} \
    | SA_URL="$url" \
      SA_VERSION="$VERSION" \
      SA_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      SA_STATUS="$status" \
      SA_CRITICALS="$CRITICALS" \
      SA_WARNINGS="$WARNINGS" \
      SA_TOTAL="$total_checks" \
      python3 -c '
import json, os, sys

findings = []
for line in sys.stdin.read().split("\n"):
    if not line.strip():
        continue
    parts = line.split("|", 2)
    if len(parts) < 3:
        continue
    findings.append({
        "severity": parts[0],
        "category": parts[1],
        "message": parts[2],
    })

report = {
    "url": os.environ["SA_URL"],
    "version": os.environ["SA_VERSION"],
    "timestamp": os.environ["SA_TIMESTAMP"],
    "summary": {
        "status": os.environ["SA_STATUS"],
        "criticals": int(os.environ["SA_CRITICALS"]),
        "warnings": int(os.environ["SA_WARNINGS"]),
        "total_checks": int(os.environ["SA_TOTAL"]),
    },
    "findings": findings,
}
print(json.dumps(report, indent=2))
'
}

# ---- Audit runner ----
run_audit() {
    local url="$1"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Security Audit: ${url}"
    echo "  Version: ${VERSION} | $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Reset counters for this URL
    CRITICALS=0
    WARNINGS=0
    FINDINGS=()

    prime_response_cache "$url"

    echo "── Response ──"
    check_response

    echo ""
    echo "── Security Headers ──"
    check_headers "$url"
    check_server_fingerprint "$url"

    echo ""
    echo "── Exposed Paths ──"
    check_exposed_paths "$url"

    echo ""
    echo "── Content Analysis ──"
    check_pii "$url"
    check_js_secrets "$url"
    check_generator_tag "$url"
    check_internal_ips "$url"

    echo ""
    echo "── SSL/TLS ──"
    check_ssl "$url"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [[ "$CRITICALS" -gt 0 ]]; then
        echo "  RESULT: FAIL — ${CRITICALS} critical, ${WARNINGS} warnings"
    elif [[ "$WARNINGS" -gt 0 ]]; then
        echo "  RESULT: WARN — ${WARNINGS} warnings (no criticals)"
    else
        echo "  RESULT: PASS — all checks passed"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# ---- Main ----
usage() {
    cat <<EOF
Usage: security-audit.sh [OPTIONS] <url> [url2] [url3...]

Production security audit for static sites.
Checks headers, exposed paths, PII, secrets, SSL, and more.

Options:
  --help        Show this help
  --json        Output JSON report (single URL only)
  --test-mode   Accepted for compatibility; mocks activate from the MOCK_*
                environment variables whether or not this flag is passed
  --version     Show version

Exit codes:
  0  All checks passed
  1  Critical issue(s) found — blocks deploy
  2  Warnings only — deploy proceeds with notice

Environment (allowlists):
  SECURITY_AUDIT_ALLOWED_EMAILS  Published addresses, e.g. "hi@site.com,@site.com"
  SECURITY_AUDIT_ALLOWED_PHONES  Published numbers, e.g. "15550101234"

Environment (test mode):
  MOCK_HEADERS         Mock file for the response headers
  MOCK_HTML            Mock file for page HTML
  MOCK_SSL             Mock file for SSL cert info
  MOCK_PATH_STATUS     Fixed HTTP status for all path probes
  MOCK_PATH_RESPONSES  File with "path:status[:body-file[:content-type]]" lines

Examples:
  ./security-audit.sh https://example.com
  ./security-audit.sh --json https://example.com
  ./security-audit.sh https://one.example https://two.example
  SECURITY_AUDIT_ALLOWED_EMAILS=hello@example.com ./security-audit.sh https://example.com

Version: ${VERSION}
EOF
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help)
                usage
                exit 0
                ;;
            --version)
                echo "security-audit ${VERSION}"
                exit 0
                ;;
            --json)
                JSON_MODE=true
                shift
                ;;
            --test-mode)
                # shellcheck disable=SC2034  # accepted for compatibility; mocks are env-driven
                TEST_MODE=true
                shift
                ;;
            -*)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
            *)
                URLS+=("$1")
                shift
                ;;
        esac
    done

    if [[ ${#URLS[@]} -eq 0 ]]; then
        echo "Error: No URL provided." >&2
        echo "" >&2
        usage >&2
        exit 1
    fi

    SCRATCH=$(mktemp -d) || { echo "Error: cannot create a scratch directory." >&2; exit 1; }
    trap 'rm -rf "$SCRATCH"' EXIT

    # Track worst exit code across all URLs. Severity order is 1 (critical) >
    # 2 (warning) > 0 (clean) — deliberately not numeric order, so a later
    # clean URL can never mask an earlier warning.
    local worst_exit=0

    for url in "${URLS[@]}"; do
        if $JSON_MODE; then
            # JSON mode: run audit (suppressed), then output JSON
            run_audit "$url" >/dev/null 2>&1 || true
            generate_json_report "$url"
        else
            run_audit "$url"
        fi

        # Determine exit code for this URL
        local this_exit=0
        if [[ "$CRITICALS" -gt 0 ]]; then
            this_exit=1
        elif [[ "$WARNINGS" -gt 0 ]]; then
            this_exit=2
        fi

        if [[ "$this_exit" -eq 1 ]]; then
            worst_exit=1
        elif [[ "$this_exit" -eq 2 && "$worst_exit" -eq 0 ]]; then
            worst_exit=2
        fi
    done

    exit "$worst_exit"
}

main "$@"
