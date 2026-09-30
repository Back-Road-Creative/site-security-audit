#!/usr/bin/env bash
# =============================================================================
# run-tests.sh — test suite for security-audit.sh
#
# Plain bash, no test framework to install: the thing under test is a
# zero-dependency script, and the suite stays that way too.
#
#   ./tests/run-tests.sh            run everything
#   ./tests/run-tests.sh pii        run only tests whose name contains "pii"
#
# Set AUDIT_SCRIPT to point the suite at a different copy of the script — handy
# for checking whether a vendored or older copy still has every behaviour.
#
# Output is TAP-ish: one "ok N - name" or "not ok N - name" per test, then a
# summary. Exit 0 when every test passed, 1 otherwise.
# =============================================================================
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${TESTS_DIR}/.." && pwd)"
AUDIT="${AUDIT_SCRIPT:-${ROOT_DIR}/security-audit.sh}"
FIX="${TESTS_DIR}/fixtures"
STUBS="${TESTS_DIR}/stubs"
TMP="$(mktemp -d)"
FILTER="${1:-}"

trap 'rm -rf "$TMP"' EXIT

TOTAL=0
PASSED=0
FAILED=0
FAILURES=()

# ---- Harness ---------------------------------------------------------------

# Runs the auditor with clean defaults; per-test overrides come from the
# environment of the caller. Captures stdout+stderr in OUT and the status in
# STATUS.
OUT=""
STATUS=0
audit() {
    OUT=$(
        MOCK_HEADERS="${M_HEADERS:-$FIX/headers-good.txt}" \
        MOCK_HTML="${M_HTML:-$FIX/html-clean.txt}" \
        MOCK_SSL="${M_SSL:-$FIX/ssl-valid.txt}" \
        MOCK_PATH_STATUS="${M_PATH_STATUS-404}" \
        MOCK_PATH_RESPONSES="${M_PATH_RESPONSES:-}" \
        SECURITY_AUDIT_ALLOWED_EMAILS="${M_ALLOW_EMAILS:-}" \
        SECURITY_AUDIT_ALLOWED_PHONES="${M_ALLOW_PHONES:-}" \
        bash "$AUDIT" "$@" 2>&1
    )
    STATUS=$?
}

reset_env() {
    unset M_HEADERS M_HTML M_SSL M_PATH_STATUS M_PATH_RESPONSES \
          M_ALLOW_EMAILS M_ALLOW_PHONES
}

_fail_reason=""

expect_status() {
    if [[ "$STATUS" != "$1" ]]; then
        _fail_reason="expected exit $1, got $STATUS"
        return 1
    fi
}

expect_contains() {
    if [[ "$OUT" != *"$1"* ]]; then
        _fail_reason="expected output to contain: $1"
        return 1
    fi
}

expect_not_contains() {
    if [[ "$OUT" == *"$1"* ]]; then
        _fail_reason="expected output NOT to contain: $1"
        return 1
    fi
}

# Runs the auditor against the curl stub with no MOCK_HEADERS/MOCK_HTML, so
# every request goes through the script's real curl invocations. The stub
# records each one in $1. Usage: run_stubbed <log> <url> [VAR=value ...]
run_stubbed() {
    local log="$1" url="$2"
    shift 2
    : > "$log"
    OUT=$(
        env PATH="$STUBS:$PATH" \
            CURL_LOG="$log" \
            STUB_HEADERS="$FIX/headers-good.txt" \
            STUB_HTML="$FIX/html-clean.txt" \
            MOCK_SSL="$FIX/ssl-valid.txt" \
            "$@" \
            bash "$AUDIT" "$url" 2>&1
    )
    STATUS=$?
}

# Every test is a function named test_<something>; `it` runs one.
it() {
    local name="$1" fn="$2"
    if [[ -n "$FILTER" && "$name" != *"$FILTER"* ]]; then
        return 0
    fi
    TOTAL=$((TOTAL + 1))
    reset_env
    _fail_reason=""
    OUT=""
    STATUS=0
    if "$fn"; then
        PASSED=$((PASSED + 1))
        echo "ok ${TOTAL} - ${name}"
    else
        FAILED=$((FAILED + 1))
        echo "not ok ${TOTAL} - ${name}"
        echo "#   ${_fail_reason:-assertion failed}"
        FAILURES+=("${name}: ${_fail_reason:-assertion failed}")
    fi
}

# Writes an openssl-style cert fixture whose expiry is N days from now, so the
# "expiring soon" threshold can be tested without a fixture that rots.
make_cert() {
    local days="$1" out="$2" not_after
    not_after=$(date -u -d "${days} days" "+%b %e %H:%M:%S %Y GMT" 2>/dev/null) \
        || not_after=$(date -u -v"${days}d" "+%b %e %H:%M:%S %Y GMT" 2>/dev/null) \
        || { echo "cannot compute a relative date on this platform" >&2; return 1; }
    {
        echo "notBefore=Jan  1 00:00:00 2020 GMT"
        echo "notAfter=${not_after}"
        echo "issuer=C = US, O = Example CA, CN = Example Root"
        echo "subject=CN = example.com"
    } > "$out"
}

# ---- CLI -------------------------------------------------------------------

test_help_exits_zero() {
    audit --help || true
    expect_status 0 && expect_contains "Usage: security-audit.sh"
}

test_version_exits_zero() {
    audit --version || true
    expect_status 0 && expect_contains "security-audit "
}

test_no_url_is_an_error() {
    audit || true
    expect_status 1 && expect_contains "Error: No URL provided."
}

test_unknown_option_is_an_error() {
    audit --bogus https://example.com || true
    expect_status 1 && expect_contains "Unknown option: --bogus"
}

test_test_mode_flag_is_accepted() {
    audit --test-mode https://example.com || true
    expect_status 0 && expect_contains "RESULT: PASS"
}

# ---- Headers ---------------------------------------------------------------

test_all_headers_present_passes() {
    audit https://example.com || true
    expect_status 0 \
        && expect_contains "content-security-policy present" \
        && expect_contains "RESULT: PASS"
}

test_missing_critical_header_is_critical() {
    M_HEADERS="$FIX/headers-missing-csp.txt"
    audit https://example.com || true
    expect_status 1 \
        && expect_contains "[CRITICAL] security-headers: Missing critical header: content-security-policy" \
        && expect_contains "RESULT: FAIL"
}

test_missing_advisory_header_is_warning_only() {
    M_HEADERS="$FIX/headers-no-advisory.txt"
    audit https://example.com || true
    expect_status 2 \
        && expect_contains "Missing advisory header: referrer-policy" \
        && expect_contains "Missing advisory header: permissions-policy" \
        && expect_contains "RESULT: WARN"
}

test_server_fingerprint_is_warned() {
    M_HEADERS="$FIX/headers-fingerprint.txt"
    audit https://example.com || true
    expect_status 2 \
        && expect_contains "X-Powered-By header exposes: php/8.2.4" \
        && expect_contains "Server header exposes version: nginx/1.24.0"
}

# ---- Exposed paths ---------------------------------------------------------

test_exposed_path_is_critical() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-exposed.txt"
    audit https://example.com || true
    expect_status 1 \
        && expect_contains "/.env is publicly accessible (HTTP 200)" \
        && expect_contains "/.git/config is publicly accessible (HTTP 200)"
}

test_clean_paths_produce_no_finding() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-clean.txt"
    audit https://example.com || true
    expect_status 0 && expect_contains "probed 30 sensitive paths"
}

test_path_probe_is_cache_busted() {
    # No path mock: probes fall through to the stubbed curl, which records the
    # URLs it was asked for. A CDN edge can serve a stale 200 for a path the
    # deploy just deleted, so every probe carries a unique query string.
    local log="$TMP/curl-cachebust.log"
    : > "$log"
    OUT=$(
        PATH="$STUBS:$PATH" \
        CURL_LOG="$log" \
        STUB_PATH_STATUS=404 \
        MOCK_HEADERS="$FIX/headers-good.txt" \
        MOCK_HTML="$FIX/html-clean.txt" \
        MOCK_SSL="$FIX/ssl-valid.txt" \
        bash "$AUDIT" https://example.com 2>&1
    )
    STATUS=$?
    if ! grep -q 'audit_cb=' "$log"; then
        _fail_reason="no probe carried a cache-busting query: $(head -3 "$log")"
        return 1
    fi
    if ! grep -q 'example.com/.env?audit_cb=' "$log"; then
        _fail_reason="the .env probe was not cache-busted"
        return 1
    fi
    expect_status 0
}

test_soft404_catchall_is_not_critical() {
    # The site answers every path with the same 200 "not found" page. Judging
    # by status alone reports five critical exposures on a clean site.
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-catchall.txt"
    audit https://example.com || true
    expect_status 0 \
        && expect_not_contains "publicly accessible" \
        && expect_contains "4 matched the catch-all baseline"
}

test_generic_html_at_a_sensitive_path_is_inconclusive() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-generic-html.txt"
    audit https://example.com || true
    expect_status 2 \
        && expect_not_contains "publicly accessible" \
        && expect_contains "/.env returned HTTP 200 but the content is not confirmed" \
        && expect_contains "inconclusive"
}

test_true_file_content_is_detected() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-signatures.txt"
    audit https://example.com || true
    expect_status 1 \
        && expect_contains "/.env is publicly accessible (HTTP 200)" \
        && expect_contains "/.git/config is publicly accessible (HTTP 200)" \
        && expect_contains "/.git/HEAD is publicly accessible (HTTP 200)" \
        && expect_contains "/db.sql is publicly accessible (HTTP 200)" \
        && expect_contains "/backup.zip is publicly accessible (HTTP 200)" \
        && expect_contains "/admin is publicly accessible (HTTP 200)"
}

test_redirect_auth_and_challenge_are_distinct_from_exposure() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-redirect-auth.txt"
    audit https://example.com || true
    expect_status 0 \
        && expect_not_contains "publicly accessible" \
        && expect_contains "1 redirected" \
        && expect_contains "3 restricted"
}

test_exposure_report_carries_a_digest_not_the_body() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-exposed.txt"
    audit https://example.com || true
    expect_contains "digest " \
        && expect_contains "text/plain" \
        && expect_not_contains "db.invalid" \
        && expect_not_contains "APP_ENV"
}

test_json_exposure_finding_has_no_body() {
    M_PATH_STATUS=""
    M_PATH_RESPONSES="$FIX/paths-exposed.txt"
    audit --json https://example.com || true
    expect_contains "publicly accessible" && expect_not_contains "db.invalid"
}

test_path_probes_carry_a_random_missing_path_baseline() {
    local log="$TMP/curl-baseline.log"
    run_stubbed "$log" https://example.com STUB_PATH_STATUS=404
    local n
    n=$(grep -c 'example.com/audit-missing-' "$log" || true)
    if [[ "$n" -ne 1 ]]; then
        _fail_reason="expected 1 baseline probe, got ${n}"
        return 1
    fi
    if ! grep 'example.com/audit-missing-' "$log" | grep -q 'audit_cb='; then
        _fail_reason="the baseline probe was not cache-busted"
        return 1
    fi
    expect_status 0
}

test_path_probes_are_size_and_time_bounded() {
    local log="$TMP/curl-bounds.log"
    run_stubbed "$log" https://example.com STUB_PATH_STATUS=404
    local unbounded
    unbounded=$(grep 'audit_cb=' "$log" | grep -vc -- '--max-filesize' || true)
    if [[ "$unbounded" -ne 0 ]]; then
        _fail_reason="${unbounded} probe request(s) had no --max-filesize"
        return 1
    fi
    if grep 'audit_cb=' "$log" | grep -vq -- '--max-time 5'; then
        _fail_reason="a probe request had no --max-time 5"
        return 1
    fi
    # Probes never follow redirects: a 3xx is reported as a redirect.
    if grep 'audit_cb=' "$log" | grep -q -- ' -L'; then
        _fail_reason="a probe request followed redirects"
        return 1
    fi
    expect_status 0
}

test_soft404_that_echoes_the_path_is_not_critical() {
    # The baseline page names the random path it was asked for, so its bytes
    # differ from the probe's; the comparison must ignore the echoed path.
    local map="$TMP/echo404.paths"
    {
        echo "@baseline:200:$FIX/body-echo404.html:text/html"
        echo ".env:200:$FIX/body-echo404.html:text/html"
        echo "admin:200:$FIX/body-echo404.html:text/html"
    } > "$map"
    run_stubbed "$TMP/curl-echo.log" https://example.com STUB_PATHS="$map"
    expect_status 0 \
        && expect_not_contains "publicly accessible" \
        && expect_contains "2 matched the catch-all baseline"
}

test_true_file_is_detected_through_the_real_request_path() {
    local map="$TMP/real.paths"
    {
        echo "@baseline:404"
        echo ".env:200:$FIX/body-env.txt:text/plain"
    } > "$map"
    run_stubbed "$TMP/curl-real.log" https://example.com STUB_PATHS="$map"
    expect_status 1 \
        && expect_contains "/.env is publicly accessible (HTTP 200)" \
        && expect_not_contains "db.invalid"
}

test_oversize_probe_answer_is_judged_by_type_not_content() {
    # curl stops at --max-filesize (exit 63) so the body cannot be inspected.
    # A large non-HTML answer at a sensitive path is reported; a large HTML
    # page is only inconclusive.
    local map="$TMP/large.paths"
    {
        echo "@baseline:404"
        echo "db.sql:200::application/sql:large"
        echo "admin:200::text/html:large"
    } > "$map"
    run_stubbed "$TMP/curl-large.log" https://example.com STUB_PATHS="$map"
    expect_status 1 \
        && expect_contains "/db.sql is publicly accessible (HTTP 200)" \
        && expect_not_contains "/admin is publicly accessible" \
        && expect_contains "/admin returned HTTP 200 but the content is not confirmed"
}

# ---- PII -------------------------------------------------------------------

test_email_in_source_is_critical() {
    M_HTML="$FIX/html-email.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "[CRITICAL] pii: email address(es) found in source: hello@testsite.invalid"
}

test_allowlisted_email_is_not_reported() {
    M_HTML="$FIX/html-email.txt"
    M_ALLOW_EMAILS="hello@testsite.invalid"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "email address(es) found"
}

test_allowlisted_email_domain_is_not_reported() {
    M_HTML="$FIX/html-email.txt"
    M_ALLOW_EMAILS="@testsite.invalid"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "email address(es) found"
}

test_example_com_email_is_never_reported() {
    printf '<p>%s</p>\n' 'a@example.com' > "$TMP/html-example-email.txt"
    M_HTML="$TMP/html-example-email.txt"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "email address(es) found"
}

test_phone_in_source_is_a_warning() {
    M_HTML="$FIX/html-phone.txt"
    audit https://example.com || true
    expect_status 2 && expect_contains "[WARN]  pii: phone number(s) found in source"
}

test_allowlisted_phone_is_not_reported() {
    M_HTML="$FIX/html-phone.txt"
    M_ALLOW_PHONES="12025550143"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "phone number(s) found"
}

test_allowlisted_phone_list_is_split_on_commas() {
    M_HTML="$FIX/html-phone.txt"
    M_ALLOW_PHONES="15550100000, 12025550143"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "phone number(s) found"
}

test_hugo_image_fingerprint_is_not_a_phone() {
    M_HTML="$FIX/html-hugo-fingerprint.txt"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "phone number(s) found"
}

test_hashed_asset_filename_is_not_a_phone() {
    M_HTML="$FIX/html-asset-hash.txt"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "phone number(s) found"
}

test_cf_email_obfuscation_attribute_is_not_a_phone() {
    M_HTML="$FIX/html-cfemail.txt"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "phone number(s) found"
}

test_cf_email_protection_link_is_not_a_phone() {
    M_HTML="$FIX/html-cfemail-link.txt"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "phone number(s) found"
}

# ---- Secrets ---------------------------------------------------------------

test_secret_patterns_are_critical() {
    M_HTML="$FIX/html-secrets.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "[CRITICAL] js-secrets: Potential secret found matching pattern:"
}

test_secret_value_is_redacted_in_output() {
    M_HTML="$FIX/html-secrets.txt"
    audit https://example.com || true
    expect_status 1 \
        && expect_contains "..." \
        && expect_not_contains "ghp_abcdefghijabcdefghijabcdefghijabcdef"
}

test_analytics_ids_are_not_secrets() {
    M_HTML="$FIX/html-analytics.txt"
    audit https://example.com || true
    expect_status 0 && expect_not_contains "js-secrets"
}

test_double_quoted_credential_assignment_is_critical() {
    M_HTML="$FIX/html-password-doublequote.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "Hardcoded credential assignment for key: secret_key"
}

test_single_quoted_credential_assignment_is_critical() {
    # Single quotes are the common JS convention; a character class written as
    # ["\x27] matches a literal backslash and the letter x instead, and lets
    # every single-quoted credential through.
    M_HTML="$FIX/html-password-singlequote.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "Hardcoded credential assignment for key: password"
}

test_credential_value_is_not_echoed() {
    M_HTML="$FIX/html-password-singlequote.txt"
    audit https://example.com || true
    expect_contains "(value redacted)" && expect_not_contains "notarealsecret"
}

# ---- Generator / internal IPs ---------------------------------------------

test_generator_tag_is_a_warning() {
    M_HTML="$FIX/html-generator.txt"
    audit https://example.com || true
    expect_status 2 && expect_contains "Generator meta tag exposes build tool:"
}

test_single_quoted_generator_tag_is_a_warning() {
    M_HTML="$FIX/html-generator-singlequote.txt"
    audit https://example.com || true
    expect_status 2 && expect_contains "Generator meta tag exposes build tool:"
}

test_internal_ips_are_warned() {
    M_HTML="$FIX/html-internal-ip.txt"
    audit https://example.com || true
    expect_status 2 \
        && expect_contains "Internal IP address(es) found: 192.168.1.50" \
        && expect_contains "Internal IP address(es) found: 10.0.0.7"
}

# ---- SSL -------------------------------------------------------------------

test_valid_certificate_passes() {
    audit https://example.com || true
    expect_status 0 && expect_contains "ssl: certificate present, expires"
}

test_expiring_certificate_is_a_warning() {
    make_cert 10 "$TMP/ssl-expiring.txt" || return 1
    M_SSL="$TMP/ssl-expiring.txt"
    audit https://example.com || true
    expect_status 2 && expect_contains "< 30 day threshold"
}

test_expired_certificate_is_critical() {
    make_cert -5 "$TMP/ssl-expired.txt" || return 1
    M_SSL="$TMP/ssl-expired.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "Certificate EXPIRED"
}

test_unreachable_certificate_is_critical() {
    M_SSL="$FIX/ssl-empty.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "Could not retrieve SSL certificate"
}

test_unparseable_certificate_is_critical() {
    M_SSL="$FIX/ssl-no-expiry.txt"
    audit https://example.com || true
    expect_status 1 && expect_contains "Could not parse SSL certificate expiry"
}

# ---- JSON report -----------------------------------------------------------

test_json_report_is_valid_json() {
    audit --json https://example.com || true
    if ! printf '%s' "$OUT" | python3 -m json.tool >/dev/null 2>&1; then
        _fail_reason="output is not valid JSON: ${OUT:0:200}"
        return 1
    fi
    expect_status 0
}

test_json_report_summarises_a_clean_run() {
    audit --json https://example.com || true
    local status
    status=$(printf '%s' "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["summary"]["status"])')
    if [[ "$status" != "PASS" ]]; then
        _fail_reason="expected summary.status PASS, got ${status}"
        return 1
    fi
    expect_status 0
}

test_json_report_lists_findings() {
    M_HEADERS="$FIX/headers-missing-csp.txt"
    audit --json https://example.com || true
    local n
    n=$(printf '%s' "$OUT" | python3 -c '
import json, sys
r = json.load(sys.stdin)
crit = [f for f in r["findings"] if f["severity"] == "CRITICAL"]
assert r["summary"]["status"] == "FAIL", r["summary"]
assert r["summary"]["criticals"] == len(crit), r["summary"]
print(len(crit))
') || { _fail_reason="JSON did not describe the critical finding: ${OUT:0:200}"; return 1; }
    if [[ "$n" -lt 1 ]]; then
        _fail_reason="expected at least one critical finding in JSON, got ${n}"
        return 1
    fi
    expect_status 1
}

test_json_report_survives_hostile_header_values() {
    # Finding text is attacker-influenced (it quotes server banners). Quotes,
    # backslashes and Python triple-quotes must not be able to rewrite the
    # report or break the parse.
    M_HEADERS="$FIX/headers-quote-injection.txt"
    audit --json https://example.com || true
    local msg
    msg=$(printf '%s' "$OUT" | python3 -c '
import json, sys
r = json.load(sys.stdin)
print([f["message"] for f in r["findings"] if f["category"] == "fingerprint"][0])
') || { _fail_reason="hostile header broke the JSON report: ${OUT:0:300}"; return 1; }
    if [[ "$msg" != *'"quoted"'* || "$msg" != *"'''triple'''"* ]]; then
        _fail_reason="hostile header value was mangled: ${msg}"
        return 1
    fi
    return 0
}

# ---- Multi-URL exit codes --------------------------------------------------

test_multi_url_keeps_the_worst_result() {
    M_HEADERS="$FIX/headers-no-advisory.txt"
    audit https://one.example https://two.example || true
    expect_status 2
}

test_a_clean_url_cannot_mask_an_earlier_warning() {
    # Severity order is 1 > 2 > 0, not numeric order. Comparing exit codes with
    # -lt lets a clean second site overwrite the first site's WARN with PASS,
    # and the run reports green while a site is missing headers.
    local map="$TMP/map-warn-then-clean"
    mkdir -p "$map"
    cp "$FIX/headers-no-advisory.txt" "$map/one.example.headers"
    cp "$FIX/headers-good.txt"        "$map/two.example.headers"
    cp "$FIX/html-clean.txt"          "$map/one.example.html"
    cp "$FIX/html-clean.txt"          "$map/two.example.html"
    OUT=$(
        PATH="$STUBS:$PATH" \
        CURL_LOG="$TMP/curl-multi.log" \
        STUB_MAP="$map" \
        STUB_PATH_STATUS=404 \
        MOCK_SSL="$FIX/ssl-valid.txt" \
        bash "$AUDIT" https://one.example https://two.example 2>&1
    )
    STATUS=$?
    expect_status 2 \
        && expect_contains "Missing advisory header: referrer-policy"
}

test_multi_url_critical_wins() {
    M_HEADERS="$FIX/headers-missing-csp.txt"
    audit https://one.example https://two.example || true
    expect_status 1
}

test_multi_url_all_clean_exits_zero() {
    audit https://one.example https://two.example || true
    expect_status 0 && expect_contains "https://two.example"
}

test_counters_reset_between_urls() {
    M_HEADERS="$FIX/headers-no-advisory.txt"
    audit https://one.example https://two.example || true
    # Two advisory headers missing per URL; the second report must say 2, not 4.
    expect_contains "RESULT: WARN — 2 warnings (no criticals)" \
        && expect_not_contains "4 warnings"
}

# ---- Request economy -------------------------------------------------------

test_page_body_is_fetched_once_per_url() {
    # Four content checks share one response. Fetching per check means four
    # full page downloads against a site we just deployed to.
    local log="$TMP/curl-count.log"
    : > "$log"
    OUT=$(
        PATH="$STUBS:$PATH" \
        CURL_LOG="$log" \
        STUB_HEADERS="$FIX/headers-good.txt" \
        STUB_HTML="$FIX/html-clean.txt" \
        STUB_PATH_STATUS=404 \
        MOCK_SSL="$FIX/ssl-valid.txt" \
        bash "$AUDIT" https://example.com 2>&1
    )
    STATUS=$?
    local bodies heads
    bodies=$(grep -c -- '--max-time 15' "$log" || true)
    heads=$(grep -c -- '-sI' "$log" || true)
    if [[ "$bodies" -ne 1 ]]; then
        _fail_reason="expected 1 page-body request, got ${bodies}"
        return 1
    fi
    if [[ "$heads" -ne 1 ]]; then
        _fail_reason="expected 1 header request, got ${heads}"
        return 1
    fi
    expect_status 0
}

# ---- Registry --------------------------------------------------------------

main() {
    echo "# security-audit.sh test suite"
    echo "# script: ${AUDIT}"
    echo ""

    it "cli: --help exits 0"                              test_help_exits_zero
    it "cli: --version exits 0"                           test_version_exits_zero
    it "cli: missing url is an error"                     test_no_url_is_an_error
    it "cli: unknown option is an error"                  test_unknown_option_is_an_error
    it "cli: --test-mode is accepted"                     test_test_mode_flag_is_accepted

    it "headers: all present passes"                      test_all_headers_present_passes
    it "headers: missing critical header fails"           test_missing_critical_header_is_critical
    it "headers: missing advisory header warns"           test_missing_advisory_header_is_warning_only
    it "headers: server fingerprint warns"                test_server_fingerprint_is_warned

    it "paths: exposed path is critical"                  test_exposed_path_is_critical
    it "paths: clean probe produces no finding"           test_clean_paths_produce_no_finding
    it "paths: probes are cache-busted"                   test_path_probe_is_cache_busted
    it "paths: soft-404 catch-all is not critical"        test_soft404_catchall_is_not_critical
    it "paths: generic html is inconclusive"              test_generic_html_at_a_sensitive_path_is_inconclusive
    it "paths: true file content is detected"             test_true_file_content_is_detected
    it "paths: redirect/auth/challenge are distinct"      test_redirect_auth_and_challenge_are_distinct_from_exposure
    it "paths: report carries a digest, not the body"     test_exposure_report_carries_a_digest_not_the_body
    it "paths: json finding carries no body"              test_json_exposure_finding_has_no_body
    it "paths: random missing-path baseline probed"       test_path_probes_carry_a_random_missing_path_baseline
    it "paths: probes are size and time bounded"          test_path_probes_are_size_and_time_bounded
    it "paths: soft-404 echoing the path is not critical" test_soft404_that_echoes_the_path_is_not_critical
    it "paths: true file detected via real request path"  test_true_file_is_detected_through_the_real_request_path
    it "paths: oversize answer judged by type"            test_oversize_probe_answer_is_judged_by_type_not_content

    it "pii: email is critical"                           test_email_in_source_is_critical
    it "pii: allowlisted email is quiet"                  test_allowlisted_email_is_not_reported
    it "pii: allowlisted email domain is quiet"           test_allowlisted_email_domain_is_not_reported
    it "pii: example.com address is quiet"                test_example_com_email_is_never_reported
    it "pii: phone number warns"                          test_phone_in_source_is_a_warning
    it "pii: allowlisted phone is quiet"                  test_allowlisted_phone_is_not_reported
    it "pii: allowlist splits on commas"                  test_allowlisted_phone_list_is_split_on_commas
    it "pii: hugo image fingerprint is not a phone"       test_hugo_image_fingerprint_is_not_a_phone
    it "pii: hashed asset name is not a phone"            test_hashed_asset_filename_is_not_a_phone
    it "pii: cf email attribute is not a phone"           test_cf_email_obfuscation_attribute_is_not_a_phone
    it "pii: cf email link is not a phone"                test_cf_email_protection_link_is_not_a_phone

    it "secrets: token patterns are critical"             test_secret_patterns_are_critical
    it "secrets: token value is redacted"                 test_secret_value_is_redacted_in_output
    it "secrets: analytics ids are allowlisted"           test_analytics_ids_are_not_secrets
    it "secrets: double-quoted credential is critical"    test_double_quoted_credential_assignment_is_critical
    it "secrets: single-quoted credential is critical"    test_single_quoted_credential_assignment_is_critical
    it "secrets: credential value is not echoed"          test_credential_value_is_not_echoed

    it "generator: meta tag warns"                        test_generator_tag_is_a_warning
    it "generator: single-quoted meta tag warns"          test_single_quoted_generator_tag_is_a_warning
    it "internal-ip: private ranges warn"                 test_internal_ips_are_warned

    it "ssl: valid certificate passes"                    test_valid_certificate_passes
    it "ssl: near expiry warns"                           test_expiring_certificate_is_a_warning
    it "ssl: expired certificate is critical"             test_expired_certificate_is_critical
    it "ssl: unreachable certificate is critical"         test_unreachable_certificate_is_critical
    it "ssl: unparseable certificate is critical"         test_unparseable_certificate_is_critical

    it "json: report parses"                              test_json_report_is_valid_json
    it "json: clean run summarised as PASS"               test_json_report_summarises_a_clean_run
    it "json: findings are listed"                        test_json_report_lists_findings
    it "json: hostile header values survive"              test_json_report_survives_hostile_header_values

    it "exit: multi-url keeps the worst result"           test_multi_url_keeps_the_worst_result
    it "exit: clean url cannot mask a warning"            test_a_clean_url_cannot_mask_an_earlier_warning
    it "exit: multi-url critical wins"                    test_multi_url_critical_wins
    it "exit: multi-url all clean exits 0"                test_multi_url_all_clean_exits_zero
    it "exit: counters reset between urls"                test_counters_reset_between_urls

    it "requests: page body fetched once"                 test_page_body_is_fetched_once_per_url

    echo ""
    echo "1..${TOTAL}"
    echo "# passed ${PASSED}, failed ${FAILED}"
    if [[ "$FAILED" -gt 0 ]]; then
        echo ""
        echo "# failures:"
        for f in "${FAILURES[@]}"; do
            echo "#   - ${f}"
        done
        exit 1
    fi
    exit 0
}

main
