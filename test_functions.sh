#!/usr/bin/env bash
# Tests unitaires des nouvelles fonctions Phase 3
set -euo pipefail

PASS=0; FAIL=0
assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $desc"
    ((++PASS))
  else
    echo "  FAIL: $desc (expected='$expected', got='$actual')"
    ((++FAIL))
  fi
}

# --- Stubs pour les fonctions du script principal ---
check_ok()   { echo "OK: $*"; }
check_warn() { echo "WARN: $*"; }
check_fail() { echo "FAIL: $*"; }
add_html_check() { echo "HTML_${1}: ${2}"; }
LOG_FILE="/dev/null"
DB_FRESH_DAYS=7
DB_STALE_DAYS=30

# Source les fonctions utilitaires
eval "$(sed -n '/^deploy_script()/,/^# =* MODULES/{ /^# =* MODULES/d; p; }' /home/debian/scripts/debian13-server.sh)"
# Source aussi add_cron_job (nécessaire pour deploy_script)
eval "$(sed -n '/^add_cron_job()/,/^}/p' /home/debian/scripts/debian13-server.sh)"

echo "=== Test php_ini_set ==="
TMPINI=$(mktemp)
cat > "$TMPINI" <<'INI'
;opcache.enable=0
expose_php = On
display_errors = On
INI
php_ini_set "opcache\.enable" "1" "$TMPINI"
php_ini_set "expose_php" "Off" "$TMPINI"
php_ini_set "display_errors" "Off" "$TMPINI"
assert_eq "opcache enabled" "opcache.enable = 1" "$(grep opcache.enable "$TMPINI")"
assert_eq "expose_php off" "expose_php = Off" "$(grep expose_php "$TMPINI")"
assert_eq "display_errors off" "display_errors = Off" "$(grep display_errors "$TMPINI")"
rm -f "$TMPINI"

echo ""
echo "=== Test check_file_perms ==="
TMPFILE=$(mktemp)
chmod 600 "$TMPFILE"
RESULT=$(check_file_perms "$TMPFILE" "TestFile" "600")
assert_eq "permissions 600 ok" "OK: TestFile : permissions correctes (600)" "$RESULT"
RESULT=$(check_file_perms "$TMPFILE" "TestFile" "700")
assert_eq "permissions 600 vs 700 warn" "WARN: TestFile : permissions = 600 (attendu : 700)" "$RESULT"
RESULT=$(check_file_perms "$TMPFILE" "TestFile" "600|640" "html")
assert_eq "html mode ok" "HTML_ok: TestFile : permissions correctes (600)" "$RESULT"
rm -f "$TMPFILE"

echo ""
echo "=== Test safe_count ==="
TMPFILE=$(mktemp)
echo -e "FOUND\nFOUND\nNOTHING\nFOUND" > "$TMPFILE"
assert_eq "count FOUND=3" "3" "$(safe_count "FOUND" "$TMPFILE")"
assert_eq "count NOTHING=1" "1" "$(safe_count "NOTHING" "$TMPFILE")"
assert_eq "count MISSING=0" "0" "$(safe_count "MISSING" "$TMPFILE")"
# Test with pipe input
PIPE_RESULT=$(safe_count "line" "$(echo -e "line1\nline2\nother")")
assert_eq "count from string=2" "2" "$PIPE_RESULT"
rm -f "$TMPFILE"

echo ""
echo "=== Test days_since / days_until ==="
NOW=$(date +%s)
FIVE_DAYS_AGO=$((NOW - 5 * 86400))
TEN_DAYS_AHEAD=$((NOW + 10 * 86400))
assert_eq "5 days ago" "5" "$(days_since $FIVE_DAYS_AGO)"
assert_eq "10 days ahead" "10" "$(days_until $TEN_DAYS_AHEAD)"
assert_eq "now=0 days since" "0" "$(days_since $NOW)"

echo ""
echo "=== Test add_line_if_missing ==="
TMPFILE=$(mktemp)
echo "existing line" > "$TMPFILE"
add_line_if_missing "^existing" "existing line" "$TMPFILE"
assert_eq "no duplicate" "1" "$(wc -l < "$TMPFILE" | tr -d ' ')"
add_line_if_missing "^new" "new line" "$TMPFILE"
assert_eq "line added" "2" "$(wc -l < "$TMPFILE" | tr -d ' ')"
assert_eq "content correct" "new line" "$(tail -1 "$TMPFILE")"
rm -f "$TMPFILE"

echo ""
echo "=== Test deploy_script with extra substitutions ==="
TMPDIR=$(mktemp -d)
EMAIL_FOR_CERTBOT="test@example.com"
deploy_script "${TMPDIR}/test.sh" 'EMAIL=__EMAIL__ RETENTION=__RETENTION__ HOST=__HOST__' "" "" "__RETENTION__" "30" "__HOST__" "myhost"
CONTENT=$(cat "${TMPDIR}/test.sh")
assert_eq "email replaced" "EMAIL=test@example.com RETENTION=30 HOST=myhost" "$CONTENT"
EXEC_CHECK=$([[ -x "${TMPDIR}/test.sh" ]] && echo true || echo false)
assert_eq "is executable" "true" "$EXEC_CHECK"
rm -rf "$TMPDIR"

echo ""
echo "=== Test check_config_grep ==="
TMPCONF=$(mktemp)
echo -e "PermitRootLogin no\nPasswordAuthentication yes\nPort 65222" > "$TMPCONF"
RESULT=$(check_config_grep "$TMPCONF" "^PermitRootLogin\s+no" "root ok" "root fail")
assert_eq "config grep ok" "OK: root ok" "$RESULT"
RESULT=$(check_config_grep "$TMPCONF" "^PasswordAuthentication\s+no" "pass ok" "pass fail")
assert_eq "config grep fail" "FAIL: pass fail" "$RESULT"
RESULT=$(check_config_grep "$TMPCONF" "^Port\s+65222" "port ok" "port fail" "html")
assert_eq "config grep html ok" "HTML_ok: port ok" "$RESULT"
rm -f "$TMPCONF"

echo ""
echo "================================="
echo "Results: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $FAIL
