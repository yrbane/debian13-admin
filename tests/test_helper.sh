#!/usr/bin/env bash
# tests/test_helper.sh — Stubs, mocks et helpers pour les tests bats
# Usage: load test_helper (dans chaque .bats)

# Repertoire temp par test
setup_test_env() {
  TEST_DIR=$(mktemp -d)
  TEST_DOMAINS_CONF="${TEST_DIR}/domains.conf"
  TEST_DKIM_KEYDIR="${TEST_DIR}/opendkim/keys"
  TEST_TEMPLATES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/templates"
  TEST_OPENDKIM_DIR="${TEST_DIR}/opendkim"
  TEST_WWW_DIR="${TEST_DIR}/www"
  TEST_APACHE_DIR="${TEST_DIR}/apache2"
  TEST_LOGROTATE_DIR="${TEST_DIR}/logrotate.d"
  TEST_LOG_DIR="${TEST_DIR}/log/apache2"
  mkdir -p "$TEST_DKIM_KEYDIR" "$TEST_OPENDKIM_DIR" "$TEST_WWW_DIR" \
           "$TEST_APACHE_DIR/sites-available" "$TEST_APACHE_DIR/sites-enabled" \
           "$TEST_LOGROTATE_DIR" "$TEST_LOG_DIR"
}

teardown_test_env() {
  [[ -d "${TEST_DIR:-}" ]] && rm -rf "$TEST_DIR"
}

# Stubs logging (silencieux en test)
log()     { :; }
warn()    { :; }
err()     { :; }
note()    { :; }
section() { :; }
die()     { echo "DIE: $1" >&2; return 1; }
print_title() { :; }
print_cmd()   { :; }
print_note()  { :; }

# Stubs verification
emit_check() { echo "${1}:${2}"; }
emit_section() { :; }
emit_section_close() { :; }
check_ok()   { :; }
check_warn() { :; }
check_fail() { :; }

# Override des constantes pour tests
override_paths() {
  DOMAINS_CONF="$TEST_DOMAINS_CONF"
  DKIM_KEYDIR="$TEST_DKIM_KEYDIR"
  OPENDKIM_DIR="$TEST_OPENDKIM_DIR"
  TEMPLATES_DIR="$TEST_TEMPLATES_DIR"
  WEB_ROOT="$TEST_WWW_DIR"
  APACHE_SITES_DIR="$TEST_APACHE_DIR/sites-available"
  LOGROTATE_DIR="$TEST_LOGROTATE_DIR"
  LOG_DIR="$TEST_LOG_DIR"
}
