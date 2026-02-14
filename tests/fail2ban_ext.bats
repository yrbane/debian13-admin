#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  FAIL2BAN_DIR="${TEST_DIR}/fail2ban"
  FAIL2BAN_FILTER_DIR="${FAIL2BAN_DIR}/filter.d"
  FAIL2BAN_JAIL_DIR="${FAIL2BAN_DIR}/jail.d"
  mkdir -p "$FAIL2BAN_FILTER_DIR" "$FAIL2BAN_JAIL_DIR"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- deploy_fail2ban_extended ---

@test "deploy_fail2ban_extended: creates POST rate limit filter" {
  deploy_fail2ban_extended
  [ -f "${FAIL2BAN_FILTER_DIR}/apache-post-flood.conf" ]
  grep -q "POST" "${FAIL2BAN_FILTER_DIR}/apache-post-flood.conf"
}

@test "deploy_fail2ban_extended: creates credential stuffing filter" {
  deploy_fail2ban_extended
  [ -f "${FAIL2BAN_FILTER_DIR}/apache-auth-flood.conf" ]
  grep -q "401\|403" "${FAIL2BAN_FILTER_DIR}/apache-auth-flood.conf"
}

@test "deploy_fail2ban_extended: creates jail config" {
  deploy_fail2ban_extended
  [ -f "${FAIL2BAN_JAIL_DIR}/custom-extended.conf" ]
}

@test "deploy_fail2ban_extended: jail enables POST flood protection" {
  deploy_fail2ban_extended
  grep -q "apache-post-flood" "${FAIL2BAN_JAIL_DIR}/custom-extended.conf"
  grep -q "enabled = true" "${FAIL2BAN_JAIL_DIR}/custom-extended.conf"
}

@test "deploy_fail2ban_extended: jail enables auth flood protection" {
  deploy_fail2ban_extended
  grep -q "apache-auth-flood" "${FAIL2BAN_JAIL_DIR}/custom-extended.conf"
}

@test "deploy_fail2ban_extended: progressive ban uses recidive" {
  deploy_fail2ban_extended
  grep -q "recidive" "${FAIL2BAN_JAIL_DIR}/custom-extended.conf"
}

@test "deploy_fail2ban_extended: recidive has increasing ban time" {
  deploy_fail2ban_extended
  # Recidive bantime should be longer than default (604800 = 1 week)
  grep -q "604800" "${FAIL2BAN_JAIL_DIR}/custom-extended.conf"
}

@test "deploy_fail2ban_extended: idempotent (second run overwrites)" {
  deploy_fail2ban_extended
  local hash1
  hash1=$(md5sum "${FAIL2BAN_JAIL_DIR}/custom-extended.conf" | cut -d' ' -f1)
  deploy_fail2ban_extended
  local hash2
  hash2=$(md5sum "${FAIL2BAN_JAIL_DIR}/custom-extended.conf" | cut -d' ' -f1)
  [ "$hash1" = "$hash2" ]
}
