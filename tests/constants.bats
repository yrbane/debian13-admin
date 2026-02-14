#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/constants.sh"
}

teardown() { teardown_test_env; }

# --- constants exist and have expected values ---

@test "constants: DNS_RESOLVER defined" {
  [ -n "$DNS_RESOLVER" ]
}

@test "constants: DNS_TTL_DEFAULT is numeric" {
  [[ "$DNS_TTL_DEFAULT" =~ ^[0-9]+$ ]]
  [ "$DNS_TTL_DEFAULT" -gt 0 ]
}

@test "constants: SECONDS_PER_DAY is 86400" {
  [ "$SECONDS_PER_DAY" -eq 86400 ]
}

@test "constants: LOGROTATE_KEEP_DAYS is numeric" {
  [[ "$LOGROTATE_KEEP_DAYS" =~ ^[0-9]+$ ]]
  [ "$LOGROTATE_KEEP_DAYS" -gt 0 ]
}

@test "constants: CAA_ISSUER defined" {
  [ -n "$CAA_ISSUER" ]
}

@test "constants: SPF_INCLUDE_OVH defined" {
  [ -n "$SPF_INCLUDE_OVH" ]
}

@test "constants: DMARC_POLICY is valid" {
  [[ "$DMARC_POLICY" =~ ^(none|quarantine|reject)$ ]]
}

# --- logrotate uses constant ---

@test "deploy_logrotate: uses LOGROTATE_KEEP_DAYS value" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  dm_deploy_logrotate "example.com"
  grep -q "rotate ${LOGROTATE_KEEP_DAYS}" "${LOGROTATE_DIR}/apache-vhost-example.com"
}

@test "deploy_logrotate: defaults to 14 without constant" {
  # Run in subshell to avoid readonly conflict
  run bash -c '
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    LOG_DIR="'"${TEST_DIR}"'/log/apache2"
    LOGROTATE_DIR="'"${TEST_DIR}"'/logrotate.d"
    mkdir -p "$LOG_DIR" "$LOGROTATE_DIR"
    TEMPLATES_DIR="'"${TEST_DIR}"'/templates"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/domain-manager.sh"
    dm_deploy_logrotate "example.com"
    grep -q "rotate 14" "${LOGROTATE_DIR}/apache-vhost-example.com"
  '
  [ "$status" -eq 0 ]
}

# --- helpers use SECONDS_PER_DAY ---

@test "days_since: uses SECONDS_PER_DAY" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  local yesterday=$(( $(date +%s) - 86400 ))
  run days_since "$yesterday"
  [ "$output" -eq 1 ]
}

@test "days_until: uses SECONDS_PER_DAY" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  local tomorrow=$(( $(date +%s) + 86400 ))
  run days_until "$tomorrow"
  [ "$output" -eq 1 ]
}
