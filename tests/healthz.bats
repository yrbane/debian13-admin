#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  HOSTNAME_FQDN="main.com"
  WEB_ROOT="${TEST_WWW_DIR}"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- deploy_healthz ---

@test "deploy_healthz: creates healthz script" {
  deploy_healthz "example.com"
  [ -f "${WEB_ROOT}/example.com/www/public/healthz" ]
}

@test "deploy_healthz: script outputs JSON" {
  deploy_healthz "example.com"
  local script="${WEB_ROOT}/example.com/www/public/healthz"
  # Script should contain JSON structure indicators
  grep -q '"status"' "$script"
}

@test "deploy_healthz: includes hostname in output" {
  deploy_healthz "example.com"
  grep -q "hostname" "${WEB_ROOT}/example.com/www/public/healthz"
}

@test "deploy_healthz: includes disk info" {
  deploy_healthz "example.com"
  grep -q "disk" "${WEB_ROOT}/example.com/www/public/healthz"
}

@test "deploy_healthz: includes uptime" {
  deploy_healthz "example.com"
  grep -q "uptime" "${WEB_ROOT}/example.com/www/public/healthz"
}

@test "deploy_healthz: script is executable" {
  deploy_healthz "example.com"
  [[ $(stat -c %a "${WEB_ROOT}/example.com/www/public/healthz") =~ [1357] ]]
}

@test "deploy_healthz: idempotent" {
  deploy_healthz "example.com"
  local hash1
  hash1=$(md5sum "${WEB_ROOT}/example.com/www/public/healthz" | cut -d' ' -f1)
  deploy_healthz "example.com"
  local hash2
  hash2=$(md5sum "${WEB_ROOT}/example.com/www/public/healthz" | cut -d' ' -f1)
  [ "$hash1" = "$hash2" ]
}
