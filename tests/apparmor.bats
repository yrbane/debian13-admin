#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  HOSTNAME_FQDN="main.com"

  # AppArmor test directories
  APPARMOR_LOCAL="${TEST_DIR}/apparmor.d/local"
  mkdir -p "$APPARMOR_LOCAL"

  # Mock system commands
  systemctl() { return 0; }
  export -f systemctl

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
}

teardown() { teardown_test_env; }

# Helper: create a mock aa-status script
make_aa_status_mock() {
  local mock="${TEST_DIR}/mock-aa-status"
  cat > "$mock" <<MOCK
#!/bin/bash
$1
MOCK
  chmod +x "$mock"
  # Use bash to run it (noexec /tmp)
  AA_STATUS_CMD="bash ${mock}"
}

# --- deploy_apparmor_profiles (defined in helpers.sh) ---

@test "deploy_apparmor_profiles: creates Apache local profile" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  [ -f "${APPARMOR_LOCAL}/usr.sbin.apache2" ]
}

@test "deploy_apparmor_profiles: Apache profile allows web root" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  grep -q "/var/www/" "${APPARMOR_LOCAL}/usr.sbin.apache2"
}

@test "deploy_apparmor_profiles: Apache profile allows SSL certs" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  grep -q "/etc/letsencrypt/" "${APPARMOR_LOCAL}/usr.sbin.apache2"
}

@test "deploy_apparmor_profiles: Apache profile allows log writing" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  grep -q "/var/log/apache2/" "${APPARMOR_LOCAL}/usr.sbin.apache2"
}

@test "deploy_apparmor_profiles: creates MariaDB local profile" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  [ -f "${APPARMOR_LOCAL}/usr.sbin.mariadbd" ]
}

@test "deploy_apparmor_profiles: MariaDB profile allows data directory" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  grep -q "/var/lib/mysql/" "${APPARMOR_LOCAL}/usr.sbin.mariadbd"
}

@test "deploy_apparmor_profiles: creates Postfix local profile" {
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  deploy_apparmor_profiles
  [ -f "${APPARMOR_LOCAL}/usr.lib.postfix.smtpd" ]
}

# --- verify_apparmor (defined in verify.sh) ---

@test "verify_apparmor: ok when apparmor loaded with profiles" {
  make_aa_status_mock '
echo "apparmor module is loaded."
echo "5 profiles are loaded."
echo "5 profiles are in enforce mode."
echo "0 profiles are in complain mode."
echo "0 processes are unconfined"
'
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_apparmor
  [[ "$output" == *"ok:AppArmor"* ]]
}

@test "verify_apparmor: warn when profiles in complain mode" {
  make_aa_status_mock '
echo "apparmor module is loaded."
echo "5 profiles are loaded."
echo "2 profiles are in enforce mode."
echo "3 profiles are in complain mode."
echo "0 processes are unconfined"
'
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_apparmor
  [[ "$output" == *"warn:"*"complain"* ]]
}

@test "verify_apparmor: fail when aa-status fails" {
  make_aa_status_mock 'exit 1'
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_apparmor
  [[ "$output" == *"fail:"* ]]
}

@test "verify_apparmor: reports enforce profile count" {
  make_aa_status_mock '
echo "apparmor module is loaded."
echo "8 profiles are loaded."
echo "8 profiles are in enforce mode."
echo "0 profiles are in complain mode."
'
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_apparmor
  [[ "$output" == *"8"* ]]
}
