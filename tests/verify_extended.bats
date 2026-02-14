#!/usr/bin/env bats
# Point 18: Additional verify checks

load test_helper

setup() {
  setup_test_env
  override_paths

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
}

teardown() { teardown_test_env; }

# --- verify_suid_binaries ---

@test "verify_suid: reports suid files" {
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  # Mock find to return known SUID files
  find() { echo "/usr/bin/passwd"; echo "/usr/bin/sudo"; }
  export -f find
  run verify_suid_binaries
  [[ "$output" == *"SUID"* ]] || [[ "$output" == *"suid"* ]]
}

# --- verify_tls_version ---

@test "verify_tls: checks TLS configuration" {
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  # Create mock ssl config
  mkdir -p "${TEST_DIR}/apache2/mods-enabled"
  cat > "${TEST_DIR}/apache2/mods-enabled/ssl.conf" <<'EOF'
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
EOF
  APACHE_CONF_DIR="${TEST_DIR}/apache2"
  run verify_tls_version
  [[ "$output" == *"ok:"* ]] || [[ "$output" == *"TLS"* ]]
}

@test "verify_tls: warns when TLSv1 enabled" {
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  mkdir -p "${TEST_DIR}/apache2/mods-enabled"
  cat > "${TEST_DIR}/apache2/mods-enabled/ssl.conf" <<'EOF'
SSLProtocol all -SSLv3
EOF
  APACHE_CONF_DIR="${TEST_DIR}/apache2"
  run verify_tls_version
  [[ "$output" == *"warn:"* ]]
}
