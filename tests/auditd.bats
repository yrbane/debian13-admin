#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  # Test directory for audit rules
  AUDIT_RULES_DIR="${TEST_DIR}/audit/rules.d"
  mkdir -p "$AUDIT_RULES_DIR"

  # Mock system commands
  systemctl() { return 0; }
  export -f systemctl
  auditctl() { return 0; }
  export -f auditctl
  augenrules() { return 0; }
  export -f augenrules

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- deploy_auditd_rules ---

@test "deploy_auditd_rules: creates rules file" {
  deploy_auditd_rules
  [ -f "${AUDIT_RULES_DIR}/99-server-hardening.rules" ]
}

@test "deploy_auditd_rules: monitors /etc/passwd" {
  deploy_auditd_rules
  grep -q "/etc/passwd" "${AUDIT_RULES_DIR}/99-server-hardening.rules"
}

@test "deploy_auditd_rules: monitors /etc/shadow" {
  deploy_auditd_rules
  grep -q "/etc/shadow" "${AUDIT_RULES_DIR}/99-server-hardening.rules"
}

@test "deploy_auditd_rules: monitors SSH authorized_keys" {
  deploy_auditd_rules
  grep -q "authorized_keys" "${AUDIT_RULES_DIR}/99-server-hardening.rules"
}

@test "deploy_auditd_rules: monitors sudoers" {
  deploy_auditd_rules
  grep -q "sudoers" "${AUDIT_RULES_DIR}/99-server-hardening.rules"
}

@test "deploy_auditd_rules: monitors SSH host keys" {
  deploy_auditd_rules
  grep -q "sshd_config" "${AUDIT_RULES_DIR}/99-server-hardening.rules"
}

@test "deploy_auditd_rules: monitors privilege escalation" {
  deploy_auditd_rules
  grep -q "execve" "${AUDIT_RULES_DIR}/99-server-hardening.rules" || \
  grep -q "privilege" "${AUDIT_RULES_DIR}/99-server-hardening.rules"
}

@test "deploy_auditd_rules: idempotent (second run overwrites)" {
  deploy_auditd_rules
  local hash1
  hash1=$(md5sum "${AUDIT_RULES_DIR}/99-server-hardening.rules" | cut -d' ' -f1)
  deploy_auditd_rules
  local hash2
  hash2=$(md5sum "${AUDIT_RULES_DIR}/99-server-hardening.rules" | cut -d' ' -f1)
  [ "$hash1" = "$hash2" ]
}

# --- verify_auditd ---

@test "verify_auditd: ok when auditd is active" {
  AUDITD_STATUS="active"
  make_auditd_status_mock

  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_auditd
  [[ "$output" == *"ok:auditd"* ]]
}

@test "verify_auditd: warn when auditd inactive" {
  AUDITD_STATUS="inactive"
  make_auditd_status_mock

  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_auditd
  [[ "$output" == *"warn:"* ]] || [[ "$output" == *"fail:"* ]]
}

@test "verify_auditd: checks rules file presence" {
  AUDITD_STATUS="active"
  make_auditd_status_mock

  # Create rules file for check
  mkdir -p "${AUDIT_RULES_DIR}"
  echo "-w /etc/passwd -p wa -k identity" > "${AUDIT_RULES_DIR}/99-server-hardening.rules"

  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_auditd
  [[ "$output" == *"ok:"*"règles"* ]] || [[ "$output" == *"ok:"*"rules"* ]]
}

# Helper: mock systemctl is-active auditd
make_auditd_status_mock() {
  systemctl() {
    if [[ "$1" == "is-active" && "$2" == "auditd" ]]; then
      if [[ "$AUDITD_STATUS" == "active" ]]; then
        echo "active"; return 0
      else
        echo "inactive"; return 1
      fi
    fi
    return 0
  }
  export -f systemctl
}
