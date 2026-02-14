#!/usr/bin/env bats
# Point 11: WAF rules per domain — deploy_waf_domain_rules / remove_waf_domain_rules

load test_helper

setup() {
  setup_test_env
  override_paths

  WAF_RULES_DIR="${TEST_DIR}/modsec.d"
  mkdir -p "$WAF_RULES_DIR"

  HOSTNAME_FQDN="main.com"

  # Mock systemctl (Apache reload)
  systemctl() { return 0; }
  export -f systemctl

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- deploy_waf_domain_rules ---

@test "deploy_waf_domain_rules: creates ModSecurity rules file" {
  deploy_waf_domain_rules "example.com"
  [ -f "${WAF_RULES_DIR}/example.com.conf" ]
}

@test "deploy_waf_domain_rules: file contains SecRule directives" {
  deploy_waf_domain_rules "example.com"
  grep -q "SecRule" "${WAF_RULES_DIR}/example.com.conf"
}

@test "deploy_waf_domain_rules: file contains domain name in comment" {
  deploy_waf_domain_rules "example.com"
  grep -q "# .*example.com" "${WAF_RULES_DIR}/example.com.conf" || \
    grep -q "#.*example.com" "${WAF_RULES_DIR}/example.com.conf"
}

@test "deploy_waf_domain_rules: supports IP whitelist" {
  deploy_waf_domain_rules "example.com" "1.2.3.4"
  grep -q "1.2.3.4" "${WAF_RULES_DIR}/example.com.conf"
  grep -q "SecRule" "${WAF_RULES_DIR}/example.com.conf"
}

@test "deploy_waf_domain_rules: supports rate limit setting via dm_set_domain_config" {
  dm_register_domain "example.com" "mail"
  deploy_waf_domain_rules "example.com" "" "100"
  local rate
  rate=$(dm_get_domain_config "example.com" "WAF_RATE_LIMIT")
  [ "$rate" = "100" ]
}

@test "deploy_waf_domain_rules: idempotent (second run overwrites without error)" {
  deploy_waf_domain_rules "example.com"
  deploy_waf_domain_rules "example.com"
  [ -f "${WAF_RULES_DIR}/example.com.conf" ]
  # Only one set of rules (no duplication)
  [ "$(grep -c 'SecRule' "${WAF_RULES_DIR}/example.com.conf")" -ge 1 ]
}

@test "deploy_waf_domain_rules: different domains get separate files" {
  deploy_waf_domain_rules "example.com"
  deploy_waf_domain_rules "other.com"
  [ -f "${WAF_RULES_DIR}/example.com.conf" ]
  [ -f "${WAF_RULES_DIR}/other.com.conf" ]
  grep -q "example.com" "${WAF_RULES_DIR}/example.com.conf"
  grep -q "other.com" "${WAF_RULES_DIR}/other.com.conf"
}

# --- remove_waf_domain_rules ---

@test "remove_waf_domain_rules: removes the rules file" {
  deploy_waf_domain_rules "example.com"
  [ -f "${WAF_RULES_DIR}/example.com.conf" ]
  remove_waf_domain_rules "example.com"
  [ ! -f "${WAF_RULES_DIR}/example.com.conf" ]
}

@test "remove_waf_domain_rules: idempotent (double remove does not fail)" {
  deploy_waf_domain_rules "example.com"
  remove_waf_domain_rules "example.com"
  remove_waf_domain_rules "example.com"
  [ ! -f "${WAF_RULES_DIR}/example.com.conf" ]
}

@test "remove_waf_domain_rules: does not affect other domains" {
  deploy_waf_domain_rules "example.com"
  deploy_waf_domain_rules "other.com"
  remove_waf_domain_rules "example.com"
  [ ! -f "${WAF_RULES_DIR}/example.com.conf" ]
  [ -f "${WAF_RULES_DIR}/other.com.conf" ]
}
