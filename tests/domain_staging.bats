#!/usr/bin/env bats
# Point 21: Staging mode for domains

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"
  TRUSTED_IPS="1.2.3.4"
  ERROR_PAGES_DIR="/var/www/errorpages"
  SSH_PORT="65222"
  # Mock certbot and openssl
  certbot() { echo "CERTBOT: $*" >> "${TEST_DIR}/certbot.log"; }
  openssl() {
    if [[ "$1" == "req" ]]; then
      echo "OPENSSL: $*" >> "${TEST_DIR}/openssl.log"
      # Create fake cert files
      local out=""
      for arg in "$@"; do
        if [[ "$prev" == "-out" ]]; then out="$arg"; fi
        prev="$arg"
      done
      [[ -n "$out" ]] && echo "FAKE CERT" > "$out"
      # Also create key file
      local keyout=""
      prev=""
      for arg in "$@"; do
        if [[ "$prev" == "-keyout" ]]; then keyout="$arg"; fi
        prev="$arg"
      done
      [[ -n "$keyout" ]] && echo "FAKE KEY" > "$keyout"
    fi
    return 0
  }
  export -f certbot openssl
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_deploy_staging ---

@test "deploy_staging: registers domain with staging flag" {
  dm_deploy_staging "staging.com"
  dm_domain_exists "staging.com"
  run dm_get_domain_config "staging.com" "STAGING"
  [ "$output" = "true" ]
}

@test "deploy_staging: creates parking page" {
  dm_deploy_staging "staging.com"
  [ -f "${WEB_ROOT}/staging.com/www/public/index.html" ]
}

@test "deploy_staging: creates VHost files" {
  dm_deploy_staging "staging.com"
  [ -f "${APACHE_SITES_DIR}/000-staging.com-redirect.conf" ]
  [ -f "${APACHE_SITES_DIR}/010-staging.com.conf" ]
}

@test "deploy_staging: does not call certbot" {
  dm_deploy_staging "staging.com"
  [ ! -f "${TEST_DIR}/certbot.log" ]
}

@test "deploy_staging: creates logrotate config" {
  dm_deploy_staging "staging.com"
  [ -f "${LOGROTATE_DIR}/apache-vhost-staging.com" ]
}

@test "dm_is_staging: returns 0 for staging domain" {
  dm_deploy_staging "staging.com"
  dm_is_staging "staging.com"
}

@test "dm_is_staging: returns 1 for non-staging domain" {
  dm_register_domain "prod.com" "mail"
  run dm_is_staging "prod.com"
  [ "$status" -eq 1 ]
}

@test "dm_promote_staging: clears staging flag" {
  dm_deploy_staging "staging.com"
  dm_promote_staging "staging.com"
  run dm_is_staging "staging.com"
  [ "$status" -eq 1 ]
}
