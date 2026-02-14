#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_deploy_parking ---
@test "deploy_parking: creates index.html with domain substituted" {
  dm_deploy_parking "example.com"
  [ -f "${WEB_ROOT}/example.com/www/public/index.html" ]
  grep -q "example.com" "${WEB_ROOT}/example.com/www/public/index.html"
  ! grep -q "__HOSTNAME_FQDN__" "${WEB_ROOT}/example.com/www/public/index.html"
}

@test "deploy_parking: creates CSS file" {
  dm_deploy_parking "example.com"
  [ -f "${WEB_ROOT}/example.com/www/public/css/style.css" ]
}

@test "deploy_parking: creates robots.txt" {
  dm_deploy_parking "example.com"
  [ -f "${WEB_ROOT}/example.com/www/public/robots.txt" ]
  grep -q "Disallow: /" "${WEB_ROOT}/example.com/www/public/robots.txt"
}

# --- dm_deploy_vhosts ---
@test "deploy_vhosts: creates HTTP redirect VHost" {
  dm_deploy_vhosts "example.com"
  [ -f "${APACHE_SITES_DIR}/000-example.com-redirect.conf" ]
  grep -q "example.com" "${APACHE_SITES_DIR}/000-example.com-redirect.conf"
  ! grep -q "__HOSTNAME_FQDN__" "${APACHE_SITES_DIR}/000-example.com-redirect.conf"
}

@test "deploy_vhosts: creates HTTPS VHost" {
  dm_deploy_vhosts "example.com"
  [ -f "${APACHE_SITES_DIR}/010-example.com.conf" ]
  grep -q "example.com" "${APACHE_SITES_DIR}/010-example.com.conf"
  ! grep -q "__HOSTNAME_FQDN__" "${APACHE_SITES_DIR}/010-example.com.conf"
}

@test "deploy_vhosts: creates log directory" {
  dm_deploy_vhosts "example.com"
  [ -d "${LOG_DIR}/example.com" ]
}

# --- dm_deploy_logrotate ---
@test "deploy_logrotate: creates logrotate config" {
  dm_deploy_logrotate "example.com"
  [ -f "${LOGROTATE_DIR}/apache-vhost-example.com" ]
  grep -q "example.com" "${LOGROTATE_DIR}/apache-vhost-example.com"
}

@test "deploy_logrotate: config contains rotation settings" {
  dm_deploy_logrotate "example.com"
  grep -q "daily" "${LOGROTATE_DIR}/apache-vhost-example.com"
  grep -q "rotate 14" "${LOGROTATE_DIR}/apache-vhost-example.com"
  grep -q "compress" "${LOGROTATE_DIR}/apache-vhost-example.com"
}

# --- dm_remove_vhosts ---
@test "remove_vhosts: removes VHost files" {
  dm_deploy_vhosts "example.com"
  [ -f "${APACHE_SITES_DIR}/000-example.com-redirect.conf" ]
  [ -f "${APACHE_SITES_DIR}/010-example.com.conf" ]

  dm_remove_vhosts "example.com"
  [ ! -f "${APACHE_SITES_DIR}/000-example.com-redirect.conf" ]
  [ ! -f "${APACHE_SITES_DIR}/010-example.com.conf" ]
}

# --- dm_remove_logrotate ---
@test "remove_logrotate: removes logrotate config" {
  echo "test" > "${LOGROTATE_DIR}/apache-vhost-example.com"
  dm_remove_logrotate "example.com"
  [ ! -f "${LOGROTATE_DIR}/apache-vhost-example.com" ]
}

# --- dm_render_template guard ---
@test "render_template: fails when template missing" {
  run dm_render_template "nonexistent.html" "example.com" "${TEST_DIR}/out.html"
  [ "$status" -ne 0 ]
  [ ! -f "${TEST_DIR}/out.html" ]
}

@test "deploy_parking: fails when HTML template missing" {
  local saved="$TEMPLATES_DIR"
  TEMPLATES_DIR="${TEST_DIR}/empty_templates"
  mkdir -p "$TEMPLATES_DIR"
  run dm_deploy_parking "example.com"
  TEMPLATES_DIR="$saved"
  [ "$status" -ne 0 ]
}

@test "deploy_vhosts: fails when VHost template missing" {
  local saved="$TEMPLATES_DIR"
  TEMPLATES_DIR="${TEST_DIR}/empty_templates"
  mkdir -p "$TEMPLATES_DIR"
  run dm_deploy_vhosts "example.com"
  TEMPLATES_DIR="$saved"
  [ "$status" -ne 0 ]
}

# --- sed metacharacter safety ---
@test "render_template: domain with dots renders correctly" {
  dm_render_template "parking-page.html" "my.example.com" "${TEST_DIR}/out.html"
  grep -q "my.example.com" "${TEST_DIR}/out.html"
  ! grep -q "__HOSTNAME_FQDN__" "${TEST_DIR}/out.html"
}

@test "render_template: domain with ampersand is escaped" {
  dm_render_template "parking-page.html" "a&b.com" "${TEST_DIR}/out.html"
  grep -q "a&b.com" "${TEST_DIR}/out.html"  # literal &
  ! grep -q "__HOSTNAME_FQDN__" "${TEST_DIR}/out.html"
}

@test "render_template: domain with slash is escaped" {
  dm_render_template "parking-page.html" "a/b.com" "${TEST_DIR}/out.html"
  grep -q "a/b.com" "${TEST_DIR}/out.html"
  ! grep -q "__HOSTNAME_FQDN__" "${TEST_DIR}/out.html"
}

# --- idempotency ---
@test "deploy_parking: idempotent (second run does not fail)" {
  dm_deploy_parking "example.com"
  dm_deploy_parking "example.com"
  [ -f "${WEB_ROOT}/example.com/www/public/index.html" ]
}

@test "deploy_vhosts: idempotent (second run overwrites)" {
  dm_deploy_vhosts "example.com"
  dm_deploy_vhosts "example.com"
  [ -f "${APACHE_SITES_DIR}/010-example.com.conf" ]
}

@test "deploy_logrotate: idempotent (second run overwrites)" {
  dm_deploy_logrotate "example.com"
  dm_deploy_logrotate "example.com"
  [ -f "${LOGROTATE_DIR}/apache-vhost-example.com" ]
  [ "$(grep -c 'daily' "${LOGROTATE_DIR}/apache-vhost-example.com")" -eq 1 ]
}

@test "remove_vhosts: idempotent (double remove does not fail)" {
  dm_deploy_vhosts "example.com"
  dm_remove_vhosts "example.com"
  dm_remove_vhosts "example.com"
  [ ! -f "${APACHE_SITES_DIR}/000-example.com-redirect.conf" ]
}

@test "remove_logrotate: idempotent (double remove does not fail)" {
  echo "test" > "${LOGROTATE_DIR}/apache-vhost-example.com"
  dm_remove_logrotate "example.com"
  dm_remove_logrotate "example.com"
  [ ! -f "${LOGROTATE_DIR}/apache-vhost-example.com" ]
}
