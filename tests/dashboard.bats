#!/usr/bin/env bats
# Point 1: Dashboard web temps réel

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"
  TRUSTED_IPS="1.2.3.4 10.0.0.1"
  SSH_PORT="65222"
  DASHBOARD_SECRET="$(echo testdash | md5sum | cut -d' ' -f1)"
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- deploy_dashboard ---

@test "deploy_dashboard: creates dashboard HTML file" {
  deploy_dashboard "main.com"
  [ -f "${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/index.html" ]
}

@test "deploy_dashboard: HTML contains auto-refresh script" {
  deploy_dashboard "main.com"
  local f="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/index.html"
  grep -q "fetch" "$f"
  grep -q "setInterval\|setTimeout\|EventSource" "$f"
}

@test "deploy_dashboard: HTML contains hostname" {
  deploy_dashboard "main.com"
  local f="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/index.html"
  grep -q "main.com" "$f"
}

@test "deploy_dashboard: creates API endpoint script" {
  deploy_dashboard "main.com"
  [ -f "${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi" ]
}

@test "deploy_dashboard: API endpoint is executable" {
  deploy_dashboard "main.com"
  local api="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi"
  [[ $(stat -c %a "$api") =~ [1357] ]]
}

@test "deploy_dashboard: API returns JSON content-type" {
  deploy_dashboard "main.com"
  local api="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi"
  run bash "$api"
  [[ "$output" == *"application/json"* ]]
}

@test "deploy_dashboard: API returns hostname field" {
  deploy_dashboard "main.com"
  local api="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi"
  run bash "$api"
  [[ "$output" == *'"hostname"'* ]]
}

@test "deploy_dashboard: API returns services field" {
  deploy_dashboard "main.com"
  local api="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi"
  run bash "$api"
  [[ "$output" == *'"services"'* ]]
}

@test "deploy_dashboard: API returns disk field" {
  deploy_dashboard "main.com"
  local api="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi"
  run bash "$api"
  [[ "$output" == *'"disk"'* ]]
}

@test "deploy_dashboard: API returns ssl field" {
  deploy_dashboard "main.com"
  local api="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/api.cgi"
  run bash "$api"
  [[ "$output" == *'"ssl"'* ]]
}

@test "deploy_dashboard: creates .htaccess with IP restriction" {
  deploy_dashboard "main.com"
  local htaccess="${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/.htaccess"
  [ -f "$htaccess" ]
  grep -q "Require ip" "$htaccess"
  grep -q "1.2.3.4" "$htaccess"
}

@test "deploy_dashboard: idempotent (second run does not fail)" {
  deploy_dashboard "main.com"
  deploy_dashboard "main.com"
  [ -f "${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}/index.html" ]
}

@test "deploy_dashboard: URL uses secret hash" {
  deploy_dashboard "main.com"
  [ -d "${WEB_ROOT}/main.com/www/public/dashboard-${DASHBOARD_SECRET}" ]
}
