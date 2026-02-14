#!/usr/bin/env bats
# Point 8: Reverse proxy — dm_deploy_proxy / dm_remove_proxy

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"
  TRUSTED_IPS="1.2.3.4"
  SSH_PORT="65222"
  ERROR_PAGES_DIR="/var/www/errorpages"
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_deploy_proxy ---

@test "deploy_proxy: creates VHost config file" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  [ -f "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf" ]
}

@test "deploy_proxy: config contains ProxyPass directive" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  grep -q "ProxyPass" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
}

@test "deploy_proxy: config contains ProxyPassReverse directive" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  grep -q "ProxyPassReverse" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
}

@test "deploy_proxy: config contains WebSocket upgrade headers" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  local conf="${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
  grep -q "Upgrade" "$conf"
  grep -q "websocket" "$conf" || grep -q "WebSocket" "$conf" || grep -q "wss" "$conf"
}

@test "deploy_proxy: config contains the backend URL" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:8080"
  grep -q "http://127.0.0.1:8080" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
}

@test "deploy_proxy: config contains security headers" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  local conf="${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
  grep -q "X-Frame-Options" "$conf"
  grep -q "X-Content-Type-Options" "$conf"
  grep -q "X-XSS-Protection" "$conf"
}

@test "deploy_proxy: config contains the domain ServerName" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  grep -q "ServerName.*app.example.com" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
}

@test "deploy_proxy: idempotent (second run overwrites without error)" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:4000"
  [ -f "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf" ]
  # Second run overwrites: new backend URL present, old one absent
  grep -q "http://127.0.0.1:4000" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
  ! grep -q "http://127.0.0.1:3000" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
}

@test "deploy_proxy: config contains ProxyPreserveHost" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  grep -q "ProxyPreserveHost" "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf"
}

# --- dm_remove_proxy ---

@test "remove_proxy: removes proxy VHost config" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  [ -f "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf" ]
  dm_remove_proxy "app.example.com"
  [ ! -f "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf" ]
}

@test "remove_proxy: idempotent (double remove does not fail)" {
  dm_deploy_proxy "app.example.com" "http://127.0.0.1:3000"
  dm_remove_proxy "app.example.com"
  dm_remove_proxy "app.example.com"
  [ ! -f "${APACHE_SITES_DIR}/015-app.example.com-proxy.conf" ]
}
