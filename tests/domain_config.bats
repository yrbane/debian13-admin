#!/usr/bin/env bats
# Point 20: Per-domain configuration

load test_helper

setup() {
  setup_test_env
  override_paths
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_set_domain_config / dm_get_domain_config ---

@test "set_domain_config: creates config file" {
  dm_register_domain "example.com" "mail"
  dm_set_domain_config "example.com" "PHP_VERSION" "8.3"
  [ -f "${DOMAINS_CONF_DIR}/example.com.conf" ]
}

@test "get_domain_config: returns stored value" {
  dm_register_domain "example.com" "mail"
  dm_set_domain_config "example.com" "PHP_VERSION" "8.3"
  run dm_get_domain_config "example.com" "PHP_VERSION"
  [ "$output" = "8.3" ]
}

@test "get_domain_config: returns default when key missing" {
  dm_register_domain "example.com" "mail"
  run dm_get_domain_config "example.com" "MISSING_KEY" "default_val"
  [ "$output" = "default_val" ]
}

@test "get_domain_config: returns empty when no default and key missing" {
  dm_register_domain "example.com" "mail"
  run dm_get_domain_config "example.com" "MISSING_KEY"
  [ -z "$output" ]
}

@test "set_domain_config: updates existing key" {
  dm_register_domain "example.com" "mail"
  dm_set_domain_config "example.com" "PHP_VERSION" "8.2"
  dm_set_domain_config "example.com" "PHP_VERSION" "8.3"
  run dm_get_domain_config "example.com" "PHP_VERSION"
  [ "$output" = "8.3" ]
  # No duplicates
  [ "$(grep -c 'PHP_VERSION' "${DOMAINS_CONF_DIR}/example.com.conf")" -eq 1 ]
}

@test "set_domain_config: supports multiple keys" {
  dm_register_domain "example.com" "mail"
  dm_set_domain_config "example.com" "PHP_VERSION" "8.3"
  dm_set_domain_config "example.com" "SSL_TYPE" "wildcard"
  run dm_get_domain_config "example.com" "PHP_VERSION"
  [ "$output" = "8.3" ]
  run dm_get_domain_config "example.com" "SSL_TYPE"
  [ "$output" = "wildcard" ]
}

@test "get_domain_config: returns empty for unregistered domain" {
  run dm_get_domain_config "unknown.com" "PHP_VERSION"
  [ -z "$output" ]
}

@test "dm_list_domain_config: lists all keys for domain" {
  dm_register_domain "example.com" "mail"
  dm_set_domain_config "example.com" "PHP_VERSION" "8.3"
  dm_set_domain_config "example.com" "SSL_TYPE" "wildcard"
  run dm_list_domain_config "example.com"
  [[ "$output" == *"PHP_VERSION=8.3"* ]]
  [[ "$output" == *"SSL_TYPE=wildcard"* ]]
}
