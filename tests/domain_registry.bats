#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_extract_base_domain ---
@test "extract_base_domain: apex domain returns itself" {
  run dm_extract_base_domain "example.com"
  [ "$status" -eq 0 ]
  [ "$output" = "example.com" ]
}

@test "extract_base_domain: subdomain returns parent" {
  run dm_extract_base_domain "srv.example.com"
  [ "$status" -eq 0 ]
  [ "$output" = "example.com" ]
}

@test "extract_base_domain: deep subdomain returns TLD+1" {
  run dm_extract_base_domain "a.b.example.com"
  [ "$status" -eq 0 ]
  [ "$output" = "example.com" ]
}

@test "extract_base_domain: co.uk style TLD not special-cased" {
  run dm_extract_base_domain "foo.co.uk"
  [ "$status" -eq 0 ]
  [ "$output" = "co.uk" ]
}

# --- dm_register_domain / dm_list_domains / dm_domain_exists ---
@test "register_domain: creates file and adds entry" {
  dm_register_domain "example.com" "mail"
  [ -f "$DOMAINS_CONF" ]
  grep -q "^example.com:mail$" "$DOMAINS_CONF"
}

@test "register_domain: idempotent (no duplicate)" {
  dm_register_domain "example.com" "mail"
  dm_register_domain "example.com" "mail"
  [ "$(grep -c 'example.com' "$DOMAINS_CONF")" -eq 1 ]
}

@test "register_domain: default selector is mail" {
  dm_register_domain "test.org"
  grep -q "^test.org:mail$" "$DOMAINS_CONF"
}

@test "list_domains: returns registered domains" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.org" "dkim"
  run dm_list_domains
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "a.com:mail" ]
  [ "${lines[1]}" = "b.org:dkim" ]
}

@test "list_domains: skips comments and empty lines" {
  echo "# comment" > "$DOMAINS_CONF"
  echo "" >> "$DOMAINS_CONF"
  echo "real.com:mail" >> "$DOMAINS_CONF"
  run dm_list_domains
  [ "${#lines[@]}" -eq 1 ]
  [ "${lines[0]}" = "real.com:mail" ]
}

@test "list_domains: empty file returns nothing" {
  touch "$DOMAINS_CONF"
  run dm_list_domains
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 0 ]
}

@test "list_domains: no file returns nothing" {
  run dm_list_domains
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 0 ]
}

@test "domain_exists: returns 0 for registered domain" {
  dm_register_domain "exists.com" "mail"
  dm_domain_exists "exists.com"
}

@test "domain_exists: returns 1 for unknown domain" {
  run dm_domain_exists "nope.com"
  [ "$status" -eq 1 ]
}

# --- dm_unregister_domain ---
@test "unregister_domain: removes entry" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.com" "mail"
  dm_unregister_domain "a.com"
  run dm_domain_exists "a.com"
  [ "$status" -eq 1 ]
  dm_domain_exists "b.com"
}

@test "unregister_domain: no-op if domain not present" {
  dm_register_domain "a.com" "mail"
  dm_unregister_domain "nonexistent.com"
  dm_domain_exists "a.com"
}

# --- dm_get_selector ---
@test "get_selector: returns correct selector" {
  dm_register_domain "test.com" "dkim2024"
  run dm_get_selector "test.com"
  [ "$status" -eq 0 ]
  [ "$output" = "dkim2024" ]
}

@test "get_selector: returns empty for unknown domain" {
  run dm_get_selector "unknown.com"
  [ -z "$output" ]
}
