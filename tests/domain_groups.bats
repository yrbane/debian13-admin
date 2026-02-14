#!/usr/bin/env bats
# Point 22: Domain groups

load test_helper

setup() {
  setup_test_env
  override_paths
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_set_group / dm_get_group / dm_list_group ---

@test "set_group: assigns domain to group" {
  dm_register_domain "a.com" "mail"
  dm_set_group "a.com" "production"
  run dm_get_group "a.com"
  [ "$output" = "production" ]
}

@test "set_group: multiple domains in same group" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.com" "mail"
  dm_set_group "a.com" "prod"
  dm_set_group "b.com" "prod"
  run dm_list_group "prod"
  [[ "$output" == *"a.com"* ]]
  [[ "$output" == *"b.com"* ]]
}

@test "list_group: returns only domains in that group" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.com" "mail"
  dm_register_domain "c.com" "mail"
  dm_set_group "a.com" "prod"
  dm_set_group "b.com" "staging"
  dm_set_group "c.com" "prod"
  run dm_list_group "prod"
  [[ "$output" == *"a.com"* ]]
  [[ "$output" == *"c.com"* ]]
  [[ "$output" != *"b.com"* ]]
}

@test "list_group: returns empty for unknown group" {
  run dm_list_group "nonexistent"
  [ -z "$output" ]
}

@test "get_group: returns empty for domain without group" {
  dm_register_domain "a.com" "mail"
  run dm_get_group "a.com"
  [ -z "$output" ]
}

@test "set_group: can change group" {
  dm_register_domain "a.com" "mail"
  dm_set_group "a.com" "staging"
  dm_set_group "a.com" "production"
  run dm_get_group "a.com"
  [ "$output" = "production" ]
}

@test "dm_list_groups: lists all distinct groups" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.com" "mail"
  dm_register_domain "c.com" "mail"
  dm_set_group "a.com" "prod"
  dm_set_group "b.com" "staging"
  dm_set_group "c.com" "prod"
  run dm_list_groups
  [ "${#lines[@]}" -eq 2 ]
  [[ "$output" == *"prod"* ]]
  [[ "$output" == *"staging"* ]]
}
