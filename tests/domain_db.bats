#!/usr/bin/env bats
# Point 10: Per-domain database — dm_create_database / dm_drop_database / dm_list_databases

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"

  # Mock mysql: log all calls to a file
  mysql_calls="${TEST_DIR}/mysql.log"
  mysql() { echo "$*" >> "$mysql_calls"; return 0; }
  export -f mysql

  # Mock pwgen / openssl for random password generation
  pwgen() { echo "R4nd0mP4ssw0rd"; }
  export -f pwgen
  # Ensure openssl rand fallback also works
  openssl() {
    if [[ "$1" == "rand" ]]; then
      echo "R4nd0mP4ssw0rd"
      return 0
    fi
    command openssl "$@"
  }
  export -f openssl

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_create_database ---

@test "create_database: calls mysql to create database" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  [ -f "$mysql_calls" ]
  grep -qi "CREATE DATABASE" "$mysql_calls"
}

@test "create_database: calls mysql to create user" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  grep -qi "CREATE USER\|GRANT" "$mysql_calls"
}

@test "create_database: DB name derived from domain (dots to underscores)" {
  dm_register_domain "my.example.com" "mail"
  dm_create_database "my.example.com"
  grep -q "my_example_com" "$mysql_calls"
}

@test "create_database: stores password in per-domain config" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  run dm_get_domain_config "example.com" "DB_PASSWORD"
  [ -n "$output" ]
}

@test "create_database: stores DB name in per-domain config" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  run dm_get_domain_config "example.com" "DB_NAME"
  [ -n "$output" ]
  [[ "$output" == *"example_com"* ]]
}

@test "create_database: stores DB user in per-domain config" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  run dm_get_domain_config "example.com" "DB_USER"
  [ -n "$output" ]
}

@test "create_database: idempotent (second run does not fail)" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  dm_create_database "example.com"
  [ -f "$mysql_calls" ]
}

# --- dm_drop_database ---

@test "drop_database: calls mysql to drop database" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  : > "$mysql_calls"
  dm_drop_database "example.com"
  grep -qi "DROP DATABASE\|DROP USER" "$mysql_calls"
}

@test "drop_database: calls mysql to drop user" {
  dm_register_domain "example.com" "mail"
  dm_create_database "example.com"
  : > "$mysql_calls"
  dm_drop_database "example.com"
  grep -qi "DROP USER" "$mysql_calls"
}

# --- dm_list_databases ---

@test "list_databases: returns registered databases" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.com" "mail"
  dm_create_database "a.com"
  dm_create_database "b.com"
  run dm_list_databases
  [[ "$output" == *"a_com"* ]]
  [[ "$output" == *"b_com"* ]]
}

@test "list_databases: returns empty when no databases created" {
  run dm_list_databases
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}
