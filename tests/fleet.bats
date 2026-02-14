#!/usr/bin/env bats
# Point 7: Fleet management (multi-server)

load test_helper

setup() {
  setup_test_env
  override_paths
  FLEET_CONF="${TEST_DIR}/fleet.conf"
  CLONE_SSH_KEY="${TEST_DIR}/clone_rsa"
  echo "FAKE KEY" > "$CLONE_SSH_KEY"

  # Mock ssh
  ssh() { echo "SSH:$*" >> "${TEST_DIR}/ssh.log"; echo "ok"; return 0; }
  export -f ssh

  # Mock rsync
  rsync() { echo "RSYNC:$*" >> "${TEST_DIR}/rsync.log"; return 0; }
  export -f rsync

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  source "${BATS_TEST_DIRNAME}/../lib/fleet.sh"
}

teardown() { teardown_test_env; }

# --- fleet_add / fleet_list / fleet_remove ---

@test "fleet_add: adds server to fleet.conf" {
  fleet_add "web1" "192.168.1.10" "22"
  [ -f "$FLEET_CONF" ]
  grep -q "web1:192.168.1.10:22" "$FLEET_CONF"
}

@test "fleet_add: default port is 22" {
  fleet_add "web2" "10.0.0.5"
  grep -q "web2:10.0.0.5:22" "$FLEET_CONF"
}

@test "fleet_add: idempotent" {
  fleet_add "web1" "192.168.1.10" "22"
  fleet_add "web1" "192.168.1.10" "22"
  [ "$(grep -c 'web1' "$FLEET_CONF")" -eq 1 ]
}

@test "fleet_list: returns registered servers" {
  fleet_add "web1" "192.168.1.10" "22"
  fleet_add "db1" "192.168.1.20" "2222"
  run fleet_list
  [ "${#lines[@]}" -eq 2 ]
  [[ "${lines[0]}" == *"web1"* ]]
  [[ "${lines[1]}" == *"db1"* ]]
}

@test "fleet_list: empty when no servers" {
  run fleet_list
  [ -z "$output" ]
}

@test "fleet_remove: removes server" {
  fleet_add "web1" "192.168.1.10" "22"
  fleet_add "web2" "192.168.1.20" "22"
  fleet_remove "web1"
  run fleet_list
  [ "${#lines[@]}" -eq 1 ]
  [[ "$output" != *"web1"* ]]
}

# --- fleet_exec ---

@test "fleet_exec: runs command on all servers" {
  fleet_add "web1" "192.168.1.10" "22"
  fleet_add "web2" "192.168.1.20" "2222"
  fleet_exec "uptime"
  [ -f "${TEST_DIR}/ssh.log" ]
  grep -q "192.168.1.10" "${TEST_DIR}/ssh.log"
  grep -q "192.168.1.20" "${TEST_DIR}/ssh.log"
}

@test "fleet_exec: uses correct SSH port" {
  fleet_add "srv" "10.0.0.1" "65222"
  fleet_exec "hostname"
  grep -q "65222" "${TEST_DIR}/ssh.log"
}

# --- fleet_status ---

@test "fleet_status: reports status for all servers" {
  fleet_add "web1" "192.168.1.10" "22"
  run fleet_status
  [[ "$output" == *"web1"* ]]
}

@test "fleet_status: handles empty fleet" {
  run fleet_status
  [ "$status" -eq 0 ]
}
