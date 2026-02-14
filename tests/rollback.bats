#!/usr/bin/env bats
# Point 3: Rollback automatique (snapshots)

load test_helper

setup() {
  setup_test_env
  override_paths
  SNAPSHOT_DIR="${TEST_DIR}/snapshots"
  mkdir -p "$SNAPSHOT_DIR"
  HOSTNAME_FQDN="main.com"
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- snapshot_create ---

@test "snapshot_create: creates snapshot directory with timestamp" {
  run snapshot_create "test-snap"
  [ "$status" -eq 0 ]
  local count
  count=$(ls -1 "$SNAPSHOT_DIR" | wc -l)
  [ "$count" -ge 1 ]
}

@test "snapshot_create: snapshot name contains label" {
  snapshot_create "before-domain-add"
  local snap
  snap=$(ls -1 "$SNAPSHOT_DIR" | head -1)
  [[ "$snap" == *"before-domain-add"* ]]
}

@test "snapshot_create: backs up domains.conf" {
  echo "test.com:mail" > "$DOMAINS_CONF"
  snapshot_create "test"
  local snap
  snap=$(ls -1d "$SNAPSHOT_DIR"/*/ | head -1)
  [ -f "${snap}domains.conf" ]
  grep -q "test.com" "${snap}domains.conf"
}

@test "snapshot_create: backs up apache sites" {
  echo "VHost test" > "${APACHE_SITES_DIR}/010-test.com.conf"
  snapshot_create "test"
  local snap
  snap=$(ls -1d "$SNAPSHOT_DIR"/*/ | head -1)
  [ -f "${snap}apache/010-test.com.conf" ]
}

@test "snapshot_create: backs up logrotate configs" {
  echo "logrotate test" > "${LOGROTATE_DIR}/apache-vhost-test.com"
  snapshot_create "test"
  local snap
  snap=$(ls -1d "$SNAPSHOT_DIR"/*/ | head -1)
  [ -f "${snap}logrotate/apache-vhost-test.com" ]
}

@test "snapshot_create: returns snapshot ID" {
  run snapshot_create "mysnap"
  [ "$status" -eq 0 ]
  [ -n "$output" ]
}

# --- snapshot_list ---

@test "snapshot_list: lists available snapshots" {
  snapshot_create "first"
  snapshot_create "second"
  run snapshot_list
  [ "${#lines[@]}" -ge 2 ]
}

@test "snapshot_list: empty when no snapshots" {
  run snapshot_list
  [ -z "$output" ]
}

# --- snapshot_restore ---

@test "snapshot_restore: restores domains.conf" {
  echo "original.com:mail" > "$DOMAINS_CONF"
  snapshot_create "before-change"
  local snap_id
  snap_id=$(ls -1 "$SNAPSHOT_DIR" | head -1)

  # Modify state
  echo "changed.com:mail" > "$DOMAINS_CONF"

  snapshot_restore "$snap_id"
  grep -q "original.com" "$DOMAINS_CONF"
  ! grep -q "changed.com" "$DOMAINS_CONF"
}

@test "snapshot_restore: restores apache configs" {
  echo "Original VHost" > "${APACHE_SITES_DIR}/010-test.com.conf"
  snapshot_create "before"
  local snap_id
  snap_id=$(ls -1 "$SNAPSHOT_DIR" | head -1)

  echo "Modified VHost" > "${APACHE_SITES_DIR}/010-test.com.conf"
  snapshot_restore "$snap_id"
  grep -q "Original" "${APACHE_SITES_DIR}/010-test.com.conf"
}

@test "snapshot_restore: fails on invalid snapshot ID" {
  run snapshot_restore "nonexistent-snap"
  [ "$status" -ne 0 ]
}

@test "snapshot_restore: restores logrotate configs" {
  echo "Original logrotate" > "${LOGROTATE_DIR}/apache-vhost-test.com"
  snapshot_create "before"
  local snap_id
  snap_id=$(ls -1 "$SNAPSHOT_DIR" | head -1)

  echo "Changed logrotate" > "${LOGROTATE_DIR}/apache-vhost-test.com"
  snapshot_restore "$snap_id"
  grep -q "Original" "${LOGROTATE_DIR}/apache-vhost-test.com"
}
