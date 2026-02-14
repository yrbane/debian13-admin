#!/usr/bin/env bats
# Point 13: Backup distant — backup_remote_config / backup_remote_encrypt / backup_remote_rsync

load test_helper

setup() {
  setup_test_env
  override_paths

  BACKUP_DIR="${TEST_DIR}/backups"
  BACKUP_REMOTE_CONF="${TEST_DIR}/backup-remote.conf"
  mkdir -p "$BACKUP_DIR"

  HOSTNAME_FQDN="main.com"

  # Mock rsync
  rsync_calls="${TEST_DIR}/rsync.log"
  rsync() { echo "$*" >> "$rsync_calls"; return 0; }
  export -f rsync

  # Mock gpg (creates output file)
  gpg_calls="${TEST_DIR}/gpg.log"
  gpg() {
    echo "$*" >> "$gpg_calls"
    # Find --output argument and create the file
    local args=("$@")
    local i
    for (( i=0; i<${#args[@]}; i++ )); do
      if [[ "${args[$i]}" == "--output" || "${args[$i]}" == "-o" ]]; then
        if [[ -n "${args[$((i+1))]:-}" ]]; then
          echo "ENCRYPTED_DATA" > "${args[$((i+1))]}"
        fi
      fi
    done
    return 0
  }
  export -f gpg

  # Mock ssh
  ssh() { return 0; }
  export -f ssh

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- backup_remote_config ---

@test "backup_remote_config: saves remote backup settings to config file" {
  backup_remote_config "backup.remote.com" "/data/backups"
  [ -f "$BACKUP_REMOTE_CONF" ]
}

@test "backup_remote_config: stores BACKUP_REMOTE_HOST" {
  backup_remote_config "backup.remote.com" "/data/backups"
  grep -q "BACKUP_REMOTE_HOST=backup.remote.com" "$BACKUP_REMOTE_CONF"
}

@test "backup_remote_config: stores BACKUP_REMOTE_PATH" {
  backup_remote_config "backup.remote.com" "/data/backups"
  grep -q "BACKUP_REMOTE_PATH=/data/backups" "$BACKUP_REMOTE_CONF"
}

@test "backup_remote_config: supports SSH port override" {
  backup_remote_config "backup.remote.com" "/data/backups" "2222"
  grep -q "BACKUP_REMOTE_PORT=2222" "$BACKUP_REMOTE_CONF" || \
    grep -q "2222" "$BACKUP_REMOTE_CONF"
}

# --- backup_remote_encrypt ---

@test "backup_remote_encrypt: creates GPG-encrypted file" {
  local src="${TEST_DIR}/backups/test-archive.tar.gz"
  echo "backup data" > "$src"
  GPG_RECIPIENT="admin@example.com"

  backup_remote_encrypt "$src"
  [ -f "${src}.gpg" ]
}

@test "backup_remote_encrypt: calls gpg with correct arguments" {
  local src="${TEST_DIR}/backups/test-archive.tar.gz"
  echo "backup data" > "$src"
  GPG_RECIPIENT="admin@example.com"

  backup_remote_encrypt "$src"
  [ -f "$gpg_calls" ]
  grep -q "admin@example.com" "$gpg_calls"
}

@test "backup_remote_encrypt: fails gracefully when no GPG key" {
  local src="${TEST_DIR}/backups/test-archive.tar.gz"
  echo "backup data" > "$src"
  unset GPG_RECIPIENT

  run backup_remote_encrypt "$src"
  # Should not produce a .gpg file or should return non-zero
  [ "$status" -ne 0 ] || [ ! -f "${src}.gpg" ]
}

# --- backup_remote_rsync ---

@test "backup_remote_rsync: calls rsync with correct paths" {
  local src="${TEST_DIR}/backups"
  BACKUP_REMOTE_HOST="backup.remote.com"
  BACKUP_REMOTE_PATH="/data/backups"

  backup_remote_rsync "$src"
  [ -f "$rsync_calls" ]
  grep -q "backup.remote.com" "$rsync_calls"
  grep -q "/data/backups" "$rsync_calls"
}

@test "backup_remote_rsync: supports SSH port override" {
  local src="${TEST_DIR}/backups"
  BACKUP_REMOTE_HOST="backup.remote.com"
  BACKUP_REMOTE_PATH="/data/backups"
  BACKUP_REMOTE_PORT="2222"

  backup_remote_rsync "$src"
  [ -f "$rsync_calls" ]
  grep -q "2222" "$rsync_calls"
}

@test "backup_remote_rsync: uses default SSH port when not specified" {
  local src="${TEST_DIR}/backups"
  BACKUP_REMOTE_HOST="backup.remote.com"
  BACKUP_REMOTE_PATH="/data/backups"
  unset BACKUP_REMOTE_PORT

  backup_remote_rsync "$src"
  [ -f "$rsync_calls" ]
  grep -q "backup.remote.com" "$rsync_calls"
}
