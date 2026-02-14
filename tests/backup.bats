#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  BACKUP_DIR="${TEST_DIR}/backups"
  HOSTNAME_FQDN="test.example.com"
  SCRIPTS_DIR="${BATS_TEST_DIRNAME}/.."
  DKIM_KEYDIR="${TEST_DKIM_KEYDIR}"
  DOMAINS_CONF="$TEST_DOMAINS_CONF"

  # Mock system commands
  mysqldump() { echo "-- SQL dump"; return 0; }
  export -f mysqldump
  systemctl() { return 0; }
  export -f systemctl

  # Source core.sh for logging; skip constants.sh (readonly conflicts with override_paths)
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  SECONDS_PER_DAY=86400
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  source "${BATS_TEST_DIRNAME}/../lib/backup.sh"
}

teardown() { teardown_test_env; }

# --- backup_init ---

@test "backup_init: creates backup directory with date" {
  backup_init
  [ -d "$BACKUP_DEST" ]
  [[ "$BACKUP_DEST" == "${BACKUP_DIR}/"* ]]
}

@test "backup_init: creates backup dir if missing" {
  rmdir "$BACKUP_DIR" 2>/dev/null || true
  backup_init
  [ -d "$BACKUP_DEST" ]
}

# --- backup_configs ---

@test "backup_configs: copies config file" {
  local conf="${TEST_DIR}/server.conf"
  echo "TEST_VAR=true" > "$conf"
  CONFIG_FILE="$conf"

  backup_init
  backup_configs
  [ -f "${BACKUP_DEST}/configs/server.conf" ]
}

@test "backup_configs: copies domains.conf if exists" {
  echo "example.com:mail" > "$DOMAINS_CONF"
  CONFIG_FILE="${TEST_DIR}/server.conf"
  echo "x=1" > "$CONFIG_FILE"

  backup_init
  backup_configs
  [ -f "${BACKUP_DEST}/configs/domains.conf" ]
}

@test "backup_configs: skips missing config file" {
  CONFIG_FILE="${TEST_DIR}/nonexistent.conf"
  backup_init
  backup_configs
  # Should not fail
}

# --- backup_dkim ---

@test "backup_dkim: copies DKIM keys" {
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo "private key" > "${DKIM_KEYDIR}/example.com/mail.private"
  echo "public key" > "${DKIM_KEYDIR}/example.com/mail.txt"

  backup_init
  backup_dkim
  [ -f "${BACKUP_DEST}/dkim/example.com/mail.private" ]
  [ -f "${BACKUP_DEST}/dkim/example.com/mail.txt" ]
}

@test "backup_dkim: skips when no DKIM directory" {
  DKIM_KEYDIR="${TEST_DIR}/nonexistent/keys"
  backup_init
  backup_dkim
  # Should not fail
}

# --- backup_mariadb ---

@test "backup_mariadb: creates SQL dump" {
  backup_init
  backup_mariadb
  [ -f "${BACKUP_DEST}/mariadb/all-databases.sql.gz" ]
}

@test "backup_mariadb: skips when mysqldump not available" {
  unset -f mysqldump
  mysqldump() { return 127; }
  export -f mysqldump

  backup_init
  backup_mariadb
  # Should not fail, just warn
}

# --- backup_crontab ---

@test "backup_crontab: saves root crontab" {
  crontab() { echo "0 2 * * * /root/scripts/clamav_scan.sh"; return 0; }
  export -f crontab

  backup_init
  backup_crontab
  [ -f "${BACKUP_DEST}/crontab/root.crontab" ]
  grep -q "clamav_scan" "${BACKUP_DEST}/crontab/root.crontab"
}

# --- backup_list ---

@test "backup_list: lists available backups" {
  backup_init
  echo "test" > "${BACKUP_DEST}/marker.txt"
  run backup_list
  [[ "$output" == *"$(date +%Y)"* ]]
}

@test "backup_list: returns empty when no backups" {
  run backup_list
  [ "$status" -eq 0 ]
}

# --- backup_cleanup ---

@test "backup_cleanup: removes old backups beyond retention" {
  BACKUP_RETENTION_DAYS=0

  mkdir -p "${BACKUP_DIR}/2020-01-01_120000"
  touch "${BACKUP_DIR}/2020-01-01_120000/test.txt"

  backup_cleanup
  [ ! -d "${BACKUP_DIR}/2020-01-01_120000" ]
}

@test "backup_cleanup: keeps recent backups" {
  BACKUP_RETENTION_DAYS=999

  backup_init
  echo "test" > "${BACKUP_DEST}/marker.txt"
  local dest="$BACKUP_DEST"

  backup_cleanup
  [ -d "$dest" ]
}
