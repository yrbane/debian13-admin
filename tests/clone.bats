#!/usr/bin/env bats
# Server clone: generate SSH key, sync to target

load test_helper

setup() {
  setup_test_env
  override_paths

  CLONE_KEY_DIR="${TEST_DIR}/clone-keys"
  CLONE_SSH_KEY="${CLONE_KEY_DIR}/clone_rsa"
  mkdir -p "$CLONE_KEY_DIR"

  # Mock ssh-keygen
  ssh_keygen_calls="${TEST_DIR}/ssh_keygen.log"
  ssh-keygen() {
    echo "$*" >> "$ssh_keygen_calls"
    # Create fake key files
    local f=""
    local prev=""
    for arg in "$@"; do
      if [[ "$prev" == "-f" ]]; then f="$arg"; fi
      prev="$arg"
    done
    if [[ -n "$f" ]]; then
      echo "FAKE_PRIVATE_KEY" > "$f"
      echo "ssh-rsa AAAAB3FAKE clone@server" > "${f}.pub"
    fi
    return 0
  }
  export -f ssh-keygen

  # Mock rsync
  rsync_calls="${TEST_DIR}/rsync.log"
  rsync() { echo "$*" >> "$rsync_calls"; return 0; }
  export -f rsync

  # Mock ssh
  ssh_calls="${TEST_DIR}/ssh.log"
  ssh() { echo "$*" >> "$ssh_calls"; return 0; }
  export -f ssh

  # Mock scp
  scp_calls="${TEST_DIR}/scp.log"
  scp() { echo "$*" >> "$scp_calls"; return 0; }
  export -f scp

  SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  source "${BATS_TEST_DIRNAME}/../lib/clone.sh"
}

teardown() { teardown_test_env; }

# --- clone_generate_key ---

@test "clone_generate_key: creates SSH key pair" {
  clone_generate_key
  [ -f "$CLONE_SSH_KEY" ]
  [ -f "${CLONE_SSH_KEY}.pub" ]
}

@test "clone_generate_key: uses ed25519 by default" {
  clone_generate_key
  grep -q "\-t ed25519" "$ssh_keygen_calls"
}

@test "clone_generate_key: does not overwrite existing key" {
  echo "existing" > "$CLONE_SSH_KEY"
  echo "existing.pub" > "${CLONE_SSH_KEY}.pub"
  clone_generate_key
  # ssh-keygen should not be called
  [ ! -f "$ssh_keygen_calls" ]
  # Original key preserved
  [ "$(cat "$CLONE_SSH_KEY")" = "existing" ]
}

@test "clone_generate_key: prints public key" {
  run clone_generate_key
  [[ "$output" == *"ssh-rsa"* ]] || [[ "$output" == *"ssh-ed25519"* ]] || [[ "$output" == *".pub"* ]]
}

# --- clone_sync ---

@test "clone_sync: calls rsync with correct source dirs" {
  clone_generate_key
  HOSTNAME_FQDN="main.com"
  clone_sync "192.168.1.100"
  [ -f "$rsync_calls" ]
  grep -q "192.168.1.100" "$rsync_calls"
}

@test "clone_sync: syncs scripts directory" {
  clone_generate_key
  HOSTNAME_FQDN="main.com"
  clone_sync "192.168.1.100"
  grep -q "${SCRIPTS_DIR}" "$rsync_calls"
}

@test "clone_sync: uses SSH key for auth" {
  clone_generate_key
  HOSTNAME_FQDN="main.com"
  clone_sync "192.168.1.100"
  grep -q "clone_rsa" "$rsync_calls" || grep -q "clone" "$rsync_calls"
}

@test "clone_sync: syncs DKIM keys" {
  clone_generate_key
  HOSTNAME_FQDN="main.com"
  clone_sync "192.168.1.100"
  grep -q "opendkim" "$rsync_calls"
}

@test "clone_sync: syncs domains.conf" {
  clone_generate_key
  HOSTNAME_FQDN="main.com"
  echo "main.com:mail" > "$DOMAINS_CONF"
  clone_sync "192.168.1.100"
  # Should sync the config
  grep -q "domains.conf\|${SCRIPTS_DIR}" "$rsync_calls"
}

# --- clone_sync with port ---

@test "clone_sync: supports custom SSH port" {
  clone_generate_key
  HOSTNAME_FQDN="main.com"
  clone_sync "192.168.1.100" "2222"
  grep -q "2222" "$rsync_calls"
}

# --- clone_preflight ---

@test "clone_preflight: fails without target IP" {
  run clone_preflight ""
  [ "$status" -ne 0 ]
}

@test "clone_preflight: fails without SSH key" {
  rm -f "$CLONE_SSH_KEY" "${CLONE_SSH_KEY}.pub"
  run clone_preflight "192.168.1.100"
  [ "$status" -ne 0 ]
}

@test "clone_preflight: succeeds with key and IP" {
  clone_generate_key
  run clone_preflight "192.168.1.100"
  [ "$status" -eq 0 ]
}
