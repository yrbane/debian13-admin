#!/usr/bin/env bats
# Point 4: DKIM key rotation

load test_helper

setup() {
  setup_test_env
  override_paths

  # Mock opendkim-genkey
  opendkim-genkey() {
    local selector="" domain="" dir=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -s) shift; selector="$1" ;;
        -d) shift; domain="$1" ;;
        -D) shift; dir="$1" ;;
      esac
      shift
    done
    mkdir -p "$dir"
    echo "PRIVATE KEY" > "${dir}/${selector}.private"
    echo "${selector}._domainkey IN TXT \"v=DKIM1; k=rsa; p=NEWKEY\"" > "${dir}/${selector}.txt"
  }
  export -f opendkim-genkey

  # Mock chown/chmod that might fail in test env
  chown() { return 0; }
  export -f chown

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_rotate_dkim ---

@test "rotate_dkim: generates new key with dated selector" {
  dm_register_domain "example.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo "OLD KEY" > "${DKIM_KEYDIR}/example.com/mail.private"
  echo "OLD TXT" > "${DKIM_KEYDIR}/example.com/mail.txt"

  run dm_rotate_dkim "example.com"
  [ "$status" -eq 0 ]
  # New selector should have a date component
  local new_sel
  new_sel=$(dm_get_selector "example.com")
  [[ "$new_sel" =~ ^mail[0-9]+ ]]
}

@test "rotate_dkim: preserves old key files" {
  dm_register_domain "example.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo "OLD KEY" > "${DKIM_KEYDIR}/example.com/mail.private"
  echo "OLD TXT" > "${DKIM_KEYDIR}/example.com/mail.txt"

  dm_rotate_dkim "example.com"
  # Old key should still exist
  [ -f "${DKIM_KEYDIR}/example.com/mail.private" ]
}

@test "rotate_dkim: new key files exist" {
  dm_register_domain "example.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo "OLD KEY" > "${DKIM_KEYDIR}/example.com/mail.private"

  dm_rotate_dkim "example.com"
  local new_sel
  new_sel=$(dm_get_selector "example.com")
  [ -f "${DKIM_KEYDIR}/example.com/${new_sel}.private" ]
  [ -f "${DKIM_KEYDIR}/example.com/${new_sel}.txt" ]
}

@test "rotate_dkim: updates domains.conf selector" {
  dm_register_domain "example.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo "OLD KEY" > "${DKIM_KEYDIR}/example.com/mail.private"

  dm_rotate_dkim "example.com"
  local new_sel
  new_sel=$(dm_get_selector "example.com")
  [[ "$new_sel" != "mail" ]]
  grep -q "^example.com:${new_sel}$" "$DOMAINS_CONF"
}

@test "rotate_dkim: fails for unregistered domain" {
  run dm_rotate_dkim "unknown.com"
  [ "$status" -ne 0 ]
}

@test "rotate_dkim: works with custom initial selector" {
  dm_register_domain "test.org" "dkim2024"
  mkdir -p "${DKIM_KEYDIR}/test.org"
  echo "OLD KEY" > "${DKIM_KEYDIR}/test.org/dkim2024.private"

  dm_rotate_dkim "test.org"
  local new_sel
  new_sel=$(dm_get_selector "test.org")
  [[ "$new_sel" =~ ^dkim2024r[0-9]+ ]] || [[ "$new_sel" =~ ^mail[0-9]+ ]]
  [ -f "${DKIM_KEYDIR}/test.org/${new_sel}.private" ]
}
