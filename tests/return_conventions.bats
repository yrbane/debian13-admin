#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
}

teardown() { teardown_test_env; }

# --- require_root ---

@test "require_root: fails when not root" {
  run bash -c '
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/constants.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/helpers.sh"
    EUID=1000
    require_root
  '
  [ "$status" -ne 0 ]
}

# --- load_config: returns non-zero on bad config ---

@test "load_config: returns non-zero on bad config" {
  local conf="${TEST_DIR}/test.conf"
  echo 'GOOD_VAR="value"' > "$conf"
  echo 'BAD_LINE=$(whoami)' >> "$conf"

  CONFIG_FILE="$conf"
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/constants.sh"
  source "${BATS_TEST_DIRNAME}/../lib/config.sh"

  run load_config
  [ "$status" -ne 0 ]
}

# --- save_config: returns 1 on write failure ---

@test "save_config: returns 1 when output path is unwritable" {
  CONFIG_FILE="${TEST_DIR}/nonexistent_dir/test.conf"
  CONFIG_VARS=()

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/constants.sh"
  source "${BATS_TEST_DIRNAME}/../lib/config.sh"

  run save_config
  [ "$status" -ne 0 ]
}

# --- ovh-api.sh: error on stderr, not stdout ---

@test "ovh_api: error output goes to stderr only" {
  export OVH_DNS_CREDENTIALS="${TEST_DIR}/ovh-dns.ini"
  cat > "$OVH_DNS_CREDENTIALS" <<'EOF'
dns_ovh_endpoint = ovh-eu
dns_ovh_application_key = AK123
dns_ovh_application_secret = AS456
dns_ovh_consumer_key = CK789
EOF

  _OVH_AK="" ; _OVH_AS="" ; _OVH_CK="" ; _OVH_EP=""
  export CURL_LOG="${TEST_DIR}/curl_calls.log"
  : > "$CURL_LOG"
  curl() {
    echo "$*" >> "$CURL_LOG"
    if [[ "$*" == *"/auth/time"* ]]; then echo "1700000000"; return 0; fi
    echo '{"class":"Client::Forbidden","message":"denied"}'
    return 0
  }
  export -f curl

  source "${BATS_TEST_DIRNAME}/../lib/ovh-api.sh"
  local stdout
  stdout=$(ovh_api GET "/test" 2>/dev/null) || true
  [ -z "$stdout" ]
}

# --- _ovh_load_creds: returns 1 on missing file ---

@test "ovh_load_creds: returns 1 on missing credentials" {
  OVH_DNS_CREDENTIALS="${TEST_DIR}/nonexistent.ini"
  _OVH_AK="" ; _OVH_AS="" ; _OVH_CK="" ; _OVH_EP=""
  curl() { :; }
  export -f curl

  source "${BATS_TEST_DIRNAME}/../lib/ovh-api.sh"
  run _ovh_load_creds
  [ "$status" -eq 1 ]
}

# --- dm_dns_upsert: propagates error codes ---

@test "dm_dns_upsert: returns 1 when create fails" {
  ovh_dns_find()   { echo ""; return 0; }
  ovh_dns_create() { return 1; }
  ovh_dns_update() { return 0; }

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  run dm_dns_upsert "example.com" "www" "A" '"1.2.3.4"'
  [ "$status" -ne 0 ]
}

@test "dm_dns_upsert: returns 1 when update fails" {
  ovh_dns_find()   { echo "42"; return 0; }
  ovh_dns_create() { return 0; }
  ovh_dns_update() { return 1; }

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  run dm_dns_upsert "example.com" "www" "A" '"1.2.3.4"'
  [ "$status" -ne 0 ]
}

@test "dm_dns_upsert: returns 0 on success" {
  ovh_dns_find()   { echo ""; return 0; }
  ovh_dns_create() { return 0; }
  ovh_dns_update() { return 0; }

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  dm_dns_upsert "example.com" "www" "A" '"1.2.3.4"'
}

@test "dm_dns_upsert: idempotent (updates if record exists)" {
  local create_count=0 update_count=0
  ovh_dns_find()   { echo "42"; return 0; }
  ovh_dns_create() { ((++create_count)); return 0; }
  ovh_dns_update() { ((++update_count)); return 0; }

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  dm_dns_upsert "example.com" "www" "A" '"1.2.3.4"'
  [ "$create_count" -eq 0 ]
  [ "$update_count" -eq 1 ]
}

# --- dm_obtain_ssl: propagates certbot exit code ---

@test "dm_obtain_ssl: returns 0 on certbot success" {
  OVH_DNS_CREDENTIALS="${TEST_DIR}/nonexistent.ini"
  EMAIL_FOR_CERTBOT="test@test.com"
  certbot() { return 0; }
  export -f certbot

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  dm_obtain_ssl "example.com"
}

@test "dm_obtain_ssl: returns 1 on certbot failure" {
  OVH_DNS_CREDENTIALS="${TEST_DIR}/nonexistent.ini"
  EMAIL_FOR_CERTBOT="test@test.com"
  certbot() { return 1; }
  export -f certbot

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  run dm_obtain_ssl "example.com"
  [ "$status" -ne 0 ]
}

# --- dm_unregister_domain: handles errors ---

@test "dm_unregister_domain: succeeds when domain exists" {
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.com" "mail"
  dm_unregister_domain "a.com"
  run dm_domain_exists "a.com"
  [ "$status" -eq 1 ]
  dm_domain_exists "b.com"
}

@test "dm_unregister_domain: succeeds when domain not present" {
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
  dm_unregister_domain "nonexistent.com"
}
