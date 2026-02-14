#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  OVH_CALLS=()
  ovh_dns_find()    { echo ""; }
  ovh_dns_create()  { OVH_CALLS+=("CREATE:$*"); return 0; }
  ovh_dns_update()  { OVH_CALLS+=("UPDATE:$*"); return 0; }
  ovh_dns_refresh() { OVH_CALLS+=("REFRESH:$1"); return 0; }

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_generate_tlsa_record ---

@test "generate_tlsa: extracts hash from certificate" {
  # Create a test certificate (self-signed)
  local certdir="${TEST_DIR}/certs"
  mkdir -p "$certdir"
  openssl req -x509 -newkey rsa:2048 -keyout "${certdir}/key.pem" \
    -out "${certdir}/cert.pem" -days 1 -nodes -subj "/CN=test.com" 2>/dev/null

  run dm_generate_tlsa_record "${certdir}/cert.pem"
  [ "$status" -eq 0 ]
  # TLSA record format: usage selector matching-type hash
  # We use 3 1 1 (DANE-EE, SPKI, SHA-256)
  [[ "$output" =~ ^3\ 1\ 1\  ]]
}

@test "generate_tlsa: hash is 64 hex characters (SHA-256)" {
  local certdir="${TEST_DIR}/certs"
  mkdir -p "$certdir"
  openssl req -x509 -newkey rsa:2048 -keyout "${certdir}/key.pem" \
    -out "${certdir}/cert.pem" -days 1 -nodes -subj "/CN=test.com" 2>/dev/null

  run dm_generate_tlsa_record "${certdir}/cert.pem"
  local hash
  hash=$(echo "$output" | awk '{print $4}')
  [ "${#hash}" -eq 64 ]
}

@test "generate_tlsa: fails on missing certificate" {
  run dm_generate_tlsa_record "/nonexistent/cert.pem"
  [ "$status" -eq 1 ]
}

# --- dm_setup_tlsa ---

@test "setup_tlsa: creates TLSA record via OVH API" {
  local certdir="${TEST_DIR}/certs"
  mkdir -p "$certdir"
  openssl req -x509 -newkey rsa:2048 -keyout "${certdir}/key.pem" \
    -out "${certdir}/cert.pem" -days 1 -nodes -subj "/CN=example.com" 2>/dev/null

  LETSENCRYPT_LIVE="${TEST_DIR}/letsencrypt/live"
  mkdir -p "${LETSENCRYPT_LIVE}/example.com"
  cp "${certdir}/cert.pem" "${LETSENCRYPT_LIVE}/example.com/cert.pem"

  # Use file-based tracking (run creates subshell)
  local log_file="${TEST_DIR}/ovh_calls.log"
  ovh_dns_find()    { echo ""; }
  ovh_dns_create()  { echo "CREATE:$*" >> "${TEST_DIR}/ovh_calls.log"; return 0; }
  ovh_dns_refresh() { return 0; }

  dm_register_domain "example.com" "mail"

  dm_setup_tlsa "example.com"
  [ -f "$log_file" ]
  grep -q "TLSA" "$log_file"
}

@test "setup_tlsa: creates record for _25._tcp subdomain" {
  local certdir="${TEST_DIR}/certs"
  mkdir -p "$certdir"
  openssl req -x509 -newkey rsa:2048 -keyout "${certdir}/key.pem" \
    -out "${certdir}/cert.pem" -days 1 -nodes -subj "/CN=example.com" 2>/dev/null

  LETSENCRYPT_LIVE="${TEST_DIR}/letsencrypt/live"
  mkdir -p "${LETSENCRYPT_LIVE}/example.com"
  cp "${certdir}/cert.pem" "${LETSENCRYPT_LIVE}/example.com/cert.pem"

  dm_register_domain "example.com" "mail"

  dm_setup_tlsa "example.com"
  local found=false
  for call in "${OVH_CALLS[@]:-}"; do
    [[ "$call" == *"_25._tcp"* ]] && found=true
  done
  $found
}

@test "setup_tlsa: skips when no certificate" {
  LETSENCRYPT_LIVE="${TEST_DIR}/letsencrypt/live"
  # No cert exists

  run dm_setup_tlsa "nocert.com"
  [ "$status" -eq 0 ]
  # No OVH calls made
  [ "${#OVH_CALLS[@]}" -eq 0 ]
}
