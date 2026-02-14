#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  # Create fake credentials file
  OVH_DNS_CREDENTIALS="${TEST_DIR}/ovh-dns.ini"
  cat > "$OVH_DNS_CREDENTIALS" <<'EOF'
dns_ovh_endpoint = ovh-eu
dns_ovh_application_key = AK123
dns_ovh_application_secret = AS456
dns_ovh_consumer_key = CK789
EOF

  # Reset cached credentials
  _OVH_AK="" ; _OVH_AS="" ; _OVH_CK="" ; _OVH_EP=""

  # File-based call tracking (survives subshells)
  export CURL_LOG="${TEST_DIR}/curl_calls.log"
  : > "$CURL_LOG"
  export CURL_RESPONSE_FILE="${TEST_DIR}/curl_response"
  echo '{"status":"ok"}' > "$CURL_RESPONSE_FILE"

  # Mock curl — logs calls to file, returns configured response
  curl() {
    echo "$*" >> "$CURL_LOG"
    if [[ "$*" == *"/auth/time"* ]]; then
      echo "1700000000"
      return 0
    fi
    cat "$CURL_RESPONSE_FILE"
    return 0
  }
  export -f curl

  source "${BATS_TEST_DIRNAME}/../lib/ovh-api.sh"
}

teardown() { teardown_test_env; }

# --- _ovh_load_creds ---

@test "load_creds: reads credentials from file" {
  _ovh_load_creds
  [ "$_OVH_AK" = "AK123" ]
  [ "$_OVH_AS" = "AS456" ]
  [ "$_OVH_CK" = "CK789" ]
}

@test "load_creds: fails when file missing" {
  OVH_DNS_CREDENTIALS="${TEST_DIR}/nonexistent.ini"
  run _ovh_load_creds
  [ "$status" -ne 0 ]
}

# --- ovh_api ---

@test "ovh_api: calls curl with OVH headers" {
  ovh_api GET "/domain/zone/" > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"X-Ovh-Application: AK123"* ]]
  [[ "$calls" == *"X-Ovh-Consumer: CK789"* ]]
  [[ "$calls" == *"X-Ovh-Signature:"* ]]
}

@test "ovh_api: passes body for POST requests" {
  ovh_api POST "/domain/zone/test.com/record" '{"fieldType":"A"}' > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *'-d {"fieldType":"A"}'* ]]
  [[ "$calls" == *"POST"* ]]
}

@test "ovh_api: returns API error on class response" {
  echo '{"class":"Client::Forbidden","message":"denied"}' > "$CURL_RESPONSE_FILE"
  run ovh_api GET "/domain/zone/"
  [ "$status" -ne 0 ]
}

@test "ovh_api: signature starts with \$1\$" {
  ovh_api GET "/test" > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *'X-Ovh-Signature: $1$'* ]]
}

# --- ovh_dns_find ---

@test "dns_find: returns first record ID" {
  echo '[42,99]' > "$CURL_RESPONSE_FILE"
  run ovh_dns_find "example.com" "" "A"
  [ "$output" = "42" ]
}

@test "dns_find: returns empty for empty array" {
  echo '[]' > "$CURL_RESPONSE_FILE"
  run ovh_dns_find "example.com" "" "A"
  [ -z "$output" ]
}

@test "dns_find: includes subdomain in query" {
  echo '[1]' > "$CURL_RESPONSE_FILE"
  ovh_dns_find "example.com" "www" "A" > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"subDomain=www"* ]]
}

# --- ovh_dns_create ---

@test "dns_create: sends POST to zone record endpoint" {
  ovh_dns_create "example.com" "www" "A" '"1.2.3.4"' 3600 > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"POST"* ]]
  [[ "$calls" == *"/domain/zone/example.com/record"* ]]
}

# --- ovh_dns_update ---

@test "dns_update: sends PUT with target" {
  ovh_dns_update "example.com" "42" '"5.6.7.8"' > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"PUT"* ]]
  [[ "$calls" == *"/domain/zone/example.com/record/42"* ]]
}

# --- ovh_dns_delete ---

@test "dns_delete: sends DELETE" {
  ovh_dns_delete "example.com" "42" > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"DELETE"* ]]
  [[ "$calls" == *"/domain/zone/example.com/record/42"* ]]
}

# --- ovh_dns_refresh ---

@test "dns_refresh: POSTs to zone refresh" {
  ovh_dns_refresh "example.com" > /dev/null
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"POST"* ]]
  [[ "$calls" == *"/domain/zone/example.com/refresh"* ]]
}

# --- ovh_test_credentials ---

@test "test_credentials: returns 0 on success" {
  echo '{"credentialId":123}' > "$CURL_RESPONSE_FILE"
  ovh_test_credentials
}

@test "test_credentials: returns 1 on API error" {
  echo '{"class":"Client::Forbidden","message":"denied"}' > "$CURL_RESPONSE_FILE"
  run ovh_test_credentials
  [ "$status" -ne 0 ]
}

# --- ovh_setup_dkim ---

@test "setup_dkim: extracts key and creates record" {
  # Fake DKIM key file (opendkim-genkey format)
  cat > "${TEST_DIR}/mail.txt" <<'DKIM'
mail._domainkey	IN	TXT	( "v=DKIM1; h=sha256; k=rsa; "
	  "p=TESTKEY123" )  ; ----- DKIM key mail for example.com
DKIM

  # Sequential responses: timestamp, dns_find returns empty, create ok, refresh ok
  local response_seq=0
  curl() {
    echo "$*" >> "$CURL_LOG"
    if [[ "$*" == *"/auth/time"* ]]; then echo "1700000000"; return 0; fi
    ((++response_seq))
    case $response_seq in
      1) echo "[]" ;;      # dns_find: no existing
      *) echo '{"id":1}' ;; # create/refresh
    esac
    return 0
  }
  export -f curl

  ovh_setup_dkim "example.com" "mail" "${TEST_DIR}/mail.txt"
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"/domain/zone/example.com/record"* ]]
}

@test "setup_dkim: fails with empty key file" {
  echo "" > "${TEST_DIR}/empty.txt"
  run ovh_setup_dkim "example.com" "mail" "${TEST_DIR}/empty.txt"
  [ "$status" -ne 0 ]
}

# --- ovh_setup_spf ---

@test "setup_spf: creates SPF when none exists" {
  local response_seq=0
  curl() {
    echo "$*" >> "$CURL_LOG"
    if [[ "$*" == *"/auth/time"* ]]; then echo "1700000000"; return 0; fi
    ((++response_seq))
    case $response_seq in
      1) echo "[]" ;;       # dns_find: no existing TXT
      *) echo '{"id":1}' ;; # create/refresh
    esac
    return 0
  }
  export -f curl

  ovh_setup_spf "example.com" "1.2.3.4"
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"v=spf1"* ]]
}

# --- ovh_setup_dmarc ---

@test "setup_dmarc: creates DMARC when none exists" {
  local response_seq=0
  curl() {
    echo "$*" >> "$CURL_LOG"
    if [[ "$*" == *"/auth/time"* ]]; then echo "1700000000"; return 0; fi
    ((++response_seq))
    case $response_seq in
      1) echo "[]" ;;       # dns_find: no existing
      *) echo '{"id":1}' ;; # create/refresh
    esac
    return 0
  }
  export -f curl

  ovh_setup_dmarc "example.com" "admin@example.com"
  local calls
  calls=$(cat "$CURL_LOG")
  [[ "$calls" == *"DMARC1"* ]]
}
