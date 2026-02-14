#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
  EMAIL_FOR_CERTBOT="admin@test.com"
  OVH_DNS_CREDENTIALS="${TEST_DIR}/ovh-dns.ini"
  CERTBOT_DNS_PROPAGATION=10
  CERTBOT_CALLS=()

  # Mock certbot — record calls instead of running
  certbot() { CERTBOT_CALLS+=("$*"); return 0; }
  export -f certbot

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

@test "obtain_ssl: uses DNS-01 when OVH credentials exist" {
  echo "dns_ovh_endpoint = ovh-eu" > "$OVH_DNS_CREDENTIALS"

  dm_obtain_ssl "example.com"

  [ "${#CERTBOT_CALLS[@]}" -gt 0 ]
  [[ "${CERTBOT_CALLS[0]}" == *"dns-ovh"* ]]
}

@test "obtain_ssl: requests wildcard with DNS-01" {
  echo "dns_ovh_endpoint = ovh-eu" > "$OVH_DNS_CREDENTIALS"

  dm_obtain_ssl "example.com"

  [[ "${CERTBOT_CALLS[0]}" == *"*.example.com"* ]]
}

@test "obtain_ssl: uses HTTP-01 when no OVH credentials" {
  rm -f "$OVH_DNS_CREDENTIALS"

  dm_obtain_ssl "example.com"

  [ "${#CERTBOT_CALLS[@]}" -gt 0 ]
  [[ "${CERTBOT_CALLS[0]}" == *"--preferred-challenges http"* ]] || [[ "${CERTBOT_CALLS[0]}" == *"--apache"* ]]
}

@test "obtain_ssl: HTTP-01 does not request wildcard" {
  rm -f "$OVH_DNS_CREDENTIALS"

  dm_obtain_ssl "example.com"

  [[ "${CERTBOT_CALLS[0]}" != *"*.example.com"* ]]
}

@test "obtain_ssl: passes email to certbot" {
  echo "dns_ovh_endpoint = ovh-eu" > "$OVH_DNS_CREDENTIALS"

  dm_obtain_ssl "example.com" "custom@email.com"

  [[ "${CERTBOT_CALLS[0]}" == *"custom@email.com"* ]]
}
