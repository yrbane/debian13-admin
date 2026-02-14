#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  # Mock OVH API functions
  ovh_dns_find()    { echo ""; }
  ovh_dns_create()  { OVH_CALLS+=("CREATE:$*"); return 0; }
  ovh_dns_update()  { OVH_CALLS+=("UPDATE:$*"); return 0; }
  ovh_dns_refresh() { OVH_CALLS+=("REFRESH:$1"); return 0; }
  ovh_setup_spf()   { OVH_CALLS+=("SPF:$1:$2"); return 0; }
  ovh_setup_dkim()  { OVH_CALLS+=("DKIM:$1:$2:$3"); return 0; }
  ovh_setup_dmarc() { OVH_CALLS+=("DMARC:$1:$2"); return 0; }
  OVH_CALLS=()

  SERVER_IP="93.184.216.34"
  SERVER_IP6=""
  EMAIL_FOR_CERTBOT="admin@test.com"

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

@test "setup_dns: calls SPF for domain" {
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo '"v=DKIM1; k=rsa; p=TESTKEY"' > "${DKIM_KEYDIR}/example.com/mail.txt"
  dm_register_domain "example.com" "mail"

  dm_setup_dns "example.com" "mail"

  local found=false
  for call in "${OVH_CALLS[@]}"; do
    [[ "$call" == SPF:example.com:* ]] && found=true
  done
  [ "$found" = true ]
}

@test "setup_dns: calls DKIM for domain" {
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo '"v=DKIM1; k=rsa; p=TESTKEY"' > "${DKIM_KEYDIR}/example.com/mail.txt"
  dm_register_domain "example.com" "mail"

  dm_setup_dns "example.com" "mail"

  local found=false
  for call in "${OVH_CALLS[@]}"; do
    [[ "$call" == DKIM:example.com:mail:* ]] && found=true
  done
  [ "$found" = true ]
}

@test "setup_dns: calls DMARC for domain" {
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo '"v=DKIM1; k=rsa; p=TESTKEY"' > "${DKIM_KEYDIR}/example.com/mail.txt"
  dm_register_domain "example.com" "mail"

  dm_setup_dns "example.com" "mail"

  local found=false
  for call in "${OVH_CALLS[@]}"; do
    [[ "$call" == DMARC:example.com:* ]] && found=true
  done
  [ "$found" = true ]
}

@test "setup_dns: calls A record creation" {
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo '"v=DKIM1; k=rsa; p=TESTKEY"' > "${DKIM_KEYDIR}/example.com/mail.txt"
  dm_register_domain "example.com" "mail"

  dm_setup_dns "example.com" "mail"

  local found=false
  for call in "${OVH_CALLS[@]}"; do
    [[ "$call" == CREATE:example.com*A* ]] && found=true
  done
  [ "$found" = true ]
}

@test "setup_dns: refreshes zone after all operations" {
  mkdir -p "${DKIM_KEYDIR}/example.com"
  echo '"v=DKIM1; k=rsa; p=TESTKEY"' > "${DKIM_KEYDIR}/example.com/mail.txt"
  dm_register_domain "example.com" "mail"

  dm_setup_dns "example.com" "mail"

  local found=false
  for call in "${OVH_CALLS[@]}"; do
    [[ "$call" == "REFRESH:example.com" ]] && found=true
  done
  [ "$found" = true ]
}

@test "setup_dns: skips DKIM if key file missing" {
  dm_register_domain "example.com" "mail"
  # No key file created

  dm_setup_dns "example.com" "mail"

  local found=false
  for call in "${OVH_CALLS[@]}"; do
    [[ "$call" == DKIM:* ]] && found=true
  done
  [ "$found" = false ]
}
