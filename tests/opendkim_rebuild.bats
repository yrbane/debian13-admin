#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

@test "rebuild_opendkim: generates keytable from domains.conf" {
  dm_register_domain "alpha.com" "mail"
  dm_register_domain "beta.org" "dkim"
  mkdir -p "${DKIM_KEYDIR}/alpha.com" "${DKIM_KEYDIR}/beta.org"
  touch "${DKIM_KEYDIR}/alpha.com/mail.private"
  touch "${DKIM_KEYDIR}/beta.org/dkim.private"

  dm_rebuild_opendkim --no-restart

  [ -f "${OPENDKIM_DIR}/keytable" ]
  grep -q "mail._domainkey.alpha.com alpha.com:mail:${DKIM_KEYDIR}/alpha.com/mail.private" "${OPENDKIM_DIR}/keytable"
  grep -q "dkim._domainkey.beta.org beta.org:dkim:${DKIM_KEYDIR}/beta.org/dkim.private" "${OPENDKIM_DIR}/keytable"
}

@test "rebuild_opendkim: generates signingtable" {
  dm_register_domain "alpha.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/alpha.com"
  touch "${DKIM_KEYDIR}/alpha.com/mail.private"

  dm_rebuild_opendkim --no-restart

  [ -f "${OPENDKIM_DIR}/signingtable" ]
  grep -q '^\*@alpha\.com mail\._domainkey\.alpha\.com$' "${OPENDKIM_DIR}/signingtable"
}

@test "rebuild_opendkim: generates trustedhosts" {
  dm_register_domain "test.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/test.com"
  touch "${DKIM_KEYDIR}/test.com/mail.private"

  dm_rebuild_opendkim --no-restart

  [ -f "${OPENDKIM_DIR}/trustedhosts" ]
  grep -q "127.0.0.1" "${OPENDKIM_DIR}/trustedhosts"
  grep -q "localhost" "${OPENDKIM_DIR}/trustedhosts"
  grep -q "::1" "${OPENDKIM_DIR}/trustedhosts"
}

@test "rebuild_opendkim: skips domain without private key" {
  dm_register_domain "nokey.com" "mail"
  dm_register_domain "haskey.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/haskey.com"
  touch "${DKIM_KEYDIR}/haskey.com/mail.private"

  dm_rebuild_opendkim --no-restart

  ! grep -q "nokey.com" "${OPENDKIM_DIR}/keytable"
  grep -q "haskey.com" "${OPENDKIM_DIR}/keytable"
}

@test "rebuild_opendkim: empty domains.conf produces empty keytable" {
  touch "$DOMAINS_CONF"

  dm_rebuild_opendkim --no-restart

  [ -f "${OPENDKIM_DIR}/keytable" ]
  [ ! -s "${OPENDKIM_DIR}/keytable" ]
}

@test "rebuild_opendkim: multiple domains produce correct signingtable" {
  dm_register_domain "a.com" "mail"
  dm_register_domain "b.org" "sel2"
  mkdir -p "${DKIM_KEYDIR}/a.com" "${DKIM_KEYDIR}/b.org"
  touch "${DKIM_KEYDIR}/a.com/mail.private"
  touch "${DKIM_KEYDIR}/b.org/sel2.private"

  dm_rebuild_opendkim --no-restart

  [ "$(wc -l < "${OPENDKIM_DIR}/signingtable")" -eq 2 ]
  grep -q '^\*@a\.com mail\._domainkey\.a\.com$' "${OPENDKIM_DIR}/signingtable"
  grep -q '^\*@b\.org sel2\._domainkey\.b\.org$' "${OPENDKIM_DIR}/signingtable"
}
