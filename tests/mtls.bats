#!/usr/bin/env bats
# Point 12: mTLS client certificates — mtls_init_ca / mtls_generate_client_cert / mtls_deploy_vhost

load test_helper

setup() {
  setup_test_env
  override_paths

  MTLS_CA_DIR="${TEST_DIR}/ca"
  mkdir -p "$MTLS_CA_DIR"

  HOSTNAME_FQDN="main.com"

  # Mock openssl: writes fake cert/key files
  openssl() {
    echo "openssl $*" >> "${TEST_DIR}/openssl.log"
    # Detect output file arguments (-out, -keyout)
    local args=("$@")
    local i
    for (( i=0; i<${#args[@]}; i++ )); do
      case "${args[$i]}" in
        -out)
          if [[ -n "${args[$((i+1))]:-}" ]]; then
            mkdir -p "$(dirname "${args[$((i+1))]}")"
            echo "FAKE_CERT_DATA" > "${args[$((i+1))]}"
          fi
          ;;
        -keyout)
          if [[ -n "${args[$((i+1))]:-}" ]]; then
            mkdir -p "$(dirname "${args[$((i+1))]}")"
            echo "FAKE_KEY_DATA" > "${args[$((i+1))]}"
          fi
          ;;
      esac
    done
    return 0
  }
  export -f openssl

  # Mock systemctl (Apache reload)
  systemctl() { return 0; }
  export -f systemctl

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- mtls_init_ca ---

@test "mtls_init_ca: creates CA directory" {
  mtls_init_ca
  [ -d "$MTLS_CA_DIR" ]
}

@test "mtls_init_ca: creates CA certificate file" {
  mtls_init_ca
  [ -f "${MTLS_CA_DIR}/ca.pem" ]
}

@test "mtls_init_ca: creates CA key file" {
  mtls_init_ca
  [ -f "${MTLS_CA_DIR}/ca-key.pem" ]
}

@test "mtls_init_ca: calls openssl to generate CA cert" {
  mtls_init_ca
  [ -f "${TEST_DIR}/openssl.log" ]
  grep -q "openssl" "${TEST_DIR}/openssl.log"
}

@test "mtls_init_ca: idempotent (second run does not fail)" {
  mtls_init_ca
  mtls_init_ca
  [ -f "${MTLS_CA_DIR}/ca.pem" ]
  [ -f "${MTLS_CA_DIR}/ca-key.pem" ]
}

# --- mtls_generate_client_cert ---

@test "mtls_generate_client_cert: creates client certificate file" {
  mtls_init_ca
  mtls_generate_client_cert "user1"
  [ -f "${MTLS_CA_DIR}/clients/user1.pem" ] || [ -f "${MTLS_CA_DIR}/user1.pem" ]
}

@test "mtls_generate_client_cert: creates client key file" {
  mtls_init_ca
  mtls_generate_client_cert "user1"
  [ -f "${MTLS_CA_DIR}/clients/user1-key.pem" ] || [ -f "${MTLS_CA_DIR}/user1-key.pem" ]
}

@test "mtls_generate_client_cert: openssl called with client name" {
  mtls_init_ca
  mtls_generate_client_cert "admin"
  grep -q "admin" "${TEST_DIR}/openssl.log"
}

# --- mtls_deploy_vhost ---

@test "mtls_deploy_vhost: creates vhost config file" {
  mtls_init_ca
  mtls_deploy_vhost "secure.example.com"
  [ -f "${APACHE_SITES_DIR}/015-secure.example.com-mtls.conf" ] || \
    [ -f "${APACHE_SITES_DIR}/010-secure.example.com-mtls.conf" ] || \
    ls "${APACHE_SITES_DIR}/"*secure.example.com*mtls* >/dev/null 2>&1
}

@test "mtls_deploy_vhost: config contains SSLVerifyClient" {
  mtls_init_ca
  mtls_deploy_vhost "secure.example.com"
  local conf
  conf=$(ls "${APACHE_SITES_DIR}/"*secure.example.com*mtls* 2>/dev/null | head -1)
  [ -n "$conf" ]
  grep -q "SSLVerifyClient" "$conf"
}

@test "mtls_deploy_vhost: idempotent (second run does not fail)" {
  mtls_init_ca
  mtls_deploy_vhost "secure.example.com"
  mtls_deploy_vhost "secure.example.com"
  local conf
  conf=$(ls "${APACHE_SITES_DIR}/"*secure.example.com*mtls* 2>/dev/null | head -1)
  [ -n "$conf" ]
  grep -q "SSLVerifyClient" "$conf"
}
