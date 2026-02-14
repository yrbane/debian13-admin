#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  HOSTNAME_FQDN="main.com"
  EXPORT_DIR="${TEST_DIR}/exports"
  mkdir -p "$EXPORT_DIR"

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# === Helper: populate a domain with realistic data ===
populate_domain() {
  local domain="$1" selector="${2:-mail}"
  dm_register_domain "$domain" "$selector"

  # DKIM keys
  mkdir -p "${DKIM_KEYDIR}/${domain}"
  echo "private-key-data" > "${DKIM_KEYDIR}/${domain}/${selector}.private"
  echo "\"v=DKIM1; k=rsa; p=TESTKEY\"" > "${DKIM_KEYDIR}/${domain}/${selector}.txt"

  # VHosts
  echo "# HTTP redirect for ${domain}" > "${APACHE_SITES_DIR}/000-${domain}-redirect.conf"
  echo "# HTTPS VHost for ${domain}" > "${APACHE_SITES_DIR}/010-${domain}.conf"

  # Logrotate
  echo "/var/log/apache2/${domain}/*.log { daily }" > "${LOGROTATE_DIR}/apache-vhost-${domain}"

  # Web root
  mkdir -p "${WEB_ROOT}/${domain}/www/public/css"
  echo "<html>${domain}</html>" > "${WEB_ROOT}/${domain}/www/public/index.html"
  echo "body{}" > "${WEB_ROOT}/${domain}/www/public/css/style.css"
  echo "User-agent: *" > "${WEB_ROOT}/${domain}/www/public/robots.txt"
}

# --- dm_export_domain ---

@test "export_domain: creates tar.gz archive" {
  populate_domain "example.com" "mail"

  run dm_export_domain "example.com" "$EXPORT_DIR"
  [ "$status" -eq 0 ]

  local archive="${EXPORT_DIR}/example.com.tar.gz"
  [ -f "$archive" ]
}

@test "export_domain: archive contains DKIM keys" {
  populate_domain "example.com" "mail"

  dm_export_domain "example.com" "$EXPORT_DIR"
  local archive="${EXPORT_DIR}/example.com.tar.gz"

  local contents
  contents=$(tar tzf "$archive")
  [[ "$contents" == *"dkim/mail.private"* ]]
  [[ "$contents" == *"dkim/mail.txt"* ]]
}

@test "export_domain: archive contains VHost configs" {
  populate_domain "example.com" "mail"

  dm_export_domain "example.com" "$EXPORT_DIR"
  local archive="${EXPORT_DIR}/example.com.tar.gz"

  local contents
  contents=$(tar tzf "$archive")
  [[ "$contents" == *"apache/000-example.com-redirect.conf"* ]]
  [[ "$contents" == *"apache/010-example.com.conf"* ]]
}

@test "export_domain: archive contains logrotate config" {
  populate_domain "example.com" "mail"

  dm_export_domain "example.com" "$EXPORT_DIR"
  local archive="${EXPORT_DIR}/example.com.tar.gz"

  local contents
  contents=$(tar tzf "$archive")
  [[ "$contents" == *"logrotate/apache-vhost-example.com"* ]]
}

@test "export_domain: archive contains web files" {
  populate_domain "example.com" "mail"

  dm_export_domain "example.com" "$EXPORT_DIR"
  local archive="${EXPORT_DIR}/example.com.tar.gz"

  local contents
  contents=$(tar tzf "$archive")
  [[ "$contents" == *"www/public/index.html"* ]]
  [[ "$contents" == *"www/public/css/style.css"* ]]
}

@test "export_domain: archive contains manifest with selector" {
  populate_domain "example.com" "dkim2024"

  dm_export_domain "example.com" "$EXPORT_DIR"
  local archive="${EXPORT_DIR}/example.com.tar.gz"

  local tmpdir
  tmpdir=$(mktemp -d)
  tar xzf "$archive" -C "$tmpdir"
  [ -f "${tmpdir}/manifest.conf" ]
  grep -q "^DOMAIN=example.com$" "${tmpdir}/manifest.conf"
  grep -q "^SELECTOR=dkim2024$" "${tmpdir}/manifest.conf"
  rm -rf "$tmpdir"
}

@test "export_domain: fails for unregistered domain" {
  run dm_export_domain "unknown.com" "$EXPORT_DIR"
  [ "$status" -eq 1 ]
}

@test "export_domain: skips missing DKIM gracefully" {
  dm_register_domain "nodkim.com" "mail"
  # No DKIM keys created

  mkdir -p "${APACHE_SITES_DIR}"
  echo "# vhost" > "${APACHE_SITES_DIR}/010-nodkim.com.conf"

  run dm_export_domain "nodkim.com" "$EXPORT_DIR"
  [ "$status" -eq 0 ]
  [ -f "${EXPORT_DIR}/nodkim.com.tar.gz" ]
}

@test "export_domain: skips missing web root gracefully" {
  dm_register_domain "noweb.com" "mail"
  mkdir -p "${DKIM_KEYDIR}/noweb.com"
  echo "key" > "${DKIM_KEYDIR}/noweb.com/mail.private"

  run dm_export_domain "noweb.com" "$EXPORT_DIR"
  [ "$status" -eq 0 ]
  [ -f "${EXPORT_DIR}/noweb.com.tar.gz" ]
}

# --- dm_import_domain ---

@test "import_domain: registers domain from archive" {
  populate_domain "example.com" "mail"
  dm_export_domain "example.com" "$EXPORT_DIR"

  # Clear the domain
  dm_unregister_domain "example.com"
  rm -rf "${DKIM_KEYDIR}/example.com"
  rm -f "${APACHE_SITES_DIR}"/*example.com*
  rm -f "${LOGROTATE_DIR}/apache-vhost-example.com"
  rm -rf "${WEB_ROOT}/example.com"

  dm_import_domain "${EXPORT_DIR}/example.com.tar.gz"

  dm_domain_exists "example.com"
  run dm_get_selector "example.com"
  [ "$output" = "mail" ]
}

@test "import_domain: restores DKIM keys" {
  populate_domain "example.com" "mail"
  dm_export_domain "example.com" "$EXPORT_DIR"

  dm_unregister_domain "example.com"
  rm -rf "${DKIM_KEYDIR}/example.com"

  dm_import_domain "${EXPORT_DIR}/example.com.tar.gz"

  [ -f "${DKIM_KEYDIR}/example.com/mail.private" ]
  [ -f "${DKIM_KEYDIR}/example.com/mail.txt" ]
  [ "$(cat "${DKIM_KEYDIR}/example.com/mail.private")" = "private-key-data" ]
}

@test "import_domain: restores VHost configs" {
  populate_domain "example.com" "mail"
  dm_export_domain "example.com" "$EXPORT_DIR"

  dm_unregister_domain "example.com"
  rm -f "${APACHE_SITES_DIR}"/*example.com*

  dm_import_domain "${EXPORT_DIR}/example.com.tar.gz"

  [ -f "${APACHE_SITES_DIR}/000-example.com-redirect.conf" ]
  [ -f "${APACHE_SITES_DIR}/010-example.com.conf" ]
}

@test "import_domain: restores logrotate config" {
  populate_domain "example.com" "mail"
  dm_export_domain "example.com" "$EXPORT_DIR"

  dm_unregister_domain "example.com"
  rm -f "${LOGROTATE_DIR}/apache-vhost-example.com"

  dm_import_domain "${EXPORT_DIR}/example.com.tar.gz"

  [ -f "${LOGROTATE_DIR}/apache-vhost-example.com" ]
}

@test "import_domain: restores web files" {
  populate_domain "example.com" "mail"
  dm_export_domain "example.com" "$EXPORT_DIR"

  dm_unregister_domain "example.com"
  rm -rf "${WEB_ROOT}/example.com"

  dm_import_domain "${EXPORT_DIR}/example.com.tar.gz"

  [ -f "${WEB_ROOT}/example.com/www/public/index.html" ]
  grep -q "example.com" "${WEB_ROOT}/example.com/www/public/index.html"
}

@test "import_domain: fails on missing archive" {
  run dm_import_domain "/nonexistent/archive.tar.gz"
  [ "$status" -eq 1 ]
}

@test "import_domain: fails on archive without manifest" {
  # Create a tar.gz without manifest
  local tmpdir
  tmpdir=$(mktemp -d)
  echo "random" > "${tmpdir}/random.txt"
  tar czf "${EXPORT_DIR}/bad.tar.gz" -C "$tmpdir" .
  rm -rf "$tmpdir"

  run dm_import_domain "${EXPORT_DIR}/bad.tar.gz"
  [ "$status" -eq 1 ]
}

@test "import_domain: does not overwrite if domain already registered" {
  populate_domain "example.com" "mail"
  dm_export_domain "example.com" "$EXPORT_DIR"

  # Domain still registered
  run dm_import_domain "${EXPORT_DIR}/example.com.tar.gz"
  [ "$status" -eq 1 ]
}

@test "export then import: roundtrip preserves selector" {
  populate_domain "test.org" "dkim2025"
  dm_export_domain "test.org" "$EXPORT_DIR"

  dm_unregister_domain "test.org"
  rm -rf "${DKIM_KEYDIR}/test.org" "${WEB_ROOT}/test.org"
  rm -f "${APACHE_SITES_DIR}"/*test.org* "${LOGROTATE_DIR}/apache-vhost-test.org"

  dm_import_domain "${EXPORT_DIR}/test.org.tar.gz"

  run dm_get_selector "test.org"
  [ "$output" = "dkim2025" ]
}
