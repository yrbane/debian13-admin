#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
  CONFIG_FILE="${TEST_DIR}/test.conf"
  CONFIG_VERSION=2
  source "${BATS_TEST_DIRNAME}/../lib/config.sh"
}

teardown() { teardown_test_env; }

# --- validate_config_line ---

@test "validate_config_line: accepts simple string" {
  validate_config_line 'HOSTNAME_FQDN="example.com"'
}

@test "validate_config_line: accepts quoted string with dots and hyphens" {
  validate_config_line 'HOSTNAME_FQDN="my-server.example.com"'
}

@test "validate_config_line: accepts boolean true" {
  validate_config_line 'INSTALL_APACHE_PHP=true'
}

@test "validate_config_line: accepts boolean false" {
  validate_config_line 'INSTALL_APACHE_PHP=false'
}

@test "validate_config_line: accepts integer" {
  validate_config_line 'SSH_PORT=65222'
}

@test "validate_config_line: accepts unquoted simple value" {
  validate_config_line 'DKIM_SELECTOR=mail'
}

@test "validate_config_line: accepts empty quoted string" {
  validate_config_line 'TRUSTED_IPS=""'
}

@test "validate_config_line: accepts IPs with spaces in quotes" {
  validate_config_line 'TRUSTED_IPS="1.2.3.4 5.6.7.8"'
}

@test "validate_config_line: accepts comment line" {
  validate_config_line '# This is a comment'
}

@test "validate_config_line: accepts empty line" {
  validate_config_line ''
}

@test "validate_config_line: rejects command substitution \$()" {
  run validate_config_line 'VAR=$(whoami)'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects backtick substitution" {
  run validate_config_line 'VAR=`whoami`'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects \$() inside quotes" {
  run validate_config_line 'VAR="$(rm -rf /)"'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects backticks inside quotes" {
  run validate_config_line 'VAR="`rm -rf /`"'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects variable expansion \${}" {
  run validate_config_line 'VAR="${HOME}"'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects simple \$VAR reference" {
  run validate_config_line 'VAR=$HOME'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects semicolon (chained command)" {
  run validate_config_line 'VAR=ok; rm -rf /'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects pipe" {
  run validate_config_line 'VAR=ok | cat /etc/passwd'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects redirect" {
  run validate_config_line 'VAR=ok > /tmp/evil'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects ampersand (background)" {
  run validate_config_line 'VAR=ok & malicious'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects newline in value" {
  run validate_config_line $'VAR="line1\nline2"'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects lowercase variable name" {
  run validate_config_line 'lowercase_var=value'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects process substitution <()" {
  run validate_config_line 'VAR=<(cat /etc/passwd)'
  [ "$status" -ne 0 ]
}

@test "validate_config_line: rejects array assignment" {
  run validate_config_line 'VAR=(one two three)'
  [ "$status" -ne 0 ]
}

# --- load_config integration ---

@test "load_config: loads valid config file" {
  cat > "$CONFIG_FILE" <<'EOF'
# Comment
CONFIG_VERSION=2
HOSTNAME_FQDN="example.com"
SSH_PORT="65222"
INSTALL_APACHE_PHP=true
EOF
  load_config
  [ "$HOSTNAME_FQDN" = "example.com" ]
  [ "$SSH_PORT" = "65222" ]
  [ "$INSTALL_APACHE_PHP" = "true" ]
}

@test "load_config: rejects file with command substitution" {
  cat > "$CONFIG_FILE" <<'EOF'
HOSTNAME_FQDN="$(whoami)"
EOF
  run load_config
  [ "$status" -ne 0 ]
}

@test "load_config: rejects file with backtick" {
  cat > "$CONFIG_FILE" <<'EOF'
HOSTNAME_FQDN="`id`"
EOF
  run load_config
  [ "$status" -ne 0 ]
}

@test "load_config: rejects file with one bad line among good ones" {
  cat > "$CONFIG_FILE" <<'EOF'
HOSTNAME_FQDN="safe.com"
EVIL=$(rm -rf /)
SSH_PORT="22"
EOF
  run load_config
  [ "$status" -ne 0 ]
}

@test "load_config: returns 1 when no config file" {
  rm -f "$CONFIG_FILE"
  run load_config
  [ "$status" -eq 1 ]
}
