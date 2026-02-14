#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  # Source core.sh for color vars and basic functions
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/constants.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
  # Source verify.sh (overrides emit_check stub from test_helper)
  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
}

teardown() { teardown_test_env; }

# --- emit_check ---

@test "emit_check: ok increments CHECKS_OK" {
  CHECKS_OK=0
  emit_check ok "test message" > /dev/null
  [ "$CHECKS_OK" -eq 1 ]
}

@test "emit_check: warn increments CHECKS_WARN" {
  CHECKS_WARN=0
  emit_check warn "test message" > /dev/null
  [ "$CHECKS_WARN" -eq 1 ]
}

@test "emit_check: fail increments CHECKS_FAIL" {
  CHECKS_FAIL=0
  emit_check fail "test message" > /dev/null
  [ "$CHECKS_FAIL" -eq 1 ]
}

@test "emit_check: dispatches to html in html mode" {
  CHECK_MODE="html"
  local html_called=false
  add_html_check() { html_called=true; }
  emit_check ok "test"
  [ "$html_called" = true ]
  CHECK_MODE="cli"
}

# --- check_config_grep ---

@test "check_config_grep: ok when pattern found" {
  local conf="${TEST_DIR}/test.conf"
  echo "PermitRootLogin no" > "$conf"

  run check_config_grep "$conf" "^PermitRootLogin\s+no" "found" "not found"
  [[ "$output" == *"found"* ]]
}

@test "check_config_grep: fail when pattern missing" {
  local conf="${TEST_DIR}/test.conf"
  echo "PermitRootLogin yes" > "$conf"

  run check_config_grep "$conf" "^PermitRootLogin\s+no" "found" "not found"
  [[ "$output" == *"not found"* ]]
}

@test "check_config_grep: fail when file missing" {
  run check_config_grep "${TEST_DIR}/nonexistent" "pattern" "found" "not found"
  [[ "$output" == *"not found"* ]]
}

# --- check_file_perms ---

@test "check_file_perms: ok for matching permissions" {
  local f="${TEST_DIR}/secret.key"
  touch "$f"
  chmod 600 "$f"

  run check_file_perms "$f" "Key" "600"
  [[ "$output" == *"correctes"* ]]
}

@test "check_file_perms: warn for wrong permissions" {
  local f="${TEST_DIR}/secret.key"
  touch "$f"
  chmod 644 "$f"

  run check_file_perms "$f" "Key" "600"
  [[ "$output" == *"644"* ]]
  [[ "$output" == *"attendu"* ]]
}

@test "check_file_perms: accepts multiple valid modes" {
  local f="${TEST_DIR}/shadow"
  touch "$f"
  chmod 640 "$f"

  run check_file_perms "$f" "Shadow" "0|640|600"
  [[ "$output" == *"correctes"* ]]
}

# --- safe_count ---

@test "safe_count: counts matches in file" {
  local f="${TEST_DIR}/log.txt"
  printf "error line1\nok line2\nerror line3\n" > "$f"

  run safe_count "error" "$f"
  [ "$output" = "2" ]
}

@test "safe_count: returns 0 for no matches" {
  local f="${TEST_DIR}/log.txt"
  echo "all good" > "$f"

  run safe_count "error" "$f"
  [ "$output" = "0" ]
}

@test "safe_count: handles missing file via string fallback" {
  run safe_count "pattern" "some text without matches"
  [ "$output" = "0" ]
}

@test "safe_count: counts matches in string when not a file" {
  run safe_count "error" "error here and error there"
  [ "$output" = "1" ]
}

# --- check_db_freshness ---

@test "check_db_freshness: ok for fresh file" {
  local f="${TEST_DIR}/fresh.db"
  touch "$f"

  run check_db_freshness "$f" "TestDB" 7 30
  [[ "$output" == *"jour"* ]]
  [[ "$output" == *"TestDB"* ]]
}

@test "check_db_freshness: warn for missing target" {
  run check_db_freshness "${TEST_DIR}/nonexistent.db" "TestDB" 7 30
  [[ "$output" == *"non trouvée"* ]]
}

@test "check_db_freshness: handles directory target" {
  mkdir -p "${TEST_DIR}/dbdir"
  touch "${TEST_DIR}/dbdir/data.dat"

  run check_db_freshness "${TEST_DIR}/dbdir" "TestDB" 7 30
  [[ "$output" == *"jour"* ]]
}

# --- counter accumulation ---

@test "counters: multiple emit_check calls accumulate" {
  CHECKS_OK=0; CHECKS_WARN=0; CHECKS_FAIL=0
  emit_check ok "a" > /dev/null
  emit_check ok "b" > /dev/null
  emit_check warn "c" > /dev/null
  emit_check fail "d" > /dev/null
  emit_check fail "e" > /dev/null
  [ "$CHECKS_OK" -eq 2 ]
  [ "$CHECKS_WARN" -eq 1 ]
  [ "$CHECKS_FAIL" -eq 2 ]
}
