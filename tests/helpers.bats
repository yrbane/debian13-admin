#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths
}

teardown() { teardown_test_env; }

# --- trap separation ---

@test "trap: normal exit does not show error message" {
  run bash -c '
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/constants.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/helpers.sh"
    exit 0
  '
  [ "$status" -eq 0 ]
  [[ "$output" != *"Erreur"* ]]
}

@test "trap: error exit shows error message" {
  run bash -c '
    set -e
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/constants.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/helpers.sh"
    false
  '
  [ "$status" -ne 0 ]
  [[ "$output" == *"Erreur"* ]] || [[ "$output" == *"erreur"* ]]
}

@test "trap: tmpfiles cleaned on normal exit" {
  # mktempfile must be called WITHOUT $() to populate _TMPFILES in the parent
  run bash -c '
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/constants.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/helpers.sh"
    mktempfile .test > /dev/null
    f="${_TMPFILES[0]}"
    echo "$f"
    [ -f "$f" ] && echo "before=exists"
    exit 0
  '
  [ "$status" -eq 0 ]
  local tmpfile="${lines[0]}"
  [[ "$tmpfile" == /tmp/* ]]
  [ ! -f "$tmpfile" ]
}

@test "trap: tmpfiles cleaned on error exit" {
  run bash -c '
    set -e
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/constants.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/helpers.sh"
    mktempfile .test > /dev/null
    f="${_TMPFILES[0]}"
    echo "$f"
    false
  '
  [ "$status" -ne 0 ]
  local tmpfile="${lines[0]}"
  [[ "$tmpfile" == /tmp/* ]]
  [ ! -f "$tmpfile" ]
}

# --- mktempfile ---

@test "mktempfile: creates file with custom suffix" {
  run bash -c '
    source "'"${BATS_TEST_DIRNAME}"'/../lib/core.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/constants.sh"
    source "'"${BATS_TEST_DIRNAME}"'/../lib/helpers.sh"
    f=$(mktempfile .myext)
    [ -f "$f" ]
    [[ "$f" == *.myext ]]
    echo "OK"
  '
  [ "$status" -eq 0 ]
  [[ "$output" == *"OK"* ]]
}

# --- backup_file ---

@test "backup_file: creates .bak copy" {
  local src="${TEST_DIR}/original.conf"
  echo "content" > "$src"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  backup_file "$src"

  local bak_count
  bak_count=$(ls "${src}".*.bak 2>/dev/null | wc -l)
  [ "$bak_count" -eq 1 ]
}

@test "backup_file: no-op if file does not exist" {
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  backup_file "${TEST_DIR}/nonexistent.conf"
  # Should not fail
}

# --- add_line_if_missing ---

@test "add_line_if_missing: adds when absent" {
  local f="${TEST_DIR}/file.txt"
  echo "existing" > "$f"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  add_line_if_missing "^newline" "newline here" "$f"
  grep -q "newline here" "$f"
}

@test "add_line_if_missing: no-op when present" {
  local f="${TEST_DIR}/file.txt"
  echo "newline here" > "$f"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  add_line_if_missing "^newline" "newline here" "$f"
  [ "$(grep -c 'newline here' "$f")" -eq 1 ]
}

# --- sanitize_int ---

@test "sanitize_int: strips non-numeric chars" {
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  run sanitize_int "abc123def"
  [ "$output" = "123" ]
}

@test "sanitize_int: returns 0 for empty" {
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  run sanitize_int ""
  [ "$output" = "0" ]
}

# --- days_since / days_until ---

@test "days_since: returns correct value" {
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  local yesterday=$(( $(date +%s) - 86400 ))
  run days_since "$yesterday"
  [ "$output" -eq 1 ]
}

@test "days_until: returns correct value" {
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"

  local tomorrow=$(( $(date +%s) + 86400 ))
  run days_until "$tomorrow"
  [ "$output" -eq 1 ]
}
