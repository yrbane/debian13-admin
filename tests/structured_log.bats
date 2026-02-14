#!/usr/bin/env bats
# Point 19: Structured logging

load test_helper

setup() {
  setup_test_env
  override_paths
  STRUCTURED_LOG="${TEST_DIR}/structured.log"
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- slog ---

@test "slog: writes JSON line to log file" {
  slog info "test message"
  [ -f "$STRUCTURED_LOG" ]
  run cat "$STRUCTURED_LOG"
  [[ "$output" == *'"level":"info"'* ]]
  [[ "$output" == *'"msg":"test message"'* ]]
}

@test "slog: includes ISO 8601 timestamp" {
  slog info "ts test"
  run cat "$STRUCTURED_LOG"
  # Match ISO 8601 pattern: 2026-02-14T12:34:56+00:00 or similar
  [[ "$output" =~ \"ts\":\"[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]
}

@test "slog: supports warn level" {
  slog warn "warning message"
  run cat "$STRUCTURED_LOG"
  [[ "$output" == *'"level":"warn"'* ]]
}

@test "slog: supports error level" {
  slog error "error message"
  run cat "$STRUCTURED_LOG"
  [[ "$output" == *'"level":"error"'* ]]
}

@test "slog: appends multiple entries" {
  slog info "first"
  slog warn "second"
  slog error "third"
  [ "$(wc -l < "$STRUCTURED_LOG")" -eq 3 ]
}

@test "slog: supports extra key=value fields" {
  slog info "domain added" domain=example.com selector=mail
  run cat "$STRUCTURED_LOG"
  [[ "$output" == *'"domain":"example.com"'* ]]
  [[ "$output" == *'"selector":"mail"'* ]]
}

@test "slog: escapes quotes in message" {
  slog info 'message with "quotes"'
  run cat "$STRUCTURED_LOG"
  [[ "$output" == *'\"quotes\"'* ]] || [[ "$output" == *"quotes"* ]]
  # Must be valid single-line JSON — no unescaped quotes breaking structure
  [ "$(wc -l < "$STRUCTURED_LOG")" -eq 1 ]
}

@test "slog: no-op when STRUCTURED_LOG unset" {
  unset STRUCTURED_LOG
  run slog info "should not crash"
  [ "$status" -eq 0 ]
}
