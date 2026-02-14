#!/usr/bin/env bats
# Point 23: Dry-run mode

load test_helper

setup() {
  setup_test_env
  override_paths
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- dry_run_wrap ---

@test "dry_run: executes command when DRY_RUN=false" {
  DRY_RUN=false
  run dry_run_wrap touch "${TEST_DIR}/created.txt"
  [ -f "${TEST_DIR}/created.txt" ]
}

@test "dry_run: skips command when DRY_RUN=true" {
  DRY_RUN=true
  run dry_run_wrap touch "${TEST_DIR}/not_created.txt"
  [ ! -f "${TEST_DIR}/not_created.txt" ]
}

@test "dry_run: logs what would be done" {
  DRY_RUN=true
  run dry_run_wrap echo "hello"
  [[ "$output" == *"[DRY-RUN]"* ]]
}

@test "dry_run: returns 0 in dry-run mode" {
  DRY_RUN=true
  run dry_run_wrap false
  [ "$status" -eq 0 ]
}
