#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  HOOKS_DIR="${TEST_DIR}/hooks.d"
  mkdir -p "$HOOKS_DIR"

  source "${BATS_TEST_DIRNAME}/../lib/hooks.sh"
}

teardown() { teardown_test_env; }

# --- run_hooks ---

@test "run_hooks: executes scripts matching hook name" {
  cat > "${HOOKS_DIR}/post-backup-notify.sh" <<'HOOK'
#!/bin/bash
echo "HOOK_EXECUTED"
HOOK
  chmod +x "${HOOKS_DIR}/post-backup-notify.sh"

  run run_hooks "post-backup"
  [[ "$output" == *"HOOK_EXECUTED"* ]]
}

@test "run_hooks: skips non-executable files" {
  cat > "${HOOKS_DIR}/post-backup-notify.sh" <<'HOOK'
#!/bin/bash
echo "SHOULD_NOT_RUN"
HOOK
  chmod 644 "${HOOKS_DIR}/post-backup-notify.sh"

  run run_hooks "post-backup"
  [[ "$output" != *"SHOULD_NOT_RUN"* ]]
}

@test "run_hooks: executes multiple hooks in order" {
  cat > "${HOOKS_DIR}/post-install-01-first.sh" <<'HOOK'
#!/bin/bash
echo "FIRST"
HOOK
  chmod +x "${HOOKS_DIR}/post-install-01-first.sh"

  cat > "${HOOKS_DIR}/post-install-02-second.sh" <<'HOOK'
#!/bin/bash
echo "SECOND"
HOOK
  chmod +x "${HOOKS_DIR}/post-install-02-second.sh"

  run run_hooks "post-install"
  [[ "${lines[0]}" == *"FIRST"* ]]
  [[ "${lines[1]}" == *"SECOND"* ]]
}

@test "run_hooks: ignores unrelated hooks" {
  cat > "${HOOKS_DIR}/pre-install-setup.sh" <<'HOOK'
#!/bin/bash
echo "PRE_INSTALL"
HOOK
  chmod +x "${HOOKS_DIR}/pre-install-setup.sh"

  cat > "${HOOKS_DIR}/post-backup-notify.sh" <<'HOOK'
#!/bin/bash
echo "POST_BACKUP"
HOOK
  chmod +x "${HOOKS_DIR}/post-backup-notify.sh"

  run run_hooks "pre-install"
  [[ "$output" == *"PRE_INSTALL"* ]]
  [[ "$output" != *"POST_BACKUP"* ]]
}

@test "run_hooks: no-op when hooks dir missing" {
  HOOKS_DIR="${TEST_DIR}/nonexistent"
  run run_hooks "post-install"
  [ "$status" -eq 0 ]
}

@test "run_hooks: no-op when no matching hooks" {
  run run_hooks "post-install"
  [ "$status" -eq 0 ]
}

@test "run_hooks: passes arguments to hook scripts" {
  cat > "${HOOKS_DIR}/post-domain-add-log.sh" <<'HOOK'
#!/bin/bash
echo "DOMAIN=$1"
HOOK
  chmod +x "${HOOKS_DIR}/post-domain-add-log.sh"

  run run_hooks "post-domain-add" "example.com"
  [[ "$output" == *"DOMAIN=example.com"* ]]
}

@test "run_hooks: continues after hook failure" {
  cat > "${HOOKS_DIR}/post-install-01-fail.sh" <<'HOOK'
#!/bin/bash
exit 1
HOOK
  chmod +x "${HOOKS_DIR}/post-install-01-fail.sh"

  cat > "${HOOKS_DIR}/post-install-02-ok.sh" <<'HOOK'
#!/bin/bash
echo "STILL_RUNNING"
HOOK
  chmod +x "${HOOKS_DIR}/post-install-02-ok.sh"

  run run_hooks "post-install"
  [[ "$output" == *"STILL_RUNNING"* ]]
}
