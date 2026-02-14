#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env
  override_paths

  UFW_CALLS=()
  ufw() { UFW_CALLS+=("$*"); return 0; }
  export -f ufw

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- deploy_egress_rules ---

@test "deploy_egress_rules: sets default deny outgoing" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"default deny outgoing"* ]] && found=true
  done
  $found
}

@test "deploy_egress_rules: allows DNS (port 53)" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"53"* && "$call" == *"out"* ]] && found=true
  done
  $found
}

@test "deploy_egress_rules: allows HTTP outbound (port 80)" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"80/tcp"* && "$call" == *"out"* ]] && found=true
  done
  $found
}

@test "deploy_egress_rules: allows HTTPS outbound (port 443)" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"443/tcp"* && "$call" == *"out"* ]] && found=true
  done
  $found
}

@test "deploy_egress_rules: allows SMTP outbound (port 25)" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"25/tcp"* && "$call" == *"out"* ]] && found=true
  done
  $found
}

@test "deploy_egress_rules: allows NTP outbound (port 123)" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"123"* && "$call" == *"out"* ]] && found=true
  done
  $found
}

@test "deploy_egress_rules: allows SMTP submission (port 587)" {
  deploy_egress_rules
  local found=false
  for call in "${UFW_CALLS[@]}"; do
    [[ "$call" == *"587/tcp"* && "$call" == *"out"* ]] && found=true
  done
  $found
}

# --- verify_egress ---

@test "verify_egress: ok when default outgoing is deny" {
  ufw() {
    echo "Status: active"
    echo "Default: deny (incoming), deny (outgoing), disabled (routed)"
    return 0
  }
  export -f ufw

  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_egress
  [[ "$output" == *"ok:"*"egress"* ]] || [[ "$output" == *"ok:"*"sortant"* ]]
}

@test "verify_egress: warn when default outgoing is allow" {
  ufw() {
    echo "Status: active"
    echo "Default: deny (incoming), allow (outgoing), disabled (routed)"
    return 0
  }
  export -f ufw

  source "${BATS_TEST_DIRNAME}/../lib/verify.sh"
  emit_check() { echo "${1}:${2}"; }
  run verify_egress
  [[ "$output" == *"warn:"* ]]
}
