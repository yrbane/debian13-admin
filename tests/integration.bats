#!/usr/bin/env bats
# Point 2: Integration tests — validate script structure & coherence

setup() {
  SCRIPTS_DIR="${BATS_TEST_DIRNAME}/.."
}

# --- Syntax validation ---

@test "integration: debian13-server.sh passes bash -n" {
  run bash -n "${SCRIPTS_DIR}/debian13-server.sh"
  [ "$status" -eq 0 ]
}

@test "integration: all lib/*.sh pass bash -n" {
  for f in "${SCRIPTS_DIR}"/lib/*.sh; do
    run bash -n "$f"
    [ "$status" -eq 0 ]
  done
}

# --- Source coherence ---

@test "integration: all sourced libs exist" {
  local missing=0
  while IFS= read -r line; do
    # Extract lib name from: source "${LIB_DIR}/something.sh"
    local lib=""
    if [[ "$line" =~ source.*LIB_DIR.*/([a-zA-Z0-9_-]+\.sh) ]]; then
      lib="${BASH_REMATCH[1]}"
    fi
    [[ -z "$lib" ]] && continue
    [ -f "${SCRIPTS_DIR}/lib/${lib}" ] || { echo "Missing: lib/${lib}"; missing=1; }
  done < "${SCRIPTS_DIR}/debian13-server.sh"
  [ "$missing" -eq 0 ]
}

@test "integration: all test files load test_helper" {
  for f in "${SCRIPTS_DIR}"/tests/*.bats; do
    grep -q "load test_helper" "$f"
  done
}

# --- Template coherence ---

@test "integration: all referenced templates exist" {
  local missing=0
  for tmpl in vhost-http-redirect.conf.template vhost-https.conf.template parking-page.html parking-style.css; do
    [ -f "${SCRIPTS_DIR}/templates/${tmpl}" ] || {
      echo "Missing template: ${tmpl}"
      missing=1
    }
  done
  [ "$missing" -eq 0 ]
}

# --- Function coverage ---

@test "integration: domain-manager exports all dm_* functions" {
  source "${SCRIPTS_DIR}/tests/test_helper.sh"
  setup_test_env
  override_paths
  source "${SCRIPTS_DIR}/lib/domain-manager.sh"
  # Core functions must exist
  declare -f dm_register_domain >/dev/null
  declare -f dm_unregister_domain >/dev/null
  declare -f dm_list_domains >/dev/null
  declare -f dm_domain_exists >/dev/null
  declare -f dm_deploy_vhosts >/dev/null
  declare -f dm_deploy_parking >/dev/null
  declare -f dm_rebuild_opendkim >/dev/null
  declare -f dm_export_domain >/dev/null
  declare -f dm_import_domain >/dev/null
  declare -f dm_deploy_staging >/dev/null
  declare -f dm_set_group >/dev/null
  teardown_test_env
}

@test "integration: helpers exports key functions" {
  source "${SCRIPTS_DIR}/lib/core.sh"
  source "${SCRIPTS_DIR}/tests/test_helper.sh"
  source "${SCRIPTS_DIR}/lib/helpers.sh"
  declare -f deploy_dashboard >/dev/null
  declare -f deploy_healthz >/dev/null
  declare -f dry_run_wrap >/dev/null
  declare -f notify_all >/dev/null
  declare -f slog >/dev/null
  declare -f html_report_start >/dev/null
}

@test "integration: clone.sh exports key functions" {
  source "${SCRIPTS_DIR}/lib/core.sh"
  source "${SCRIPTS_DIR}/tests/test_helper.sh"
  source "${SCRIPTS_DIR}/lib/clone.sh"
  declare -f clone_generate_key >/dev/null
  declare -f clone_sync >/dev/null
  declare -f clone_preflight >/dev/null
}

# --- Flag coherence ---

@test "integration: --help does not crash" {
  # Capture just the help (override require_root)
  run bash -c "
    require_root() { :; }
    load_config() { :; }
    source '${SCRIPTS_DIR}/lib/core.sh'
    source '${SCRIPTS_DIR}/lib/constants.sh'
    show_help() { :; }
    source '${SCRIPTS_DIR}/debian13-server.sh' --help 2>&1 || true
  "
  # Should not have a bash syntax error
  [[ "$output" != *"syntax error"* ]]
}

# --- Dockerfile ---

@test "integration: Dockerfile.test exists" {
  [ -f "${SCRIPTS_DIR}/Dockerfile.test" ]
}

@test "integration: Makefile has test target" {
  [ -f "${SCRIPTS_DIR}/Makefile" ]
  grep -q "^test:" "${SCRIPTS_DIR}/Makefile"
}

@test "integration: Makefile has docker-test target" {
  grep -q "docker-test" "${SCRIPTS_DIR}/Makefile"
}
