#!/usr/bin/env bats
# Point 14: Conteneurisation — dm_deploy_container / dm_stop_container / dm_container_status / dm_container_logs

load test_helper

setup() {
  setup_test_env
  override_paths

  HOSTNAME_FQDN="main.com"

  # Mock docker
  docker_calls="${TEST_DIR}/docker.log"
  docker() {
    echo "$*" >> "$docker_calls"
    case "$1" in
      run)
        # Simulate returning a container ID
        echo "abc123def456"
        ;;
      ps)
        echo "CONTAINER ID   IMAGE   STATUS"
        echo "abc123def456   nginx   Up 2 hours"
        ;;
      logs)
        echo "[2026-02-14] Container started"
        echo "[2026-02-14] Listening on port 80"
        ;;
      stop)
        echo "abc123def456"
        ;;
    esac
    return 0
  }
  export -f docker

  # Mock systemctl (Apache reload)
  systemctl() { return 0; }
  export -f systemctl

  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

# --- dm_deploy_container ---

@test "dm_deploy_container: calls docker run" {
  dm_deploy_container "app.example.com" "nginx:latest"
  [ -f "$docker_calls" ]
  grep -q "run" "$docker_calls"
}

@test "dm_deploy_container: container name derived from domain" {
  dm_deploy_container "app.example.com" "nginx:latest"
  grep -q "app.example.com\|app_example_com\|app-example-com" "$docker_calls"
}

@test "dm_deploy_container: stores container info in per-domain config" {
  dm_register_domain "app.example.com" "mail"
  dm_deploy_container "app.example.com" "nginx:latest"
  local image
  image=$(dm_get_domain_config "app.example.com" "CONTAINER_IMAGE")
  [ "$image" = "nginx:latest" ]
}

@test "dm_deploy_container: sets up proxy VHost" {
  dm_register_domain "app.example.com" "mail"
  dm_deploy_container "app.example.com" "nginx:latest"
  # Should create a proxy config (reuses dm_deploy_proxy)
  ls "${APACHE_SITES_DIR}/"*app.example.com*proxy* >/dev/null 2>&1 || \
    ls "${APACHE_SITES_DIR}/"*app.example.com* >/dev/null 2>&1
}

@test "dm_deploy_container: passes image to docker run" {
  dm_deploy_container "app.example.com" "nginx:latest"
  grep -q "nginx:latest" "$docker_calls"
}

# --- dm_stop_container ---

@test "dm_stop_container: calls docker stop" {
  dm_register_domain "app.example.com" "mail"
  dm_deploy_container "app.example.com" "nginx:latest"
  dm_stop_container "app.example.com"
  grep -q "stop" "$docker_calls"
}

@test "dm_stop_container: uses container name derived from domain" {
  dm_register_domain "app.example.com" "mail"
  dm_deploy_container "app.example.com" "nginx:latest"
  dm_stop_container "app.example.com"
  # The stop call should reference the domain-based container name
  local stop_line
  stop_line=$(grep "stop" "$docker_calls" | tail -1)
  [[ "$stop_line" == *"app.example.com"* ]] || [[ "$stop_line" == *"app_example_com"* ]] || [[ "$stop_line" == *"app-example-com"* ]]
}

# --- dm_container_status ---

@test "dm_container_status: calls docker ps" {
  dm_deploy_container "app.example.com" "nginx:latest"
  run dm_container_status "app.example.com"
  [ "$status" -eq 0 ]
  grep -q "ps" "$docker_calls"
}

@test "dm_container_status: returns container status output" {
  dm_deploy_container "app.example.com" "nginx:latest"
  run dm_container_status "app.example.com"
  [[ "$output" == *"Up"* ]] || [[ "$output" == *"abc123"* ]] || [[ "$output" == *"STATUS"* ]]
}

# --- dm_container_logs ---

@test "dm_container_logs: calls docker logs" {
  dm_deploy_container "app.example.com" "nginx:latest"
  run dm_container_logs "app.example.com"
  [ "$status" -eq 0 ]
  grep -q "logs" "$docker_calls"
}

@test "dm_container_logs: returns log output" {
  dm_deploy_container "app.example.com" "nginx:latest"
  run dm_container_logs "app.example.com"
  [[ "$output" == *"Container started"* ]] || [[ "$output" == *"Listening"* ]]
}
