#!/usr/bin/env bats
# Point 6: Monitoring et alertes proactives

load test_helper

setup() {
  setup_test_env
  override_paths
  HOSTNAME_FQDN="main.com"
  EMAIL_FOR_CERTBOT="admin@main.com"
  ALERT_LOG="${TEST_DIR}/alerts.log"

  # Mock notify_all
  notify_all() { echo "NOTIFY:$*" >> "$ALERT_LOG"; }
  export -f notify_all

  # Mock systemctl
  systemctl() {
    case "$2" in
      apache2|postfix|fail2ban|ufw|mariadb) echo "active" ;;
      *) echo "inactive" ;;
    esac
  }
  export -f systemctl

  # Mock df
  df() { echo "Filesystem Size Used Avail Use% Mounted"; echo "/dev/sda1 50G 30G 20G 60% /"; }
  export -f df

  # Mock mailq
  mailq() { echo "Mail queue is empty"; }
  export -f mailq

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- monitor_check_services ---

@test "monitor_check_services: returns 0 when all services running" {
  run monitor_check_services
  [ "$status" -eq 0 ]
}

@test "monitor_check_services: alerts when service is down" {
  systemctl() { echo "inactive"; }
  export -f systemctl
  run monitor_check_services
  [ "$status" -ne 0 ]
}

# --- monitor_check_disk ---

@test "monitor_check_disk: returns 0 when disk usage normal" {
  run monitor_check_disk 85
  [ "$status" -eq 0 ]
}

@test "monitor_check_disk: alerts when disk usage high" {
  df() { echo "Filesystem Size Used Avail Use% Mounted"; echo "/dev/sda1 50G 45G 5G 90% /"; }
  export -f df
  run monitor_check_disk 85
  [ "$status" -ne 0 ]
}

# --- monitor_check_ssl ---

@test "monitor_check_ssl: returns 0 when no certs to check" {
  LETSENCRYPT_DIR="${TEST_DIR}/le-empty"
  mkdir -p "$LETSENCRYPT_DIR"
  run monitor_check_ssl 14
  [ "$status" -eq 0 ]
}

@test "monitor_check_ssl: alerts when cert expiring soon" {
  LETSENCRYPT_DIR="${TEST_DIR}/le"
  mkdir -p "${LETSENCRYPT_DIR}/live/main.com"
  # Create a self-signed cert expiring in 5 days
  openssl req -x509 -newkey rsa:1024 -keyout /dev/null -out "${LETSENCRYPT_DIR}/live/main.com/fullchain.pem" \
    -days 5 -nodes -subj "/CN=main.com" 2>/dev/null
  run monitor_check_ssl 14
  [ "$status" -ne 0 ]
}

# --- monitor_check_postfix ---

@test "monitor_check_postfix: returns 0 when queue empty" {
  run monitor_check_postfix 50
  [ "$status" -eq 0 ]
}

@test "monitor_check_postfix: alerts when queue saturated" {
  mailq() { echo "-- 100 Kbytes in 75 Requests."; }
  export -f mailq
  run monitor_check_postfix 50
  [ "$status" -ne 0 ]
}

# --- monitor_run_all ---

@test "monitor_run_all: returns summary" {
  run monitor_run_all
  [[ "$output" == *"OK"* ]] || [[ "$output" == *"ok"* ]] || [[ "$output" == *"checks"* ]] || [ "$status" -eq 0 ]
}

# --- deploy_monitor_cron ---

@test "deploy_monitor_cron: creates monitoring script" {
  MONITOR_SCRIPT="${TEST_DIR}/monitor.sh"
  deploy_monitor_cron
  [ -f "$MONITOR_SCRIPT" ]
  [[ $(stat -c %a "$MONITOR_SCRIPT") =~ [1357] ]]
}
