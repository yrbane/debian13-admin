#!/usr/bin/env bats
# Point 24: Multi-channel notifications

load test_helper

setup() {
  setup_test_env
  override_paths

  CURL_CALLS="${TEST_DIR}/curl_calls.log"
  curl() { echo "$*" >> "$CURL_CALLS"; return 0; }
  export -f curl

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- notify_slack ---

@test "notify_slack: sends to webhook URL" {
  SLACK_WEBHOOK="https://hooks.slack.com/test"
  notify_slack "Test message"
  [ -f "$CURL_CALLS" ]
  grep -q "hooks.slack.com" "$CURL_CALLS"
}

@test "notify_slack: skips when no webhook" {
  unset SLACK_WEBHOOK
  run notify_slack "Test message"
  [ "$status" -eq 0 ]
  [ ! -f "$CURL_CALLS" ]
}

# --- notify_telegram ---

@test "notify_telegram: sends to bot API" {
  TELEGRAM_BOT_TOKEN="123:ABC"
  TELEGRAM_CHAT_ID="-100123"
  notify_telegram "Test message"
  [ -f "$CURL_CALLS" ]
  grep -q "api.telegram.org" "$CURL_CALLS"
}

@test "notify_telegram: skips when no token" {
  unset TELEGRAM_BOT_TOKEN
  run notify_telegram "Test message"
  [ "$status" -eq 0 ]
  [ ! -f "$CURL_CALLS" ]
}

# --- notify_discord ---

@test "notify_discord: sends to webhook URL" {
  DISCORD_WEBHOOK="https://discord.com/api/webhooks/test"
  notify_discord "Test message"
  [ -f "$CURL_CALLS" ]
  grep -q "discord.com" "$CURL_CALLS"
}

# --- notify_all ---

@test "notify_all: sends to all configured channels" {
  SLACK_WEBHOOK="https://hooks.slack.com/test"
  TELEGRAM_BOT_TOKEN="123:ABC"
  TELEGRAM_CHAT_ID="-100123"
  notify_all "Multi-channel test"
  [ -f "$CURL_CALLS" ]
  grep -q "slack.com" "$CURL_CALLS"
  grep -q "telegram.org" "$CURL_CALLS"
}

@test "notify_all: works with no channels configured" {
  unset SLACK_WEBHOOK TELEGRAM_BOT_TOKEN DISCORD_WEBHOOK
  run notify_all "No channels"
  [ "$status" -eq 0 ]
}
