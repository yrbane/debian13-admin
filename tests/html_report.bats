#!/usr/bin/env bats
# Point 25: HTML audit report

load test_helper

setup() {
  setup_test_env
  override_paths
  HTML_REPORT="${TEST_DIR}/report.html"
  CHECKS_OK=0
  CHECKS_WARN=0
  CHECKS_FAIL=0
  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/helpers.sh"
}

teardown() { teardown_test_env; }

# --- html_report_* ---

@test "html_report_start: creates HTML file with header" {
  html_report_start "Test Report"
  [ -f "$HTML_REPORT" ]
  grep -q "<html" "$HTML_REPORT"
  grep -q "Test Report" "$HTML_REPORT"
}

@test "html_report_section: adds section heading" {
  html_report_start "Report"
  html_report_section "Security Checks"
  grep -q "Security Checks" "$HTML_REPORT"
}

@test "html_report_check: adds ok entry" {
  html_report_start "Report"
  html_report_check "ok" "SSH hardened"
  grep -q "SSH hardened" "$HTML_REPORT"
  grep -q "ok" "$HTML_REPORT"
}

@test "html_report_check: adds warn entry" {
  html_report_start "Report"
  html_report_check "warn" "TLS 1.0 enabled"
  grep -q "warn" "$HTML_REPORT"
}

@test "html_report_check: adds fail entry" {
  html_report_start "Report"
  html_report_check "fail" "No firewall"
  grep -q "fail" "$HTML_REPORT"
}

@test "html_report_end: closes HTML tags and adds summary" {
  html_report_start "Report"
  html_report_check "ok" "test1"
  html_report_check "warn" "test2"
  html_report_end
  grep -q "</html>" "$HTML_REPORT"
}

@test "html_report: full workflow produces valid structure" {
  html_report_start "Audit $(date +%F)"
  html_report_section "Firewall"
  html_report_check "ok" "UFW active"
  html_report_check "ok" "SSH port restricted"
  html_report_section "TLS"
  html_report_check "warn" "TLSv1.1 not disabled"
  html_report_end
  # Should have opening and closing tags
  grep -q "<html" "$HTML_REPORT"
  grep -q "</html>" "$HTML_REPORT"
  # Sections present
  grep -q "Firewall" "$HTML_REPORT"
  grep -q "TLS" "$HTML_REPORT"
}

@test "html_report_start: no-op when HTML_REPORT unset" {
  unset HTML_REPORT
  run html_report_start "Test"
  [ "$status" -eq 0 ]
}
