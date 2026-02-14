#!/usr/bin/env bats
# Point 5: TUI helpers (whiptail/dialog abstraction)

load test_helper

setup() {
  setup_test_env
  override_paths
  # Mock whiptail
  whiptail() {
    echo "WHIPTAIL:$*" >> "${TEST_DIR}/whiptail.log"
    # Simulate user selecting first option
    case "$1" in
      --yesno) return 0 ;;
      --inputbox) echo "user_input" ;;
      --menu) echo "option1" ;;
      --checklist) echo '"opt1" "opt3"' ;;
      --msgbox) return 0 ;;
    esac
  }
  export -f whiptail

  # Ensure whiptail is "available"
  TUI_BACKEND="whiptail"

  source "${BATS_TEST_DIRNAME}/../lib/core.sh"
  source "${BATS_TEST_DIRNAME}/../lib/tui.sh"
}

teardown() { teardown_test_env; }

# --- tui_yesno ---

@test "tui_yesno: returns 0 for yes" {
  run tui_yesno "Proceed?" "Continue"
  [ "$status" -eq 0 ]
}

@test "tui_yesno: calls whiptail with correct args" {
  tui_yesno "Install SSH?" "SSH Setup"
  grep -q "yesno" "${TEST_DIR}/whiptail.log"
  grep -q "Install SSH" "${TEST_DIR}/whiptail.log"
}

# --- tui_input ---

@test "tui_input: returns user input" {
  run tui_input "Enter hostname:" "Hostname" "default.com"
  [ "$output" = "user_input" ]
}

@test "tui_input: calls whiptail with inputbox" {
  tui_input "Port:" "SSH Port" "22"
  grep -q "inputbox" "${TEST_DIR}/whiptail.log"
}

# --- tui_menu ---

@test "tui_menu: returns selected option" {
  run tui_menu "Choose:" "Menu" "opt1" "Option 1" "opt2" "Option 2"
  [ "$output" = "option1" ]
}

# --- tui_checklist ---

@test "tui_checklist: returns selected options" {
  run tui_checklist "Select:" "Features" "opt1" "Feature 1" "on" "opt2" "Feature 2" "off" "opt3" "Feature 3" "on"
  [[ "$output" == *"opt1"* ]]
}

# --- tui_msg ---

@test "tui_msg: displays message" {
  run tui_msg "Done!" "Complete"
  [ "$status" -eq 0 ]
  grep -q "msgbox" "${TEST_DIR}/whiptail.log"
}

# --- tui_available ---

@test "tui_available: returns 0 when backend exists" {
  run tui_available
  [ "$status" -eq 0 ]
}

@test "tui_available: returns 1 when no backend" {
  TUI_BACKEND="nonexistent_tool_xyz"
  run tui_available
  [ "$status" -ne 0 ]
}

# --- fallback to plain text ---

@test "tui_yesno: falls back to plain when no TUI" {
  TUI_BACKEND="nonexistent_tool_xyz"
  # Simulate stdin "y"
  run bash -c "
    source '${BATS_TEST_DIRNAME}/../lib/core.sh'
    TUI_BACKEND=nonexistent_tool_xyz
    source '${BATS_TEST_DIRNAME}/../lib/tui.sh'
    echo y | tui_yesno 'Proceed?' 'Test'
  "
  [ "$status" -eq 0 ]
}
