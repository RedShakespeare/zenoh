#!/usr/bin/env bash
set -euo pipefail

# Matrix test for keepalive strategy modes.
# Runs verify_local.sh three times:
#   - disabled
#   - transport_closed_only
#   - inactivity
#
# Usage:
#   plugins/zenoh-plugin-robot-status/scripts/test_keepalive_modes.sh
#
# Optional env vars:
#   ZENOHD_PORT_BASE (default: 7448)
#   BACKEND_PORT_BASE (default: 18080)
#   PROJECT_ID (default: project-123)
#   AUTH_TOKEN (default: demo-token)
#   REPORT_MODE (default: http, supports http|dry_run)
#   PLUGIN_SO (default: ./target/debug/libzenoh_plugin_robot_status.so)
#   INACTIVITY_TIMEOUT_SECS (default: 3)
#   OTHER_TIMEOUT_SECS (default: 10)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

VERIFY_SCRIPT="plugins/zenoh-plugin-robot-status/scripts/verify_local.sh"
[[ -x "$VERIFY_SCRIPT" ]] || {
  echo "ERROR: verify script not executable: $VERIFY_SCRIPT" >&2
  exit 1
}

ZENOHD_PORT_BASE="${ZENOHD_PORT_BASE:-7448}"
BACKEND_PORT_BASE="${BACKEND_PORT_BASE:-18080}"
PROJECT_ID="${PROJECT_ID:-project-123}"
AUTH_TOKEN="${AUTH_TOKEN:-demo-token}"
REPORT_MODE="${REPORT_MODE:-http}"
PLUGIN_SO="${PLUGIN_SO:-./target/debug/libzenoh_plugin_robot_status.so}"
INACTIVITY_TIMEOUT_SECS="${INACTIVITY_TIMEOUT_SECS:-3}"
OTHER_TIMEOUT_SECS="${OTHER_TIMEOUT_SECS:-10}"

run_case() {
  local case_name="$1"
  local mode="$2"
  local timeout_secs="$3"
  local zport="$4"
  local bport="$5"

  echo
  echo "===== ${case_name} ====="
  echo "mode=${mode}, timeout_secs=${timeout_secs}, zenohd_port=${zport}, backend_port=${bport}"

  KEEPALIVE_MODE="$mode" \
  TIMEOUT_SECS="$timeout_secs" \
  ZENOHD_PORT="$zport" \
  BACKEND_PORT="$bport" \
  PROJECT_ID="$PROJECT_ID" \
  AUTH_TOKEN="$AUTH_TOKEN" \
  REPORT_MODE="$REPORT_MODE" \
  PLUGIN_SO="$PLUGIN_SO" \
  "$VERIFY_SCRIPT"
}

main() {
  local z0="$ZENOHD_PORT_BASE"
  local b0="$BACKEND_PORT_BASE"

  run_case "Case 1/3: disabled" "disabled" "$OTHER_TIMEOUT_SECS" "$z0" "$b0"
  run_case "Case 2/3: transport_closed_only" "transport_closed_only" "$OTHER_TIMEOUT_SECS" "$((z0 + 1))" "$((b0 + 1))"
  run_case "Case 3/3: inactivity" "inactivity" "$INACTIVITY_TIMEOUT_SECS" "$((z0 + 2))" "$((b0 + 2))"

  echo
  echo "✅ All keepalive mode test cases passed."
}

main "$@"
