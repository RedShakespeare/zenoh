#!/usr/bin/env bash
set -euo pipefail

# Local end-to-end verification for zenoh-plugin-robot-status.
# It will:
#   1) start a fake HTTP backend to capture PATCH calls,
#   2) start zenohd with robot_status plugin,
#   3) start multiple clients with fixed IDs,
#   4) stop clients one by one,
#   5) verify ONLINE/OFFLINE pair for each client id.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

ZENOHD_PORT="${ZENOHD_PORT:-7448}"
BACKEND_PORT="${BACKEND_PORT:-18080}"
PROJECT_ID="${PROJECT_ID:-project-123}"
AUTH_TOKEN="${AUTH_TOKEN:-demo-token}"
KEEPALIVE_MODE="${KEEPALIVE_MODE:-disabled}"
TIMEOUT_SECS="${TIMEOUT_SECS:-10}"
PLUGIN_SO="${PLUGIN_SO:-./target/debug/libzenoh_plugin_robot_status.so}"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"

CLIENT_IDS=(
  "3c95e7dca08d8f0f906801e9636aaa79"
  "7a599bcc7512b97f5f10df5d5e12ee04"
  "5664c34d6e813e0b4b6d43c18cc1db4"
)

WORK_DIR="${TMPDIR:-/tmp}/zenoh_robot_status_verify_$$"
mkdir -p "$WORK_DIR"
BACKEND_LOG="$WORK_DIR/backend.log"
BACKEND_PID_FILE="$WORK_DIR/backend.pid"
touch "$BACKEND_LOG"

dump_logs() {
  echo "--- backend.log ---" >&2
  cat "$BACKEND_LOG" >&2 || true
  echo "--- zenohd.log ---" >&2
  cat "$WORK_DIR/zenohd.log" >&2 || true
  for f in "$WORK_DIR"/client_*.log; do
    [[ -f "$f" ]] || continue
    echo "--- $(basename "$f") ---" >&2
    cat "$f" >&2 || true
  done
}

fail() {
  echo "ERROR: $1" >&2
  dump_logs
  exit 1
}

cleanup() {
  set +e
  for pid_file in "$WORK_DIR"/*.pid; do
    [[ -f "$pid_file" ]] || continue
    pid="$(cat "$pid_file")"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ "$KEEP_WORK_DIR" == "1" ]]; then
    echo "KEEP_WORK_DIR=1, logs preserved at: $WORK_DIR"
  else
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

start_fake_backend() {
  python3 - <<'PY' "$BACKEND_PORT" "$BACKEND_LOG" "$BACKEND_PID_FILE" &
import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
log_file = sys.argv[2]
pid_file = sys.argv[3]

class H(BaseHTTPRequestHandler):
    def do_PATCH(self):
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"PATCH {self.path}\n")
            f.write(f"X-Auth-Token: {self.headers.get('X-Auth-Token')}\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass

with open(pid_file, "w", encoding="utf-8") as f:
    f.write(str(os.getpid()))

HTTPServer(("127.0.0.1", port), H).serve_forever()
PY

  sleep 1

  [[ -f "$BACKEND_PID_FILE" ]] || fail "backend failed to start (missing pid file)"
  kill -0 "$(cat "$BACKEND_PID_FILE")" 2>/dev/null || fail "backend process is not running"
}

ensure_binaries() {
  echo "[1/6] Building plugin + zenohd + example client..."
  cargo build -p zenoh-plugin-robot-status -p zenohd --manifest-path Cargo.toml >/dev/null
  cargo build --manifest-path examples/Cargo.toml --example z_pub >/dev/null

  [[ -f "$PLUGIN_SO" ]] || fail "plugin library not found: $PLUGIN_SO"
}

start_zenohd() {
  echo "[2/6] Starting zenohd with robot_status plugin..."
  ./target/debug/zenohd \
    -l "tcp/0.0.0.0:${ZENOHD_PORT}" \
    -P "robot_status:${PLUGIN_SO}" \
    --cfg="plugins/robot_status:{api_base_url:\"http://127.0.0.1:${BACKEND_PORT}\",auth_token:\"${AUTH_TOKEN}\",project_id:\"${PROJECT_ID}\",keepalive:{mode:\"${KEEPALIVE_MODE}\",timeout_secs:${TIMEOUT_SECS}}}" \
    >"$WORK_DIR/zenohd.log" 2>&1 &
  echo $! > "$WORK_DIR/zenohd.pid"
  sleep 2
}

start_clients() {
  echo "[3/6] Starting ${#CLIENT_IDS[@]} clients with fixed IDs..."
  for i in "${!CLIENT_IDS[@]}"; do
    id="${CLIENT_IDS[$i]}"
    cargo run --manifest-path examples/Cargo.toml --example z_pub -- \
      -m client \
      -e "tcp/127.0.0.1:${ZENOHD_PORT}" \
      --cfg="id:\"${id}\"" \
      >"$WORK_DIR/client_${i}.log" 2>&1 &
    echo $! > "$WORK_DIR/client_${i}.pid"
  done
  sleep 5
}

stop_clients_one_by_one() {
  echo "[4/6] Stopping clients one by one..."
  for i in "${!CLIENT_IDS[@]}"; do
    pid="$(cat "$WORK_DIR/client_${i}.pid")"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep 2
  done
}

assert_backend_results() {
  echo "[5/6] Verifying backend PATCH records..."
  sleep 2

  for id in "${CLIENT_IDS[@]}"; do
    online="PATCH /v1/${PROJECT_ID}/robots/${id}/status?status=ONLINE"
    offline="PATCH /v1/${PROJECT_ID}/robots/${id}/status?status=OFFLINE"

    grep -F "$online" "$BACKEND_LOG" >/dev/null || fail "missing ONLINE for ${id}"
    grep -F "$offline" "$BACKEND_LOG" >/dev/null || fail "missing OFFLINE for ${id}"
  done

  grep -F "X-Auth-Token: ${AUTH_TOKEN}" "$BACKEND_LOG" >/dev/null || fail "missing auth token header"
  echo "Auth token header verified."
}

main() {
  echo "Logs temp dir: $WORK_DIR"
  start_fake_backend
  ensure_binaries
  start_zenohd
  start_clients
  stop_clients_one_by_one
  assert_backend_results

  echo "[6/6] ✅ Verification succeeded."
  echo "Backend log:" && cat "$BACKEND_LOG"
}

main
