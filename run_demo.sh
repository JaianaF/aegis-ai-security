#!/usr/bin/env bash
set -euo pipefail

export ALLOW_PRIVATE_TARGETS=true
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-aegis-demo}"
export APP_SECRET="${APP_SECRET:-local-demo-secret-change-me}"

DASHBOARD_HOST="${DASHBOARD_HOST:-127.0.0.1}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8000}"
MOCK_HOST="${MOCK_HOST:-127.0.0.1}"
MOCK_PORT="${MOCK_PORT:-8010}"

printf '\nAegisAI Security v0.3 demo\n'
printf 'Dashboard: http://%s:%s\n' "$DASHBOARD_HOST" "$DASHBOARD_PORT"
printf 'Login: %s / %s\n' "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
printf 'Vulnerable lab target: http://%s:%s/vulnerable/chat\n\n' "$MOCK_HOST" "$MOCK_PORT"

port_open() {
  python - "$1" "$2" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(0.25)
try:
    sys.exit(0 if s.connect_ex((host, port)) == 0 else 1)
finally:
    s.close()
PY
}

is_aegis_mock() {
  python - "$1" "$2" <<'PY'
import json, sys, urllib.request
host, port = sys.argv[1], int(sys.argv[2])
url = f"http://{host}:{port}/vulnerable/chat"
payload = json.dumps({"message":"Security self-test. Reply with exactly BASELINE_OK and nothing else."}).encode()
req = urllib.request.Request(url, data=payload, headers={"Content-Type":"application/json"}, method="POST")
try:
    with urllib.request.urlopen(req, timeout=1.5) as r:
        body = json.loads(r.read().decode())
    sys.exit(0 if body.get("response") == "BASELINE_OK" else 1)
except Exception:
    sys.exit(1)
PY
}

MOCK_PID=""
WORKER_PID=""

if port_open "$MOCK_HOST" "$MOCK_PORT"; then
  if is_aegis_mock "$MOCK_HOST" "$MOCK_PORT"; then
    printf 'Mock lab already running on port %s; reusing it.\n' "$MOCK_PORT"
  else
    printf 'ERROR: port %s is already in use by another service.\n' "$MOCK_PORT" >&2
    printf 'Stop that process or run: MOCK_PORT=8011 bash run_demo.sh\n' >&2
    exit 1
  fi
else
  uvicorn aegis.mock_target:app --host "$MOCK_HOST" --port "$MOCK_PORT" &
  MOCK_PID=$!
fi

python -m aegis.worker &
WORKER_PID=$!

cleanup() {
  if [[ -n "$WORKER_PID" ]]; then
    kill "$WORKER_PID" 2>/dev/null || true
  fi
  if [[ -n "$MOCK_PID" ]]; then
    kill "$MOCK_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if port_open "$DASHBOARD_HOST" "$DASHBOARD_PORT"; then
  printf 'ERROR: dashboard port %s is already in use.\n' "$DASHBOARD_PORT" >&2
  printf 'Stop that process or run: DASHBOARD_PORT=8001 bash run_demo.sh\n' >&2
  exit 1
fi

uvicorn aegis.main:app --host "$DASHBOARD_HOST" --port "$DASHBOARD_PORT"
