#!/usr/bin/env bash
set -euo pipefail
export ALLOW_PRIVATE_TARGETS=true
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-aegis-demo}"
export APP_SECRET="${APP_SECRET:-local-demo-secret-change-me}"

printf '\nAegisAI Security v0.2 demo\n'
printf 'Dashboard: http://127.0.0.1:8000\n'
printf 'Login: %s / %s\n' "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
printf 'Vulnerable lab target: http://127.0.0.1:8010/vulnerable/chat\n\n'

uvicorn aegis.mock_target:app --host 127.0.0.1 --port 8010 &
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null || true' EXIT
uvicorn aegis.main:app --host 127.0.0.1 --port 8000
