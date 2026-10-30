#!/usr/bin/env bash
# Launch APIGuard on macOS / Linux (demo APIs, VAmPI benchmark, backend + dashboard). Ctrl+C stops everything.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
LOG="$ROOT/logs"; mkdir -p "$LOG"

pids=()
cleanup() { echo; echo "Stopping APIGuard services..."; kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

"$PY" -m demo_api.app.main --mode vulnerable --port 8001 >"$LOG/vulnerable_api.log" 2>&1 & pids+=($!)
"$PY" -m demo_api.app.main --mode secure     --port 8002 >"$LOG/secure_api.log"     2>&1 & pids+=($!)
"$PY" third_party/run_vampi.py --mode vulnerable --port 8003 >"$LOG/vampi_vulnerable.log" 2>&1 & pids+=($!)
"$PY" third_party/run_vampi.py --mode secure     --port 8004 >"$LOG/vampi_secure.log"     2>&1 & pids+=($!)
"$PY" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 >"$LOG/backend.log" 2>&1 & pids+=($!)

echo "Vulnerable demo API : http://127.0.0.1:8001"
echo "Secure demo API     : http://127.0.0.1:8002"
echo "VAmPI vulnerable    : http://127.0.0.1:8003"
echo "VAmPI secure mode   : http://127.0.0.1:8004"
echo "Dashboard + backend : http://127.0.0.1:8000"
echo "Logs in $LOG — press Ctrl+C to stop."
wait
