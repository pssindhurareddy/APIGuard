#!/usr/bin/env bash
# Run the full APIGuard automated test suite (macOS / Linux).
set -euo pipefail
cd "$(dirname "$0")/.."
"${PYTHON:-python3}" -m pytest backend/tests demo_api/tests -v "$@"
