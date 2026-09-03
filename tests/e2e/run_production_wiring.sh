#!/usr/bin/env bash
set -euo pipefail
E2E_DIR="${A4DIAG_E2E_DIR:-/tmp/a4diag-e2e}"
rm -rf -- "$E2E_DIR"
mkdir -p -- "$E2E_DIR"
export A4DIAG_E2E_DIR="$E2E_DIR"
python tests/e2e/run_production_wiring.py
test -s "$E2E_DIR/evidence.json"
