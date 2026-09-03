#!/usr/bin/env bash
set -euo pipefail
E2E_DIR="${A4DIAG_E2E_DIR:-/tmp/a4diag-e2e}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$ROOT_DIR/src:$ROOT_DIR/packages/a4diag-builtin-plugins/src:$ROOT_DIR/packages/a4diag-target-runtime/src${PYTHONPATH:+:$PYTHONPATH}"
rm -rf -- "$E2E_DIR"
mkdir -p -- "$E2E_DIR"
export A4DIAG_E2E_DIR="$E2E_DIR"
python tests/e2e/run_production_wiring.py
test -s "$E2E_DIR/evidence.json"
