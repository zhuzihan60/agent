#!/usr/bin/env bash
set -euo pipefail
if [[ "${CI:-}" != "true" || "${GITHUB_ACTIONS:-}" != "true" || "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]]; then
  echo "production wiring harness is restricted to the disposable GitHub Linux runner" >&2
  exit 64
fi
E2E_DIR="${A4DIAG_E2E_DIR-/tmp/a4diag-e2e}"
if [[ -z "$E2E_DIR" ]]; then
  echo "E2E directory must not be empty" >&2
  exit 64
fi
E2E_DIR="$(realpath -m -- "$E2E_DIR")"
case "$E2E_DIR" in
  /tmp/a4diag-e2e|/tmp/a4diag-e2e/*) ;;
  *) echo "E2E directory must remain beneath /tmp/a4diag-e2e" >&2; exit 64 ;;
esac
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$ROOT_DIR/src:$ROOT_DIR/packages/a4diag-builtin-plugins/src:$ROOT_DIR/packages/a4diag-target-runtime/src${PYTHONPATH:+:$PYTHONPATH}"
rm -rf -- "$E2E_DIR"
mkdir -p -- "$E2E_DIR"
export A4DIAG_E2E_DIR="$E2E_DIR"
sudo --preserve-env=CI,GITHUB_ACTIONS,RUNNER_ENVIRONMENT,PYTHONPATH,A4DIAG_E2E_DIR,PATH \
  "$(command -v python)" tests/e2e/run_production_wiring.py
test -s "$E2E_DIR/evidence.json"
sudo --preserve-env=CI,GITHUB_ACTIONS,RUNNER_ENVIRONMENT,PYTHONPATH,A4DIAG_E2E_DIR,PATH \
  "$(command -v python)" tests/e2e/run_plugin_deployment_smoke.py
test -s "$E2E_DIR/plugin-deployment-smoke.json"
