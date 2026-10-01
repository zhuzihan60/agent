#!/usr/bin/env bash
# Download the python-build-standalone archive pinned in tools/build_release.py
# and refuse it unless its SHA-256 matches the pinned digest.
set -euo pipefail

output="${1:?usage: fetch_python_runtime.sh OUTPUT_FILE}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="$(cd "$root" && python -c 'from tools.build_release import PYTHON_RUNTIME_NAME; print(PYTHON_RUNTIME_NAME)')"
digest="$(cd "$root" && python -c 'from tools.build_release import PYTHON_RUNTIME_SHA256; print(PYTHON_RUNTIME_SHA256)')"
tag="${name#*+}"
tag="${tag%%-*}"
url="https://github.com/astral-sh/python-build-standalone/releases/download/${tag}/${name//+/%2B}"

curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --max-time 600 -o "$output.part" "$url"
echo "${digest}  $output.part" | sha256sum -c - >/dev/null || {
  rm -f "$output.part"
  echo "fetch_python_runtime: digest mismatch for $url" >&2
  exit 1
}
mv -f "$output.part" "$output"
echo "fetch_python_runtime: $name verified"
