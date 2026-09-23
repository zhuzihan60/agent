#!/usr/bin/env bash
set -euo pipefail

# The caller starts this script with sudo unshare --mount --propagation private.
source_tree="$1"
python="$2"
test_root="$(mktemp -d /opt/a4diag-privileged-pytest.XXXXXXXX)"
trap 'rm -rf -- "$test_root"' EXIT
mkdir -m 700 "$test_root/source" "$test_root/tmp"
cp -a "$source_tree/." "$test_root/source/"
chown -R root:root "$test_root/source"
cd "$test_root/source"
export TMPDIR="$test_root/tmp"
export PYTHONPATH="$PWD/src:$PWD/packages/a4diag-builtin-plugins/src:$PWD/packages/a4diag-target-runtime/src"
export PYTHONDONTWRITEBYTECODE=1
"$python" -m pytest -p no:cacheprovider -q -rs -m privileged_linux
