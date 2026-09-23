#!/usr/bin/env bash
set -euo pipefail

# The caller starts this script with sudo unshare --mount --propagation private.
source_tree="$1"
python="$2"
shift 2
test_root="$(mktemp -d /var/lib/a4diag-ci-privileged-pytest.XXXXXXXX)"
[[ "$test_root" == /var/lib/a4diag-ci-privileged-pytest.* && -d "$test_root" ]] || exit 1
trap 'rm -rf -- "$test_root"' EXIT
mkdir -m 700 "$test_root/source" "$test_root/tmp"
cp -a "$source_tree/." "$test_root/source/"
chown -R root:root "$test_root/source"
chmod 0700 "$test_root/source"
cd "$test_root/source"
export TMPDIR="$test_root/tmp"
export PYTHONPATH="$PWD:$PWD/src:$PWD/packages/a4diag-builtin-plugins/src:$PWD/packages/a4diag-target-runtime/src"
export PYTHONDONTWRITEBYTECODE=1
"$python" - <<'PY'
from pathlib import Path
import tests.target_runtime.test_repair_disk as disk_tests

source = Path.cwd().resolve()
for ancestor in (source, *source.parents):
    info = ancestor.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit(f"untrusted privileged test path: {ancestor} uid={info.st_uid} mode={info.st_mode & 0o777:04o}")
module = Path(disk_tests.__file__).resolve()
if module != source / "tests/target_runtime/test_repair_disk.py":
    raise SystemExit(f"privileged tests imported from {module}, expected {source}")
print(f"privileged test source: {source}; disk fixture: {module}", flush=True)
PY
"$python" -m pytest -p no:cacheprovider --basetemp="$test_root/t" -q -rs -m privileged_linux "$@"
