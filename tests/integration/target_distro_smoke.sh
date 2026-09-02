#!/usr/bin/env bash
set -euo pipefail

release="${TARGET_RELEASE_DIR:-/target-release}"
config="$(mktemp)"
trap 'rm -f "$config"' EXIT
cat >"$config" <<'JSON'
{"protocol_version":"1.0","target_id":"ci-sandbox","ssh_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyController ci","operation_public_key":"-----BEGIN PUBLIC KEY-----\nTEST-ONLY\n-----END PUBLIC KEY-----\n","controller_key_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_source_cidrs":["127.0.0.1/32"],"managed_resources":[],"confirm_managed_resources":"DISABLED"}
JSON

echo "target-distro-smoke: verify exact inventory"
python3.11 tools/build_release.py verify-target-release --release-root "$release"

echo "target-distro-smoke: offline install with no managed resources"
A4DIAG_TARGET_SKIP_SYSTEMD=1 \
  A4DIAG_TARGET_MACHINE_ID=0123456789abcdef0123456789abcdef \
  bash "$release/tools/install_target_lib.sh" install "$release" "$config"

test -x /usr/libexec/a4diag/a4diag-transport-helper
test "$(stat -c %a /usr/libexec/a4diag/a4diag-transport-helper)" = 755
test "$(stat -c %a /etc/a4diag-target/operation-public.pem)" = 644
test "$(stat -c %a /var/lib/a4diag-target/executor)" = 700
grep -Fq 'restrict,command="/usr/libexec/a4diag/a4diag-transport-helper"' /var/lib/a4diag-target/.ssh/authorized_keys
! find /opt/a4diag-target /etc/a4diag-target /var/lib/a4diag-target -name '*private.pem' -print -quit | grep -q .

echo "target-distro-smoke: idempotent reinstall"
A4DIAG_TARGET_SKIP_SYSTEMD=1 \
  A4DIAG_TARGET_MACHINE_ID=0123456789abcdef0123456789abcdef \
  bash "$release/tools/install_target_lib.sh" install "$release" "$config"
echo "target-distro-smoke: PASS"
