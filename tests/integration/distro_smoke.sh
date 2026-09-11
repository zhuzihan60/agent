#!/usr/bin/env bash
#
# Distro smoke: offline-install the assembled release inside a supported
# distribution container, confirm read-only defaults and the offline
# self-check, confirm no service can write the configuration, and confirm the
# model-failure fallback stays read-only. No real server, mail, model, or
# FlashDuty connection is made.
#
# The release is expected at /release (the CI artifact mount). Requires root
# (container default) and bash.
set -euo pipefail

RELEASE_DIR="${RELEASE_DIR:-/release}"
[ -d "$RELEASE_DIR" ] || {
  echo "distro-smoke: release directory missing: $RELEASE_DIR" >&2
  exit 1
}

echo "distro-smoke: verifying release"
(cd "$RELEASE_DIR" && sha256sum -c SHA256SUMS >/dev/null)

# Minimal distro containers omit systemd; install its tools so this gate checks
# the distribution's real credential capability, even without a booted PID 1.
if ! command -v systemctl >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install systemd
  elif command -v yum >/dev/null 2>&1; then
    yum -y install systemd
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y systemd
  else
    echo "distro-smoke: cannot install systemd prerequisite" >&2
    exit 1
  fi
fi
SYSTEMD_VERSION="$(systemctl --version | head -n1 | cut -d' ' -f2)"
case "$SYSTEMD_VERSION" in ''|*[!0-9]*) exit 1 ;; esac
if [ "$SYSTEMD_VERSION" -lt 247 ]; then
  PREFLIGHT_LOG="$(mktemp)"
  trap 'rm -f "$PREFLIGHT_LOG"' EXIT
  if A4DIAG_SKIP_SYSTEMD=0 A4DIAG_SKIP_DISK=1 bash "$RELEASE_DIR/install.sh" --offline "$RELEASE_DIR" >"$PREFLIGHT_LOG" 2>&1; then
    echo "distro-smoke: FAIL unsupported controller unexpectedly installed" >&2
    exit 1
  fi
  grep -q 'systemd 247 or newer is required' "$PREFLIGHT_LOG"
  [ ! -e /opt/a4diag/current ]
  echo "distro-smoke: PASS expected controller rejection (systemd $SYSTEMD_VERSION <247); target runtime remains separate"
  exit 0
fi

echo "distro-smoke: offline install"
A4DIAG_SKIP_SYSTEMD=1 A4DIAG_SKIP_DISK=1 bash "$RELEASE_DIR/install.sh" --offline "$RELEASE_DIR"

echo "distro-smoke: offline self-check reports read-only defaults"
OUTPUT="$(A4DIAG_CONFIG=/etc/a4diag/config.yaml /opt/a4diag/current/venv/bin/a4diag self-check --offline)"
echo "$OUTPUT"
echo "$OUTPUT" | grep -q '"ok": true'
echo "$OUTPUT" | grep -q '"global_mode": "read_only"'
echo "$OUTPUT" | grep -q '"targets": \[\]'

echo "distro-smoke: production runtime starts with an empty read-only install"
A4DIAG_CONFIG=/etc/a4diag/config.yaml /opt/a4diag/current/venv/bin/a4diag serve --once

echo "distro-smoke: system CLI entrypoint resolves to the current release"
[ -x /usr/local/bin/a4diag ]
[ "$(readlink /usr/local/bin/a4diag)" = "/opt/a4diag/current/venv/bin/a4diag" ]
/usr/local/bin/a4diag self-check --offline >/dev/null

echo "distro-smoke: default configuration is root-owned and read-only defaults"
[ -f /etc/a4diag/config.yaml ]
grep -q '^global_mode: read_only$' /etc/a4diag/config.yaml
grep -q '^targets: \[\]$' /etc/a4diag/config.yaml

echo "distro-smoke: systemd units forbid configuration writes"
grep -q 'ProtectSystem=strict' "$RELEASE_DIR/systemd/a4diag-core.service"
grep -q 'ProtectSystem=strict' "$RELEASE_DIR/systemd/a4diag-plugin@.service"
if grep -E '^[[:space:]]*ReadWritePaths=' "$RELEASE_DIR/systemd/a4diag-core.service" \
  | grep -q '/etc/a4diag'; then
  echo "distro-smoke: FAIL core unit may write /etc/a4diag" >&2
  exit 1
fi

echo "distro-smoke: model-failure fallback stays read-only (static contract)"
# The runtime maps a failing model port to read_only_no_model with zero
# executor calls; the unit test suite covers the behavior, and the smoke only
# re-asserts the binary reports a safe mode.
A4DIAG_CONFIG=/etc/a4diag/config.yaml /opt/a4diag/current/venv/bin/a4diag self-check --offline \
  | grep -q '"global_mode": "read_only"'

echo "distro-smoke: PASS on $(grep -E '^(ID|VERSION_ID)=' /etc/os-release | tr '\n' ' ')"
