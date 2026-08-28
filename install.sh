#!/usr/bin/env bash
#
# A4Diag atomic online/offline installer.
#
#   sudo ./install.sh --offline /path/to/release-dir
#   sudo ./install.sh --online            # fetches $A4DIAG_RELEASE_URL
#
# Fail-closed: requires root and a supported distribution, verifies the
# release SHA256 and RSA signature before extraction, stages
# into /opt/a4diag/releases/<version>, creates an isolated venv with locked
# wheels, runs the offline self-check, and only then atomically switches the
# /opt/a4diag/current symlink. A service-start failure rolls back to the
# previous version. /etc/a4diag/config.yaml is created only when absent and
# never overwritten.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tools/install_lib.sh
. "$SCRIPT_DIR/tools/install_lib.sh"

usage() {
  echo "usage: install.sh --offline RELEASE_DIR | --online" >&2
  exit 2
}

[ $# -ge 1 ] || usage

MODE="$1"
shift || true

case "$MODE" in
  --offline)
    [ $# -eq 1 ] || usage
    RELEASE_DIR="$1"
    [ -d "$RELEASE_DIR" ] || die "release directory missing: $RELEASE_DIR"
    ;;
  --online)
    RELEASE_DIR=""
    ;;
  *)
    usage
    ;;
esac

a4diag_require_root
a4diag_check_distro
a4diag_require_commands
a4diag_check_disk

if [ -z "$RELEASE_DIR" ]; then
  url="${A4DIAG_RELEASE_URL:-https://releases.a4diag.example/v${A4DIAG_EXPECTED_VERSION}/a4diag-${A4DIAG_EXPECTED_VERSION}.tar.gz}"
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' EXIT
  log "fetching release from $url"
  if [[ "$url" == file://* ]]; then
    cp -a "${url#file://}" "$temp_dir/release.tar.gz"
  else
    curl -fsSL --max-time 600 -o "$temp_dir/release.tar.gz" "$url"
  fi
  tar -xzf "$temp_dir/release.tar.gz" -C "$temp_dir"
  RELEASE_DIR="$temp_dir/release"
  [ -d "$RELEASE_DIR" ] || die "downloaded archive did not contain a release/ directory"
fi

a4diag_install_release_tree "$RELEASE_DIR"
log "done: a4diag ${A4DIAG_EXPECTED_VERSION}"
