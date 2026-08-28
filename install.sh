#!/usr/bin/env bash
#
# A4Diag atomic offline installer.
#
#   sudo ./install.sh --offline /path/to/release-dir
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
  echo "usage: install.sh --offline RELEASE_DIR" >&2
  exit 2
}

[ $# -eq 2 ] || usage
[ "$1" = "--offline" ] || usage
RELEASE_DIR="$2"
[ -d "$RELEASE_DIR" ] || die "release directory missing: $RELEASE_DIR"

a4diag_require_root
a4diag_check_distro
a4diag_require_commands
a4diag_check_disk

a4diag_install_release_tree "$RELEASE_DIR"
log "done: a4diag ${A4DIAG_EXPECTED_VERSION}"
