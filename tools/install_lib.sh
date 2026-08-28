#!/usr/bin/env bash
#
# A4Diag installer library (POSIX bash subset).
#
# Generic and fail-closed: every path derives from A4DIAG_ROOT, every
# environment override is explicit, and no fixed target id, IP address, or SSH
# username appears anywhere in this file.
#
# Overrides (tests inject these; production uses defaults):
#   A4DIAG_ROOT          install prefix (default /)
#   A4DIAG_OS_RELEASE    path to os-release (default /etc/os-release)
#   A4DIAG_SKIP_ROOT     set to 1 to skip the root check (tests only)
#   A4DIAG_SKIP_SYSTEMD  set to 1 to skip systemd unit install/start (tests only)
#   A4DIAG_SKIP_DISK     set to 1 to skip the disk-space check (tests only)
#   A4DIAG_INJECT_FAILURE  "before_switch" fails the install before the atomic
#                          current-link switch (tests only)
#   A4DIAG_TRUSTED_KEY   path to the HMAC key used to verify MANIFEST.sig
#   A4DIAG_ALLOW_UNSIGNED set to 1 to accept a release without MANIFEST.sig
#   A4DIAG_PIP_LOG       path where the pip argv is recorded (tests only)

set -euo pipefail

# Test overrides may pin a different expected version; production is 0.4.0.
A4DIAG_EXPECTED_VERSION="${A4DIAG_EXPECTED_VERSION:-0.4.0}"

A4DIAG_ROOT="${A4DIAG_ROOT:-/}"
RELEASE_BASE="${A4DIAG_ROOT}opt/a4diag/releases"
CURRENT_LINK="${A4DIAG_ROOT}opt/a4diag/current"
ETC_DIR="${A4DIAG_ROOT}etc/a4diag"
SYSTEMD_DIR="${A4DIAG_ROOT}etc/systemd/system"

die() {
  echo "a4diag installer: $*" >&2
  exit 1
}

log() {
  echo "a4diag installer: $*"
}

a4diag_require_root() {
  if [ "${A4DIAG_SKIP_ROOT:-0}" != "1" ]; then
    if [ "$(id -u)" -ne 0 ]; then
      die "must run as root (or set A4DIAG_SKIP_ROOT=1 for tests)"
    fi
  fi
}

a4diag_check_distro() {
  local os_release="${A4DIAG_OS_RELEASE:-/etc/os-release}"
  [ -f "$os_release" ] || die "cannot read $os_release"
  local id version
  id="$(grep -E '^ID=' "$os_release" | head -n1 | cut -d= -f2- | tr -d '"')"
  version="$(grep -E '^VERSION_ID=' "$os_release" | head -n1 | cut -d= -f2- | tr -d '"')"
  case "$id:$version" in
    rocky:8|rocky:9|almalinux:8|almalinux:9|rhel:8|rhel:9) ;;
    ubuntu:22.04|ubuntu:24.04|debian:12) ;;
    *)
      die "unsupported distribution $id:$version (supported: rocky/almalinux/rhel 8-9, ubuntu 22.04/24.04, debian 12)"
      ;;
  esac
  log "supported distribution: $id $version"
}

a4diag_require_commands() {
  for command in python3.11 sha256sum grep cut head; do
    command -v "$command" >/dev/null 2>&1 || die "required command missing: $command"
  done
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" != "1" ]; then
    for command in systemctl systemd-sysusers systemd-tmpfiles; do
      command -v "$command" >/dev/null 2>&1 || die "required command missing: $command"
    done
  fi
  command -v openssl >/dev/null 2>&1 || die "required command missing: openssl"
}

a4diag_check_disk() {
  if [ "${A4DIAG_SKIP_DISK:-0}" = "1" ]; then
    return 0
  fi
  local available_kb
  available_kb="$(df -k "${A4DIAG_ROOT}opt" 2>/dev/null | awk 'NR==2 {print $4}')"
  if [ -z "${available_kb:-}" ] || [ "${available_kb:-0}" -lt 524288 ]; then
    die "insufficient disk space beneath ${A4DIAG_ROOT}opt (need at least 512 MiB)"
  fi
}

a4diag_verify_release() {
  local release_dir="$1"
  [ -d "$release_dir" ] || die "release directory missing: $release_dir"
  [ -f "$release_dir/VERSION" ] || die "release is missing VERSION"
  local version
  version="$(cat "$release_dir/VERSION")"
  [ "$version" = "$A4DIAG_EXPECTED_VERSION" ] || {
    die "release version $version does not match expected $A4DIAG_EXPECTED_VERSION"
  }
  (cd "$release_dir" && sha256sum -c SHA256SUMS >/dev/null) || {
    die "release SHA256 verification failed"
  }

  python3.11 - "$release_dir" <<'PY' || die "release manifests are inconsistent"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate manifest key")
        value[key] = item
    return value

manifest = json.loads(
    (root / "MANIFEST.json").read_text(encoding="utf-8"),
    object_pairs_hook=unique,
)
declared = {}
for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1)
    if name in declared:
        raise ValueError("duplicate SHA256SUMS path")
    declared[name] = digest
artifacts = manifest.get("artifacts")
if not isinstance(artifacts, dict):
    raise ValueError("manifest artifacts missing")
if set(artifacts) != set(declared) - {"MANIFEST.json"}:
    raise ValueError("manifest inventory mismatch")
if any(declared.get(name) != digest for name, digest in artifacts.items()):
    raise ValueError("manifest digest mismatch")
PY

  if [ -f "$release_dir/MANIFEST.sig" ]; then
    [ -n "${A4DIAG_TRUSTED_KEY:-}" ] || die "release is signed but no A4DIAG_TRUSTED_KEY was provided"
    python3.11 - "$release_dir/MANIFEST.json" "$release_dir/MANIFEST.sig" "$A4DIAG_TRUSTED_KEY" <<'PY' || die "release manifest signature mismatch"
import hashlib
import hmac
import pathlib
import sys

manifest, signature, key = map(pathlib.Path, sys.argv[1:])
expected = hmac.new(key.read_bytes(), manifest.read_bytes(), hashlib.sha256).hexdigest()
if not hmac.compare_digest(signature.read_text(encoding="utf-8").strip(), expected):
    raise SystemExit(1)
PY
  elif [ "${A4DIAG_ALLOW_UNSIGNED:-0}" != "1" ]; then
    die "release is unsigned; set A4DIAG_ALLOW_UNSIGNED=1 to accept"
  fi
  log "release verified: $version"
}

a4diag_install_release() {
  local release_dir="$1"
  local version
  version="$(cat "$release_dir/VERSION")"
  local target="${RELEASE_BASE}/${version}"
  if [ -e "$target" ]; then
    die "release already installed: $target"
  fi
  mkdir -p "$target"
  cp -a "$release_dir/." "$target/"

  log "creating virtual environment for $version"
  python3.11 -m venv "$target/venv"
  local pip
  pip="$target/venv/bin/python"
  if [ ! -x "$pip" ]; then
    pip="python3.11"
  fi
  "$pip" -m pip install \
    --no-index \
    --find-links "$target/wheelhouse" \
    -r "$target/requirements.lock" \
    "$target/wheelhouse/a4diag-${version}-py3-none-any.whl" \
    "$target/wheelhouse/a4diag_builtin_plugins-${version}-py3-none-any.whl"

  mkdir -p "$ETC_DIR"
  if [ ! -f "$ETC_DIR/config.yaml" ]; then
    install -m 0640 "$target/config/config.example.yaml" "$ETC_DIR/config.yaml"
    log "created default configuration at $ETC_DIR/config.yaml (read-only defaults)"
  fi

  A4DIAG_CONFIG="$ETC_DIR/config.yaml" "$target/venv/bin/a4diag" self-check --offline >/dev/null || {
    die "installed release failed self-check"
  }
  log "release installed: $version"
}

a4diag_install_identities() {
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" = "1" ]; then
    log "skipping systemd user/group and runtime directory creation (A4DIAG_SKIP_SYSTEMD=1)"
    return 0
  fi
  local version="$1"
  mkdir -p "${A4DIAG_ROOT}etc/sysusers.d" "${A4DIAG_ROOT}etc/tmpfiles.d"
  install -m 0644 "${RELEASE_BASE}/${version}/sysusers.d/a4diag.conf" "${A4DIAG_ROOT}etc/sysusers.d/a4diag.conf"
  systemd-sysusers a4diag.conf || die "systemd-sysusers failed"
  install -m 0644 "${RELEASE_BASE}/${version}/tmpfiles.d/a4diag.conf" "${A4DIAG_ROOT}etc/tmpfiles.d/a4diag.conf"
  systemd-tmpfiles --create a4diag.conf || die "systemd-tmpfiles failed"
  chown root:a4diag "$ETC_DIR/config.yaml"
  chmod 0640 "$ETC_DIR/config.yaml"
  log "created a4diag user/group and runtime directories"
}

a4diag_install_units() {
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" = "1" ]; then
    log "skipping systemd unit installation (A4DIAG_SKIP_SYSTEMD=1)"
    return 0
  fi
  local version="$1"
  mkdir -p "$SYSTEMD_DIR"
  install -m 0644 "${RELEASE_BASE}/${version}/systemd/"* "$SYSTEMD_DIR/"
  log "installed systemd units"
}

a4diag_switch_current() {
  local version="$1"
  local temporary_link="${A4DIAG_ROOT}opt/a4diag/.current.tmp.$$"
  [ "${A4DIAG_INJECT_FAILURE:-}" = "before_switch" ] && die "injected failure before_switch"
  ln -s "releases/${version}" "$temporary_link"
  mv -T "$temporary_link" "$CURRENT_LINK"
  log "switched current -> $version"
}

a4diag_restart_services() {
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" = "1" ]; then
    log "skipping service start (A4DIAG_SKIP_SYSTEMD=1)"
    return 0
  fi
  systemctl daemon-reload || return 1
  systemctl enable --now a4diag-core.service || return 1
  systemctl is-active --quiet a4diag-core.service || return 1
  log "started a4diag-core.service"
}

a4diag_install_release_tree() {
  local release_dir="$1"
  a4diag_verify_release "$release_dir"
  local version previous=""
  version="$(cat "$release_dir/VERSION")"
  if [ -L "$CURRENT_LINK" ]; then
    previous="$(readlink "$CURRENT_LINK" | sed 's#^releases/##')"
  fi

  a4diag_install_release "$release_dir"
  a4diag_install_identities "$version"
  a4diag_install_units "$version"
  a4diag_switch_current "$version"

  if ! a4diag_restart_services "$version"; then
    if [ -n "$previous" ] && [ "$previous" != "$version" ]; then
      log "new services failed; rolling back to $previous"
      ln -s "releases/${previous}" "${A4DIAG_ROOT}opt/a4diag/.current.tmp.$$"
      mv -T "${A4DIAG_ROOT}opt/a4diag/.current.tmp.$$" "$CURRENT_LINK"
      a4diag_restart_services "$previous" || die "rollback services also failed"
      die "rolled back to $previous after service failure"
    fi
    die "a4diag-core.service failed to start"
  fi
  log "a4diag ${version} installed and current"
}
