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
#   A4DIAG_TRUSTED_KEY   path to the RSA public key used to verify MANIFEST.sig
#   A4DIAG_ALLOW_UNSIGNED set to 1 to accept a release without MANIFEST.sig
#   A4DIAG_PIP_LOG       path where the pip argv is recorded (tests only)
#   A4DIAG_SERVICE_START_ATTEMPTS  bounded readiness checks (tests only)
#   A4DIAG_SERVICE_START_INTERVAL  seconds between checks (tests only)

set -euo pipefail

# Test overrides may pin a different expected version; production is 0.4.1.
A4DIAG_EXPECTED_VERSION="${A4DIAG_EXPECTED_VERSION:-0.4.1}"

A4DIAG_ROOT="${A4DIAG_ROOT:-/}"
RELEASE_BASE="${A4DIAG_ROOT}opt/a4diag/releases"
CURRENT_LINK="${A4DIAG_ROOT}opt/a4diag/current"
ETC_DIR="${A4DIAG_ROOT}etc/a4diag"
SYSTEMD_DIR="${A4DIAG_ROOT}etc/systemd/system"
PLUGIN_ROOT="${A4DIAG_ROOT}opt/a4diag/plugins"
CLI_LINK="${A4DIAG_ROOT}usr/local/bin/a4diag"
RUN_ROOT="${A4DIAG_ROOT}run/a4diag"
STATE_ROOT="${A4DIAG_ROOT}var/lib/a4diag"

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
    alinux:3|alinux:3.*) ;;
    rocky:8|rocky:8.*|rocky:9|rocky:9.*|almalinux:8|almalinux:8.*|almalinux:9|almalinux:9.*|rhel:8|rhel:8.*|rhel:9|rhel:9.*) ;;
    ubuntu:22.04|ubuntu:24.04|debian:12) ;;
    *)
      die "unsupported distribution $id:$version (supported: Alibaba Cloud Linux 3, rocky/almalinux/rhel 8-9, ubuntu 22.04/24.04, debian 12)"
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
    [ -f "$A4DIAG_TRUSTED_KEY" ] || die "trusted release public key is missing: $A4DIAG_TRUSTED_KEY"
    command -v openssl >/dev/null 2>&1 || die "required command missing: openssl"
    openssl dgst -sha256 -verify "$A4DIAG_TRUSTED_KEY" \
      -signature "$release_dir/MANIFEST.sig" \
      "$release_dir/MANIFEST.json" >/dev/null 2>&1 \
      || die "release manifest signature mismatch"
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
  chown -hR root:root "$target"
  chmod 0755 "$target"

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
    -r "$target/requirements.lock"
  "$pip" -m pip install \
    --no-index \
    --no-deps \
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
  install -m 0644 "${RELEASE_BASE}/${version}/systemd/sysusers.d/a4diag.conf" "${A4DIAG_ROOT}etc/sysusers.d/a4diag.conf"
  systemd-sysusers a4diag.conf || die "systemd-sysusers failed"
  install -m 0644 "${RELEASE_BASE}/${version}/systemd/tmpfiles.d/a4diag.conf" "${A4DIAG_ROOT}etc/tmpfiles.d/a4diag.conf"
  systemd-tmpfiles --create a4diag.conf || die "systemd-tmpfiles failed"
  chown root:a4diag "$ETC_DIR/config.yaml"
  chmod 0640 "$ETC_DIR/config.yaml"
  log "created a4diag user/group and runtime directories"
}

a4diag_initialize_runtime() {
  local registry="$ETC_DIR/plugin-registry.json"
  local secrets_dir="$ETC_DIR/secrets"
  local runtime_dir
  local secret

  [ ! -L "$ETC_DIR" ] || die "configuration directory must not be a symlink"
  [ ! -L "$PLUGIN_ROOT" ] || die "plugin directory must not be a symlink"
  [ ! -L "$secrets_dir" ] || die "secret directory must not be a symlink"

  for runtime_dir in \
    "$RUN_ROOT" \
    "$STATE_ROOT" \
    "$STATE_ROOT/checkpoints" \
    "$STATE_ROOT/transactions" \
    "$STATE_ROOT/approvals" \
    "$STATE_ROOT/reports" \
    "$STATE_ROOT/audit" \
    "$STATE_ROOT/plugins"; do
    [ ! -L "$runtime_dir" ] || die "runtime directory must not be a symlink: $runtime_dir"
    install -d -m 0750 "$runtime_dir"
  done

  install -d -m 0750 "$PLUGIN_ROOT"
  install -d -m 0700 "$secrets_dir"

  if [ ! -f "$registry" ]; then
    local registry_tmp="$ETC_DIR/.plugin-registry.json.tmp.$$"
    (umask 077 && printf '%s\n' '{"plugins":[]}' > "$registry_tmp")
    chmod 0640 "$registry_tmp"
    mv -T "$registry_tmp" "$registry"
    log "created empty plugin registry at $registry"
  fi

  for secret in core-ticket.key core-policy.key; do
    if [ ! -f "$secrets_dir/$secret" ]; then
      python3.11 - "$secrets_dir/$secret" <<'PY'
import os
import secrets
import sys

path = sys.argv[1]
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as handle:
    handle.write(secrets.token_hex(32) + "\n")
PY
      log "created internal authorization key: $secret"
    fi
    chmod 0600 "$secrets_dir/$secret"
  done

  chmod 0640 "$registry"
  chmod 0750 "$PLUGIN_ROOT"
  chmod 0700 "$secrets_dir"
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" != "1" ]; then
    chown root:a4diag "$registry" "$PLUGIN_ROOT"
    chown a4diag:a4diag \
      "$RUN_ROOT" \
      "$STATE_ROOT" \
      "$STATE_ROOT/checkpoints" \
      "$STATE_ROOT/transactions" \
      "$STATE_ROOT/approvals" \
      "$STATE_ROOT/reports" \
      "$STATE_ROOT/audit" \
      "$STATE_ROOT/plugins"
    chown a4diag:a4diag "$secrets_dir" \
      "$secrets_dir/core-ticket.key" \
      "$secrets_dir/core-policy.key"
  fi
}

a4diag_install_builtin_catalog() {
  local version="$1"
  local release="${RELEASE_BASE}/${version}"
  local index="${release}/builtin-plugins/builtin-index.json"
  local registry="$ETC_DIR/plugin-registry.json"

  [ -f "$index" ] || die "release is missing the built-in plugin index"
  "$release/venv/bin/python" -m a4diag.builtin_catalog \
    install "$index" "$PLUGIN_ROOT" "$registry" \
    || die "built-in plugin catalog installation failed"

  chmod 0750 \
    "$PLUGIN_ROOT/releases/$version" \
    "$PLUGIN_ROOT/releases/$version/manifests" \
    "$PLUGIN_ROOT/releases/$version/artifacts"
  chmod 0640 \
    "$PLUGIN_ROOT/releases/$version/builtin-index.json" \
    "$PLUGIN_ROOT/releases/$version/manifests/"*.json \
    "$PLUGIN_ROOT/releases/$version/artifacts/"*.whl \
    "$PLUGIN_ROOT/"*.json
  chmod 0640 "$registry"
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" != "1" ]; then
    chown -R root:a4diag "$PLUGIN_ROOT/releases/$version"
    chown root:a4diag "$PLUGIN_ROOT"/*.json "$registry"
  fi
  log "installed ${version} built-in plugin catalog"
}

a4diag_install_units() {
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" = "1" ]; then
    log "skipping systemd unit installation (A4DIAG_SKIP_SYSTEMD=1)"
    return 0
  fi
  local version="$1"
  local unit
  mkdir -p "$SYSTEMD_DIR"
  for unit in \
    a4diag-cleanup.service \
    a4diag-cleanup.timer \
    a4diag-core.service \
    a4diag-plugin@.service \
    a4diag-plugin@.socket; do
    install -m 0644 \
      "${RELEASE_BASE}/${version}/systemd/${unit}" \
      "$SYSTEMD_DIR/${unit}"
  done
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

a4diag_install_cli_link() {
  local expected="/opt/a4diag/current/venv/bin/a4diag"
  local cli_dir
  cli_dir="$(dirname "$CLI_LINK")"
  mkdir -p "$cli_dir"
  if [ -e "$CLI_LINK" ] || [ -L "$CLI_LINK" ]; then
    [ -L "$CLI_LINK" ] || die "refusing to replace non-symlink CLI path: $CLI_LINK"
    [ "$(readlink "$CLI_LINK")" = "$expected" ] || {
      die "refusing to replace unexpected CLI symlink: $CLI_LINK"
    }
  fi
  local temporary_link="${CLI_LINK}.tmp.$$"
  ln -s "$expected" "$temporary_link"
  mv -T "$temporary_link" "$CLI_LINK"
  log "installed CLI entrypoint at $CLI_LINK"
}

a4diag_restart_services() {
  if [ "${A4DIAG_SKIP_SYSTEMD:-0}" = "1" ]; then
    log "skipping service start (A4DIAG_SKIP_SYSTEMD=1)"
    return 0
  fi
  systemctl daemon-reload || return 1
  systemctl enable --now a4diag-core.service || return 1
  local attempts="${A4DIAG_SERVICE_START_ATTEMPTS:-60}"
  local interval="${A4DIAG_SERVICE_START_INTERVAL:-1}"
  case "$attempts:$interval" in
    *[!0-9:]*|0:*) die "invalid service readiness bounds" ;;
  esac
  local state="" attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    state="$(systemctl is-active a4diag-core.service 2>/dev/null || true)"
    if [ "$state" = "active" ]; then
      log "started a4diag-core.service"
      return 0
    fi
    sleep "$interval"
    attempt=$((attempt + 1))
  done
  echo "a4diag installer: a4diag-core.service failed to reach active state (last state: ${state:-unknown})" >&2
  return 1
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
  a4diag_initialize_runtime
  a4diag_install_builtin_catalog "$version"
  a4diag_install_units "$version"
  a4diag_install_cli_link
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
