#!/usr/bin/env bash
# Fail-closed installer for the public-only A4Diag target runtime.
set -euo pipefail

TARGET_ROOT="${A4DIAG_TARGET_ROOT:-/}"
TARGET_BASE="${TARGET_ROOT}opt/a4diag-target"
TARGET_CURRENT="$TARGET_BASE/current"
TARGET_ETC="${TARGET_ROOT}etc/a4diag-target"
TARGET_STATE="${TARGET_ROOT}var/lib/a4diag-target"
TARGET_LIBEXEC="${TARGET_ROOT}usr/libexec/a4diag"
TARGET_SYSTEMD="${TARGET_ROOT}etc/systemd/system"

die() { echo "a4diag target installer: $*" >&2; exit 1; }
log() { echo "a4diag target installer: $*"; }

require_root() {
  [ "${A4DIAG_TARGET_SKIP_ROOT:-0}" = "1" ] || [ "$(id -u)" -eq 0 ] || die "must run as root"
}

check_distro() {
  local file="${A4DIAG_TARGET_OS_RELEASE:-/etc/os-release}" id version
  [ -f "$file" ] || die "cannot read $file"
  id="$(grep -E '^ID=' "$file" | head -n1 | cut -d= -f2- | tr -d '\"')"
  version="$(grep -E '^VERSION_ID=' "$file" | head -n1 | cut -d= -f2- | tr -d '\"')"
  case "$id:$version" in
    alinux:3|alinux:3.*|rocky:8|rocky:8.*|rocky:9|rocky:9.*|almalinux:8|almalinux:8.*|almalinux:9|almalinux:9.*|rhel:8|rhel:8.*|rhel:9|rhel:9.*|ubuntu:22.04|ubuntu:24.04|debian:12) ;;
    *) die "unsupported distribution $id:$version" ;;
  esac
}

validate_config() {
  local config="$1"
  [ -f "$config" ] || die "target-install.json is missing"
  [ ! -L "$config" ] || die "target-install.json must not be a symlink"
  python3.11 - "$config" <<'PY' || exit 65
import ipaddress, json, pathlib, re, sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate key")
        result[key] = value
    return result

def fail(message):
    print(f"a4diag target installer: {message}", file=sys.stderr)
    raise SystemExit(65)

try:
    raw = pathlib.Path(sys.argv[1]).read_bytes()
    if len(raw) > 262144: fail("target-install.json is too large")
    value = json.loads(raw, object_pairs_hook=unique)
    allowed = {"protocol_version", "target_id", "ssh_public_key", "operation_public_key",
               "controller_key_fingerprint", "allowed_source_cidrs", "managed_resources",
               "confirm_managed_resources"}
    if type(value) is not dict or set(value) - allowed: fail("unknown configuration field")
    required = allowed - {"confirm_managed_resources"}
    if not required <= set(value): fail("missing configuration field")
    if value["protocol_version"] != "1.0": fail("protocol_version must be 1.0")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value["target_id"]): fail("invalid target_id")
    key = value["ssh_public_key"]
    if type(key) is not str or "\n" in key or not re.fullmatch(r"ssh-(?:ed25519|rsa) [A-Za-z0-9+/=]+(?: [^\x00-\x1f]+)?", key):
        fail("invalid ssh_public_key")
    public = value["operation_public_key"]
    if type(public) is not str or "PRIVATE KEY" in public: fail("private key input is forbidden")
    if "-----BEGIN PUBLIC KEY-----" not in public or "-----END PUBLIC KEY-----" not in public:
        fail("operation_public_key must be public PEM")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value["controller_key_fingerprint"]):
        fail("invalid controller_key_fingerprint")
    cidrs = value["allowed_source_cidrs"]
    if type(cidrs) is not list or not cidrs: fail("source_cidr list must be nonempty")
    for cidr in cidrs:
        if type(cidr) is not str or "/" not in cidr: fail("invalid source_cidr")
        try: network = ipaddress.ip_network(cidr, strict=True)
        except (TypeError, ValueError): fail("invalid source_cidr")
        if network.prefixlen == 0: fail("source_cidr cannot allow the world")
    resources = value["managed_resources"]
    if type(resources) is not list: fail("managed_resources must be a list")
    for item in resources:
        if type(item) is not dict or set(item) != {"capability", "resource"}:
            fail("invalid managed resource")
        if item["capability"] not in {"files", "services", "packages"} or type(item["resource"]) is not str:
            fail("invalid managed resource")
    if resources and value.get("confirm_managed_resources") != "ENABLE":
        fail("nonempty managed_resources requires literal ENABLE")
except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
    fail(str(exc))
PY
}

verify_release() {
  local release="$1"
  [ -f "$release/VERSION" ] || die "release is missing VERSION"
  (cd "$release" && sha256sum -c SHA256SUMS >/dev/null) || die "release SHA256 verification failed"
  python3.11 - "$release" <<'PY' || die "release inventory is inconsistent"
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
if any(path.is_symlink() for path in root.rglob("*")):
    raise ValueError("release symlink is forbidden")
declared = {}
for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1)
    path = pathlib.PurePosixPath(name)
    if name in declared or path.is_absolute() or ".." in path.parts: raise ValueError("unsafe manifest")
    declared[name] = digest
actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name not in {"SHA256SUMS", "MANIFEST.sig"}}
if set(declared) != actual: raise ValueError("inventory mismatch")
manifest = json.loads((root / "MANIFEST.json").read_bytes())
if set(manifest.get("artifacts", {})) != set(declared) - {"MANIFEST.json"}: raise ValueError("manifest mismatch")
if any(declared.get(k) != v for k, v in manifest["artifacts"].items()): raise ValueError("digest mismatch")
PY
  if [ -f "$release/MANIFEST.sig" ]; then
    [ -f "${A4DIAG_TARGET_TRUSTED_KEY:-}" ] || die "signed release requires A4DIAG_TARGET_TRUSTED_KEY"
    openssl dgst -sha256 -verify "$A4DIAG_TARGET_TRUSTED_KEY" -signature "$release/MANIFEST.sig" "$release/MANIFEST.json" >/dev/null 2>&1 || die "release manifest signature mismatch"
  elif [ "${A4DIAG_TARGET_ALLOW_UNSIGNED:-0}" != "1" ]; then
    die "release is unsigned"
  fi
}

write_configuration() {
  local config="$1" runtime_python="$2" machine_id fingerprint
  machine_id="${A4DIAG_TARGET_MACHINE_ID:-$(cat /etc/machine-id)}"
  [ -n "$machine_id" ] || die "target identity unavailable"
  fingerprint="$($runtime_python - "$TARGET_ROOT" "$machine_id" <<'PY'
import os, pathlib, sys
from a4diag_target.server import target_fingerprint
release = os.environ.get("A4DIAG_TARGET_OS_RELEASE")
print(target_fingerprint(pathlib.Path(sys.argv[1] or "/"), machine_id_override=sys.argv[2], os_release_path=pathlib.Path(release) if release else None))
PY
)"
  [ -n "$fingerprint" ] || die "target fingerprint unavailable"
  install -d -m 0755 "$TARGET_ETC"
  python3.11 - "$config" "$TARGET_ETC/policy.json.tmp" "$fingerprint" <<'PY'
import json, pathlib, sys
source = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
resources = source["managed_resources"]
roots, units, packages = [], [], []
for item in resources:
    if type(item) is not dict or set(item) != {"capability", "resource"}: raise ValueError("invalid managed resource")
    capability, resource = item["capability"], item["resource"]
    if capability == "files": roots.append(resource)
    elif capability == "services": units.append(resource)
    elif capability == "packages": packages.append(resource)
    else: raise ValueError("invalid managed resource capability")
policy = {"target_id": source["target_id"], "target_fingerprint": sys.argv[3],
          "controller_key_fingerprint": source["controller_key_fingerprint"],
          "managed_roots": roots, "allowed_units": units, "allowed_packages": packages}
pathlib.Path(sys.argv[2]).write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  install -m 0600 "$TARGET_ETC/policy.json.tmp" "$TARGET_ETC/policy.json"
  rm -f "$TARGET_ETC/policy.json.tmp"
  python3.11 - "$config" "$TARGET_ETC/operation-public.pem" "$TARGET_STATE/.ssh/authorized_keys" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pathlib.Path(sys.argv[2]).write_text(value["operation_public_key"], encoding="ascii")
cidrs = ",".join(value["allowed_source_cidrs"])
line = f'restrict,command="/usr/libexec/a4diag/a4diag-transport-helper",from="{cidrs}" {value["ssh_public_key"]}\n'
pathlib.Path(sys.argv[3]).write_text(line, encoding="ascii")
PY
  chmod 0644 "$TARGET_ETC/operation-public.pem"
  chmod 0600 "$TARGET_STATE/.ssh/authorized_keys"
}

install_target() {
  local release="$1" config="$2" version destination
  require_root
  for protected in "$TARGET_BASE" "$TARGET_ETC" "$TARGET_STATE" "$TARGET_LIBEXEC"; do
    [ ! -L "$protected" ] || die "protected install path must not be a symlink: $protected"
  done
  check_distro
  validate_config "$config"
  verify_release "$release"
  version="$(cat "$release/VERSION")"
  destination="$TARGET_BASE/releases/$version"
  install -d -m 0755 "$TARGET_BASE/releases" "$TARGET_LIBEXEC" "$TARGET_SYSTEMD"
  install -d -m 0750 "$TARGET_STATE"
  install -d -m 0700 "$TARGET_STATE/executor" "$TARGET_STATE/.ssh"
  if [ ! -d "$destination" ]; then
    cp -a "$release" "$destination.tmp.$$"
    python3.11 -m venv "$destination.tmp.$$/venv"
    "$destination.tmp.$$/venv/bin/python" -m pip install --no-index --find-links "$destination.tmp.$$/wheelhouse" "a4diag-target-runtime==$version"
    mv "$destination.tmp.$$" "$destination"
  fi
  if [ "${A4DIAG_TARGET_INJECT_FAILURE:-}" = "before_switch" ]; then die "injected failure before switch"; fi
  ln -sfn "$destination" "$TARGET_CURRENT.tmp.$$"
  mv -Tf "$TARGET_CURRENT.tmp.$$" "$TARGET_CURRENT"
  install -m 0755 "$destination/venv/bin/a4diag-transport-helper" "$TARGET_LIBEXEC/a4diag-transport-helper"
  write_configuration "$config" "$destination/venv/bin/python"
  install -m 0644 "$destination/systemd/a4diag-target-executor.service" "$TARGET_SYSTEMD/a4diag-target-executor.service"
  install -m 0644 "$destination/systemd/a4diag-target-executor.socket" "$TARGET_SYSTEMD/a4diag-target-executor.socket"
  if [ "${A4DIAG_TARGET_SKIP_SYSTEMD:-0}" != "1" ]; then
    install -d -m 0755 "${TARGET_ROOT}etc/sysusers.d" "${TARGET_ROOT}etc/tmpfiles.d"
    install -m 0644 "$destination/systemd/sysusers.d/a4diag-target.conf" "${TARGET_ROOT}etc/sysusers.d/a4diag-target.conf"
    install -m 0644 "$destination/systemd/tmpfiles.d/a4diag-target.conf" "${TARGET_ROOT}etc/tmpfiles.d/a4diag-target.conf"
    systemd-sysusers a4diag-target.conf
    systemd-tmpfiles --create a4diag-target.conf
    chown -R root:root "$TARGET_STATE/executor" "$TARGET_ETC"
    chown -R a4diag-target:a4diag-target "$TARGET_STATE/.ssh"
    systemctl daemon-reload
    systemctl enable --now a4diag-target-executor.socket
  fi
  log "installed restricted target runtime $version"
}

uninstall_target() {
  require_root
  if [ -f "$TARGET_STATE/executor/replay.sqlite3" ]; then
    python3.11 - "$TARGET_STATE/executor/replay.sqlite3" <<'PY' || die "incomplete target transactions prevent uninstall"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
count = db.execute("SELECT count(*) FROM replay WHERE completed_at IS NULL").fetchone()[0]
raise SystemExit(1 if count else 0)
PY
  fi
  [ "${A4DIAG_TARGET_CONFIRM_UNINSTALL:-}" = "REMOVE" ] || die "set A4DIAG_TARGET_CONFIRM_UNINSTALL=REMOVE"
  systemctl disable --now a4diag-target-executor.socket 2>/dev/null || true
  log "runtime disabled; state retained for audit"
}

case "${1:-}" in
  validate) [ "$#" -eq 2 ] || die "usage: validate target-install.json"; validate_config "$2" ;;
  install) [ "$#" -eq 3 ] || die "usage: install RELEASE target-install.json"; install_target "$2" "$3" ;;
  uninstall) [ "$#" -eq 1 ] || die "usage: uninstall"; uninstall_target ;;
  *) die "usage: $0 validate CONFIG | install RELEASE CONFIG | uninstall" ;;
esac
