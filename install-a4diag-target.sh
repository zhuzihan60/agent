#!/usr/bin/env bash
# Public bootstrap for the signed, target-only A4Diag runtime. Needs only bash,
# curl, openssl and tar: the release bundles its own Python 3.11 when the host
# has none. Everything runs inside main so a truncated download never executes.
set -euo pipefail

ARCHIVE_URL="${A4DIAG_TARGET_RELEASE_URL:-https://github.com/zhuzihan60/agent/releases/latest/download/a4diag-target.tar.gz}"
SIGNATURE_URL="${A4DIAG_TARGET_RELEASE_SIGNATURE_URL:-https://github.com/zhuzihan60/agent/releases/latest/download/a4diag-target.tar.gz.sig}"
CONFIG="${A4DIAG_TARGET_INSTALL_CONFIG:-target-install.json}"
die() { echo "a4diag target bootstrap: $*" >&2; exit 1; }
fetch() { case "$1" in file://*) cp -a -- "${1#file://}" "$2" ;; https://*) curl -fsSL --proto '=https' --tlsv1.2 --max-time 600 -o "$2" "$1" ;; *) die "unsupported URL scheme" ;; esac; }

# Only regular files and directories, no absolute or parent-relative paths.
check_archive() {
  local archive="$1" names types name
  names="$(tar -tzf "$archive")" || die "unsafe target release archive"
  types="$(tar -tvzf "$archive" | cut -c1 | sort -u | tr -d '\n')" || die "unsafe target release archive"
  case "$types" in *[!-d]*) die "unsafe target release archive" ;; esac
  while IFS= read -r name; do
    case "/$name/" in //*|*/../*) die "unsafe target release archive" ;; esac
  done <<< "$names"
}

main() {
  [ -f "$CONFIG" ] || die "target-install.json is required"
  for command in openssl mktemp tar; do command -v "$command" >/dev/null || die "required command missing: $command"; done
  temporary="$(mktemp -d)"
  trap 'rm -rf "$temporary"' EXIT
  public_key="$temporary/release-public.pem"
  cat >"$public_key" <<'KEY'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmtUGXCaz3E+6PLvyHGSf
3UV9j84kECWrlKHxlaeszir/rLupKFVwTiUNDyFpdxRIkGA1RgznCA/uKzpLoe/U
dtO+HGHjb7yyMTwSk38V14T0qP+tajzr9tHIhJTPG/FILK9GumkfHPQKSEps/neR
0OQGmvv2O72j/JjOih96gtoPlqqXMWopZVOfS67NyPFjbDQTSVgcfxGQx9mti0X4
iFOxZT5WvgnyHZHVDLXJpodGSePXqYy9VzQlxWz9BuBstClXqrzUubYFCNKo13Ef
pan76SHlsrOuwcikVR1GVYwPWKbXid0lahfA/Q/GbjlISA903CMa9JUpRYAF9cgA
gDKLrmOzb/7iL6mKQKZESC0TZUVIfK4vMfu8+Szgme1bkhSSOMtejI2DEennB9Fq
JWDeBk+FYCTvhFpSzGv3X9hY87RgjNrPtBNcw3Jaji36aP7C/zAyM2RRSsU95BhO
8bbutB20LiPdW+O3afKq9sQwEdEovcOJc2DejNkXadtnAgMBAAE=
-----END PUBLIC KEY-----
KEY
  fetch "$ARCHIVE_URL" "$temporary/a4diag-target.tar.gz"
  fetch "$SIGNATURE_URL" "$temporary/a4diag-target.tar.gz.sig"
  openssl dgst -sha256 -verify "$public_key" -signature "$temporary/a4diag-target.tar.gz.sig" "$temporary/a4diag-target.tar.gz" >/dev/null 2>&1 || die "archive signature mismatch"
  check_archive "$temporary/a4diag-target.tar.gz"
  tar -xzf "$temporary/a4diag-target.tar.gz" -C "$temporary" --no-same-owner
  release="$temporary/release"
  [ -f "$release/tools/install_target_lib.sh" ] || die "target installer missing"
  A4DIAG_TARGET_TRUSTED_KEY="$public_key" bash "$release/tools/install_target_lib.sh" install "$release" "$CONFIG"
}

main "$@"
