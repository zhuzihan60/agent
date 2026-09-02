#!/usr/bin/env bash
# Public bootstrap for the signed, target-only A4Diag runtime.
set -euo pipefail

ARCHIVE_URL="${A4DIAG_TARGET_RELEASE_URL:-https://github.com/zhuzihan60/agent/releases/latest/download/a4diag-target.tar.gz}"
SIGNATURE_URL="${A4DIAG_TARGET_RELEASE_SIGNATURE_URL:-https://github.com/zhuzihan60/agent/releases/latest/download/a4diag-target.tar.gz.sig}"
CONFIG="${A4DIAG_TARGET_INSTALL_CONFIG:-target-install.json}"
die() { echo "a4diag target bootstrap: $*" >&2; exit 1; }
fetch() { case "$1" in file://*) cp -a -- "${1#file://}" "$2" ;; https://*) curl -fsSL --proto '=https' --tlsv1.2 --max-time 600 -o "$2" "$1" ;; *) die "unsupported URL scheme" ;; esac; }
[ -f "$CONFIG" ] || die "target-install.json is required"
for command in python3.11 openssl mktemp; do command -v "$command" >/dev/null || die "required command missing: $command"; done
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
python3.11 - "$temporary/a4diag-target.tar.gz" "$temporary" <<'PY' || exit 65
import pathlib, sys, tarfile
archive, destination = sys.argv[1:]
with tarfile.open(archive, "r:gz") as source:
    for item in source.getmembers():
        path = pathlib.PurePosixPath(item.name)
        if path.is_absolute() or ".." in path.parts or item.issym() or item.islnk() or not (item.isfile() or item.isdir()):
            raise SystemExit("unsafe target release archive")
    source.extractall(destination, filter="data")
PY
release="$temporary/release"
[ -f "$release/tools/install_target_lib.sh" ] || die "target installer missing"
A4DIAG_TARGET_TRUSTED_KEY="$public_key" bash "$release/tools/install_target_lib.sh" install "$release" "$CONFIG"
