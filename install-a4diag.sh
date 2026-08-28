#!/usr/bin/env bash
# Public A4Diag bootstrap installer. The embedded public key is the trust root;
# the private signing key exists only in the GitHub Actions release environment.
set -euo pipefail

ARCHIVE_URL="${A4DIAG_RELEASE_URL:-https://github.com/zhuzihan60/agent/releases/latest/download/a4diag.tar.gz}"
SIGNATURE_URL="${A4DIAG_RELEASE_SIGNATURE_URL:-https://github.com/zhuzihan60/agent/releases/latest/download/a4diag.tar.gz.sig}"

die() {
  echo "a4diag bootstrap: $*" >&2
  exit 1
}

fetch() {
  local url="$1" destination="$2"
  case "$url" in
    file://*) cp -a -- "${url#file://}" "$destination" ;;
    https://*) curl -fsSL --proto '=https' --tlsv1.2 --max-time 600 -o "$destination" "$url" ;;
    *) die "unsupported download URL scheme" ;;
  esac
}

for command in tar openssl mktemp; do
  command -v "$command" >/dev/null 2>&1 || die "required command missing: $command"
done
case "$ARCHIVE_URL$SIGNATURE_URL" in
  *https://*) command -v curl >/dev/null 2>&1 || die "required command missing: curl" ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
archive="$temporary/a4diag.tar.gz"
signature="$temporary/a4diag.tar.gz.sig"
public_key="$temporary/a4diag-release-public.pem"

cat >"$public_key" <<'A4DIAG_RELEASE_PUBLIC_KEY'
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
A4DIAG_RELEASE_PUBLIC_KEY
chmod 0600 "$public_key"

echo "a4diag bootstrap: downloading signed release"
fetch "$ARCHIVE_URL" "$archive"
fetch "$SIGNATURE_URL" "$signature"
openssl dgst -sha256 -verify "$public_key" -signature "$signature" "$archive" \
  >/dev/null 2>&1 || die "release archive signature mismatch"

tar -xzf "$archive" -C "$temporary"
release_dir="$temporary/release"
[ -f "$release_dir/install.sh" ] || die "signed archive is missing release/install.sh"

echo "a4diag bootstrap: archive signature verified"
A4DIAG_ALLOW_UNSIGNED=0 \
  A4DIAG_TRUSTED_KEY="$public_key" \
  bash "$release_dir/install.sh" --offline "$release_dir"
