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
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEApZY89+gtJv7U+wIaA4Tl
gLpxAZ7+hxzFhclqplwGNhNlyQo+mydDp+Nvvfv6mXYP9b4xbr8dPT2zY9pKPZRX
Zt/Jglcxd6ixQdEwY3V+sp4vyXG7435Jf7w9+8LqcUXtaID1dh6IIOmGJ3gxGg+W
KguPJy+24ZKZmWPFsEcbo151zEfIX4DvK+/yYtySoy2QXeVr34mVC0SFxoim6Px6
r4GsIi86VG+mfoa9+lH10/co9oNb+peUjjPaYem4uMLURcM5ZPjDy0b9XmsnJ96v
B8rrCp7OkwfVaHa7SLut0mcxQ1O8EZ+vzXJ41qFrsAjm7KjTS+ESoBTlGibNH+9o
Xtgy5dlPvHsGqktzilhZItm94I3+j8rEEeUog3VYih+qhip3w3LuBlmcvi0pcBAu
buv3aGZvOLhHD5dfLkqYsawsO5yE83Q/E4mGr0331g7SlaKULircEVLHfdUxuY5l
uUj1lzmUD/S4fn35X7bmb6zuowLgeerjd3+4wSMO26dBAgMBAAE=
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
