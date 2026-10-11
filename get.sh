#!/bin/sh
# CertSmith online installer. Downloads a release, verifies its checksum, and runs the
# installer that is packaged with it.
#
#   bash -c "$(wget -nv -O- https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)"
#
# Installer options are passed through after the script:
#
#   bash -c "$(wget -nv -O- https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)" _ --allow-from 192.0.2.0/24
#
# Ubuntu ships wget but usually not curl, so wget is shown here and is the tool this script
# uses when it is present; curl is used where there is no wget (replace "wget -nv -O-" with
# "curl -fsSL" in the command above). If the command returns at once and prints
# nothing, the script could not be downloaded (a private repository answers 404): run the
# download part on its own to see the error.
#
# Environment:
#   CERTSMITH_VERSION   release to install, for example v0.12.0 (default: the latest release)
#   CERTSMITH_REPO      owner/name of the repository (default: CautiousCapsLock/certsmith)
#
# The checksum comes from the same release as the download, so it detects a corrupted or
# incomplete download. It does not authenticate the publisher; read this script, and the
# installer in the release, before running them as root.
set -eu

REPO="${CERTSMITH_REPO:-CautiousCapsLock/certsmith}"
VERSION="${CERTSMITH_VERSION:-}"
BASE="${CERTSMITH_BASE_URL:-https://github.com}"   # a test hook; leave unset

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# wget first (Ubuntu ships it), curl where there is no wget; a minimal container image may have neither
if   have wget; then DL=wget
elif have curl; then DL=curl
else die "wget or curl is required to download the release. On a minimal system, install one first: apt-get update && apt-get install -y wget"
fi
have tar  || die "tar is required"

# download URL FILE: fails on an HTTP error
download() {
  if [ "$DL" = curl ]; then curl -fsSL -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}
# the address a URL redirects to (GitHub redirects /releases/latest to the release's page)
redirect_target() {
  if [ "$DL" = curl ]; then
    curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"
  else
    wget -q -S --max-redirect=0 -O /dev/null "$1" 2>&1 | tr -d '\r' | awk 'tolower($1) == "location:" { print $2; exit }'
  fi
}
[ "$(uname -s)" = Linux ] || die "CertSmith installs on Linux with systemd; this system is $(uname -s)"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m) (amd64 and arm64 are published)" ;;
esac

# Which release: the one asked for, or the one GitHub redirects /releases/latest to.
if [ -z "$VERSION" ]; then
  url=$(redirect_target "$BASE/$REPO/releases/latest") \
    || die "could not reach $BASE/$REPO/releases/latest"
  [ -n "$url" ] || die "no published release found at $BASE/$REPO/releases/latest, or it could not be reached (is the repository private? GitHub answers 404 for a private repository)"
  VERSION="${url##*/}"
fi
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "no published release found for $REPO (got \"$VERSION\"). Check that the repository is public and has a release." ;;
esac
case "$VERSION" in *[!0-9A-Za-z.+_-]*) die "unexpected characters in version: $VERSION" ;; esac

num="${VERSION#v}"
PKG="certsmith-${num}-linux-${ARCH}"
REL="$BASE/$REPO/releases/download/$VERSION"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM HUP

say "CertSmith $VERSION for linux/$ARCH"
say "Downloading $PKG.tar.gz ..."
download "$REL/$PKG.tar.gz" "$TMP/$PKG.tar.gz" || die "download failed: $REL/$PKG.tar.gz"
download "$REL/SHA256SUMS" "$TMP/SHA256SUMS"   || die "download failed: $REL/SHA256SUMS"

# Verify before anything is unpacked or run.
want=$(awk -v n="$PKG.tar.gz" '{ f = $2; sub(/^\*/, "", f); sub(/^\.\//, "", f); if (f == n) { print $1; exit } }' "$TMP/SHA256SUMS")
[ -n "$want" ] || die "SHA256SUMS has no entry for $PKG.tar.gz; nothing was installed"
if   have sha256sum; then got=$(sha256sum "$TMP/$PKG.tar.gz" | awk '{ print $1 }')
elif have shasum;    then got=$(shasum -a 256 "$TMP/$PKG.tar.gz" | awk '{ print $1 }')
elif have openssl;   then got=$(openssl dgst -sha256 "$TMP/$PKG.tar.gz" | awk '{ print $NF }')
else die "no sha256sum, shasum or openssl to verify the download with"
fi
[ "$got" = "$want" ] || die "checksum mismatch for $PKG.tar.gz (expected $want, got $got); nothing was installed"
say "Checksum verified."

# The archive must unpack only into its own directory.
stray=$(tar tzf "$TMP/$PKG.tar.gz" | grep -v "^$PKG/" | head -1 || true)
if [ -n "$stray" ]; then
  hint=""
  case "$stray" in
    ._*|*/._*) hint=" (names starting with ._ are macOS metadata; an archive made on a Mac needs COPYFILE_DISABLE=1 tar --no-xattrs)" ;;
  esac
  die "the archive contains a path outside $PKG/: $stray$hint; nothing was installed"
fi
tar xzf "$TMP/$PKG.tar.gz" -C "$TMP"
[ -f "$TMP/$PKG/install.sh" ] || die "the archive has no install.sh"

# The installer needs root.
cd "$TMP/$PKG"
if [ "$(id -u)" -eq 0 ]; then
  sh ./install.sh "$@"
elif have sudo; then
  say "Running the installer with sudo ..."
  sudo sh ./install.sh "$@"
else
  die "the installer must run as root, and sudo is not available"
fi
