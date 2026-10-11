#!/bin/sh
# One-line installer for the REFFIX OpenWrt LuCI app. Supports Flint4-class aarch64_cortex-a53 only.
set -eu

REPO=REFFIX-X/luci-app-log
TMP="/tmp/reffix-luci-install.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() {
  url="$1"
  dest="$2"
  if command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
  else
    echo "ERROR: install uclient-fetch or wget first." >&2
    return 1
  fi
}

if command -v apk >/dev/null 2>&1; then
  ARCH="$(apk --print-arch 2>/dev/null || true)"
  case "$ARCH" in
    aarch64_cortex-a53*) FAMILY=25.12; EXT=apk ;;
    *) echo "ERROR: unsupported APK architecture: ${ARCH:-unknown}. Current release assets target aarch64_cortex-a53 (GL.iNet Flint4 / mediatek filogic)." >&2; exit 1 ;;
  esac
  PM=apk
elif command -v opkg >/dev/null 2>&1; then
  ARCH="$(opkg print-architecture 2>/dev/null | awk '$2 >= 10 {print $1}' | tail -n 1)"
  case "$ARCH" in
    *aarch64_cortex-a53*) FAMILY=24.10; EXT=ipk ;;
    *) echo "ERROR: unsupported opkg architecture: ${ARCH:-unknown}. Current release assets target aarch64_cortex-a53." >&2; exit 1 ;;
  esac
  PM=opkg
else
  echo "ERROR: neither apk nor opkg was found." >&2
  exit 1
fi

echo "REFFIX LuCI installer: detected ${PM}, target family ${FAMILY}, architecture ${ARCH}."
fetch "https://api.github.com/repos/${REPO}/releases?per_page=30" "$TMP/releases.json"
APP="$TMP/reffix-luci-app-log-viewer.${EXT}"
LIB="$TMP/reffix-libmaxminddb.${EXT}"
VERSION=""
VERSIONS="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"(v[^\"]*)".*/\1/p' "$TMP/releases.json" | awk '{ a[NR]=$0 } END { for (i=NR; i>0; i--) print a[i] }')"
for candidate in $VERSIONS; do
  BASE="https://github.com/${REPO}/releases/download/${candidate}"
  if fetch "$BASE/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" "$LIB" &&
     fetch "$BASE/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" "$APP"; then
    VERSION="$candidate"
    break
  fi
done
if [ -z "$VERSION" ]; then
  echo "ERROR: no GitHub release has packages for OpenWrt ${FAMILY} (${EXT}) and this architecture." >&2
  exit 1
fi
echo "Using package release ${VERSION}."

echo "Installing GeoIP helper library..."
if [ "$PM" = apk ]; then
  apk add --allow-untrusted "$LIB"
  echo "Installing/upgrading REFFIX LuCI app..."
  apk add --allow-untrusted "$APP"
else
  opkg install "$LIB"
  echo "Installing/upgrading REFFIX LuCI app..."
  opkg install "$APP"
fi

if [ -x /usr/bin/flint4-geoip-update ]; then
  echo "Downloading local GeoLite2 country and ASN databases..."
  if /usr/bin/flint4-geoip-update; then
    echo "GeoIP databases are ready."
  else
    echo "WARNING: GeoIP database download failed; the app is installed, but local country/ASN enrichment will be unavailable until updated." >&2
  fi
fi

/etc/init.d/rpcd restart
echo "Done. Open Status -> Log Viewer -> Firewall Log in LuCI."
echo "The existing luci-app-log-viewer package was upgraded in place; do not uninstall it first."
