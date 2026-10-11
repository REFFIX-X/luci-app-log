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
  # Prefer OpenWrt's configured package architecture. apk --print-arch can
  # report the generic CPU architecture ("aarch64") on some vendor builds.
  if [ -r /etc/apk/arch ]; then
    ARCH="$(sed -n '1{s/[[:space:]]*$//;p;}' /etc/apk/arch)"
  else
    ARCH="$(apk --print-arch 2>/dev/null || true)"
  fi
  # If the configured file is absent or generic, confirm release/target before
  # mapping aarch64 to the supported Cortex-A53 package family.
  if [ -r /etc/openwrt_release ]; then
    . /etc/openwrt_release
  fi
  case "$ARCH" in
    aarch64_cortex-a53*) FAMILY=25.12; EXT=apk ;;
    aarch64)
      case "${DISTRIB_RELEASE:-}:${DISTRIB_TARGET:-}" in
        25.12*:mediatek/filogic*|SNAPSHOT:mediatek/filogic*)
          FAMILY=25.12; EXT=apk
          ;;
        *)
          echo "ERROR: apk reports generic architecture aarch64, but this installer only supports OpenWrt 25.12 on mediatek/filogic. Detected release=${DISTRIB_RELEASE:-unknown}, target=${DISTRIB_TARGET:-unknown}." >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "ERROR: unsupported APK architecture: ${ARCH:-unknown}. Supported target: OpenWrt 25.12 mediatek/filogic (aarch64 Cortex-A53)." >&2
      exit 1
      ;;
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
VERSION_FILE="$TMP/latest"
if ! fetch "https://raw.githubusercontent.com/${REPO}/package-assets/latest" "$VERSION_FILE"; then
  echo "ERROR: couldn't read the direct-download package index from GitHub." >&2
  exit 1
fi
VERSION="$(sed -n '1p' "$VERSION_FILE")"
case "$VERSION" in
  v[0-9]*) ;;
  *) echo "ERROR: package mirror returned an invalid release version: ${VERSION:-empty}." >&2; exit 1 ;;
esac
BASE="https://raw.githubusercontent.com/${REPO}/package-assets/${VERSION}"
APP="$TMP/reffix-luci-app-log-viewer.${EXT}"
LIB="$TMP/reffix-libmaxminddb.${EXT}"
echo "Using package release ${VERSION} via direct raw downloads."
if ! fetch "$BASE/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" "$LIB"; then
  echo "ERROR: failed to download the matching libmaxminddb package from the direct package mirror." >&2
  exit 1
fi
if ! fetch "$BASE/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" "$APP"; then
  echo "ERROR: failed to download the REFFIX LuCI package from the direct package mirror." >&2
  exit 1
fi

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
