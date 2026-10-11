#!/bin/sh
# REFFIX Log Viewer installer for Flint4-class aarch64_cortex-a53 targets.
set -eu

REPO=REFFIX-X/luci-app-log
VERSION_FALLBACK=v2.0.0
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
  if [ -r /etc/apk/arch ]; then
    ARCH="$(sed -n '1{s/[[:space:]]*$//;p;}' /etc/apk/arch)"
  else
    ARCH="$(apk --print-arch 2>/dev/null || true)"
  fi
  if [ -r /etc/openwrt_release ]; then . /etc/openwrt_release; fi
  case "$ARCH" in
    aarch64_cortex-a53*) FAMILY=25.12; EXT=apk ;;
    aarch64)
      case "${DISTRIB_RELEASE:-}:${DISTRIB_TARGET:-}" in
        25.12*:mediatek/filogic*|SNAPSHOT:mediatek/filogic*) FAMILY=25.12; EXT=apk ;;
        *)
          echo "ERROR: generic aarch64 is only mapped for OpenWrt 25.12/SNAPSHOT mediatek/filogic. Detected release=${DISTRIB_RELEASE:-unknown}, target=${DISTRIB_TARGET:-unknown}." >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "ERROR: unsupported APK architecture: ${ARCH:-unknown}. Supported target is aarch64_cortex-a53." >&2
      exit 1
      ;;
  esac
  PM=apk
elif command -v opkg >/dev/null 2>&1; then
  ARCH="$(opkg print-architecture 2>/dev/null | awk '$2 >= 10 {print $1}' | tail -n 1)"
  case "$ARCH" in
    *aarch64_cortex-a53*) FAMILY=24.10; EXT=ipk ;;
    *) echo "ERROR: unsupported opkg architecture: ${ARCH:-unknown}. Supported target is aarch64_cortex-a53." >&2; exit 1 ;;
  esac
  PM=opkg
else
  echo "ERROR: neither apk nor opkg was found." >&2
  exit 1
fi

echo "REFFIX installer: package manager=$PM, target family=$FAMILY, architecture=$ARCH."
VERSION_FILE="$TMP/latest"
VERSION=""
if fetch "https://raw.githubusercontent.com/${REPO}/package-assets/latest" "$VERSION_FILE"; then
  CANDIDATE="$(sed -n '1p' "$VERSION_FILE" 2>/dev/null || true)"
  case "$CANDIDATE" in v[0-9]*) VERSION="$CANDIDATE" ;; esac
fi

if [ -n "$VERSION" ]; then
  BASE="https://raw.githubusercontent.com/${REPO}/package-assets/${VERSION}"
  echo "Using package mirror release $VERSION."
  if ! fetch "$BASE/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" "$TMP/lib.${EXT}" ||
     ! fetch "$BASE/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" "$TMP/app.${EXT}"; then
    echo "WARNING: package mirror download failed; trying GitHub release assets." >&2
    VERSION=""
  fi
fi

if [ -z "$VERSION" ]; then
  VERSION="$VERSION_FALLBACK"
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
  echo "Using GitHub release asset fallback: $VERSION."
  fetch "$BASE/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" "$TMP/lib.${EXT}" || {
    echo "ERROR: couldn't download the matching GeoIP helper package from GitHub Releases." >&2
    echo "Check connectivity to github.com and confirm release $VERSION contains this platform's assets." >&2
    exit 1
  }
  fetch "$BASE/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" "$TMP/app.${EXT}" || {
    echo "ERROR: couldn't download the REFFIX Log Viewer package from GitHub Releases." >&2
    echo "Check connectivity to github.com and confirm release $VERSION contains this platform's assets." >&2
    exit 1
  }
fi

echo "Installing matching GeoIP helper library..."
if [ "$PM" = apk ]; then
  apk add --allow-untrusted "$TMP/lib.${EXT}"
  echo "Installing/upgrading REFFIX Log Viewer..."
  apk add --allow-untrusted "$TMP/app.${EXT}"
else
  opkg install "$TMP/lib.${EXT}"
  echo "Installing/upgrading REFFIX Log Viewer..."
  opkg install "$TMP/app.${EXT}"
fi

if [ -x /usr/bin/flint4-geoip-update ]; then
  echo "Downloading local GeoLite2 country and ASN databases..."
  if /usr/bin/flint4-geoip-update; then
    echo "GeoIP databases are ready."
  else
    echo "WARNING: GeoIP download failed; the app is installed, but local country/ASN enrichment is unavailable until updated." >&2
  fi
fi

/etc/init.d/rpcd restart
echo "Done. Open Status -> Log Viewer -> Firewall Log in LuCI."
echo "The existing luci-app-log-viewer package was upgraded in place; do not uninstall it first."
