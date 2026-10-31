#!/bin/sh
# REFFIX Log Viewer installer for OpenWrt 25.12 / APK (Flint4 / MediaTek Filogic).
set -eu

REPO=REFFIX-X/luci-app-log
VERSION_FALLBACK=v3.3.0
FAMILY=25.12
EXT=apk
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

verify_checksums() {
  app_name="reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}"
  lib_name="reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}"
  [ -s "$TMP/SHA256SUMS.txt" ] || return 1
  grep -Fq "  $app_name" "$TMP/SHA256SUMS.txt" || return 1
  grep -Fq "  $lib_name" "$TMP/SHA256SUMS.txt" || return 1
  (cd "$TMP" && sha256sum -c SHA256SUMS.txt)
}

pkgver_of() {
  tar -xOf "$1" .PKGINFO 2>/dev/null | sed -n 's/^pkgver = //p' | head -n 1
}

installed_pkgver() {
  name="$1"
  apk list -I "$name" 2>/dev/null | sed -n "s/^${name}-\\([^ ]*\\) .*/\\1/p" | head -n 1
}

pkg_action() {
  name="$1"
  file="$2"
  PKG_NEW="$(pkgver_of "$file")"
  [ -n "$PKG_NEW" ] || { echo "ERROR: $file has no package version." >&2; return 1; }
  PKG_OLD="$(installed_pkgver "$name")"
  if [ -z "$PKG_OLD" ]; then
    PKG_ACT=install
    return 0
  fi
  rel="$(apk version -t "$PKG_OLD" "$PKG_NEW" 2>/dev/null || printf '?')"
  case "$rel" in
    '<') PKG_ACT=upgrade ;;
    '=') PKG_ACT=same ;;
    '>') PKG_ACT=keep ;;
    *) PKG_ACT=replace ;;
  esac
}

install_downloaded_packages() {
  lib="$1"
  app="$2"
  pkg_action libmaxminddb "$lib" || return 1
  lib_act="$PKG_ACT"
  lib_old="$PKG_OLD"
  lib_new="$PKG_NEW"
  pkg_action luci-app-log-viewer "$app" || return 1
  app_act="$PKG_ACT"
  app_old="$PKG_OLD"
  app_new="$PKG_NEW"
  if [ "$app_act" = same ]; then app_act=replace; fi
  if [ "$lib_act" = same ]; then
    if [ "$app_act" = replace ]; then lib_act=replace; else lib_act=keep; fi
  fi
  # A failed version comparison must not delete the library out from under a newer app.
  if [ "$app_act" = keep ] && [ "$lib_act" = replace ]; then lib_act=keep; fi
  case "$lib_act" in
    install) echo "Installing libmaxminddb $lib_new." ;;
    upgrade) echo "Upgrading libmaxminddb from $lib_old to $lib_new." ;;
    replace) echo "Replacing installed libmaxminddb $lib_old." ;;
    keep)
      if [ -n "$lib_old" ] && [ "$lib_old" != "$lib_new" ]; then
        echo "Installed libmaxminddb $lib_old is newer than $lib_new; leaving it."
      fi
      ;;
  esac
  case "$app_act" in
    install) echo "Installing luci-app-log-viewer $app_new." ;;
    upgrade) echo "Upgrading luci-app-log-viewer from $app_old to $app_new." ;;
    replace) echo "Replacing installed luci-app-log-viewer $app_old." ;;
    keep) echo "Installed luci-app-log-viewer $app_old is newer than $app_new; leaving it." ;;
  esac
  if [ "$lib_act" = keep ] && [ "$app_act" = keep ]; then
    return 0
  fi
  if [ "$lib_act" = replace ] && [ "$app_act" != keep ] && [ "$app_act" != install ]; then
    apk del luci-app-log-viewer
  elif [ "$app_act" = replace ]; then
    apk del luci-app-log-viewer
  fi
  if [ "$lib_act" = replace ]; then
    apk del libmaxminddb
  fi
  if [ "$lib_act" != keep ] && [ "$app_act" != keep ]; then
    apk add --allow-untrusted --upgrade "$lib" "$app"
  elif [ "$lib_act" != keep ]; then
    apk add --allow-untrusted --upgrade "$lib"
  elif [ "$app_act" != keep ]; then
    apk add --allow-untrusted --upgrade "$app"
  fi
}

command -v apk >/dev/null 2>&1 || {
  echo "ERROR: REFFIX Firewall Log requires APK on OpenWrt 25.12 or a supported MediaTek Filogic snapshot. IPK/opkg releases are no longer built." >&2
  exit 1
}
if [ -r /etc/openwrt_release ]; then . /etc/openwrt_release; fi
case "${DISTRIB_RELEASE:-}:${DISTRIB_TARGET:-}" in
  25.12*:*) ;;
  SNAPSHOT:mediatek/filogic*) ;;
  *)
    echo "ERROR: this installer is for OpenWrt 25.12 or SNAPSHOT:mediatek/filogic with APK. Detected release=${DISTRIB_RELEASE:-unknown}, target=${DISTRIB_TARGET:-unknown}." >&2
    exit 1
    ;;
esac
ARCH="$(sed -n '1{s/[[:space:]]*$//;p;}' /etc/apk/arch 2>/dev/null || apk --print-arch 2>/dev/null || true)"
case "$ARCH" in
  aarch64_cortex-a53*) ;;
  aarch64)
    case "${DISTRIB_TARGET:-}" in
      mediatek/filogic*) ;;
      *) echo "ERROR: generic aarch64 is only supported here for mediatek/filogic." >&2; exit 1 ;;
    esac
    ;;
  *) echo "ERROR: unsupported APK architecture: ${ARCH:-unknown}. Expected aarch64_cortex-a53." >&2; exit 1 ;;
esac

echo "REFFIX installer: OpenWrt 25.12 APK, architecture $ARCH."
VERSION_FILE="$TMP/latest"
VERSION=""
if fetch "https://raw.githubusercontent.com/${REPO}/package-assets/latest" "$VERSION_FILE"; then
  CANDIDATE="$(sed -n '1p' "$VERSION_FILE" 2>/dev/null || true)"
  case "$CANDIDATE" in v[0-9]*) VERSION="$CANDIDATE" ;; esac
fi

if [ -n "$VERSION" ]; then
  BASE="https://raw.githubusercontent.com/${REPO}/package-assets/${VERSION}"
  echo "Using package mirror release $VERSION."
  if ! fetch "$BASE/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" "$TMP/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" ||
     ! fetch "$BASE/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" "$TMP/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" ||
     ! fetch "$BASE/SHA256SUMS-openwrt-${FAMILY}.txt" "$TMP/SHA256SUMS.txt" ||
     ! verify_checksums; then
    echo "WARNING: package mirror download failed; trying GitHub release assets." >&2
    VERSION=""
  fi
fi

if [ -z "$VERSION" ]; then
  VERSION="$VERSION_FALLBACK"
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
  echo "Using GitHub release asset fallback: $VERSION."
  fetch "$BASE/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" "$TMP/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" || {
    echo "ERROR: couldn't download the matching GeoIP helper APK from GitHub Releases." >&2
    echo "Check connectivity to github.com and confirm release $VERSION contains the 25.12 assets." >&2
    exit 1
  }
  fetch "$BASE/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" "$TMP/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}" || {
    echo "ERROR: couldn't download the REFFIX Log Viewer APK from GitHub Releases." >&2
    echo "Check connectivity to github.com and confirm release $VERSION contains the 25.12 assets." >&2
    exit 1
  }
  fetch "$BASE/SHA256SUMS-openwrt-${FAMILY}.txt" "$TMP/SHA256SUMS.txt" || {
    echo "ERROR: couldn't download the package checksum file from GitHub Releases." >&2
    exit 1
  }
  verify_checksums || {
    echo "ERROR: APK checksum verification failed; refusing to install either package." >&2
    exit 1
  }
fi

echo "Installing checksum-verified GeoIP helper and REFFIX Log Viewer..."
install_downloaded_packages \
  "$TMP/reffix-libmaxminddb-openwrt-${FAMILY}.${EXT}" \
  "$TMP/reffix-luci-app-log-viewer-openwrt-${FAMILY}.${EXT}"

if [ -x /usr/bin/flint4-geoip-update ]; then
  echo "Downloading local GeoLite2 country and ASN databases..."
  if /usr/bin/flint4-geoip-update; then
    echo "GeoIP databases are ready."
  else
    echo "WARNING: GeoIP download failed; the app is installed, but local country/ASN enrichment is unavailable until updated." >&2
  fi
fi

/etc/init.d/rpcd restart
echo "Done. Open Status -> Firewall Log in LuCI."
echo "Running this installer again upgrades an older luci-app-log-viewer, or replaces the same release. Your saved /etc/config/infra-port-watch stays."
