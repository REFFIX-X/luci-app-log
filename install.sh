#!/bin/sh
# Installs this source overlay to an existing LuCI/OpenWrt router.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP="/root/reffix-log-viewer-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"

backup() {
  src="$1"
  if [ -e "$src" ]; then
    dest="$BACKUP$src"
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest"
  fi
}

backup /www/luci-static/resources/view/log-viewer/firewall.js
backup /usr/bin/flint4-geoip
backup /usr/bin/flint4-geoip-update
backup /usr/share/luci/menu.d/luci-app-log-viewer.json
backup /usr/share/rpcd/acl.d/luci-app-log-viewer.json

mkdir -p /www/luci-static/resources/view/log-viewer /usr/bin
mkdir -p /usr/share/luci/menu.d /usr/share/rpcd/acl.d
cp "$ROOT/htdocs/luci-static/resources/view/log-viewer/firewall.js" /www/luci-static/resources/view/log-viewer/firewall.js
cp "$ROOT/root/usr/bin/flint4-geoip" /usr/bin/flint4-geoip
cp "$ROOT/root/usr/bin/flint4-geoip-update" /usr/bin/flint4-geoip-update
cp "$ROOT/root/usr/share/luci/menu.d/luci-app-log-viewer.json" /usr/share/luci/menu.d/luci-app-log-viewer.json
cp "$ROOT/root/usr/share/rpcd/acl.d/luci-app-log-viewer.json" /usr/share/rpcd/acl.d/luci-app-log-viewer.json
chmod 755 /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update

echo "Installed REFFIX Firewall Log overlay."
echo "Existing files backed up under: $BACKUP"
echo "Next: install libmaxminddb, run /usr/bin/flint4-geoip-update, restart rpcd, then hard-refresh LuCI."
