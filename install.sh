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
backup /usr/sbin/infra-port-watch
backup /usr/sbin/infra-port-watch-config
backup /etc/infra-port-watch.sh
backup /etc/init.d/infra-port-watch
backup /usr/share/luci/menu.d/luci-app-log-viewer.json
backup /usr/share/rpcd/acl.d/luci-app-log-viewer.json

mkdir -p /www/luci-static/resources/view/log-viewer /usr/bin /usr/sbin
mkdir -p /etc/config /etc/init.d
mkdir -p /usr/share/luci/menu.d /usr/share/rpcd/acl.d
cp "$ROOT/htdocs/luci-static/resources/view/log-viewer/firewall.js" /www/luci-static/resources/view/log-viewer/firewall.js
cp "$ROOT/root/usr/bin/flint4-geoip" /usr/bin/flint4-geoip
cp "$ROOT/root/usr/bin/flint4-geoip-update" /usr/bin/flint4-geoip-update
cp "$ROOT/root/usr/sbin/infra-port-watch" /usr/sbin/infra-port-watch
cp "$ROOT/root/usr/sbin/infra-port-watch-config" /usr/sbin/infra-port-watch-config
cp "$ROOT/root/etc/infra-port-watch.sh" /etc/infra-port-watch.sh
cp "$ROOT/root/etc/init.d/infra-port-watch" /etc/init.d/infra-port-watch
[ -f /etc/config/infra-port-watch ] || cp "$ROOT/root/etc/config/infra-port-watch" /etc/config/infra-port-watch
cp "$ROOT/root/usr/share/luci/menu.d/luci-app-log-viewer.json" /usr/share/luci/menu.d/luci-app-log-viewer.json
cp "$ROOT/root/usr/share/rpcd/acl.d/luci-app-log-viewer.json" /usr/share/rpcd/acl.d/luci-app-log-viewer.json
chmod 755 /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
chmod 755 /usr/sbin/infra-port-watch /usr/sbin/infra-port-watch-config /etc/infra-port-watch.sh /etc/init.d/infra-port-watch
/etc/init.d/infra-port-watch enable
if ! /etc/init.d/infra-port-watch start; then
  echo "WARNING: WAN watch logging was not started. Configure the WAN interface and run /etc/init.d/infra-port-watch restart." >&2
fi

echo "Installed REFFIX Firewall Log overlay and enabled the log-only WAN port watch."
echo "Existing files backed up under: $BACKUP"
echo "Next: install libmaxminddb, run /usr/bin/flint4-geoip-update, restart rpcd, then hard-refresh LuCI."
