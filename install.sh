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
backup /usr/sbin/log-viewer-history
backup /etc/infra-port-watch.sh
backup /etc/init.d/infra-port-watch
backup /etc/init.d/log-viewer-history
backup /usr/share/luci/menu.d/luci-app-log-viewer.json
backup /usr/share/rpcd/acl.d/luci-app-log-viewer.json
backup /etc/hotplug.d/iface/99-infra-port-watch

mkdir -p /www/luci-static/resources/view/log-viewer /usr/bin /usr/sbin
mkdir -p /www/luci-static/resources/log-viewer
mkdir -p /etc/config /etc/init.d /etc/hotplug.d/iface
mkdir -p /usr/share/luci/menu.d /usr/share/rpcd/acl.d /usr/share/log-viewer
cp "$ROOT/htdocs/luci-static/resources/view/log-viewer/firewall.js" /www/luci-static/resources/view/log-viewer/firewall.js
rm -rf /www/luci-static/resources/log-viewer/flags
cp -a "$ROOT/htdocs/luci-static/resources/log-viewer/flags" /www/luci-static/resources/log-viewer/
cp "$ROOT/root/usr/bin/flint4-geoip" /usr/bin/flint4-geoip
cp "$ROOT/root/usr/bin/flint4-geoip-update" /usr/bin/flint4-geoip-update
cp "$ROOT/root/usr/sbin/infra-port-watch" /usr/sbin/infra-port-watch
cp "$ROOT/root/usr/sbin/infra-port-watch-config" /usr/sbin/infra-port-watch-config
cp "$ROOT/root/usr/sbin/log-viewer-history" /usr/sbin/log-viewer-history
cp "$ROOT/root/etc/infra-port-watch.sh" /etc/infra-port-watch.sh
cp "$ROOT/root/etc/init.d/infra-port-watch" /etc/init.d/infra-port-watch
cp "$ROOT/root/etc/init.d/log-viewer-history" /etc/init.d/log-viewer-history
cp "$ROOT/root/etc/hotplug.d/iface/99-infra-port-watch" /etc/hotplug.d/iface/99-infra-port-watch
[ -f /etc/config/infra-port-watch ] || cp "$ROOT/root/etc/config/infra-port-watch" /etc/config/infra-port-watch
cp "$ROOT/root/usr/share/log-viewer/policies.example.json" /usr/share/log-viewer/policies.example.json
cp "$ROOT/root/usr/share/luci/menu.d/luci-app-log-viewer.json" /usr/share/luci/menu.d/luci-app-log-viewer.json
cp "$ROOT/root/usr/share/rpcd/acl.d/luci-app-log-viewer.json" /usr/share/rpcd/acl.d/luci-app-log-viewer.json
chmod 755 /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
chmod 755 /usr/sbin/infra-port-watch /usr/sbin/infra-port-watch-config /usr/sbin/log-viewer-history /etc/infra-port-watch.sh /etc/init.d/infra-port-watch
chmod 755 /etc/init.d/log-viewer-history /etc/hotplug.d/iface/99-infra-port-watch
/etc/init.d/log-viewer-history enable
/etc/init.d/log-viewer-history start || echo "WARNING: firewall history ring did not start." >&2
/etc/init.d/infra-port-watch enable
if ! /etc/init.d/infra-port-watch start; then
  echo "WARNING: WAN watch logging was not started. Configure the WAN interface and run /etc/init.d/infra-port-watch restart." >&2
fi
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
if [ -x /etc/init.d/rpcd ]; then
  /etc/init.d/rpcd restart >/dev/null 2>&1 || true
fi

echo "Installed REFFIX Firewall Log overlay and enabled the log-only WAN port watch."
echo "Existing files backed up under: $BACKUP"
echo "Next: install libmaxminddb (the package that provides mmdblookup), run /usr/bin/flint4-geoip-update, then hard-refresh LuCI."
echo "Log in again if Status -> Firewall Log is missing; rpcd was restarted so the new ACL applies."
