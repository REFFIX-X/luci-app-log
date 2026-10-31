#!/bin/sh
# Removes the source overlay. Package installs should use: apk del luci-app-log-viewer
set -eu
/etc/init.d/infra-port-watch disable 2>/dev/null || true
/etc/init.d/infra-port-watch stop 2>/dev/null || true
/etc/init.d/log-viewer-history disable 2>/dev/null || true
/etc/init.d/log-viewer-history stop 2>/dev/null || true
rm -f /usr/sbin/infra-port-watch /usr/sbin/infra-port-watch-config /usr/sbin/log-viewer-history
rm -f /etc/infra-port-watch.sh /etc/init.d/infra-port-watch /etc/init.d/log-viewer-history
rm -rf /tmp/log-viewer
rm -f /etc/hotplug.d/iface/99-infra-port-watch
rm -f /www/luci-static/resources/view/log-viewer/firewall.js
rm -rf /www/luci-static/resources/log-viewer/flags
rm -f /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
rm -f /usr/share/log-viewer/policies.example.json
rm -f /usr/share/luci/menu.d/luci-app-log-viewer.json
rm -f /usr/share/rpcd/acl.d/luci-app-log-viewer.json
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
if [ -x /etc/init.d/rpcd ]; then
  /etc/init.d/rpcd restart >/dev/null 2>&1 || true
fi
echo "Removed the Firewall Log overlay, country flags, and the WAN logging rule."
echo "Router watch settings remain in /etc/config/infra-port-watch."
echo "GeoIP database files in /usr/share/GeoIP were left in place."
echo "Backups from install.sh, if any, are under /root/reffix-log-viewer-backup-*."
