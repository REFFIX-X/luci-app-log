#!/bin/sh
# Removes the overlay files. Existing menu/ACL backups are left for manual restore.
set -eu
/etc/init.d/infra-port-watch disable 2>/dev/null || true
/etc/init.d/infra-port-watch stop 2>/dev/null || true
rm -f /usr/sbin/infra-port-watch /etc/infra-port-watch.sh /etc/init.d/infra-port-watch
rm -f /usr/sbin/infra-port-watch-config
rm -f /www/luci-static/resources/view/log-viewer/firewall.js
rm -f /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
echo "Removed Firewall Log view, GeoIP helpers, and the WAN logging rule."
echo "Restore the menu/ACL JSON from /root/reffix-log-viewer-backup-* if you want the exact pre-install state."
