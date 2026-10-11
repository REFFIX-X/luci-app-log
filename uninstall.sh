#!/bin/sh
# Removes the overlay files. Existing menu/ACL backups are left for manual restore.
set -eu
rm -f /www/luci-static/resources/view/log-viewer/firewall.js
rm -f /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
echo "Removed Firewall Log view and GeoIP helpers."
echo "Restore the menu/ACL JSON from /root/reffix-log-viewer-backup-* if you want the exact pre-install state."
