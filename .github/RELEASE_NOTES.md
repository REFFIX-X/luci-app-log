# REFFIX Firewall Log v3.2.1

OpenWrt 25.12 release. The package name remains `luci-app-log-viewer`. IPv4 only.

## Page

The log type is one step smaller. The table and fields are 13px, buttons are 13px, and the summary numbers are 22px. Column titles stay pinned while the log scrolls inside the table.

**Details** on an Other event can add that destination port to the known list. The button is **Log this port at the full budget**. It keeps the current WAN device and enabled state, restarts the watch, and later hits on that port use the full per-address budget. A port already on the list is left alone. The list still stops at 256 ports.

## WAN watch

Each source address has its own log budget:

- Known ports: 30 per minute after a burst of 15.
- A known port that is also an enabled firewall forward: 4 per minute after a burst of 4.
- Any other port: 2 per minute after a burst of 5.

Listed ports jump to their log chain with goto, so they are not sampled again. Both chains only log, then return the packet. The watch does not accept or drop. If the hashlimit match is unavailable, those rates fall back to one shared limit and the status line says so.

**Blocked** is a known-port probe with no allow and no forward. The subtitle is **Default deny**. **Other** is the low-rate sample of a port that is not on the list. The subtitle is **Not on the watch list**.

`/etc/config/infra-port-watch` is a conffile, so an upgrade keeps the port list you already saved. Package install and `install.sh` start the watch again.

GeoLite2 databases are downloaded separately and are not in the APK. See the README for install steps and licensing.

The release build attaches the OpenWrt 25.12 APK app, the matching `libmaxminddb` helper, and their SHA-256 checksums when that build finishes.
