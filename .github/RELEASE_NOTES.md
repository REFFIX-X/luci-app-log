# REFFIX Firewall Log v3.3.0

OpenWrt 25.12 release. The package name remains `luci-app-log-viewer`. IPv4 only.

## This release

The package depends on `iptables-mod-hashlimit`. That package also installs the kernel match, so each source address keeps its own log budget. If the match still cannot be loaded, the watch falls back to one shared limit and the status line says so.

**Settings → Edit WAN watch → Add missing default ports** appends shipped defaults that are missing from the saved list, including TR-069 (7547), MikroTik (8291), MQTT TLS (8883), kubelet (10250), and WireGuard (51820). Ports you already saved stay. Choose **Save settings** to apply them. The list still stops at 256 ports.

**Settings → Files → Update GeoIP databases** downloads fresh Country and ASN databases on the router and refreshes the age shown on the page. The databases stay local.

## WAN watch

Each source address has its own log budget:

- Known ports: 30 per minute after a burst of 15.
- A known port that is also an enabled firewall forward: 4 per minute after a burst of 4.
- Any other port: 2 per minute after a burst of 5.

Listed ports jump to their log chain with goto, so they are not sampled again. Both chains only log, then return the packet. The watch does not accept or drop.

**Blocked** is a known-port probe with no allow and no forward. The subtitle is **Default deny**. **Other** is the low-rate sample of a port that is not on the list. The subtitle is **Not on the watch list**. **Details** on an Other row can add that port to the known list.

`/etc/config/infra-port-watch` is a conffile, so an upgrade keeps the port list you already saved.

GeoLite2 databases are not in the APK. See the README for licensing.

The release build attaches the OpenWrt 25.12 APK app, the matching `libmaxminddb` helper, and their SHA-256 checksums when that build finishes.
