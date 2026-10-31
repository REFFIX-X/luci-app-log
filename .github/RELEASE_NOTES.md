# REFFIX Firewall Log v3.3.1

OpenWrt 25.12 release. The package name remains `luci-app-log-viewer`. IPv4 only.

## This release

Running the installer again upgrades an older `luci-app-log-viewer`. The same release is removed and installed again, so the files match the download. A newer installed app is left alone. `/etc/config/infra-port-watch` stays either way.

The package depends on `iptables-mod-hashlimit`, so each source address keeps its own log budget. If the match cannot be loaded, the watch falls back to one shared limit and the status line says so.

**Settings → Edit WAN watch → Add missing default ports** appends shipped defaults that are missing from the saved list, including TR-069 (7547), MikroTik (8291), MQTT TLS (8883), kubelet (10250), and WireGuard (51820). Saved ports stay. Choose **Save settings** to apply them. The list still stops at 256 ports.

**Settings → Files → Update GeoIP databases** downloads fresh Country and ASN databases on the router.

## WAN watch

Each source address has its own log budget:

- Known ports: 30 per minute after a burst of 15.
- A known port that is also an enabled firewall forward: 4 per minute after a burst of 4.
- Any other port: 2 per minute after a burst of 5.

Listed ports jump to their log chain with goto. Both chains only log, then return the packet.

**Blocked** is a known-port probe with no allow and no forward. **Other** is the low-rate sample of a port that is not on the list. **Details** on an Other row can add that port to the known list.

GeoLite2 databases are not in the APK. See the README before sharing them.
