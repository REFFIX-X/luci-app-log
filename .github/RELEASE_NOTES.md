# REFFIX Firewall Log v3.2.0

OpenWrt 25.12 release for the WAN watch and the Firewall Log page. The package name remains `luci-app-log-viewer`. IPv4 only.

## WAN watch

Each source address has its own log budget:

- Known ports: 30 per minute after a burst of 15.
- A known port that is also an enabled firewall forward: 4 per minute after a burst of 4.
- Any other port: 2 per minute after a burst of 5.

Listed ports jump to their log chain with goto, so they are not sampled again. Both chains only log, then return the packet. The watch does not accept or drop. If the hashlimit match is unavailable, those rates fall back to one shared limit and the status line says so.

**Blocked** is a known-port probe with no allow and no forward. The subtitle is **Default deny**: the watch logged the probe, and the firewall's default policy drops it later. **Other** is the low-rate sample of a port that is not on the list. The subtitle is **Not on the watch list**. Logging every dropped packet is still not done.

The default list adds TR-069 (7547), MikroTik (8291), MQTT TLS (8883), kubelet (10250), and WireGuard (51820). `/etc/config/infra-port-watch` is a conffile, so an upgrade keeps the port list you already saved. Those five ports are used for a new install and when the list is empty. The other-port sample does not need a list edit. Package install and `install.sh` start the watch again, which replaces the previous raw-table rules. If the rules look unchanged, run `/etc/init.d/infra-port-watch restart`.

## Page

- GeoIP looks up a batch of addresses in one `flint4-geoip --batch` call. Positive hits stay in this browser for 7 days.
- The 15-second timer reloads log lines. WAN watch status reloads about once a minute.
- The router keeps up to 500 firewall lines in `/tmp/log-viewer/events.ring`, including other-port samples. That memory ring is updated every 15 seconds and cleared on reboot. Browser history is separate.
- Settings is grouped into WAN watch, exposed labels, history, and files. Saved filters stay with the other filters. This page does not offer Save & Apply.

GeoLite2 databases are downloaded separately and are not in the APK. See the README for install steps and licensing.

The release build attaches the OpenWrt 25.12 APK app, the matching `libmaxminddb` helper, and their SHA-256 checksums when that build finishes.
