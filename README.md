# REFFIX Firewall Log

REFFIX-maintained Firewall Log dashboard for OpenWrt with local GeoIP enrichment.

## Highlights

- Repeated probes grouped by source, destination, port, protocol and verdict, with expandable event rows.
- Clickable source, burst and destination-port insights; expand the top-five port list to show every port.
- Router-configurable WAN interface and port watch, plus browser-local exposed-service labels to distinguish unexposed blocked probes from hits matching a configured forward.
- Installs a rate-limited, log-only WAN watch rule for common service ports; the port list and WAN device can be changed in the Firewall Log settings.
- Search and filters for addresses, ports, protocol, country and ASN.
- Local GeoLite2 country/ASN lookup; no per-IP web lookup API.
- Browser-local filter presets, event details, filtered/all-loaded CSV export, copyable IP addresses, recent-event summaries and scan/burst heuristics.
- Monokai Pro-inspired dark palette coordinated with [REFFIX Monokai Pro for LuCI](https://github.com/REFFIX-X/luci-theme-footstrap).
- Existing package identity `luci-app-log-viewer` is retained so upgrades replace the installed app in place.

## Install on a supported Flint4 / OpenWrt 25.12

Connect over SSH as root:

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/REFFIX-X/luci-app-log/master/install-online.sh | sh
```

The installer supports OpenWrt 25.12/APK and `SNAPSHOT:mediatek/filogic` on Flint4-class MediaTek Filogic routers. It checks the downloaded app and GeoIP helper against the release SHA-256 file before installing. It first uses the package mirror; if the mirror assets or checksums are unavailable or invalid, it falls back to the versioned GitHub release assets and verifies those too. A checksum mismatch on the release stops installation.

Supported release assets:
- OpenWrt 25.12, APK, `aarch64_cortex-a53` only

The installer also accepts the Flint 4-compatible `SNAPSHOT:mediatek/filogic` build when APK is present and its architecture is `aarch64` or `aarch64_cortex-a53`.

Manual APK packages and SHA-256 checksums are published on [GitHub Releases](https://github.com/REFFIX-X/luci-app-log/releases). The Firewall Log reads at most 1,500 recent system log lines at a time and initially displays 500 matching groups; use **Load more groups** to page through that loaded window. Expand a group to inspect its individual log lines. GeoIP enrichment is local and limited to the 60 most recent unique public sources. Filter presets, exposed-service labels and the option to show external AbuseIPDB links are stored in your browser. The watch-rule ports and WAN device are stored on the router. Opening an AbuseIPDB link sends that source IP to AbuseIPDB. The matching [REFFIX Monokai Pro for LuCI theme](https://github.com/REFFIX-X/luci-theme-footstrap) has its own OpenWrt 25.12/APK release and installation guide.

## Firewall log semantics

- **Blocked** includes explicit DROP/REJECT markers and, by default, `INFRA_PORT_HIT` watchlist entries. On a default-deny WAN, unsolicited hits to ports without an explicit allow rule or port forward are blocked. A configured exposed-port label changes the display to **Exposed** for matching watchlist hits.
- **Allowed** requires an explicit allow/accept log marker. Silent allow traffic is not inferred from absence of a drop.
- Scan/burst signals are heuristic indicators, not proof of malicious activity.
- Use **WAN / exposed ports** to enter the actual interface names shown in `IN=` log fields and ports forwarded to services. Labels apply only in this browser. A hit matching an exposed label is marked **Exposed**; the watchlist line does not prove that the forward accepted the connection. No LAN hostname lookup is performed.
- The `INFRA_PORT_HIT` port set is determined by the firewall logging rule on the router. This app displays the destination ports present in those log entries; the port insight ranks the ports in the currently selected time window.
- The package installs a log-only raw-table watch rule for common TCP SYN and UDP destination ports on the logical WAN device. It never accepts or drops traffic, and its shared rate limit is 10 log entries per minute after an initial burst of 20. Edit the WAN device and up to 256 ports in **WAN / exposed ports**. The defaults are in `/etc/config/infra-port-watch`; the UI applies changes immediately and preserves them across upgrades.
- The app does not change firewall accept/drop policy. The watchlist is not exhaustive: add uncommon ports such as 25125 in the UI if you want to log them.

## GeoIP and privacy

GeoIP databases are downloaded separately by the helper and are not bundled in source control. Review the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) obligations before redistributing database files. GeoIP country and ASN matches are approximate.

## Upstream and license

This project is a REFFIX-maintained fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log). The original application is MIT-licensed; see [LICENSE](LICENSE). Preserve upstream attribution and license notices when redistributing the derived application.
