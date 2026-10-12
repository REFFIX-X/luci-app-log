# REFFIX Firewall Log

REFFIX Firewall Log for OpenWrt LuCI, with local GeoIP enrichment.

## Highlights

- Line-by-line firewall events classified as Blocked, Exposed, or explicitly Allowed, with evidence and policy notes shown for each event.
- Search and filters for addresses, ports, protocol, country and ASN.
- Local GeoLite2 country/ASN lookup; no per-IP web lookup API.
- Browser-local filter presets, event details, filtered/all-loaded CSV export, portable settings, optional bounded local history, interactive activity timeline and scan/burst heuristics.
- Monokai Pro-inspired dark palette coordinated with [REFFIX Monokai Pro for LuCI](https://github.com/REFFIX-X/luci-theme-footstrap).
- Existing package identity `luci-app-log-viewer` is retained so upgrades replace the installed app in place.

## Install on a supported Flint4 / OpenWrt 25.12

Connect over SSH as root:

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/REFFIX-X/luci-app-log/main/install-online.sh | sh
```

The installer supports OpenWrt 25.12/APK and `SNAPSHOT:mediatek/filogic` on Flint4-class MediaTek Filogic routers. It checks the downloaded app and GeoIP helper against the release SHA-256 file before installing. It first uses the package mirror; if the mirror assets or checksums are unavailable or invalid, it falls back to the versioned GitHub release assets and verifies those too. A checksum mismatch on the release stops installation.

Supported release assets:
- OpenWrt 25.12, APK, `aarch64_cortex-a53` only

The installer also accepts the Flint 4-compatible `SNAPSHOT:mediatek/filogic` build when APK is present and its architecture is `aarch64` or `aarch64_cortex-a53`.

Manual APK packages and SHA-256 checksums are published on [GitHub Releases](https://github.com/REFFIX-X/luci-app-log/releases). The Firewall Log reads at most 1,500 recent system log lines at a time and displays events individually, 100 rows at a time; use **Show more events** to page through that loaded window. The Activity timeline filters the event table by a selected interval. Optional history is stored only in the current browser and is capped at 10,000 events; it is disabled by default. Filter presets, exposed-service labels and the option to show external AbuseIPDB links are stored in your browser. Settings can be exported/imported as JSON; router watch settings are reviewed before they are applied. You can review configured firewall forwards and import selected destination-port labels without LAN hostname lookup. GeoIP enrichment is local and limited to the 60 most recent unique public sources. The watch-rule ports and WAN device are stored on the router. Opening an AbuseIPDB link sends that source IP to AbuseIPDB. The matching [REFFIX Monokai Pro for LuCI theme](https://github.com/REFFIX-X/luci-theme-footstrap) has its own OpenWrt 25.12/APK release and installation guide.

## Firewall log semantics

- **Blocked** includes explicit DROP/REJECT markers and, by default, `INFRA_PORT_HIT` watchlist entries. On a default-deny WAN, unsolicited hits to ports without an explicit allow rule or port forward are blocked. A configured exposed-port label changes matching watchlist hits to **Exposed**.
- **Exposed** means the destination port matches a configured exposed-service label or imported firewall forward. It does not prove the connection was accepted.
- **Allowed** requires an explicit allow/accept log marker. Silent allow traffic is not inferred from absence of a drop.
- Scan/burst signals are heuristic indicators, not proof of malicious activity.
- Use **WAN / exposed ports** to enter the actual interface names shown in `IN=` log fields and ports forwarded to services. Labels apply only in this browser. A hit matching an exposed label is marked **Exposed**; the watchlist line does not prove that the forward accepted the connection. No LAN hostname lookup is performed.
- The `INFRA_PORT_HIT` port set is determined by the firewall logging rule on the router. This app displays the destination ports present in those log entries; the port insight ranks the ports in the currently selected time window.
- The package installs an IPv4-only log-only raw-table watch rule for common TCP SYN and UDP destination ports on the logical WAN device. It never accepts or drops traffic, and its shared rate limit is 10 log entries per minute after an initial burst of 20. Edit the WAN device and up to 256 ports in **WAN / exposed ports**. The defaults are in `/etc/config/infra-port-watch`; the UI applies changes immediately and preserves them across upgrades.
- v3.1.1 fixed WAN watcher startup during package post-upgrade on OpenWrt 25.12. If upgrading from v3.1.0 left the watcher inactive, update the package and run `/etc/init.d/infra-port-watch restart` once.
- The app does not change firewall accept/drop policy. The watchlist is not exhaustive: add uncommon ports such as 25125 in the UI if you want to log them.

## GeoIP and privacy

GeoIP databases are downloaded separately by the helper and are not bundled in source control. Review the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) obligations before redistributing database files. GeoIP country and ASN matches are approximate.

## Upstream and license

This project is a REFFIX-maintained fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log). The original application is MIT-licensed; see [LICENSE](LICENSE). Preserve upstream attribution and license notices when redistributing the derived application.
