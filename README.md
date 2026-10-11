# REFFIX Firewall Log

REFFIX Firewall Log for OpenWrt LuCI, with local GeoIP enrichment.

## Highlights

- Firewall events classified only from explicit log evidence: blocked, observed, or explicitly allowed.
- Search and filters for addresses, ports, protocol, country and ASN.
- Local GeoLite2 country/ASN lookup; no per-IP web lookup API.
- Browser-local filter presets, event details, filtered/all-loaded CSV export, copyable IP addresses, recent-event summaries and scan/burst heuristics.
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

Manual APK packages and SHA-256 checksums are published on [GitHub Releases](https://github.com/REFFIX-X/luci-app-log/releases). The Firewall Log reads at most 1,500 recent system log lines at a time and initially displays 500 matches; use **Load more** for additional rows from that loaded window. GeoIP enrichment is local and limited to the 60 most recent unique public sources. Local filter presets and the option to show external AbuseIPDB links are stored in your browser. Opening an AbuseIPDB link sends that source IP to AbuseIPDB. The matching [REFFIX Monokai Pro for LuCI theme](https://github.com/REFFIX-X/luci-theme-footstrap) has its own OpenWrt 25.12/APK release and installation guide.

## Firewall log semantics

- **Blocked** is shown only for explicit DROP/REJECT or block-marker evidence.
- **Observed** means the infrastructure watch rule logged a packet. It does not itself prove that traffic was blocked or allowed.
- **Allowed** requires an explicit allow/accept log marker. Silent allow traffic is not inferred from absence of a drop.
- Scan/burst signals are heuristic indicators, not proof of malicious activity.
- The app reads logs and local GeoIP data. It does not add, remove or modify firewall rules.

## GeoIP and privacy

GeoIP databases are downloaded separately by the helper and are not bundled in source control. Review the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) obligations before redistributing database files. GeoIP country and ASN matches are approximate.

## Upstream and license

This project is a REFFIX-maintained fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log). The original application is MIT-licensed; see [LICENSE](LICENSE). Preserve upstream attribution and license notices when redistributing the derived application.
