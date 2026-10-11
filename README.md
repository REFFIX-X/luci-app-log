# REFFIX Log Viewer

REFFIX-maintained LuCI log viewer for OpenWrt, including System Log, Kernel Log, and a firewall-event dashboard with local GeoIP enrichment.

## Highlights

- Firewall events classified only from explicit log evidence: blocked, observed, or explicitly allowed.
- Search and filters for addresses, ports, protocol, country and ASN.
- Local GeoLite2 country/ASN lookup; no per-IP web lookup API.
- CSV export, copyable IP addresses, recent-event summaries and scan/burst heuristics.
- Monokai Pro-inspired dark palette coordinated with the REFFIX Footstrap theme family.
- Existing package identity `luci-app-log-viewer` is retained so upgrades replace the installed app in place.

## Install on a supported Flint4 / OpenWrt 25.12

Connect over SSH as root:

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/REFFIX-X/luci-app-log/master/install-online.sh | sh
```

The installer detects APK/IPK support and downloads the matching package and GeoIP helper. It first uses the package mirror; if GitHub's raw-content host is unavailable, it falls back to the assets attached to the pinned v2.0.0 release.

Supported release assets:
- OpenWrt 25.12, APK, `aarch64_cortex-a53`
- OpenWrt 24.10, IPK, `aarch64_cortex-a53`

Manual packages and checksums are published on [GitHub Releases](https://github.com/REFFIX-X/luci-app-log/releases).

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
