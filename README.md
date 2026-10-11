# REFFIX luci-app-log

A REFFIX-maintained fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log) for OpenWrt LuCI. Retains the upstream System Log and Kernel Log views and adds a general-purpose **Firewall Log** with local GeoIP enrichment.

## Features

- Original System Log and Kernel Log pages.
- **Firewall Log** parses generic `INFRA_PORT_HIT`, `DROP` / `REJECT`, and explicitly logged block/allow markers (for example, rules tagged `JELLYFIN_BLOCK`). No Jellyfin-specific logic is hardcoded.
- Readable table with timestamp, source IP, locally bundled GeoIP country flag/name and ASN organisation, destination IP, destination port/service, protocol, explicit verdict classification, source port, ingress interface and TCP flags. Source IPs can be copied with one click.
- Filters for event type and TCP/UDP, search across IPs/countries/ASNs/ports/services, CSV export and periodic refresh.
- GeoIP enrichment uses a local MaxMind GeoLite2 database. No per-IP lookup API is called. Country flag SVGs are bundled locally from the MIT-licensed flag-icons project. The browser loads them from this router, so external image hosts and CSP exceptions are not required.
- Does not add or modify firewall rules.

## Installation

### One-line installer (recommended)

On a supported Flint4 / aarch64 Cortex-A53 router, connect over SSH as root and run:

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/REFFIX-X/luci-app-log/master/install-online.sh | sh
```

The installer detects `apk` versus `opkg`, reads the current package tag from the direct-download package mirror, installs the matching `libmaxminddb` helper package and complete REFFIX LuCI package, attempts to download the GeoLite2 databases, and restarts `rpcd`.

Current published package targets are **OpenWrt 25.12 (APK)** and **OpenWrt 24.10 (IPK)**, built for package architecture `aarch64_cortex-a53` (including the Flint4 / MediaTek Filogic target). Other CPU architectures are rejected by the installer rather than being given the wrong library binary.

### What happens to the existing `luci-app-log-viewer`?

The REFFIX build deliberately uses the same package name, `luci-app-log-viewer`, and includes the original System Log and Kernel Log pages as well as the new Firewall Log. Installing it **upgrades/replaces the existing package in place**. You do not need to remove the old package first, and there is no dependency on a second upstream `luci-app-log-viewer` package.

The installer's second package, `libmaxminddb`, provides the local `mmdblookup` command used for GeoIP enrichment. The matching library package is attached to the release so the installer does not need to find that package in a third-party feed.

### Manual installation

Open [GitHub Releases](https://github.com/REFFIX-X/luci-app-log/releases) and download both matching assets for your firmware:

- OpenWrt 25.12: `reffix-luci-app-log-viewer-openwrt-25.12.apk` and `reffix-libmaxminddb-openwrt-25.12.apk`.
- OpenWrt 24.10: `reffix-luci-app-log-viewer-openwrt-24.10.ipk` and `reffix-libmaxminddb-openwrt-24.10.ipk`.

Install the `libmaxminddb` package first, then the app package. For APK-based firmware, use `apk add --allow-untrusted /path/to/package.apk`; for opkg-based firmware, use `opkg install /path/to/package.ipk`. The installer script does this automatically.

### Development overlay

For testing only, the repository still contains `install.sh` and `uninstall.sh` to apply the source overlay manually. The overlay approach is not needed for normal installs; the packaged release is the preferred route because it replaces the existing application cleanly.

## GeoIP data and privacy

GeoLite2 Country and ASN database files are not bundled in the repository. The helper downloads them from the third-party [P3TERX/GeoLite.mmdb mirror](https://github.com/P3TERX/GeoLite.mmdb), not directly from MaxMind. Review the current [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) requirements before distributing or using the database files. Database updates can be run manually with:

```sh
/usr/bin/flint4-geoip-update
```

Monthly updates are a reasonable starting point. GeoIP is approximate; VPNs, proxies, mobile carrier networks, cloud egress and anycast can affect country and ASN attribution.

## Firewall event meaning

- `INFRA_PORT_HIT`: traffic matched the infrastructure watchlist. The existing logging-only rule returns to normal firewall processing and does not itself block traffic.
- Generic `DROP` / `REJECT`: shown when the log line has source IP and destination port fields.
- A TCP SYN is a connection attempt, not evidence that a service accepted the connection or that a compromise occurred.

## Compatibility and upstream

- Designed for LuCI / OpenWrt >= 22.03. The automated build validates the source and creates packages for OpenWrt 25.12 and 24.10 on `aarch64_cortex-a53`. Hardware testing and compatibility with other release series, architectures, and third-party firmware builds are not yet guaranteed.
- Upstream project: https://github.com/gSpotx2f/luci-app-log
- The original project is MIT-licensed; preserve its license and attribution. GeoLite2 data terms are separate from the app's license.


## Verdict semantics

- **Blocked** is shown only when a log line explicitly identifies DROP, REJECT or a block marker (for example, `JELLYFIN_BLOCK:`).
- **Observed** means an `INFRA_PORT_HIT` watch rule logged the packet. This logging-only rule returns and does not itself decide the firewall verdict. The normal default-deny policy can still drop the packet later.
- **Allowed** is shown only when a firewall rule emits an explicit ALLOW/ACCEPT marker. Traffic that is allowed silently is not visible as an allowed event.

The app parses logs only. It does not change firewall policy or rules.


## Firewall Log controls and verdicts

- **Blocked** requires explicit DROP/REJECT or a block marker in the log.
- **Observed** means `INFRA_PORT_HIT` logged a packet. Your watch rule returns, so this is not itself a block verdict; normal firewall processing and default-deny policy run separately.
- **Allowed** appears only when a rule emits an explicit ALLOW/ACCEPT marker. Silent allowed traffic cannot be inferred from absence of a drop.
- Time filters limit the displayed recent buffer. Pause live refresh to inspect rows.
- Top sources, destination ports and GeoIP-resolved ASNs summarize the selected time window. GeoIP enrichment is capped at 60 unique source IPs per refresh to keep router load sensible.
- Scan/burst signals are heuristics, not proof of malicious activity: a source is flagged at 8 or more distinct destination ports or 25 or more logged events in the selected window.
- CSV includes the parsed verdict, original log marker and optional policy label/note.

### Optional local policy labels

The package includes an example configuration at `/usr/share/log-viewer/policies.example.json`. To activate and customize it:

```sh
mkdir -p /etc/log-viewer
cp /usr/share/log-viewer/policies.example.json /etc/log-viewer/policies.json
vi /etc/log-viewer/policies.json
```

The sample includes labels for `JELLYFIN_BLOCK`, `JELLYFIN_ALLOW` and `INFRA_PORT_HIT`. These labels only annotate log entries; they do not add or modify firewall rules. `JELLYFIN_ALLOW` events appear only if your allow rule emits that marker.


## Display accessibility

The Firewall Log uses higher-contrast text, stronger card boundaries and larger secondary labels while retaining the dark slate and amber/blue/green palette.
