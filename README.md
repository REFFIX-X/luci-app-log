<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/c0774cb6-6b59-4271-b1c7-5aa9944f68a8" />

# REFFIX Firewall Log

REFFIX Firewall Log for OpenWrt LuCI, with local GeoIP enrichment.

## Highlights

- Line-by-line firewall events classified as Blocked, Other, Exposed, or explicitly Allowed, with evidence and policy notes shown for each event.
- Search and filters for addresses, ports, protocol, country and ASN.
- Local GeoLite2 country/ASN lookup; no per-IP web lookup API.
- Browser-local filter presets, event details, filtered/all-loaded CSV export, portable settings, optional bounded local history, interactive activity timeline and scan/burst heuristics.
- Monokai Pro-inspired dark palette coordinated with [REFFIX Monokai Pro for LuCI](https://github.com/REFFIX-X/luci-theme-footstrap).
- Existing package identity `luci-app-log-viewer` is retained so upgrades replace the installed app in place.

## Install on OpenWrt 25.12 / APK

Connect over SSH as root:

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/REFFIX-X/luci-app-log/main/install-online.sh | sh
```

The installer accepts OpenWrt 25.12 and `SNAPSHOT:mediatek/filogic` when `apk` is installed. Release assets are built for `aarch64_cortex-a53`. A generic `aarch64` arch is accepted only when the target is `mediatek/filogic`.

It installs two packages, `luci-app-log-viewer` and `libmaxminddb` (this build includes `mmdblookup`). Checksums are verified before `apk add`. The script tries the `package-assets` mirror first and, if that download or checksum check fails, uses the GitHub release named by `VERSION_FALLBACK` in `install-online.sh` (currently v3.2.1). A checksum mismatch on the release stops installation. It then runs `/usr/bin/flint4-geoip-update` and restarts `rpcd`.

After it finishes, open **Status → Firewall Log**. Log in again if the menu entry is missing; the ACL is loaded when `rpcd` restarts.

### Manual APK install

Download both APKs and `SHA256SUMS-openwrt-25.12.txt` from [GitHub Releases](https://github.com/REFFIX-X/luci-app-log/releases). Verify the checksums, then:

```sh
apk add --allow-untrusted \
  reffix-libmaxminddb-openwrt-25.12.apk \
  reffix-luci-app-log-viewer-openwrt-25.12.apk
/usr/bin/flint4-geoip-update
```

The package postinst enables `/etc/init.d/infra-port-watch`, starts it, clears the LuCI menu cache, and restarts `rpcd`. GeoLite2 files are not inside the APK. If the helper cannot download them, the log still loads and country/ASN fields stay empty until a later update.

Remove the app with `apk del luci-app-log-viewer`. That stops the watch rule. It does not delete `/usr/share/GeoIP` or, when the file was modified, the conffile `/etc/config/infra-port-watch`. `libmaxminddb` stays installed until you remove it separately.

### Install from a source checkout

`install.sh` copies this tree onto a router that already has LuCI. It does not build or install `libmaxminddb`.

```sh
sh install.sh
```

The script backs up files it replaces under `/root/reffix-log-viewer-backup-*`, installs the view, country flags, watch scripts, hotplug hook, menu, ACL, and `/usr/share/log-viewer/policies.example.json`, and restarts `rpcd`. It leaves an existing `/etc/config/infra-port-watch` in place. Then install `libmaxminddb` (it provides `mmdblookup`) and `iptables-mod-hashlimit`, and run `/usr/bin/flint4-geoip-update`. The package install pulls `iptables-mod-hashlimit` in through its dependency.

`uninstall.sh` removes that overlay, including the menu and ACL entries, and leaves the UCI watch config and GeoIP database files.

## Using Firewall Log

The page reads up to 1,500 recent system log entries from ubus `log.read` (one-shot, not a stream). If that call fails, it retries 400 entries, then falls back to `logread -l 1500` at `/sbin/logread`, `/usr/sbin/logread`, or `/usr/libexec/logread-ubox`. The fallback goes through LuCI `file.exec`, which keeps about 256 KiB of command output, so a busy fallback can return fewer than 1,500 lines. The status line shows how many source lines were actually read.

Events are shown 100 at a time. **Show more events** pages through the loaded set. The activity timeline filters the table to one interval. Auto-refresh is every 15 seconds while the tab is visible; **Pause live** stops it.

Search covers the visible fields plus country and ASN after GeoIP returns. Kind filters are All, Blocked, Other ports, Exposed, Other interface / unclassified, and Allowed. Protocol filters are All, TCP, and UDP. Time windows are all loaded lines, 5 minutes, 15 minutes, 1 hour, 6 hours, and 24 hours, compared with the router clock reported by the watch helper.

**Export filtered CSV** exports the current filter. **Export all loaded** exports the in-memory events, including browser history when that is on. Cells are quoted, and values that look like spreadsheet formulas are prefixed with a quote.

Optional browser history is off by default. When set to 1, 7, or 30 days it is stored in this browser's IndexedDB, capped at 10,000 events. Separately, the router keeps a memory ring of up to 500 firewall lines in `/tmp/log-viewer/events.ring`. That ring is cleared on reboot. `log-viewer-history` updates it every 15 seconds so other syslog cannot push firewall lines out of the live buffer. Clear either store from Settings.

Filter presets, exposed-service labels, the insights panel open/closed state, and the AbuseIPDB checkbox are `localStorage` keys beginning with `reffix-log-viewer.`. **Export settings** / **Import settings** move that browser state. If the file includes watcher settings, the import review writes them to this router. Opening an AbuseIPDB link sends that source IP to AbuseIPDB.

**Import firewall forwards** reads enabled DNAT redirects from `/etc/config/firewall` and can label the external port (`src_dport`). The watch logs in the raw table, before DNAT, so that external port is the destination port in the log line. The import does not read LAN hostnames and does not change firewall rules.

GeoIP looks up at most 60 distinct recent public IPv4 sources in one batched `/usr/bin/flint4-geoip --batch` call, split so the argument list stays under rpcd's limit. IPv6 and private addresses are not looked up. Hits are remembered in this browser for 7 days. Misses are cached for about five minutes. The status line shows the age of the older database file and calls it stale after 45 days. **Settings → Files → Update GeoIP databases** runs `/usr/bin/flint4-geoip-update` on this router. The page reloads WAN watch status about once a minute, and reloads log lines every 15 seconds.

## Configuration

Router watch settings live in `/etc/config/infra-port-watch` (`main.enabled`, `main.wan_interface`, `main.ports`). **Settings → Edit WAN watch** writes them with `/usr/sbin/infra-port-watch-config` and restarts the service. `wan_interface` is `auto` or a device name such as `eth2` or `pppoe-wan` (the `IN=` value). `auto` uses `network.interface.wan`'s `device`, then `l3_device`. At most 256 ports are stored. The UI applies the change immediately.

`/etc/init.d/infra-port-watch` installs the rules at boot. If the WAN device does not exist yet, `/etc/hotplug.d/iface/99-infra-port-watch` runs the same init script again when interface `wan` comes up. `/etc/infra-port-watch.sh` only execs the apply command for older path compatibility.

Optional policy labels come from `/etc/log-viewer/policies.json`. The package ships an example, not a live file:

```sh
mkdir -p /etc/log-viewer
cp /usr/share/log-viewer/policies.example.json /etc/log-viewer/policies.json
```

A rule matches the log marker and, when `port` is set, the destination port. The LuCI ACL allows reading only that path.

The matching [REFFIX Monokai Pro for LuCI theme](https://github.com/REFFIX-X/luci-theme-footstrap) has its own OpenWrt 25.12/APK release and installation guide.

## Firewall log semantics

- **Blocked** is a known-port probe (`INFRA_PORT_HIT`) with no allow and no forward, or an explicit DROP/REJECT log. The watch logged the probe and returned the packet. On a default-deny WAN the firewall drops it later. The subtitle is **Default deny**.
- **Other** is a low-rate sample of a WAN port that is not on that list (`INFRA_PORT_OTHER`, 2 per minute per source after a burst of 5). The subtitle is **Not on the watch list**. Logging every dropped packet would flood the system log, so ports outside the list stay a sample.
- **Exposed** means the destination port matches a configured exposed-service label or imported firewall forward. It does not prove the connection was accepted.
- **Allowed** requires an explicit allow/accept log marker. Silent allow traffic is not inferred from absence of a drop.
- Scan/burst signals are heuristic indicators, not proof of malicious activity.
- Use **Settings → Edit WAN watch** to set one WAN device (`auto` or the `IN=` name) and browser-local exposed-service labels. A logged hit on that device whose destination port has a label is marked **Exposed**. The log line does not prove that a forward accepted the connection. No LAN hostname lookup is performed.
- Known ports are the watch list in `/etc/config/infra-port-watch`, not every port the firewall drops. The default list includes common services plus TR-069 (7547), MikroTik (8291), MQTT TLS (8883), kubelet (10250), and WireGuard (51820). The app shows the destination ports present in the loaded log lines. The port insight ranks ports in the selected time window.
- The package installs an IPv4-only log-only raw-table watch for TCP SYN and UDP on the resolved WAN device. Listed ports go to a log chain with goto, so they are not sampled again. Ports outside the list hit a second log chain. Neither chain accepts or drops; both return the packet to normal firewall processing. Each source address may log 30 times per minute after a burst of 15 on a known port. Destination ports that match an enabled firewall forward use 4 per minute after a burst of 4. Every other port uses 2 per minute after a burst of 5. The package depends on `iptables-mod-hashlimit`, which also installs the kernel match. If that match still cannot be loaded, those rates fall back to shared limits and the status line says so. Edit the device and up to 256 known ports in **Settings → WAN watch**. **Add missing default ports** there appends shipped defaults that are absent and leaves the ports you already saved. Save settings to apply them. The UCI file is a package conffile, so an upgrade keeps the port list you already saved. The five ports added in v3.2.0 are defaults for a new install and for an empty list. After upgrading, run `/etc/init.d/infra-port-watch restart` once so the goto rules and the other-port chain replace the previous watch.
- The watch script sets `IPKG_INSTROOT` to empty when the package manager left it unset, then sources `/lib/functions.sh`. That keeps `set -u` from aborting the service on OpenWrt 25.12. If a v3.1.0 install left the watcher stopped, upgrade and run `/etc/init.d/infra-port-watch restart` once.
- The app does not change firewall accept/drop policy. A port such as 25125 is still logged, at the low other-port rate, without adding it to the known list. **Details** on an Other row can add that destination port to the known list, which restarts the watch so later hits use the full per-address budget. There is no IPv6 watch rule.

## GeoIP and privacy

`/usr/bin/flint4-geoip-update` downloads `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` from `https://github.com/P3TERX/GeoLite.mmdb/raw/download` into `/usr/share/GeoIP`. It checks both files with `mmdblookup` before replacing the live copies. Override the directory with `GEOIP_DB_DIR` when calling `/usr/bin/flint4-geoip`. The databases are not in git or in the APK. Review the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) obligations before redistributing database files. Country and ASN matches are approximate.

## Upstream and license

This project is a REFFIX-maintained fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log). The original application is MIT-licensed; see [LICENSE](LICENSE). Preserve upstream attribution and license notices when redistributing the derived application.
