# REFFIX luci-app-log

A REFFIX-maintained fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log). The original System Log and Kernel Log views are retained, with a new **Firewall Log** view for OpenWrt and GL.iNet routers.

## Features

- Original System Log and Kernel Log pages.
- **Firewall Log** parses the `INFRA_PORT_HIT`, `JELLYFIN_BLOCK`, and conventional `DROP` / `REJECT` kernel log messages.
- Readable table with timestamp, source IP, local GeoIP country flag/name and ASN organisation, destination IP, destination port/service, protocol, event type, source port, ingress interface and TCP flags.
- Filters for event type and TCP/UDP, search across IPs/countries/ASNs/ports/services, CSV export and periodic refresh.
- GeoIP enrichment uses a local MaxMind GeoLite2 database. No per-IP lookup API is called.
- Does not add or modify firewall rules.

## Installation

The current fork includes source files for the new Firewall Log view and helper scripts. A ready-to-install APK/IPK release has not yet been published, so use the source overlay steps below for now.

### Install on OpenWrt / GL.iNet Flint4

Run the following commands on the router as root. Make a backup first, especially if you have customized the existing LuCI menu or ACL files.

1. **Copy the repository to the router.** From Windows PowerShell, with the repo cloned locally:

   ```powershell
   scp -r .\luci-app-log root@192.168.1.1:/tmp/
   ssh root@192.168.1.1
   cd /tmp/luci-app-log
   ```

   Replace the IP with the router's LAN address and adjust the local folder if needed.

2. **Install the GeoIP database reader.**

   OpenWrt 25.12 and newer versions using APK:
   ```sh
   apk update
   apk add libmaxminddb
   ```

   OpenWrt 24.10 and older versions using opkg:
   ```sh
   opkg update
   opkg install libmaxminddb
   ```

3. **Install the view and menu files.**

   From the repo directory on the router:
   ```sh
   sh ./install.sh
   ```

4. **Download the GeoLite2 Country and ASN databases, then test the helper.**
   ```sh
   /usr/bin/flint4-geoip-update
   /usr/bin/flint4-geoip --json 1.1.1.1
   ```

5. **Reload LuCI permissions and refresh the browser.**
   ```sh
   /etc/init.d/rpcd restart
   ```

   Then press **Ctrl+F5** in the browser and open **Status → Log Viewer → Firewall Log**.

The installer keeps timestamped backups of the menu and ACL JSON files under `/root/reffix-log-viewer-backup-*`. Review those backups if you need to restore your previous configuration.

### Remove the overlay

From the repository directory on the router:

```sh
sh ./uninstall.sh
/etc/init.d/rpcd restart
```

The uninstall script removes the new view and GeoIP helpers. Restore the backed-up menu and ACL files manually if you want to revert those too. It does not remove the GeoLite2 database files or the `libmaxminddb` package.

## Building a package for hosting

For a proper release download, build the fork inside an OpenWrt SDK/buildroot matching the router's OpenWrt release and target:

```sh
# Copy this repository to package/luci-app-log-viewer in the matching build tree
make menuconfig
# Select LuCI -> Applications -> luci-app-log-viewer
make package/luci-app-log-viewer/compile V=s
```

The output is under `bin/packages/...` for APK-based OpenWrt releases or `bin/packages/...` / `bin/targets/...` depending on the build setup. Publish only packages built for the matching release and architecture. Do not install an APK/IPK from another OpenWrt branch.

GitHub Releases can host the resulting package and source archive. A package feed is another option, but it needs per-release package builds and repository metadata. Once the packages are built and tested, the README can link to stable release assets.

## GeoIP data and privacy

GeoLite2 Country and ASN database files are not bundled in the repository. The helper downloads them from the third-party [P3TERX/GeoLite.mmdb mirror](https://github.com/P3TERX/GeoLite.mmdb), not directly from MaxMind. Review the current [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) and [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) requirements before distributing or using the database files. Database updates can be run manually with:

```sh
/usr/bin/flint4-geoip-update
```

Monthly updates are a reasonable starting point. GeoIP is approximate; VPNs, proxies, mobile carrier networks, cloud egress and anycast can affect country and ASN attribution.

## Firewall event meaning

- `INFRA_PORT_HIT`: traffic matched the infrastructure watchlist. The existing logging-only rule returns to normal firewall processing and does not itself block traffic.
- `JELLYFIN_BLOCK`: a custom Jellyfin log prefix. Verify the paired DROP rule if you need to confirm packet handling.
- Generic `DROP` / `REJECT`: shown when the log line has source IP and destination port fields.
- A TCP SYN is a connection attempt, not evidence that a service accepted the connection or that a compromise occurred.

## Compatibility and upstream

- Designed for LuCI / OpenWrt >= 22.03, but the overlay has not yet been verified on every OpenWrt release or theme.
- Upstream project: https://github.com/gSpotx2f/luci-app-log
- The original project is MIT-licensed; preserve its license and attribution. GeoLite2 data terms are separate from the app's license.
