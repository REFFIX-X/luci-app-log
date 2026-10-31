<img width="1920" height="1080" alt="Firewall Log" src="https://github.com/user-attachments/assets/c0774cb6-6b59-4271-b1c7-5aa9944f68a8" />

# REFFIX Firewall Log

OpenWrt 25.12 LuCI page for the IPv4 firewall log. It classifies events locally, looks up country and ASN from GeoLite2 on the router, and can log WAN probes without accepting or dropping them. The package name is `luci-app-log-viewer`.

## Install

On the router, as root:

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/REFFIX-X/luci-app-log/main/install-online.sh | sh
```

OpenWrt 25.12, or a `SNAPSHOT:mediatek/filogic` image with `apk`. Builds are `aarch64_cortex-a53`. A generic `aarch64` arch is accepted only on that Filogic target.

The script installs the latest release. If `luci-app-log-viewer` is already there and older, it upgrades that package. Running it again on the same release replaces the files. Your saved `/etc/config/infra-port-watch` stays. Checksums are verified before `apk add`. Then open **Status → Firewall Log**.

Manual install: download both APKs and `SHA256SUMS-openwrt-25.12.txt` from [Releases](https://github.com/REFFIX-X/luci-app-log/releases), check the sums, then `apk add --allow-untrusted` those two files and run `/usr/bin/flint4-geoip-update`.

`apk del luci-app-log-viewer` removes the app and stops the watch. It leaves GeoIP databases and a modified port list. `libmaxminddb` stays until you remove it.

## Using it

**Blocked** is a known-port probe with nothing allowing it. The firewall's default policy drops it later. **Other** is a low-rate sample of every other WAN port. **Exposed** means that port has a label or a firewall forward. **Allowed** requires an explicit accept log.

Each source gets its own budget: 30 per minute on a known port, 4 per minute when that port is also forwarded, 2 per minute on anything else. The package depends on `iptables-mod-hashlimit`. The watch only logs IPv4 TCP SYN and UDP, then returns the packet.

**Details** on an Other row can add that port to the known list. **Settings → Edit WAN watch → Add missing default ports** fills in shipped defaults that a saved list does not have. **Settings → Files → Update GeoIP databases** refreshes the local databases. They are not in the APK. Review the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) before sharing them.

Browser history is optional. The router also keeps 500 firewall lines in memory at `/tmp/log-viewer/events.ring`, cleared on reboot.

## License

REFFIX fork of [gSpotx2f/luci-app-log](https://github.com/gSpotx2f/luci-app-log), MIT. See [LICENSE](LICENSE).
