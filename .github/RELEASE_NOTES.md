# REFFIX Firewall Log v3.1.1

OpenWrt 25.12 APK packages for the REFFIX Firewall Log and matching local GeoIP helper. The package retains the `luci-app-log-viewer` identity for in-place upgrades.

## What's included

- IPv4-only, rate-limited log-only WAN watch with configurable interface and port list.
- Grouped probes, source/port insights, a time-filtering activity timeline and browser-local optional history.
- Portable browser settings and reviewed import of firewall-forward port labels.
- OpenWrt 25.12 APK app and matching `libmaxminddb` helper with SHA-256 checksums.
- Fixes WAN watcher post-upgrade startup when OpenWrt leaves `IPKG_INSTROOT` unset.

## Important

- Tests cover JavaScript syntax, firewall parser behavior, installer checksum handling, shell syntax and JSON syntax.
- GeoLite2 databases are downloaded separately by the helper and are not included in the APK. See the README for data source and licensing notes.

See the [README](https://github.com/REFFIX-X/luci-app-log/blob/main/README.md) for supported router targets and installation instructions.
