# Changelog

## v1.5.0-r10 - 2026-10-11

- Build a complete `luci-app-log-viewer` APK/IPK package including original log pages and the REFFIX Firewall Log.
- Include a matching `libmaxminddb` package so local GeoIP works without a dependency on a separate package feed.
- Add a one-line installer that detects APK/opkg and upgrades the existing app package in place.
- Automate OpenWrt 25.12 APK and 24.10 IPK builds for `aarch64_cortex-a53`.
- Publish SHA-256 checksums and document installation and upgrade behaviour.
- Fix the bundled libmaxminddb build recipe and executable permissions for the GeoIP helper scripts.

The package name remains `luci-app-log-viewer`, so an existing installation is upgraded/replaced in place. Router-side testing is still recommended.
