# Changelog

## v1.5.0-r11 - 2026-10-11

- Build a complete `luci-app-log-viewer` APK/IPK package including original log pages and the REFFIX Firewall Log.
- Include a matching `libmaxminddb` package so local GeoIP works without requiring an unrelated package feed at install time.
- Add a one-line installer that detects APK/opkg and upgrades the existing app package in place.
- Automate OpenWrt 25.12 APK and 24.10 IPK builds for `aarch64_cortex-a53`.
- Publish SHA-256 checksums and document installation and upgrade behaviour.
- Use OpenWrt's upstream `libmaxminddb` build recipe and correct executable permissions for helper scripts.

The package name remains `luci-app-log-viewer`, so an existing installation is upgraded/replaced in place. The build validates both package variants before publishing. Router-side testing is still recommended.
