# Changelog

## v1.5.0-r9 - 2026-10-11

- Build a complete `luci-app-log-viewer` APK/IPK package including the original log pages and REFFIX Firewall Log.
- Include a matching `libmaxminddb` package so the one-line installer does not rely on a third-party package feed for local GeoIP.
- Add an online installer that detects APK/opkg and upgrades the installed app in place.
- Automate OpenWrt 25.12 APK and 24.10 IPK builds for `aarch64_cortex-a53`.
- Publish SHA-256 checksums and document install and upgrade behavior.

The package name remains `luci-app-log-viewer`, so an existing installation is upgraded/replaced in place. The package build marks the GeoIP helpers executable and supports both APK and IPK package filename conventions. Router-side testing is still recommended.
