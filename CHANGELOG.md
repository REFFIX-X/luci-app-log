# Changelog

## v1.5.0-r12 - 2026-10-11

- Build a complete `luci-app-log-viewer` APK/IPK package including the original System Log, Kernel Log and REFFIX Firewall Log.
- Include a matching `libmaxminddb` package for local GeoIP enrichment.
- Add a one-line installer that detects APK/opkg and upgrades the existing package in place.
- Automate OpenWrt 25.12 APK and 24.10 IPK builds for `aarch64_cortex-a53`.
- Make the app's package name explicit for the OpenWrt feed scanner while keeping LuCI's standard file staging rules.
- Publish SHA-256 checksums for release assets.

The package name remains `luci-app-log-viewer`, so an existing installation is upgraded/replaced in place. Source validation passes; the release workflow publishes APK/IPK artifacts only after both SDK build jobs and checksum generation succeed.