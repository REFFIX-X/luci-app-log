# Changelog

## v1.5.0-r8 - 2026-10-11

- Build a complete `luci-app-log-viewer` APK/IPK package that includes all original log pages and the REFFIX Firewall Log.
- Publish matching release assets for the app and `libmaxminddb`, plus SHA-256 checksums, for OpenWrt 25.12 and 24.10.
- Add a matching `libmaxminddb` package to releases so local GeoIP does not rely on an unrelated package feed.
- Add a one-line online installer that detects APK/opkg and upgrades the existing app package in place.
- Automate package builds and GitHub release assets for OpenWrt 25.12 (APK) and 24.10 (IPK) on `aarch64_cortex-a53`.
- Publish SHA-256 checksums and clarify package installation in the README.

This release uses the existing package name, so an already installed `luci-app-log-viewer` is upgraded/replaced rather than kept as a second required package. Router-side testing is still recommended.
