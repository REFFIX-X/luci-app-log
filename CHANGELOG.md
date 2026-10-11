# Changelog

## v1.5.0-r13 - 2026-10-11

- Replace the LuCI macro-based Makefile with a conventional OpenWrt `package.mk` recipe so the external feed scanner can discover the app reliably.
- Package all existing LuCI views, menu/ACL files, RPC ucode service and GeoIP helpers as a single `luci-app-log-viewer` package.
- Keep the upstream package name for in-place upgrades.
- Continue building APK for OpenWrt 25.12 and IPK for OpenWrt 24.10 on `aarch64_cortex-a53`.

The package build workflow must complete successfully before this version is published as a release. Hardware testing is still recommended.