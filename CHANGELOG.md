# Changelog

## v1.5.0-r15 - 2026-10-11

- Publish built APK/IPK packages on a versioned `package-assets` branch for direct `raw.githubusercontent.com` downloads.
- Update the one-line installer to fetch a simple `latest` marker and download binaries without GitHub release-asset redirects, which some OpenWrt `uclient-fetch` builds cannot follow.
- Keep the APK/IPK release assets and SHA-256 checksum files on GitHub Releases as before.
- Bump package release to r15; keep the existing `luci-app-log-viewer` package name for in-place upgrades.

Targeted builds remain OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.