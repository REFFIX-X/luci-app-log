# Changelog

## v1.5.0-r20 - 2026-10-11

- Fix country flags not appearing when LuCI's Content Security Policy blocks third-party image hosts.
- Bundle 40 commonly encountered country flag SVGs locally and serve them directly from the router.
- Use a neutral globe icon for country codes without a bundled flag rather than showing broken image alt text.
- Retain the Firewall Log event-loading fix and the GeoLite2 updater validation fix.
- Continue targeting OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.

The release workflow publishes packages to the direct-download mirror and GitHub Releases only after both SDK builds succeed.