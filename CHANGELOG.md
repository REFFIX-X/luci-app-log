# Changelog

## v1.5.0-r16 - 2026-10-11

- Fix GeoLite2 update validation by using `8.8.8.8` rather than `1.1.1.1`; an anycast IP may not contain the optional `country.iso_code` path, causing a valid database to be rejected.
- Keep both Country and ASN database lookups validated before replacing the currently installed database files.
- Continue publishing the APK/IPK packages through the direct-download `package-assets` branch and GitHub release assets.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`. Both package builds and mirror publication must pass before the installer index advances to this version.