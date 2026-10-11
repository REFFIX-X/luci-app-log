# Changelog

## v1.5.0-r25 - 2026-10-11

- Prevent out-of-order GitHub Actions builds from downgrading the direct-download `package-assets/latest` marker.
- Include dashboard enhancements from r24/r23: time windows, pause/resume, top source/port/ASN summaries, scan/burst signals, policy-aware labels, explicit verdict semantics, copy-IP and richer CSV.
- Bundle local country flags, fix ISO code case handling, and keep GeoLite2 updater validation safe.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.