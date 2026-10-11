# Changelog

## v1.5.0-r23 - 2026-10-11

- Fix JavaScript syntax in the new policy-context help text.
- Include selectable time windows, pause/resume refresh, top sources/ports/ASNs, scan/burst heuristics, policy-label support and richer CSV export from r22.
- Fix uppercase GeoIP country-code matching against locally bundled lowercase flag asset names.
- Keep policy annotations configurable in `/etc/log-viewer/policies.json`; the app remains read-only and does not edit firewall rules.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`. Release automation updates the direct-download mirror only after both package builds pass.