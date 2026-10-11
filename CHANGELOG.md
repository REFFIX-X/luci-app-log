# Changelog

## v1.5.0-r21 - 2026-10-11

- Fix local flag lookup by normalizing uppercase GeoIP country codes before checking the lowercase bundled asset list.
- Clarify and classify three event states: Blocked (explicit DROP/REJECT/BLOCK evidence), Observed (INFRA_PORT_HIT, final verdict unknown), and Allowed (explicit ALLOW/ACCEPT log marker only).
- Recognize generic block/allow log prefixes, including custom markers such as `JELLYFIN_BLOCK:`, without hardcoding service-specific rules.
- Add event-type filters and separate stats for blocked, observed, explicitly logged allowed events and countries; make stats reflect the current filter instead of only the first 500 rows.
- Add one-click source-IP copy and include verdict/log marker in CSV exports.
- Preserve local bundled flag SVGs and previous GeoIP validation and log-loading fixes.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`. Packages publish to the direct-download mirror only after both SDK builds succeed.