# Changelog

## v1.5.0-r28 - 2026-10-11

- Apply a cohesive Monokai Pro-inspired colorway to the Firewall Log: warm charcoal canvas, deep aubergine panels, warm white text, yellow, pink, orange, green, cyan and purple accents.
- Replace layered contrast overrides with one scoped theme block, preserving the dashboard layout and avoiding unintended styling changes to the rest of LuCI.
- Improve panel, table, stat, toolbar, link, scan-signal and verdict badge contrast; retain clear text sizing and responsive layout.
- No changes to firewall rules, policy behavior, event parsing or GeoIP sources.

Palette reference: Monokai Pro public theme colors; this is an original dashboard CSS adaptation, not bundled editor-theme code.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.