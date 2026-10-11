# Changelog

## v2.0.0

- Establishes REFFIX's own v2 release line.
- Reduces Firewall Log typography by one step across the event table, toolbar, statistics and insight panels.
- Prevents destination IP addresses from wrapping inside table cells.
- Makes the online installer fall back to GitHub release assets when the raw-content package index cannot be fetched.
- Keeps the existing `luci-app-log-viewer` package identity for in-place upgrades.

- Restricts package builds and online installation to OpenWrt 25.12 / APK only.
- Release pipeline removes legacy releases, tags and old package-mirror directories after publishing v2.0.0.
