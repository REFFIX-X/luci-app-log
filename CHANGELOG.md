# Changelog

## Unreleased

- Verifies both APK downloads against the published SHA-256 file before package installation.
- Documents OpenWrt 25.12 and supported MediaTek Filogic snapshot installation.
- Adds browser-local filter presets, event details, filtered/all-loaded CSV export, formula-safe CSV cells, and opt-in external reputation links.
- Reports the loaded log window and GeoIP database age, and supports loading more matching rows.
- Avoids repeat parsing of unchanged logs and duplicate Firewall Log style injection; GeoIP lookups run after the log table is rendered and unavailable results are briefly cached.
- Removes the unreferenced root screenshot assets while retaining the documented developer examples and required upstream license notices.

## v2.0.0

- Establishes REFFIX's own v2 release line.
- Reduces Firewall Log typography by one step across the event table, toolbar, statistics and insight panels.
- Prevents destination IP addresses from wrapping inside table cells.
- Makes the online installer fall back to GitHub release assets when the raw-content package index cannot be fetched.
- Keeps the existing `luci-app-log-viewer` package identity for in-place upgrades.

- Restricts package builds and online installation to OpenWrt 25.12 / APK only.
- Release pipeline removes legacy releases, tags and old package-mirror directories after publishing v2.0.0.
