# Changelog

## v3.1.1

- Fixes WAN watcher startup on OpenWrt 25.12 when `IPKG_INSTROOT` is unset during package post-upgrade.

## v3.1.0

- Classifies configured `INFRA_PORT_HIT` WAN watchlist entries as Blocked and clarifies default-deny behavior.
- Adds clickable source, burst and destination-port insights, expandable repeated-probe groups, and a collapsible Insights panel.
- Adds a router-configurable WAN interface and browser-local exposed-service labels to distinguish hits matching configured forwards.
- Packages and enables a rate-limited, log-only WAN port watch with the existing Flint4 defaults; its interface and up to 256 ports are configurable from the Firewall Log UI.
- Adds router-timezone-aware event filtering, a selectable activity timeline, and IPv4-only watcher status.
- Adds browser-local optional history with retention and a 10,000-event cap, plus reviewed firewall-forward label imports and portable settings files.
- Bounds log-group and expanded-row rendering pages and caches local history in memory between refreshes.
- Improves filter and file-import accessibility, reports the 1,500-source-line limit, and retains the theme unchanged.

## v3.0.0

- Makes Firewall Log the only page and renames the Status menu entry to Firewall Log.
- Removes the System Log and Kernel Log views and their unused RPC access.

## v2.1.0

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
