# Changelog

## v1.5.0-r22 - 2026-10-11

- Add selectable event windows: all loaded, 5 minutes, 15 minutes, 1 hour, 6 hours and 24 hours.
- Add pause/resume live refresh and a last-update indicator.
- Add Top Sources, Top Destination Ports, Top GeoIP ASNs and heuristic Scan/Burst panels.
- Add optional local policy labels with a sample config for Jellyfin ports 8096/8920, Fibia allow-marker annotation and INFRA_PORT_HIT watch events.
- Distinguish Observed (verdict unknown), explicit Blocked, and explicitly logged Allowed traffic in filters, counters and rows.
- Add unique source counts, one-click copy IP, richer CSV exports and counters that respect the active time/verdict/protocol/search filters.
- Fix case-normalization for locally bundled country flags.
- No firewall rules are changed by this app.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.