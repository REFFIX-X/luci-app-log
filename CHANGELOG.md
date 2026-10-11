# Changelog

## v1.5.0-r17 - 2026-10-11

- Fix Firewall Log showing zero events when matching `INFRA_PORT_HIT`, `DROP` and `REJECT` messages are present in Kernel Log.
- Fetch the latest 1,500 syslog entries and filter events in JavaScript, avoiding `logread -e` regex alternation compatibility issues across OpenWrt builds.
- Preserve generic `DROP`/`REJECT` detection, port-probe parsing and local GeoIP enrichment.
- Include the GeoIP updater validation fix from r16.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`, distributed through the direct-download package mirror and GitHub Releases.