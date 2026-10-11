# Changelog

## v1.5.0-r18 - 2026-10-11

- Fix country flag display by explicitly using common emoji-capable system font stacks instead of inheriting the LuCI page font, which rendered regional-indicator flag sequences as country-code letters in some browsers.
- Keep local GeoLite2 Country/ASN lookup and the Firewall Log event-filtering fix from r17.
- Continue supporting OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.

The release workflow publishes packages to the direct-download mirror and GitHub Releases only after both SDK builds succeed. Package release number: `r18`.