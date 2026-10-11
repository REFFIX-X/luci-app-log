# Changelog

## v1.5.0-r19 - 2026-10-11

- Render country flags with small PNG assets from FlagCDN instead of Unicode flag emoji, which can appear as two-letter country codes on Windows and some other client systems.
- Keep GeoIP country and ASN resolution local using the installed GeoLite2 databases; only the ISO country code is used in the flag image URL.
- Include Firewall Log event loading fix from r17 and GeoIP database validation fix from r16.
- Continue supporting OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.

The release workflow publishes packages to the direct-download mirror and GitHub Releases only after both SDK builds succeed. Package release number: `r19`.