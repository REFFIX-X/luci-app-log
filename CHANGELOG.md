# Changelog

## v1.5.0-r14 - 2026-10-11

- Fix the SDK compile error by defining an empty `Build/Compile` for this files-only package.
- Keep the standard OpenWrt `package.mk` recipe so feed discovery and package generation work without a source Makefile.
- Package the original System Log and Kernel Log pages plus the REFFIX Firewall Log and local GeoIP helpers.
- Continue targeting OpenWrt 25.12 APK and 24.10 IPK on `aarch64_cortex-a53`.

The release workflow will attach APK/IPK and checksum assets only after both SDK builds pass. This version fixes the empty source-directory compile failure found in the previous SDK run.