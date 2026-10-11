# REFFIX luci-app-log v1.5.0-r7

This is a **source-only pre-release** of the REFFIX fork of `luci-app-log-viewer`, adding a general-purpose firewall log page.

## What's included

- New general-purpose Firewall Log LuCI view.
- Local GeoLite2 Country and ASN enrichment using `mmdblookup`.
- Filtering, search, CSV export, service/port labels and periodic refresh.
- LuCI menu and RPC ACL entries, overlay install/uninstall scripts.
- Updated installation and troubleshooting documentation.

## Important

- This release does **not** include a prebuilt APK/IPK.
- The overlay assumes the upstream `luci-app-log-viewer` package is already installed.
- The source passes automated JavaScript, shell and JSON validation, but has not yet been verified on every OpenWrt release/theme or exhaustively tested on router hardware.
- GeoLite2 databases are downloaded separately by the helper and are not included in this release. See the README for the data source and licensing notes.

Install using the source overlay steps in [README.md](https://github.com/REFFIX-X/luci-app-log/blob/master/README.md).
