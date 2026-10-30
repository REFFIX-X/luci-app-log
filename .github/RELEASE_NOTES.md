# REFFIX Firewall Log v3.1.3

OpenWrt 25.12 bugfix release for installing and using Firewall Log. The package name remains `luci-app-log-viewer`.

## Fixes

- LuCI can save WAN watch settings. The exec ACL grants `/usr/sbin/infra-port-watch-config`. The previous entry matched only `set` with no arguments, so saving the interface and port list was denied. A long port list also exceeds rpcd's 1024-byte command check.
- Firewall Log reads ubus `log.read` first (1,500 entries, then 400 if that call fails), then `logread` at `/sbin/logread`, `/usr/sbin/logread`, and `/usr/libexec/logread-ubox`. OpenWrt 25.12 installs logread under `/usr/libexec`, and LuCI `file.exec` keeps only about 256 KiB.
- The WAN watch is applied again when interface `wan` comes up, so a boot before PPPoE or DHCP still installs the log-only rule.
- `infra-port-watch get` still prints status when `/etc/config/firewall` is missing.
- Package install restarts `rpcd` and clears the LuCI menu cache. The source overlay installs country flags, the policy example, and the WAN hotplug hook.
- CSV and settings downloads work in browsers that ignore a click on a detached link.
- The package depends on `luci-base` and `logd`.

GeoLite2 databases are downloaded separately and are not in the APK. See the README for install steps and licensing.

The release build attaches the OpenWrt 25.12 APK app, the matching `libmaxminddb` helper, and their SHA-256 checksums when that build finishes.
