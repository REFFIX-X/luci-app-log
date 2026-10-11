# Changelog

## v1.5.0-r27 - 2026-10-11

- Strengthen readability after the initial contrast pass was too subtle at the actual LuCI rendered size.
- Set explicit pixel sizes for table cells, insight rows, helper text, toolbar controls and KPI labels/numbers using `!important` to beat inherited LuCI rules.
- Increase text brightness, weight, line-height and card/table padding while keeping the established dark slate, blue, amber and green palette.
- No changes to event parsing, verdict logic, policy config, or firewall behaviour.

Targets: OpenWrt 25.12 APK and OpenWrt 24.10 IPK for `aarch64_cortex-a53`.