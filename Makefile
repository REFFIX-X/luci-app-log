#
# REFFIX maintained fork of gSpotx2f/luci-app-log
# Original application is distributed under the MIT License.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-log-viewer
PKG_VERSION:=1.5.0
PKG_RELEASE:=12
LUCI_TITLE:=Advanced syslog, kernel and firewall log viewer
LUCI_DEPENDS:=+ucode +ucode-mod-fs +libmaxminddb
LUCI_PKGARCH:=all
PKG_LICENSE:=MIT

# Keep the package name literal so external OpenWrt feed scanners can discover it.
# luci.mk below supplies the actual metadata and install rules.
define Package/luci-app-log-viewer
endef

include $(TOPDIR)/feeds/luci/luci.mk
