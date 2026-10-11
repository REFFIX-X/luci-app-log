#
# REFFIX maintained fork of gSpotx2f/luci-app-log
# Original application is distributed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-log-viewer
PKG_VERSION:=1.5.0
PKG_RELEASE:=27
PKG_LICENSE:=MIT
PKG_MAINTAINER:=REFFIX

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-log-viewer
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=REFFIX System, Kernel and Firewall Log Viewer
  URL:=https://github.com/REFFIX-X/luci-app-log
  DEPENDS:=+ucode +ucode-mod-fs +libmaxminddb
  PKGARCH:=all
endef

define Package/luci-app-log-viewer/description
 REFFIX fork of luci-app-log-viewer with System Log, Kernel Log,
 Firewall Log and optional local GeoLite2 Country/ASN enrichment.
endef

define Build/Compile
endef

define Package/luci-app-log-viewer/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/* $(1)/www/
	$(CP) ./root/* $(1)/
endef

$(eval $(call BuildPackage,luci-app-log-viewer))
