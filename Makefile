#
# REFFIX-maintained fork of gSpotx2f/luci-app-log.
# Original application is distributed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-log-viewer
# REFFIX v3.0.0; OpenWrt 25.12 APK only
PKG_VERSION:=3.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=REFFIX

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-log-viewer
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=REFFIX Firewall Log
  URL:=https://github.com/REFFIX-X/luci-app-log
  DEPENDS:=+libmaxminddb
  PKGARCH:=all
endef

define Package/luci-app-log-viewer/description
 REFFIX Firewall Log with optional local GeoLite2 Country/ASN enrichment.
endef

define Build/Compile
endef

define Package/luci-app-log-viewer/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/* $(1)/www/
	$(CP) ./root/* $(1)/
endef

$(eval $(call BuildPackage,luci-app-log-viewer))
