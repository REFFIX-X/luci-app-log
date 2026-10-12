#
# REFFIX-maintained fork of gSpotx2f/luci-app-log.
# Original application is distributed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-log-viewer
# REFFIX v2.1.0; OpenWrt 25.12 APK only
PKG_VERSION:=2.1.0
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
  DEPENDS:=+ucode +ucode-mod-fs +libmaxminddb +iptables-nft +jsonfilter
  PKGARCH:=all
endef

define Package/luci-app-log-viewer/conffiles
/etc/config/infra-port-watch
endef

define Package/luci-app-log-viewer/description
 REFFIX firewall event dashboard with optional local GeoLite2 Country/ASN
 enrichment and configurable log-only WAN port monitoring.
endef

define Build/Compile
endef

define Package/luci-app-log-viewer/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/* $(1)/www/
	$(CP) ./root/* $(1)/
	chmod 755 $(1)/usr/bin/flint4-geoip $(1)/usr/bin/flint4-geoip-update $(1)/usr/sbin/infra-port-watch $(1)/usr/sbin/infra-port-watch-config $(1)/etc/init.d/infra-port-watch $(1)/etc/infra-port-watch.sh
endef

define Package/luci-app-log-viewer/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/infra-port-watch enable
/etc/init.d/infra-port-watch start || echo "WARNING: WAN watch rule could not start; configure the WAN device and restart infra-port-watch."
exit 0
endef

define Package/luci-app-log-viewer/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/infra-port-watch stop 2>/dev/null || true
/etc/init.d/infra-port-watch disable 2>/dev/null || true
exit 0
endef

$(eval $(call BuildPackage,luci-app-log-viewer))
