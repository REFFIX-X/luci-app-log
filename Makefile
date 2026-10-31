#
# REFFIX-maintained fork of gSpotx2f/luci-app-log.
# Original application is distributed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-log-viewer
# REFFIX v3.2.1; OpenWrt 25.12 APK only
PKG_VERSION:=3.2.1
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
  DEPENDS:=+luci-base +logd +ucode +ucode-mod-fs +libmaxminddb +iptables-nft +jsonfilter
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
	chmod 755 $(1)/usr/bin/flint4-geoip $(1)/usr/bin/flint4-geoip-update $(1)/usr/sbin/infra-port-watch $(1)/usr/sbin/infra-port-watch-config $(1)/usr/sbin/log-viewer-history $(1)/etc/init.d/infra-port-watch $(1)/etc/init.d/log-viewer-history $(1)/etc/infra-port-watch.sh $(1)/etc/hotplug.d/iface/99-infra-port-watch
endef

define Package/luci-app-log-viewer/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/infra-port-watch enable
/etc/init.d/infra-port-watch start || echo "WARNING: WAN watch rule could not start; configure the WAN device and restart infra-port-watch."
/etc/init.d/log-viewer-history enable
/etc/init.d/log-viewer-history start || echo "WARNING: firewall history ring did not start."
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
exit 0
endef

define Package/luci-app-log-viewer/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/infra-port-watch stop 2>/dev/null || true
/etc/init.d/infra-port-watch disable 2>/dev/null || true
/etc/init.d/log-viewer-history stop 2>/dev/null || true
/etc/init.d/log-viewer-history disable 2>/dev/null || true
exit 0
endef

$(eval $(call BuildPackage,luci-app-log-viewer))
