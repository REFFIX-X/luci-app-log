const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');
const config = fs.readFileSync(path.join(root, 'root/etc/config/infra-port-watch'), 'utf8');
const watcher = fs.readFileSync(path.join(root, 'root/usr/sbin/infra-port-watch'), 'utf8');
const writer = fs.readFileSync(path.join(root, 'root/usr/sbin/infra-port-watch-config'), 'utf8');
const defaults = [...config.matchAll(/list ports '(\d+)'/g)].map(match => Number(match[1]));

test('ships the Flint4 default watchlist in UCI and the runtime fallback consistently', () => {
  const fallback = watcher.match(/ports="([0-9 ]+)"/);
  assert.ok(fallback, 'runtime helper must have a safe fallback port list');
  assert.deepEqual(defaults, fallback[1].trim().split(/\s+/).map(Number));
  assert.equal(defaults.length, 100);
  assert.equal(new Set(defaults).size, defaults.length);
  assert.ok(defaults.every(port => port >= 1 && port <= 65535));
  assert.equal(defaults.includes(25125), false, 'arbitrary ports are opt-in via the UI');
});

test('watcher only logs TCP SYN and UDP matches, then returns traffic to normal firewall processing', () => {
  assert.match(watcher, /-p tcp .*--syn -j "\$chain"/);
  assert.match(watcher, /-p udp .* -j "\$chain"/);
  assert.match(watcher, /-j LOG --log-prefix 'INFRA_PORT_HIT: '/);
  assert.match(watcher, /-j RETURN/);
  assert.match(watcher, /--hashlimit-mode srcip/);
  assert.match(watcher, /--hashlimit-upto "\$rate"/);
  assert.match(watcher, /--hashlimit-burst "\$burst"/);
  assert.match(watcher, /install_log_chain "\$LOG_CHAIN" reffix_scan 30\/minute 15/);
  assert.match(watcher, /install_log_chain "\$FWD_CHAIN" reffix_fwd 4\/minute 4/);
  assert.match(watcher, /--hashlimit-htable-expire 120000/);
  assert.match(watcher, /INFRA_PORT_FWD/);
  assert.match(watcher, /src_dport/);
  assert.doesNotMatch(watcher, /--limit 10\/minute --limit-burst 20/);
  assert.doesNotMatch(watcher, /\-j (?:ACCEPT|DROP|REJECT)\b/);
  assert.match(watcher, /if \[ "\$count" -ge 15 \]/, 'multiport groups stay within the xt_multiport limit');
});

test('watcher initializes OpenWrt package install context before sourcing system functions', () => {
  assert.match(watcher, /IPKG_INSTROOT="\$\{IPKG_INSTROOT:-\}"[\s\S]*?\. \/lib\/functions\.sh/);
});

test('WAN hotplug reapplies the watch after interface wan comes up', () => {
  const hotplug = fs.readFileSync(path.join(root, 'root/etc/hotplug.d/iface/99-infra-port-watch'), 'utf8');
  assert.match(hotplug, /\[ "\$\{ACTION:-\}" = ifup \]/);
  assert.match(hotplug, /\[ "\$\{INTERFACE:-\}" = wan \]/);
  assert.match(hotplug, /\/etc\/init\.d\/infra-port-watch restart/);
});

test('status JSON still prints when the firewall config cannot be loaded', () => {
  assert.match(watcher, /config_load firewall \|\| true/);
  assert.match(watcher, /CONFIG_SECTIONS="\$\{CONFIG_SECTIONS:-\}"/);
});

test('UI writer validates configurable WAN device and port list before committing UCI', () => {
  assert.match(writer, /invalid WAN interface/);
  assert.match(writer, /port out of range/);
  assert.match(writer, /maximum 256 ports/);
  assert.match(writer, /uci commit infra-port-watch/);
  assert.match(writer, /\/etc\/init\.d\/infra-port-watch restart/);
});
