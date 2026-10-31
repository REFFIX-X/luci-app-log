const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const acl = JSON.parse(fs.readFileSync(path.join(__dirname, '../root/usr/share/rpcd/acl.d/luci-app-log-viewer.json'), 'utf8'));
const grant = acl['luci-app-log-viewer'];
const view = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');

test('WAN watch saves are granted on the helper path, not a truncated argument string', () => {
  const writePaths = Object.keys(grant.write.file);
  assert.ok(writePaths.includes('/usr/sbin/infra-port-watch-config'));
  assert.equal(writePaths.includes('/usr/sbin/infra-port-watch-config set'), false);
  assert.deepEqual(grant.write.ubus.file, ['exec']);
});

test('log reading is allowed through ubus and the OpenWrt 25.12 logread path', () => {
  assert.deepEqual(grant.read.ubus.log, ['read']);
  assert.ok(grant.read.ubus.file.includes('exec'));
  assert.ok(grant.read.ubus.file.includes('read'));
  assert.ok(Object.keys(grant.read.file).includes('/usr/libexec/logread-ubox*'));
  assert.match(view, /object: 'log'/);
  assert.match(view, /\/usr\/libexec\/logread-ubox/);
});

test('GeoIP database refresh is granted as its own command', () => {
  assert.ok(Object.keys(grant.write.file).includes('/usr/bin/flint4-geoip-update'));
  assert.deepEqual(grant.write.file['/usr/bin/flint4-geoip-update'], ['exec']);
});
