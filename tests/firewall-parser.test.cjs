const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');
const servicesStart = source.indexOf('const SERVICES = {');
const servicesEnd = source.indexOf('\n};', servicesStart) + 3;
const fieldsStart = source.indexOf('function parseFields(');
const lineStart = source.indexOf('function parseLine(', fieldsStart);
const lineEnd = source.indexOf('\nconst BUNDLED_FLAGS', lineStart);
assert.ok(servicesStart >= 0 && servicesEnd > servicesStart && fieldsStart >= 0 && lineStart > fieldsStart && lineEnd > lineStart);

const parser = new Function(
  source.slice(servicesStart, servicesEnd) + '\n' +
  source.slice(fieldsStart, lineEnd) + '\nreturn parseLine;'
)();

test('classifies explicit blocked events and retains original packet data', () => {
  const event = parser('Oct 12 12:00:00 2026 router kernel: FIREWALL_BLOCK: IN=wan SRC=198.51.100.25 DST=192.0.2.1 PROTO=TCP SPT=41234 DPT=22 TTL=51 SYN', 1);
  assert.equal(event.kind, 'Blocked');
  assert.equal(event.source, '198.51.100.25');
  assert.equal(event.dport, 22);
  assert.equal(event.rawLine.includes('FIREWALL_BLOCK'), true);
});

test('classifies infrastructure WAN watchlist hits as blocked', () => {
  const event = parser('Oct 12 12:00:01 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=UDP DPT=443', 2);
  assert.equal(event.kind, 'Blocked');
  assert.equal(event.prefix, 'INFRA_PORT_HIT');
});

test('classifies only explicit allow markers as allowed', () => {
  const event = parser('Oct 12 12:00:02 2026 router kernel: FIREWALL_ALLOW: IN=wan SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP SPT=4567 DPT=443', 3);
  assert.equal(event.kind, 'Allowed');
  assert.equal(parser('Oct 12 12:00:03 2026 router kernel: IN=wan SRC=203.0.113.9 DST=192.0.2.1 PROTO=TCP DPT=443', 4), null);
});

test('parses quoted fields without changing verdict semantics', () => {
  const event = parser('Oct 12 12:00:04 2026 router kernel: DROP: IN=wan SRC=198.51.100.3 DST=192.0.2.1 PROTO=TCP DPT=443 INFO="quoted value"', 5);
  assert.equal(event.kind, 'Blocked');
  assert.equal(event.source, '198.51.100.3');
});
