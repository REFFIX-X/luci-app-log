const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');

function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} must be a top-level function`);
  const next = source.indexOf('\nfunction ', start + 1);
  const body = source.slice(start, next === -1 ? source.length : next);
  return new Function(`${body}\nreturn ${name};`)();
}

test('GeoIP batches stay under the rpcd argument limit', () => {
  const geoBatchChunks = extract('geoBatchChunks');
  const ips = Array.from({length: 80}, (_, i) => `203.0.113.${i % 250}`);
  const chunks = geoBatchChunks(ips, 900);
  assert.ok(chunks.length > 1);
  assert.equal(chunks.flat().length, ips.length);
  chunks.forEach(chunk => {
    const bytes = '--batch'.length + chunk.reduce((sum, ip) => sum + 1 + ip.length, 0);
    assert.ok(bytes <= 900, `chunk is ${bytes} bytes`);
  });
  assert.deepEqual(geoBatchChunks([], 900), []);
});

test('positive GeoIP hits are remembered and misses are not kept for a week', () => {
  const readGeoMemory = extract('readGeoMemory');
  const writeGeoMemory = extract('writeGeoMemory');
  const now = Date.UTC(2026, 9, 31, 5, 0, 0);
  let store = writeGeoMemory({}, '203.0.113.8', {
    country_code: 'DE', country_name: 'Germany', asn_organization: 'Example'
  }, now, 2);
  store = writeGeoMemory(store, '198.51.100.9', {
    country_code: 'US', country_name: 'United States', asn_organization: 'Other'
  }, now + 1000, 2);
  store = writeGeoMemory(store, '192.0.2.10', {
    country_code: 'JP', country_name: 'Japan', asn_organization: 'Third'
  }, now + 2000, 2);
  assert.equal(store['203.0.113.8'], undefined);
  assert.equal(store['192.0.2.10'].country_code, 'JP');
  const loaded = readGeoMemory(JSON.stringify(store), now + 2000 + 6 * 86400000, 7 * 86400000);
  assert.equal(loaded['192.0.2.10'].country_name, 'Japan');
  const expired = readGeoMemory(JSON.stringify(store), now + 2000 + 8 * 86400000, 7 * 86400000);
  assert.deepEqual(expired, {});
  assert.deepEqual(readGeoMemory('{', now, 1000), {});
});

test('watch status stays fresh for a minute instead of reloading on every live tick', () => {
  const watchConfigIsFresh = extract('watchConfigIsFresh');
  assert.equal(watchConfigIsFresh(0, 1000, 60000), false);
  assert.equal(watchConfigIsFresh(1000, 50000, 60000), true);
  assert.equal(watchConfigIsFresh(1000, 61000, 60000), false);
  assert.match(source, /WATCH_CONFIG_TTL_MS = 60000/);
  const refresh = source.slice(source.indexOf('refreshEvents:'), source.indexOf('enrichAndRender:'));
  assert.match(refresh, /loadWatchConfig\(false\)/);
  assert.doesNotMatch(refresh, /loadWatchConfig\(true\)/);
});

test('an insight filter describes itself and settings are grouped by job', () => {
  const insightFilterText = extract('insightFilterText');
  assert.equal(insightFilterText('', null, null), '');
  assert.equal(insightFilterText('203.0.113.8', 22, null), '203.0.113.8 · port 22');
  assert.equal(insightFilterText('', null, {start: 1, end: 2}), 'time bar');
  assert.match(source, /summary', \{\}, _\('Settings'\)\)/);
  assert.doesNotMatch(source, /_\('More options'\)/);
  assert.match(source, /fw-settings-watch/);
  assert.match(source, /fw-settings-labels/);
  assert.match(source, /fw-settings-history/);
  assert.match(source, /fw-settings-files/);
  assert.match(source, /handleSaveApply: null/);
  assert.match(source, /Default deny/);
  assert.match(source, /Not on the watch list/);
  assert.match(source, /value: 'other'/);
  assert.doesNotMatch(source, /WAN watchlist/);
  assert.match(source, /fw-primary-toolbar[\s\S]{0,500}this\.presets/);
  assert.doesNotMatch(source, /_\('Clear insight filters'\)/);
});

test('the log type is one step smaller and an Other row can join the known list', () => {
  const appendWatchPort = extract('appendWatchPort');
  assert.deepEqual(appendWatchPort('22,80', 443), {ok: true, changed: true, ports: '22,80,443'});
  assert.deepEqual(appendWatchPort('22, 80', 22), {ok: true, changed: false, ports: '22,80'});
  assert.deepEqual(appendWatchPort('', 25125), {ok: true, changed: true, ports: '25125'});
  assert.equal(appendWatchPort('22', 0).ok, false);
  assert.equal(appendWatchPort('22', 65536).ok, false);
  const full = Array.from({length: 256}, (_, i) => i + 1).join(',');
  assert.deepEqual(appendWatchPort(full, 700), {ok: false, reason: 'full'});
  assert.equal(appendWatchPort(full, 22).changed, false);

  assert.match(source, /position: sticky/);
  assert.match(source, /\.fw-table thead th \{[\s\S]*background: #403A42 !important/);
  assert.match(source, /\.fw-shell \.fw-table \{ min-width: 960px; font-size: 13px !important; \}/);
  assert.match(source, /\.fw-shell \.fw-stat strong \{ font-size: 22px !important; \}/);
  assert.match(source, /\.fw-primary-toolbar input,\n      \.fw-shell \.fw-primary-toolbar select \{ min-height: 36px; font-size: 13px !important; \}/);
  assert.doesNotMatch(source, /font-size: 15px/);
  assert.doesNotMatch(source, /font-size: 28px/);
  assert.match(source, /Log this port at the full budget/);
  assert.match(source, /event\.kind === 'Other'/);
});

test('missing default ports are appended and GeoIP can be refreshed from settings', () => {
  const mergeMissingDefaultPorts = extract('mergeMissingDefaultPorts');
  const listed = source.match(/const DEFAULT_WATCH_PORTS = \[([^\]]+)\]/);
  assert.ok(listed, 'the page must carry the default watch ports');
  const defaults = listed[1].split(',').map(item => Number(item.trim()));
  const uci = fs.readFileSync(path.join(__dirname, '../root/etc/config/infra-port-watch'), 'utf8');
  const shipped = [...uci.matchAll(/list ports '(\d+)'/g)].map(match => Number(match[1]));
  assert.deepEqual(defaults, shipped);

  assert.deepEqual(mergeMissingDefaultPorts('25125,22', [22, 80, 443]), {
    ok: true, added: [80, 443], ports: '25125,22,80,443'
  });
  assert.deepEqual(mergeMissingDefaultPorts('22, 80', [22, 80]), {
    ok: true, added: [], ports: '22,80'
  });
  assert.equal(mergeMissingDefaultPorts('nope', [22]).ok, false);
  const full = Array.from({length: 256}, (_, i) => i + 1).join(',');
  assert.equal(mergeMissingDefaultPorts(full, [700]).reason, 'full');

  assert.match(source, /Add missing default ports/);
  assert.match(source, /Update GeoIP databases/);
  assert.match(source, /\/usr\/bin\/flint4-geoip-update/);
});
