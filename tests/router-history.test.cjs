const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const helper = path.join(__dirname, '../root/usr/sbin/log-viewer-history');
const initScript = path.join(__dirname, '../root/etc/init.d/log-viewer-history');

test('router history keeps firewall lines in a tmpfs ring and drops other syslog', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-history-'));
  const bin = path.join(root, 'bin');
  const ring = path.join(root, 'events.ring');
  fs.mkdirSync(bin);
  const log = [
    'Oct 31 06:00:00 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN',
    'Oct 31 06:00:01 2026 router dnsmasq[1]: query[A] example.test from 192.168.1.2',
    'Oct 31 06:00:04 2026 router kernel: INFRA_PORT_OTHER: IN=wan SRC=203.0.113.11 DST=192.0.2.1 PROTO=TCP DPT=25125 SYN',
    'Oct 31 06:00:02 2026 router kernel: DROP: IN=wan SRC=198.51.100.9 DST=192.0.2.1 PROTO=TCP DPT=443 SYN',
    'Oct 31 06:00:03 2026 router kernel: INFRA_PORT_HIT: IN=wan SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP DPT=22 SYN'
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'logread'), `#!/bin/sh\ncat <<'EOF'\n${log}EOF\n`, {mode: 0o755});

  const env = {
    ...process.env,
    PATH: `${bin}:/usr/bin:/bin`,
    LOG_VIEWER_RING: ring,
    LOG_VIEWER_RING_CAP: '4'
  };
  try {
    const status = JSON.parse(execFileSync(helper, ['update'], {env, encoding: 'utf8'}));
    assert.equal(status.storage, 'tmpfs');
    assert.equal(status.cap, 4);
    assert.equal(status.count, 4);
    const lines = fs.readFileSync(ring, 'utf8').trim().split('\n');
    assert.equal(lines.some(line => line.includes('dnsmasq')), false);
    assert.equal(lines.filter(line => line.includes('INFRA_PORT_HIT')).length, 2);
    assert.equal(lines.some(line => line.includes('INFRA_PORT_OTHER:')), true);
    assert.equal(lines.some(line => line.includes('DROP:')), true);

    const cleared = JSON.parse(execFileSync(helper, ['clear'], {env, encoding: 'utf8'}));
    assert.equal(cleared.count, 0);
    assert.equal(fs.existsSync(ring), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('history collector is started with the package and survives without the page open', () => {
  const init = fs.readFileSync(initScript, 'utf8');
  const makefile = fs.readFileSync(path.join(__dirname, '../Makefile'), 'utf8');
  assert.match(init, /log-viewer-history follow/);
  assert.match(makefile, /log-viewer-history enable/);
  assert.match(makefile, /log-viewer-history start/);
});
