const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');
const gitUsr = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'usr', 'bin');
const shell = process.platform === 'win32' ? path.join(gitUsr, 'sh.exe') : 'sh';
const cygpath = path.join(gitUsr, 'cygpath.exe');
const shellAvailable = process.platform !== 'win32' || fs.existsSync(shell) && fs.existsSync(cygpath);

test('GeoIP status reports missing, current, and stale database pairs', {skip: !shellAvailable}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-geoip-status-'));
  const db = path.join(root, 'db');
  const bin = path.join(root, 'bin');
  fs.mkdirSync(db);
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'mmdblookup'), '#!/bin/sh\nexit 0\n', {mode: 0o755});
  const helper = path.join(__dirname, '../root/usr/bin/flint4-geoip');
  const dbPath = process.platform === 'win32' ? execFileSync(cygpath, ['-u', db], {encoding: 'utf8'}).trim() : db;
  const binPath = process.platform === 'win32' ? execFileSync(cygpath, ['-u', bin], {encoding: 'utf8'}).trim() : bin;
  const helperPath = process.platform === 'win32' ? execFileSync(cygpath, ['-u', helper], {encoding: 'utf8'}).trim() : helper;
  const runStatus = () => JSON.parse(execFileSync(shell, [helperPath, '--status'], {
    env: {...process.env, GEOIP_DB_DIR: dbPath, PATH: `${binPath}:/usr/bin:/bin`},
    encoding: 'utf8'
  }));

  try {
    assert.deepEqual(runStatus(), {available: false, age_days: null, stale: false});
    const country = path.join(db, 'GeoLite2-Country.mmdb');
    const asn = path.join(db, 'GeoLite2-ASN.mmdb');
    fs.writeFileSync(country, 'country');
    fs.writeFileSync(asn, 'asn');
    assert.equal(runStatus().available, true);
    const old = new Date(Date.now() - 46 * 86400000);
    fs.utimesSync(country, old, old);
    fs.utimesSync(asn, old, old);
    const status = runStatus();
    assert.equal(status.stale, true);
    assert.ok(status.age_days >= 45);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});
