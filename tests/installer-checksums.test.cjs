const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');
const gitUsr = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'usr', 'bin');
const shell = process.platform === 'win32' ? path.join(gitUsr, 'sh.exe') : 'sh';
const cygpath = path.join(gitUsr, 'cygpath.exe');
const shellAvailable = process.platform !== 'win32' || fs.existsSync(shell) && fs.existsSync(cygpath);

const installer = fs.readFileSync(path.join(__dirname, '../install-online.sh'), 'utf8');
const match = installer.match(/^verify_checksums\(\) \{[\s\S]*?^\}/m);
assert.ok(match, 'installer must expose its checksum verification function');

test('installer checksum verifier accepts valid APKs and rejects mismatches or missing sums', {skip: !shellAvailable}, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-checksums-'));
  try {
    const app = 'reffix-luci-app-log-viewer-openwrt-25.12.apk';
    const lib = 'reffix-libmaxminddb-openwrt-25.12.apk';
    const appData = Buffer.from('app package fixture');
    const libData = Buffer.from('library package fixture');
    fs.writeFileSync(path.join(dir, app), appData);
    fs.writeFileSync(path.join(dir, lib), libData);
    const sums = [appData, libData].map((data, i) =>
      `${crypto.createHash('sha256').update(data).digest('hex')}  ${i === 0 ? app : lib}`
    ).join('\n') + '\n';
    const sumsPath = path.join(dir, 'SHA256SUMS.txt');
    fs.writeFileSync(sumsPath, sums);

    const shellDir = process.platform === 'win32' ? execFileSync(cygpath, ['-u', dir], {encoding: 'utf8'}).trim() : dir;
    const runVerifier = () => execFileSync(shell, ['-c', `FAMILY=25.12\nEXT=apk\nTMP="${shellDir}"\n${match[0]}\nverify_checksums`], {
      env: {...process.env, PATH: `${gitUsr}${path.delimiter}${process.env.PATH}`},
      stdio: 'pipe'
    });

    assert.doesNotThrow(runVerifier, 'valid package pair should verify');
    fs.writeFileSync(sumsPath, sums.split('\n')[0] + '\n');
    assert.throws(runVerifier, 'checksum list missing one APK must fail closed');
    fs.writeFileSync(sumsPath, sums);
    fs.writeFileSync(path.join(dir, app), 'corrupted package');
    assert.throws(runVerifier, 'mismatched package must fail verification');
    fs.writeFileSync(sumsPath, '');
    assert.throws(runVerifier, 'empty checksum file must fail closed');
    fs.rmSync(sumsPath);
    assert.throws(runVerifier, 'missing checksum file must fail closed');
  }
  finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});
