const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const installer = fs.readFileSync(path.join(__dirname, '../install-online.sh'), 'utf8');
const match = installer.match(/^pkgver_of\(\) \{[\s\S]*?^install_downloaded_packages\(\) \{[\s\S]*?^\}/m);
assert.ok(match, 'installer must decide install, upgrade, replace, or keep');

test('a fresh router installs both packages', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Installing libmaxminddb 1\.0\.0-r1/);
    assert.match(result.out, /Installing luci-app-log-viewer 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/lib\.apk \/tmp\/app\.apk/);
    assert.equal(result.log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('an older install is upgraded in place', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '1.0.0-r1'],
      ['luci-app-log-viewer', '3.2.1-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Upgrading luci-app-log-viewer from 3\.2\.1-r1 to 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/app\.apk/);
    assert.equal(result.log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('the same release is replaced when the installer runs again', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '1.0.0-r1'],
      ['luci-app-log-viewer', '3.3.1-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Replacing installed luci-app-log-viewer 3\.3\.1-r1/);
    assert.match(result.log, /del luci-app-log-viewer/);
    assert.match(result.log, /del libmaxminddb/);
    const delApp = result.log.indexOf('del luci-app-log-viewer');
    const delLib = result.log.indexOf('del libmaxminddb');
    const add = result.log.indexOf('add --allow-untrusted --upgrade');
    assert.ok(delApp < delLib && delLib < add);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('an older helper is upgraded without touching a newer app', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '0.9.0-r1'],
      ['luci-app-log-viewer', '9.0.0-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /Upgrading libmaxminddb from 0\.9\.0-r1 to 1\.0\.0-r1/);
    assert.match(result.out, /newer than 3\.3\.1-r1/);
    assert.match(result.log, /add --allow-untrusted --upgrade \/tmp\/lib\.apk/);
    assert.equal(result.log.includes('/tmp/app.apk'), false);
    assert.equal(result.log.includes('del '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('a newer installed app is left in place', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-upgrade-'));
  try {
    const result = runPlan(root, [
      ['libmaxminddb', '1.0.0-r1'],
      ['luci-app-log-viewer', '9.0.0-r1']
    ], '1.0.0-r1', '3.3.1-r1');
    assert.match(result.out, /newer than 3\.3\.1-r1/);
    assert.equal(result.log.includes('del '), false);
    assert.equal(result.log.includes('add '), false);
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function runPlan(root, installed, libVer, appVer) {
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const log = path.join(root, 'apk.log');
  const db = path.join(root, 'installed');
  fs.writeFileSync(db, installed.map(row => row.join(' ')).join('\n') + (installed.length ? '\n' : ''));
  fs.writeFileSync(path.join(bin, 'apk'), `#!/bin/sh
printf '%s\\n' "$*" >> "${log}"
cmd="$1"; shift
case "$cmd" in
  list)
    name=""
    while [ $# -gt 0 ]; do
      case "$1" in -*) shift ;; *) name="$1"; shift ;; esac
    done
    if [ -n "$name" ] && grep -q "^$name " "${db}"; then
      ver=$(awk -v n="$name" '$1 == n { print $2; exit }' "${db}")
      echo "$name-$ver arch {world} [installed]"
    fi
    ;;
  version)
    a=""; b=""
    while [ $# -gt 0 ]; do
      case "$1" in -t) shift; a="$1"; b="$2"; break ;; *) shift ;; esac
    done
    first=$(printf '%s\\n%s\\n' "$a" "$b" | sort -V | head -n 1)
    if [ "$a" = "$b" ]; then echo '='; elif [ "$first" = "$a" ]; then echo '<'; else echo '>'; fi
    ;;
  add|del) ;;
esac
`, {mode: 0o755});
  fs.writeFileSync(path.join(bin, 'tar'), `#!/bin/sh
case "$2" in
  *lib.apk*) echo 'pkgver = ${libVer}' ;;
  *) echo 'pkgver = ${appVer}' ;;
esac
`, {mode: 0o755});
  const out = execFileSync('sh', ['-c', `set -eu
${match[0]}
install_downloaded_packages /tmp/lib.apk /tmp/app.apk`], {
    env: {...process.env, PATH: `${bin}:${process.env.PATH}`},
    encoding: 'utf8'
  });
  return {out, log: fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : ''};
}
