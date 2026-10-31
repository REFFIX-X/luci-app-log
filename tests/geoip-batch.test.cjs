const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const helper = path.join(__dirname, '../root/usr/bin/flint4-geoip');

test('one GeoIP invocation looks up every address and reads each database once per address', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reffix-geoip-batch-'));
  const db = path.join(root, 'db');
  const bin = path.join(root, 'bin');
  fs.mkdirSync(db);
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(db, 'GeoLite2-Country.mmdb'), 'country');
  fs.writeFileSync(path.join(db, 'GeoLite2-ASN.mmdb'), 'asn');
  const counter = path.join(root, 'calls');
  fs.writeFileSync(counter, '0\n');
  fs.writeFileSync(path.join(bin, 'mmdblookup'), `#!/bin/sh
count=$(cat ${JSON.stringify(counter)})
echo $((count + 1)) > ${JSON.stringify(counter)}
if printf '%s\\n' "$*" | grep -q autonomous_system_organization; then
  echo '  "Example ASN" <utf8_string>'
  exit 0
fi
cat <<'EOF'
  "iso_code":
    "DE" <utf8_string>
  "names":
    {
      "en":
        "Germany" <utf8_string>
    }
EOF
`, {mode: 0o755});

  try {
    const raw = execFileSync(helper, ['--batch', '203.0.113.10', '198.51.100.8', 'not-an-ip'], {
      env: {...process.env, GEOIP_DB_DIR: db, PATH: `${bin}:/usr/bin:/bin`},
      encoding: 'utf8'
    });
    const data = JSON.parse(raw);
    assert.deepEqual(data['203.0.113.10'], {
      country_code: 'DE',
      country_name: 'Germany',
      asn_organization: 'Example ASN'
    });
    assert.deepEqual(data['198.51.100.8'].country_code, 'DE');
    assert.deepEqual(data['not-an-ip'], {error: 'invalid IP'});
    const calls = Number(fs.readFileSync(counter, 'utf8'));
    assert.equal(calls, 4, 'two valid addresses, one country read and one ASN read each');
  }
  finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});
