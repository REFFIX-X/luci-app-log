const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../htdocs/luci-static/resources/view/log-viewer/firewall.js'), 'utf8');
const match = source.match(/function csvCell\(value\) \{[\s\S]*?\n\}/);
assert.ok(match, 'firewall view must define the shared CSV cell encoder');
const csvCell = new Function(`${match[0]}\nreturn csvCell;`)();

test('CSV cells quote delimiters and neutralize spreadsheet formulas', () => {
  assert.equal(csvCell('router, east'), '"router, east"');
  assert.equal(csvCell('say "hello"'), '"say ""hello"""');
  for (const value of ['=1+1', '+SUM(A1:A2)', '-1', '@SUM(A1)', '  =cmd'])
    assert.equal(csvCell(value), `"'${value}"`);
  assert.equal(csvCell(null), '""');
});
