const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const ROOT = path.resolve(__dirname, '..');

test('false-positive intake exposes the 72-hour response path and rule identity', () => {
  const form = fs.readFileSync(path.join(ROOT, '.github/ISSUE_TEMPLATE/scan-feedback.yml'), 'utf8');
  const process = fs.readFileSync(path.join(ROOT, 'docs/FALSE-POSITIVE-SLA.md'), 'utf8');

  assert.match(form, /first response within 72 hours/i);
  assert.match(form, /id: rule_code/);
  assert.match(form, /id: report_received_at/);
  assert.match(process, /Two reviewers independently record the expected decision/);
  assert.match(process, /fixtures\/corpus-regression\//);
  assert.match(process, /docs\/RULES\.md/);
  assert.match(process, /homoglyph tool-name shadowing: undispositioned/);
});
