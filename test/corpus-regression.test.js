'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { collectEvidence } = require('../lib/evidence.js');
const { scanEvidence } = require('../lib/scanner.js');
const { createVetResult } = require('../lib/vet-tools.js');

const ROOT = path.join(__dirname, '..');
const FIXTURE_ROOT = path.join(ROOT, 'fixtures', 'corpus-regression');
const INDEX = JSON.parse(fs.readFileSync(path.join(FIXTURE_ROOT, 'cases.json'), 'utf8'));
const NOW = new Date('2026-08-31T12:00:00.000Z');

test('corpus boundary fixtures stay explicit about provenance', () => {
  assert.equal(INDEX.protocol, 'backbond-corpus-regression/v1');
  assert.equal(INDEX.ruleset, 'backbond-local-rules/2.0.1');
  assert.equal(INDEX.source.raw_bundle_available, true);
  assert.equal(INDEX.source.status, 'synthetic-and-redacted-corpus-derived-boundaries');
  assert.match(INDEX.source.csv_sha256, /^[0-9a-f]{64}$/);
  assert.match(INDEX.source.archive_sha256, /^[0-9a-f]{64}$/);
  assert.equal(INDEX.source.baseline_replay_mismatches, 0);
  assert.match(INDEX.source.bb001_delta_sha256, /^[0-9a-f]{64}$/);
  assert.equal(INDEX.source.bb001_delta_rows, 191);
  assert.equal(INDEX.cases.length, 18);
});

for (const fixture of INDEX.cases) {
  test(`corpus boundary: ${fixture.file} => ${fixture.expected_decision}`, () => {
    const target = path.join(FIXTURE_ROOT, fixture.file);
    const raw = fs.readFileSync(target);
    const evidence = collectEvidence({ documents: [{
      kind: 'tool_schema',
      name: fixture.file,
      document: JSON.parse(raw.toString('utf8')),
      raw,
    }] });
    const result = createVetResult(scanEvidence(evidence, { now: NOW }), evidence);
    assert.equal(result.decision, fixture.expected_decision);
    const findingIds = result.findings.map(item => item.id).sort();
    const gapCodes = result.coverage.gaps.map(item => item.code).sort();
    assert.deepEqual(findingIds, [...(fixture.finding_ids || [])].sort(), `${fixture.file} finding set changed`);
    assert.deepEqual(gapCodes, [...(fixture.gap_codes || [])].sort(), `${fixture.file} coverage-gap set changed`);
  });
}
