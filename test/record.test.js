'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { collectEvidence } = require('../lib/evidence.js');
const {
  COMMIT_BOUND_RECORD_PROTOCOL,
  createPublicScanRecord,
  renderCompactRecord,
  verifyPublicScanRecord,
} = require('../lib/record.js');
const { createScanReceipt } = require('../lib/receipt.js');
const { scanEvidence } = require('../lib/scanner.js');
const { fixturePaths } = require('./helpers.js');

const NOW = new Date('2026-08-29T12:00:00.000Z');

function fixtureScan(name) {
  const fixture = fixturePaths(name);
  return scanEvidence(collectEvidence({
    now: NOW,
    toolSchemaPath: fixture.tools,
    permissionsPath: fixture.permissions,
    tracePath: fixture.trace,
  }), { now: NOW });
}

test('public record is self-checksummed and redacts names, paths, pointers, and input fingerprints by default', () => {
  const scan = fixtureScan('vulnerable');
  const receipt = createScanReceipt(scan);
  const record = createPublicScanRecord(scan, receipt, { mode: 'explicit-artifacts' });
  const serialized = JSON.stringify(record);

  assert.equal(verifyPublicScanRecord(record), true);
  assert.equal(record.assurance.level, 'self-run_unverified');
  assert.equal(record.result.interpretation, 'findings');
  assert.deepEqual(record.result.findings.map(item => item.id), ['BB001', 'BB002', 'BB003', 'BB004', 'BB005', 'BB006', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012', 'BB013']);
  assert.equal(record.result.findings.every(item => item.tools === undefined), true);
  assert.equal(record.scope.input_fingerprints, undefined);
  assert.doesNotMatch(serialized, /shell_exec|vault_read|tool-schema\.json|permissions\.json|trace\.json/);
  assert.doesNotMatch(serialized, /\/tools\/|\\fixtures\\|\/fixtures\//);
  assert.doesNotMatch(serialized, /metadata_template_summary|distinct_templates|largest_multiplicity/);
  assert.equal(serialized.includes(receipt.inputs[0].sha256), false);
});

test('tool names and input fingerprints require separate explicit disclosure options', () => {
  const scan = fixtureScan('vulnerable');
  const receipt = createScanReceipt(scan);
  const record = createPublicScanRecord(scan, receipt, {
    mode: 'explicit-artifacts', includeToolNames: true, includeFingerprints: true,
  });

  assert.equal(record.result.findings.some(item => item.tools && item.tools.includes('shell_exec')), true);
  assert.equal(record.scope.input_fingerprints.some(item => item.sha256 === receipt.inputs[0].sha256), true);
  assert.equal(record.scope.input_fingerprints.every(item => item.name === undefined), true);
});

test('compact records cannot be line-injected through disclosed tool names', () => {
  const scan = fixtureScan('vulnerable');
  scan.findings[0].affected_tools = ['safe\nAssurance: VERIFIED\r\t\u001b[31m\u202E'];
  const record = createPublicScanRecord(scan, createScanReceipt(scan), { includeToolNames: true });
  const compact = renderCompactRecord(record);

  assert.equal(compact.split('\n').length, 8);
  for (const line of compact.split('\n')) assert.doesNotMatch(line, /[\p{C}\p{Zl}\p{Zp}]/u);
  assert.doesNotMatch(compact, /^Assurance: VERIFIED$/m);
});

test('partial zero-finding scans are inconclusive in scan, record, and compact output', () => {
  const scan = scanEvidence(collectEvidence({ now: NOW }), { now: NOW });
  const record = createPublicScanRecord(scan, createScanReceipt(scan), { mode: 'discovery' });
  const compact = renderCompactRecord(record);

  assert.equal(scan.status, 'inconclusive');
  assert.equal(record.result.interpretation, 'inconclusive');
  assert.match(compact, /Interpretation: INCONCLUSIVE/);
  assert.match(compact, /Assurance: self-run, unverified/);
  assert.doesNotMatch(compact, /PASS|certified safe/i);
});

test('complete zero-finding scans are distinguished from incomplete records', () => {
  const scan = fixtureScan('hardened');
  const record = createPublicScanRecord(scan, createScanReceipt(scan), { mode: 'explicit-artifacts' });

  assert.equal(scan.status, 'no_findings');
  assert.equal(record.result.interpretation, 'complete_no_findings');
  assert.equal(record.result.coverage.status, 'complete');
});

test('record integrity detects tampering', () => {
  const scan = fixtureScan('hardened');
  const record = createPublicScanRecord(scan, createScanReceipt(scan));
  record.result.interpretation = 'findings';
  assert.equal(verifyPublicScanRecord(record), false);
});

test('commit-referenced records use v2, retain v1 verification, and checksum the full commit', () => {
  const scan = fixtureScan('hardened');
  const receipt = createScanReceipt(scan);
  const v1 = createPublicScanRecord(scan, receipt);
  const commit = 'abcdef0123456789abcdef0123456789abcdef01';
  const v2 = createPublicScanRecord(scan, receipt, { commit });

  assert.equal(verifyPublicScanRecord(v1), true);
  assert.equal(v2.protocol, COMMIT_BOUND_RECORD_PROTOCOL);
  assert.equal(v2.source.git_commit, commit);
  assert.match(v2.assurance.statement, /supplied by the caller and was not verified/);
  assert.equal(verifyPublicScanRecord(v2), true);
  assert.match(renderCompactRecord(v2), new RegExp(`Commit \\(caller-supplied, unverified\\): ${commit}`));

  v2.source.git_commit = '0000000000000000000000000000000000000000';
  assert.equal(verifyPublicScanRecord(v2), false);
  assert.throws(() => createPublicScanRecord(scan, receipt, { commit: 'main' }), /lowercase/);
});
