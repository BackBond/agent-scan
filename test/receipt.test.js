'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { collectEvidence } = require('../lib/evidence.js');
const { createScanReceipt, verifyScanReceipt } = require('../lib/receipt.js');
const { scanEvidence } = require('../lib/scanner.js');
const { fixturePaths, tempDirectory } = require('./helpers.js');

const NOW = new Date('2026-08-29T12:00:00.000Z');

function vulnerableScan() {
  const f = fixturePaths('vulnerable');
  return scanEvidence(collectEvidence({ now: NOW, toolSchemaPath: f.tools, permissionsPath: f.permissions, tracePath: f.trace }), { now: NOW });
}

test('receipt records input hashes, ruleset, finding IDs, and no raw bodies', () => {
  const receipt = createScanReceipt(vulnerableScan());
  assert.equal(verifyScanReceipt(receipt), true);
  assert.deepEqual(receipt.result.findings.map(item => item.id), ['BB001', 'BB002', 'BB003', 'BB004', 'BB005', 'BB006', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012']);
  assert.match(receipt.ruleset.sha256, /^[a-f0-9]{64}$/);
  assert.equal(receipt.inputs.every(item => /^[a-f0-9]{64}$/.test(item.sha256)), true);
  assert.doesNotMatch(JSON.stringify(receipt), /Run an operating-system command/);
});

test('receipt verification detects finding and input tampering', () => {
  const receipt = createScanReceipt(vulnerableScan());
  receipt.result.findings[0].severity = 'low';
  assert.equal(verifyScanReceipt(receipt), false);
});

test('optional Ed25519 receipt signatures verify and detect signature tampering', (t) => {
  const directory = tempDirectory(t);
  const { privateKey } = generateKeyPairSync('ed25519');
  const keyPath = path.join(directory, 'receipt-key.pem');
  fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const receipt = createScanReceipt(vulnerableScan(), { signingKeyPath: keyPath });
  assert.equal(receipt.integrity.signature.algorithm, 'Ed25519');
  assert.equal(verifyScanReceipt(receipt), true);
  const downgraded = structuredClone(receipt);
  downgraded.integrity.signature = null;
  assert.equal(verifyScanReceipt(downgraded), false);
  receipt.integrity.signature.value_base64 = Buffer.alloc(64).toString('base64');
  assert.equal(verifyScanReceipt(receipt), false);
});
