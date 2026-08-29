'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { CLI, claimSubmission, fixturePaths, tempDirectory, writeJson } = require('./helpers.js');

function scanArgs(fixture, extra = []) {
  return [CLI, 'scan', '--tool-schema', fixture.tools, '--permissions', fixture.permissions, '--trace', fixture.trace, '--json', ...extra];
}

test('start describes a local scanner with no analyzer or network dependency', () => {
  const run = spawnSync(process.execPath, [CLI], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.equal(output.protocol, 'backbond-agent-scan/v1');
  assert.equal(output.mode, 'local_deterministic');
  assert.match(output.guarantees.join(' '), /no private analyzer/i);
  assert.match(output.guarantees.join(' '), /no network request/i);
});

test('vulnerable fixture exits 1 with all expected finding IDs', () => {
  const run = spawnSync(process.execPath, scanArgs(fixturePaths('vulnerable')), { encoding: 'utf8' });
  assert.equal(run.status, 1, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.deepEqual(output.findings.map(item => item.id), ['BB001', 'BB002', 'BB003', 'BB004', 'BB005', 'BB006', 'BB007', 'BB008']);
  assert.equal(output.coverage.status, 'complete');
});

test('hardened fixture exits 0 with complete coverage and no findings', () => {
  const run = spawnSync(process.execPath, scanArgs(fixturePaths('hardened')), { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.deepEqual(output.findings, []);
  assert.equal(output.coverage.status, 'complete');
});

test('--fail-on supports CI thresholds and none disables finding failure', () => {
  const vulnerable = fixturePaths('vulnerable');
  const disabled = spawnSync(process.execPath, scanArgs(vulnerable, ['--fail-on', 'none']), { encoding: 'utf8' });
  assert.equal(disabled.status, 0, disabled.stderr);
  const critical = spawnSync(process.execPath, scanArgs(vulnerable, ['--fail-on', 'critical']), { encoding: 'utf8' });
  assert.equal(critical.status, 1, critical.stderr);
});

test('claims annotate contradictions but cannot change findings or severity', (t) => {
  const directory = tempDirectory(t);
  const claims = writeJson(directory, 'claims.json', claimSubmission({
    exec_code: false, browse_web: false, filesystem: false, human_approval: 'always',
    persistent_memory: false, tool_count: 0, audit_logging: true,
  }));
  const vulnerable = fixturePaths('vulnerable');
  const plain = spawnSync(process.execPath, scanArgs(vulnerable), { encoding: 'utf8' });
  const annotated = spawnSync(process.execPath, scanArgs(vulnerable, ['--input', claims]), { encoding: 'utf8' });
  const plainOutput = JSON.parse(plain.stdout);
  const annotatedOutput = JSON.parse(annotated.stdout);
  assert.deepEqual(
    annotatedOutput.findings.map(item => [item.id, item.severity]),
    plainOutput.findings.map(item => [item.id, item.severity]),
  );
  assert.equal(annotatedOutput.claim_contradictions.length > 0, true);
});

test('receipt can be written, verified, and tampering returns exit 1', (t) => {
  const directory = tempDirectory(t);
  const receiptPath = path.join(directory, 'scan-receipt.json');
  const scan = spawnSync(process.execPath, scanArgs(fixturePaths('hardened'), ['--receipt', receiptPath]), { encoding: 'utf8' });
  assert.equal(scan.status, 0, scan.stderr);
  assert.equal(fs.existsSync(receiptPath), true);
  const valid = spawnSync(process.execPath, [CLI, 'verify-receipt', '--input', receiptPath], { encoding: 'utf8' });
  assert.equal(valid.status, 0, valid.stderr);
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  receipt.result.status = 'findings';
  fs.writeFileSync(receiptPath, JSON.stringify(receipt));
  const invalid = spawnSync(process.execPath, [CLI, 'verify-receipt', '--input', receiptPath], { encoding: 'utf8' });
  assert.equal(invalid.status, 1, invalid.stderr);
});

test('raw trace bodies do not appear in JSON output or receipts', (t) => {
  const directory = tempDirectory(t);
  const marker = 'SUPER_SECRET_TRACE_ARGUMENT_9841';
  const trace = writeJson(directory, 'trace.json', {
    protocol: 'backbond-trace/v1',
    events: [{ type: 'tool_call', tool: 'status', input_trust: 'trusted', approval: 'enforced', audit: 'observable', arguments: { secret: marker } }],
  });
  const run = spawnSync(process.execPath, [CLI, 'scan', '--trace', trace, '--json'], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stdout, new RegExp(marker));
});

test('invalid inputs and removed analyzer/network options exit 2', (t) => {
  const directory = tempDirectory(t);
  const invalid = path.join(directory, 'invalid.json');
  fs.writeFileSync(invalid, '{');
  const malformed = spawnSync(process.execPath, [CLI, 'scan', '--tool-schema', invalid, '--json'], { encoding: 'utf8' });
  assert.equal(malformed.status, 2);
  const removed = spawnSync(process.execPath, [CLI, 'scan', '--tool-schema', fixturePaths('hardened').tools, '--analyzer', 'anything'], { encoding: 'utf8' });
  assert.equal(removed.status, 2);
  assert.match(removed.stderr, /unknown option/);
  const empty = spawnSync(process.execPath, [CLI, 'scan', '--json'], {
    encoding: 'utf8', cwd: directory, env: { ...process.env, USERPROFILE: directory, APPDATA: directory },
  });
  assert.equal(empty.status, 0, empty.stderr);
  assert.equal(JSON.parse(empty.stdout).discovery.protocol, 'backbond-discovery-plan/v1');
});
