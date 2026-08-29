'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { CLI, ROOT, claimSubmission, fixturePaths, tempDirectory, writeJson } = require('./helpers.js');

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
  assert.deepEqual(output.findings.map(item => item.id), ['BB001', 'BB002', 'BB003', 'BB004', 'BB005', 'BB006', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012']);
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

test('redacted public record is write-once and omits tool names and input fingerprints by default', (t) => {
  const directory = tempDirectory(t);
  const recordPath = path.join(directory, 'scan-record.json');
  const run = spawnSync(process.execPath, scanArgs(fixturePaths('vulnerable'), [
    '--record-public', recordPath, '--fail-on', 'none',
  ]), { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
  const serialized = JSON.stringify(record);
  assert.equal(record.assurance.level, 'self-run_unverified');
  assert.equal(record.scope.input_fingerprints, undefined);
  assert.doesNotMatch(serialized, /shell_exec|tool-schema\.json|permissions\.json|trace\.json/);

  const duplicate = spawnSync(process.execPath, scanArgs(fixturePaths('hardened'), [
    '--record-public', recordPath,
  ]), { encoding: 'utf8' });
  assert.equal(duplicate.status, 2);
  assert.match(duplicate.stderr, /exist/i);
});

test('discovery public record excludes home paths, config names, server commands, and env keys', (t) => {
  const directory = tempDirectory(t);
  const project = path.join(directory, 'PRIVATE_USER_HOME_MARKER', 'project');
  const cursor = path.join(project, '.cursor');
  fs.mkdirSync(cursor, { recursive: true });
  writeJson(cursor, 'mcp.json', {
    mcpServers: {
      confidential_server_name: {
        command: 'PRIVATE_SERVER_COMMAND_MARKER',
        env: { PRIVATE_ENV_KEY_MARKER: 'PRIVATE_ENV_VALUE_MARKER' },
      },
    },
  });
  const recordPath = path.join(directory, 'public-record.json');
  const run = spawnSync(process.execPath, [CLI, 'scan', '--record-public', recordPath, '--fail-on', 'none', '--json'], {
    encoding: 'utf8', cwd: project, env: { ...process.env, USERPROFILE: path.join(directory, 'PRIVATE_USER_HOME_MARKER'), APPDATA: path.join(directory, 'appdata') },
  });
  assert.equal(run.status, 0, run.stderr);
  const serialized = fs.readFileSync(recordPath, 'utf8');
  assert.doesNotMatch(serialized, /PRIVATE_USER_HOME_MARKER|PRIVATE_SERVER_COMMAND_MARKER|PRIVATE_ENV_KEY_MARKER|PRIVATE_ENV_VALUE_MARKER|confidential_server_name|mcp\.json|\.cursor/);
});

test('--require-coverage exits 3 for inconclusive scans and 0 for complete scans', (t) => {
  const directory = tempDirectory(t);
  const incomplete = spawnSync(process.execPath, [CLI, 'scan', '--json', '--require-coverage'], {
    encoding: 'utf8', cwd: directory, env: { ...process.env, USERPROFILE: directory, APPDATA: directory },
  });
  assert.equal(incomplete.status, 3, incomplete.stderr);
  assert.equal(JSON.parse(incomplete.stdout).status, 'inconclusive');

  const incompleteHuman = spawnSync(process.execPath, [CLI, 'scan', '--require-coverage'], {
    encoding: 'utf8', cwd: directory, env: { ...process.env, USERPROFILE: directory, APPDATA: directory },
  });
  assert.equal(incompleteHuman.status, 3, incompleteHuman.stderr);
  assert.match(incompleteHuman.stdout, /^INCONCLUSIVE — 0 findings/);

  const complete = spawnSync(process.execPath, scanArgs(fixturePaths('hardened'), ['--require-coverage']), { encoding: 'utf8' });
  assert.equal(complete.status, 0, complete.stderr);

  const findingAndPartial = spawnSync(process.execPath, [CLI, 'scan', '--stdin', '--require-coverage'], {
    input: fs.readFileSync(path.join(ROOT, 'fixtures', 'wild', 'mcp-prompt-poison.json'), 'utf8'), encoding: 'utf8',
  });
  assert.equal(findingAndPartial.status, 1, findingAndPartial.stderr);

  const missingRecord = spawnSync(process.execPath, [CLI, 'scan', '--record-include-tool-names'], { encoding: 'utf8' });
  assert.equal(missingRecord.status, 2);
  assert.match(missingRecord.stderr, /require --record-public/);
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
  const emptyOutput = JSON.parse(empty.stdout);
  assert.equal(emptyOutput.discovery.protocol, 'backbond-discovery-plan/v1');
  assert.equal(emptyOutput.status, 'inconclusive');
});
