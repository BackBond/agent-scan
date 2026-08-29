'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { ROOT, fixturePaths, tempDirectory } = require('./helpers.js');
const { verifyPublicScanRecord } = require('../lib/record.js');

const ACTION = path.join(ROOT, 'action', 'index.js');

function git(directory, args) {
  const result = spawnSync('git', args, { cwd: directory, encoding: 'utf8', shell: false });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function createCommittedFixture(t, fixtureName = 'hardened') {
  const workspace = tempDirectory(t);
  const fixture = fixturePaths(fixtureName);
  for (const [source, destination] of [
    [fixture.tools, 'tool-schema.json'],
    [fixture.permissions, 'permissions.json'],
    [fixture.trace, 'trace.json'],
  ]) fs.copyFileSync(source, path.join(workspace, destination));
  git(workspace, ['init']);
  git(workspace, ['config', 'user.email', 'action-test@backbond.invalid']);
  git(workspace, ['config', 'user.name', 'BackBond Action Test']);
  git(workspace, ['add', '.']);
  git(workspace, ['commit', '-m', 'fixture']);
  return { workspace, commit: git(workspace, ['rev-parse', 'HEAD']) };
}

function actionEnvironment(workspace, commit, output, summary) {
  return {
    ...process.env,
    GITHUB_WORKSPACE: workspace,
    GITHUB_SHA: commit,
    GITHUB_OUTPUT: output,
    GITHUB_STEP_SUMMARY: summary,
    'INPUT_TOOL-SCHEMA': 'tool-schema.json',
    INPUT_PERMISSIONS: 'permissions.json',
    INPUT_TRACE: 'trace.json',
    'INPUT_RECORD-PATH': 'artifacts/scan-record.json',
    'INPUT_FAIL-ON': 'high',
    'INPUT_FAIL-ON-PROMPT': 'none',
  };
}

test('official Action verifies a clean checkout and emits a redacted v2 record and job summary', (t) => {
  const { workspace, commit } = createCommittedFixture(t);
  const output = path.join(workspace, 'github-output.txt');
  const summary = path.join(workspace, 'github-summary.md');
  const run = spawnSync(process.execPath, [ACTION], {
    cwd: workspace,
    env: actionEnvironment(workspace, commit, output, summary),
    encoding: 'utf8',
  });
  assert.equal(run.status, 0, run.stderr);

  const recordPath = path.join(workspace, 'artifacts', 'scan-record.json');
  const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
  assert.equal(record.protocol, 'backbond-scan-record/v2');
  assert.equal(record.source.git_commit, commit);
  assert.equal(record.result.interpretation, 'complete_no_findings');
  assert.equal(verifyPublicScanRecord(record), true);
  assert.match(record.assurance.statement, /supplied by the caller and was not verified/);

  const jobSummary = fs.readFileSync(summary, 'utf8');
  assert.equal(jobSummary.includes(`verified against \`${commit}\``), true);
  assert.match(jobSummary, /portable record remains self-run and unverified/);
  assert.doesNotMatch(jobSummary, /shell_exec|vault_read|tool-schema\.json/);
  const outputs = fs.readFileSync(output, 'utf8');
  assert.match(outputs, /record-path=/);
  assert.match(outputs, new RegExp(`record-sha256=${record.integrity.sha256}`));
  assert.match(outputs, new RegExp(`commit=${commit}`));
});

test('official Action refuses an input changed after the verified commit', (t) => {
  const { workspace, commit } = createCommittedFixture(t);
  fs.appendFileSync(path.join(workspace, 'tool-schema.json'), '\n');
  const run = spawnSync(process.execPath, [ACTION], {
    cwd: workspace,
    env: actionEnvironment(workspace, commit, path.join(workspace, 'output.txt'), path.join(workspace, 'summary.md')),
    encoding: 'utf8',
  });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /differs from the verified commit/);
  assert.equal(fs.existsSync(path.join(workspace, 'artifacts', 'scan-record.json')), false);
});

test('official Action preserves a finding exit while still writing the redacted evidence', (t) => {
  const { workspace, commit } = createCommittedFixture(t, 'vulnerable');
  const output = path.join(workspace, 'github-output.txt');
  const summary = path.join(workspace, 'github-summary.md');
  const run = spawnSync(process.execPath, [ACTION], {
    cwd: workspace,
    env: actionEnvironment(workspace, commit, output, summary),
    encoding: 'utf8',
  });
  assert.equal(run.status, 1, run.stderr);
  const record = JSON.parse(fs.readFileSync(path.join(workspace, 'artifacts', 'scan-record.json'), 'utf8'));
  assert.equal(record.result.interpretation, 'findings');
  assert.match(fs.readFileSync(summary, 'utf8'), /BB001/);
  assert.match(fs.readFileSync(output, 'utf8'), /record-sha256=/);
});

test('official Action never treats an existing record as output from the current run', (t) => {
  const { workspace, commit } = createCommittedFixture(t);
  const recordDirectory = path.join(workspace, 'artifacts');
  fs.mkdirSync(recordDirectory);
  fs.writeFileSync(path.join(recordDirectory, 'scan-record.json'), '{"stale":true}\n');
  const run = spawnSync(process.execPath, [ACTION], {
    cwd: workspace,
    env: actionEnvironment(workspace, commit, path.join(workspace, 'output.txt'), path.join(workspace, 'summary.md')),
    encoding: 'utf8',
  });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /already exists and will not be overwritten/);
  assert.equal(fs.existsSync(path.join(workspace, 'summary.md')), false);
  assert.equal(fs.readFileSync(path.join(recordDirectory, 'scan-record.json'), 'utf8'), '{"stale":true}\n');
});
