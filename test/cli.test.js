'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { sha256 } = require('../lib/canonical.js');
const { PROTOCOL, QUESTIONS } = require('../lib/assessment.js');
const { TEASER_PROTOCOL } = require('../lib/teaser.js');

const CLI = path.join(__dirname, '..', 'bin', 'agent-scan.js');

function submission() {
  const values = {
    name: 'test-runtime', framework: 'custom', exec_code: true, browse_web: false,
    filesystem: false, exposure: 'local', handles_payments: false, human_approval: 'always',
    persistent_memory: false, tool_count: 2, guardrails: true, audit_logging: true, incident_plan: true,
  };
  return {
    protocol: TEASER_PROTOCOL,
    subject: 'self',
    assessment: {
      protocol: PROTOCOL,
      subject: 'self',
      answers: Object.fromEntries(QUESTIONS.map(question => [question.key, {
        value: values[question.key], source: 'agent_asserted', evidence: `claim for ${question.key}`,
      }])),
    },
  };
}

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-scan-public-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const claims = path.join(directory, 'claims.json');
  const tools = path.join(directory, 'tools.json');
  fs.writeFileSync(claims, JSON.stringify(submission()));
  fs.writeFileSync(tools, JSON.stringify({ marker: 'RAW_ARTIFACT_CONTENT_MUST_STAY_LOCAL' }));
  return { directory, claims, tools };
}

function fakeAnalyzer(directory) {
  const target = path.join(directory, 'analyzer.js');
  fs.writeFileSync(target, `'use strict';
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
 const q=JSON.parse(d); const a=q.submission.assessment.answers;
 const profile=Object.fromEntries(Object.entries(a).map(([k,v])=>[k,v.value]));
 process.stdout.write(JSON.stringify({protocol:'backbond-private-analyzer/v1',payload:{client:'backbond-agent-scan/0.4.1',submitted_at:q.captured_at,profile},result:{score:73,score_kind:'private_analysis',controls:{actions:['control-required']}}}));
});\n`);
  return { path: target, digest: sha256(fs.readFileSync(target)) };
}

test('default contract says the public client does not analyze', () => {
  const run = spawnSync(process.execPath, [CLI], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.equal(output.protocol, TEASER_PROTOCOL);
  assert.equal(output.public_client_role, 'capture_validate_bridge');
  assert.match(output.instructions.join(' '), /does not contain or perform proprietary analysis/i);
  assert.match(output.instructions.join(' '), /not a scan or quick exposure check/i);
  assert.match(output.instructions.join(' '), /does not establish publisher authenticity/i);
});

test('inspect hashes artifacts without returning their contents', (t) => {
  const f = fixture(t);
  const run = spawnSync(process.execPath, [CLI, 'inspect', '--tool-schema', f.tools], { encoding: 'utf8', cwd: f.directory });
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.equal(output.artifacts.length, 1);
  assert.match(output.artifacts[0].sha256, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(run.stdout, /RAW_ARTIFACT_CONTENT_MUST_STAY_LOCAL/);
});

test('scan without the private analyzer captures a receipt and fails closed', (t) => {
  const f = fixture(t);
  const receipt = path.join(f.directory, 'capture-receipt.json');
  const run = spawnSync(process.execPath, [CLI, 'scan', '--input', f.claims, '--tool-schema', f.tools, '--receipt', receipt, '--json'], {
    encoding: 'utf8', cwd: f.directory,
  });
  assert.equal(run.status, 3, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'analysis_required');
  assert.equal(output.fail_closed, true);
  assert.equal(fs.existsSync(receipt), true);
});

test('private analyzer must match an explicit SHA-256 pin', (t) => {
  const f = fixture(t);
  const analyzer = fakeAnalyzer(f.directory);
  const rejected = spawnSync(process.execPath, [CLI, 'scan', '--input', f.claims, '--analyzer', analyzer.path, '--analyzer-sha256', '0'.repeat(64), '--json'], {
    encoding: 'utf8', cwd: f.directory,
  });
  assert.equal(rejected.status, 2);
  assert.match(rejected.stderr, /does not match the pinned digest/);
  const accepted = spawnSync(process.execPath, [CLI, 'scan', '--input', f.claims, '--analyzer', analyzer.path, '--analyzer-sha256', analyzer.digest, '--json'], {
    encoding: 'utf8', cwd: f.directory,
  });
  assert.equal(accepted.status, 0, accepted.stderr);
  const output = JSON.parse(accepted.stdout);
  assert.equal(output.status, 'analyzed');
  assert.equal(output.analysis.score, 73);
  assert.equal(output.analyzer.sha256, analyzer.digest);
  assert.equal(output.analyzer.digest_verification, 'matches_caller_supplied_pin');
  assert.equal(output.analyzer.publisher_authenticity, 'not_established_by_public_client');
});

test('human output labels analyzer results without claiming verification', (t) => {
  const f = fixture(t);
  const analyzer = fakeAnalyzer(f.directory);
  const run = spawnSync(process.execPath, [CLI, 'scan', '--input', f.claims, '--analyzer', analyzer.path, '--analyzer-sha256', analyzer.digest], {
    encoding: 'utf8', cwd: f.directory,
  });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /Analyzer-reported score: 73\/100/);
  assert.match(run.stdout, /publisher authenticity was not established/i);
  assert.doesNotMatch(run.stdout, /Verified initial score/i);
});

test('dry-run exposes only the private analyzer POST envelope', (t) => {
  const f = fixture(t);
  const analyzer = fakeAnalyzer(f.directory);
  const run = spawnSync(process.execPath, [CLI, 'scan', '--input', f.claims, '--tool-schema', f.tools, '--analyzer', analyzer.path, '--analyzer-sha256', analyzer.digest, '--dry-run'], {
    encoding: 'utf8', cwd: f.directory,
  });
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'dry_run');
  assert.equal(Object.keys(output.exact_post_body.profile).length, 13);
  assert.doesNotMatch(JSON.stringify(output.exact_post_body), /RAW_ARTIFACT_CONTENT_MUST_STAY_LOCAL/);
});

test('capture receipt can be independently verified', (t) => {
  const f = fixture(t);
  const receipt = path.join(f.directory, 'capture-receipt.json');
  spawnSync(process.execPath, [CLI, 'scan', '--input', f.claims, '--receipt', receipt, '--json'], { encoding: 'utf8', cwd: f.directory });
  const verify = spawnSync(process.execPath, [CLI, 'verify-receipt', '--input', receipt], { encoding: 'utf8' });
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).valid, true);
});

module.exports = { submission };
