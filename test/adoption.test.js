'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { discover } = require('../lib/discovery.js');
const { collectEvidence } = require('../lib/evidence.js');
const { handleMessage, TOOL } = require('../lib/mcp-server.js');
const { scanEvidence } = require('../lib/scanner.js');
const { CLI, ROOT, tempDirectory, writeJson } = require('./helpers.js');

const NOW = new Date('2026-08-29T12:00:00.000Z');

test('bounded discovery finds known project/user configs and instruction files', (t) => {
  const root = tempDirectory(t);
  const project = path.join(root, 'project');
  const home = path.join(root, 'home');
  fs.mkdirSync(path.join(project, '.cursor'), { recursive: true });
  fs.mkdirSync(path.join(project, '.git'), { recursive: true });
  fs.mkdirSync(path.join(home, '.codeium', 'windsurf'), { recursive: true });
  writeJson(path.join(project, '.cursor'), 'mcp.json', { mcpServers: {} });
  writeJson(path.join(home, '.codeium', 'windsurf'), 'mcp_config.json', { mcpServers: {} });
  fs.writeFileSync(path.join(project, 'AGENTS.md'), '# Local instructions');
  const plan = discover({ cwd: project, home, appData: path.join(root, 'appdata') });
  assert.deepEqual(plan.files.map(item => item.adapter).sort(), ['cursor', 'windsurf']);
  assert.equal(plan.instruction_files.some(item => item.endsWith('AGENTS.md')), true);
  assert.doesNotMatch(JSON.stringify(plan), /Local instructions/);
});

test('messy non-BackBond fixtures produce named findings with derived evidence', () => {
  const shell = collectEvidence({ now: NOW, toolSchemaPath: path.join(ROOT, 'fixtures', 'wild', 'mcp-shell-tools.json') });
  const shellScan = scanEvidence(shell, { now: NOW });
  assert.deepEqual(shellScan.findings.map(item => item.id), ['BB001', 'BB007']);
  assert.equal(shellScan.findings.every(item => item.evidence_quality === 'derived'), true);

  const vscode = collectEvidence({ now: NOW, artifactPaths: [{ kind: 'config', path: path.join(ROOT, 'fixtures', 'wild', 'vscode-mcp.json'), adapter: 'vscode' }] });
  assert.deepEqual(scanEvidence(vscode, { now: NOW }).findings.map(item => item.id), ['BB006']);

  const gemini = collectEvidence({ now: NOW, artifactPaths: [{ kind: 'config', path: path.join(ROOT, 'fixtures', 'wild', 'gemini-settings.json'), adapter: 'gemini' }] });
  const geminiScan = scanEvidence(gemini, { now: NOW });
  assert.deepEqual(geminiScan.findings.map(item => item.id), ['BB003']);
  assert.equal(geminiScan.coverage.gaps.some(item => item.code === 'BB-COV-BB005-AUDIT'), true);
});

test('stdin accepts a live tool manifest and human output stays compact', () => {
  const manifest = fs.readFileSync(path.join(ROOT, 'fixtures', 'wild', 'mcp-shell-tools.json'), 'utf8');
  const run = spawnSync(process.execPath, [CLI, 'scan', '--stdin'], { input: manifest, encoding: 'utf8' });
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stdout, /BB001 run_shell \[derived\]/);
  assert.match(run.stdout, /Stop:/);
  assert.doesNotMatch(run.stdout, /backbond-agent-scan\/v1/);
  assert.equal(run.stdout.trim().split(/\r?\n/).length <= 10, true);
});

test('SARIF output uses named rules and JSON evidence locations', () => {
  const fixture = path.join(ROOT, 'fixtures', 'wild', 'mcp-shell-tools.json');
  const run = spawnSync(process.execPath, [CLI, 'scan', '--tool-schema', fixture, '--sarif'], { encoding: 'utf8' });
  assert.equal(run.status, 1, run.stderr);
  const sarif = JSON.parse(run.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.deepEqual(sarif.runs[0].results.map(item => item.ruleId), ['BB001', 'BB007']);
  assert.equal(sarif.runs[0].results[0].locations[0].logicalLocations[0].kind, 'json-pointer');
});

test('OTLP JSON tool spans are ingested without retaining span attributes', (t) => {
  const directory = tempDirectory(t);
  const marker = 'SECRET_ATTRIBUTE_VALUE_MUST_NOT_SURVIVE';
  const trace = writeJson(directory, 'otel.json', {
    resourceSpans: [{ scopeSpans: [{ spans: [{
      name: 'execute tool',
      attributes: [
        { key: 'gen_ai.operation.name', value: { stringValue: 'execute_tool' } },
        { key: 'gen_ai.tool.name', value: { stringValue: 'run_shell' } },
        { key: 'tool.arguments', value: { stringValue: marker } },
      ],
    }] }] }],
  });
  const evidence = collectEvidence({ now: NOW, tracePath: trace });
  const scan = scanEvidence(evidence, { now: NOW });
  assert.equal(evidence.artifacts[0].dialect, 'opentelemetry-otlp-json/v1');
  assert.equal(scan.findings.some(item => item.id === 'BB001'), true);
  assert.doesNotMatch(JSON.stringify({ evidence, scan }), new RegExp(marker));
});

test('policy suggestions are structured, non-enforcing, and never auto-applied', () => {
  const vulnerable = path.join(ROOT, 'fixtures', 'vulnerable');
  const run = spawnSync(process.execPath, [CLI, 'scan',
    '--tool-schema', path.join(vulnerable, 'tool-schema.json'),
    '--permissions', path.join(vulnerable, 'permissions.json'),
    '--trace', path.join(vulnerable, 'trace.json'),
    '--suggest-policy', '--fail-on', 'none', '--json'], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const policy = JSON.parse(run.stdout).policy_suggestion;
  assert.equal(policy.enforced, false);
  assert.equal(policy.actions.some(item => item.tool === 'shell_exec' && item.action === 'disable'), true);
  assert.equal(policy.patches.some(item => item.finding_id === 'BB006' && item.template === true), true);
  assert.equal(policy.patches.every(item => item.safe_to_apply_automatically === false), true);
});

test('MCP exposes scan_my_runtime with no required args and accepts live tools', () => {
  assert.equal(TOOL.inputSchema.required, undefined);
  const listed = handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(listed.result.tools[0].name, 'scan_my_runtime');
  const called = handleMessage({
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'scan_my_runtime', arguments: { tools: [{ name: 'run_shell', description: 'Execute shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } }], suggest_policy: true } },
  });
  assert.equal(called.result.isError, false);
  assert.equal(called.result.structuredContent.scan.findings.some(item => item.id === 'BB001'), true);
  assert.match(called.result.content[0].text, /Stop:/);
});
