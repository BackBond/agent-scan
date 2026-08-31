'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { collectEvidence } = require('../lib/evidence.js');
const { scanEvidence } = require('../lib/scanner.js');
const { sha256 } = require('../lib/canonical.js');
const { RULES, RULESET_DIGEST, createRulesetDigest } = require('../lib/rules.js');
const rulesetSources = require('../lib/ruleset-sources.json');
const { fixturePaths, tempDirectory, writeJson } = require('./helpers.js');

const NOW = new Date('2026-08-29T12:00:00.000Z');

function scanFixture(name) {
  const f = fixturePaths(name);
  const evidence = collectEvidence({ now: NOW, toolSchemaPath: f.tools, permissionsPath: f.permissions, tracePath: f.trace });
  return scanEvidence(evidence, { now: NOW });
}

test('every open rule has a positive vulnerable fixture and a negative hardened fixture', () => {
  const vulnerable = scanFixture('vulnerable');
  const hardened = scanFixture('hardened');
  assert.equal(vulnerable.ruleset.version, 'backbond-local-rules/1.4.0');
  assert.deepEqual(vulnerable.findings.map(item => item.id), ['BB001', 'BB002', 'BB003', 'BB004', 'BB005', 'BB006', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012', 'BB013']);
  assert.equal(vulnerable.coverage.status, 'complete');
  assert.deepEqual(hardened.findings, []);
  assert.equal(hardened.coverage.status, 'complete');
});

test('rule output is deterministic for identical bytes and time', () => {
  assert.deepEqual(scanFixture('vulnerable'), scanFixture('vulnerable'));
});

test('ruleset identity covers normalized evidence-detector source and rule evaluators', () => {
  const evidenceSource = fs.readFileSync(path.join(__dirname, '..', 'lib', 'evidence.js'), 'utf8').replace(/\r\n?/g, '\n');
  assert.equal(rulesetSources.evidence_sha256, sha256(evidenceSource));
  assert.notEqual(createRulesetDigest('0'.repeat(64)), RULESET_DIGEST);
  assert.notEqual(createRulesetDigest(rulesetSources.evidence_sha256, ['changed helper']), RULESET_DIGEST);
  assert.notEqual(createRulesetDigest(rulesetSources.evidence_sha256, undefined, {
    severity_order: { critical: 5, high: 3, medium: 2, low: 1, none: 0 },
    prompt_lint_ids: ['BB009', 'BB010', 'BB011', 'BB013'],
  }), RULESET_DIGEST);
  assert.notEqual(createRulesetDigest(rulesetSources.evidence_sha256, undefined, {
    severity_order: { critical: 4, high: 3, medium: 2, low: 1, none: 0 },
    prompt_lint_ids: ['BB009', 'BB010', 'BB011'],
  }), RULESET_DIGEST);
});

test('every rule declares one honest finding class and a nonempty precision note', () => {
  const classes = RULES.reduce((counts, rule) => {
    assert.equal(['capability_exposure', 'prompt_injection_indicator'].includes(rule.finding_class), true, rule.id);
    assert.equal(typeof rule.precision_note, 'string', rule.id);
    assert.notEqual(rule.precision_note.trim(), '', rule.id);
    counts[rule.finding_class] += 1;
    return counts;
  }, { capability_exposure: 0, prompt_injection_indicator: 0 });
  assert.deepEqual(classes, { capability_exposure: 9, prompt_injection_indicator: 4 });
});

test('missing evidence becomes coverage gaps, never a synthetic finding', (t) => {
  const directory = tempDirectory(t);
  const tools = writeJson(directory, 'openai-tools.json', {
    tools: [{ type: 'function', function: { name: 'delete_record', description: 'Delete a record', parameters: { type: 'object' } } }],
  });
  const result = scanEvidence(collectEvidence({ now: NOW, toolSchemaPath: tools }), { now: NOW });
  assert.equal(result.findings.some(item => item.id === 'BB003'), false);
  assert.equal(result.coverage.gaps.some(item => item.code === 'BB-COV-BB003-APPROVAL'), true);
  assert.equal(result.coverage.gaps.some(item => item.code === 'BB-COV-MISSING-PERMISSIONS'), true);
  assert.equal(result.coverage.gaps.some(item => item.code === 'BB-COV-MISSING-TRACE'), true);
});

test('unsupported JSON becomes a coverage gap instead of a finding', (t) => {
  const directory = tempDirectory(t);
  const tools = writeJson(directory, 'unknown.json', { arbitrary: 'document' });
  const result = scanEvidence(collectEvidence({ now: NOW, toolSchemaPath: tools }), { now: NOW });
  assert.deepEqual(result.findings, []);
  assert.equal(result.coverage.gaps.some(item => item.code === 'BB-COV-UNSUPPORTED-TOOL_SCHEMA'), true);
});

test('malformed supported dialects fail as invalid scanner input', (t) => {
  const directory = tempDirectory(t);
  const malformed = [
    ['tools.json', { protocol: 'backbond-tool-schema/v1', tools: {} }, { toolSchemaPath: null }],
    ['permissions.json', { protocol: 'backbond-permissions/v1', tools: [] }, { permissionsPath: null }],
    ['trace.json', { protocol: 'backbond-trace/v1', events: {} }, { tracePath: null }],
  ];
  for (const [name, document, option] of malformed) {
    const target = writeJson(directory, name, document);
    const key = Object.keys(option)[0];
    assert.throws(() => collectEvidence({ now: NOW, [key]: target }), /must be (an array|a JSON object)/);
  }
});

test('malformed canonical permission scopes fail instead of looking restricted', (t) => {
  const directory = tempDirectory(t);
  const permissions = writeJson(directory, 'permissions.json', {
    protocol: 'backbond-permissions/v1',
    network: { egress: 42 },
  });
  assert.throws(() => collectEvidence({ now: NOW, permissionsPath: permissions }), /must be a string array/);
});

test('OpenAI, Anthropic, and MCP tool schemas normalize without raw arguments', (t) => {
  const directory = tempDirectory(t);
  const documents = [
    ['openai.json', { tools: [{ type: 'function', function: { name: 'run_shell', description: 'Run shell', parameters: { type: 'object', properties: { command: { type: 'string' } } } } }] }, 'openai-function-tools/v1'],
    ['anthropic.json', [{ name: 'fetch_web', description: 'Fetch web URL', input_schema: { type: 'object' } }], 'anthropic-tools/v1'],
    ['mcp.json', { jsonrpc: '2.0', result: { tools: [{ name: 'read_file', description: 'Read file', inputSchema: { type: 'object' } }] } }, 'mcp-tools-list/v1'],
  ];
  for (const [name, document, dialect] of documents) {
    const target = writeJson(directory, name, document);
    const evidence = collectEvidence({ now: NOW, toolSchemaPath: target });
    assert.equal(evidence.artifacts[0].dialect, dialect);
    assert.equal(evidence.facts.tools.length, 1);
  }
});

test('artifact bodies are not retained in serializable evidence or findings', (t) => {
  const directory = tempDirectory(t);
  const marker = 'RAW_PROMPT_AND_SECRET_MUST_NOT_LEAVE_DISK';
  const trace = writeJson(directory, 'trace.json', {
    protocol: 'backbond-trace/v1',
    events: [{ type: 'tool_call', tool: 'safe_tool', input_trust: 'trusted', approval: 'enforced', audit: 'observable', arguments: { prompt: marker } }],
  });
  const evidence = collectEvidence({ now: NOW, tracePath: trace });
  const scan = scanEvidence(evidence, { now: NOW });
  assert.doesNotMatch(JSON.stringify(evidence), new RegExp(marker));
  assert.doesNotMatch(JSON.stringify(scan), new RegExp(marker));
});
