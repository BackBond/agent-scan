'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { collectEvidence } = require('../lib/evidence.js');
const { scanEvidence } = require('../lib/scanner.js');
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
  assert.equal(vulnerable.ruleset.version, 'backbond-local-rules/1.3.0');
  assert.deepEqual(vulnerable.findings.map(item => item.id), ['BB001', 'BB002', 'BB003', 'BB004', 'BB005', 'BB006', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012', 'BB013']);
  assert.equal(vulnerable.coverage.status, 'complete');
  assert.deepEqual(hardened.findings, []);
  assert.equal(hardened.coverage.status, 'complete');
});

test('rule output is deterministic for identical bytes and time', () => {
  assert.deepEqual(scanFixture('vulnerable'), scanFixture('vulnerable'));
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
