'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { CLI, ROOT, fixturePaths, tempDirectory } = require('./helpers.js');

const BUILDER = path.join(ROOT, 'scripts', 'build-standalone.js');

function run(entry, args, input) {
  return spawnSync(process.execPath, [entry, ...args], { encoding: 'utf8', input });
}

function stableScan(result) {
  return {
    protocol: result.protocol,
    scanner: result.scanner,
    ruleset: result.ruleset,
    status: result.status,
    summary: result.summary,
    findings: result.findings,
    exposure_paths: result.exposure_paths,
    coverage: result.coverage,
    claim_contradictions: result.claim_contradictions,
    inputs: result.inputs,
  };
}

test('the standalone release asset matches scan, vet-tools, and MCP package behavior', (t) => {
  const directory = tempDirectory(t);
  const standalone = path.join(directory, 'agent-scan.cjs');
  const built = spawnSync(process.execPath, [BUILDER, standalone], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(built.status, 0, built.stderr);
  assert.equal(fs.existsSync(standalone), true);
  assert.doesNotMatch(fs.readFileSync(standalone, 'utf8'), new RegExp(ROOT.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&'), 'i'));

  const packageHelp = run(CLI, ['--help']);
  const standaloneHelp = run(standalone, ['--help']);
  assert.equal(standaloneHelp.status, packageHelp.status);
  assert.equal(standaloneHelp.stdout, packageHelp.stdout);

  const fixture = fixturePaths('hardened');
  const scanArgs = ['scan', '--tool-schema', fixture.tools, '--permissions', fixture.permissions, '--trace', fixture.trace, '--json'];
  const packageScan = run(CLI, scanArgs);
  const standaloneScan = run(standalone, scanArgs);
  assert.equal(standaloneScan.status, packageScan.status, standaloneScan.stderr);
  assert.deepEqual(stableScan(JSON.parse(standaloneScan.stdout)), stableScan(JSON.parse(packageScan.stdout)));

  const manifest = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [{
    name: 'get_status', description: 'Returns current status.', inputSchema: { type: 'object', properties: {} },
  }] } });
  const packageVet = run(CLI, ['vet-tools', '--stdin', '--json'], manifest);
  const standaloneVet = run(standalone, ['vet-tools', '--stdin', '--json'], manifest);
  assert.equal(standaloneVet.status, packageVet.status, standaloneVet.stderr);
  const packageVetResult = JSON.parse(packageVet.stdout);
  const standaloneVetResult = JSON.parse(standaloneVet.stdout);
  delete packageVetResult.scanned_at;
  delete standaloneVetResult.scanned_at;
  assert.deepEqual(standaloneVetResult, packageVetResult);

  const mcpInput = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
  ].map(message => JSON.stringify(message)).join('\n') + '\n';
  const packageMcp = run(CLI, ['mcp'], mcpInput);
  const standaloneMcp = run(standalone, ['mcp'], mcpInput);
  assert.equal(standaloneMcp.status, packageMcp.status, standaloneMcp.stderr);
  assert.equal(standaloneMcp.stdout, packageMcp.stdout);
});
