'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { ROOT, fixturePaths, tempDirectory } = require('./helpers.js');

function npmInvocation(args, options) {
  const configuredCli = process.env.npm_execpath;
  if (configuredCli && fs.existsSync(configuredCli)) {
    return spawnSync(process.execPath, [configuredCli, ...args], options);
  }
  if (process.platform === 'win32') {
    const cli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
    return spawnSync(process.execPath, [cli, ...args], options);
  }
  return spawnSync('npm', args, options);
}

test('the packed release tarball runs with an empty npm cache and offline mode', (t) => {
  const directory = tempDirectory(t);
  const dist = path.join(directory, 'dist');
  const runDirectory = path.join(directory, 'run');
  fs.mkdirSync(dist);
  fs.mkdirSync(runDirectory);

  const packed = npmInvocation([
    'pack', '--ignore-scripts', '--pack-destination', dist, '--cache', path.join(directory, 'pack-cache'),
  ], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(packed.status, 0, packed.stderr);

  const archiveName = fs.readdirSync(dist).find(name => name.endsWith('.tgz'));
  assert.equal(typeof archiveName, 'string', `npm pack produced no tarball:\n${packed.stdout}\n${packed.stderr}`);
  const archive = path.join(dist, archiveName);
  const unpacked = path.join(directory, 'unpacked');
  fs.mkdirSync(unpacked);
  const extracted = spawnSync('tar', ['-xzf', archive, '-C', unpacked], { encoding: 'utf8' });
  assert.equal(extracted.status, 0, extracted.stderr);
  const packedManifest = JSON.parse(fs.readFileSync(path.join(unpacked, 'package', 'package.json'), 'utf8'));
  const packedRegistry = JSON.parse(fs.readFileSync(path.join(unpacked, 'package', 'server.json'), 'utf8'));
  assert.equal(fs.existsSync(path.join(unpacked, 'package', 'scripts', 'check-mcp-registry.js')), false);
  assert.equal(packedManifest.mcpName, 'io.github.backbond/agent-scan');
  assert.equal(packedRegistry.name, packedManifest.mcpName);
  assert.equal(packedRegistry.version, packedManifest.version);
  assert.deepEqual(packedRegistry.packages[0].packageArguments, [{ type: 'positional', value: 'mcp' }]);

  const fixture = fixturePaths('vulnerable');
  const scanned = npmInvocation([
    'exec', '--yes', '--offline', '--cache', path.join(directory, 'empty-target-cache'),
    `--package=${archive}`, '--', 'agent-scan', 'scan',
    '--tool-schema', fixture.tools, '--permissions', fixture.permissions, '--trace', fixture.trace,
    '--fail-on', 'none',
  ], {
    cwd: runDirectory,
    encoding: 'utf8',
    env: { ...process.env, npm_config_registry: 'http://127.0.0.1:9' },
  });

  assert.equal(scanned.status, 0, scanned.stderr);
  assert.match(scanned.stdout, /BB012/);
  assert.match(scanned.stdout, /Coverage: complete/);
  assert.doesNotMatch(`${scanned.stdout}\n${scanned.stderr}`, /EAI_AGAIN|ENETUNREACH|registry timeout/i);

  const mcpInput = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
  ].map(message => JSON.stringify(message)).join('\n') + '\n';
  const mcp = npmInvocation([
    'exec', '--yes', '--offline', '--cache', path.join(directory, 'empty-target-cache'),
    `--package=${archive}`, '--', 'agent-scan', 'mcp',
  ], {
    cwd: runDirectory,
    encoding: 'utf8',
    input: mcpInput,
    env: { ...process.env, npm_config_registry: 'http://127.0.0.1:9' },
  });
  assert.equal(mcp.status, 0, mcp.stderr);
  const responses = mcp.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(responses[0].result.serverInfo.version, packedManifest.version);
  assert.deepEqual(responses[1].result.tools.map(tool => tool.name), [
    'scan_my_runtime',
    'vet_tools_before_attach',
  ]);
});
