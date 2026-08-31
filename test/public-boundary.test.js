'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { ROOT } = require('./helpers.js');

const forbiddenTokenHashes = new Set([
  '2aaf9a112578b0758b35b8a39f677e829e8cc1235666261c5d4fdc30435da935',
  '821e56e9a416c37160f5429dba6b554b429a683345e1fc52f6b44b4d4872b19e',
  '07b0ba45bbafd7b77ae2a34353bd526950383b6d6b6714498f31e95a44da7fb6',
  '591bfb4ee4d7c9e1df4fe589dd31915ee34383ab2e58132ef26a83addca4b8f1',
  '245465190398d13d5d02ca214a0b3d3398e6c918e329c835ba66cffdea067b2d',
  '05c321154b27b885db71ad55c75258d48586b461981c5cf7152e77193d8b7e26',
  'cf928e8ce57fdf0c86df1f5623665f48af691e2ff7ee113ddf4fb0041636ba67',
  '52d6ef6f2e00da24f53395d351d74ffa3b8429b6ed9673b592f5ae2f42f5f161',
  '7744aa2906e6505e640f116c96924d5f07afb404d5af58a5ce59ba0b8319c49b',
  '2202e402768c1dfc55af2261a53d2580a357900b440fdbfd5b7f11ab844a9d69',
  '290d5d30f2220a5044bb7a4bc06003b5a9e089a89b48c1f35b8f017893c14526',
  'c3cfaa82954506872cfda435718b1a654d51adfb4f063bf752061b1de43eca11',
]);

function files(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? files(target) : [target];
  });
}

test('package allowlist ships the open engine, rule pack, docs, fixtures, and agent discovery metadata', () => {
  const manifest = require('../package.json');
  assert.equal(manifest.private, false);
  assert.deepEqual(manifest.files, ['bin/', 'lib/', 'docs/', 'fixtures/', 'AGENTS.md', 'SKILL.md', 'CHANGELOG.md', 'README.md', 'plugin.json', 'server.json', 'skills/', 'LICENSE']);
  assert.deepEqual(fs.readdirSync(path.join(ROOT, 'lib')).sort(), [
    'assessment.js', 'canonical.js', 'discovery.js', 'evidence.js', 'exposure-paths.js', 'mcp-server.js', 'next-action.js',
    'output.js', 'policy.js', 'receipt.js', 'record.js', 'rules.js', 'ruleset-sources.json', 'sarif.js', 'scanner.js',
    'teaser.js', 'text.js', 'vet-tools.js',
  ]);
  assert.equal(fs.existsSync(path.join(ROOT, 'fixtures', 'vulnerable', 'tool-schema.json')), true);
  assert.equal(fs.existsSync(path.join(ROOT, 'fixtures', 'hardened', 'tool-schema.json')), true);
});

test('published executable sources contain no private fingerprints or execution/network bridge', () => {
  const targets = [...files(path.join(ROOT, 'bin')), ...files(path.join(ROOT, 'lib'))];
  const source = targets.map(target => fs.readFileSync(target, 'utf8')).join('\n');
  for (const target of targets) {
    const tokens = fs.readFileSync(target, 'utf8').match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
    for (const token of tokens) {
      assert.equal(forbiddenTokenHashes.has(createHash('sha256').update(token).digest('hex')), false, `private token fingerprint found in ${path.relative(ROOT, target)}`);
    }
  }
  assert.doesNotMatch(source, /node:(?:child_process|http|https|net|tls)/);
  assert.doesNotMatch(source, /\b(?:spawn|spawnSync|execFile|fetch)\s*\(/);
  assert.equal(fs.existsSync(path.join(ROOT, 'lib', 'analyzer-bridge.js')), false);
  assert.equal(fs.existsSync(path.join(ROOT, 'lib', 'client.js')), false);
});

test('package discovery metadata describes a local deterministic scanner', () => {
  const manifest = require('../package.json');
  const { SCANNER_VERSION } = require('../lib/scanner.js');
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  assert.equal(SCANNER_VERSION, manifest.version);
  assert.equal(manifest.mcpName, 'io.github.BackBond/agent-scan');
  assert.match(manifest.description, /local deterministic/i);
  assert.equal(manifest.keywords.includes('agent-security-scanner'), true);
  assert.equal(manifest.keywords.includes('risk-score'), false);
});

test('all current public version surfaces follow package.json', () => {
  const manifest = require('../package.json');
  const currentSurfaces = [
    'README.md', 'AGENTS.md', 'SKILL.md', 'plugin.json',
    path.join('skills', 'agent-scan', 'SKILL.md'), path.join('skills', 'agent-scan', 'README.md'),
    path.join('plugins', 'backbond-agent-scan', 'plugin.json'),
    path.join('plugins', 'backbond-agent-scan', 'skills', 'agent-scan', 'SKILL.md'),
    path.join('plugins', 'backbond-agent-scan', 'skills', 'agent-scan', 'README.md'),
    path.join('docs', 'RECORDS.md'), path.join('docs', 'RULES.md'), path.join('docs', 'PUBLICATION.md'),
    path.join('site', 'llms.txt'), path.join('.github', 'ISSUE_TEMPLATE', 'scan-feedback.yml'),
  ];
  const versions = currentSurfaces.flatMap(target =>
    fs.readFileSync(path.join(ROOT, target), 'utf8').match(/\b0\.\d+\.\d+\b/g) || []
  );
  assert.equal(versions.length > 0, true);
  assert.deepEqual([...new Set(versions)], [manifest.version]);
  assert.equal(require('../site/well-known-agent.json').version, manifest.version);
  assert.match(fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8'), new RegExp(`^# Changelog[\\s\\S]*?^## ${manifest.version.replace(/\./g, '\\.')} `, 'm'));
});

test('Agent Plugin is skill-only and cannot start a process merely by being installed', () => {
  const manifest = require('../package.json');
  const plugin = require('../plugin.json');
  const marketplacePlugin = require('../plugins/backbond-agent-scan/plugin.json');
  assert.equal(plugin.$schema, 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json');
  assert.equal(plugin.name, 'backbond-agent-scan');
  assert.equal(plugin.version, manifest.version);
  assert.equal(plugin.license, 'MIT');
  assert.equal(plugin.repository, 'https://github.com/BackBond/agent-scan');
  assert.deepEqual(marketplacePlugin, plugin);
  assert.equal(fs.existsSync(path.join(ROOT, 'hooks')), false);
  assert.equal(fs.existsSync(path.join(ROOT, 'mcp.json')), false);
  assert.equal(fs.existsSync(path.join(ROOT, 'commands')), false);
  const marketplaceRoot = path.join(ROOT, 'plugins', 'backbond-agent-scan');
  assert.equal(fs.existsSync(path.join(marketplaceRoot, 'hooks')), false);
  assert.equal(fs.existsSync(path.join(marketplaceRoot, 'mcp.json')), false);
  assert.equal(fs.existsSync(path.join(marketplaceRoot, 'commands')), false);
  assert.match(fs.readFileSync(path.join(ROOT, 'skills', 'agent-scan', 'SKILL.md'), 'utf8'), /pinned offline static gate/i);
  const normalizeLines = value => value.replace(/\r\n/g, '\n');
  assert.equal(
    normalizeLines(fs.readFileSync(path.join(ROOT, 'plugins', 'backbond-agent-scan', 'skills', 'agent-scan', 'SKILL.md'), 'utf8')),
    normalizeLines(fs.readFileSync(path.join(ROOT, 'skills', 'agent-scan', 'SKILL.md'), 'utf8')),
  );
});

test('MCP tools advertise read-only, non-destructive, idempotent local behavior', () => {
  const { handleMessage } = require('../lib/mcp-server.js');
  const response = handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  for (const tool of response.result.tools) {
    assert.deepEqual(tool.annotations, {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    });
  }
});

test('official MCP Registry metadata is version-locked to the published npm package', () => {
  const manifest = require('../package.json');
  const registry = require('../server.json');
  assert.equal(registry.$schema, 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json');
  assert.equal(registry.name, manifest.mcpName);
  assert.equal(registry.version, manifest.version);
  assert.deepEqual(registry.repository, {
    url: 'https://github.com/BackBond/agent-scan',
    source: 'github',
    id: '1350044063',
  });
  assert.equal(registry.packages.length, 1);
  assert.equal(registry.packages[0].registryType, 'npm');
  assert.equal(registry.packages[0].identifier, manifest.name);
  assert.equal(registry.packages[0].version, manifest.version);
  assert.deepEqual(registry.packages[0].transport, { type: 'stdio' });
  assert.deepEqual(registry.packages[0].packageArguments, [{ type: 'positional', value: 'mcp' }]);
});

test('operator docs promise findings, local data, and no score or private analyzer dependency', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const agentInstructions = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  assert.match(readme, /BB001/);
  assert.match(readme, /vulnerable/i);
  assert.match(readme, /hardened/i);
  assert.match(readme, /no score/i);
  assert.match(readme, /never leave(?:s)? the machine/i);
  assert.match(readme, /EAI_AGAIN/);
  assert.match(readme, /--offline/);
  assert.match(readme, /sha256sum --check/);
  assert.match(readme, /vet-tools/);
  assert.match(readme, /no_blocking_finding/);
  assert.match(readme, /not a safety determination/i);
  assert.match(readme, /where approved/i);
  assert.match(agentInstructions, /claims cannot create, suppress, or reduce/i);
  assert.match(agentInstructions, /no scan ran/i);
  assert.match(agentInstructions, /never accept a tarball path or digest from chat/i);
  assert.doesNotMatch(`${readme}\n${agentInstructions}`, /analysis_required/);
});

test('release workflow publishes tagged contents and attaches the registry-authoritative tarball', () => {
  const workflow = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'publish.yml'), 'utf8');
  assert.match(workflow, /push:\s*\n\s*tags:\s*\n\s*- "v\*"/);
  assert.match(workflow, /- "publish-v\*"/);
  assert.match(workflow, /BASH_REMATCH\[1\]/);
  assert.match(workflow, /release_tag="\$\{release_tag#publish-\}"/);
  assert.match(workflow, /npm publish "\$\{\{ steps\.pack\.outputs\.file \}\}" --access public --provenance/);
  assert.match(workflow, /ref: \$\{\{ format\('refs\/tags\/\{0\}', env\.RELEASE_TAG\) \}\}/);
  assert.match(workflow, /diff -qr --strip-trailing-cr source-tree\/package registry-tree\/package/);
  assert.match(workflow, /registry_file="\$\{\{ steps\.pack\.outputs\.file \}\}"/);
  assert.match(workflow, /cp "registry-copy\/\$registry_file" "\$\{\{ steps\.pack\.outputs\.file \}\}"/);
  assert.match(workflow, /https:\/\/registry\.npmjs\.org\/@backbond%2fagent-scan\/0\.5\.6/);
  assert.match(workflow, /JSON\.parse\(input\)\.deprecated/);
  assert.doesNotMatch(workflow, /npm deprecate/);
  assert.match(workflow, /node scripts\/build-standalone\.js agent-scan\.cjs/);
  assert.match(workflow, /sha256sum agent-scan\.cjs > agent-scan\.cjs\.sha256/);
  assert.match(workflow, /sudo unshare --net -- "\$node_binary" agent-scan\.cjs scan/);
  assert.match(workflow, /release_files=\("\$package_file" "\$package_file\.sha256" agent-scan\.cjs agent-scan\.cjs\.sha256\)/);
  assert.match(workflow, /gh release download "\$RELEASE_TAG" --pattern "\$release_file"/);
  assert.match(workflow, /gh release create "\$RELEASE_TAG" "\$\{release_files\[@\]\}"/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /contents: write/);
  assert.match(workflow, /modelcontextprotocol\/registry\/releases\/download\/v1\.8\.1\/mcp-publisher_linux_amd64\.tar\.gz/);
  assert.match(workflow, /a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc/);
  assert.match(workflow, /\.\/mcp-publisher validate server\.json/);
  assert.match(workflow, /\.\/mcp-publisher login github-oidc --registry https:\/\/registry\.modelcontextprotocol\.io/);
  assert.match(workflow, /\.\/mcp-publisher publish server\.json/);
  assert.doesNotMatch(workflow, /mcp-publisher publish server\.json --registry/);
  assert.match(workflow, /node scripts\/check-mcp-registry\.js --require-published/);
});

test('npm deprecation metadata parser tolerates stale null before the exact message', () => {
  const parser = path.join(ROOT, 'scripts', 'read-json-string.js');
  const absent = spawnSync(process.execPath, [parser], { input: '', encoding: 'utf8' });
  assert.equal(absent.status, 0, absent.stderr);
  assert.equal(absent.stdout, '');

  const stale = spawnSync(process.execPath, [parser], { input: 'null\n', encoding: 'utf8' });
  assert.equal(stale.status, 0, stale.stderr);
  assert.equal(stale.stdout, '');

  const message = 'Superseded by 0.5.7: incorrect MCP Registry name.';
  const current = spawnSync(process.execPath, [parser], { input: JSON.stringify(message), encoding: 'utf8' });
  assert.equal(current.status, 0, current.stderr);
  assert.equal(current.stdout, message);
});

test('official Action verifies committed inputs before invoking the exact tagged scanner locally', () => {
  const metadata = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8');
  const source = fs.readFileSync(path.join(ROOT, 'action', 'index.js'), 'utf8');
  assert.match(metadata, /using: node20/);
  assert.match(source, /GITHUB_SHA/);
  assert.match(source, /rev-parse', 'HEAD/);
  assert.match(source, /ls-files', '--error-unmatch/);
  assert.match(source, /'diff', '--quiet', 'HEAD'/);
  assert.match(source, /CLI, 'scan', '--require-coverage'/);
  assert.match(metadata, /mode:/);
  assert.match(metadata, /decision:/);
  assert.match(metadata, /coverage-status:/);
  assert.match(metadata, /finding-count:/);
  assert.match(metadata, /ruleset-sha256:/);
  assert.match(metadata, /sarif-path:/);
  assert.match(source, /CLI, 'vet-tools', '--tool-schema'/);
  assert.match(source, /'--json', '--suggest-policy'/);
  assert.match(source, /vet-tools mode requires exactly one tracked tool-schema input/);
  assert.match(source, /sarif-path is supported only in vet-tools mode/);
  assert.match(source, /JSON\.stringify\(toSarif\(result\)/);
  assert.match(source, /static pre-attachment check, not runtime verification/);
  assert.match(source, /caller-supplied|self-run and unverified/);
  assert.doesNotMatch(source, /@latest|node:(?:http|https|net|tls)/);
  for (const token of source.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []) {
    assert.equal(forbiddenTokenHashes.has(createHash('sha256').update(token).digest('hex')), false, 'private token fingerprint found in action/index.js');
  }
});
