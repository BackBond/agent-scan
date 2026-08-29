'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
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

test('package allowlist ships the open engine, rule pack, docs, and fixtures', () => {
  const manifest = require('../package.json');
  assert.equal(manifest.private, false);
  assert.deepEqual(manifest.files, ['bin/', 'lib/', 'docs/', 'fixtures/', 'AGENTS.md', 'SKILL.md', 'CHANGELOG.md', 'README.md', 'LICENSE']);
  assert.deepEqual(fs.readdirSync(path.join(ROOT, 'lib')).sort(), [
    'assessment.js', 'canonical.js', 'discovery.js', 'evidence.js', 'mcp-server.js', 'next-action.js', 'output.js',
    'policy.js', 'receipt.js', 'record.js', 'rules.js', 'sarif.js', 'scanner.js', 'teaser.js', 'text.js',
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
  assert.equal(manifest.version, '0.5.4');
  assert.match(manifest.description, /local deterministic/i);
  assert.equal(manifest.keywords.includes('agent-security-scanner'), true);
  assert.equal(manifest.keywords.includes('risk-score'), false);
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
  assert.match(workflow, /gh release download "\$RELEASE_TAG" --pattern "\$package_file"/);
  assert.match(workflow, /gh release create "\$RELEASE_TAG" "\$package_file" "\$package_file\.sha256"/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /contents: write/);
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
  assert.match(source, /caller-supplied|self-run and unverified/);
  assert.doesNotMatch(source, /@latest|node:(?:http|https|net|tls)/);
  for (const token of source.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []) {
    assert.equal(forbiddenTokenHashes.has(createHash('sha256').update(token).digest('hex')), false, 'private token fingerprint found in action/index.js');
  }
});
