'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const manifest = require('../package.json');
const card = require('../server.json');
const { checkRegistryVersion, exactRegistryUrl } = require('../scripts/check-mcp-registry.js');
const { ROOT, tempDirectory } = require('./helpers.js');

test('official registry lookup uses the exact encoded server name and version endpoint', () => {
  assert.equal(
    exactRegistryUrl('https://registry.modelcontextprotocol.io', card.name, card.version).href,
    `https://registry.modelcontextprotocol.io/v0.1/servers/io.github.BackBond%2Fagent-scan/versions/${card.version}`,
  );
});

test('registry card exposes the canonical website and a first-party icon', () => {
  assert.equal(card.websiteUrl, 'https://backbond.ai/agent-scan/');
  assert.deepEqual(card.icons, [{
    src: 'https://backbond.ai/agent-scan/backbond-agent-scan.png',
    mimeType: 'image/png',
  }]);
});

test('registry status distinguishes an unpublished exact version from a matching publication', async () => {
  const absent = await checkRegistryVersion({
    manifest,
    card,
    fetchImpl: async () => ({ status: 404, ok: false }),
  });
  assert.equal(absent, false);

  const published = await checkRegistryVersion({
    manifest,
    card,
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      json: async () => ({
        server: {
          ...card,
          packages: card.packages,
        },
      }),
    }),
  });
  assert.equal(published, true);

  const direct = await checkRegistryVersion({
    manifest,
    card,
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      json: async () => card,
    }),
  });
  assert.equal(direct, true);
});

test('registry status rejects a same-version response bound to another npm package', async () => {
  await assert.rejects(
    checkRegistryVersion({
      manifest,
      card,
      fetchImpl: async () => ({
        status: 200,
        ok: true,
        json: async () => ({
          server: {
            ...card,
            packages: [{ ...card.packages[0], identifier: '@attacker/agent-scan' }],
          },
        }),
      }),
    }),
    /does not match the npm package metadata/,
  );
});

test('registry status rejects drift in immutable launch and repository metadata', async () => {
  for (const [label, changedServer, expected] of [
    ['package arguments', {
      ...card,
      packages: [{ ...card.packages[0], packageArguments: [{ type: 'positional', value: 'scan' }] }],
    }, /package launch descriptor/],
    ['remote transport', {
      ...card,
      remotes: [{ type: 'streamable-http', url: 'https://attacker.example/mcp' }],
    }, /remote launch descriptor/],
    ['repository identity', {
      ...card,
      repository: { ...card.repository, id: '1' },
    }, /repository identity/],
  ]) {
    await assert.rejects(
      checkRegistryVersion({
        manifest,
        card,
        fetchImpl: async () => ({ status: 200, ok: true, json: async () => ({ server: changedServer }) }),
      }),
      expected,
      label,
    );
  }
});

test('registry helper CLI writes the workflow output and enforces --require-published', (t) => {
  const directory = tempDirectory(t);
  const preload = path.join(directory, 'mock-fetch.js');
  fs.writeFileSync(preload, [
    "'use strict';",
    'global.fetch = async () => ({',
    '  status: Number(process.env.MOCK_REGISTRY_STATUS),',
    '  ok: Number(process.env.MOCK_REGISTRY_STATUS) >= 200 && Number(process.env.MOCK_REGISTRY_STATUS) < 300,',
    '  json: async () => JSON.parse(process.env.MOCK_REGISTRY_BODY || "{}"),',
    '});',
  ].join('\n'));
  const script = path.join(ROOT, 'scripts', 'check-mcp-registry.js');

  const run = (status, body, required) => {
    const output = path.join(directory, `github-output-${status}-${required}.txt`);
    const result = spawnSync(process.execPath, [
      '--require', preload, script, ...(required ? ['--require-published'] : []),
    ], {
      encoding: 'utf8',
      env: {
        ...process.env,
        GITHUB_OUTPUT: output,
        MOCK_REGISTRY_STATUS: String(status),
        MOCK_REGISTRY_BODY: JSON.stringify(body),
      },
    });
    return { result, output: fs.readFileSync(output, 'utf8') };
  };

  const absent = run(404, {}, false);
  assert.equal(absent.result.status, 0, absent.result.stderr);
  assert.equal(absent.output, 'published=false\n');
  assert.match(absent.result.stdout, /^not_published /);

  const requiredAbsent = run(404, {}, true);
  assert.equal(requiredAbsent.result.status, 1, requiredAbsent.result.stderr);
  assert.equal(requiredAbsent.output, 'published=false\n');

  const published = run(200, { server: card }, true);
  assert.equal(published.result.status, 0, published.result.stderr);
  assert.equal(published.output, 'published=true\n');
  assert.match(published.result.stdout, /^published /);
});
