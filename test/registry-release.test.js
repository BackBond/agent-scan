'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const manifest = require('../package.json');
const card = require('../server.json');
const { checkRegistryVersion, exactRegistryUrl } = require('../scripts/check-mcp-registry.js');
const {
  DEFAULT_BUDGET_MS,
  FIRST_DELAY_MS,
  MAX_DELAY_MS,
  awaitRegistryTarball,
  unreadableMessage,
} = require('../scripts/await-registry-tarball.js');
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

test('the registry wait outlasts a propagation that takes minutes rather than seconds', async () => {
  const slept = [];
  let readableAfter = 8; // roughly three minutes of propagation
  let calls = 0;

  const outcome = await awaitRegistryTarball({
    version: '0.6.3',
    destination: 'registry-copy',
    expectedFile: 'backbond-agent-scan-0.6.3.tgz',
    pack: () => {
      calls += 1;
      return calls > readableAfter;
    },
    exists: () => true,
    sleep: async (ms) => {
      slept.push(ms);
    },
  });

  assert.equal(outcome.attempts, readableAfter + 1);
  const waitedSeconds = slept.reduce((total, ms) => total + ms, 0) / 1000;
  assert.ok(waitedSeconds > 180, `waited only ${waitedSeconds}s before succeeding`);
  // The old loop gave up after six five-second polls; that budget must be gone.
  assert.ok(slept.slice(0, 6).reduce((total, ms) => total + ms, 0) > 30_000);
});

test('the registry wait backs off to a ceiling instead of polling tightly', async () => {
  const slept = [];
  await assert.rejects(
    awaitRegistryTarball({
      version: '0.6.3',
      destination: 'registry-copy',
      expectedFile: 'backbond-agent-scan-0.6.3.tgz',
      pack: () => false,
      exists: () => false,
      sleep: async (ms) => {
        slept.push(ms);
      },
    }),
    /was not readable from the npm registry/,
  );

  assert.equal(slept[0], FIRST_DELAY_MS);
  for (let index = 1; index < slept.length; index += 1) {
    assert.ok(slept[index] >= slept[index - 1], 'delays must never shrink');
    assert.ok(slept[index] <= MAX_DELAY_MS, 'delays must stay under the ceiling');
  }
  const total = slept.reduce((sum, ms) => sum + ms, 0);
  assert.ok(total >= DEFAULT_BUDGET_MS - MAX_DELAY_MS, `total budget was only ${total}ms`);
  assert.equal(DEFAULT_BUDGET_MS, 10 * 60 * 1000);
});

test('a pack that exits clean without writing the tarball is not treated as readable', async () => {
  await assert.rejects(
    awaitRegistryTarball({
      version: '0.6.3',
      destination: 'registry-copy',
      expectedFile: 'backbond-agent-scan-0.6.3.tgz',
      budgetMs: 1,
      pack: () => true,
      exists: () => false,
      sleep: async () => {},
    }),
    /was not readable from the npm registry/,
  );
});

test('the give-up message separates what is already public from what has not run', () => {
  const message = unreadableMessage({ version: '0.6.3', attempts: 12, waitedMs: 600_000 });
  assert.match(message, /ALREADY PUBLISHED, IRREVERSIBLE/);
  assert.match(message, /@backbond\/agent-scan@0\.6\.3 on npm/);
  assert.match(message, /re-tagging or bumping the version is the wrong response/);
  assert.match(message, /NOT DONE YET/);
  assert.match(message, /GitHub release/);
  assert.match(message, /MCP Registry publish/);
  assert.match(message, /re-run this failed job/);
});

test('the publish step republishes nothing on a re-run and still verifies and releases', () => {
  const workflow = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'publish.yml'), 'utf8');
  const step = workflow
    .split('- name: Publish with npm token fallback and verify registry bytes')[1]
    .split('\n      - name:')[0];

  // `npm publish` may appear only in the branch taken when the version is absent.
  const branch = step.split('else')[1].split('fi')[0];
  assert.match(branch, /npm publish/);
  assert.equal(step.split('npm publish').length - 1, 1);
  assert.match(step.split('else')[0], /already published; verifying exact bytes/);

  // Byte verification and the registry-authoritative copy run after the branch closes,
  // so a mid-propagation re-run verifies rather than assumes.
  const afterBranch = step.slice(step.indexOf('\n          fi\n'));
  assert.match(afterBranch, /await-registry-tarball\.js "\$version" registry-copy "\$registry_file"/);
  assert.match(afterBranch, /diff -qr --strip-trailing-cr source-tree\/package registry-tree\/package/);
  assert.match(afterBranch, /cp "registry-copy\/\$registry_file"/);

  // The 30-second budget that killed run 35288486227 must not come back.
  assert.doesNotMatch(step, /for attempt in 1 2 3 4 5 6/);
  assert.doesNotMatch(workflow, /was not observable after 30 seconds/);

  // A post-publish failure has to say the npm version is already public.
  assert.match(step, /already public on npm and cannot be replaced/);

  // The GitHub release step compares existing assets instead of replacing them.
  const releaseStep = workflow
    .split('- name: Create the GitHub release with the exact npm tarball')[1]
    .split('\n      - name:')[0];
  assert.match(releaseStep, /gh release view "\$RELEASE_TAG" >\/dev\/null 2>&1/);
  assert.match(releaseStep, /cmp -s "\$release_file" "release-assets\/\$release_file"/);
});
