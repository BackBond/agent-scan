'use strict';

const fs = require('node:fs');
const { isDeepStrictEqual } = require('node:util');

const OFFICIAL_REGISTRY = 'https://registry.modelcontextprotocol.io';

function exactRegistryUrl(registryUrl, name, version) {
  return new URL(
    `/v0.1/servers/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
    registryUrl,
  );
}

function requireMatchingPackage(body, manifest, card) {
  const server = body && (body.server || body);
  if (!server || server.name !== card.name || server.version !== card.version) {
    throw new Error('MCP Registry response does not match the requested server name and version');
  }
  const npmPackage = (server.packages || []).find(item => item.registryType === 'npm');
  if (!npmPackage || npmPackage.identifier !== manifest.name || npmPackage.version !== manifest.version) {
    throw new Error('MCP Registry version does not match the npm package metadata');
  }
  if (!isDeepStrictEqual(server.packages || [], card.packages || [])) {
    throw new Error('MCP Registry package launch descriptor does not match server.json');
  }
  if (!isDeepStrictEqual(server.remotes || [], card.remotes || [])) {
    throw new Error('MCP Registry remote launch descriptor does not match server.json');
  }
  if (!isDeepStrictEqual(server.repository || null, card.repository || null)) {
    throw new Error('MCP Registry repository identity does not match server.json');
  }
  return server;
}

async function checkRegistryVersion({ fetchImpl = fetch, registryUrl = OFFICIAL_REGISTRY, manifest, card }) {
  const response = await fetchImpl(exactRegistryUrl(registryUrl, card.name, card.version));
  if (response.status === 404) return false;
  if (!response.ok) throw new Error(`MCP Registry lookup failed: ${response.status}`);
  requireMatchingPackage(await response.json(), manifest, card);
  return true;
}

async function main() {
  const manifest = require('../package.json');
  const card = require('../server.json');
  const published = await checkRegistryVersion({ manifest, card });
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `published=${published}\n`);
  }
  process.stdout.write(`${published ? 'published' : 'not_published'} ${card.name}@${card.version}\n`);
  if (process.argv.includes('--require-published') && !published) process.exitCode = 1;
}

if (require.main === module) {
  main().catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { OFFICIAL_REGISTRY, checkRegistryVersion, exactRegistryUrl, requireMatchingPackage };
