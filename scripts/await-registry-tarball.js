'use strict';

// The npm registry serves a freshly published version some time after `npm publish`
// returns; npm's own output says propagation "may take a few minutes". The release
// job's irreversible step is the publish itself, so the wait that follows it must
// outlast realistic propagation instead of failing the job after the package is
// already public (BEAAA-33614).

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');

const PACKAGE_NAME = '@backbond/agent-scan';
const DEFAULT_BUDGET_MS = 10 * 60 * 1000;
const FIRST_DELAY_MS = 5_000;
const MAX_DELAY_MS = 30_000;

function unreadableMessage({ version, attempts, waitedMs }) {
  const waitedSeconds = Math.round(waitedMs / 1000);
  return [
    `Refusing release: ${PACKAGE_NAME}@${version} was not readable from the npm registry`,
    `after ${attempts} attempts over ${waitedSeconds}s.`,
    '',
    'ALREADY PUBLISHED, IRREVERSIBLE:',
    `  ${PACKAGE_NAME}@${version} on npm. An npm version can never be republished or`,
    '  overwritten, so re-tagging or bumping the version is the wrong response.',
    '',
    'NOT DONE YET:',
    '  registry byte verification, the GitHub release and its agent-scan.cjs,',
    '  agent-scan.cjs.sha256, tarball and tarball .sha256 assets, and the official',
    '  MCP Registry publish.',
    '',
    'NEXT STEP:',
    '  re-run this failed job once the registry serves the version. Every step is',
    '  idempotent: the publish step verifies the existing bytes instead of',
    '  republishing, and the release step compares existing assets instead of',
    '  replacing them.',
  ].join('\n');
}

function packFromRegistry(version, destination) {
  const result = spawnSync(
    'npm',
    ['pack', `${PACKAGE_NAME}@${version}`, '--pack-destination', destination, '--silent'],
    { encoding: 'utf8' },
  );
  return result.status === 0;
}

// Five seconds, then doubling to a thirty-second ceiling, so a fast propagation is
// still caught in seconds while a slow one is not punished with a tight poll.
function nextDelay(current) {
  return Math.min(current * 2, MAX_DELAY_MS);
}

async function awaitRegistryTarball({
  version,
  destination,
  expectedFile,
  budgetMs = DEFAULT_BUDGET_MS,
  pack = packFromRegistry,
  sleep = delay,
  exists = (file) => fs.existsSync(file),
}) {
  let waitedMs = 0;
  let pause = FIRST_DELAY_MS;

  for (let attempts = 1; ; attempts += 1) {
    if (pack(version, destination) && exists(path.join(destination, expectedFile))) {
      return { attempts, waitedMs };
    }
    if (waitedMs + pause > budgetMs) {
      throw new Error(unreadableMessage({ version, attempts, waitedMs }));
    }
    await sleep(pause);
    waitedMs += pause;
    pause = nextDelay(pause);
  }
}

module.exports = {
  DEFAULT_BUDGET_MS,
  FIRST_DELAY_MS,
  MAX_DELAY_MS,
  PACKAGE_NAME,
  awaitRegistryTarball,
  unreadableMessage,
};

if (require.main === module) {
  const [version, destination, expectedFile] = process.argv.slice(2);
  if (!version || !destination || !expectedFile) {
    console.error('usage: await-registry-tarball.js <version> <destination> <expected-file>');
    process.exit(2);
  }
  awaitRegistryTarball({ version, destination, expectedFile }).then(
    ({ attempts, waitedMs }) => {
      console.log(
        `${PACKAGE_NAME}@${version} readable from the npm registry after ${attempts} attempts (${Math.round(waitedMs / 1000)}s).`,
      );
    },
    (error) => {
      console.error(error.message);
      process.exit(1);
    },
  );
}
