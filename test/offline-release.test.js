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

  const archive = path.join(dist, fs.readdirSync(dist).find(name => name.endsWith('.tgz')));
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
});
