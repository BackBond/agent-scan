#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { verifyPublicScanRecord } = require('../lib/record.js');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'agent-scan.js');
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

function getInput(name, fallback = '') {
  const key = `INPUT_${name.toUpperCase()}`;
  const underscored = key.replaceAll('-', '_');
  return String(process.env[key] || process.env[underscored] || fallback).trim();
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: options.cwd,
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
    maxBuffer: MAX_OUTPUT_BYTES,
  });
}

function git(workspace, args) {
  const result = run('git', args, { cwd: workspace });
  if (result.error) throw new Error(`could not run git: ${result.error.message}`);
  return result;
}

function isInside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function verifyCheckout(workspace, expectedCommit) {
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(expectedCommit)) {
    throw new Error('GITHUB_SHA must be a full 40- or 64-character lowercase hexadecimal commit');
  }
  const result = git(workspace, ['rev-parse', 'HEAD']);
  if (result.status !== 0) throw new Error(`could not resolve checkout HEAD: ${result.stderr.trim()}`);
  const actual = result.stdout.trim().toLowerCase();
  if (actual !== expectedCommit) {
    throw new Error(`checkout HEAD ${actual} does not match GITHUB_SHA ${expectedCommit}`);
  }
  return actual;
}

function resolveTrackedInput(workspace, filename, label) {
  const candidate = path.resolve(workspace, filename);
  if (!fs.existsSync(candidate)) throw new Error(`${label} does not exist: ${filename}`);
  const target = fs.realpathSync(candidate);
  if (!isInside(workspace, target)) throw new Error(`${label} must resolve inside GITHUB_WORKSPACE`);
  if (!fs.statSync(target).isFile()) throw new Error(`${label} must be a file: ${filename}`);
  const relative = path.relative(workspace, target).split(path.sep).join('/');
  const tracked = git(workspace, ['ls-files', '--error-unmatch', '--', relative]);
  if (tracked.status !== 0) throw new Error(`${label} is not tracked by the verified commit: ${relative}`);
  const clean = git(workspace, ['diff', '--quiet', 'HEAD', '--', relative]);
  if (clean.status !== 0) throw new Error(`${label} differs from the verified commit: ${relative}`);
  return { absolute: target, relative };
}

function resolveRecordPath(workspace, filename) {
  const target = path.resolve(workspace, filename);
  if (!isInside(workspace, target)) throw new Error('record-path must stay inside GITHUB_WORKSPACE');
  if (fs.existsSync(target)) throw new Error(`record-path already exists and will not be overwritten: ${filename}`);
  let existingAncestor = path.dirname(target);
  while (!fs.existsSync(existingAncestor)) {
    const parent = path.dirname(existingAncestor);
    if (parent === existingAncestor) throw new Error('record-path has no existing parent');
    existingAncestor = parent;
  }
  if (!isInside(workspace, fs.realpathSync(existingAncestor))) {
    throw new Error('record-path parent must resolve inside GITHUB_WORKSPACE');
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const parent = fs.realpathSync(path.dirname(target));
  if (!isInside(workspace, parent)) throw new Error('record-path parent must resolve inside GITHUB_WORKSPACE');
  return target;
}

function appendKeyValue(filename, key, value) {
  if (!filename) return;
  fs.appendFileSync(filename, `${key}=${String(value).replace(/[\r\n]/g, '')}\n`, 'utf8');
}

function countSummary(summary) {
  const parts = Object.entries(summary).filter(([, count]) => count > 0).map(([severity, count]) => `${count} ${severity}`);
  return parts.length ? parts.join(', ') : 'none observed';
}

function renderJobSummary(record, commit) {
  const ids = [...new Set(record.result.findings.map(item => item.id))].sort();
  const gaps = record.result.coverage.gaps;
  return [
    '## BackBond agent-scan',
    '',
    `- Checkout and explicit input files verified against \`${commit}\` by the pinned Action.`,
    `- Interpretation: **${record.result.interpretation}**`,
    `- Findings: ${countSummary(record.result.summary)}${ids.length ? ` (${ids.join(', ')})` : ''}`,
    `- Coverage: ${record.result.coverage.status}${gaps.length ? ` (${gaps.join(', ')})` : ''}`,
    `- Record integrity: \`${record.integrity.sha256}\``,
    `- Assurance: ${record.assurance.statement}`,
    '',
    'The Action verified this checkout for this run. The portable record remains self-run and unverified; it is not a safety certificate or BackBond attestation.',
    '',
  ].join('\n');
}

function main() {
  try {
    const workspaceValue = process.env.GITHUB_WORKSPACE;
    const expectedCommit = String(process.env.GITHUB_SHA || '').trim().toLowerCase();
    if (!workspaceValue) throw new Error('GITHUB_WORKSPACE is required');
    const workspace = fs.realpathSync(workspaceValue);
    const commit = verifyCheckout(workspace, expectedCommit);
    const inputDefinitions = [
      ['tool-schema', '--tool-schema'],
      ['permissions', '--permissions'],
      ['trace', '--trace'],
      ['config', '--config'],
    ];
    const supplied = inputDefinitions
      .map(([name, flag]) => ({ name, flag, value: getInput(name) }))
      .filter(item => item.value)
      .map(item => ({ ...item, file: resolveTrackedInput(workspace, item.value, item.name) }));
    if (!supplied.length) {
      throw new Error('at least one explicit tracked input is required: tool-schema, permissions, trace, or config');
    }
    const recordPath = resolveRecordPath(workspace, getInput('record-path', 'backbond-scan-record.json'));
    const args = [
      CLI, 'scan', '--require-coverage',
      '--fail-on', getInput('fail-on', 'high'),
      '--fail-on-prompt', getInput('fail-on-prompt', 'none'),
      '--record-public', recordPath,
      '--record-commit', commit,
    ];
    for (const input of supplied) args.push(input.flag, input.file.absolute);
    const scan = run(process.execPath, args, { cwd: workspace });
    if (scan.stdout) process.stdout.write(scan.stdout);
    if (scan.stderr) process.stderr.write(scan.stderr);
    if (scan.error) throw new Error(`scanner failed to start: ${scan.error.message}`);

    if (fs.existsSync(recordPath)) {
      const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
      if (!verifyPublicScanRecord(record)) throw new Error('generated public record failed its integrity check');
      if (!record.source || record.source.git_commit !== commit) throw new Error('generated public record does not reference the verified commit');
      appendKeyValue(process.env.GITHUB_OUTPUT, 'record-path', recordPath);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'record-sha256', record.integrity.sha256);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'commit', commit);
      if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, renderJobSummary(record, commit), 'utf8');
    }
    process.exitCode = Number.isInteger(scan.status) ? scan.status : 2;
  } catch (error) {
    process.stderr.write(`BackBond agent-scan Action: ${String(error.message).replace(/[\r\n]/g, ' ')}\n`);
    process.exitCode = 2;
  }
}

if (require.main === module) main();

module.exports = {
  getInput,
  isInside,
  main,
  renderJobSummary,
  resolveRecordPath,
  resolveTrackedInput,
  verifyCheckout,
};
