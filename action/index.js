#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { verifyPublicScanRecord } = require('../lib/record.js');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'agent-scan.js');
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const NEXT_STEP = 'Running this check does not create coverage or determine eligibility. Need deeper assessment, continuous runtime evidence, or information about financial protection where approved? [Contact BackBond](mailto:hello@backbond.ai).';

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
    NEXT_STEP,
    '',
  ].join('\n');
}

function renderVetJobSummary(result, commit) {
  const ids = [...new Set(result.findings.map(item => item.id))].sort();
  const gaps = result.coverage.gaps.map(item => item.code);
  const patches = result.policy_suggestion && Array.isArray(result.policy_suggestion.patches)
    ? result.policy_suggestion.patches
    : [];
  const patchIds = [...new Set(patches.map(item => item.finding_id))].sort();
  return [
    '## BackBond Schema Check',
    '',
    `- Checkout and tool manifest verified against \`${commit}\` by the pinned Action.`,
    `- Decision: **${result.decision}**`,
    `- Findings: ${countSummary(result.summary.by_severity)}${ids.length ? ` (${ids.join(', ')})` : ''}`,
    `- Coverage: ${result.coverage.status}${gaps.length ? ` (${gaps.join(', ')})` : ''}`,
    `- Scanner: \`${result.scanner.name}@${result.scanner.version}\``,
    `- Ruleset: \`${result.ruleset.version}\` (\`${result.ruleset.sha256}\`)`,
    `- Review-only remediation templates: ${patches.length}${patchIds.length ? ` (${patchIds.join(', ')})` : ''}`,
    '',
    'This committed manifest passed only when the decision is `no_blocking_finding`. This is a static pre-attachment check, not runtime verification, insurance coverage, or proof that a deployed server matches the manifest.',
    '',
    NEXT_STEP,
    '',
  ].join('\n');
}

function parseVetResult(output) {
  let result;
  try { result = JSON.parse(output); }
  catch (error) { throw new Error(`vet-tools returned invalid JSON: ${error.message}`); }
  if (!result || result.protocol !== 'backbond-pre-attach/v1') throw new Error('vet-tools returned an unexpected protocol');
  if (!['block', 'review', 'no_blocking_finding'].includes(result.decision)) throw new Error('vet-tools returned an unexpected decision');
  if (!result.coverage || !['complete', 'partial'].includes(result.coverage.status)) throw new Error('vet-tools returned an unexpected coverage status');
  return result;
}

function main() {
  try {
    const workspaceValue = process.env.GITHUB_WORKSPACE;
    const expectedCommit = String(process.env.GITHUB_SHA || '').trim().toLowerCase();
    if (!workspaceValue) throw new Error('GITHUB_WORKSPACE is required');
    const workspace = fs.realpathSync(workspaceValue);
    const commit = verifyCheckout(workspace, expectedCommit);
    const mode = getInput('mode', 'scan');
    if (!['scan', 'vet-tools'].includes(mode)) throw new Error('mode must be scan or vet-tools');
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
    appendKeyValue(process.env.GITHUB_OUTPUT, 'commit', commit);

    if (mode === 'vet-tools') {
      if (supplied.length !== 1 || supplied[0].name !== 'tool-schema') {
        throw new Error('vet-tools mode requires exactly one tracked tool-schema input and accepts no permissions, trace, or config input');
      }
      const vet = run(process.execPath, [
        CLI, 'vet-tools', '--tool-schema', supplied[0].file.absolute, '--json', '--suggest-policy',
      ], { cwd: workspace });
      if (vet.stderr) process.stderr.write(vet.stderr);
      if (vet.error) throw new Error(`scanner failed to start: ${vet.error.message}`);
      const result = parseVetResult(vet.stdout);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'decision', result.decision);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'coverage-status', result.coverage.status);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'finding-count', result.summary.total);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'ruleset-sha256', result.ruleset.sha256);
      process.stdout.write(`BackBond Schema Check: ${result.decision}; ${result.summary.total} finding(s); coverage ${result.coverage.status}\n`);
      if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, renderVetJobSummary(result, commit), 'utf8');
      process.exitCode = Number.isInteger(vet.status) ? vet.status : 2;
      return;
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
      appendKeyValue(process.env.GITHUB_OUTPUT, 'coverage-status', record.result.coverage.status);
      appendKeyValue(process.env.GITHUB_OUTPUT, 'finding-count', Object.values(record.result.summary).reduce((total, count) => total + count, 0));
      appendKeyValue(process.env.GITHUB_OUTPUT, 'ruleset-sha256', record.ruleset.sha256);
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
  parseVetResult,
  renderJobSummary,
  renderVetJobSummary,
  resolveRecordPath,
  resolveTrackedInput,
  verifyCheckout,
};
