#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { questionSet } = require('../lib/assessment.js');
const { sha256 } = require('../lib/canonical.js');
const { collectEvidence, publicEvidence } = require('../lib/evidence.js');
const { createScanReceipt, verifyScanReceipt } = require('../lib/receipt.js');
const { meetsThreshold, SEVERITY_ORDER } = require('../lib/rules.js');
const { scanEvidence, scannerContract } = require('../lib/scanner.js');
const { validateTeaserSubmission } = require('../lib/teaser.js');

function usage() {
  process.stdout.write(`@backbond/agent-scan — local deterministic AI-agent evidence scanner

Usage:
  agent-scan scan [artifact options] [--input claims.json] [--fail-on high] [--json]
  agent-scan inspect [artifact options]
  agent-scan verify-receipt --input receipt.json
  agent-scan start

Artifact options:
  --tool-schema <file>  Supported tool/function schema JSON.
  --permissions <file>  backbond-permissions/v1 JSON.
  --trace <file>        backbond-trace/v1 JSON.

Scan options:
  --input <file>        Optional v4 claim document; used only for contradictions.
  --stdin               Read the optional claim document from stdin.
  --fail-on <severity>  Exit 1 at critical, high, medium, or low; none disables (default: high).
  --receipt <file>      Write the tamper-evident scan receipt without overwriting.
  --signing-key <file>  Optionally sign the receipt with an Ed25519 private key.
  --json                Emit the complete JSON result.

Exit codes: 0 below threshold, 1 threshold met, 2 invalid input or scanner failure.
The scanner performs no network requests and requires no private analyzer.
`);
}

function fail(message) {
  process.stderr.write(`agent-scan: ${message}\n`);
  process.exitCode = 2;
}

function parseArgs(argv) {
  const command = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'start';
  const rest = command === argv[0] ? argv.slice(1) : argv;
  const options = {
    command, input: null, stdin: false, json: false, failOn: 'high',
    toolSchemaPath: null, permissionsPath: null, tracePath: null,
    receiptPath: null, signingKeyPath: null,
  };
  const paths = {
    '--input': 'input', '--tool-schema': 'toolSchemaPath', '--permissions': 'permissionsPath',
    '--trace': 'tracePath', '--receipt': 'receiptPath', '--signing-key': 'signingKeyPath',
    '--fail-on': 'failOn',
  };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--help' || argument === '-h') options.command = 'help';
    else if (argument === '--json') options.json = true;
    else if (argument === '--stdin') options.stdin = true;
    else if (paths[argument]) {
      const value = rest[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${argument} needs a value`);
      options[paths[argument]] = value;
      index += 1;
    } else if (argument.startsWith('--')) throw new Error(`unknown option: ${argument}`);
    else throw new Error(`unexpected argument: ${argument}`);
  }
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, options.failOn)) throw new Error('--fail-on must be critical, high, medium, low, or none');
  if (options.stdin && options.input) throw new Error('use either --stdin or --input, not both');
  return options;
}

async function readStdin() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  return input;
}

async function loadClaims(options) {
  if (!options.stdin && !options.input) return { submission: null, metadata: null };
  const raw = options.stdin ? await readStdin() : fs.readFileSync(options.input);
  const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8');
  if (!bytes.toString('utf8').trim()) throw new Error('claim document is empty');
  let submission;
  try { submission = JSON.parse(bytes.toString('utf8')); }
  catch (error) { throw new Error(`claim document is not valid JSON: ${error.message}`); }
  validateTeaserSubmission(submission);
  return {
    submission,
    metadata: {
      kind: 'claims',
      name: options.input ? path.basename(path.resolve(options.input)) : '<stdin>',
      bytes: bytes.length,
      sha256: sha256(bytes),
      dialect: submission.protocol,
    },
  };
}

function requireArtifacts(options) {
  if (!options.toolSchemaPath && !options.permissionsPath && !options.tracePath) {
    throw new Error('scan requires at least one of --tool-schema, --permissions, or --trace');
  }
}

function writeNew(filename, value) {
  const target = path.resolve(filename);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return target;
}

function renderHuman(scan, threshold, receiptPath) {
  process.stdout.write(`\nBackBond local scan: ${scan.summary.total} finding(s)\n`);
  process.stdout.write(`Coverage: ${scan.coverage.status}${scan.coverage.gaps.length ? ` (${scan.coverage.gaps.length} gap(s))` : ''}\n`);
  for (const item of scan.findings) {
    process.stdout.write(`\n[${item.severity.toUpperCase()}] ${item.id} ${item.title}\n`);
    process.stdout.write(`  ${item.detail}\n`);
    process.stdout.write(`  Fix: ${item.remediation}\n`);
  }
  if (scan.claim_contradictions.length) process.stdout.write(`\nClaim contradictions: ${scan.claim_contradictions.map(item => item.code).join(', ')}\n`);
  if (scan.coverage.gaps.length) process.stdout.write(`Coverage gaps: ${scan.coverage.gaps.map(item => item.code).join(', ')}\n`);
  if (receiptPath) process.stdout.write(`Receipt: ${receiptPath}\n`);
  process.stdout.write(`Threshold: ${threshold}\n\n`);
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { fail(error.message); return; }
  if (options.command === 'help') { usage(); return; }
  if (options.command === 'start') { process.stdout.write(`${JSON.stringify(scannerContract(), null, 2)}\n`); return; }
  if (options.command === 'questions') { process.stdout.write(`${JSON.stringify(questionSet(), null, 2)}\n`); return; }

  try {
    if (options.command === 'verify-receipt') {
      if (options.stdin || !options.input) throw new Error('verify-receipt requires --input <file>');
      const raw = fs.readFileSync(options.input, 'utf8');
      let receipt;
      try { receipt = JSON.parse(raw); }
      catch (error) { throw new Error(`receipt is not valid JSON: ${error.message}`); }
      const valid = verifyScanReceipt(receipt);
      process.stdout.write(`${JSON.stringify({ valid, protocol: receipt.protocol || null })}\n`);
      if (!valid) process.exitCode = 1;
      return;
    }
    if (!['scan', 'inspect'].includes(options.command)) throw new Error(`unknown command: ${options.command}`);
    requireArtifacts(options);
    const now = new Date();
    const evidence = collectEvidence({
      now,
      toolSchemaPath: options.toolSchemaPath,
      permissionsPath: options.permissionsPath,
      tracePath: options.tracePath,
    });
    if (options.command === 'inspect') {
      process.stdout.write(`${JSON.stringify(publicEvidence(evidence), null, 2)}\n`);
      return;
    }
    const claims = await loadClaims(options);
    const scan = scanEvidence(evidence, { now, claims: claims.submission });
    const receipt = createScanReceipt(scan, { claimInput: claims.metadata, signingKeyPath: options.signingKeyPath });
    const receiptPath = options.receiptPath ? writeNew(options.receiptPath, receipt) : null;
    const output = { ...scan, receipt, receipt_path: receiptPath };
    if (options.json) process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    else renderHuman(scan, options.failOn, receiptPath);
    if (meetsThreshold(scan.findings, options.failOn)) process.exitCode = 1;
  } catch (error) {
    fail(error.message);
  }
}

main().catch(error => fail(`unexpected error: ${error.message}`));
