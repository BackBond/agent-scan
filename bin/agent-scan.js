#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { questionSet } = require('../lib/assessment.js');
const { sha256 } = require('../lib/canonical.js');
const { discover } = require('../lib/discovery.js');
const { collectEvidence, publicEvidence } = require('../lib/evidence.js');
const { startMcpServer } = require('../lib/mcp-server.js');
const { renderHuman } = require('../lib/output.js');
const { suggestPolicy } = require('../lib/policy.js');
const { createPublicScanRecord, renderCompactRecord } = require('../lib/record.js');
const { createScanReceipt, verifyScanReceipt } = require('../lib/receipt.js');
const { meetsThreshold, SEVERITY_ORDER } = require('../lib/rules.js');
const { toSarif } = require('../lib/sarif.js');
const { scanEvidence, scannerContract } = require('../lib/scanner.js');
const { validateTeaserSubmission } = require('../lib/teaser.js');
const { safeInline } = require('../lib/text.js');

function usage() {
  process.stdout.write(`@backbond/agent-scan — static, local AI-agent tool scanner

Usage:
  agent-scan scan                         Auto-discover and scan known local agent configs.
  agent-scan scan --stdin                 Read a live MCP/OpenAI/Anthropic tool manifest.
  agent-scan scan [artifact options]      Scan intentionally exported evidence.
  agent-scan inspect [artifact options]
  agent-scan mcp                          Serve scan_my_runtime over MCP stdio.
  agent-scan verify-receipt --input receipt.json

Artifact options:
  --config <file>       Claude/Cursor/VS Code/Windsurf/Gemini MCP config (repeatable).
  --tool-schema <file>  BackBond, MCP, OpenAI, Anthropic, or OpenAPI JSON.
  --permissions <file>  backbond-permissions/v1 JSON.
  --trace <file>        backbond-trace/v1 or OpenTelemetry OTLP JSON.
  --stdin               Read a live tool manifest from stdin; use --input for claims.

Scan options:
  --input <file>        Optional v4 claims; hypotheses used only for contradictions.
  --fail-on <severity>  Exit 1 at critical, high, medium, or low; none disables (default: high).
  --receipt <file>      Write a tamper-evident receipt without overwriting.
  --signing-key <file>  Sign the receipt with an Ed25519 private key.
  --record-public <file>  Write a redacted self-run scan record without overwriting.
  --record-include-tool-names  Include tool names in that public record (off by default).
  --record-include-fingerprints  Include input hashes and byte lengths (off by default).
  --require-coverage    Exit 3 unless coverage is complete.
  --suggest-policy      Include non-enforcing disable/wrap and patch templates.
  --json                Emit the complete JSON result.
  --sarif               Emit SARIF 2.1.0 for code scanning and IDEs.

Exit codes: 0 below threshold, 1 threshold met, 2 invalid input or scanner failure, 3 required coverage incomplete.
Static only: scan execution makes no network requests. Package installation may contact the configured npm registry.
`);
}

function fail(message) {
  process.stderr.write(`${safeInline(`agent-scan: ${message}`)}\n`);
  process.exitCode = 2;
}

function parseArgs(argv) {
  const command = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'start';
  const rest = command === argv[0] ? argv.slice(1) : argv;
  const options = {
    command, input: null, stdin: false, json: false, sarif: false, suggestPolicy: false, failOn: 'high',
    requireCoverage: false, recordIncludeToolNames: false, recordIncludeFingerprints: false,
    toolSchemaPath: null, permissionsPath: null, tracePath: null, configPaths: [],
    receiptPath: null, signingKeyPath: null, recordPath: null,
  };
  const paths = {
    '--input': 'input', '--tool-schema': 'toolSchemaPath', '--permissions': 'permissionsPath',
    '--trace': 'tracePath', '--receipt': 'receiptPath', '--signing-key': 'signingKeyPath', '--fail-on': 'failOn',
    '--record-public': 'recordPath',
  };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--help' || argument === '-h') options.command = 'help';
    else if (argument === '--json') options.json = true;
    else if (argument === '--sarif') options.sarif = true;
    else if (argument === '--stdin') options.stdin = true;
    else if (argument === '--suggest-policy') options.suggestPolicy = true;
    else if (argument === '--require-coverage') options.requireCoverage = true;
    else if (argument === '--record-include-tool-names') options.recordIncludeToolNames = true;
    else if (argument === '--record-include-fingerprints') options.recordIncludeFingerprints = true;
    else if (argument === '--config') {
      const value = rest[index + 1];
      if (!value || value.startsWith('--')) throw new Error('--config needs a value');
      options.configPaths.push(value);
      index += 1;
    } else if (paths[argument]) {
      const value = rest[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${argument} needs a value`);
      options[paths[argument]] = value;
      index += 1;
    } else if (argument.startsWith('--')) throw new Error(`unknown option: ${argument}`);
    else throw new Error(`unexpected argument: ${argument}`);
  }
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, options.failOn)) throw new Error('--fail-on must be critical, high, medium, low, or none');
  if (options.json && options.sarif) throw new Error('use either --json or --sarif, not both');
  if ((options.recordIncludeToolNames || options.recordIncludeFingerprints) && !options.recordPath) {
    throw new Error('record disclosure options require --record-public <file>');
  }
  return options;
}

async function readStdin() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  return input;
}

async function loadStdinManifest(options) {
  if (!options.stdin) return [];
  const raw = await readStdin();
  if (!raw.trim()) throw new Error('stdin tool manifest is empty');
  let document;
  try { document = JSON.parse(raw); }
  catch (error) { throw new Error(`stdin tool manifest is not valid JSON: ${error.message}`); }
  if (document && document.protocol === 'backbond-agent-teaser/v4') throw new Error('--stdin accepts a live tool manifest; use --input <file> for claims');
  return [{ kind: 'tool_schema', name: '<stdin>', document, raw }];
}

function loadClaims(options) {
  if (!options.input) return { submission: null, metadata: null };
  const bytes = fs.readFileSync(options.input);
  if (!bytes.toString('utf8').trim()) throw new Error('claim document is empty');
  let submission;
  try { submission = JSON.parse(bytes.toString('utf8')); }
  catch (error) { throw new Error(`claim document is not valid JSON: ${error.message}`); }
  validateTeaserSubmission(submission);
  return {
    submission,
    metadata: { kind: 'claims', name: path.basename(path.resolve(options.input)), bytes: bytes.length, sha256: sha256(bytes), dialect: submission.protocol },
  };
}

function writeNew(filename, value) {
  const target = path.resolve(filename);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return target;
}

function hasExplicitArtifacts(options) {
  return Boolean(options.toolSchemaPath || options.permissionsPath || options.tracePath || options.configPaths.length || options.stdin);
}

function recordScopeMode(options) {
  if (options.stdin) return 'live-manifest';
  return hasExplicitArtifacts(options) ? 'explicit-artifacts' : 'discovery';
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { fail(error.message); return; }
  if (options.command === 'help') { usage(); return; }
  if (options.command === 'start') { process.stdout.write(`${JSON.stringify(scannerContract(), null, 2)}\n`); return; }
  if (options.command === 'questions') { process.stdout.write(`${JSON.stringify(questionSet(), null, 2)}\n`); return; }
  if (options.command === 'mcp') { startMcpServer(); return; }

  try {
    if (options.command === 'verify-receipt') {
      if (options.stdin || !options.input) throw new Error('verify-receipt requires --input <file>');
      let receipt;
      try { receipt = JSON.parse(fs.readFileSync(options.input, 'utf8')); }
      catch (error) { throw new Error(`receipt is not valid JSON: ${error.message}`); }
      const valid = verifyScanReceipt(receipt);
      process.stdout.write(`${JSON.stringify({ valid, protocol: receipt.protocol || null })}\n`);
      if (!valid) process.exitCode = 1;
      return;
    }
    if (!['scan', 'inspect'].includes(options.command)) throw new Error(`unknown command: ${options.command}`);
    if (options.command === 'inspect' && (options.recordPath || options.requireCoverage)) {
      throw new Error('--record-public and --require-coverage are scan options');
    }
    const documents = await loadStdinManifest(options);
    const plan = hasExplicitArtifacts(options) ? null : discover();
    const artifactPaths = [
      ...options.configPaths.map(filename => ({ kind: 'config', path: filename, adapter: 'explicit' })),
      ...(plan ? plan.files : []),
    ];
    const now = new Date();
    const evidence = collectEvidence({
      now, documents, artifactPaths, discovery: plan,
      toolSchemaPath: options.toolSchemaPath, permissionsPath: options.permissionsPath, tracePath: options.tracePath,
    });
    if (options.command === 'inspect') {
      process.stdout.write(`${JSON.stringify(publicEvidence(evidence), null, 2)}\n`);
      return;
    }
    const claims = loadClaims(options);
    const scan = scanEvidence(evidence, { now, claims: claims.submission });
    const policy = options.suggestPolicy ? suggestPolicy(scan) : null;
    const receipt = createScanReceipt(scan, { claimInput: claims.metadata, signingKeyPath: options.signingKeyPath });
    const receiptPath = options.receiptPath ? writeNew(options.receiptPath, receipt) : null;
    const record = options.recordPath ? createPublicScanRecord(scan, receipt, {
      mode: recordScopeMode(options),
      includeToolNames: options.recordIncludeToolNames,
      includeFingerprints: options.recordIncludeFingerprints,
    }) : null;
    const recordPath = record ? writeNew(options.recordPath, record) : null;
    const output = { ...scan, receipt, receipt_path: receiptPath, policy_suggestion: policy };
    if (record) {
      output.public_record = record;
      output.public_record_path = recordPath;
    }
    if (options.json) process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    else if (options.sarif) process.stdout.write(`${JSON.stringify(toSarif(scan), null, 2)}\n`);
    else {
      process.stdout.write(renderHuman(scan, { policy, receiptPath }));
      if (record) process.stdout.write(`\n${renderCompactRecord(record)}\n${safeInline(`Saved: ${recordPath}`)}\n`);
    }
    if (meetsThreshold(scan.findings, options.failOn)) process.exitCode = 1;
    else if (options.requireCoverage && scan.coverage.status !== 'complete') process.exitCode = 3;
  } catch (error) {
    fail(error.message);
  }
}

main().catch(error => fail(`unexpected error: ${error.message}`));
