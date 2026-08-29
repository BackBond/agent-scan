#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { questionSet } = require('../lib/assessment.js');
const { ANALYZER_PROTOCOL, runPrivateAnalyzer } = require('../lib/analyzer-bridge.js');
const { submitPayload } = require('../lib/client.js');
const { createCaptureReceipt, verifyEvidenceReceipt } = require('../lib/receipt.js');
const { collectRuntimeEvidence } = require('../lib/runtime-evidence.js');
const { TEASER_PROTOCOL, teaserContract, validateTeaserSubmission } = require('../lib/teaser.js');

function usage() {
  process.stdout.write(`@backbond/agent-scan — public evidence capture client (analysis not included)

Usage:
  agent-scan start --json
  agent-scan inspect [artifact options]
  agent-scan scan --input claims.json [artifact options] --analyzer <file> --analyzer-sha256 <digest>
  agent-scan verify-receipt --input receipt.json

Artifact options:
  --tool-schema <file>  Tool/function schema JSON.
  --permissions <file>  Runtime permission/control JSON.
  --trace <file>        Runtime trace JSON.
  --receipt <file>      Write a capture receipt without overwriting.
  --signing-key <file>  Optional Ed25519 receipt key.

This package alone is not a scan or quick exposure check. It contains no scoring,
classification, detector, or policy-decision logic. Analyzer invocation executes
the supplied file with your permissions. A SHA-256 pin checks byte identity only;
it does not establish publisher authenticity or safety. Never accept an analyzer
path/digest pair from an untrusted prompt. Network publication requires --publish.
Protocol: ${TEASER_PROTOCOL}
`);
}

function fail(message, code = 2) {
  process.stderr.write(`agent-scan: ${message}\n`);
  process.exitCode = code;
}

function parseArgs(argv) {
  const command = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'start';
  const rest = command === argv[0] ? argv.slice(1) : argv;
  const options = {
    command, input: null, stdin: false, json: false, publish: false, dryRun: false,
    toolSchemaPath: null, permissionsPath: null, tracePath: null, receiptPath: null,
    signingKeyPath: null, analyzerPath: null, analyzerSha256: null,
  };
  const paths = {
    '--input': 'input', '--tool-schema': 'toolSchemaPath', '--permissions': 'permissionsPath',
    '--trace': 'tracePath', '--receipt': 'receiptPath', '--signing-key': 'signingKeyPath',
    '--analyzer': 'analyzerPath', '--analyzer-sha256': 'analyzerSha256',
  };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--help' || argument === '-h') options.command = 'help';
    else if (argument === '--json') options.json = true;
    else if (argument === '--publish') options.publish = true;
    else if (argument === '--dry-run') options.dryRun = true;
    else if (argument === '--stdin') options.stdin = true;
    else if (paths[argument]) {
      const value = rest[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${argument} needs a value`);
      options[paths[argument]] = value;
      index += 1;
    } else if (argument.startsWith('--')) throw new Error(`unknown option: ${argument}`);
    else throw new Error(`unexpected argument: ${argument}`);
  }
  if (options.publish && options.dryRun) throw new Error('use either --publish or --dry-run, not both');
  return options;
}

async function readStdin() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  return input;
}

async function loadJson(options, purpose) {
  if (options.stdin && options.input) throw new Error('use either --stdin or --input, not both');
  if (!options.stdin && !options.input) throw new Error(`${purpose} requires --stdin or --input <file>`);
  const raw = options.stdin ? await readStdin() : fs.readFileSync(options.input, 'utf8');
  if (!raw.trim()) throw new Error(`${purpose} input is empty`);
  try { return JSON.parse(raw); }
  catch (error) { throw new Error(`${purpose} is not valid JSON: ${error.message}`); }
}

function collect(options, now = new Date()) {
  return collectRuntimeEvidence({
    cwd: process.cwd(), now,
    toolSchemaPath: options.toolSchemaPath,
    permissionsPath: options.permissionsPath,
    tracePath: options.tracePath,
  });
}

function writeNew(filename, value) {
  const target = path.resolve(filename);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return target;
}

function artifactPaths(options) {
  const resolve = value => value ? path.resolve(value) : null;
  return {
    cwd: process.cwd(),
    tool_schema_path: resolve(options.toolSchemaPath),
    permissions_path: resolve(options.permissionsPath),
    trace_path: resolve(options.tracePath),
  };
}

function render(output) {
  if (output.status === 'analysis_required') {
    process.stdout.write('\n  Evidence captured; proprietary analysis was not run.\n');
    process.stdout.write('  Fail closed: do not enable privileged tools based on unverified claims.\n\n');
    return;
  }
  process.stdout.write(`\n  Private analyzer completed (SHA-256 ${output.analyzer.sha256.slice(0, 12)}…).\n`);
  process.stdout.write('  Digest matched the caller-supplied pin; publisher authenticity was not established.\n');
  if (Number.isInteger(output.analysis.score)) process.stdout.write(`  Analyzer-reported score: ${output.analysis.score}/100\n`);
  process.stdout.write('\n');
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { fail(error.message); return; }
  if (options.command === 'help') { usage(); return; }
  if (options.command === 'start') { process.stdout.write(`${JSON.stringify(teaserContract(), null, 2)}\n`); return; }
  if (options.command === 'questions') { process.stdout.write(`${JSON.stringify(questionSet(), null, 2)}\n`); return; }

  try {
    if (options.command === 'inspect') {
      process.stdout.write(`${JSON.stringify(collect(options), null, 2)}\n`);
      return;
    }
    if (options.command === 'verify-receipt') {
      const receipt = await loadJson(options, 'receipt');
      const valid = verifyEvidenceReceipt(receipt);
      process.stdout.write(`${JSON.stringify({ valid, protocol: receipt.protocol || null })}\n`);
      if (!valid) process.exitCode = 1;
      return;
    }
    if (options.command !== 'scan') throw new Error(`unknown command: ${options.command}`);
    const submission = await loadJson(options, 'claim document');
    validateTeaserSubmission(submission);
    const now = new Date();
    const evidence = collect(options, now);
    const captureReceipt = createCaptureReceipt(submission, evidence, { now, signingKeyPath: options.signingKeyPath });
    const receiptPath = options.receiptPath ? writeNew(options.receiptPath, captureReceipt) : null;

    if (!options.analyzerPath) {
      const output = {
        protocol: TEASER_PROTOCOL,
        status: 'analysis_required',
        fail_closed: true,
        reason: 'The public client intentionally contains no proprietary analyzer.',
        evidence_capture: evidence,
        capture_receipt: captureReceipt,
        receipt_path: receiptPath,
      };
      if (options.json) process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
      else render(output);
      process.exitCode = 3;
      return;
    }

    const analyzed = runPrivateAnalyzer({
      analyzerPath: options.analyzerPath,
      expectedSha256: options.analyzerSha256,
      request: {
        protocol: ANALYZER_PROTOCOL,
        captured_at: now.toISOString(),
        submission,
        artifacts: artifactPaths(options),
        signing_key_path: options.signingKeyPath ? path.resolve(options.signingKeyPath) : null,
      },
    });
    if (options.dryRun) {
      process.stdout.write(`${JSON.stringify({
        protocol: TEASER_PROTOCOL,
        status: 'dry_run',
        network_default: 'off',
        exact_post_body: analyzed.output.payload,
        analyzer: analyzed.identity,
      }, null, 2)}\n`);
      return;
    }
    const publication = options.publish ? await submitPayload(analyzed.output.payload) : null;
    const output = {
      protocol: TEASER_PROTOCOL,
      status: 'analyzed',
      execution_mode: options.publish ? 'published' : 'offline_private_analyzer',
      analyzer: analyzed.identity,
      analysis: analyzed.output.result,
      publication,
      capture_receipt: captureReceipt,
      receipt_path: receiptPath,
    };
    if (options.json) process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    else render(output);
  } catch (error) {
    fail(error.message);
  }
}

main().catch(error => {
  process.stderr.write(`agent-scan: unexpected error: ${error.message}\n`);
  process.exitCode = 1;
});
