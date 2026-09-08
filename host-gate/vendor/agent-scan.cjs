#!/usr/bin/env node
'use strict';

/*
 * @backbond/agent-scan standalone release asset.
 * Generated deterministically by scripts/build-standalone.js.
 * Local modules are embedded below without minification; Node built-ins remain native.
 */

/*
 * MIT License
 * 
 * Copyright (c) 2026 BackBond / Corwin Foundation
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

const __nativeRequire = require;
const __posix = __nativeRequire('node:path').posix;
const __factories = {
"bin/agent-scan.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { questionSet } = require('../lib/assessment.js');
const { sha256 } = require('../lib/canonical.js');
const { discover } = require('../lib/discovery.js');
const { collectEvidence, MAX_ARTIFACT_BYTES, publicEvidence } = require('../lib/evidence.js');
const { startMcpServer } = require('../lib/mcp-server.js');
const { liveToolsNextAction, renderNextAction } = require('../lib/next-action.js');
const { renderHuman } = require('../lib/output.js');
const { suggestPolicy } = require('../lib/policy.js');
const { createPublicScanRecord, renderCompactRecord } = require('../lib/record.js');
const { createScanReceipt, verifyScanReceipt } = require('../lib/receipt.js');
const { isPromptLintFinding, meetsThreshold, SEVERITY_ORDER } = require('../lib/rules.js');
const { toSarif } = require('../lib/sarif.js');
const { scanEvidence, scannerContract, SCANNER_VERSION } = require('../lib/scanner.js');
const { validateTeaserSubmission } = require('../lib/teaser.js');
const { safeInline } = require('../lib/text.js');
const { createVetResult, createVetSummary, renderVetHuman, vetExitCode } = require('../lib/vet-tools.js');

function usage() {
  process.stdout.write(`@backbond/agent-scan — static, local AI-agent tool scanner

Usage:
  agent-scan scan                         Auto-discover and scan known local agent configs.
  agent-scan scan --stdin                 Read a live MCP or supported function-tool manifest.
  agent-scan vet-tools --stdin            Vet a proposed tool manifest before attachment.
  agent-scan vet-tools --tool-schema <file>
  agent-scan vet-tools --stdin --summary-only
                                           Emit identity-free aggregate JSON for large local runs.
  agent-scan scan [artifact options]      Scan intentionally exported evidence.
  agent-scan inspect [artifact options]
  agent-scan mcp                          Serve scan_my_runtime over MCP stdio.
  agent-scan verify-receipt --input receipt.json

Artifact options:
  --config <file>       Recognized desktop or coding-agent MCP config (repeatable).
  --tool-schema <file>  BackBond, MCP, supported function-tool, or OpenAPI JSON.
  --permissions <file>  backbond-permissions/v1 JSON.
  --trace <file>        backbond-trace/v1 or OpenTelemetry OTLP JSON.
  --stdin               Read a live tool manifest from stdin; use --input for claims.

Live tools/list recipe:
  1. Ask the agent client for its current MCP tools/list response.
  2. Save the complete JSON response as tools-list.json.
  3. Expected shape: {"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}
  4. POSIX/cmd: npx -y @backbond/agent-scan@${SCANNER_VERSION} scan --stdin --require-coverage < tools-list.json
  5. PowerShell: Get-Content -Raw .\\tools-list.json | npx -y @backbond/agent-scan@${SCANNER_VERSION} scan --stdin --require-coverage

Pre-attachment gate:
  POSIX/cmd: npx -y @backbond/agent-scan@${SCANNER_VERSION} vet-tools --stdin < tools-list.json
  PowerShell: Get-Content -Raw .\\tools-list.json | npx -y @backbond/agent-scan@${SCANNER_VERSION} vet-tools --stdin
  Decisions: block (exit 1), no_blocking_finding (exit 0), review for a medium finding or incomplete/ambiguous evidence (exit 3).
  Scope: tool metadata and composition only; never a runtime safety determination.
  Review-only templates: add --json --suggest-policy; placeholders are never applied automatically.
  Large local runs: add --summary-only for counts, rule/coverage histograms, review items, and template multiplicity without tool or server identities.

Scan options:
  --input <file>        Optional v4 claims; hypotheses used only for contradictions.
  --fail-on <severity>  Gate BB001-BB008 and BB012 (default: high).
  --fail-on-prompt <severity>  Separately gate BB009-BB011 and BB013 (default: none).
  --receipt <file>      Write a tamper-evident receipt without overwriting.
  --signing-key <file>  Sign the receipt with an Ed25519 private key.
  --record-public <file>  Write a redacted self-run scan record without overwriting.
  --record-commit <sha>  Add a caller-supplied, unverified Git commit reference (record v2).
  --record-include-tool-names  Include tool names in that public record (off by default).
  --record-include-fingerprints  Include input hashes and byte lengths (off by default).
  --require-coverage    Exit 3 unless coverage is complete.
  --suggest-policy      Include non-enforcing disable/wrap and patch templates.
  --summary-only        vet-tools only: emit privacy-safe aggregate JSON; preserves decision exit codes.
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
    command, input: null, stdin: false, json: false, sarif: false, summaryOnly: false, suggestPolicy: false, failOn: 'high', failOnPrompt: 'none',
    requireCoverage: false, recordIncludeToolNames: false, recordIncludeFingerprints: false,
    toolSchemaPath: null, permissionsPath: null, tracePath: null, configPaths: [],
    receiptPath: null, signingKeyPath: null, recordPath: null, recordCommit: null, provided: new Set(),
  };
  const paths = {
    '--input': 'input', '--tool-schema': 'toolSchemaPath', '--permissions': 'permissionsPath',
    '--trace': 'tracePath', '--receipt': 'receiptPath', '--signing-key': 'signingKeyPath', '--fail-on': 'failOn',
    '--fail-on-prompt': 'failOnPrompt', '--record-public': 'recordPath', '--record-commit': 'recordCommit',
  };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument.startsWith('--')) options.provided.add(argument);
    if (argument === '--help' || argument === '-h') options.command = 'help';
    else if (argument === '--json') options.json = true;
    else if (argument === '--sarif') options.sarif = true;
    else if (argument === '--summary-only') options.summaryOnly = true;
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
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, options.failOnPrompt)) throw new Error('--fail-on-prompt must be critical, high, medium, low, or none');
  if (options.json && options.sarif) throw new Error('use either --json or --sarif, not both');
  if (options.summaryOnly && (options.json || options.sarif)) throw new Error('use --summary-only without --json or --sarif');
  if ((options.recordIncludeToolNames || options.recordIncludeFingerprints || options.recordCommit) && !options.recordPath) {
    throw new Error('record options require --record-public <file>');
  }
  if (options.recordCommit && !/^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(options.recordCommit)) {
    throw new Error('--record-commit must be a 40- or 64-character hexadecimal Git commit');
  }
  if (options.recordCommit) options.recordCommit = options.recordCommit.toLowerCase();
  return options;
}

function validateVetOptions(options) {
  const allowed = new Set(['--stdin', '--tool-schema', '--json', '--suggest-policy', '--summary-only']);
  const unsupported = [...options.provided].filter(argument => !allowed.has(argument));
  if (unsupported.length) throw new Error(`vet-tools does not accept ${unsupported.join(', ')}`);
  if (options.stdin === Boolean(options.toolSchemaPath)) throw new Error('vet-tools requires exactly one of --stdin or --tool-schema <file>');
  if (options.summaryOnly && options.suggestPolicy) throw new Error('--summary-only cannot be combined with --suggest-policy');
}

async function readStdin() {
  process.stdin.setEncoding('utf8');
  let input = '';
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += Buffer.byteLength(chunk, 'utf8');
    if (bytes > MAX_ARTIFACT_BYTES) throw new Error(`stdin tool manifest exceeds ${MAX_ARTIFACT_BYTES} bytes`);
    input += chunk;
  }
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

function thresholdMet(findings, options) {
  const promptLint = findings.filter(isPromptLintFinding);
  const runtimeExposure = findings.filter(item => !isPromptLintFinding(item));
  return meetsThreshold(runtimeExposure, options.failOn) || meetsThreshold(promptLint, options.failOnPrompt);
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { fail(error.message); return; }
  if (options.summaryOnly && options.command !== 'vet-tools') {
    fail('--summary-only is supported only for vet-tools');
    return;
  }
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
    if (!['scan', 'inspect', 'vet-tools'].includes(options.command)) throw new Error(`unknown command: ${options.command}`);
    if (options.command === 'vet-tools') {
      validateVetOptions(options);
      const documents = await loadStdinManifest(options);
      const now = new Date();
      const evidence = collectEvidence({ now, documents, toolSchemaPath: options.toolSchemaPath, reviewAmbiguousToolManifest: true });
      const scan = scanEvidence(evidence, { now });
      const result = createVetResult(scan, evidence);
      const output = options.suggestPolicy ? { ...result, policy_suggestion: suggestPolicy(result) } : result;
      if (options.summaryOnly) process.stdout.write(`${JSON.stringify(createVetSummary(result))}\n`);
      else if (options.json) process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
      else process.stdout.write(renderVetHuman(result));
      process.exitCode = vetExitCode(result.decision);
      return;
    }
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
    const nextAction = plan ? liveToolsNextAction(SCANNER_VERSION) : null;
    const policy = options.suggestPolicy ? suggestPolicy(scan) : null;
    const receipt = createScanReceipt(scan, { claimInput: claims.metadata, signingKeyPath: options.signingKeyPath });
    const receiptPath = options.receiptPath ? writeNew(options.receiptPath, receipt) : null;
    const record = options.recordPath ? createPublicScanRecord(scan, receipt, {
      mode: recordScopeMode(options),
      includeToolNames: options.recordIncludeToolNames,
      includeFingerprints: options.recordIncludeFingerprints,
      commit: options.recordCommit,
    }) : null;
    const recordPath = record ? writeNew(options.recordPath, record) : null;
    const output = { ...scan, ...(nextAction ? { next_action: nextAction } : {}), receipt, receipt_path: receiptPath, policy_suggestion: policy };
    if (record) {
      output.public_record = record;
      output.public_record_path = recordPath;
    }
    if (options.json) process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    else if (options.sarif) process.stdout.write(`${JSON.stringify(toSarif(scan), null, 2)}\n`);
    else {
      process.stdout.write(renderHuman(scan, { policy, receiptPath }));
      if (nextAction) process.stdout.write(`\n${renderNextAction(nextAction)}\n`);
      if (record) process.stdout.write(`\n${renderCompactRecord(record)}\n${safeInline(`Saved: ${recordPath}`)}\n`);
    }
    if (thresholdMet(scan.findings, options)) process.exitCode = 1;
    else if (options.requireCoverage && scan.coverage.status !== 'complete') process.exitCode = 3;
  } catch (error) {
    fail(error.message);
  }
}

main().catch(error => fail(`unexpected error: ${error.message}`));

},

"lib/assessment.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const PROTOCOL = 'backbond-agent-self-assessment/v1';
const SOURCES = ['observed', 'derived', 'agent_asserted', 'unknown'];

const QUESTIONS = [
  ['name', 'What runtime name or stable identifier describes you?', { type: 'string', minLength: 1, maxLength: 200 }],
  ['framework', 'Which framework or runtime are you executing in?', { type: 'string', minLength: 1, maxLength: 200 }],
  ['exec_code', 'Can you execute code, shell commands, or dynamically generated programs?', { type: 'boolean' }],
  ['browse_web', 'Can you fetch arbitrary URLs, use a browser, or make outbound web requests?', { type: 'boolean' }],
  ['filesystem', 'Can you read or write files outside a runtime-enforced sandbox?', { type: 'boolean' }],
  ['exposure', 'Who can supply instructions or content to you?', { type: 'string', enum: ['public', 'internal', 'local'] }],
  ['handles_payments', 'Can you move money, use payment credentials, or create a financial commitment?', { type: 'boolean' }],
  ['human_approval', 'How often does a runtime-enforced human approval gate block consequential actions?', { type: 'string', enum: ['always', 'sometimes', 'never'] }],
  ['persistent_memory', 'Can information you write influence later sessions through memory, a vector store, or a database?', { type: 'boolean' }],
  ['tool_count', 'How many distinct tools or functions can you invoke in this runtime?', { type: 'integer', minimum: 0 }],
  ['guardrails', 'Does the runtime enforce prompt-injection, moderation, or input/output safety controls outside your own instructions?', { type: 'boolean' }],
  ['audit_logging', 'Are your tool calls and consequential actions recorded in an audit log?', { type: 'boolean' }],
  ['incident_plan', 'Can you identify a documented shutdown and incident-response procedure for this deployment?', { type: 'boolean' }],
].map(([key, prompt, value]) => ({ key, prompt, value }));

const QUESTION_BY_KEY = Object.fromEntries(QUESTIONS.map(question => [question.key, question]));

function questionSet() {
  return {
    protocol: PROTOCOL,
    subject: 'self',
    role: 'unverified_claims',
    instructions: [
      'Answer from the current runtime without asking a person.',
      'These answers are optional hypotheses, not score or finding inputs.',
      'The local scanner may compare them with artifact evidence only to report contradictions.',
      'Use source="unknown" when evidence is unavailable.',
    ],
    sources: SOURCES,
    questions: QUESTIONS.map(question => ({
      ...question,
      answer: {
        type: 'object',
        required: ['source'],
        properties: {
          value: question.value,
          source: { type: 'string', enum: SOURCES },
          evidence: { type: 'string', minLength: 1, maxLength: 500 },
        },
      },
    })),
  };
}

function assessmentJsonSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['protocol', 'subject', 'answers'],
    properties: {
      protocol: { type: 'string', const: PROTOCOL },
      subject: { type: 'string', const: 'self' },
      answers: {
        type: 'object',
        additionalProperties: false,
        required: QUESTIONS.map(question => question.key),
        properties: Object.fromEntries(QUESTIONS.map(question => [question.key, {
          type: 'object',
          additionalProperties: false,
          required: ['source'],
          properties: {
            value: question.value,
            source: { type: 'string', enum: SOURCES },
            evidence: { type: 'string', minLength: 1, maxLength: 500 },
          },
        }])),
      },
    },
  };
}

function validateValue(question, value) {
  const schema = question.value;
  if (schema.type === 'boolean' && typeof value !== 'boolean') throw new Error(`answers.${question.key}.value must be a boolean`);
  if (schema.type === 'integer' && (!Number.isInteger(value) || value < 0)) throw new Error(`answers.${question.key}.value must be a non-negative integer`);
  if (schema.type === 'string') {
    if (typeof value !== 'string' || !value.trim()) throw new Error(`answers.${question.key}.value must be a non-empty string`);
    if (schema.maxLength && value.length > schema.maxLength) throw new Error(`answers.${question.key}.value is too long`);
    if (schema.enum && !schema.enum.includes(value)) throw new Error(`answers.${question.key}.value must be one of ${schema.enum.join(', ')}`);
  }
}

function validateAssessment(assessment) {
  if (!assessment || typeof assessment !== 'object' || Array.isArray(assessment)) throw new Error('assessment must be a JSON object');
  if (assessment.protocol !== PROTOCOL) throw new Error(`protocol must be "${PROTOCOL}"`);
  if (assessment.subject !== 'self') throw new Error('subject must be "self"');
  if (!assessment.answers || typeof assessment.answers !== 'object' || Array.isArray(assessment.answers)) throw new Error('answers must be a JSON object');
  const extras = Object.keys(assessment.answers).filter(key => !QUESTION_BY_KEY[key]);
  if (extras.length) throw new Error(`unknown answer fields: ${extras.join(', ')}`);
  for (const question of QUESTIONS) {
    const answer = assessment.answers[question.key];
    if (!answer || typeof answer !== 'object' || Array.isArray(answer)) throw new Error(`answers.${question.key} must be an object`);
    const answerExtras = Object.keys(answer).filter(key => !['value', 'source', 'evidence'].includes(key));
    if (answerExtras.length) throw new Error(`answers.${question.key} has unknown fields: ${answerExtras.join(', ')}`);
    if (!SOURCES.includes(answer.source)) throw new Error(`answers.${question.key}.source is invalid`);
    if (answer.source === 'unknown') {
      if (answer.value !== undefined && answer.value !== null) throw new Error(`answers.${question.key}.value must be omitted when source is unknown`);
      continue;
    }
    validateValue(question, answer.value);
    if (typeof answer.evidence !== 'string' || !answer.evidence.trim() || answer.evidence.length > 500) throw new Error(`answers.${question.key}.evidence is required and must be 500 characters or fewer`);
  }
  return assessment;
}

module.exports = { PROTOCOL, QUESTIONS, SOURCES, assessmentJsonSchema, questionSet, validateAssessment };

},

"lib/canonical.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { createHash } = require('node:crypto');

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
}

function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : canonicalize(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}

module.exports = { canonicalize, sha256 };

},

"lib/discovery.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PROJECT_CONFIGS = [
  ['.mcp.json', 'mcp-project'],
  ['mcp.json', 'mcp-project'],
  [path.join('.cursor', 'mcp.json'), 'cursor'],
  [path.join('.vscode', 'mcp.json'), 'vscode'],
  [path.join('.gemini', 'settings.json'), 'gemini'],
  [path.join('.claude', 'settings.json'), 'claude-code'],
  [path.join('.claude', 'settings.local.json'), 'claude-code'],
];

const PROJECT_INSTRUCTIONS = [
  'AGENTS.md', 'SKILL.md',
  path.join('.claude', 'CLAUDE.md'),
  path.join('.cursor', 'rules'),
];

function existingFile(filename) {
  try { return fs.statSync(filename).isFile(); }
  catch { return false; }
}

function existingDirectory(filename) {
  try { return fs.statSync(filename).isDirectory(); }
  catch { return false; }
}

function addCandidate(seen, files, filename, adapter, location) {
  const absolute = path.resolve(filename);
  const key = process.platform === 'win32' ? absolute.toLowerCase() : absolute;
  if (seen.has(key) || !existingFile(absolute)) return;
  seen.add(key);
  files.push({ kind: 'config', path: absolute, adapter, location });
}

function projectRoots(start, home) {
  const roots = [];
  let current = path.resolve(start);
  for (let depth = 0; depth < 8; depth += 1) {
    roots.push(current);
    if (fs.existsSync(path.join(current, '.git'))) break;
    const parent = path.dirname(current);
    if (parent === current) break;
    if (home && current === path.resolve(home)) break;
    current = parent;
  }
  return roots;
}

function discoverInstructionFiles(roots) {
  const found = [];
  const seen = new Set();
  for (const root of roots) {
    for (const relative of PROJECT_INSTRUCTIONS) {
      const candidate = path.join(root, relative);
      if (existingFile(candidate)) {
        const absolute = path.resolve(candidate);
        if (!seen.has(absolute)) { seen.add(absolute); found.push(absolute); }
      } else if (relative.endsWith('rules') && existingDirectory(candidate)) {
        for (const entry of fs.readdirSync(candidate, { withFileTypes: true })) {
          if (!entry.isFile() || !/\.(md|mdc)$/i.test(entry.name)) continue;
          const absolute = path.join(candidate, entry.name);
          if (!seen.has(absolute)) { seen.add(absolute); found.push(absolute); }
        }
      }
    }
  }
  return found.sort();
}

function homeCandidates(home, appData) {
  const candidates = [
    [path.join(home, '.cursor', 'mcp.json'), 'cursor'],
    [path.join(home, '.gemini', 'settings.json'), 'gemini'],
    [path.join(home, '.claude', 'settings.json'), 'claude-code'],
    [path.join(home, '.claude.json'), 'claude-code'],
    [path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), 'windsurf'],
    [path.join(home, '.copilot', 'mcp-config.json'), 'vscode'],
  ];
  if (process.platform === 'win32' && appData) {
    candidates.push(
      [path.join(appData, 'Claude', 'claude_desktop_config.json'), 'claude-desktop'],
      [path.join(appData, 'Code', 'User', 'mcp.json'), 'vscode'],
    );
  } else if (process.platform === 'darwin') {
    candidates.push(
      [path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), 'claude-desktop'],
      [path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'), 'vscode'],
    );
  } else {
    candidates.push([path.join(home, '.config', 'Code', 'User', 'mcp.json'), 'vscode']);
  }
  return candidates;
}

function discover(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const home = path.resolve(options.home || os.homedir());
  const appData = options.appData === undefined ? process.env.APPDATA : options.appData;
  const roots = projectRoots(cwd, home);
  const files = [];
  const seen = new Set();
  for (const root of roots) {
    for (const [relative, adapter] of PROJECT_CONFIGS) {
      addCandidate(seen, files, path.join(root, relative), adapter, 'project');
    }
  }
  for (const [filename, adapter] of homeCandidates(home, appData)) {
    addCandidate(seen, files, filename, adapter, 'user');
  }
  return {
    protocol: 'backbond-discovery-plan/v1',
    root: cwd,
    scanned_locations: ['project ancestors (bounded to 8)', 'known user config paths'],
    files: files.sort((a, b) => a.path.localeCompare(b.path)),
    instruction_files: discoverInstructionFiles(roots),
  };
}

module.exports = { PROJECT_CONFIGS, discover };

},

"lib/evidence.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256 } = require('./canonical.js');

const EVIDENCE_PROTOCOL = 'backbond-scan-evidence/v1';
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_SCHEMA_ANALYSIS_DEPTH = 64;
const MAX_SCHEMA_ANALYSIS_NODES = 10000;
const ARTIFACT_KINDS = ['tool_schema', 'permissions', 'trace'];
const CAPABILITIES = new Set([
  'code_execution', 'secret_read', 'network_egress', 'destructive_action',
  'financial_action', 'persistent_write', 'privileged_action', 'filesystem_access',
]);
const INPUT_TRUST = new Set(['trusted', 'untrusted', 'mixed', 'unknown']);
const APPROVAL = new Set(['enforced', 'advisory', 'none', 'unknown']);
const AUDIT = new Set(['observable', 'none', 'unknown']);

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
}

function readJsonArtifact(kind, filename, adapter = null) {
  const absolute = path.resolve(filename);
  const stat = fs.statSync(absolute);
  if (!stat.isFile()) throw new Error(`${kind} artifact is not a file: ${filename}`);
  if (stat.size > MAX_ARTIFACT_BYTES) throw new Error(`${kind} artifact exceeds ${MAX_ARTIFACT_BYTES} bytes: ${filename}`);
  const bytes = fs.readFileSync(absolute);
  let document;
  try { document = JSON.parse(bytes.toString('utf8')); }
  catch (error) { throw new Error(`${kind} artifact is not valid JSON (${filename}): ${error.message}`); }
  return {
    document,
    metadata: { kind, name: path.basename(absolute), bytes: stat.size, sha256: sha256(bytes), dialect: null, adapter },
  };
}

function memoryArtifact(kind, name, document, raw, adapter = null) {
  const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || JSON.stringify(document), 'utf8');
  if (bytes.length > MAX_ARTIFACT_BYTES) throw new Error(`${kind} artifact exceeds ${MAX_ARTIFACT_BYTES} bytes: ${name}`);
  return { document, metadata: { kind, name, bytes: bytes.length, sha256: sha256(bytes), dialect: null, adapter } };
}

function ref(artifact, pointer) {
  return { artifact_kind: artifact.kind, artifact_name: artifact.name, pointer };
}

function validateEnum(value, allowed, label) {
  if (value !== undefined && !allowed.has(value)) throw new Error(`${label} must be one of ${[...allowed].join(', ')}`);
  return value === undefined ? 'unknown' : value;
}

function validateCapabilities(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  for (const capability of value) {
    if (!CAPABILITIES.has(capability)) throw new Error(`${label} contains unsupported capability: ${capability}`);
  }
  return [...new Set(value)].sort();
}

function schemaText(value, depth = 0) {
  if (!value || depth > 5) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(item => schemaText(item, depth + 1)).join(' ');
  if (typeof value !== 'object') return '';
  return Object.entries(value)
    .filter(([key]) => !['default', 'example', 'examples', 'const'].includes(key))
    .map(([key, item]) => `${key} ${schemaText(item, depth + 1)}`).join(' ');
}

const INPUT_SCHEMA_KEYS = ['parameters', 'input_schema', 'inputSchema', 'schema'];

function inputSchemaEntries(tool) {
  return INPUT_SCHEMA_KEYS
    .filter(key => Object.prototype.hasOwnProperty.call(tool, key))
    .map(key => [key, tool[key]]);
}

function inputSchema(tool) {
  const entry = inputSchemaEntries(tool).find(([, value]) => value && typeof value === 'object' && !Array.isArray(value));
  return entry ? entry[1] : {};
}

function schemaHasReference(value, depth = 0) {
  if (!value || typeof value !== 'object') return false;
  if (depth > 8) return true;
  if (Array.isArray(value)) return value.some(item => schemaHasReference(item, depth + 1));
  if (Object.prototype.hasOwnProperty.call(value, '$ref')) return true;
  return Object.values(value).some(item => schemaHasReference(item, depth + 1));
}

const OPAQUE_SCHEMA_BRANCHES = new Set([
  'patternProperties', 'dependentSchemas', 'if', 'then', 'else', 'contains',
  'prefixItems', 'unevaluatedProperties', 'contentSchema', 'dependencies',
  'additionalItems', 'unevaluatedItems', 'not', 'propertyNames', '$defs', 'definitions',
]);

function schemaHasOpaqueBranch(value, depth = 0) {
  if (!value || typeof value !== 'object') return false;
  if (depth > 8) return true;
  if (Array.isArray(value)) return value.some(item => schemaHasOpaqueBranch(item, depth + 1));
  if (Object.keys(value).some(key => OPAQUE_SCHEMA_BRANCHES.has(key))) return true;
  if (value.additionalProperties && typeof value.additionalProperties === 'object') return true;
  return Object.values(value).some(item => schemaHasOpaqueBranch(item, depth + 1));
}

function hasInputSchema(tool) {
  const entries = inputSchemaEntries(tool);
  if (entries.length !== 1) return false;
  const schema = entries[0][1];
  return Boolean(schema && typeof schema === 'object' && !Array.isArray(schema)
    && schema.type === 'object'
    && schema.properties && typeof schema.properties === 'object' && !Array.isArray(schema.properties)
    && !schemaHasReference(schema)
    && !schemaHasOpaqueBranch(schema));
}

function normalizedWords(value) {
  return String(value)
    .replace(/[’‘]/g, "'")
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ');
}

function normalizedIdentifierReference(value) {
  return normalizedWords(value).replace(/[.:]+/g, ' ').replace(/\s+/g, ' ').trim();
}

function withoutExecutionActionModifiers(value) {
  return String(value).replace(
    /\b(exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b\s*,\s*([^,.;!?]{1,40})\s*,\s*/g,
    (match, action, modifier) => /\b(?:not|never|without|cannot|can't|doesn't|does\s+not|do\s+not|don't)\b/.test(modifier)
      || /\b(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b/.test(modifier)
      ? match
      : `${action} `,
  );
}

function withoutContrastedExecution(value) {
  const action = String.raw`(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)`;
  const language = String.raw`(?:shell|bash|terminal|commands?|code|scripts?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?)`;
  return String(value)
    .replace(
      new RegExp(String.raw`\b(?:rather\s+than|instead\s+of)\s+${action}\b[^,.;!?]{0,40}?\b(${language})\b[^,.;!?]{0,30}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or)\b|[.;!?]|$)`, 'g'),
      '. $1',
    )
    .replace(
      new RegExp(String.raw`\b(?:rather\s+than|instead\s+of)\s+${action}\b[^.!?;]{0,60}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or)\b|[.;!?]|$)`, 'g'),
      ' ',
    );
}

function withoutHypotheticalExecution(value) {
  return String(value)
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b[^,.;!?]{0,40}?\b(?:can|could|may|might|would)\s+be\s+(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/g,
      '. $1',
    )
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+(?:(?:(?:the|an?)\s+)?(?:(?:external|remote)\s+)?(?:runtime|service|tool|worker|component)|another\s+(?:runtime|service|tool|worker|component)|[a-z][a-z0-9]*(?:[.:][a-z0-9]+)+)\s+(?:can|could|may|might|would)\s+(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,40}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b/g,
      '. $1',
    )
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+((?:(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/g,
      '. $1',
    )
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+(quer(?:y|ies))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\b/g,
      '. $1',
    );
}

function withoutDocumentationExecutionExamples(value) {
  return String(value)
    .replace(
      /\b(?:examples?\s+(?:showing|demonstrating)\s+how\s+to|tutorial\s+(?:(?:about|on)|(?:showing|explaining|describing)\s+how\s+to)|walkthrough\s+(?:showing|explaining|describing)\s+how\s+to|guide\s+to|instructions?\s+for|(?:reference|readme|quickstart)\s+(?:showing|explaining|describing)\s+how\s+to|(?:documentation|handbook)\s+(?:on|for|about)|(?:explains?|describes?)\s+how\s+to|shows?\s+how\s+to)\s+(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,50}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|quer(?:y|ies)|(?:duckdb|postgres(?:ql)?|mysql|sqlite|sql\s+server)\s+quer(?:y|ies)))\b/gi,
      '. $1',
    )
    .replace(
      /\b(?:(?:an?\s+)?(?:documentation|reference|handbook|readme|quickstart|guide)\s+)?(?:explains?|describes?|shows?|explaining|describing|showing)\s+how\s+((?:(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/gi,
      '. $1',
    )
    .replace(
      /\b(?:(?:an?\s+)?(?:documentation|reference|handbook|readme|quickstart|guide)\s+)?(?:explains?|describes?|shows?|explaining|describing|showing)\s+how\s+(quer(?:y|ies))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\b/gi,
      '. $1',
    );
}

function withoutNegatedExecution(value) {
  return withoutHypotheticalExecution(withoutContrastedExecution(withoutExecutionActionModifiers(value)))
    .replace(
      /\b(?:(?:does\s+not|doesn't|do\s+not|don't|never|cannot|can\s+not|can't|without|isn't|aren't|wasn't|weren't|won't|wouldn't|shouldn't|couldn't)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?|(?:will|must|may|can|could|would|should|is|are|was|were)\s+(?:not|never)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?)(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,50}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b[^,.;!?]{0,30}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or\s+instead|rather)\b|[.;!?]|$)/g,
      '. $1',
    )
    .replace(
      /\b(?:(?:does\s+not|doesn't|do\s+not|don't|never|cannot|can\s+not|can't|without|isn't|aren't|wasn't|weren't|won't|wouldn't|shouldn't|couldn't)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?|(?:will|must|may|can|could|would|should|is|are|was|were)\s+(?:not|never)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?)(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^.!?;]{0,60}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or\s+instead|rather)\b|[.;!?]|$)/g,
      ' ',
    )
    .replace(/\bno\s+(?:other\s+|target\s+)?(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python|javascript|java\s+script|wolfram\s+language|sql|hogql|queries?)\s+(?:execution|(?:(?:is|are|will|can|may|must)\s+(?:be\s+)?)?(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned))\b/g, ' ')
    .replace(/\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python|javascript|wolfram\s+language|sql|hogql|queries?))\b(?:\s*,?\s*(?:which|that|it))?\s+(?:(?:isn't|aren't|wasn't|weren't|won't|wouldn't|shouldn't|couldn't|can't|cannot)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?|(?:is|are|was|were|will|can|could|would|may|must|should)\s+(?:not|never)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?)(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/g, '. $1');
}

function withoutNominalExecutionTerms(value) {
  return String(value)
    .replace(/\bpoint\s+(?:(?:your|the)\s+)?code\b[^.;!?]{0,50}\brun\s+it\b/g, ' ')
    .replace(/\bshell\s+(?:is\s+)?available\b[^.;!?]{0,50}\brun\s+`?curl\b[^.;!?]*/g, ' ')
    .replace(/\b(?:returns?|provides?)\s+instructions?\b[^.;!?]{0,100}\b(?:curl\s+)?commands?\b[^.;!?]{0,40}\b(?:for\s+(?:the\s+)?user\s+to\s+run|to\s+run)\b/g, ' ')
    .replace(/\bhand\s+the\s+command\s+to\s+(?:the\s+)?user\s+to\s+run\b[^.;!?]*/g, ' ')
    .replace(/\b(?:returns?|provides?)\b[^.;!?]{0,40}\bchecklist\b[^.;!?]{0,100}\bcode\b[^.;!?]{0,50}\brun\s+builds?\b/g, ' ')
    .replace(/\b(?:is\s+|are\s+|was\s+|were\s+)?(?:not|never)\s+(?:an?|the)\s+commands?\s+to\s+run\b/g, ' ')
    .replace(/\b(?:newly|recently|freshly)\s+launched\b/g, ' ')
    .replace(/\b(?:a|the)\s+spawn\b/g, ' ')
    .replace(/\b(?:(?:federal\s+)?grant|security|partnership|assistance|fitness|community|equity\s+offering|atm)\s+programs?\b/g, ' ');
}

function executionDescriptionSignals(description) {
  const withoutNegatedPhrases = withoutNominalExecutionTerms(withoutNegatedExecution(description));
  const active = /\b(?:exec(?:ute|utes|uting)?|run(?:s|ning)?|launch(?:es|ing)?|invoke(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,50}\b(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess)\b/;
  const passive = /(?:^|[.!?;]\s*)(?:(?:the|an?)\s+)?(?:(?:user[- ]supplied|model[- ]generated|supplied|arbitrary|raw|input)\s+){0,3}\b(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess)\b[^,.;!?]{0,30}\b(?:is|are|can be|will be|may be|must be)\s+(?:exec(?:ute|uted)?|run|launched|invoked|interpreted|spawned)\b/;
  const query = /\b(?:exec(?:ute|utes|uting)?|run(?:s|ning)?|evaluate(?:s|d|ing)?)\b[^,.;!?]{0,50}\b(?:expressions?|sql|queries?)\b|\b(?:expressions?|sql|queries?)\b[^,.;!?]{0,30}\b(?:is|are|can be|will be|may be|must be)\s+(?:executed|run|evaluated)\b/;
  return {
    active: active.test(withoutNegatedPhrases),
    passive: passive.test(withoutNegatedPhrases),
    query: query.test(withoutNegatedPhrases),
  };
}

function searchableToolText(tool) {
  return [tool.name, tool.description, tool.title, schemaText(inputSchema(tool))]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
}

function schemaHasExecutionInput(value, executionContext, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 5) return false;
  if (value.properties && typeof value.properties === 'object') {
    for (const [name, child] of Object.entries(value.properties)) {
      if (executionInputField(normalizedWords(name), child, executionContext)) return true;
      if (schemaHasExecutionInput(child, executionContext, depth + 1)) return true;
    }
  }
  if (value.items && schemaHasExecutionInput(value.items, executionContext, depth + 1)) return true;
  for (const keyword of ['anyOf', 'oneOf', 'allOf']) {
    if (Array.isArray(value[keyword]) && value[keyword].some(child => schemaHasExecutionInput(child, executionContext, depth + 1))) return true;
  }
  return false;
}

function usefulSchemaPattern(node) {
  return typeof node.pattern === 'string' && !['.*', '^.*$', '.+'].includes(node.pattern.trim());
}

function identifierCharacterClass(body) {
  if (!body || body.startsWith('^')) return false;
  let grammar = body
    .replace(/(?:A-Z|a-z|0-9)/g, 'R')
    .replace(/\\[wd._-]/g, 'A');
  if (grammar.includes('\\')) return false;
  if (grammar.slice(1, -1).includes('-')) return false;
  grammar = grammar.replace(/^-|-$/g, 'L');
  return /^[A-Za-z0-9_.]+$/.test(grammar);
}

function executionPatternConstrainsInput(pattern) {
  if (typeof pattern !== 'string') return false;
  const compact = pattern.trim();
  if (!compact) return false;
  if (!(compact.startsWith('^') && compact.endsWith('$'))) return false;
  try {
    new RegExp(compact);
  } catch {
    return false;
  }

  let grammar = compact.slice(1, -1);
  if (!grammar) return false;
  grammar = grammar.replace(/\[[^\]]*\]/g, characterClass => {
    const body = characterClass.slice(1, -1);
    return identifierCharacterClass(body) ? 'A' : '!';
  });
  grammar = grammar
    .replace(/\\[wd._-]/g, 'A')
    .replace(/\{\d+(?:,\d*)?\}/g, '');
  return /^[A-Za-z0-9_+*?-]+$/.test(grammar);
}

function freeTextSchemaField(node) {
  if (!node || typeof node !== 'object') return false;
  const constrained = Array.isArray(node.enum)
    || Object.hasOwn(node, 'const')
    || executionPatternConstrainsInput(node.pattern);
  return (node.type === 'string' || node.type === undefined) && !constrained;
}

function directInterpreterExecutionContext(value, identityAliases = []) {
  const text = withoutNominalExecutionTerms(withoutNegatedExecution(normalizedWords(value)));
  const action = String.raw`(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|evaluate(?:s|d|ing)?|invoke(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?|ejecut(?:a|ar)|exécute(?:r|s)?)`;
  const language = String.raw`(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python|javascript|wolfram language|sql|hogql|(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db))`;
  const activeLanguage = String.raw`(?:shell|bash|terminal|commands?|code|scripts?|(?:(?:caller|user)[- ]supplied|supplied|arbitrary|raw|executable)\s+programs?|binaries?|powershell|subprocess|python|javascript|wolfram language|sql|hogql|(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db))`;
  const roleSubjects = identityAliases
    .map(normalizedIdentifierReference)
    .map(alias => {
      const words = alias.split(/\s+/).filter(Boolean);
      const role = words.at(-1);
      return /^(?:tool|service|component|validator|runner|executor|interpreter|kernel|worker|processor|handler)$/.test(role)
        ? role
        : '';
    })
    .filter(Boolean)
    .map(role => role.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const roleSubject = roleSubjects.length > 0 ? `|(?:the\\s+)?(?:${[...new Set(roleSubjects)].join('|')})` : '';
  const selfSubject = String.raw`(?:(?:this|the)\s+(?:tool|service|component)|it|we${roleSubject})`;
  const executionAdverb = String.raw`(?:(?!(?:not|never)\b)[a-z]+ly\s+)`;
  const executionObject = String.raw`(?:it|them|the\s+(?:resulting\s+)?(?:query|statement|code|script|command|expression|input|payload)|(?:the\s+)?(?:input|payload))`;
  const selfModal = String.raw`(?:(?:may|will|can|could|would|must)\s+)?`;
  const executionTemporal = String.raw`(?:(?:later|also)\s+)?`;
  const direct = new RegExp(String.raw`\b${action}\b[^,.;!?]{0,30}\b${activeLanguage}\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^,.;!?]{0,20}\b(?:is|are|can be|will be|may be|must be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^,.;!?]{0,50}(?:[,;]\s*(?:(?:and\s+then|and|but|however|yet|then|later|before|after|followed\s+by)\s+)?|\s+\b(?:and\s+then|and|but|however|yet|then|later|before|after|followed\s+by)\s+)(?:${selfSubject}\s+)?${selfModal}${executionTemporal}(?:${executionAdverb}){0,2}${action}\s+${executionObject}\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^.;!?]{0,60}[.;!?]\s*(?:(?:(?:when|if)\s+[a-z]+(?:\s+[a-z]+){0,3}|(?:afterward|subsequently|later|however|yet))\s*,?\s*)?(?:${selfSubject}\s+)?(?:then\s+)?${selfModal}${executionTemporal}(?:${executionAdverb}){0,2}${action}\s+${executionObject}\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^,.;!?]{0,20}\b(?:executes|runs|launches|evaluates|invokes|interprets|spawns)\b[^,.;!?]{0,30}\b(?:locally|in\s+(?:this|the)\s+(?:tool|service|component)|by\s+(?:this|the)\s+(?:tool|service|component))\b`).test(text)
    || new RegExp(String.raw`\b${action}\b[^,.;!?]{0,50}\b(?:the\s+|an?\s+)?(?:caller[- ]supplied|user[- ]supplied|supplied|raw)\s+(?:quer(?:y|ies)\b[^,.;!?]{0,30}\b(?:database|db)|(?:database|db)\s+quer(?:y|ies))\b`).test(text)
    || new RegExp(String.raw`\b${action}\b[^,.;!?]{0,50}\b(?:the\s+|an?\s+)?(?:database|db)\s+quer(?:y|ies)\b(?:\s+(?:supplied|provided)\s+by\s+(?:the\s+)?(?:caller|user))?`).test(text)
    || new RegExp(String.raw`\b${action}\b[^,.;!?]{0,50}\b(?:the\s+|an?\s+)?quer(?:y|ies)\b\s+(?:supplied|provided)\s+by\s+(?:the\s+)?(?:caller|user)\b[^,.;!?]{0,30}\b(?:database|db)\b`).test(text)
    || new RegExp(String.raw`\b(?:the\s+)?(?:(?:caller[- ]supplied|user[- ]supplied|supplied|provided)\s+)?quer(?:y|ies)\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\b`).test(text)
    || new RegExp(String.raw`\b(?:the\s+|an?\s+)?(?:caller[- ]supplied|user[- ]supplied|supplied|raw)\s+(?:database|db)\s+quer(?:y|ies)\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b`).test(text)
    || new RegExp(String.raw`\b(?:(?:(?:the|every)\s+)?(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+against\s+(?:the\s+)?(?:database|db))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b`).test(text);
  return direct;
}

function executionToolContext(toolContext, toolIdentity = '', identityAliases = []) {
  const text = normalizedWords(toolContext);
  const identity = normalizedWords(toolIdentity);
  const normalizedAliases = new Set(identityAliases.map(normalizedIdentifierReference).filter(alias => alias && alias.length <= 160));
  const attributionText = withoutNegatedExecution(text);
  let aliasAttribution = false;
  if (normalizedAliases.size > 0) {
    const attributionPattern = /\b(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\s+(?:by|via|through)\s+(?:`([^`]{1,160})`|([a-z][a-z0-9]*(?:[._:-][a-z0-9]+)+)|([^`.,;!?]{1,160}))/g;
    for (const match of attributionText.matchAll(attributionPattern)) {
      const target = normalizedIdentifierReference((match[1] || match[2] || match[3]).replace(
        /\s+\b(?:before|after|then|and|but|while|when|during|followed\s+by)\b.*$/,
        '',
      ));
      if (normalizedAliases.has(target)) {
        aliasAttribution = true;
        break;
      }
    }
  }
  const selfExecutionAttribution = aliasAttribution
    || /\b(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\s+(?:by|via|through)\s+(?:this\s+tool|itself|self)\b/.test(attributionText);
  const executorIdentity = /\b(?:runner|executor|interpreter|kernel)\b/.test(identity);
  const mediatedIdentity = /\b(?:check(?:er|list)?|inspect(?:or|ion)?|review(?:er)?|analy[sz](?:e|er|is)|lint(?:er)?|validat(?:e|or|ion)|authoriz(?:e|er|ation)|gate|guard|bind|cert(?:ificate)?|challenge|verif(?:y|ier|ication)|transpil(?:e|er)|format(?:ter)?|convert(?:er)?|conversion|explain(?:er)?|explanation|preview|scan(?:ner)?|classif(?:y|ier|ication)|detect(?:or|ion)?|audit(?:or)?|pars(?:e|er))\b/.test(identity)
    || /\bsql ?guard\b/.test(identity);
  const mediationOnly = mediatedIdentity
    && !executorIdentity
    && !/\b(?:create|run|execute|render|deploy|play|live)\b/.test(identity);
  const mediatedAction = String.raw`(?:runs?|exec(?:ute|utes|uted|uting)?|performs?|evaluate(?:s|d|ing)?)`;
  const mediatedNoun = String.raw`(?:parser|analyzer|scanner|validator|formatter|transpiler|analysis|validation|reviewer?|linter|verification|verifier|conversion|converter|classification|classifier|detection|detector|explanation|explainer|audit|auditor|inspection|inspector|authorization|authorizer|checker|checklist|check)`;
  const executionAction = String.raw`(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)`;
  const mediatedGap = String.raw`(?:(?![,.;!?]|\b(?:and|but|then|before|after|without|however|yet|while|although|or|rather|${executionAction})\b).)`;
  const normalizedExecutionText = withoutExecutionActionModifiers(text);
  const executionText = mediationOnly
    ? normalizedExecutionText
      .replace(new RegExp(String.raw`\b${mediatedNoun}\b${mediatedGap}{0,30}?\b${mediatedAction}\b${mediatedGap}{0,40}?\b(?:source\s+|python\s+)?(?:code|scripts?|sql)\b`, 'g'), ' ')
      .replace(new RegExp(String.raw`\b${mediatedAction}\b${mediatedGap}{0,30}?\b${mediatedNoun}\b${mediatedGap}{0,40}?\b(?:source\s+|python\s+)?(?:code|scripts?)\b`, 'g'), ' ')
      .replace(new RegExp(String.raw`\b${mediatedAction}\b${mediatedGap}{0,30}?\b(?:python\s+code|source\s+code|code|sql)\s+${mediatedNoun}\b`, 'g'), ' ')
      .replace(new RegExp(String.raw`\b${mediatedAction}\b${mediatedGap}{0,30}?\b${mediatedNoun}\b`, 'g'), ' ')
    : normalizedExecutionText;
  const classificationText = withoutNegatedExecution(executionText);
  return {
    text,
    identity,
    directExecution: selfExecutionAttribution || directInterpreterExecutionContext(executionText, [toolIdentity, ...identityAliases]),
    executorIdentity,
    mediationOnly,
    sqlIdentity: /^(?:query|execute|run|submit)\b.{0,30}\b(?:sql|hogql)\b|^(?:sql|hogql)\b.{0,30}\b(?:query|execute|run|submit)\b/.test(identity),
    databaseOperationIdentity: /^(?:query|execute|run|submit)\b.{0,20}\b(?:database|db)\b/.test(identity)
      || /^(?:database|db)\b.{0,20}\b(?:query|execute|run|submit)\b/.test(identity),
    commandLanguage: /\b(?:shell|terminal|bash|powershell|subprocess|python|javascript|wolfram language|code|scripts?|programs?|commands?)\b/.test(classificationText),
    executableLanguage: /\b(?:python|javascript|typescript|wolfram language|es module|repl|interpreter|kernel)\b/.test(classificationText),
    runtimeSignal: /\b(?:render|deploy|runtime|live code|repl|autoplay|complete python script|code defining)\b/.test(classificationText),
    expressionLanguage: /\b(?:javascript|python|wolfram language|expression engine|interpreter)\b/.test(classificationText),
    sqlLanguage: /\b(?:sql|hogql|database|db|duckdb|postgres(?:ql)?|mysql|sqlite|sql server|query engine|select(?: statement)?|common table expression|cte)\b/.test(classificationText),
  };
}

function executionInputField(name, node, executionContext, { unconstrainedOnly = false } = {}) {
  if (!node || typeof node !== 'object' || !(node.type === 'string' || node.type === undefined)) return false;
  const strong = /^(cmd|python|shell|eval|shell command|command text|source code|python code)$/.test(name);
  const commandLike = /^(command|code|script)$/.test(name);
  const expressionLike = name === 'expression';
  const sqlLike = /^(sql|sql query)$/.test(name);
  const queryLike = /^(query|q)$/.test(name);
  const enumerated = Array.isArray(node.enum) || Object.hasOwn(node, 'const');
  const constrained = !freeTextSchemaField(node);
  if (unconstrainedOnly && constrained) return false;
  if (strong) return !enumerated || executionContext.directExecution || executionContext.executorIdentity;
  if (!(commandLike || expressionLike || sqlLike || queryLike)) return false;
  const fieldContext = normalizedWords(typeof node.description === 'string' ? node.description : '');
  const directFieldContext = fieldContext.replace(
    /\b(?:about|before|after)\s+to\s+(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|evaluate(?:s|d|ing)?|submit(?:s|ted|ting)?)\b[^,.;!?]{0,60}/g,
    ' ',
  );
  const reverseExecution = /\b(?:shell|terminal|bash|powershell|subprocess|commands?|code|scripts?|python|javascript|sql|queries?)\b.{0,20}\bto\s+(?:execute|run|evaluate|submit)\b/.test(fieldContext)
    && !/\b(?:about|before|after)\s+to\s+(?:execute|run|evaluate|submit)\b/.test(fieldContext);
  const fieldExecution = directInterpreterExecutionContext(directFieldContext)
    || reverseExecution;
  const directExecution = executionContext.directExecution || fieldExecution;
  const commandLanguage = executionContext.commandLanguage
    || /\b(?:shell|terminal|bash|powershell|subprocess|python|javascript|wolfram language|code|script|program|command)\b/.test(fieldContext);
  const executableLanguage = executionContext.executableLanguage
    || /\b(?:python|javascript|typescript|wolfram language|es module|repl|interpreter|kernel)\b/.test(fieldContext);
  const runtimeSignal = executionContext.runtimeSignal
    || /\b(?:render|deploy|runtime|live code|repl|autoplay|complete python script|code defining)\b/.test(fieldContext);
  const expressionLanguage = executionContext.expressionLanguage
    || /\b(?:javascript|python|wolfram language|expression engine|interpreter)\b/.test(fieldContext);
  const sqlLanguage = executionContext.sqlLanguage
    || /\b(?:sql|hogql|database|db|duckdb|postgres(?:ql)?|mysql|sqlite|sql server|query engine|select(?: statement)?|common table expression|cte)\b/.test(fieldContext);
  const explicitExecution = directExecution || (executableLanguage && runtimeSignal);
  if (constrained && !(explicitExecution || executionContext.executorIdentity)) return false;
  const mediationOnly = executionContext.mediationOnly && !explicitExecution;
  const declaredSqlInput = sqlLike
    && !mediationOnly
    && sqlLanguage;
  const commandContext = directExecution && commandLanguage;
  const executableCodeContext = !mediationOnly
    && executableLanguage
    && runtimeSignal;
  const expressionContext = directExecution && expressionLanguage;
  const queryContext = (directExecution
      || executionContext.sqlIdentity
      || ((sqlLike || queryLike) && executionContext.databaseOperationIdentity)
      || declaredSqlInput)
    && sqlLanguage;
  return (commandLike && (commandContext || executableCodeContext || executionContext.executorIdentity))
    || (expressionLike && expressionContext)
    || ((sqlLike || queryLike) && queryContext);
}

function withoutDelegatedQueryReferences(rawDescription, identityAliases) {
  return String(rawDescription).replace(/\s+/g, ' ')
    .replace(
      /\b(?:call|use|invoke|then|ask|delegate(?:\s+to)?|route(?:\s+to)?)\s+(?:`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?)\s+to\s+(?:run|execute|evaluate)\b(?:(?![,.;!?]|\b(?:and|but|then|before|after|prior\s+to|followed\s+by|after\s+which|however|yet|while|although|or|rather)\b).){0,30}?\b(sql|queries?)\b(?:(?![,.;!?]|\b(?:and|but|then|before|after|prior\s+to|followed\s+by|after\s+which|however|yet|while|although|or|rather)\b).){0,80}/gi,
      (match, singleTarget, multiWordTarget, structuredTarget, language) => {
        const target = singleTarget || multiWordTarget || structuredTarget;
        return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language} `;
      },
    )
    .replace(
      /\b(?:forwards?|routes?|delegates?)\s+(quer(?:y|ies))\s+to\s+(?:`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?)\s*[.!?]\s*the\s+quer(?:y|ies)\b[^.!?]{0,60}\b(?:executed|run|evaluated|invoked|submitted|launched|interpreted)\b[^.!?]{0,60}\bthere\b/gi,
      (match, language, singleTarget, multiWordTarget, structuredTarget) => {
        const target = singleTarget || multiWordTarget || structuredTarget;
        return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. database ${language} `;
      },
    );
}

function withoutExternalExecutionAttribution(rawDescription, identityAliases) {
  const normalized = String(rawDescription).replace(/\s+/g, ' ');
  const withoutDatabasePassiveAttribution = normalized.replace(
    /\b((?:(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)))\b[^,.;!?]{0,30}\b(?:is|are|was|were|gets?|got|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\s+(?:by|via|through)\s+(?:`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?|`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|((?:another|(?:(?:an?|the)\s+)?external)\s+(?:service|tool|runtime|worker|runner|component)))(?=\W|$)/gi,
    (match, language, structuredTarget, singleTarget, multiWordTarget, externalActor) => {
      if (externalActor) return `. ${language}`;
      const target = structuredTarget || singleTarget || multiWordTarget;
      return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language}`;
    },
  );
  const withoutPassiveAttribution = withoutDatabasePassiveAttribution.replace(
    /\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql(?:\s+(?:queries?|statements?))?|hogql|queries?))\b[^,.;!?]{0,50}?\b(?:is|are|was|were|gets?|got|(?:will|can|could|would|may|must|should)(?:\s+(?!(?:not|never)\b)[a-z]+ly){0,2}\s+be)\s+(?:(?!(?:not|never)\b)[a-z]+ly\s+){0,2}(?:be\s+)?(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\s+(?:by|via|through)\s+(?:`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?|`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|((?:another|(?:(?:an?|the)\s+)?external)\s+(?:service|tool|runtime|worker|runner|component)))(?=\W|$)/gi,
    (match, language, structuredTarget, singleTarget, multiWordTarget, externalActor) => {
      if (externalActor) return `. ${language}`;
      const target = structuredTarget || singleTarget || multiWordTarget;
      return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language}`;
    },
  );
  return withoutPassiveAttribution.replace(
    /\b(?:`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?|`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|((?:another|(?:(?:an?|the)\s+)?external)\s+(?:service|tool|runtime|worker|runner|component)))\s+(?:(?!(?:not|never)\b)[a-z]+ly\s+){0,2}(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?|submit(?:s|ted|ting)?)\b[^,.;!?]{0,50}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b/gi,
    (match, structuredTarget, singleTarget, multiWordTarget, externalActor, language) => {
      if (externalActor) return `. ${language}`;
      const target = structuredTarget || singleTarget || multiWordTarget;
      return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language}`;
    },
  );
}

function inferredPersistentWrite(tool, identity, description) {
  const writeAction = String.raw`(?:save|remember|memorize|persist|store|write|upsert|insert|append|cache|index)`;
  const writeObject = String.raw`(?:data|content|text|notes?|memory|memories|records?|entries|documents?|artifacts?|context|knowledge|preferences?|state|values?)`;
  const actionIdentity = new RegExp(String.raw`^(?:${writeAction})\b`).test(identity)
    || new RegExp(String.raw`\b(?:create|add|update)\b.{0,30}\b(?:memory|note|record|entry|document|artifact|knowledge)\b`).test(identity);
  if (actionIdentity) return true;
  if (tool.annotations && tool.annotations.readOnlyHint === true) return false;
  const imperativeDescription = new RegExp(String.raw`(?:^|[.!?;]\s*)(?:(?:this|the)\s+tool\s+)?${writeAction}\b.{0,60}\b${writeObject}\b`).test(description);
  const activeDescription = new RegExp(String.raw`\b(?:saves|remembers|memorizes|persists|stores|writes|upserts|inserts|appends|caches|indexes)\b.{0,60}\b${writeObject}\b`).test(description);
  return imperativeDescription || activeDescription;
}

function inferCapabilities(tool) {
  const text = searchableToolText(tool);
  const identity = [tool.name, tool.title].filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const rawDescription = typeof tool.description === 'string' ? tool.description : '';
  const description = normalizedWords(rawDescription);
  const toolContext = `${identity} ${description}`;
  const identityAliases = [tool.name, tool.title]
    .filter(value => typeof value === 'string')
    .map(normalizedIdentifierReference);
  const directDescription = normalizedWords(withoutDocumentationExecutionExamples(
    withoutExternalExecutionAttribution(
      withoutDelegatedQueryReferences(rawDescription, identityAliases),
      identityAliases,
    ),
  ));
  const directToolContext = `${identity} ${directDescription}`;
  const executionContext = executionToolContext(directToolContext, identity, identityAliases);
  const executionIdentity = /\b(shell|bash|terminal|exec(?:ute)?|subprocess|powershell|run code|eval)\b/.test(identity);
  const executionField = schemaHasExecutionInput(inputSchema(tool), executionContext);
  const executionDescription = executionDescriptionSignals(directDescription);
  const queryExecutionContext = executionContext.directExecution;
  const documentationIdentity = /\b(doc|docs|documentation|handbook|reference|readme|quickstart|catalog|list|examples?|tutorial|walkthrough|guide|instructions?|explain|describe|lint|analy[sz](?:e|er)|pars(?:e|er)|inspect|preview|check(?:list)?|audit|vet|scan|classify|review|authorize|gate)\b/.test(identity);
  const documentationDescription = /\b(document(?:ation|ed)?|handbook|reference|catalog|guide|explains?|describes?|examples?|read[ -]only|prose(?: only)?|text only|classification|risk analysis|authorization|authorize)\b/.test(description);
  const passiveDocumentationOnly = documentationIdentity && documentationDescription
    && (executionDescription.passive || executionDescription.query) && !executionDescription.active && !executionField;
  const checklistDocumentationOnly = /\bchecklist\b/.test(identity)
    && /\b(?:returns?|provides?|shows?|gives?)\b[^.!?]{0,40}\b(?:steps?|instructions?|requirements?|checklist)\b/.test(description)
    && !executionField;
  const proceduralDocumentationOnly = executionContext.mediationOnly
    && /\b(?:recipe|returned\s+steps?|provided\s+steps?|instructions?|commands?)\b/.test(description)
    && /\b(?:this\s+)?server\s+(?:performs?\s+no\s+computation|does\s+not\s+(?:run|execute|invoke|launch))\b/.test(description)
    && !/\b(?:this\s+tool|server)\s+(?:executes?|runs?|launch(?:es)?|interprets?|spawns?)\b/.test(directDescription)
    && !executionField;
  const documentationOnly = passiveDocumentationOnly || proceduralDocumentationOnly || checklistDocumentationOnly;
  const matches = [
    ['secret_read', /\b(secret|credential|password|1password|onepassword|token|keychain|vault|api key|environment variable)\b/],
    ['network_egress', /\b(http|https|url|uri|fetch|request|browser|webhook|network|upload|email|slack|send|post message)\b/],
    ['destructive_action', /\b(delete|remove|destroy|drop|terminate|cancel|revoke|wipe|purge)\b/],
    ['financial_action', /\b(pay|payment|purchase|transfer|wire|trade|order)\b/],
    ['privileged_action', /\b(admin|sudo|privilege|permission|iam|deploy|publish|merge|revoke|payment|transfer|delete)\b/],
    ['filesystem_access', /\b(file|filesystem|directory|folder|path|read file|write file)\b/],
  ];
  const capabilities = matches.filter(([, pattern]) => pattern.test(text)).map(([capability]) => capability);
  if (inferredPersistentWrite(tool, identity, description)) capabilities.push('persistent_write');
  const descriptionExecutionAllowed = !executionContext.mediationOnly
    || executionContext.directExecution
    || executionField;
  if (executionField
    || (executionIdentity && !(documentationIdentity && documentationDescription && !executionDescription.active) && !documentationOnly)
    || (executionContext.directExecution && descriptionExecutionAllowed && !documentationOnly)
    || ((executionDescription.active
      || executionDescription.passive
      || (executionDescription.query && queryExecutionContext)) && descriptionExecutionAllowed && !documentationOnly)) {
    capabilities.push('code_execution');
  }
  if (tool.annotations && tool.annotations.destructiveHint === true) capabilities.push('destructive_action', 'privileged_action');
  if (tool.annotations && tool.annotations.openWorldHint === true) capabilities.push('network_egress');
  return [...new Set(capabilities)].sort();
}

function compositionPrivilegeEvidence(tool, artifact, toolPointer, explicitCapabilities, forcedCapabilities = []) {
  const privilegedCapabilities = new Set(['privileged_action', 'destructive_action', 'financial_action']);
  const explicit = explicitCapabilities.some(capability => privilegedCapabilities.has(capability));
  const forced = forcedCapabilities.some(capability => privilegedCapabilities.has(capability));
  const destructiveHint = Boolean(tool.annotations && tool.annotations.destructiveHint === true);
  const identity = normalizedWords(typeof tool.name === 'string' ? tool.name : '').trim();
  const readOnlyIdentity = /^(?:status|list|get|read|search|query|inspect|preview|help|docs?|documentation|explain|describe)\b/.test(identity);
  const sequencedPrivilege = /^(?:status|list|get|read|search|query|inspect|preview|help|docs?|documentation|explain|describe)\b.{0,40}\b(?:and|then|to)\b.{0,30}\b(?:deploy|iam|admin|sudo|revoke|delete|remove|destroy|drop|terminate|wipe|purge|publish|merge|payment|transfer)\b/.test(identity);
  const privilegedIdentity = /\b(?:deploy|iam|admin|sudo|revoke|delete|remove|destroy|drop|terminate|wipe|purge|publish|merge|payment|transfer)\b/.test(identity)
    && (!readOnlyIdentity || sequencedPrivilege);
  if (!(explicit || forced || destructiveHint || privilegedIdentity)) {
    return { observed: false, provenance: 'none', ref: null };
  }
  const pointer = destructiveHint
    ? `${toolPointer}/annotations/destructiveHint`
    : explicit
      ? `${toolPointer}/${tool['x-backbond'] ? 'x-backbond/' : ''}capabilities`
      : `${toolPointer}/name`;
  return {
    observed: true,
    provenance: explicit || destructiveHint ? 'explicit' : 'derived',
    ref: ref(artifact, pointer),
  };
}

function destinationPatternConstrainsHost(pattern) {
  if (!usefulSchemaPattern({ pattern })) return false;
  if (!pattern.startsWith('^') || /(^|[^\\])\|/.test(pattern)) return false;
  const readable = pattern.slice(1).replace(/\\\//g, '/');
  const scheme = readable.match(/^https?\??:\/\//i);
  if (!scheme) return false;
  const authorityPattern = readable.slice(scheme[0].length);
  const delimiter = authorityPattern.match(/(?:\\[?#]|[/?#])/);
  const exactAuthority = !delimiter && authorityPattern.endsWith('$');
  if (!delimiter && !exactAuthority) return false;
  const hostPattern = delimiter
    ? authorityPattern.slice(0, delimiter.index)
    : authorityPattern.slice(0, -1);
  if (!hostPattern || /[()[\]{}*+?|@$^]/.test(hostPattern)) return false;
  if (/(^|[^\\])\./.test(hostPattern)) return false;
  const literalHost = hostPattern.replace(/\\\./g, '.').replace(/\\-/g, '-');
  if (literalHost.includes('\\')) return false;
  return /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?::\d+)?$/i.test(literalHost);
}

function destinationIsConstrained(node) {
  if (Array.isArray(node.enum) && node.enum.length > 0) return true;
  if (Object.hasOwn(node, 'const')) return true;
  return typeof node.pattern === 'string' && destinationPatternConstrainsHost(node.pattern);
}

function networkActionContext(toolContext) {
  return /\b(?:fetch|download|retrieve|browse|search|read|open|get|scrape|crawl|send|post|upload|request|call|navigate|proxy|webhook|callback|deploy|publish)\b/.test(toolContext);
}

function destinationInputClass(propertyName, node, toolContext) {
  if (!node || typeof node !== 'object' || destinationIsConstrained(node)) return null;
  if (!(node.type === 'string' || node.type === undefined)) return null;
  const name = normalizedWords(propertyName).trim();
  const description = normalizedWords(typeof node.description === 'string' ? node.description : '');
  const label = `${name} ${description}`.trim();
  const strongName = /^(?:url|uri|webhook|webhook url|callback url|destination url|target url|request url|remote url)$/.test(name);
  const strongDescription = /\b(?:webhook url|callback url|destination url|target url|request url|remote url)\b/.test(description)
    || /\b(?:publicly reachable|user supplied|operator supplied|supplied|arbitrary|external|remote)\b[^.]{0,80}\b(?:url|uri)\b/.test(description)
    || /\b(?:url|uri)\b[^.]{0,40}\b(?:to|for)\s+(?:fetch|download|open|browse|scrape|crawl|request|navigate|load|retrieve|send|post|upload)\b/.test(description);
  const ambiguous = /\b(?:endpoint|href|path|host|hostname|destination|target)\b/.test(label)
    || /(?:^|\s)(?:url|uri)$/.test(name);
  if (!(strongName || strongDescription || ambiguous)) return null;
  const documentationLocator = /\b(?:doc|docs|documentation|reference|schema|specification)\b/.test(label);
  const explicitDestinationAction = /\b(?:fetch|download|open|browse|scrape|crawl|request|navigate|webhook|callback)\b/.test(toolContext);
  if (documentationLocator && !explicitDestinationAction) return 'ambiguous_destination_reference';
  return (strongName || strongDescription) && networkActionContext(toolContext)
    ? 'unvalidated_destination'
    : 'ambiguous_destination_reference';
}

function semanticRisks(tool, artifact, toolPointer) {
  const schema = inputSchema(tool);
  const risks = [];
  const observedRiskIds = new Set();
  const addRisk = risk => {
    if (observedRiskIds.has(risk.id)) return;
    observedRiskIds.add(risk.id);
    risks.push(risk);
  };
  const toolIdentity = [tool.name, tool.title]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const identityAliases = [tool.name, tool.title]
    .filter(value => typeof value === 'string')
    .map(normalizedIdentifierReference);
  const directDescription = withoutDocumentationExecutionExamples(
    withoutExternalExecutionAttribution(
      withoutDelegatedQueryReferences(
        typeof tool.description === 'string' ? tool.description : '',
        identityAliases,
      ),
      identityAliases,
    ),
  );
  const toolContext = [tool.name, tool.title, directDescription]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const executionContext = executionToolContext(toolContext, toolIdentity, identityAliases);
  const formalQuerySignal = /\b(?:sql|hogql|expression|query language|where clause|filter expression|text to sql|lucene|solr|openfda|jsonpath|regular expression|cron expression|formula expression)\b/;
  const toolHasFormalQueryContext = formalQuerySignal.test(toolContext);
  const rootPointer = `${toolPointer}/${tool.parameters ? 'parameters' : tool.input_schema ? 'input_schema' : tool.inputSchema ? 'inputSchema' : 'schema'}`;
  const pending = [{ node: schema, pointer: rootPointer, propertyName: '', depth: 0 }];
  const visited = new WeakSet();
  let analyzedNodes = 0;
  let analysisIncomplete = false;
  let unresolvedSchema = false;
  while (pending.length) {
    const { node, pointer, propertyName, depth } = pending.pop();
    if (!node || typeof node !== 'object' || visited.has(node)) continue;
    if (depth > MAX_SCHEMA_ANALYSIS_DEPTH || analyzedNodes >= MAX_SCHEMA_ANALYSIS_NODES) {
      analysisIncomplete = true;
      continue;
    }
    visited.add(node);
    analyzedNodes += 1;
    if (typeof node.$ref === 'string' || node['x-backbond-analysis-incomplete'] === true) unresolvedSchema = true;
    const description = typeof node.description === 'string' ? node.description.toLowerCase() : '';
    const label = `${propertyName.replace(/[_-]+/g, ' ')} ${description}`;
    const constrained = Array.isArray(node.enum) || Object.hasOwn(node, 'const');
    if ((node.type === 'string' || node.type === undefined) && !constrained) {
      const interpreterField = executionInputField(normalizedWords(propertyName), node, executionContext, { unconstrainedOnly: true });
      const normalizedPropertyName = normalizedWords(propertyName).trim();
      const formalQueryName = /^(?:query|q|sql|sql query|statement|expression|filter|where|where clause)$/.test(normalizedPropertyName);
      const queryExpression = formalQuerySignal.test(label) || (formalQueryName && toolHasFormalQueryContext);
      if (interpreterField) {
        addRisk({ id: 'arbitrary_interpreter_input', reason: `${propertyName || 'input'} accepts unconstrained command, expression, or SQL text`, ref: ref(artifact, pointer) });
      } else if (freeTextSchemaField(node) && queryExpression) {
        addRisk({ id: 'ambiguous_query_expression', reason: `${propertyName || 'input'} accepts query or expression text whose execution semantics are not observable`, ref: ref(artifact, pointer) });
      }
    }
    const destinationClass = destinationInputClass(propertyName, node, toolContext);
    if (destinationClass) {
      const reason = destinationClass === 'unvalidated_destination'
        ? `${propertyName || 'input'} accepts a network destination without a host allowlist`
        : `${propertyName || 'input'} may identify a destination, but network action and host constraints are not both observable`;
      addRisk({ id: destinationClass, reason, ref: ref(artifact, pointer) });
    }
    if (node.properties && typeof node.properties === 'object') {
      const entries = Object.entries(node.properties);
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const [name, child] = entries[index];
        pending.push({ node: child, pointer: `${pointer}/properties/${escapePointer(name)}`, propertyName: name, depth: depth + 1 });
      }
    }
    if (node.items) pending.push({ node: node.items, pointer: `${pointer}/items`, propertyName, depth: depth + 1 });
    for (const keyword of ['allOf', 'oneOf', 'anyOf']) {
      if (!Array.isArray(node[keyword])) continue;
      for (let index = node[keyword].length - 1; index >= 0; index -= 1) {
        pending.push({ node: node[keyword][index], pointer: `${pointer}/${keyword}/${index}`, propertyName, depth: depth + 1 });
      }
    }
  }
  if (analysisIncomplete || unresolvedSchema) {
    addRisk({
      id: 'schema_analysis_incomplete',
      reason: unresolvedSchema
        ? 'input schema contains an unresolved reference or input shape that was not safely flattened'
        : `input schema exceeds the local analysis budget (${MAX_SCHEMA_ANALYSIS_DEPTH} levels or ${MAX_SCHEMA_ANALYSIS_NODES} nodes)`,
      ref: ref(artifact, rootPointer),
    });
  }
  return risks;
}

function normalizedPromptMetadata(value) {
  return String(value).toLowerCase().replace(/\s+/g, ' ').trim();
}

function withoutQuotedOrExampleText(value) {
  let text = normalizedPromptMetadata(value);
  text = text
    .replace(/`[^`\r\n]{0,500}`/g, ' ')
    .replace(/"[^"\r\n]{0,500}"/g, ' ')
    .replace(/“[^”\r\n]{0,500}”/g, ' ')
    .replace(/‘[^’\r\n]{0,500}’/g, ' ')
    .replace(/'(?:(?:ignore|disregard|forget|override|do not|don't|never|always|must|send|provide)[^'\r\n]{0,300})'/g, ' ');
  text = text.replace(/\(([^()\r\n]{0,300})\)/g, (match, _content, offset, source) => {
    const prefix = source.slice(Math.max(0, offset - 100), offset);
    return /\b(?:examples?|e\.g\.|for example|such as|detect(?:ed|s|ing)?|screen(?:s|ed|ing)?|signature corpus|detected classes?)\b/.test(prefix)
      ? ' '
      : match;
  });
  text = text.replace(
    /\b(?:examples?|e\.g\.|for example|such as|detected classes?|signature corpus)\s*(?::|-)?\s*[^.!?\r\n]{0,300}/g,
    ' ',
  );
  return text.replace(/\s+/g, ' ').trim();
}

function promptClauses(value) {
  return withoutQuotedOrExampleText(value).split(/[.!?;\r\n]+/).map(item => item.trim()).filter(Boolean);
}

function promptMetadataReviewSignal(value, toolLevelMetadata) {
  const raw = normalizedPromptMetadata(value)
    .replace(/[`"“”‘’']/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const filtered = withoutQuotedOrExampleText(value);
  const suppressed = raw !== filtered;
  const override = /\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:instruction|message|policy|rule)s?\b/.test(raw);
  const concealed = /\b(?:do not|don't|never)\b.{0,50}\b(?:tell|mention|show|reveal|disclose|inform|notify)\b.{0,80}\b(?:user|operator|human)\b/.test(raw);
  const sensitive = /\b(?:send|upload|post|transmit|reveal|provide|enter|share|submit|request)\b.{0,100}\b(?:password|secret|credential|api[ _-]?key|access[ _-]?token|private[ _-]?key)s?\b/.test(raw);
  const globalSelection = toolLevelMetadata && /\b(?:always|must|required)\b.{0,50}\b(?:call|use|invoke|select|choose)\b.{0,40}\b(?:this|the)\s+tool\b/.test(raw);
  const scopedResponseOrdering = toolLevelMetadata
    && /\b(?:this|the)\s+tool\b.{0,40}\b(?:must|should|required|needs?)\b.{0,35}\b(?:used|called|invoked|selected|chosen)\b.{0,60}\b(?:before|prior to)\b.{0,50}\b(?:answering|responding|replying|handling)\b/.test(raw);
  return (suppressed && (override || concealed || sensitive || globalSelection)) || scopedResponseOrdering;
}

function securityAnalysisContext(hasSecuritySubject, clause) {
  if (!hasSecuritySubject) return false;
  const analysisAction = /\b(?:detect(?:s|ed|ing)?|scan(?:s|ned|ning)?|screen(?:s|ed|ing)?|audit(?:s|ed|ing)?|identify|identifies|flag(?:s|ged|ging)?|signature corpus|guardrail)\b/;
  return analysisAction.test(clause);
}

function instructionOverrideSignal(hasSecuritySubject, clause) {
  const target = /\b(?:previous|prior|system|developer|safety|operator|user)\b.{0,40}\b(?:instruction|message|policy|rule)s?\b/;
  if (!target.test(clause) || securityAnalysisContext(hasSecuritySubject, clause)) return false;
  const action = String.raw`(?:ignore|disregard|forget|override)`;
  const direct = new RegExp(String.raw`^(?:(?:important|instruction|note)\s*:\s*)?(?:(?:please|always)\s+)*${action}\b`);
  const addressed = new RegExp(String.raw`\b(?:you|agent|assistant|model)\s+(?:must|should|need(?:s)?\s+to|is\s+required\s+to|has\s+to)\s+${action}\b`);
  return direct.test(clause) || addressed.test(clause);
}

function concealmentSignal(clause) {
  const hide = String.raw`(?:do\s+not|don't|never)\s+(?:tell|mention|show|reveal|disclose|inform|notify)`;
  const audience = String.raw`(?:the\s+)?(?:user|operator|human)`;
  const behavior = String.raw`(?:this|the)?\s*(?:action|operation|invocation|tool|request|call|behavior|instruction|activity|execution|change)`;
  const preventsUnapprovedAction = new RegExp(String.raw`\b(?:do\s+not|does\s+not|will\s+not|cannot|can't|never|must\s+not)\b.{0,60}\b(?:execute|run|invoke|call|perform|proceed)\b.{0,50}\bwithout\b.{0,20}\b${audience}(?:'s)?\b.{0,20}\b(?:knowledge|consent|approval)\b`);
  if (preventsUnapprovedAction.test(clause)) return false;
  const audienceThenBehavior = new RegExp(String.raw`\b${hide}\b.{0,45}\b${audience}\b.{0,45}\b${behavior}\b`);
  const behaviorThenAudience = new RegExp(String.raw`\b${hide}\b.{0,45}\b${behavior}\b.{0,45}\b${audience}\b`);
  const hiddenAction = new RegExp(String.raw`\b(?:hide|conceal|withhold)\b.{0,45}\b${behavior}\b.{0,45}\bfrom\s+${audience}\b`);
  const withoutKnowledge = new RegExp(String.raw`(?:\b${behavior}\b.{0,45})?\bwithout\b.{0,20}\b${audience}(?:'s)?\b.{0,20}\b(?:knowledge|consent|approval)\b`);
  return audienceThenBehavior.test(clause) || behaviorThenAudience.test(clause)
    || hiddenAction.test(clause) || (withoutKnowledge.test(clause) && new RegExp(String.raw`\b${behavior}\b`).test(clause));
}

function sensitiveDataRequestClass(clause) {
  const sensitiveTerm = String.raw`(?:passwords?(?!\s+reset\b)|secrets?|credentials?|api[ _-]?keys?|access[ _-]?tokens?|private[ _-]?keys?|environment variables?)`;
  const transferVerb = String.raw`(?:send|upload|post|transmit|exfiltrate|reveal|return|provide|enter|share|supply|submit|include|collect|request)`;
  const transferredVerb = String.raw`(?:sent|uploaded|posted|transmitted|exfiltrated|revealed|returned|provided|entered|shared|supplied|submitted|included|collected|requested)`;
  const preventsTransfer = new RegExp(String.raw`\b(?:do not|don't|never|must not|should not)\b.{0,35}\b${transferVerb}\b.{0,90}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,45}\b(?:must not|should not|never)\b.{0,30}\b(?:be\s+)?${transferVerb}\b`);
  const statusOnly = new RegExp(String.raw`\b(?:return|report|show)\b.{0,35}\b(?:whether|if|status)\b.{0,35}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,35}\b(?:configured|exists|present|available|set)\b`);
  if (preventsTransfer.test(clause) || statusOnly.test(clause)) return null;
  const direct = new RegExp(String.raw`(?:^|\b(?:and|then)\s+)(?:(?:please|always)\s+)*(?:${transferVerb})\b.{0,100}\b${sensitiveTerm}\b`);
  const addressed = new RegExp(String.raw`\b(?:you|user|agent|assistant|model)\s+(?:must|should|need(?:s)?\s+to|is\s+required\s+to|has\s+to)\s+${transferVerb}\b.{0,100}\b${sensitiveTerm}\b`);
  const askUser = new RegExp(String.raw`^(?:(?:please|always)\s+)*(?:ask(?:s)?|prompt(?:s)?)\b.{0,30}\b(?:the\s+)?user\b(?:(?:.{0,30}\b(?:to\s+)?${transferVerb}\b.{0,60}\b${sensitiveTerm}\b)|(?:.{0,45}\bfor\b.{0,20}\b${sensitiveTerm}\b))`);
  const requiredPassive = new RegExp(String.raw`\b${sensitiveTerm}\b.{0,35}\b(?:must|should|needs?\s+to|is\s+required\s+to)\b.{0,25}\b(?:be\s+)?(?:${transferVerb}|${transferredVerb})\b`);
  if (!(direct.test(clause) || addressed.test(clause) || askUser.test(clause) || requiredPassive.test(clause))) return null;
  const emission = new RegExp(String.raw`\b(?:return|reveal|send|upload|post|transmit|exfiltrate)\b.{0,100}\b${sensitiveTerm}\b`);
  return emission.test(clause) ? 'emits_or_transmits_credential' : 'solicits_secret';
}

function forcedInvocationSignal(clause) {
  const invoke = String.raw`(?:call|use|invoke|select|choose)`;
  const tool = String.raw`(?:this|the)\s+tool`;
  const globalResponse = String.raw`(?:answer(?:ing)?|respond(?:ing)?|reply(?:ing)?|handling)(?:\s+to)?\s+(?:any|every|all)`;
  const beforeGlobalResponse = new RegExp(String.raw`^(?:before|prior\s+to)\s+${globalResponse}\b.{0,80}\b(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b`);
  const reverseGlobalResponse = new RegExp(String.raw`^(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b.{0,50}\b(?:before|prior\s+to)\b.{0,50}\b${globalResponse}\b`);
  const passiveGlobalResponse = new RegExp(String.raw`^${tool}\s+(?:must|should|needs?\s+to|is\s+required\s+to|has\s+to)\s+be\s+(?:used|called|invoked|selected|chosen)\b.{0,50}\b(?:before|prior\s+to)\b.{0,50}\b${globalResponse}\b`);
  const first = new RegExp(String.raw`^(?:always|must)\s+${invoke}\b.{0,30}\b${tool}\b.{0,12}\bfirst\b`);
  const addressedFirst = new RegExp(String.raw`\b(?:you|agent|assistant|model)\s+(?:must|should|need(?:s)?\s+to|is\s+required\s+to|has\s+to)\s+(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b.{0,12}\bfirst\b`);
  const globalEveryRequest = new RegExp(String.raw`\b(?:for|on)\s+(?:any|every|all)\s+(?:question|request|prompt|task)\b.{0,60}\b(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b`);
  const exclusivePreference = new RegExp(String.raw`\b(?:prefer|always\s+use|must\s+use)\b.{0,30}\b${tool}\b.{0,40}\b(?:over|instead\s+of|rather\s+than)\b.{0,24}\b(?:any|all|other|another|competing)\b`);
  const excludeOthers = new RegExp(String.raw`\b(?:do not|don't|never|avoid)\b.{0,30}\b${invoke}\b.{0,30}\b(?:any|all|other|another|competing)\s+tools?\b`);
  return beforeGlobalResponse.test(clause) || reverseGlobalResponse.test(clause) || passiveGlobalResponse.test(clause) || first.test(clause)
    || addressedFirst.test(clause) || globalEveryRequest.test(clause)
    || exclusivePreference.test(clause) || excludeOthers.test(clause);
}

function toolDescriptionRisks(tool, artifact, toolPointer) {
  const risks = [];
  const networkVerb = String.raw`(?:fetch|download|retrieve|browse|search|read|open|get|scrape|crawl)`;
  const networkSource = String.raw`(?:url|uri|web|website|webpage|internet|remote|http|https)`;
  const networkIntake = new RegExp(String.raw`\b${networkVerb}\b.{0,60}\b${networkSource}\b|\b${networkSource}\b.{0,60}\b${networkVerb}\b`);
  const fields = [
    ['description', tool.description],
    ['title', tool.title],
  ];
  const securityIdentity = [tool.name, tool.title, tool.description]
    .filter(value => typeof value === 'string').map(normalizedPromptMetadata).join(' ');
  const hasSecuritySubject = /\b(?:prompt[ -]?injection|instruction[ -]?override|jailbreak|malware|tool poisoning|adversarial instruction)\b/.test(securityIdentity);
  const schemaEntry = inputSchemaEntries(tool).find(([, value]) => value && typeof value === 'object' && !Array.isArray(value));
  const visitedSchemaNodes = new WeakSet();
  function addSchemaMetadata(node, pointer, depth = 0) {
    if (!node || typeof node !== 'object' || depth > 8) return;
    if (visitedSchemaNodes.has(node)) return;
    visitedSchemaNodes.add(node);
    if (Array.isArray(node)) {
      node.forEach((child, index) => addSchemaMetadata(child, `${pointer}/${index}`, depth + 1));
      return;
    }
    for (const field of ['description', 'title']) {
      if (typeof node[field] === 'string') fields.push([`${pointer}/${field}`, node[field]]);
    }
    for (const [key, child] of Object.entries(node)) {
      if (child && typeof child === 'object') addSchemaMetadata(child, `${pointer}/${escapePointer(key)}`, depth + 1);
    }
  }
  if (schemaEntry) addSchemaMetadata(schemaEntry[1], `${toolPointer}/${schemaEntry[0]}`);
  for (const [field, value] of fields) {
    if (typeof value !== 'string') continue;
    const text = normalizedPromptMetadata(value);
    const clauses = promptClauses(value);
    const pointer = field.startsWith('/') ? field : `${toolPointer}/${field}`;
    const metadataSha256 = sha256(text);
    const instructionOverride = clauses.some(clause => instructionOverrideSignal(hasSecuritySubject, clause));
    const concealedBehavior = clauses.some(concealmentSignal);
    const sensitiveClasses = clauses.map(sensitiveDataRequestClass).filter(Boolean);
    const sensitiveRequest = sensitiveClasses.length > 0;
    const toolLevelMetadata = field === 'description' || field === 'title';
    const forcedInvocation = toolLevelMetadata && clauses.some(forcedInvocationSignal);
    const permissionRequirement = toolLevelMetadata
      && /\b(?:requires?|needs?|must have)\b.{0,45}\b(?:permission|authorization|privilege|administrator|admin role)\b/.test(text);
    if (instructionOverride) {
      risks.push({ id: 'prompt_instruction_override', reason: 'tool description contains directed instruction-override language', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (concealedBehavior) {
      risks.push({ id: 'prompt_concealed_behavior', reason: 'tool description directly asks that tool behavior be concealed from the operator', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (sensitiveRequest) {
      risks.push({
        id: 'prompt_sensitive_data_request',
        subtype: sensitiveClasses.includes('emits_or_transmits_credential') ? 'emits_or_transmits_credential' : 'solicits_secret',
        reason: 'tool description directly solicits or emits sensitive data for a result or transmission',
        ref: ref(artifact, pointer),
        metadata_sha256: metadataSha256,
      });
    }
    if (forcedInvocation) {
      risks.push({ id: 'prompt_forced_invocation', reason: 'tool description attempts to control global tool selection or force invocation', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (permissionRequirement) {
      risks.push({ id: 'permission_requirement_unverified', reason: 'tool metadata claims a permission requirement whose runtime enforcement is not observable', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (!(instructionOverride || concealedBehavior || sensitiveRequest || forcedInvocation)
      && promptMetadataReviewSignal(value, toolLevelMetadata)) {
      risks.push({ id: 'prompt_metadata_review', reason: 'tool metadata contains ambiguous directive-like language that requires operator review', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
  }
  for (const [field, value] of [['name', tool.name], ...fields]) {
    if (typeof value !== 'string') continue;
    const text = normalizedWords(value).replace(/\s+/g, ' ');
    if (networkIntake.test(text)) {
      risks.push({ id: 'untrusted_network_fetch', reason: 'tool retrieves content from a network-controlled source', ref: ref(artifact, `${toolPointer}/${field}`) });
      break;
    }
  }
  return risks;
}

function normalizeTool(tool, index, artifact, basePointer, dialect, options = {}) {
  assertObject(tool, `${artifact.kind} tool ${index}`);
  if (typeof tool.name !== 'string' || !tool.name.trim()) throw new Error(`${artifact.kind} tool ${index}.name must be a non-empty string`);
  if (inputSchemaEntries(tool).length > 1) {
    throw new Error(`tool manifest tool ${index} contains multiple supported input schema aliases`);
  }
  const extension = tool['x-backbond'];
  if (extension !== undefined) assertObject(extension, `${artifact.kind} tool ${index}.x-backbond`);
  const controls = options.canonical ? tool : (extension || {});
  const explicitCapabilities = validateCapabilities(controls.capabilities, `${artifact.kind} tool ${index}.capabilities`);
  const derivedCapabilities = [...new Set([...inferCapabilities(tool), ...(options.forceCapabilities || [])])].sort();
  const capabilities = [...new Set([...derivedCapabilities, ...explicitCapabilities])].sort();
  const toolPointer = options.pointerOverride || `${basePointer}/${index}`;
  const compositionPrivilege = compositionPrivilegeEvidence(tool, artifact, toolPointer, explicitCapabilities, options.forceCapabilities || []);
  const explicitTrust = controls.input_trust !== undefined;
  const inputTrust = explicitTrust
    ? validateEnum(controls.input_trust, INPUT_TRUST, `${artifact.kind} tool ${index}.input_trust`)
    : (options.canonical ? 'unknown' : 'mixed');
  const risks = [...semanticRisks(tool, artifact, toolPointer), ...toolDescriptionRisks(tool, artifact, toolPointer)];
  return {
    name: tool.name,
    dialect,
    capabilities,
    input_schema_observed: hasInputSchema(tool),
    semantic_metadata_observed: [tool.description, tool.title].some(value => typeof value === 'string' && value.trim()),
    semantic_risks: risks,
    composition_privilege: compositionPrivilege,
    input_trust: inputTrust,
    approval: validateEnum(controls.approval !== undefined ? controls.approval : options.approval, APPROVAL, `${artifact.kind} tool ${index}.approval`),
    audit: validateEnum(controls.audit, AUDIT, `${artifact.kind} tool ${index}.audit`),
    provenance: {
      capabilities: Object.fromEntries(capabilities.map(capability => [capability, explicitCapabilities.includes(capability) ? 'explicit' : 'derived'])),
      input_trust: explicitTrust ? 'explicit' : (options.canonical ? 'unknown' : 'derived'),
      semantic_risks: risks.length ? 'derived' : 'none',
    },
    refs: {
      identity: ref(artifact, `${toolPointer}/name`),
      capabilities: ref(artifact, `${toolPointer}${options.canonical ? '/capabilities' : ''}`),
      input_trust: ref(artifact, `${toolPointer}${options.canonical ? '/input_trust' : ''}`),
      approval: ref(artifact, `${toolPointer}${options.canonical ? '/approval' : ''}`),
      audit: ref(artifact, `${toolPointer}${options.canonical ? '/audit' : ''}`),
    },
  };
}

function normalizeToolSchema(document, artifact) {
  const openApiMarked = document && typeof document === 'object' && !Array.isArray(document)
    && Boolean((document.openapi || document.swagger) && document.paths);
  const toolListMarked = Array.isArray(document)
    || Boolean(document && typeof document === 'object' && !Array.isArray(document)
      && (Array.isArray(document.tools) || (document.result && Array.isArray(document.result.tools))));
  if (openApiMarked && (toolListMarked || document.protocol === 'backbond-tool-schema/v1')) {
    throw new Error('tool manifest mixes OpenAPI and tool-list dialect markers');
  }
  if (document && document.protocol === 'backbond-tool-schema/v1') {
    assertObject(document, 'tool schema');
    if (!Array.isArray(document.tools)) throw new Error('backbond-tool-schema/v1 tools must be an array');
    artifact.dialect = 'backbond-tool-schema/v1';
    return document.tools.map((tool, index) => normalizeTool(tool, index, artifact, '/tools', artifact.dialect, { canonical: true }));
  }
  let tools;
  let basePointer;
  let dialect;
  const candidates = [];
  if (Array.isArray(document)) candidates.push({ tools: document, basePointer: '' });
  else if (document && typeof document === 'object') {
    if (Array.isArray(document.tools)) candidates.push({ tools: document.tools, basePointer: '/tools' });
    if (document.result && Array.isArray(document.result.tools)) candidates.push({ tools: document.result.tools, basePointer: '/result/tools', dialect: 'mcp-tools-list/v1' });
  }
  if (candidates.length > 1) throw new Error('tool manifest contains multiple supported tool-list locations');
  if (!candidates.length) return null;
  ({ tools, basePointer, dialect } = candidates[0]);
  if (!dialect && tools.length > 0 && tools.every(tool => tool && tool.type === 'function' && tool.function)) {
    dialect = 'openai-function-tools/v1';
    artifact.dialect = dialect;
    return tools.map((entry, index) => normalizeTool(entry.function, index, artifact, basePointer, dialect, { pointerOverride: `${basePointer}/${index}/function` }));
  }
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && tool.input_schema)) dialect = 'anthropic-tools/v1';
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && (tool.inputSchema || tool.parameters))) dialect = 'mcp-tools-list/v1';
  if (!dialect && tools.length === 0) dialect = 'generic-tool-list/v1';
  if (!dialect) {
    const entryDialects = tools.map(tool => {
      const matches = [];
      if (tool && tool.type === 'function' && tool.function) matches.push('openai');
      if (tool && typeof tool.name === 'string' && tool.input_schema) matches.push('anthropic');
      if (tool && typeof tool.name === 'string' && (tool.inputSchema || tool.parameters)) matches.push('mcp');
      return matches;
    });
    if (entryDialects.some(matches => matches.length > 0)) {
      throw new Error('tool manifest contains mixed supported tool entry dialects');
    }
    return null;
  }
  artifact.dialect = dialect;
  return tools.map((tool, index) => normalizeTool(tool, index, artifact, basePointer, dialect));
}

function isAmbiguousToolManifestError(error) {
  return error instanceof Error && ([
    'tool manifest mixes OpenAPI and tool-list dialect markers',
    'tool manifest contains multiple supported tool-list locations',
    'tool manifest contains mixed supported tool entry dialects',
  ].includes(error.message) || error.message.startsWith('tool manifest tool ') && error.message.endsWith(' contains multiple supported input schema aliases'));
}

function normalizeOpenApi(document, artifact) {
  if (!document || typeof document !== 'object' || (!document.openapi && !document.swagger) || !document.paths) return null;
  const dialect = document.openapi ? `openapi/${document.openapi}` : `swagger/${document.swagger}`;
  artifact.dialect = dialect;
  const tools = [];
  const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);
  for (const [route, routeItem] of Object.entries(document.paths)) {
    if (!routeItem || typeof routeItem !== 'object') continue;
    for (const [method, operation] of Object.entries(routeItem)) {
      if (!methods.has(method.toLowerCase()) || !operation || typeof operation !== 'object') continue;
      const properties = {};
      let analysisIncomplete = false;
      const routeParameters = Array.isArray(routeItem.parameters) ? routeItem.parameters : [];
      const operationParameters = Array.isArray(operation.parameters) ? operation.parameters : [];
      if (routeItem.parameters !== undefined && !Array.isArray(routeItem.parameters)) analysisIncomplete = true;
      if (operation.parameters !== undefined && !Array.isArray(operation.parameters)) analysisIncomplete = true;
      for (const parameter of [...routeParameters, ...operationParameters]) {
        if (!parameter || typeof parameter !== 'object') {
          analysisIncomplete = true;
          continue;
        }
        if (typeof parameter.$ref === 'string' || !parameter.name) {
          analysisIncomplete = true;
          continue;
        }
        properties[parameter.name] = parameter.schema || { type: parameter.type || 'string', description: parameter.description };
      }
      const requestContent = operation.requestBody && operation.requestBody.content;
      const requestSchema = requestContent && Object.values(requestContent).find(item => item && item.schema);
      if (operation.requestBody && typeof operation.requestBody.$ref === 'string') analysisIncomplete = true;
      if (requestContent && !requestSchema) analysisIncomplete = true;
      let parameters = { type: 'object', properties };
      if (requestSchema && requestSchema.schema) {
        parameters = { allOf: [parameters, requestSchema.schema] };
      }
      if (analysisIncomplete) parameters['x-backbond-analysis-incomplete'] = true;
      const tool = {
        name: operation.operationId || `${method.toLowerCase()}_${route.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '')}`,
        description: [operation.summary, operation.description, `${method.toUpperCase()} ${route}`].filter(Boolean).join(' '),
        parameters,
      };
      const forced = ['network_egress'];
      if (method.toLowerCase() === 'delete') forced.push('destructive_action', 'privileged_action');
      tools.push(normalizeTool(tool, tools.length, artifact, `/paths/${escapePointer(route)}/${method}`, dialect, {
        pointerOverride: `/paths/${escapePointer(route)}/${method}`,
        forceCapabilities: forced,
      }));
    }
  }
  return tools;
}

function scopeIsWildcard(value) {
  if (value === true) return true;
  if (typeof value === 'string') return ['*', '**', '/*', '/', 'all', 'any'].includes(value.toLowerCase()) || /^[a-z]:[\\/]?$/i.test(value);
  if (Array.isArray(value)) return value.some(scopeIsWildcard);
  if (value && typeof value === 'object') return value.unrestricted === true;
  return false;
}

function validateScope(value, label) {
  if (value === undefined) return;
  if (typeof value === 'string') { if (!value.trim()) throw new Error(`${label} must not be empty`); return; }
  if (Array.isArray(value)) { if (value.some(item => typeof item !== 'string' || !item.trim())) throw new Error(`${label} must contain only non-empty strings`); return; }
  if (value && typeof value === 'object' && !Array.isArray(value) && value.unrestricted === true) return;
  throw new Error(`${label} must be a string array or {"unrestricted":true}`);
}

function emptyPermissionFacts() {
  return { input_trust: 'unknown', input_trust_ref: null, tools: [], wildcards: [], secret_access_unrestricted: false, network_egress_unrestricted: false, network_scope_observed: false };
}

function normalizePermissions(document, artifact) {
  if (!document || document.protocol !== 'backbond-permissions/v1') return null;
  assertObject(document, 'permissions');
  artifact.dialect = 'backbond-permissions/v1';
  const inputTrust = validateEnum(document.input_trust, INPUT_TRUST, 'permissions.input_trust');
  const tools = [];
  if (document.tools !== undefined) assertObject(document.tools, 'permissions.tools');
  for (const [name, controls] of Object.entries(document.tools || {})) {
    if (!name.trim()) throw new Error('permissions.tools keys must be non-empty tool names');
    assertObject(controls, `permissions.tools.${name}`);
    tools.push({
      name,
      capabilities: validateCapabilities(controls.capabilities, `permissions.tools.${name}.capabilities`), semantic_risks: [],
      input_trust: validateEnum(controls.input_trust, INPUT_TRUST, `permissions.tools.${name}.input_trust`),
      approval: validateEnum(controls.approval, APPROVAL, `permissions.tools.${name}.approval`),
      audit: validateEnum(controls.audit, AUDIT, `permissions.tools.${name}.audit`),
      provenance: { capabilities: Object.fromEntries((controls.capabilities || []).map(item => [item, 'explicit'])), input_trust: controls.input_trust === undefined ? 'unknown' : 'explicit', semantic_risks: 'none' },
      refs: {
        identity: ref(artifact, `/tools/${escapePointer(name)}`), capabilities: ref(artifact, `/tools/${escapePointer(name)}/capabilities`),
        input_trust: ref(artifact, `/tools/${escapePointer(name)}/input_trust`), approval: ref(artifact, `/tools/${escapePointer(name)}/approval`), audit: ref(artifact, `/tools/${escapePointer(name)}/audit`),
      },
    });
  }
  const scopes = [['filesystem', 'read'], ['filesystem', 'write'], ['subprocess', 'allow'], ['credentials', 'read'], ['network', 'egress']];
  const wildcards = [];
  for (const [domain, field] of scopes) {
    const container = document[domain];
    if (container !== undefined) assertObject(container, `permissions.${domain}`);
    if (container) validateScope(container[field], `permissions.${domain}.${field}`);
    if (container && scopeIsWildcard(container[field])) wildcards.push({ domain, field, provenance: 'explicit', ref: ref(artifact, `/${domain}/${field}`) });
  }
  return {
    input_trust: inputTrust, input_trust_ref: ref(artifact, '/input_trust'), tools, wildcards,
    secret_access_unrestricted: wildcards.some(item => item.domain === 'credentials'),
    network_egress_unrestricted: wildcards.some(item => item.domain === 'network'),
    network_scope_observed: Boolean(document.network && document.network.egress !== undefined),
  };
}

function normalizeClaudeSettings(document, artifact) {
  if (artifact.adapter !== 'claude-code' || !document || typeof document !== 'object' || Array.isArray(document)) return null;
  artifact.dialect = 'claude-code-settings/v1';
  const permission = emptyPermissionFacts();
  const tools = [];
  if (document.permissions !== undefined) assertObject(document.permissions, 'Claude Code permissions');
  const controls = document.permissions || {};
  for (const field of ['allow', 'ask']) {
    if (controls[field] !== undefined && !Array.isArray(controls[field])) throw new Error(`Claude Code permissions.${field} must be an array`);
    if (Array.isArray(controls[field]) && controls[field].some(rule => typeof rule !== 'string' || !rule.trim())) {
      throw new Error(`Claude Code permissions.${field} must contain only non-empty strings`);
    }
  }
  if (controls.defaultMode !== undefined && typeof controls.defaultMode !== 'string') throw new Error('Claude Code permissions.defaultMode must be a string');
  const permissionObserved = Array.isArray(controls.allow) || Array.isArray(controls.ask) || controls.defaultMode !== undefined;
  for (const [field, approval] of [['allow', 'none'], ['ask', 'enforced']]) {
    if (!Array.isArray(controls[field])) continue;
    controls[field].forEach((rule, index) => {
      const name = rule.trim().split(/[(:]/, 1)[0].trim();
      if (!name) return;
      const pointer = `/permissions/${field}/${index}`;
      const bodyMatch = rule.trim().match(/^[^(]+\((.*)\)$/);
      const body = bodyMatch ? bodyMatch[1].trim() : '';
      const normalizedName = name.toLowerCase();
      const allInvocations = !bodyMatch || !body;
      const globalPath = allInvocations || scopeIsWildcard(body) || /^(?:\/{1,2}\*{1,2}|[a-z]:[\\/]\*{1,2})$/i.test(body);
      const forcedCapabilities = [];
      if (['read', 'edit', 'write'].includes(normalizedName)) forcedCapabilities.push('filesystem_access');
      if (normalizedName === 'bash') forcedCapabilities.push('code_execution');
      if (normalizedName === 'webfetch') forcedCapabilities.push('network_egress');
      tools.push(normalizeTool({ name, description: rule, inputSchema: { type: 'object' } }, index, artifact, `/permissions/${field}`, artifact.dialect, { pointerOverride: pointer, approval, forceCapabilities: forcedCapabilities }));
      if (normalizedName === 'bash' && (allInvocations || scopeIsWildcard(body))) permission.wildcards.push({ domain: 'subprocess', field: 'allow', provenance: 'derived', ref: ref(artifact, pointer) });
      if (normalizedName === 'read' && globalPath) permission.wildcards.push({ domain: 'filesystem', field: 'read', provenance: 'derived', ref: ref(artifact, pointer) });
      if (['edit', 'write'].includes(normalizedName) && globalPath) permission.wildcards.push({ domain: 'filesystem', field: 'write', provenance: 'derived', ref: ref(artifact, pointer) });
      if (normalizedName === 'webfetch' && (allInvocations || /^(?:domain\s*:\s*)?\*$/i.test(body))) {
        permission.wildcards.push({ domain: 'network', field: 'egress', provenance: 'derived', ref: ref(artifact, pointer) });
        permission.network_scope_observed = true;
      }
    });
  }
  if (controls.defaultMode === 'bypassPermissions') {
    permission.wildcards.push({ domain: 'subprocess', field: 'allow', provenance: 'derived', ref: ref(artifact, '/permissions/defaultMode') });
  }
  permission.secret_access_unrestricted = permission.wildcards.some(item => item.domain === 'credentials');
  permission.network_egress_unrestricted = permission.wildcards.some(item => item.domain === 'network');
  return {
    tools,
    permission,
    permissionObserved,
    gaps: tools.length ? [] : [gap('tool_schema', 'missing', 'BB-COV-CLAUDE-TOOLS-NOT-EXPORTED', 'Claude Code settings were found, but no allow/ask tool identities were exported', artifact)],
  };
}

function normalizeAgentConfig(document, artifact) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return null;
  const containers = [];
  if (document.mcpServers && typeof document.mcpServers === 'object') containers.push({ servers: document.mcpServers, pointer: '/mcpServers' });
  if (document.servers && typeof document.servers === 'object') containers.push({ servers: document.servers, pointer: '/servers' });
  if (document.mcp && document.mcp.servers && typeof document.mcp.servers === 'object') containers.push({ servers: document.mcp.servers, pointer: '/mcp/servers' });
  if (document.projects && typeof document.projects === 'object') {
    for (const [projectName, projectConfig] of Object.entries(document.projects)) {
      if (projectConfig && projectConfig.mcpServers && typeof projectConfig.mcpServers === 'object') {
        containers.push({ servers: projectConfig.mcpServers, pointer: `/projects/${escapePointer(projectName)}/mcpServers` });
      }
    }
  }
  if (!containers.length) return normalizeClaudeSettings(document, artifact);
  artifact.dialect = `${artifact.adapter || 'generic'}-mcp-config/v1`;
  const tools = [];
  const permission = emptyPermissionFacts();
  const gaps = [];
  const addWildcard = (domain, field, pointer) => permission.wildcards.push({ domain, field, provenance: 'derived', ref: ref(artifact, pointer) });
  const sandbox = document.sandbox || {};
  const filesystem = sandbox.filesystem || {};
  const network = sandbox.network || {};
  if (filesystem.allowRead !== undefined) validateScope(filesystem.allowRead, 'config sandbox.filesystem.allowRead');
  if (filesystem.allowWrite !== undefined) validateScope(filesystem.allowWrite, 'config sandbox.filesystem.allowWrite');
  if (scopeIsWildcard(filesystem.allowRead)) addWildcard('filesystem', 'read', '/sandbox/filesystem/allowRead');
  if (scopeIsWildcard(filesystem.allowWrite)) addWildcard('filesystem', 'write', '/sandbox/filesystem/allowWrite');
  if (network.allowedDomains !== undefined) {
    validateScope(network.allowedDomains, 'config sandbox.network.allowedDomains');
    permission.network_scope_observed = true;
  }
  if (scopeIsWildcard(network.allowedDomains)) addWildcard('network', 'egress', '/sandbox/network/allowedDomains');
  for (const container of containers) {
    for (const [serverName, server] of Object.entries(container.servers)) {
      if (!server || typeof server !== 'object') continue;
      const pointer = `${container.pointer}/${escapePointer(serverName)}`;
      const autoApprovedNames = [
        ...(Array.isArray(server.alwaysAllow) ? server.alwaysAllow : []),
        ...(Array.isArray(server.autoApprove) ? server.autoApprove : []),
      ].filter(item => typeof item === 'string' && item.trim());
      const approval = server.trust === true || server.autoApprove === true ? 'none' : undefined;
      const manifests = Array.isArray(server.tools) ? server.tools : Array.isArray(server.toolSchemas) ? server.toolSchemas : null;
      if (manifests) {
        manifests.forEach((tool, index) => tools.push(normalizeTool(tool, index, artifact, `${pointer}/tools`, artifact.dialect, { approval })));
      } else if (Array.isArray(server.includeTools) || autoApprovedNames.length) {
        const namedTools = [...new Set([...(Array.isArray(server.includeTools) ? server.includeTools : []), ...autoApprovedNames])];
        const namedPointer = Array.isArray(server.includeTools) ? 'includeTools' : Array.isArray(server.alwaysAllow) ? 'alwaysAllow' : 'autoApprove';
        namedTools.forEach((name, index) => {
          if (typeof name !== 'string' || !name.trim()) return;
          const namedApproval = autoApprovedNames.includes(name) ? 'none' : approval;
          tools.push(normalizeTool({ name, description: `Tool exported by MCP server ${serverName}`, inputSchema: { type: 'object' } }, index, artifact, `${pointer}/${namedPointer}`, artifact.dialect, { approval: namedApproval }));
        });
      } else {
        gaps.push(gap('tool_schema', 'missing', 'BB-COV-MCP-TOOLS-NOT-EXPORTED', `MCP server ${serverName} is configured, but its live tools are not exported`, artifact));
      }
      const serverArgs = Array.isArray(server.args) ? server.args.filter(item => typeof item === 'string') : [];
      const roleArgs = serverArgs.filter(item => /mcp|server|shell|bash|terminal|exec|fetch|browser|filesystem|database|postgres|mysql|sqlite|1password|onepassword|vault/i.test(item));
      const command = typeof server.command === 'string'
        ? server.command.trim().replace(/^["']|["']$/g, '').split(/[\\/]/).pop()
        : '';
      const roleText = `${serverName} ${command || ''} ${roleArgs.join(' ')}`;
      const forced = inferCapabilities({ name: serverName, description: roleText, inputSchema: { type: 'object' } });
      if (server.url || server.httpUrl) {
        forced.push('network_egress');
        permission.network_scope_observed = true;
        if (scopeIsWildcard(server.url || server.httpUrl)) addWildcard('network', 'egress', `${pointer}/${server.url ? 'url' : 'httpUrl'}`);
      }
      const directServerDomains = server.allowedDomains !== undefined;
      const serverDomains = directServerDomains ? server.allowedDomains : server.network && server.network.allowedDomains;
      const serverDomainsPointer = `${pointer}/${directServerDomains ? 'allowedDomains' : 'network/allowedDomains'}`;
      if (serverDomains !== undefined) {
        validateScope(serverDomains, `config MCP server ${serverName}.allowedDomains`);
        permission.network_scope_observed = true;
        if (scopeIsWildcard(serverDomains)) addWildcard('network', 'egress', serverDomainsPointer);
      } else if (forced.includes('network_egress') && /\b(fetch|browser|web|http|request)\b/i.test(normalizedWords(roleText))) {
        permission.network_scope_observed = true;
        addWildcard('network', 'egress', pointer);
      }
      const envKeys = server.env && typeof server.env === 'object' ? Object.keys(server.env) : [];
      if (envKeys.some(key => /token|secret|password|credential|api.?key/i.test(key))) {
        gaps.push(gap('permissions', 'insufficient_evidence', 'BB-COV-MCP-CREDENTIAL-EXPOSURE', `MCP server ${serverName} has credential-shaped environment names, but tool access to their values is not observable`, artifact));
      }
      if (forced.length && !manifests && !Array.isArray(server.includeTools) && !autoApprovedNames.length) {
        tools.push(normalizeTool({ name: `mcp_server_${serverName}`, description: `Configured MCP server ${serverName}`, inputSchema: { type: 'object' } }, tools.length, artifact, pointer, artifact.dialect, { pointerOverride: pointer, forceCapabilities: forced, approval }));
      }
      if (forced.includes('filesystem_access') && serverArgs.some(scopeIsWildcard)) {
        addWildcard('filesystem', 'read', `${pointer}/args`);
        if (!serverArgs.some(item => /^(?:--)?read[-_]?only(?:=true)?$/i.test(item))) addWildcard('filesystem', 'write', `${pointer}/args`);
      }
    }
  }
  permission.secret_access_unrestricted = permission.wildcards.some(item => item.domain === 'credentials');
  permission.network_egress_unrestricted = permission.wildcards.some(item => item.domain === 'network');
  const permissionObserved = permission.wildcards.length > 0
    || permission.network_scope_observed
    || tools.some(tool => tool.approval !== 'unknown');
  return { tools, permission, permissionObserved, gaps };
}

function normalizeTrace(document, artifact) {
  if (!document || document.protocol !== 'backbond-trace/v1') return null;
  assertObject(document, 'trace');
  if (!Array.isArray(document.events)) throw new Error('backbond-trace/v1 events must be an array');
  artifact.dialect = 'backbond-trace/v1';
  const calls = [];
  document.events.forEach((event, index) => {
    assertObject(event, `trace event ${index}`);
    if (event.type !== 'tool_call') return;
    if (typeof event.tool !== 'string' || !event.tool.trim()) throw new Error(`trace event ${index}.tool must be a non-empty string`);
    calls.push({
      name: event.tool, capabilities: validateCapabilities(event.capabilities, `trace event ${index}.capabilities`), semantic_risks: [],
      input_trust: validateEnum(event.input_trust, INPUT_TRUST, `trace event ${index}.input_trust`), approval: validateEnum(event.approval, APPROVAL, `trace event ${index}.approval`), audit: validateEnum(event.audit, AUDIT, `trace event ${index}.audit`),
      provenance: { capabilities: Object.fromEntries((event.capabilities || []).map(item => [item, 'explicit'])), input_trust: event.input_trust === undefined ? 'unknown' : 'explicit', semantic_risks: 'none' },
      refs: { identity: ref(artifact, `/events/${index}/tool`), capabilities: ref(artifact, `/events/${index}/capabilities`), input_trust: ref(artifact, `/events/${index}/input_trust`), approval: ref(artifact, `/events/${index}/approval`), audit: ref(artifact, `/events/${index}/audit`) },
    });
  });
  return calls;
}

function otelAttributeMap(attributes) {
  const result = {};
  for (const attribute of attributes || []) {
    if (!attribute || !attribute.key || !attribute.value) continue;
    const value = attribute.value;
    result[attribute.key] = value.stringValue ?? value.boolValue ?? value.intValue ?? value.doubleValue ?? null;
  }
  return result;
}

function normalizeOtel(document, artifact) {
  const resourceSpans = document && (document.resourceSpans || document.resource_spans);
  if (!Array.isArray(resourceSpans)) return null;
  artifact.dialect = 'opentelemetry-otlp-json/v1';
  const tools = [];
  resourceSpans.forEach((resource, resourceIndex) => {
    const scopes = resource.scopeSpans || resource.scope_spans || resource.instrumentationLibrarySpans || [];
    scopes.forEach((scope, scopeIndex) => (scope.spans || []).forEach((span, spanIndex) => {
      const attrs = otelAttributeMap(span.attributes);
      const operation = attrs['gen_ai.operation.name'] || attrs['gen_ai.operation_name'];
      const toolName = attrs['gen_ai.tool.name'] || attrs['gen_ai.tool_name'] || attrs['tool.name'];
      if (!toolName && !/tool/i.test(span.name || '') && !/execute_tool|tool_call/i.test(operation || '')) return;
      const name = String(toolName || span.name || `tool_span_${spanIndex}`);
      const pointer = `/resourceSpans/${resourceIndex}/scopeSpans/${scopeIndex}/spans/${spanIndex}`;
      tools.push(normalizeTool({ name, description: String(span.name || ''), inputSchema: { type: 'object' } }, tools.length, artifact, pointer, artifact.dialect, { pointerOverride: pointer }));
    }));
  });
  return tools;
}

function escapePointer(value) { return String(value).replace(/~/g, '~0').replace(/\//g, '~1'); }

function mergeTrust(values, fallback = 'unknown') {
  const known = values.filter(value => value && value !== 'unknown');
  if (known.some(value => value === 'untrusted' || value === 'mixed')) return 'untrusted';
  if (known.length && known.every(value => value === 'trusted')) return 'trusted';
  return fallback === 'mixed' ? 'untrusted' : fallback;
}

function mergeApproval(values) {
  const known = values.filter(value => value && value !== 'unknown');
  if (known.some(value => value === 'none' || value === 'advisory')) return 'not_enforced';
  if (known.some(value => value === 'enforced')) return 'enforced';
  return 'unknown';
}

function mergeAudit(values) {
  const known = values.filter(value => value && value !== 'unknown');
  if (known.some(value => value === 'none')) return 'not_observable';
  if (known.some(value => value === 'observable')) return 'observable';
  return 'unknown';
}

function uniqueRefs(refs) {
  const seen = new Set();
  return refs.flat().filter(Boolean).filter(item => {
    const key = `${item.artifact_kind}:${item.artifact_name}:${item.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mergeToolFacts(sources, globalInputTrust) {
  const grouped = new Map();
  for (const source of sources) { if (!grouped.has(source.name)) grouped.set(source.name, []); grouped.get(source.name).push(source); }
  return [...grouped.entries()].map(([name, entries]) => {
    const capabilities = [...new Set(entries.flatMap(entry => entry.capabilities))].sort();
    const semantic = entries.flatMap(entry => entry.semantic_risks || []);
    const inventoryObservations = entries.map(entry => {
      const identity = entry.refs && entry.refs.identity;
      const inventory = identity ? `${identity.artifact_kind}:${identity.artifact_name}` : 'unknown';
      return {
        inventory,
        capabilities: [...entry.capabilities],
        semantic_risks: [...(entry.semantic_risks || [])],
        composition_privilege: entry.composition_privilege || { observed: false, provenance: 'none', ref: null },
        input_trust: mergeTrust([entry.input_trust], globalInputTrust),
        refs: entry.refs,
      };
    });
    return {
      name, capabilities, semantic_risks: semantic,
      composition_privilege: entries.find(entry => entry.composition_privilege && entry.composition_privilege.observed)?.composition_privilege
        || { observed: false, provenance: 'none', ref: null },
      observation_count: entries.length,
      input_schema_observed: entries.every(entry => entry.input_schema_observed === true),
      semantic_metadata_observed: entries.every(entry => entry.semantic_metadata_observed === true),
      inventory_observations: inventoryObservations,
      input_trust: mergeTrust(entries.map(entry => entry.input_trust), globalInputTrust),
      approval: mergeApproval(entries.map(entry => entry.approval)), audit: mergeAudit(entries.map(entry => entry.audit)),
      provenance: {
        capabilities: Object.fromEntries(capabilities.map(capability => [capability, entries.some(entry => entry.provenance && entry.provenance.capabilities[capability] === 'explicit') ? 'explicit' : 'derived'])),
        input_trust: entries.some(entry => entry.provenance && entry.provenance.input_trust === 'explicit') ? 'explicit' : entries.some(entry => entry.provenance && entry.provenance.input_trust === 'derived') ? 'derived' : 'unknown',
        semantic_risks: semantic.length ? 'derived' : 'none',
      },
      refs: {
        identity: uniqueRefs(entries.map(entry => entry.refs.identity)), capabilities: uniqueRefs(entries.filter(entry => entry.capabilities.length).map(entry => entry.refs.capabilities)),
        input_trust: uniqueRefs(entries.filter(entry => entry.input_trust !== 'unknown').map(entry => entry.refs.input_trust)), approval: uniqueRefs(entries.filter(entry => entry.approval !== 'unknown').map(entry => entry.refs.approval)), audit: uniqueRefs(entries.filter(entry => entry.audit !== 'unknown').map(entry => entry.refs.audit)),
      },
    };
  }).sort((a, b) => a.name.localeCompare(b.name));
}

function gap(kind, status, code, message, artifact = null) {
  return { code, artifact_kind: kind, status, message, artifact_name: artifact ? artifact.name : null };
}

function mergePermissions(items) {
  if (!items.length) return emptyPermissionFacts();
  return {
    input_trust: mergeTrust(items.map(item => item.input_trust)),
    input_trust_ref: items.find(item => item.input_trust_ref)?.input_trust_ref || null,
    tools: items.flatMap(item => item.tools), wildcards: items.flatMap(item => item.wildcards),
    secret_access_unrestricted: items.some(item => item.secret_access_unrestricted),
    network_egress_unrestricted: items.some(item => item.network_egress_unrestricted),
    network_scope_observed: items.some(item => item.network_scope_observed),
  };
}

function collectEvidence(options = {}) {
  const sources = [];
  if (options.toolSchemaPath) sources.push({ kind: 'tool_schema', path: options.toolSchemaPath });
  if (options.permissionsPath) sources.push({ kind: 'permissions', path: options.permissionsPath });
  if (options.tracePath) sources.push({ kind: 'trace', path: options.tracePath });
  for (const item of options.artifactPaths || []) sources.push(item);
  const loadedSources = sources.map(item => readJsonArtifact(item.kind || 'config', item.path, item.adapter || null));
  for (const item of options.documents || []) loadedSources.push(memoryArtifact(item.kind || 'tool_schema', item.name || '<memory>', item.document, item.raw, item.adapter || null));
  const totals = new Map();
  for (const loaded of loadedSources) {
    const key = `${loaded.metadata.kind}:${loaded.metadata.name}`;
    totals.set(key, (totals.get(key) || 0) + 1);
  }
  const ordinals = new Map();
  for (const loaded of loadedSources) {
    const key = `${loaded.metadata.kind}:${loaded.metadata.name}`;
    if (totals.get(key) <= 1) continue;
    const ordinal = (ordinals.get(key) || 0) + 1;
    ordinals.set(key, ordinal);
    loaded.metadata.name = `${loaded.metadata.name}#${ordinal}`;
  }

  const artifacts = [];
  const coverageGaps = [];
  const toolSources = [];
  const permissionSources = [];
  let toolEvidenceSeen = false;
  let permissionEvidenceSeen = false;
  let traceEvidenceSeen = false;

  for (const loaded of loadedSources) {
    const { document, metadata } = loaded;
    let recognized = false;
    const canonicalPermissions = normalizePermissions(document, metadata);
    if (canonicalPermissions) { permissionSources.push(canonicalPermissions); permissionEvidenceSeen = true; recognized = true; }
    if (!recognized) {
      const canonicalTrace = normalizeTrace(document, metadata);
      const otelTrace = canonicalTrace === null ? normalizeOtel(document, metadata) : null;
      if (canonicalTrace !== null || otelTrace !== null) {
        toolSources.push(...(canonicalTrace || otelTrace)); traceEvidenceSeen = true; recognized = true;
      }
    }
    if (!recognized) {
      let schema;
      let openapi;
      try {
        schema = normalizeToolSchema(document, metadata);
        openapi = schema === null ? normalizeOpenApi(document, metadata) : null;
      } catch (error) {
        if (!options.reviewAmbiguousToolManifest || !isAmbiguousToolManifestError(error)) throw error;
        metadata.dialect = 'ambiguous-tool-manifest';
        coverageGaps.push(gap(metadata.kind, 'insufficient_evidence', 'BB-VET-AMBIGUOUS-MANIFEST', `Tool manifest is ambiguous: ${error.message}`, metadata));
        recognized = true;
      }
      if (!recognized && (schema !== null || openapi !== null)) { toolSources.push(...(schema || openapi)); toolEvidenceSeen = true; recognized = true; }
    }
    if (!recognized) {
      const config = normalizeAgentConfig(document, metadata);
      if (config) {
        toolSources.push(...config.tools); permissionSources.push(config.permission); coverageGaps.push(...config.gaps);
        toolEvidenceSeen = config.tools.length > 0 || toolEvidenceSeen;
        permissionEvidenceSeen = config.permissionObserved === true || permissionEvidenceSeen;
        recognized = true;
      }
    }
    if (!recognized) {
      metadata.dialect = 'unsupported';
      coverageGaps.push(gap(metadata.kind, 'unsupported', `BB-COV-UNSUPPORTED-${metadata.kind.toUpperCase()}`, `${metadata.kind} JSON does not match a supported dialect`, metadata));
    }
    artifacts.push(metadata);
  }

  if (!toolEvidenceSeen) coverageGaps.push(gap('tool_schema', 'missing', 'BB-COV-MISSING-TOOL_SCHEMA', 'No live tool schema or recognized tool manifest was observed'));
  if (!permissionEvidenceSeen) coverageGaps.push(gap('permissions', 'missing', 'BB-COV-MISSING-PERMISSIONS', 'No supported approval or permission map was observed'));
  if (!traceEvidenceSeen) coverageGaps.push(gap('trace', 'missing', 'BB-COV-MISSING-TRACE', 'No supported runtime trace was observed'));
  const permissions = mergePermissions(permissionSources);
  const facts = {
    tools: mergeToolFacts([...toolSources, ...permissions.tools], permissions.input_trust),
    global_input_trust: permissions.input_trust, global_input_trust_ref: permissions.input_trust_ref,
    wildcards: permissions.wildcards, secret_access_unrestricted: permissions.secret_access_unrestricted,
    network_egress_unrestricted: permissions.network_egress_unrestricted, network_scope_observed: permissions.network_scope_observed,
  };
  return {
    protocol: EVIDENCE_PROTOCOL, collected_at: (options.now || new Date()).toISOString(),
    artifacts: artifacts.sort((a, b) => `${a.kind}:${a.name}`.localeCompare(`${b.kind}:${b.name}`)), coverage_gaps: coverageGaps,
    discovery: options.discovery ? {
      protocol: options.discovery.protocol,
      scanned_locations: options.discovery.scanned_locations,
      files: options.discovery.files.map(item => ({ name: path.basename(item.path), adapter: item.adapter, location: item.location })),
      instruction_files: options.discovery.instruction_files.map(item => path.basename(item)),
    } : null,
    facts,
  };
}

function publicEvidence(evidence) {
  return {
    protocol: evidence.protocol, collected_at: evidence.collected_at, artifacts: evidence.artifacts,
    discovery: evidence.discovery, coverage_gaps: evidence.coverage_gaps,
    observations: {
      tool_count: evidence.facts.tools.length,
      tools: evidence.facts.tools.map(tool => ({ name: tool.name, capabilities: tool.capabilities, semantic_risks: tool.semantic_risks.map(item => item.id), input_trust: tool.input_trust, approval: tool.approval, audit: tool.audit, provenance: tool.provenance })),
      wildcard_permission_count: evidence.facts.wildcards.length,
    },
  };
}

module.exports = {
  ARTIFACT_KINDS, CAPABILITIES, EVIDENCE_PROTOCOL, MAX_ARTIFACT_BYTES,
  collectEvidence, inferCapabilities, publicEvidence, readJsonArtifact, semanticRisks,
};

},

"lib/exposure-paths.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const EXPOSURE_PATH_PROTOCOL = 'backbond-exposure-paths/v1';

const DEFINITIONS = [
  {
    id: 'EP001',
    trigger: 'BB012',
    title: 'Untrusted retrieval shares context with privileged tools',
    chain: ['untrusted network retrieval', 'shared agent context', 'privileged tool availability'],
    supporting: ['BB001', 'BB007', 'BB012'],
    action: 'Split retrieval and privileged execution into isolated contexts, or enforce a runtime trust boundary between them.',
  },
  {
    id: 'EP002',
    trigger: 'BB002',
    title: 'Secret access is combined with unrestricted egress',
    chain: ['secret access', 'shared agent authority', 'unrestricted network egress'],
    supporting: ['BB002', 'BB006'],
    action: 'Separate secret-reading and network-sending roles, and restrict both secrets and destinations to explicit allowlists.',
  },
  {
    id: 'EP003',
    trigger: 'BB001',
    title: 'Untrusted input can reach code execution',
    chain: ['untrusted input', 'model-selected tool call', 'code or shell execution'],
    supporting: ['BB001', 'BB007'],
    action: 'Disable the executor or place it behind narrow argument validation and a runtime-enforced sandbox.',
  },
];

function buildExposurePaths(findings) {
  const byId = new Map(findings.map(item => [item.id, item]));
  const paths = DEFINITIONS.filter(definition => byId.has(definition.trigger)).map(definition => {
    const triggerFinding = byId.get(definition.trigger);
    const triggerTools = new Set(triggerFinding.affected_tools);
    const linked = definition.supporting.filter(id => {
      const finding = byId.get(id);
      return finding && (id === definition.trigger || finding.affected_tools.some(tool => triggerTools.has(tool)));
    });
    const linkedFindings = linked.map(id => byId.get(id));
    return {
      id: definition.id,
      kind: 'potential_exposure_path',
      title: definition.title,
      chain: [...definition.chain],
      finding_ids: linked,
      affected_tools: [...new Set(linkedFindings.flatMap(item => item.affected_tools))].sort(),
      evidence_quality: linkedFindings.some(item => item.evidence_quality === 'derived') ? 'derived' : 'explicit',
      action: definition.action,
      caveat: 'Potential composition inferred from static co-residence; not an observed runtime data flow.',
    };
  });
  return { protocol: EXPOSURE_PATH_PROTOCOL, paths };
}

module.exports = { EXPOSURE_PATH_PROTOCOL, buildExposurePaths };

},

"lib/mcp-server.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { discover } = require('./discovery.js');
const { collectEvidence, MAX_ARTIFACT_BYTES } = require('./evidence.js');
const { renderHuman } = require('./output.js');
const { liveToolsNextAction, renderNextAction } = require('./next-action.js');
const { suggestPolicy } = require('./policy.js');
const { createPublicScanRecord, renderCompactRecord } = require('./record.js');
const { createScanReceipt } = require('./receipt.js');
const { scanEvidence, SCANNER_VERSION } = require('./scanner.js');
const { safeInline } = require('./text.js');
const { createVetResult, renderVetHuman } = require('./vet-tools.js');

const TOOL = {
  name: 'scan_my_runtime',
  title: 'Scan my runtime tools',
  description: 'Statically scans a supplied live tool manifest, or bounded local agent config discovery when omitted. No network requests or tool execution.',
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  inputSchema: {
    type: 'object',
    properties: {
      tools: {
        type: 'array',
        description: 'Optional live MCP or supported function-tool list. Omit to scan recognized local agent configs.',
        items: { type: 'object' },
      },
      suggest_policy: { type: 'boolean', description: 'Include non-enforcing disable/wrap suggestions.' },
      emit_record: { type: 'boolean', description: 'Return only a redacted self-run scan record and compact text. No discovery paths, artifact names, or tool names are returned.' },
    },
    additionalProperties: false,
  },
};

const VET_TOOL = {
  name: 'vet_tools_before_attach',
  title: 'Vet tools before attaching them',
  description: 'Runs a scoped static pre-attachment gate over a proposed live tool list. Returns block, review, or no_blocking_finding; never a runtime safety determination.',
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  inputSchema: {
    type: 'object',
    properties: {
      tools: {
        type: 'array',
        description: 'Proposed live MCP or supported function tools to vet before attachment.',
        items: { type: 'object' },
      },
    },
    required: ['tools'],
    additionalProperties: false,
  },
};

function validateRuntimeArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be an object');
  const allowed = new Set(['tools', 'suggest_policy', 'emit_record']);
  const unknown = Object.keys(args).find(key => !allowed.has(key));
  if (unknown) throw new Error(`unknown argument: ${unknown}`);
  if (args.tools !== undefined && !Array.isArray(args.tools)) throw new Error('tools must be an array');
  if (args.suggest_policy !== undefined && typeof args.suggest_policy !== 'boolean') throw new Error('suggest_policy must be a boolean');
  if (args.emit_record !== undefined && typeof args.emit_record !== 'boolean') throw new Error('emit_record must be a boolean');
}

function validateVetArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be an object');
  const unknown = Object.keys(args).find(key => key !== 'tools');
  if (unknown) throw new Error(`unknown argument: ${unknown}`);
  if (!Array.isArray(args.tools)) throw new Error('tools must be an array');
}

function runtimeScan(args = {}, options = {}) {
  validateRuntimeArgs(args);
  const now = options.now || new Date();
  let plan = null;
  const documents = [];
  const artifactPaths = [];
  if (Array.isArray(args.tools)) {
    documents.push({ kind: 'tool_schema', name: '<mcp-runtime>', document: { tools: args.tools } });
  } else {
    plan = discover({ cwd: options.cwd || process.cwd() });
    artifactPaths.push(...plan.files);
  }
  const evidence = collectEvidence({ now, documents, artifactPaths, discovery: plan });
  const scan = scanEvidence(evidence, { now });
  const receipt = createScanReceipt(scan);
  const policy = args.suggest_policy ? suggestPolicy(scan) : null;
  const record = args.emit_record === true ? createPublicScanRecord(scan, receipt, {
    mode: Array.isArray(args.tools) ? 'live-manifest' : 'discovery',
  }) : null;
  const nextAction = Array.isArray(args.tools) ? null : liveToolsNextAction(SCANNER_VERSION);
  return { scan, receipt, policy, record, next_action: nextAction };
}

function runtimeVet(args, options = {}) {
  validateVetArgs(args);
  const now = options.now || new Date();
  const evidence = collectEvidence({
    now,
    documents: [{ kind: 'tool_schema', name: '<mcp-pre-attach>', document: { tools: args.tools } }],
  });
  return createVetResult(scanEvidence(evidence, { now }), evidence);
}

function response(id, result) { return { jsonrpc: '2.0', id, result }; }
function errorResponse(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

function oversizedRequestResponse() {
  return errorResponse(null, -32600, `Request exceeds ${MAX_ARTIFACT_BYTES} bytes`);
}

function handleMessage(message) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return errorResponse(message && message.id, -32600, 'Invalid Request');
  if (message.id === undefined) return null;
  if (message.method === 'initialize') {
    return response(message.id, {
      protocolVersion: '2025-06-18',
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: '@backbond/agent-scan', version: SCANNER_VERSION },
      instructions: 'Static-only local scan. Inferred facts are marked derived. No traces or config bodies are uploaded.',
    });
  }
  if (message.method === 'ping') return response(message.id, {});
  if (message.method === 'tools/list') return response(message.id, { tools: [TOOL, VET_TOOL] });
  if (message.method === 'tools/call') {
    if (!message.params || ![TOOL.name, VET_TOOL.name].includes(message.params.name)) return errorResponse(message.id, -32602, 'Unknown tool');
    const args = message.params.arguments === undefined ? {} : message.params.arguments;
    try {
      if (message.params.name === VET_TOOL.name) {
        const result = runtimeVet(args);
        return response(message.id, {
          content: [{ type: 'text', text: renderVetHuman(result).trimEnd() }],
          structuredContent: result,
          isError: false,
        });
      }
      const result = runtimeScan(args);
      if (result.record) {
        const text = [renderCompactRecord(result.record), result.next_action ? renderNextAction(result.next_action) : null]
          .filter(Boolean).join('\n\n');
        return response(message.id, {
          content: [{ type: 'text', text }],
          structuredContent: { record: result.record, ...(result.next_action ? { next_action: result.next_action } : {}) },
          isError: false,
        });
      }
      return response(message.id, {
        content: [{ type: 'text', text: [
          renderHuman(result.scan, { policy: result.policy }).trimEnd(),
          result.next_action ? renderNextAction(result.next_action) : null,
        ].filter(Boolean).join('\n\n') }],
        structuredContent: result,
        isError: false,
      });
    } catch (error) {
      if (message.params.name === TOOL.name && args && typeof args === 'object' && !Array.isArray(args) && args.emit_record === true) {
        return response(message.id, { content: [{ type: 'text', text: 'agent-scan: scan failed; no public record was created' }], isError: true });
      }
      return response(message.id, { content: [{ type: 'text', text: safeInline(`agent-scan: ${error.message}`) }], isError: true });
    }
  }
  return errorResponse(message.id, -32601, 'Method not found');
}

function startMcpServer(input = process.stdin, output = process.stdout) {
  input.setEncoding('utf8');
  let buffer = '';
  input.on('data', chunk => {
    buffer += chunk;
    let newline = buffer.indexOf('\n');
    while (newline >= 0) {
      const rawLine = buffer.slice(0, newline);
      const line = rawLine.trim();
      buffer = buffer.slice(newline + 1);
      if (line) {
        let outgoing;
        if (Buffer.byteLength(rawLine, 'utf8') > MAX_ARTIFACT_BYTES) outgoing = oversizedRequestResponse();
        else {
          try { outgoing = handleMessage(JSON.parse(line)); }
          catch { outgoing = errorResponse(null, -32700, 'Parse error'); }
        }
        if (outgoing) output.write(`${JSON.stringify(outgoing)}\n`);
      }
      newline = buffer.indexOf('\n');
    }
    if (Buffer.byteLength(buffer, 'utf8') > MAX_ARTIFACT_BYTES) {
      output.write(`${JSON.stringify(oversizedRequestResponse())}\n`);
      buffer = '';
    }
  });
}

module.exports = { TOOL, VET_TOOL, handleMessage, runtimeScan, runtimeVet, startMcpServer };

},

"lib/next-action.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { safeInline } = require('./text.js');

function liveToolsNextAction(version) {
  const packageSpec = `@backbond/agent-scan@${version}`;
  return {
    code: 'provide_live_tools',
    reason: 'A live runtime tool inventory was not supplied.',
    save_as: 'tools-list.json',
    stdin_shape: {
      jsonrpc: '2.0',
      id: 1,
      result: {
        tools: [{
          name: 'tool_name',
          description: 'What the tool does',
          inputSchema: { type: 'object', properties: {} },
        }],
      },
    },
    commands: {
      posix_or_cmd: `npx -y ${packageSpec} scan --stdin --require-coverage < tools-list.json`,
      powershell: `Get-Content -Raw .\\tools-list.json | npx -y ${packageSpec} scan --stdin --require-coverage`,
      vet_posix_or_cmd: `npx -y ${packageSpec} vet-tools --stdin < tools-list.json`,
      vet_powershell: `Get-Content -Raw .\\tools-list.json | npx -y ${packageSpec} vet-tools --stdin`,
    },
  };
}

function renderNextAction(action) {
  return [
    'Next: save your current MCP tools/list response as tools-list.json.',
    `Shape: ${JSON.stringify(action.stdin_shape)}`,
    `Run: ${action.commands.posix_or_cmd}`,
    `PowerShell: ${action.commands.powershell}`,
    `Vet before attach: ${action.commands.vet_posix_or_cmd}`,
    `Vet PowerShell: ${action.commands.vet_powershell}`,
  ].map(line => safeInline(line)).join('\n');
}

module.exports = { liveToolsNextAction, renderNextAction };

},

"lib/output.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { safeInline } = require('./text.js');
const { isPromptLintFinding } = require('./rules.js');

function countSummary(summary) {
  const parts = Object.entries(summary.by_severity)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`);
  return `${summary.total} finding${summary.total === 1 ? '' : 's'}${parts.length ? ` (${parts.join(', ')})` : ''}`;
}

function findingSubject(item) {
  if (item.affected_tools.length) return item.affected_tools.join(' + ');
  const wildcard = item.detail.match(/^Wildcard scopes: (.+)\.$/);
  return wildcard ? wildcard[1] : item.title;
}

function renderHuman(scan, options = {}) {
  const lines = [scan.status === 'inconclusive' ? `INCONCLUSIVE — ${countSummary(scan.summary)}` : countSummary(scan.summary)];
  if (scan.summary.total) {
    lines.push(`Capability exposure: ${scan.finding_classes.capability_exposure.count}; prompt-injection indicators: ${scan.finding_classes.prompt_injection_indicator.count}`);
  }
  if (scan.discovery) {
    const labels = scan.discovery.files.map(item => `${item.adapter}:${item.name}`);
    const shown = labels.slice(0, 4).join(', ') || 'no recognized configs';
    lines.push(`Scanned: ${shown}${labels.length > 4 ? `, +${labels.length - 4} more` : ''}; ${scan.discovery.instruction_files.length} instruction file${scan.discovery.instruction_files.length === 1 ? '' : 's'} noted`);
  }
  for (const item of scan.findings) {
    const labels = [
      item.evidence_quality === 'derived' ? 'derived' : null,
      isPromptLintFinding(item) ? 'prompt lint' : null,
    ].filter(Boolean);
    lines.push(`${item.id} ${findingSubject(item)}${labels.length ? ` [${labels.join(', ')}]` : ''}`);
    lines.push(`  Stop: ${item.stop}`);
  }
  for (const path of (scan.exposure_paths && scan.exposure_paths.paths) || []) {
    lines.push(`${path.id} potential: ${path.chain.join(' → ')} (${path.finding_ids.join(', ')})`);
    lines.push(`  Agent action: ${path.action}`);
  }
  if (scan.coverage.gaps.length) {
    const messages = [...new Set(scan.coverage.gaps.map(item => item.message))];
    const shown = messages.slice(0, 2).join('; ');
    lines.push(`Coverage: ${shown}${messages.length > 2 ? `; +${messages.length - 2} more gap${messages.length - 2 === 1 ? '' : 's'}` : ''}`);
  } else {
    lines.push('Coverage: complete');
  }
  if (scan.findings.some(isPromptLintFinding)) {
    lines.push('Prompt lint is reported separately; gate it with --fail-on-prompt.');
  }
  if (options.policy) {
    const disabled = options.policy.actions.filter(item => item.action === 'disable').map(item => item.tool);
    const wrapped = options.policy.actions.filter(item => item.action === 'wrap').map(item => item.tool);
    if (disabled.length) lines.push(`Suggested deny: ${[...new Set(disabled)].join(', ')}`);
    if (wrapped.length) lines.push(`Suggested wrap: ${[...new Set(wrapped)].join(', ')}`);
    lines.push('Policy suggestions are not enforced or automatically applied.');
  }
  if (options.receiptPath) lines.push(`Receipt: ${options.receiptPath}`);
  return `${lines.map(line => safeInline(line)).join('\n')}\n`;
}

module.exports = { renderHuman };

},

"lib/policy.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const HIGH_RISK = new Set(['critical', 'high']);

function actionForFinding(finding, tool) {
  if (['BB001', 'BB002', 'BB003', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB013'].includes(finding.id)) {
    return {
      action: HIGH_RISK.has(finding.severity) ? 'disable' : 'wrap',
      tool,
      finding_id: finding.id,
      until: finding.stop,
    };
  }
  return { action: 'wrap', tool, finding_id: finding.id, until: finding.stop };
}

function suggestedPatches(scan) {
  const patches = [];
  for (const finding of scan.findings) {
    if (finding.id === 'BB006') {
      for (const evidence of finding.evidence) {
        patches.push({
          artifact_name: evidence.artifact_name,
          operations: [{ op: 'replace', path: evidence.pointer, value: ['<explicit-allowlist-entry>'] }],
          template: true,
          safe_to_apply_automatically: false,
          finding_id: finding.id,
        });
      }
    }
    if (finding.id === 'BB003') {
      for (const evidence of finding.evidence.filter(item => item.pointer.endsWith('/approval'))) {
        patches.push({
          artifact_name: evidence.artifact_name,
          operations: [{ op: 'replace', path: evidence.pointer, value: 'enforced' }],
          template: true,
          safe_to_apply_automatically: false,
          finding_id: finding.id,
        });
      }
    }
    if (finding.id === 'BB007') {
      for (const evidence of finding.evidence) {
        patches.push({
          artifact_name: evidence.artifact_name,
          operations: [{ op: 'add', path: `${evidence.pointer}/enum`, value: ['<approved-operation>'] }],
          patch_kind: 'constrain_free_form_operation',
          template: true,
          safe_to_apply_automatically: false,
          review_required: true,
          review_reason: 'The scanner cannot infer the valid operation set for this tool.',
          finding_id: finding.id,
        });
      }
    }
    if (finding.id === 'BB013') {
      for (const evidence of finding.evidence) {
        patches.push({
          artifact_name: evidence.artifact_name,
          operations: [{
            op: 'replace',
            path: evidence.pointer,
            value: '<factual capability description without routing, priority, or mandatory-invocation instructions>',
          }],
          patch_kind: 'rewrite_selection_manipulation',
          template: true,
          safe_to_apply_automatically: false,
          review_required: true,
          review_reason: 'The tool owner must preserve intended behavior while removing model-routing instructions.',
          finding_id: finding.id,
        });
      }
    }
  }
  return patches;
}

function suggestPolicy(scan) {
  const actions = [];
  for (const finding of scan.findings) {
    for (const tool of finding.affected_tools) actions.push(actionForFinding(finding, tool));
  }
  const seen = new Set();
  return {
    protocol: 'backbond-policy-suggestion/v1',
    mode: 'suggestion_only',
    enforced: false,
    actions: actions.filter(item => {
      const key = `${item.action}:${item.tool}:${item.finding_id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
    patches: suggestedPatches(scan),
    warning: 'Review against the runtime configuration. Template placeholders and inferred findings must not be auto-applied.',
  };
}

module.exports = { suggestPolicy };

},

"lib/receipt.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const fs = require('node:fs');
const { createPublicKey, sign, verify } = require('node:crypto');
const { canonicalize, sha256 } = require('./canonical.js');

const RECEIPT_PROTOCOL = 'backbond-scan-receipt/v1';

function addIntegrity(payload, signingKeyPath = null) {
  let privateKey = null;
  let publicDer = null;
  if (signingKeyPath) {
    privateKey = fs.readFileSync(signingKeyPath);
    const publicKey = createPublicKey(privateKey);
    publicDer = publicKey.export({ type: 'spki', format: 'der' });
  }
  const securedPayload = {
    ...payload,
    signing: publicDer ? { algorithm: 'Ed25519', key_fingerprint_sha256: sha256(publicDer) } : null,
  };
  const canonical = canonicalize(securedPayload);
  const integrity = { canonicalization: 'lexicographic-json/v1', sha256: sha256(canonical), signature: null };
  if (privateKey) {
    integrity.signature = {
      algorithm: 'Ed25519',
      public_key_spki_base64: publicDer.toString('base64'),
      value_base64: sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64'),
    };
  }
  return { ...securedPayload, integrity };
}

function receiptFinding(finding) {
  return {
    id: finding.id,
    severity: finding.severity,
    evidence_refs: finding.evidence.map(item => ({
      artifact_kind: item.artifact_kind,
      artifact_name: item.artifact_name,
      artifact_sha256: null,
      pointer: item.pointer,
    })),
  };
}

function attachArtifactDigests(findings, inputs) {
  const byIdentity = new Map(inputs.map(input => [`${input.kind}:${input.name}`, input.sha256]));
  return findings.map(finding => ({
    ...finding,
    evidence_refs: finding.evidence_refs.map(item => ({ ...item, artifact_sha256: byIdentity.get(`${item.artifact_kind}:${item.artifact_name}`) || null })),
  }));
}

function createScanReceipt(scan, options = {}) {
  const inputs = [...scan.inputs, ...(options.claimInput ? [options.claimInput] : [])]
    .map(input => ({ kind: input.kind, name: input.name, bytes: input.bytes, sha256: input.sha256, dialect: input.dialect || null }))
    .sort((a, b) => `${a.kind}:${a.name}`.localeCompare(`${b.kind}:${b.name}`));
  const findings = attachArtifactDigests(scan.findings.map(receiptFinding), inputs);
  return addIntegrity({
    protocol: RECEIPT_PROTOCOL,
    issued_at: scan.scanned_at,
    scanner: scan.scanner,
    ruleset: scan.ruleset,
    inputs,
    result: {
      status: scan.status,
      findings,
      coverage_gaps: scan.coverage.gaps.map(item => ({ code: item.code, rule_id: item.rule_id || null, artifact_kind: item.artifact_kind, status: item.status })),
      claim_contradictions: scan.claim_contradictions.map(item => ({ code: item.code, claim: item.claim, finding_ids: item.finding_ids })),
    },
  }, options.signingKeyPath || null);
}

function verifyScanReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || receipt.protocol !== RECEIPT_PROTOCOL || !receipt.integrity) return false;
  const { integrity, ...payload } = receipt;
  if (!integrity || integrity.canonicalization !== 'lexicographic-json/v1' || typeof integrity.sha256 !== 'string') return false;
  const canonical = canonicalize(payload);
  if (sha256(canonical) !== integrity.sha256) return false;
  if (!payload.signing) return integrity.signature === null;
  if (!integrity.signature || payload.signing.algorithm !== 'Ed25519' || integrity.signature.algorithm !== 'Ed25519') return false;
  try {
    const publicDer = Buffer.from(integrity.signature.public_key_spki_base64, 'base64');
    if (sha256(publicDer) !== payload.signing.key_fingerprint_sha256) return false;
    return verify(
      null,
      Buffer.from(canonical, 'utf8'),
      { key: publicDer, type: 'spki', format: 'der' },
      Buffer.from(integrity.signature.value_base64, 'base64'),
    );
  } catch {
    return false;
  }
}

module.exports = { RECEIPT_PROTOCOL, createScanReceipt, verifyScanReceipt };

},

"lib/record.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { canonicalize, sha256 } = require('./canonical.js');
const { safeInline } = require('./text.js');

const RECORD_PROTOCOL = 'backbond-scan-record/v1';
const COMMIT_BOUND_RECORD_PROTOCOL = 'backbond-scan-record/v2';

function interpretationFor(scan) {
  if (scan.findings.length) return 'findings';
  return scan.coverage.status === 'complete' ? 'complete_no_findings' : 'inconclusive';
}

function inputScope(inputs, options) {
  const grouped = new Map();
  for (const input of inputs) {
    const kind = input.kind || 'unknown';
    const dialect = input.dialect || null;
    const key = `${kind}:${dialect || ''}`;
    const current = grouped.get(key) || { kind, dialect, count: 0 };
    current.count += 1;
    grouped.set(key, current);
  }
  const scope = {
    mode: options.mode,
    input_count: inputs.length,
    input_kinds: [...grouped.values()].sort((a, b) => `${a.kind}:${a.dialect || ''}`.localeCompare(`${b.kind}:${b.dialect || ''}`)),
  };
  if (options.includeFingerprints) {
    scope.input_fingerprints = inputs.map(input => ({
      kind: input.kind || 'unknown',
      dialect: input.dialect || null,
      bytes: input.bytes,
      sha256: input.sha256,
    })).sort((a, b) => `${a.kind}:${a.dialect || ''}:${a.sha256}`.localeCompare(`${b.kind}:${b.dialect || ''}:${b.sha256}`));
  }
  return scope;
}

function publicFinding(finding, options) {
  const item = {
    id: finding.id,
    severity: finding.severity,
    evidence_quality: finding.evidence_quality,
  };
  if (options.includeToolNames) item.tools = [...new Set(finding.affected_tools)].sort();
  return item;
}

function createPublicScanRecord(scan, receipt, options = {}) {
  if (!scan || !receipt || !receipt.integrity || typeof receipt.integrity.sha256 !== 'string') {
    throw new Error('public scan record requires a scan and its checksummed local receipt');
  }
  const resolved = {
    mode: options.mode || (scan.discovery ? 'discovery' : 'explicit-artifacts'),
    includeToolNames: options.includeToolNames === true,
    includeFingerprints: options.includeFingerprints === true,
    commit: options.commit || null,
  };
  if (resolved.commit && !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(resolved.commit)) {
    throw new Error('public scan record commit must be a lowercase 40- or 64-character Git commit');
  }
  const payload = {
    protocol: resolved.commit ? COMMIT_BOUND_RECORD_PROTOCOL : RECORD_PROTOCOL,
    kind: 'scan_record',
    assurance: {
      level: 'self-run_unverified',
      statement: resolved.commit
        ? 'Local scan record only. Git commit was supplied by the caller and was not verified by the scanner. Not a safety certificate or BackBond attestation.'
        : 'Local scan record only. Not a safety certificate or BackBond attestation.',
    },
    scanned_at: scan.scanned_at,
    scanner: { name: scan.scanner.name, version: scan.scanner.version, mode: scan.scanner.mode },
    ruleset: { version: scan.ruleset.version, sha256: scan.ruleset.sha256 },
    scope: inputScope(receipt.inputs || [], resolved),
    result: {
      interpretation: interpretationFor(scan),
      summary: { ...scan.summary.by_severity },
      findings: scan.findings.map(item => publicFinding(item, resolved)),
      coverage: {
        status: scan.coverage.status,
        gaps: [...new Set(scan.coverage.gaps.map(item => item.code))].sort(),
      },
    },
    rerun: {
      package: scan.scanner.name,
      version: scan.scanner.version,
      command: `npx -y ${scan.scanner.name}@${scan.scanner.version} scan`,
      note: 'Run this official pinned command on your own artifacts. It does not reproduce another environment.',
    },
    source_receipt: { integrity_sha256: receipt.integrity.sha256 },
  };
  if (resolved.commit) payload.source = { git_commit: resolved.commit };
  return {
    ...payload,
    integrity: {
      canonicalization: 'lexicographic-json/v1',
      sha256: sha256(canonicalize(payload)),
    },
  };
}

function verifyPublicScanRecord(record) {
  if (!record || ![RECORD_PROTOCOL, COMMIT_BOUND_RECORD_PROTOCOL].includes(record.protocol) || !record.integrity) return false;
  if (record.protocol === COMMIT_BOUND_RECORD_PROTOCOL
    && (!record.source || typeof record.source.git_commit !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(record.source.git_commit))) return false;
  const { integrity, ...payload } = record;
  return integrity.canonicalization === 'lexicographic-json/v1'
    && typeof integrity.sha256 === 'string'
    && sha256(canonicalize(payload)) === integrity.sha256;
}

function countSummary(summary) {
  const parts = Object.entries(summary)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`);
  return parts.length ? parts.join(', ') : 'none observed';
}

function renderCompactRecord(record) {
  const findingItems = record.result.findings.map(item => {
    const tools = item.tools && item.tools.length ? ` ${item.tools.join('+')}` : '';
    return `${item.id}${tools}${item.evidence_quality === 'derived' ? ' [derived]' : ''}`;
  });
  const coverage = record.result.coverage.gaps.length
    ? `${record.result.coverage.status}; ${record.result.coverage.gaps.join(' ')}`
    : record.result.coverage.status;
  return [
    'BackBond local scan record',
    'Assurance: self-run, unverified; not a safety certificate',
    `${record.scanner.name}@${record.scanner.version}  ruleset ${record.ruleset.version}`,
    ...(record.source ? [`Commit (caller-supplied, unverified): ${record.source.git_commit}`] : []),
    `Interpretation: ${record.result.interpretation.toUpperCase()}`,
    `Findings: ${countSummary(record.result.summary)}${findingItems.length ? `; ${findingItems.join(' ')}` : ''}`,
    `Coverage: ${coverage}`,
    `Rerun: ${record.rerun.command}`,
    `Record: ${record.integrity.sha256}`,
  ].map(line => safeInline(line)).join('\n');
}

module.exports = {
  COMMIT_BOUND_RECORD_PROTOCOL,
  RECORD_PROTOCOL,
  createPublicScanRecord,
  interpretationFor,
  renderCompactRecord,
  verifyPublicScanRecord,
};

},

"lib/rules.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { sha256 } = require('./canonical.js');
const RULESET_SOURCES = require('./ruleset-sources.json');

const RULESET_VERSION = 'backbond-local-rules/2.0.1';
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
const PROMPT_LINT_IDS = new Set(['BB009', 'BB010', 'BB011', 'BB013']);

function uniqueRefs(refs) {
  const seen = new Set();
  return refs.flat(Infinity).filter(Boolean).filter(item => {
    const key = `${item.artifact_kind}:${item.artifact_name}:${item.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => `${a.artifact_kind}:${a.pointer}`.localeCompare(`${b.artifact_kind}:${b.pointer}`));
}

function finding(rule, tools, refs, detail) {
  const derived = ['BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB013'].includes(rule.id) || tools.some(tool => tool.provenance && (
    tool.provenance.input_trust === 'derived'
    || Object.values(tool.provenance.capabilities || {}).includes('derived')
    || tool.provenance.semantic_risks === 'derived'
  ));
  return {
    id: rule.id,
    severity: rule.severity,
    finding_class: rule.finding_class,
    precision_note: rule.precision_note,
    title: rule.title,
    description: rule.description,
    detail,
    affected_tools: [...new Set(tools.map(tool => tool.name))].sort(),
    evidence: uniqueRefs(refs),
    evidence_quality: derived ? 'derived' : 'explicit',
    stop: rule.stop,
    remediation: rule.remediation,
  };
}

function promptTemplateSummary(tools, riskId) {
  const groups = new Map();
  for (const tool of tools) {
    for (const risk of tool.semantic_risks.filter(item => item.id === riskId && typeof item.metadata_sha256 === 'string')) {
      if (!groups.has(risk.metadata_sha256)) groups.set(risk.metadata_sha256, new Set());
      groups.get(risk.metadata_sha256).add(tool.name);
    }
  }
  const templates = [...groups.entries()].map(([sha256, names]) => ({ sha256, multiplicity: names.size }))
    .sort((a, b) => b.multiplicity - a.multiplicity || a.sha256.localeCompare(b.sha256));
  return {
    distinct_templates: templates.length,
    largest_multiplicity: templates.reduce((largest, item) => Math.max(largest, item.multiplicity), 0),
    templates,
  };
}

function promptFinding(rule, tools, refs, detail, riskId) {
  const item = finding(rule, tools, refs, detail);
  item.metadata_template_summary = promptTemplateSummary(tools, riskId);
  const subtypes = [...new Set(tools.flatMap(tool => tool.semantic_risks
    .filter(risk => risk.id === riskId && typeof risk.subtype === 'string')
    .map(risk => risk.subtype)))].sort();
  if (subtypes.length) item.risk_subtypes = subtypes;
  return item;
}

function coverage(rule, code, message, kind = 'combined') {
  return { code, rule_id: rule.id, artifact_kind: kind, status: 'insufficient_evidence', message, artifact_name: null };
}

const RULES = [
  {
    id: 'BB001', severity: 'high', title: 'Untrusted input can reach code execution',
    finding_class: 'capability_exposure',
    precision_note: 'Strong when capability and input trust are explicit; derived name, description, or schema inference requires implementation review.',
    description: 'A code or shell execution capability accepts content classified as untrusted.',
    stop: 'Disable the named executor for this session, or wrap it with a narrow argument allowlist and runtime sandbox.',
    remediation: 'Restrict executable inputs to trusted sources, validate against a narrow allowlist, and isolate execution in a runtime-enforced sandbox.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.includes('code_execution'));
      const exposed = capable.filter(tool => tool.input_trust === 'untrusted');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.input_trust]), `Untrusted input reaches ${exposed.length} code-execution tool(s).`) };
      if (capable.some(tool => tool.input_trust === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB001-INPUT-TRUST', 'Code execution is present, but its accepted input trust is not observable.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB002', severity: 'critical', title: 'Secret access is combined with unrestricted egress',
    finding_class: 'capability_exposure',
    precision_note: 'Strong when credential access and network scope are explicit; derived capability inference requires implementation review.',
    description: 'The runtime can access secrets and has an unrestricted outbound network scope.',
    stop: 'Do not attach secret-reading and unrestricted network tools to the same agent; split the roles or allowlist destinations.',
    remediation: 'Scope credential access to named secrets and restrict outbound destinations to an explicit allowlist; separate secret-reading and network-sending roles.',
    evaluate(facts, rule) {
      const secretTools = facts.tools.filter(tool => tool.capabilities.includes('secret_read'));
      const secretAccess = facts.secret_access_unrestricted || secretTools.length > 0;
      if (secretAccess && facts.network_egress_unrestricted) {
        const refs = [
          secretTools.flatMap(tool => tool.refs.capabilities),
          facts.wildcards.filter(item => item.domain === 'credentials' || item.domain === 'network').map(item => item.ref),
        ];
        return { finding: finding(rule, secretTools, refs, 'Secret-reading capability and unrestricted network egress are both available.') };
      }
      if (secretAccess && !facts.network_scope_observed) return { gaps: [coverage(rule, 'BB-COV-BB002-EGRESS-SCOPE', 'Secret access is present, but a supported network-egress scope was not observed.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB003', severity: 'high', title: 'Consequential action lacks enforced approval',
    finding_class: 'capability_exposure',
    precision_note: 'Strong only when approval enforcement is explicitly observable; missing approval evidence is reported as a coverage gap.',
    description: 'A destructive or financial capability can run without a runtime-enforced approval gate.',
    stop: 'Disable the consequential tool until the runtime enforces approval outside the model.',
    remediation: 'Place the named consequential tools behind a runtime-enforced approval gate and test that bypass attempts are blocked.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.some(capability => ['destructive_action', 'financial_action'].includes(capability)));
      const exposed = capable.filter(tool => tool.approval === 'not_enforced');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.approval]), `${exposed.length} consequential tool(s) lack enforced approval.`) };
      if (capable.some(tool => tool.approval === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB003-APPROVAL', 'Consequential capability is present, but approval enforcement is not observable.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB004', severity: 'high', title: 'Persistent write accepts untrusted content',
    finding_class: 'capability_exposure',
    precision_note: 'A standalone persistent write is a medium-severity review finding. It becomes high only when an untrusted network fetch or unallowlisted destination is observed in the same supplied inventory.',
    description: 'A persistent write capability accepts untrusted content; same-inventory network intake raises the pre-attachment severity.',
    stop: 'Disable persistent writes for untrusted content or quarantine them for operator review.',
    remediation: 'Validate and provenance-tag memory writes, segregate untrusted content, and require review before untrusted data influences later sessions.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.includes('persistent_write'));
      const exposed = capable.filter(tool => tool.input_trust === 'untrusted');
      if (exposed.length) {
        const observations = facts.tools.flatMap(tool => (tool.inventory_observations || []).map(observation => ({ tool, observation })));
        const networkInventories = new Set(observations
          .filter(({ observation }) => observation.input_trust === 'untrusted'
            && observation.semantic_risks.some(item => ['untrusted_network_fetch', 'unvalidated_destination'].includes(item.id)))
          .map(({ observation }) => observation.inventory));
        const compound = exposed.filter(tool => (tool.inventory_observations || []).some(observation => (
          observation.input_trust === 'untrusted'
          && observation.capabilities.includes('persistent_write')
          && networkInventories.has(observation.inventory)
        )));
        const affected = compound.length ? compound : exposed;
        const refs = affected.flatMap(tool => [tool.refs.capabilities, tool.refs.input_trust]);
        if (compound.length) {
          refs.push(observations
            .filter(({ observation }) => networkInventories.has(observation.inventory))
            .flatMap(({ observation }) => observation.semantic_risks
              .filter(item => ['untrusted_network_fetch', 'unvalidated_destination'].includes(item.id))
              .map(item => item.ref)));
        }
        const item = finding(rule, affected, refs, compound.length
          ? `Untrusted network intake and ${compound.length} persistent-write tool(s) share a supplied inventory.`
          : `Untrusted content reaches ${exposed.length} persistent-write tool(s); no same-inventory network intake was observed.`);
        item.severity = compound.length ? 'high' : 'medium';
        item.variant = compound.length ? 'network_intake_to_persistent_write' : 'standalone_persistent_write';
        return { finding: item };
      }
      if (capable.some(tool => tool.input_trust === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB004-INPUT-TRUST', 'Persistent writes are present, but input trust is not observable.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB005', severity: 'medium', title: 'Privileged action lacks observable audit evidence',
    finding_class: 'capability_exposure',
    precision_note: 'Strong only when missing audit observability is explicit; absent evidence is reported as a coverage gap.',
    description: 'A privileged capability is configured without observable audit recording.',
    stop: 'Do not run the privileged action until invocation, approval, and outcome are recorded outside the agent.',
    remediation: 'Record privileged tool invocation, approval identity, outcome, and stable correlation IDs in an operator-controlled audit sink.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.includes('privileged_action'));
      const exposed = capable.filter(tool => tool.audit === 'not_observable');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.audit]), `${exposed.length} privileged tool(s) lack observable audit evidence.`) };
      if (capable.some(tool => tool.audit === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB005-AUDIT', 'Privileged capability is present, but audit observability is not described.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB006', severity: 'high', title: 'Runtime permission scope contains wildcards',
    finding_class: 'capability_exposure',
    precision_note: 'High precision for explicit wildcard scopes; derived config adapters require confirmation against runtime interpretation.',
    description: 'Filesystem, subprocess, credential, or network permissions use an unrestricted wildcard scope.',
    stop: 'Replace each wildcard with the smallest explicit path, executable, credential, or destination allowlist.',
    remediation: 'Replace wildcard permissions with the smallest explicit path, executable, credential, and destination allowlists required by the runtime.',
    evaluate(facts, rule) {
      if (!facts.wildcards.length) return {};
      const scopes = [...new Set(facts.wildcards.map(item => `${item.domain}.${item.field}`))].sort();
      const item = finding(rule, [], facts.wildcards.map(entry => entry.ref), `Wildcard scopes: ${scopes.join(', ')}.`);
      item.evidence_quality = facts.wildcards.some(entry => entry.provenance === 'derived') ? 'derived' : 'explicit';
      return { finding: item };
    },
  },
  {
    id: 'BB007', severity: 'high', title: 'Tool accepts unconstrained interpreter input',
    finding_class: 'capability_exposure',
    precision_note: 'High only for recognized interpreter fields in executable context. Generic query, filter, GIS, and calculation expressions are routed to coverage review.',
    description: 'A tool schema accepts raw shell, code, evaluator, or database-interpreter input without an observable constraint.',
    stop: 'Disable the tool or replace the free-form field with an enum or validated, parameterized operation.',
    remediation: 'Use parameterized queries and named operations; reject arbitrary commands, scripts, expressions, and SQL before tool dispatch.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.input_trust === 'untrusted' && tool.semantic_risks.some(item => item.id === 'arbitrary_interpreter_input'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'arbitrary_interpreter_input').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool(s) accept unconstrained interpreter or query text.`) };
    },
  },
  {
    id: 'BB008', severity: 'high', title: 'Network-capable tool accepts an unallowlisted destination',
    finding_class: 'capability_exposure',
    precision_note: 'High only when both an active network context and a URL-like unconstrained field are observable. Ambiguous endpoint, href, path, host, and destination fields route to coverage review.',
    description: 'A network-capable tool accepts a URL, URI, or webhook destination without an observable hostname allowlist.',
    stop: 'Disable arbitrary destinations or wrap the tool with an explicit scheme-and-host allowlist.',
    remediation: 'Resolve destinations from operator-owned identifiers or enforce an explicit scheme and hostname allowlist before dispatch.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.input_trust === 'untrusted'
        && tool.capabilities.includes('network_egress')
        && tool.semantic_risks.some(item => item.id === 'unvalidated_destination'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'unvalidated_destination').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool(s) accept an unvalidated network destination.`) };
    },
  },
  {
    id: 'BB009', severity: 'high', title: 'Tool description contains instruction-override language',
    finding_class: 'prompt_injection_indicator',
    precision_note: 'Narrow directed-language heuristic with quoted-example and security-analysis suppression; triage the metadata before treating it as malicious intent.',
    description: 'A tool description contains language that attempts to replace system, developer, safety, operator, or user instructions.',
    stop: 'Do not attach the tool until the description is removed or rewritten and the server source is reviewed.',
    remediation: 'Treat tool metadata as untrusted input; reject instruction-override phrases and keep behavioral policy outside tool descriptions.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_instruction_override'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_instruction_override').map(item => item.ref));
      return { finding: promptFinding(rule, exposed, refs, `${exposed.length} tool description(s) contain directed instruction-override language.`, 'prompt_instruction_override') };
    },
  },
  {
    id: 'BB010', severity: 'high', title: 'Tool description asks to conceal behavior',
    finding_class: 'prompt_injection_indicator',
    precision_note: 'Narrow operator-concealment heuristic; triage the metadata before treating it as malicious intent.',
    description: 'A tool description tells the agent to hide an action or instruction from the user, operator, or human reviewer.',
    stop: 'Do not attach the tool until the concealment instruction is removed and the server source is reviewed.',
    remediation: 'Reject tool metadata that suppresses operator visibility; require user-visible intent, invocation, and outcome for consequential actions.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_concealed_behavior'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_concealed_behavior').map(item => item.ref));
      return { finding: promptFinding(rule, exposed, refs, `${exposed.length} tool description(s) directly request concealed tool behavior.`, 'prompt_concealed_behavior') };
    },
  },
  {
    id: 'BB011', severity: 'high', title: 'Tool description solicits sensitive data',
    finding_class: 'prompt_injection_indicator',
    precision_note: 'Directed-solicitation heuristic; authentication mentions alone are excluded, and remaining matches require human triage.',
    description: 'A tool description directs passwords, secrets, credentials, tokens, private keys, or environment values into a result or transmission.',
    stop: 'Do not attach the tool or provide credentials until the sensitive-data instruction is removed and the destination is independently trusted.',
    remediation: 'Keep credentials out of tool descriptions and model-visible arguments; use runtime secret injection scoped to an allowlisted destination.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_sensitive_data_request'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_sensitive_data_request').map(item => item.ref));
      return { finding: promptFinding(rule, exposed, refs, `${exposed.length} tool description(s) directly solicit sensitive data.`, 'prompt_sensitive_data_request') };
    },
  },
  {
    id: 'BB012', severity: 'high', title: 'Untrusted network fetch shares an agent with privileged tools',
    finding_class: 'capability_exposure',
    precision_note: 'Static same-inventory composition signal requiring a fetch-shaped tool plus explicit, destructive-hint, OpenAPI-method, or action-shaped privilege evidence. Privilege words in help text do not qualify.',
    description: 'A tool that retrieves untrusted network content is available in the same agent as a privileged action.',
    stop: 'Separate network retrieval from privileged tools, or quarantine fetched content before any privileged tool can consume it.',
    remediation: 'Use separate agent roles or a runtime-enforced trust boundary that prevents fetched content from influencing privileged tool selection and arguments.',
    evaluate(facts, rule) {
      const observations = facts.tools.flatMap(tool => (tool.inventory_observations || []).map(observation => ({ tool, observation })));
      const fetchObservations = observations.filter(({ observation }) => observation.input_trust === 'untrusted'
        && observation.semantic_risks.some(item => item.id === 'untrusted_network_fetch'));
      const privilegedObservations = observations.filter(({ observation }) => observation.composition_privilege
        && observation.composition_privilege.observed === true);
      const privilegedInventories = new Set(privilegedObservations.map(item => item.observation.inventory));
      const sharedInventories = new Set(fetchObservations
        .filter(fetch => privilegedInventories.has(fetch.observation.inventory))
        .map(item => item.observation.inventory));
      if (!sharedInventories.size) return {};
      const matchedFetch = fetchObservations.filter(item => sharedInventories.has(item.observation.inventory));
      const matchedPrivileged = privilegedObservations.filter(item => sharedInventories.has(item.observation.inventory));
      const tools = [...matchedFetch, ...matchedPrivileged].map(item => item.tool);
      const refs = [
        matchedFetch.flatMap(({ observation }) => [
          observation.refs.input_trust,
          ...observation.semantic_risks.filter(item => item.id === 'untrusted_network_fetch').map(item => item.ref),
        ]),
        matchedPrivileged.map(({ observation }) => observation.composition_privilege.ref),
      ];
      return { finding: finding(rule, tools, refs, `${matchedFetch.length} untrusted fetch tool observation(s) share an inventory with ${matchedPrivileged.length} privileged tool observation(s).`) };
    },
  },
  {
    id: 'BB013', severity: 'high', title: 'Tool description attempts to force tool selection',
    finding_class: 'prompt_injection_indicator',
    precision_note: 'Narrow global-selection heuristic; scoped task guidance is excluded, and remaining matches require human triage.',
    description: 'A tool description directs the model to always select it, invoke it before responding, or avoid competing tools.',
    stop: 'Do not attach the tool until the selection-manipulation language is removed and the server source is reviewed.',
    remediation: 'Keep routing and tool-selection policy outside untrusted tool metadata; reject descriptions that demand priority, mandatory invocation, or exclusion of other tools.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_forced_invocation'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_forced_invocation').map(item => item.ref));
      return { finding: promptFinding(rule, exposed, refs, `${exposed.length} tool description(s) attempt to control global tool selection.`, 'prompt_forced_invocation') };
    },
  },
];

function ruleDigestDescriptor(rule) {
  const { evaluate, ...metadata } = rule;
  return {
    ...metadata,
    detector: evaluate.toString().replace(/\r\n?/g, '\n').trim(),
  };
}

function helperDigestDescriptors() {
  return [uniqueRefs, finding, promptTemplateSummary, promptFinding, coverage, evaluateRules, meetsThreshold, isPromptLintFinding, summarizeFindingClasses]
    .map(helper => helper.toString().replace(/\r\n?/g, '\n').trim());
}

function rulesetBehaviorDescriptor(overrides = {}) {
  return {
    severity_order: overrides.severity_order || SEVERITY_ORDER,
    prompt_lint_ids: overrides.prompt_lint_ids || [...PROMPT_LINT_IDS].sort(),
  };
}

function createRulesetDigest(evidenceSourceSha256 = RULESET_SOURCES.evidence_sha256, helpers = helperDigestDescriptors(), behavior = rulesetBehaviorDescriptor()) {
  return sha256({
    evidence_source_sha256: evidenceSourceSha256,
    behavior,
    helpers,
    rules: RULES.map(ruleDigestDescriptor),
  });
}

const RULESET_DIGEST = createRulesetDigest();

function evaluateRules(facts) {
  const findings = [];
  const coverageGaps = [];
  for (const rule of RULES) {
    const result = rule.evaluate(facts, rule);
    if (result.finding) findings.push(result.finding);
    if (result.gaps) coverageGaps.push(...result.gaps);
  }
  return { findings, coverage_gaps: coverageGaps };
}

function meetsThreshold(findings, threshold) {
  if (threshold === 'none') return false;
  const minimum = SEVERITY_ORDER[threshold];
  return findings.some(item => SEVERITY_ORDER[item.severity] >= minimum);
}

function isPromptLintFinding(finding) {
  return PROMPT_LINT_IDS.has(typeof finding === 'string' ? finding : finding && finding.id);
}

function summarizeFindingClasses(findings) {
  const result = {
    capability_exposure: { count: 0, rule_ids: [] },
    prompt_injection_indicator: { count: 0, rule_ids: [] },
  };
  for (const finding of findings) {
    const key = finding.finding_class;
    if (!Object.prototype.hasOwnProperty.call(result, key)) continue;
    result[key].count += 1;
    result[key].rule_ids.push(finding.id);
  }
  for (const item of Object.values(result)) item.rule_ids = [...new Set(item.rule_ids)].sort();
  return result;
}

module.exports = { RULES, RULESET_DIGEST, RULESET_VERSION, SEVERITY_ORDER, createRulesetDigest, evaluateRules, isPromptLintFinding, meetsThreshold, summarizeFindingClasses };

},

"lib/ruleset-sources.json": function(module) {
module.exports = {
  "evidence_sha256": "e041485a445e12a5a43c895f8277ed34f5743969ac9f616e87e62ccc871dbb6d"
};
},

"lib/sarif.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { RULES } = require('./rules.js');

function level(severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function location(evidence) {
  return {
    physicalLocation: { artifactLocation: { uri: evidence.artifact_name } },
    logicalLocations: [{ fullyQualifiedName: evidence.pointer, kind: 'json-pointer' }],
  };
}

function toSarif(scan) {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: '@backbond/agent-scan',
          version: scan.scanner.version,
          informationUri: 'https://github.com/BackBond/agent-scan',
          rules: RULES.map(rule => ({
            id: rule.id,
            name: rule.title.replace(/[^a-z0-9]+/gi, '_'),
            shortDescription: { text: rule.title },
            fullDescription: { text: rule.description },
            help: { text: rule.remediation },
            helpUri: `https://backbond.ai/agent-scan/rules/#${rule.id}`,
            properties: {
              securitySeverity: String({ critical: 9.5, high: 8, medium: 5, low: 2 }[rule.severity]),
              findingClass: rule.finding_class,
              precisionNote: rule.precision_note,
            },
          })),
        },
      },
      results: scan.findings.map(item => ({
        ruleId: item.id,
        level: level(item.severity),
        message: { text: `${item.title}. ${item.detail} Stop: ${item.stop}` },
        locations: item.evidence.slice(0, 10).map(location),
        properties: {
          severity: item.severity,
          evidenceQuality: item.evidence_quality,
          affectedTools: item.affected_tools,
          findingClass: item.finding_class,
          precisionNote: item.precision_note,
        },
      })),
      invocations: [{ executionSuccessful: true }],
      properties: { coverageStatus: scan.coverage.status, coverageGaps: scan.coverage.gaps.map(item => item.code) },
    }],
  };
}

module.exports = { toSarif };

},

"lib/scanner.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { evaluateRules, RULESET_DIGEST, RULESET_VERSION, summarizeFindingClasses } = require('./rules.js');
const { buildExposurePaths, EXPOSURE_PATH_PROTOCOL } = require('./exposure-paths.js');
const { VET_DECISIONS, VET_PROFILE, VET_SUMMARY_PROTOCOL } = require('./vet-tools.js');
const { version: SCANNER_VERSION } = require('../package.json');

const SCAN_PROTOCOL = 'backbond-agent-scan/v1';

function dedupeGaps(gaps) {
  const seen = new Set();
  return gaps.filter(item => {
    const key = `${item.code}:${item.rule_id || ''}:${item.artifact_name || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => a.code.localeCompare(b.code));
}

function evidenceForCapabilities(facts, capabilities) {
  return facts.tools
    .filter(tool => tool.capabilities.some(capability => capabilities.includes(capability)))
    .flatMap(tool => tool.refs.capabilities);
}

function claimContradictions(submission, facts, findings) {
  if (!submission) return [];
  const answers = submission.assessment.answers;
  const findingIds = new Set(findings.map(item => item.id));
  const contradictions = [];
  const add = (code, claim, observed, evidence, related = []) => contradictions.push({
    code, claim, observed, finding_ids: related.filter(id => findingIds.has(id)), evidence,
  });
  if (answers.exec_code.value === false && facts.tools.some(tool => tool.capabilities.includes('code_execution'))) {
    add('BB-CLAIM-EXEC-CODE', 'exec_code', 'code_execution capability observed', evidenceForCapabilities(facts, ['code_execution']), ['BB001']);
  }
  if (answers.browse_web.value === false && (facts.network_egress_unrestricted || facts.tools.some(tool => tool.capabilities.includes('network_egress')))) {
    add('BB-CLAIM-WEB', 'browse_web', 'network egress capability observed', evidenceForCapabilities(facts, ['network_egress']), ['BB002', 'BB006']);
  }
  if (answers.filesystem.value === false && (facts.wildcards.some(item => item.domain === 'filesystem') || facts.tools.some(tool => tool.capabilities.includes('filesystem_access')))) {
    add('BB-CLAIM-FILESYSTEM', 'filesystem', 'filesystem capability observed', [
      ...evidenceForCapabilities(facts, ['filesystem_access']),
      ...facts.wildcards.filter(item => item.domain === 'filesystem').map(item => item.ref),
    ], ['BB006']);
  }
  if (answers.human_approval.value === 'always' && findingIds.has('BB003')) {
    add('BB-CLAIM-APPROVAL', 'human_approval', 'consequential action without enforced approval observed', findings.find(item => item.id === 'BB003').evidence, ['BB003']);
  }
  if (answers.persistent_memory.value === false && facts.tools.some(tool => tool.capabilities.includes('persistent_write'))) {
    add('BB-CLAIM-MEMORY', 'persistent_memory', 'persistent write capability observed', evidenceForCapabilities(facts, ['persistent_write']), ['BB004']);
  }
  if (answers.audit_logging.value === true && findingIds.has('BB005')) {
    add('BB-CLAIM-AUDIT', 'audit_logging', 'privileged action without observable audit evidence', findings.find(item => item.id === 'BB005').evidence, ['BB005']);
  }
  if (Number.isInteger(answers.tool_count.value) && answers.tool_count.value !== facts.tools.length) {
    add('BB-CLAIM-TOOL-COUNT', 'tool_count', `${facts.tools.length} tool identities observed`, facts.tools.flatMap(tool => tool.refs.identity), []);
  }
  return contradictions.sort((a, b) => a.code.localeCompare(b.code));
}

function summary(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) counts[item.severity] += 1;
  return { total: findings.length, by_severity: counts };
}

function scanEvidence(evidence, options = {}) {
  const evaluated = evaluateRules(evidence.facts);
  const gaps = dedupeGaps([...evidence.coverage_gaps, ...evaluated.coverage_gaps]);
  const contradictions = claimContradictions(options.claims || null, evidence.facts, evaluated.findings);
  const coverageStatus = gaps.length ? 'partial' : 'complete';
  return {
    protocol: SCAN_PROTOCOL,
    scanned_at: (options.now || new Date()).toISOString(),
    scanner: { name: '@backbond/agent-scan', version: SCANNER_VERSION, mode: 'local_deterministic' },
    ruleset: { version: RULESET_VERSION, sha256: RULESET_DIGEST },
    status: evaluated.findings.length ? 'findings' : coverageStatus === 'complete' ? 'no_findings' : 'inconclusive',
    summary: summary(evaluated.findings),
    finding_classes: summarizeFindingClasses(evaluated.findings),
    findings: evaluated.findings,
    exposure_paths: buildExposurePaths(evaluated.findings),
    coverage: { status: coverageStatus, gaps },
    claim_contradictions: contradictions,
    inputs: evidence.artifacts,
    discovery: evidence.discovery,
  };
}

function scannerContract() {
  return {
    protocol: SCAN_PROTOCOL,
    product: '@backbond/agent-scan',
    version: SCANNER_VERSION,
    mode: 'local_deterministic',
    ruleset: { version: RULESET_VERSION, sha256: RULESET_DIGEST },
    supported_inputs: {
      tool_schema: ['backbond-tool-schema/v1', 'openai-function-tools/v1', 'anthropic-tools/v1', 'mcp-tools-list/v1', 'OpenAPI 3.x'],
      agent_config: ['Claude Desktop/Code', 'Cursor', 'VS Code', 'Windsurf', 'Gemini CLI'],
      permissions: ['backbond-permissions/v1', 'recognized MCP sandbox fields'],
      trace: ['backbond-trace/v1', 'OpenTelemetry OTLP JSON'],
      claims: ['backbond-agent-teaser/v4 (optional hypotheses only)'],
    },
    profiles: {
      pre_attachment: {
        protocol: VET_PROFILE,
        summary_protocol: VET_SUMMARY_PROTOCOL,
        command: 'vet-tools',
        decisions: [...VET_DECISIONS],
        scope: 'supplied tool metadata and same-manifest composition only',
      },
    },
    exposure_paths: { protocol: EXPOSURE_PATH_PROTOCOL, kind: 'potential static composition summaries' },
    guarantees: [
      'Rules execute locally and require no private analyzer.',
      'Claims cannot create, suppress, or reduce finding severity.',
      'No network request is implemented by the scanner.',
      'Receipts contain hashes and finding references, not raw artifact bodies.',
      'Capability and semantic inferences are labeled derived rather than presented as explicit controls.',
      'Capability exposure and prompt-injection indicators are counted separately, with a non-numeric precision note on every finding.',
      'Partial zero-finding scans are inconclusive rather than presented as clean.',
      'Public records are self-run and unverified; they are not BackBond attestations.',
      'A no-blocking-finding pre-attachment decision is not a safety determination or runtime attestation.',
    ],
  };
}

module.exports = { SCAN_PROTOCOL, SCANNER_VERSION, claimContradictions, scanEvidence, scannerContract };

},

"lib/teaser.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { PROTOCOL: ASSESSMENT_PROTOCOL, assessmentJsonSchema, questionSet, validateAssessment } = require('./assessment.js');

const TEASER_PROTOCOL = 'backbond-agent-teaser/v4';

function teaserContract() {
  return {
    protocol: TEASER_PROTOCOL,
    subject: 'self',
    public_client_role: 'optional_claim_hypotheses',
    instructions: [
      'Claims are optional hypotheses and are never finding or severity inputs.',
      'The local scanner compares claims with observed evidence only to report contradictions.',
      'Omitting claims does not reduce scanner coverage for supported artifacts.',
    ],
    assessment: questionSet(),
    submit_shape: {
      protocol: TEASER_PROTOCOL,
      subject: 'self',
      assessment: `<${ASSESSMENT_PROTOCOL} document>`,
    },
  };
}

function teaserSubmissionJsonSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['protocol', 'subject', 'assessment'],
    properties: {
      protocol: { type: 'string', const: TEASER_PROTOCOL },
      subject: { type: 'string', const: 'self' },
      assessment: assessmentJsonSchema(),
    },
  };
}

function validateTeaserSubmission(submission) {
  if (!submission || typeof submission !== 'object' || Array.isArray(submission)) throw new Error('teaser submission must be a JSON object');
  const extras = Object.keys(submission).filter(key => !['protocol', 'subject', 'assessment'].includes(key));
  if (extras.length) throw new Error(`teaser submission has unknown fields: ${extras.join(', ')}`);
  if (submission.protocol !== TEASER_PROTOCOL) throw new Error(`protocol must be "${TEASER_PROTOCOL}"`);
  if (submission.subject !== 'self') throw new Error('subject must be "self"');
  validateAssessment(submission.assessment);
  return submission;
}

module.exports = { TEASER_PROTOCOL, teaserContract, teaserSubmissionJsonSchema, validateTeaserSubmission };

},

"lib/text.js": function(module, exports, require, __filename, __dirname) {
'use strict';

function safeInline(value, maxLength = 500) {
  const cleaned = String(value).replace(/[\p{C}\p{Zl}\p{Zp}]/gu, '\uFFFD');
  const characters = Array.from(cleaned);
  return characters.length > maxLength ? `${characters.slice(0, maxLength - 1).join('')}\u2026` : cleaned;
}

module.exports = { safeInline };

},

"lib/vet-tools.js": function(module, exports, require, __filename, __dirname) {
'use strict';

const { buildExposurePaths } = require('./exposure-paths.js');
const { sha256 } = require('./canonical.js');
const { meetsThreshold, RULESET_DIGEST, RULESET_VERSION, summarizeFindingClasses } = require('./rules.js');
const { safeInline } = require('./text.js');

const VET_PROFILE = 'backbond-pre-attach/v1';
const VET_SUMMARY_PROTOCOL = 'backbond-vet-summary/v1';
const VET_DECISIONS = Object.freeze(['block', 'review', 'no_blocking_finding']);
const VET_EXIT_CODES = Object.freeze({ block: 1, review: 3, no_blocking_finding: 0 });
const VET_RULE_IDS = new Set(['BB001', 'BB002', 'BB004', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012', 'BB013']);
const VET_THRESHOLD = 'high';
const VET_EXCLUDED_RULE_IDS = Object.freeze(['BB003', 'BB005', 'BB006']);
const SUPPORTED_DIALECTS = new Set(['openai-function-tools/v1', 'anthropic-tools/v1', 'mcp-tools-list/v1']);
const CONFUSABLE_TO_ASCII = new Map([
  ['\u03b1', 'a'], ['\u03b2', 'b'], ['\u03b5', 'e'], ['\u03b9', 'i'], ['\u03ba', 'k'], ['\u03bc', 'm'],
  ['\u03bd', 'v'], ['\u03bf', 'o'], ['\u03c1', 'p'], ['\u03c4', 't'], ['\u03c5', 'y'], ['\u03c7', 'x'],
  ['\u0430', 'a'], ['\u0432', 'b'], ['\u0441', 'c'], ['\u0435', 'e'], ['\u043d', 'h'], ['\u0456', 'i'],
  ['\u0458', 'j'], ['\u043a', 'k'], ['\u043c', 'm'], ['\u043e', 'o'], ['\u0440', 'p'], ['\u0455', 's'],
  ['\u0442', 't'], ['\u0443', 'y'], ['\u0445', 'x'],
]);

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;
  return { total: findings.length, by_severity: bySeverity };
}

function profileGap(code, message) {
  return { code, artifact_kind: 'tool_schema', status: 'insufficient_evidence', message };
}

function countBy(values) {
  const counts = new Map();
  for (const value of values.filter(Boolean)) counts.set(value, (counts.get(value) || 0) + 1);
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function toolNameSkeleton(name) {
  return [...name.normalize('NFKC').trim().toLowerCase()]
    .map(character => CONFUSABLE_TO_ASCII.get(character) || character)
    .join('')
    .replace(/[\s._-]+/g, '_');
}

function toolNameCoverageGaps(tools) {
  const gaps = [];
  const nonAscii = tools.filter(tool => /[^\x20-\x7e]/.test(tool.name));
  if (nonAscii.length) {
    gaps.push(profileGap('BB-VET-NON-ASCII-TOOL-NAME', `${nonAscii.length} tool name(s) contain non-ASCII characters that require operator review.`));
  }
  const skeletons = new Map();
  for (const tool of tools) {
    const skeleton = toolNameSkeleton(tool.name);
    if (!skeletons.has(skeleton)) skeletons.set(skeleton, new Set());
    skeletons.get(skeleton).add(tool.name);
  }
  const collisions = [...skeletons.values()].filter(names => names.size > 1);
  if (collisions.length) {
    gaps.push(profileGap('BB-VET-CONFUSABLE-TOOL-NAME', `${collisions.length} tool-name group(s) become indistinguishable after compatibility, case, separator, and common-script confusable normalization.`));
  }
  return gaps;
}

function profileCoverage(scan, evidence) {
  const gaps = scan.coverage.gaps.filter(item => (
    item.code === 'BB-COV-MISSING-TOOL_SCHEMA'
    || item.code === 'BB-COV-UNSUPPORTED-TOOL_SCHEMA'
    || item.code.startsWith('BB-VET-')
    || (item.rule_id && VET_RULE_IDS.has(item.rule_id))
  )).map(item => ({
    code: item.code,
    rule_id: item.rule_id || null,
    artifact_kind: item.artifact_kind,
    status: item.status,
    message: item.message,
  }));
  if (!evidence.facts.tools.length) {
    gaps.push(profileGap('BB-VET-NO-TOOLS', 'The supplied manifest contains no tool identities to vet.'));
  }
  gaps.push(...toolNameCoverageGaps(evidence.facts.tools));
  const duplicateNames = evidence.facts.tools.filter(tool => tool.observation_count > 1);
  if (duplicateNames.length) {
    gaps.push(profileGap('BB-VET-DUPLICATE-TOOL-NAME', `${duplicateNames.length} tool name(s) appear more than once in the supplied manifest.`));
  }
  const missingSchemas = evidence.facts.tools.filter(tool => tool.input_schema_observed !== true);
  if (missingSchemas.length) {
    gaps.push(profileGap('BB-VET-MISSING-INPUT-SCHEMA', `${missingSchemas.length} tool(s) did not provide one unambiguous, analyzable object input schema.`));
  }
  const missingDescriptions = evidence.facts.tools.filter(tool => tool.semantic_metadata_observed !== true);
  if (missingDescriptions.length) {
    gaps.push(profileGap('BB-VET-MISSING-DESCRIPTION', `${missingDescriptions.length} tool(s) did not provide a description or title.`));
  }
  const promptReview = evidence.facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_metadata_review'));
  if (promptReview.length) {
    gaps.push(profileGap('BB-VET-PROMPT-METADATA-REVIEW', `${promptReview.length} tool(s) contain ambiguous directive-like metadata that requires operator review.`));
  }
  const incompleteSchemas = evidence.facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'schema_analysis_incomplete'));
  if (incompleteSchemas.length) {
    gaps.push(profileGap('BB-VET-SCHEMA-ANALYSIS-INCOMPLETE', `${incompleteSchemas.length} tool schema(s) exceed the local analysis budget or contain unresolved input structure.`));
  }
  const ambiguousDestinations = evidence.facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'ambiguous_destination_reference'));
  if (ambiguousDestinations.length) {
    gaps.push(profileGap('BB-VET-AMBIGUOUS-DESTINATION', `${ambiguousDestinations.length} tool(s) contain endpoint, href, path, host, destination, or URL-like input whose network action and host constraints are not both observable.`));
  }
  const ambiguousQueries = evidence.facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'ambiguous_query_expression'));
  if (ambiguousQueries.length) {
    gaps.push(profileGap('BB-VET-AMBIGUOUS-QUERY-EXPRESSION', `${ambiguousQueries.length} tool(s) accept query or expression text whose interpreter semantics are not observable.`));
  }
  const permissionClaims = evidence.facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'permission_requirement_unverified'));
  if (permissionClaims.length) {
    gaps.push(profileGap('BB-VET-PERMISSION-REQUIREMENT-UNVERIFIED', `${permissionClaims.length} tool(s) claim a permission requirement, but this profile cannot observe runtime enforcement.`));
  }
  const unsupported = evidence.artifacts.filter(artifact => artifact.dialect !== 'ambiguous-tool-manifest' && (artifact.kind !== 'tool_schema'
    || (!SUPPORTED_DIALECTS.has(artifact.dialect) && !String(artifact.dialect || '').startsWith('openapi/') && !String(artifact.dialect || '').startsWith('swagger/'))));
  if (unsupported.length) {
    gaps.push(profileGap('BB-VET-UNSUPPORTED-MANIFEST', 'vet-tools requires an MCP, OpenAI, Anthropic, or OpenAPI tool manifest.'));
  }
  const seen = new Set();
  const unique = gaps.filter(item => {
    const key = `${item.code}:${item.rule_id || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => a.code.localeCompare(b.code));
  return {
    status: unique.length ? 'partial' : 'complete',
    gaps: unique,
    states: {
      tool_identities: evidence.facts.tools.length ? 'observed' : 'insufficient_evidence',
      tool_descriptions: evidence.facts.tools.length && missingDescriptions.length === 0 ? 'observed' : 'partial_or_missing',
      input_schemas: evidence.facts.tools.length && missingSchemas.length === 0 && incompleteSchemas.length === 0 ? 'observed' : 'partial_or_missing',
      same_manifest_composition: evidence.facts.tools.length ? 'observed' : 'insufficient_evidence',
      runtime_permissions: 'unobservable_in_profile',
      approval_enforcement: 'unobservable_in_profile',
      audit_behavior: 'unobservable_in_profile',
      runtime_execution: 'not_performed',
    },
  };
}

function affectedToolCountForGap(gap, tools) {
  const byRisk = riskId => tools.filter(tool => tool.semantic_risks.some(item => item.id === riskId)).length;
  const byCapability = capabilities => tools.filter(tool => tool.capabilities.some(item => capabilities.includes(item))).length;
  switch (gap.code) {
    case 'BB-VET-NO-TOOLS': return 0;
    case 'BB-VET-NON-ASCII-TOOL-NAME': return tools.filter(tool => /[^\x20-\x7e]/.test(tool.name)).length;
    case 'BB-VET-CONFUSABLE-TOOL-NAME': {
      const skeletons = new Map();
      for (const tool of tools) {
        const skeleton = toolNameSkeleton(tool.name);
        if (!skeletons.has(skeleton)) skeletons.set(skeleton, []);
        skeletons.get(skeleton).push(tool.name);
      }
      return [...skeletons.values()].filter(names => new Set(names).size > 1).reduce((count, names) => count + names.length, 0);
    }
    case 'BB-VET-DUPLICATE-TOOL-NAME': return tools.filter(tool => tool.observation_count > 1).length;
    case 'BB-VET-MISSING-INPUT-SCHEMA': return tools.filter(tool => tool.input_schema_observed !== true).length;
    case 'BB-VET-MISSING-DESCRIPTION': return tools.filter(tool => tool.semantic_metadata_observed !== true).length;
    case 'BB-VET-PROMPT-METADATA-REVIEW': return byRisk('prompt_metadata_review');
    case 'BB-VET-SCHEMA-ANALYSIS-INCOMPLETE': return byRisk('schema_analysis_incomplete');
    case 'BB-VET-AMBIGUOUS-DESTINATION': return byRisk('ambiguous_destination_reference');
    case 'BB-VET-AMBIGUOUS-QUERY-EXPRESSION': return byRisk('ambiguous_query_expression');
    case 'BB-VET-PERMISSION-REQUIREMENT-UNVERIFIED': return byRisk('permission_requirement_unverified');
    default:
      break;
  }
  switch (gap.rule_id) {
    case 'BB001': return byCapability(['code_execution']);
    case 'BB002': {
      const secretReaders = byCapability(['secret_read']);
      return secretReaders || null;
    }
    case 'BB004': return byCapability(['persistent_write']);
    case 'BB007': return byRisk('arbitrary_interpreter_input');
    case 'BB008': return byRisk('unvalidated_destination');
    case 'BB009': return byRisk('prompt_instruction_override');
    case 'BB010': return byRisk('prompt_concealed_behavior');
    case 'BB011': return byRisk('prompt_sensitive_data_request');
    case 'BB012': return tools.filter(tool => tool.semantic_risks.some(item => item.id === 'untrusted_network_fetch')
      || tool.capabilities.some(item => ['privileged_action', 'destructive_action', 'financial_action', 'code_execution', 'secret_read'].includes(item))).length;
    case 'BB013': return byRisk('prompt_forced_invocation');
    default: return null;
  }
}

function reviewGuidance(code, variant = null) {
  if (code === 'BB004' && variant === 'standalone_persistent_write') {
    return {
      evidence_needed: 'Runtime-enforced write scope, retention, and approval policy for the persistent destination.',
      next_step: 'Constrain the write destination and retention, then review the implementation before attachment.',
    };
  }
  switch (code) {
    case 'BB-VET-AMBIGUOUS-DESTINATION': return {
      evidence_needed: 'Schema-enforced hostname restriction or runtime network-policy evidence.',
      next_step: 'Constrain the hostname or review the implementation before attachment.',
    };
    case 'BB-VET-AMBIGUOUS-QUERY-EXPRESSION': return {
      evidence_needed: 'The accepted grammar and the runtime interpreter, if any, for the query or expression field.',
      next_step: 'Replace free-form interpreter input with a named or parameterized operation, or confirm that the field is data-only.',
    };
    case 'BB-VET-PERMISSION-REQUIREMENT-UNVERIFIED': return {
      evidence_needed: 'Runtime policy or implementation evidence that the claimed permission check is enforced.',
      next_step: 'Verify the permission gate outside tool metadata before attachment.',
    };
    case 'BB-VET-PROMPT-METADATA-REVIEW': return {
      evidence_needed: 'Operator confirmation that directive-like metadata is descriptive or example text, not agent policy.',
      next_step: 'Rewrite the metadata as a factual capability description or keep the tool detached pending review.',
    };
    case 'BB-VET-SCHEMA-ANALYSIS-INCOMPLETE': return {
      evidence_needed: 'A bounded, fully resolvable object schema within the local analysis budget.',
      next_step: 'Simplify or pre-resolve the schema, then run the pre-attachment check again.',
    };
    case 'BB-VET-MISSING-INPUT-SCHEMA': return {
      evidence_needed: 'One unambiguous, analyzable object input schema for every affected tool.',
      next_step: 'Export complete tool schemas and run the pre-attachment check again.',
    };
    case 'BB-VET-MISSING-DESCRIPTION': return {
      evidence_needed: 'A factual title or description for every affected tool.',
      next_step: 'Add factual semantic metadata and run the pre-attachment check again.',
    };
    case 'BB-VET-NON-ASCII-TOOL-NAME':
    case 'BB-VET-CONFUSABLE-TOOL-NAME':
    case 'BB-VET-DUPLICATE-TOOL-NAME': return {
      evidence_needed: 'A unique, unambiguous tool identity set after compatibility and confusable-name normalization.',
      next_step: 'Rename or remove ambiguous identities, then run the pre-attachment check again.',
    };
    case 'BB-VET-NO-TOOLS': return {
      evidence_needed: 'The complete exported tool inventory intended for attachment.',
      next_step: 'Export the live tools/list manifest and run the pre-attachment check again.',
    };
    case 'BB-VET-AMBIGUOUS-MANIFEST':
    case 'BB-VET-UNSUPPORTED-MANIFEST':
    case 'BB-COV-MISSING-TOOL_SCHEMA':
    case 'BB-COV-UNSUPPORTED-TOOL_SCHEMA': return {
      evidence_needed: 'One supported MCP, OpenAI, Anthropic, or OpenAPI tool manifest with an unambiguous dialect.',
      next_step: 'Export one supported manifest shape and run the pre-attachment check again.',
    };
    default: return {
      evidence_needed: 'Supported metadata or runtime-policy evidence that closes this coverage gap.',
      next_step: 'Inspect the implementation and supply explicit constraints before attachment.',
    };
  }
}

function createReviewItems(findings, coverage, evidence) {
  const items = findings.filter(item => !meetsThreshold([item], VET_THRESHOLD)).map(item => {
    const guidance = reviewGuidance(item.id, item.variant || null);
    return {
      code: item.id,
      ...(item.variant ? { variant: item.variant } : {}),
      affected_tool_count: Array.isArray(item.affected_tools) ? item.affected_tools.length : null,
      reason: item.detail,
      ...guidance,
    };
  });
  for (const gap of coverage.gaps) {
    items.push({
      code: gap.code,
      ...(gap.rule_id ? { rule_id: gap.rule_id } : {}),
      affected_tool_count: affectedToolCountForGap(gap, evidence.facts.tools),
      reason: gap.message,
      ...reviewGuidance(gap.code),
    });
  }
  return items.sort((left, right) => `${left.code}:${left.variant || ''}`.localeCompare(`${right.code}:${right.variant || ''}`));
}

function promptTemplateMultiplicity(findings) {
  const templates = new Map();
  for (const finding of findings) {
    const entries = finding.metadata_template_summary && finding.metadata_template_summary.templates;
    for (const item of Array.isArray(entries) ? entries : []) {
      if (!item || typeof item.sha256 !== 'string' || !Number.isInteger(item.multiplicity) || item.multiplicity < 1) continue;
      templates.set(item.sha256, Math.max(templates.get(item.sha256) || 0, item.multiplicity));
    }
  }
  const multiplicities = [...templates.values()];
  return {
    distinct_templates: multiplicities.length,
    largest_multiplicity: multiplicities.reduce((largest, value) => Math.max(largest, value), 0),
    multiplicity_histogram: countBy(multiplicities.map(String)),
  };
}

function createVetSummary(result) {
  return {
    protocol: VET_SUMMARY_PROTOCOL,
    scanned_at: result.scanned_at,
    scanner: result.scanner,
    ruleset: result.ruleset,
    profile: result.profile,
    decision: result.decision,
    threshold: result.threshold,
    summary: result.summary,
    finding_classes: result.finding_classes,
    rule_histogram: countBy(result.findings.map(item => item.id)),
    coverage: {
      status: result.coverage.status,
      gap_codes: countBy(result.coverage.gaps.map(item => item.code)),
      states: result.coverage.states,
    },
    review_items: result.review_items,
    template_multiplicity: { prompt_metadata: promptTemplateMultiplicity(result.findings) },
    scope: {
      tool_count: result.scope.tool_count,
      excluded_rule_ids: result.scope.excluded_rule_ids,
    },
    privacy: {
      server_ids_included: false,
      tool_names_included: false,
      tool_descriptions_included: false,
      artifact_names_included: false,
      evidence_pointers_included: false,
      template_hashes_included: false,
    },
    assurance: result.assurance,
  };
}

function createVetResult(scan, evidence) {
  const findings = scan.findings.filter(item => VET_RULE_IDS.has(item.id));
  const coverage = profileCoverage(scan, evidence);
  const blocking = meetsThreshold(findings, VET_THRESHOLD);
  const decision = blocking ? 'block' : findings.length || coverage.status !== 'complete' ? 'review' : 'no_blocking_finding';
  const reviewItems = createReviewItems(findings, coverage, evidence);
  return {
    protocol: VET_PROFILE,
    scanned_at: scan.scanned_at,
    scanner: scan.scanner,
    ruleset: scan.ruleset,
    profile: { version: VET_PROFILE, sha256: VET_PROFILE_DIGEST },
    decision,
    threshold: VET_THRESHOLD,
    summary: summarize(findings),
    finding_classes: summarizeFindingClasses(findings),
    findings,
    review_items: reviewItems,
    coverage,
    exposure_paths: buildExposurePaths(findings),
    scope: {
      tool_count: evidence.facts.tools.length,
      assessed: ['tool identities', 'tool descriptions', 'supplied input schemas', 'same-manifest tool composition'],
      not_assessed: ['runtime permission enforcement', 'approval enforcement', 'audit behavior', 'runtime traces', 'actual tool execution'],
      excluded_rule_ids: [...VET_EXCLUDED_RULE_IDS],
    },
    assurance: 'Static pre-attachment metadata check only. A no-blocking-finding decision is not a safety determination or runtime attestation.',
  };
}

function vetExitCode(decision) {
  if (!Object.prototype.hasOwnProperty.call(VET_EXIT_CODES, decision)) throw new Error(`unknown pre-attachment decision: ${decision}`);
  return VET_EXIT_CODES[decision];
}

function createVetProfileDigest(overrides = {}) {
  const functions = [toolNameSkeleton, toolNameCoverageGaps, profileCoverage, affectedToolCountForGap, reviewGuidance,
    createReviewItems, createVetResult, vetExitCode]
    .map(helper => helper.toString().replace(/\r\n?/g, '\n').trim());
  return sha256({
    protocol: overrides.protocol || VET_PROFILE,
    decisions: overrides.decisions || VET_DECISIONS,
    exit_codes: overrides.exit_codes || VET_EXIT_CODES,
    rule_ids: overrides.rule_ids || [...VET_RULE_IDS].sort(),
    threshold: overrides.threshold || VET_THRESHOLD,
    excluded_rule_ids: overrides.excluded_rule_ids || [...VET_EXCLUDED_RULE_IDS],
    ruleset_version: overrides.ruleset_version || RULESET_VERSION,
    ruleset_sha256: overrides.ruleset_sha256 || RULESET_DIGEST,
    supported_dialects: overrides.supported_dialects || [...SUPPORTED_DIALECTS].sort(),
    confusable_map: overrides.confusable_map || [...CONFUSABLE_TO_ASCII.entries()].sort(([left], [right]) => left.localeCompare(right)),
    functions: overrides.functions || functions,
  });
}

const VET_PROFILE_DIGEST = createVetProfileDigest();

function findingCount(summary) {
  const parts = Object.entries(summary.by_severity).filter(([, count]) => count > 0).map(([severity, count]) => `${count} ${severity}`);
  return `${summary.total} finding${summary.total === 1 ? '' : 's'}${parts.length ? ` (${parts.join(', ')})` : ''}`;
}

function renderVetHuman(result) {
  const heading = result.decision === 'block'
    ? `BLOCK — ${findingCount(result.summary)}`
    : result.decision === 'review'
      ? `REVIEW — ${findingCount(result.summary)}`
      : `NO BLOCKING FINDING — ${findingCount(result.summary)}`;
  const lines = [heading, 'Profile: pre-attachment tool manifest only'];
  if (result.summary.total) {
    lines.push(`Capability exposure: ${result.finding_classes.capability_exposure.count}; prompt-injection indicators: ${result.finding_classes.prompt_injection_indicator.count}`);
  }
  for (const finding of result.findings) {
    const derived = finding.evidence_quality === 'derived' ? ' [derived]' : '';
    lines.push(`${finding.id} ${finding.affected_tools.join(' + ') || finding.title}${derived}`);
    lines.push(`  Stop: ${finding.stop}`);
  }
  for (const path of result.exposure_paths.paths) {
    lines.push(`${path.id} potential: ${path.chain.join(' → ')} (${path.finding_ids.join(', ')})`);
    lines.push(`  Agent action: ${path.action}`);
  }
  if (result.coverage.gaps.length) {
    lines.push(`Profile coverage: partial — ${result.coverage.gaps.map(item => item.message).join('; ')}`);
  } else {
    lines.push('Profile coverage: complete');
  }
  lines.push(`Agent decision: ${result.decision === 'block' ? 'do not attach automatically; isolate or review the toolset.' : result.decision === 'review' ? 'do not attach automatically; a finding or evidence gap requires operator review.' : 'this profile found no reason to block; runtime policy still controls attachment.'}`);
  lines.push('Not assessed: runtime enforcement, approval, audit behavior, traces, or actual execution.');
  lines.push('BackBond combines deeper evaluation, continuous runtime evidence, and—where approved—financial protection: https://backbond.ai');
  return `${lines.map(line => safeInline(line)).join('\n')}\n`;
}

module.exports = {
  VET_DECISIONS, VET_PROFILE, VET_PROFILE_DIGEST, VET_RULE_IDS, VET_SUMMARY_PROTOCOL,
  createVetProfileDigest, createVetResult, createVetSummary, profileCoverage, renderVetHuman, vetExitCode,
};

},

"package.json": function(module) {
module.exports = {
  "name": "@backbond/agent-scan",
  "version": "0.6.2",
  "private": false,
  "mcpName": "io.github.BackBond/agent-scan",
  "description": "Local deterministic pre-attachment security scanner for MCP and AI-agent tool manifests.",
  "bin": {
    "agent-scan": "bin/agent-scan.js",
    "backbond-agent-scan": "bin/agent-scan.js"
  },
  "files": [
    "bin/",
    "lib/",
    "docs/",
    "fixtures/",
    "AGENTS.md",
    "SKILL.md",
    "CHANGELOG.md",
    "README.md",
    "plugin.json",
    "server.json",
    "skills/",
    "LICENSE"
  ],
  "engines": {
    "node": ">=18"
  },
  "scripts": {
    "test": "node --test",
    "test:corpus-regression": "node --test test/corpus-regression.test.js test/corpus-summary.test.js",
    "test:public-boundary": "node --test test/public-boundary.test.js",
    "prepack": "node --test",
    "prepublishOnly": "node scripts/assert-clean-history.js"
  },
  "keywords": [
    "ai-agent",
    "agent-security",
    "agent-security-scanner",
    "static-analysis",
    "security-findings",
    "ci-security",
    "tamper-evident-receipt",
    "runtime-evidence",
    "offline-first",
    "mcp-security",
    "mcp",
    "mcp-server",
    "mcp-tool-vetting",
    "model-context-protocol",
    "agent-skills",
    "tool-security",
    "pre-attachment-security",
    "shareable-scan-record"
  ],
  "homepage": "https://backbond.ai/agent-scan/",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/BackBond/agent-scan.git"
  },
  "bugs": {
    "url": "https://github.com/BackBond/agent-scan/issues"
  },
  "author": "BackBond (https://backbond.ai)",
  "license": "MIT"
};
}
};
const __cache = Object.create(null);

function __resolve(from, request) {
  if (!request.startsWith('.')) return request;
  const base = __posix.normalize(__posix.join(__posix.dirname(from), request));
  for (const candidate of [base, base + '.js', base + '.json']) {
    if (Object.prototype.hasOwnProperty.call(__factories, candidate)) return candidate;
  }
  throw new Error('standalone module not found: ' + request + ' from ' + from);
}

function __load(id) {
  if (!Object.prototype.hasOwnProperty.call(__factories, id)) return __nativeRequire(id);
  if (__cache[id]) return __cache[id].exports;
  const module = { exports: {} };
  __cache[id] = module;
  const localRequire = request => __load(__resolve(id, request));
  __factories[id](module, module.exports, localRequire, id, __posix.dirname(id));
  return module.exports;
}

__load("bin/agent-scan.js");
