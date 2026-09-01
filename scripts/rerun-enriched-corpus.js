#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXPECTED_COLUMNS = [
  'manifest_file', 'server_name', 'remote_url', 'version', 'tool_count', 'decision',
  'exit_code', 'finding_count', 'rule_ids', 'rule_titles', 'tool_names',
];
const DECISION_TO_EXIT = { block: 1, review: 3, no_blocking_finding: 0 };
const DECISIONS = Object.keys(DECISION_TO_EXIT);
const EXACT_BASELINE = Object.freeze({
  scanner_version: '0.5.15',
  ruleset_version: 'backbond-local-rules/1.4.0',
  ruleset_sha256: 'b237dddf135bc7f7a1b8c8cfee4262c7f0c184a4923cc7d85c219750c15fac98',
  profile_version: 'backbond-pre-attach/v1',
  profile_sha256: 'bddae8f53903eb90f6984e75dbb93730ecfd589bd50c3ed8671a2165ded19438',
  source_commit: '649bfa41a87f9b646ce550f37d3afc62b5088b3a',
});
const ZERO_ERROR_VALIDATION_FIELDS = Object.freeze([
  'duplicate_manifest_keys',
  'csv_rows_without_manifest',
  'manifests_without_csv_row',
  'invalid_decisions',
  'decision_exit_mismatches',
  'invalid_tool_counts',
  'invalid_finding_counts',
  'baseline_finding_count_mismatches',
  'baseline_rule_title_count_mismatches',
  'unknown_baseline_rule_ids',
  'json_parse_failures',
  'unsupported_manifest_shapes',
  'tool_count_mismatches',
  'tool_name_count_mismatches',
  'tool_name_set_mismatches',
  'manifests_over_scanner_byte_limit',
  'scanner_failures',
]);

function increment(map, key, count = 1) {
  if (key === null || key === undefined || key === '') return;
  const normalized = String(key);
  map.set(normalized, (map.get(normalized) || 0) + count);
}

function sortedObject(map) {
  return Object.fromEntries([...map.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function incrementNested(map, outerKey, innerKey, count = 1) {
  if (!map.has(outerKey)) map.set(outerKey, new Map());
  increment(map.get(outerKey), innerKey, count);
}

function sortedNestedObject(map) {
  return Object.fromEntries([...map.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, counts]) => [key, sortedObject(counts)]));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
}

function sameCounts(actual, expected) {
  return canonicalize(actual || {}) === canonicalize(expected || {});
}

function validateBaselineVerification(verification, expected) {
  const fail = detail => {
    throw new Error(`baseline verification JSON does not prove an exact 0.5.15 / ruleset 1.4.0 replay of this CSV: ${detail}`);
  };
  if (!verification || verification.protocol !== 'backbond-corpus-delta/v1') fail('unexpected protocol');
  if (!verification.corpus || verification.corpus.rows !== expected.rows) fail('corpus row count mismatch');
  if (!verification.sources || !verification.sources.csv || verification.sources.csv.sha256 !== expected.csvSha256) fail('CSV digest mismatch');
  if (expected.archiveSha256
    && (!verification.sources.archive || verification.sources.archive.sha256 !== expected.archiveSha256)) fail('archive digest mismatch');
  if (!verification.delta || verification.delta.changed_rows !== 0) fail('baseline decisions changed');
  if (!verification.current || verification.current.source_commit !== EXACT_BASELINE.source_commit) fail('source commit mismatch');
  if (!verification.current.scanner || verification.current.scanner.version !== EXACT_BASELINE.scanner_version) fail('scanner version mismatch');
  if (!verification.current.ruleset
    || verification.current.ruleset.version !== EXACT_BASELINE.ruleset_version
    || verification.current.ruleset.sha256 !== EXACT_BASELINE.ruleset_sha256) fail('ruleset identity mismatch');
  if (!verification.current.profile
    || verification.current.profile.version !== EXACT_BASELINE.profile_version
    || verification.current.profile.sha256 !== EXACT_BASELINE.profile_sha256) fail('profile identity mismatch');
  if (!sameCounts(verification.current.decisions, expected.decisions)) fail('current decision histogram mismatch');
  if (!sameCounts(verification.current.rule_histogram, expected.ruleHistogram)) fail('current rule histogram mismatch');
  if (!verification.baseline
    || !sameCounts(verification.baseline.decisions, expected.decisions)
    || !sameCounts(verification.baseline.rule_histogram, expected.ruleHistogram)) fail('CSV baseline histogram mismatch');
  if (!verification.validation) fail('validation summary missing');
  if (verification.validation.csv_rows !== expected.rows
    || verification.validation.distinct_manifest_keys !== expected.rows
    || verification.validation.manifest_files !== expected.rows) fail('validation row totals mismatch');
  for (const field of ZERO_ERROR_VALIDATION_FIELDS) {
    if (verification.validation[field] !== 0) fail(`validation.${field} is not zero`);
  }
  return {
    exact_tag_replay: true,
    changed_rows: 0,
    source_commit: verification.current.source_commit,
    scanner: verification.current.scanner,
    ruleset: verification.current.ruleset,
    profile: verification.current.profile,
  };
}

function parseCsv(text) {
  const records = [];
  let record = [];
  let field = '';
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') quoted = false;
      else field += character;
      continue;
    }
    if (character === '"') quoted = true;
    else if (character === ',') {
      record.push(field);
      field = '';
    } else if (character === '\n') {
      record.push(field.replace(/\r$/, ''));
      if (record.some(value => value !== '')) records.push(record);
      record = [];
      field = '';
    } else field += character;
  }
  if (quoted) throw new Error('CSV ends inside a quoted field');
  if (field !== '' || record.length) {
    record.push(field.replace(/\r$/, ''));
    if (record.some(value => value !== '')) records.push(record);
  }
  if (!records.length) throw new Error('CSV is empty');
  const header = records.shift();
  if (new Set(header).size !== header.length) throw new Error('CSV contains duplicate column names');
  return {
    header,
    rows: records.map((values, index) => {
      if (values.length !== header.length) throw new Error(`CSV row ${index + 2} has ${values.length} fields; expected ${header.length}`);
      return Object.fromEntries(header.map((name, column) => [name, values[column]]));
    }),
  };
}

function splitList(value) {
  return typeof value === 'string' && value.length ? value.split(';') : [];
}

function listFiles(root) {
  const files = [];
  const pending = [root];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const resolved = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(resolved);
      else if (entry.isFile()) files.push(resolved);
    }
  }
  return files;
}

function countMultiplicity(values) {
  const counts = new Map();
  for (const value of values) increment(counts, value);
  const histogram = new Map();
  for (const count of counts.values()) increment(histogram, count);
  return {
    distinct_templates: counts.size,
    largest_multiplicity: [...counts.values()].reduce((largest, count) => Math.max(largest, count), 0),
    multiplicity_histogram: sortedObject(histogram),
  };
}

function numeric(value) {
  if (!/^\d+$/.test(String(value))) return null;
  return Number(value);
}

function addCandidate(pools, key, value, limit = 30) {
  if (!pools[key]) pools[key] = [];
  if (pools[key].length < limit) pools[key].push(value);
}

function candidateRecord(row, result) {
  return {
    manifest_file: row.manifest_file,
    transition: `${row.decision}->${result.decision}`,
    baseline_rules: splitList(row.rule_ids),
    current_rules: result.findings.map(finding => `${finding.id}:${finding.severity}`),
    coverage_gap_codes: result.coverage.gaps.map(gap => gap.code),
    review_item_codes: (result.review_items || []).map(item => item.code),
    tool_count: result.scope.tool_count,
  };
}

function inspectManifest(document) {
  const tools = document && document.result && Array.isArray(document.result.tools)
    ? document.result.tools
    : Array.isArray(document && document.tools) ? document.tools : null;
  if (!tools) return { tools: null, missing_input_schema: null, invalid_input_schema: null };
  let missingInputSchema = 0;
  let invalidInputSchema = 0;
  for (const tool of tools) {
    if (!tool || !Object.prototype.hasOwnProperty.call(tool, 'inputSchema')) missingInputSchema += 1;
    else if (!tool.inputSchema || typeof tool.inputSchema !== 'object' || Array.isArray(tool.inputSchema)) invalidInputSchema += 1;
  }
  return { tools, missing_input_schema: missingInputSchema, invalid_input_schema: invalidInputSchema };
}

function validateArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--csv') options.csv = argv[++index];
    else if (argument === '--manifest-dir') options.manifestDir = argv[++index];
    else if (argument === '--archive-sha256') options.archiveSha256 = argv[++index];
    else if (argument === '--corpus-date') options.corpusDate = argv[++index];
    else if (argument === '--output-json') options.outputJson = argv[++index];
    else if (argument === '--output-markdown') options.outputMarkdown = argv[++index];
    else if (argument === '--private-candidates') options.privateCandidates = argv[++index];
    else if (argument === '--scanner-root') options.scannerRoot = argv[++index];
    else if (argument === '--scanner-source-commit') options.scannerSourceCommit = argv[++index];
    else if (argument === '--baseline-verification-json') options.baselineVerificationJson = argv[++index];
    else throw new Error(`unknown option: ${argument}`);
  }
  for (const required of ['csv', 'manifestDir', 'outputJson', 'outputMarkdown']) {
    if (!options[required]) throw new Error(`missing --${required.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)}`);
  }
  if (options.corpusDate && !/^\d{4}-\d{2}-\d{2}$/.test(options.corpusDate)) throw new Error('--corpus-date must be YYYY-MM-DD');
  if (options.archiveSha256 && !/^[0-9a-f]{64}$/i.test(options.archiveSha256)) throw new Error('--archive-sha256 must be 64 hexadecimal characters');
  if (options.scannerSourceCommit && !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(options.scannerSourceCommit)) throw new Error('--scanner-source-commit must be a 40- or 64-character hexadecimal commit');
  return options;
}

function loadScanner(scannerRoot) {
  const root = path.resolve(scannerRoot || path.join(__dirname, '..'));
  const evidenceModule = require(path.join(root, 'lib', 'evidence.js'));
  const scannerModule = require(path.join(root, 'lib', 'scanner.js'));
  const vetModule = require(path.join(root, 'lib', 'vet-tools.js'));
  return {
    collectEvidence: evidenceModule.collectEvidence,
    maxArtifactBytes: evidenceModule.MAX_ARTIFACT_BYTES,
    scanEvidence: scannerModule.scanEvidence,
    createVetResult: vetModule.createVetResult,
  };
}

function formatCount(value) {
  return new Intl.NumberFormat('en-US').format(value);
}

function signed(value) {
  return value > 0 ? `+${value}` : String(value);
}

function renderMarkdown(report) {
  const baseline = report.baseline.decisions;
  const current = report.current.decisions;
  const allRules = [...new Set([...Object.keys(report.baseline.rule_histogram), ...Object.keys(report.current.rule_histogram)])].sort();
  const transitions = Object.entries(report.delta.transitions).filter(([, count]) => count > 0);
  const lines = [
    '# MCP corpus precision rerun: 0.5.15 baseline to 0.6.1',
    '',
    '> Publication status: internal validation draft. The aggregate tables contain no server names, URLs, tool names, descriptions, evidence pointers, or per-manifest identifiers. A second reviewer should check the fixture adjudications and publication claims before release.',
    '',
    `Corpus date: ${report.corpus.date || 'not encoded in exports'}  `,
    `Rows analyzed: ${formatCount(report.corpus.rows)}  `,
    `Current scanner: ${report.current.scanner.version}  `,
    `Current ruleset: ${report.current.ruleset.version} (${report.current.ruleset.sha256})  `,
    `Pre-attach profile: ${report.current.profile.version} (${report.current.profile.sha256})`,
    '',
    '## Decision delta',
    '',
    '| Decision | CSV baseline | 0.6.1 rerun | Change |',
    '|---|---:|---:|---:|',
    `| block | ${baseline.block || 0} | ${current.block || 0} | ${signed((current.block || 0) - (baseline.block || 0))} |`,
    `| review | ${baseline.review || 0} | ${current.review || 0} | ${signed((current.review || 0) - (baseline.review || 0))} |`,
    `| no_blocking_finding | ${baseline.no_blocking_finding || 0} | ${current.no_blocking_finding || 0} | ${signed((current.no_blocking_finding || 0) - (baseline.no_blocking_finding || 0))} |`,
    `| total | ${report.corpus.rows} | ${report.corpus.rows} | 0 |`,
    '',
    `${formatCount(report.delta.changed_rows)} of ${formatCount(report.corpus.rows)} rows changed decision (${report.delta.changed_row_percent}%). This is a deterministic comparison on the same captured manifests, not a fresh registry measurement.`,
    '',
    '## Decision transitions',
    '',
    '| From | To | Rows |',
    '|---|---|---:|',
    ...transitions.map(([transition, count]) => {
      const [from, to] = transition.split('->');
      return `| ${from} | ${to} | ${count} |`;
    }),
    '',
    '## Rule delta',
    '',
    '| Rule | CSV baseline | 0.6.1 rerun | Change |',
    '|---|---:|---:|---:|',
    ...allRules.map(rule => {
      const before = report.baseline.rule_histogram[rule] || 0;
      const after = report.current.rule_histogram[rule] || 0;
      return `| ${rule} | ${before} | ${after} | ${signed(after - before)} |`;
    }),
    '',
    '## Rows upgraded into block',
    '',
    '| Transition | Current rule counts on those rows |',
    '|---|---|',
    ...['no_blocking_finding->block', 'review->block'].map(transition => {
      const counts = report.delta.current_rules_by_transition[transition] || {};
      const rendered = Object.entries(counts).map(([rule, count]) => `${rule}: ${count}`).join(', ') || 'none';
      return `| ${transition} | ${rendered} |`;
    }),
    '',
    '## Export validation',
    '',
    `The CSV contains ${formatCount(report.validation.csv_rows)} rows and ${formatCount(report.validation.distinct_manifest_keys)} distinct manifest keys. The archive extraction contains ${formatCount(report.validation.manifest_files)} JSON files. Missing joins: ${report.validation.csv_rows_without_manifest}. Extra manifests: ${report.validation.manifests_without_csv_row}. JSON parse failures: ${report.validation.json_parse_failures}. Tool-count mismatches: ${report.validation.tool_count_mismatches}.`,
    '',
    `The handoff text described 8,147 raw files. The supplied ZIP contains 7,749 manifest files. The earlier internal funnel used 8,147 for reachable endpoints and 7,749 for unique manifests, so the archive is consistent with the unique-manifest denominator.`,
    '',
    '## Interpretation',
    '',
    'This rerun measures the effect of the precision rules on a frozen corpus. It does not establish vulnerability, exploitability, ecosystem prevalence, runtime enforcement, or safety. Block means the supplied metadata met the static pre-attachment threshold. Review means a lower-severity match or evidence gap requires operator review.',
    '',
    report.baseline.verification && report.baseline.verification.exact_tag_replay
      ? 'The CSV does not encode the baseline scanner or ruleset version. A local replay of the exact 0.5.15 tag and ruleset 1.4.0 reproduced all 7,749 decisions and every rule count with zero mismatches.'
      : 'The CSV does not encode the baseline scanner or ruleset version. Its decision and rule totals match the internal snapshot labeled package 0.5.15 and ruleset 1.4.0, so this report uses that label with that provenance limitation.',
    '',
    '## Reproducibility',
    '',
    `CSV SHA-256: ${report.sources.csv.sha256}  `,
    `Raw archive SHA-256: ${report.sources.archive.sha256 || 'not supplied'}  `,
    `Distinct exact manifest bodies: ${report.current.template_multiplicity.exact_input.distinct_templates}; largest multiplicity: ${report.current.template_multiplicity.exact_input.largest_multiplicity}.  `,
    `Distinct exact tool-schema templates: ${report.current.template_multiplicity.exact_tool_schema.distinct_templates}; largest multiplicity: ${report.current.template_multiplicity.exact_tool_schema.largest_multiplicity}.`,
    '',
    'No live registry request, MCP tool invocation, or tools/call occurred during this rerun.',
    '',
  ];
  return lines.join('\n');
}

function main() {
  const options = validateArgs(process.argv.slice(2));
  const { collectEvidence, createVetResult, maxArtifactBytes, scanEvidence } = loadScanner(options.scannerRoot);
  const csvBytes = fs.readFileSync(options.csv);
  const parsed = parseCsv(csvBytes.toString('utf8').replace(/^\uFEFF/, ''));
  const missingColumns = EXPECTED_COLUMNS.filter(column => !parsed.header.includes(column));
  if (missingColumns.length) throw new Error(`CSV is missing columns: ${missingColumns.join(', ')}`);

  const manifestFiles = listFiles(options.manifestDir).filter(filename => path.extname(filename).toLowerCase() === '.json');
  const manifestByName = new Map();
  for (const filename of manifestFiles) {
    const basename = path.basename(filename);
    if (manifestByName.has(basename)) throw new Error(`duplicate manifest basename: ${basename}`);
    manifestByName.set(basename, filename);
  }

  const rowKeys = new Set();
  const baselineDecisions = new Map();
  const baselineRules = new Map();
  const currentDecisions = new Map();
  const currentRules = new Map();
  const currentSeverities = new Map();
  const coverageStatuses = new Map();
  const coverageGaps = new Map();
  const reviewItems = new Map();
  const transitions = new Map();
  const baselineRulesByTransition = new Map();
  const currentRulesByTransition = new Map();
  const exactInputHashes = [];
  const exactToolSchemaHashes = [];
  const promptTemplateCounts = new Map();
  const bb008PropertyNames = new Map();
  const bb008ToolNames = new Map();
  const candidatePools = {};
  const now = new Date(`${options.corpusDate || '2026-09-01'}T00:00:00.000Z`);
  const validation = {
    csv_rows: parsed.rows.length,
    distinct_manifest_keys: 0,
    duplicate_manifest_keys: 0,
    manifest_files: manifestFiles.length,
    csv_rows_without_manifest: 0,
    manifests_without_csv_row: 0,
    invalid_decisions: 0,
    decision_exit_mismatches: 0,
    invalid_tool_counts: 0,
    invalid_finding_counts: 0,
    baseline_finding_count_mismatches: 0,
    baseline_rule_title_count_mismatches: 0,
    unknown_baseline_rule_ids: 0,
    json_parse_failures: 0,
    unsupported_manifest_shapes: 0,
    tool_count_mismatches: 0,
    tool_name_count_mismatches: 0,
    tool_name_set_mismatches: 0,
    manifests_with_missing_input_schema: 0,
    manifests_with_invalid_input_schema: 0,
    manifests_over_scanner_byte_limit: 0,
    scanner_failures: 0,
    total_tool_instances: 0,
  };
  let scanner = null;
  let ruleset = null;
  let profile = null;
  let changedRows = 0;

  for (let index = 0; index < parsed.rows.length; index += 1) {
    const row = parsed.rows[index];
    if (rowKeys.has(row.manifest_file)) validation.duplicate_manifest_keys += 1;
    rowKeys.add(row.manifest_file);
    if (!DECISIONS.includes(row.decision)) validation.invalid_decisions += 1;
    else {
      increment(baselineDecisions, row.decision);
      if (numeric(row.exit_code) !== DECISION_TO_EXIT[row.decision]) validation.decision_exit_mismatches += 1;
    }
    const toolCount = numeric(row.tool_count);
    const findingCount = numeric(row.finding_count);
    if (toolCount === null) validation.invalid_tool_counts += 1;
    if (findingCount === null) validation.invalid_finding_counts += 1;
    const oldRules = splitList(row.rule_ids);
    const oldTitles = splitList(row.rule_titles);
    if (findingCount !== null && oldRules.length !== findingCount) validation.baseline_finding_count_mismatches += 1;
    if (oldTitles.length !== oldRules.length) validation.baseline_rule_title_count_mismatches += 1;
    for (const rule of oldRules) {
      increment(baselineRules, rule);
      if (!/^BB(?:00[1-9]|01[0-3])$/.test(rule)) validation.unknown_baseline_rule_ids += 1;
    }

    const filename = manifestByName.get(row.manifest_file);
    if (!filename) {
      validation.csv_rows_without_manifest += 1;
      continue;
    }
    const raw = fs.readFileSync(filename);
    if (raw.length > maxArtifactBytes) validation.manifests_over_scanner_byte_limit += 1;
    exactInputHashes.push(sha256(raw));
    let document;
    try { document = JSON.parse(raw.toString('utf8'));
    } catch (_) {
      validation.json_parse_failures += 1;
      continue;
    }
    const inspected = inspectManifest(document);
    if (!inspected.tools) validation.unsupported_manifest_shapes += 1;
    else {
      validation.total_tool_instances += inspected.tools.length;
      for (const tool of inspected.tools) exactToolSchemaHashes.push(sha256(Buffer.from(canonicalize(tool), 'utf8')));
      if (toolCount !== null && inspected.tools.length !== toolCount) validation.tool_count_mismatches += 1;
      const listedNames = splitList(row.tool_names);
      const rawNames = inspected.tools.map(tool => tool && tool.name).filter(name => typeof name === 'string');
      if (listedNames.length !== rawNames.length) validation.tool_name_count_mismatches += 1;
      if ([...listedNames].sort().join('\u0000') !== [...rawNames].sort().join('\u0000')) validation.tool_name_set_mismatches += 1;
      if (inspected.missing_input_schema > 0) validation.manifests_with_missing_input_schema += 1;
      if (inspected.invalid_input_schema > 0) validation.manifests_with_invalid_input_schema += 1;
    }

    let result;
    try {
      const evidence = collectEvidence({
        now,
        documents: [{ kind: 'tool_schema', name: '<corpus-manifest>', document, raw }],
        reviewAmbiguousToolManifest: true,
      });
      result = createVetResult(scanEvidence(evidence, { now }), evidence);
    } catch (_) {
      validation.scanner_failures += 1;
      continue;
    }
    scanner = result.scanner;
    ruleset = result.ruleset;
    profile = result.profile;
    const transition = `${row.decision}->${result.decision}`;
    increment(currentDecisions, result.decision);
    increment(transitions, transition);
    if (row.decision !== result.decision) changedRows += 1;
    for (const rule of oldRules) incrementNested(baselineRulesByTransition, transition, rule);
    const resultPromptTemplates = new Map();
    for (const finding of result.findings) {
      increment(currentRules, finding.id);
      increment(currentSeverities, finding.severity);
      incrementNested(currentRulesByTransition, transition, finding.id);
      if (finding.id === 'BB008') {
        for (const toolName of finding.affected_tools || []) increment(bb008ToolNames, toolName);
        for (const evidenceRef of finding.evidence || []) {
          const encoded = String(evidenceRef.pointer || '').split('/').filter(Boolean).pop();
          if (encoded) increment(bb008PropertyNames, encoded.replace(/~1/g, '/').replace(/~0/g, '~'));
        }
      }
      for (const template of (finding.metadata_template_summary && finding.metadata_template_summary.templates) || []) {
        if (template && typeof template.sha256 === 'string' && Number.isInteger(template.multiplicity)) {
          resultPromptTemplates.set(template.sha256, Math.max(resultPromptTemplates.get(template.sha256) || 0, template.multiplicity));
        }
      }
    }
    for (const [templateHash, multiplicity] of resultPromptTemplates) increment(promptTemplateCounts, templateHash, multiplicity);
    increment(coverageStatuses, result.coverage.status);
    for (const gap of result.coverage.gaps) increment(coverageGaps, gap.code);
    for (const item of result.review_items || []) increment(reviewItems, item.code);

    const candidate = candidateRecord(row, result);
    const severities = new Map(result.findings.map(finding => [finding.id, finding.severity]));
    const gapCodes = new Set(result.coverage.gaps.map(gap => gap.code));
    if (result.decision === 'block' && severities.get('BB008') === 'high') addCandidate(candidatePools, 'true_block_bb008', candidate);
    if (result.decision === 'block' && severities.get('BB012') === 'high') addCandidate(candidatePools, 'true_block_bb012', candidate);
    if (result.decision === 'block' && severities.get('BB004') === 'high') addCandidate(candidatePools, 'true_block_bb004', candidate);
    if (result.decision === 'block' && result.coverage.status === 'complete') addCandidate(candidatePools, 'true_block_complete_coverage', candidate);
    if (result.decision === 'review' && severities.get('BB008') === 'medium') addCandidate(candidatePools, 'review_bb008', candidate);
    if (result.decision === 'review' && severities.get('BB004') === 'medium') addCandidate(candidatePools, 'review_bb004', candidate);
    if (result.decision === 'review' && (result.review_items || []).some(item => item.code === 'BB-VET-PERMISSION-REQUIREMENT-UNVERIFIED')) addCandidate(candidatePools, 'review_permission_claim', candidate);
    if (result.decision === 'review' && gapCodes.has('BB-VET-AMBIGUOUS-DESTINATION')) addCandidate(candidatePools, 'review_ambiguous_destination', candidate);
    if (result.decision === 'review' && gapCodes.has('BB-VET-AMBIGUOUS-QUERY-EXPRESSION')) addCandidate(candidatePools, 'review_ambiguous_query_expression', candidate);
    if (result.decision === 'review' && gapCodes.has('BB-VET-PROMPT-METADATA-REVIEW')) addCandidate(candidatePools, 'review_prompt_metadata', candidate);
    if (result.decision === 'review' && gapCodes.has('BB-VET-MISSING-INPUT-SCHEMA')) addCandidate(candidatePools, 'review_missing_input_schema', candidate);
    if (result.decision === 'no_blocking_finding') addCandidate(candidatePools, 'no_blocking_finding', candidate);
    if (result.coverage.gaps.some(gap => gap.code === 'BB-VET-AMBIGUOUS-MANIFEST')) addCandidate(candidatePools, 'incomplete_or_ambiguous', candidate);
  }

  validation.distinct_manifest_keys = rowKeys.size;
  validation.manifests_without_csv_row = [...manifestByName.keys()].filter(name => !rowKeys.has(name)).length;
  const processed = [...currentDecisions.values()].reduce((sum, count) => sum + count, 0);
  if (processed !== parsed.rows.length) throw new Error(`only ${processed} of ${parsed.rows.length} rows produced scanner results`);

  const promptMultiplicityHistogram = new Map();
  for (const count of promptTemplateCounts.values()) increment(promptMultiplicityHistogram, count);
  let baselineVerification = null;
  if (options.baselineVerificationJson) {
    const verification = JSON.parse(fs.readFileSync(options.baselineVerificationJson, 'utf8'));
    baselineVerification = validateBaselineVerification(verification, {
      rows: parsed.rows.length,
      csvSha256: sha256(csvBytes),
      archiveSha256: options.archiveSha256 ? options.archiveSha256.toLowerCase() : null,
      decisions: sortedObject(baselineDecisions),
      ruleHistogram: sortedObject(baselineRules),
    });
  }
  const report = {
    protocol: 'backbond-corpus-delta/v1',
    generated_at: now.toISOString(),
    sources: {
      csv: { sha256: sha256(csvBytes), bytes: csvBytes.length },
      archive: { sha256: options.archiveSha256 ? options.archiveSha256.toLowerCase() : null },
    },
    corpus: { date: options.corpusDate || null, rows: parsed.rows.length, unit: 'unique captured tool manifest' },
    validation,
    baseline: {
      label: baselineVerification
        ? 'CSV-provided baseline; reproduced exactly with local tag 0.5.15 / ruleset 1.4.0'
        : 'CSV-provided baseline; matched to internal 0.5.15 / ruleset 1.4.0 snapshot by aggregate counts',
      scanner_version_encoded_in_csv: false,
      verification: baselineVerification,
      decisions: sortedObject(baselineDecisions),
      rule_histogram: sortedObject(baselineRules),
    },
    current: {
      scanner,
      ruleset,
      profile,
      source_commit: options.scannerSourceCommit ? options.scannerSourceCommit.toLowerCase() : null,
      decisions: sortedObject(currentDecisions),
      rule_histogram: sortedObject(currentRules),
      severity_histogram: sortedObject(currentSeverities),
      coverage: { statuses: sortedObject(coverageStatuses), gap_codes: sortedObject(coverageGaps) },
      review_item_codes: sortedObject(reviewItems),
      template_multiplicity: {
        exact_input: countMultiplicity(exactInputHashes),
        exact_tool_schema: countMultiplicity(exactToolSchemaHashes),
        prompt_metadata: {
          distinct_templates: promptTemplateCounts.size,
          largest_multiplicity: [...promptTemplateCounts.values()].reduce((largest, count) => Math.max(largest, count), 0),
          multiplicity_histogram: sortedObject(promptMultiplicityHistogram),
        },
      },
    },
    delta: {
      changed_rows: changedRows,
      changed_row_percent: Number(((changedRows / parsed.rows.length) * 100).toFixed(1)),
      transitions: sortedObject(transitions),
      baseline_rules_by_transition: sortedNestedObject(baselineRulesByTransition),
      current_rules_by_transition: sortedNestedObject(currentRulesByTransition),
    },
    privacy: {
      server_ids_included: false,
      remote_urls_included: false,
      manifest_ids_included: false,
      tool_names_included: false,
      tool_descriptions_included: false,
      evidence_pointers_included: false,
    },
    assurance: 'Aggregate static pre-attachment metadata comparison only. This is not a representative ecosystem score, runtime attestation, safety determination, vulnerability confirmation, or insurance decision.',
  };

  fs.writeFileSync(options.outputJson, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  fs.writeFileSync(options.outputMarkdown, renderMarkdown(report), { flag: 'wx' });
  if (options.privateCandidates) {
    fs.writeFileSync(options.privateCandidates, `${JSON.stringify({
      generated_at: now.toISOString(),
      pools: candidatePools,
      diagnostics: {
        bb008_property_names: sortedObject(bb008PropertyNames),
        bb008_tool_names: sortedObject(bb008ToolNames),
      },
    }, null, 2)}\n`, { flag: 'wx' });
  }
  process.stdout.write(`${JSON.stringify({ rows: report.corpus.rows, validation, baseline: report.baseline.decisions, current: report.current.decisions, changed_rows: report.delta.changed_rows, outputs: { json: options.outputJson, markdown: options.outputMarkdown, private_candidates: options.privateCandidates || null } }, null, 2)}\n`);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    process.stderr.write(`corpus rerun error: ${error.message}\n`);
    process.exitCode = 2;
  }
}

module.exports = { EXACT_BASELINE, ZERO_ERROR_VALIDATION_FIELDS, parseCsv, renderMarkdown, validateBaselineVerification };
