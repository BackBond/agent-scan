#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const FULL_PROTOCOL = 'backbond-pre-attach/v1';
const SUMMARY_PROTOCOL = 'backbond-vet-summary/v1';
const DECISIONS = new Set(['block', 'review', 'no_blocking_finding']);
const COVERAGE_STATUSES = new Set(['complete', 'partial']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

function increment(map, key, count = 1) {
  if (!key) return;
  map.set(String(key), (map.get(String(key)) || 0) + count);
}

function sortedObject(map) {
  return Object.fromEntries([...map.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function multiplicitySummary(counts, unavailableRows = 0) {
  const values = [...counts.values()];
  const histogram = new Map();
  for (const value of values) increment(histogram, value);
  return {
    distinct_templates: values.length,
    largest_multiplicity: values.reduce((largest, value) => Math.max(largest, value), 0),
    multiplicity_histogram: sortedObject(histogram),
    unavailable_rows: unavailableRows,
  };
}

function addObjectCounts(map, value, label) {
  for (const [key, count] of Object.entries(value || {})) {
    if (!Number.isInteger(count) || count < 0) throw new Error(`${label}.${key} must be a non-negative integer`);
    if (count > 0) increment(map, key, count);
  }
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(value, label) {
  if (!isObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function requireString(value, label) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function countTotal(value, label) {
  const counts = requireObject(value, label);
  let total = 0;
  for (const [key, count] of Object.entries(counts)) {
    if (!Number.isInteger(count) || count < 0) throw new Error(`${label}.${key} must be a non-negative integer`);
    total += count;
  }
  return total;
}

function findingClassTotal(value, label) {
  const classes = requireObject(value, label);
  let total = 0;
  for (const [findingClass, details] of Object.entries(classes)) {
    if (!isObject(details) || !Number.isInteger(details.count) || details.count < 0) {
      throw new Error(`${label}.${findingClass}.count must be a non-negative integer`);
    }
    total += details.count;
  }
  return total;
}

function validateCommonRow(row, index) {
  const label = `row ${index + 1}`;
  if (!isObject(row)) throw new Error(`${label} must be a JSON object`);
  if (![FULL_PROTOCOL, SUMMARY_PROTOCOL].includes(row.protocol)) throw new Error(`${label}.protocol is unsupported`);
  if (!DECISIONS.has(row.decision)) throw new Error(`${label}.decision is invalid`);
  requireString(row.scanner && row.scanner.version, `${label}.scanner.version`);
  requireString(row.ruleset && row.ruleset.version, `${label}.ruleset.version`);
  const coverage = requireObject(row.coverage, `${label}.coverage`);
  if (!COVERAGE_STATUSES.has(coverage.status)) throw new Error(`${label}.coverage.status is invalid`);
  requireArray(row.review_items, `${label}.review_items`);
  const summary = requireObject(row.summary, `${label}.summary`);
  if (!Number.isInteger(summary.total) || summary.total < 0) throw new Error(`${label}.summary.total must be a non-negative integer`);
  if (countTotal(summary.by_severity, `${label}.summary.by_severity`) !== summary.total) {
    throw new Error(`${label}.summary.by_severity does not equal summary.total`);
  }
  return { label, coverage, summary };
}

function validateFullRow(row, index) {
  const { label, coverage, summary } = validateCommonRow(row, index);
  const findings = requireArray(row.findings, `${label}.findings`);
  requireArray(coverage.gaps, `${label}.coverage.gaps`);
  if (findings.length !== summary.total) throw new Error(`${label}.findings length does not equal summary.total`);
  findings.forEach((finding, findingIndex) => {
    const findingLabel = `${label}.findings[${findingIndex}]`;
    requireObject(finding, findingLabel);
    if (!/^BB(?:00[1-9]|01[0-3])$/.test(finding.id)) throw new Error(`${findingLabel}.id is invalid`);
    if (!SEVERITIES.has(finding.severity)) throw new Error(`${findingLabel}.severity is invalid`);
    requireString(finding.finding_class, `${findingLabel}.finding_class`);
  });
  if (findingClassTotal(row.finding_classes, `${label}.finding_classes`) !== summary.total) {
    throw new Error(`${label}.finding_classes does not equal summary.total`);
  }
}

function validateSummaryRow(row, index) {
  const { label, coverage, summary } = validateCommonRow(row, index);
  const ruleTotal = countTotal(row.rule_histogram, `${label}.rule_histogram`);
  if (ruleTotal !== summary.total) throw new Error(`${label}.rule_histogram does not equal summary.total`);
  if (findingClassTotal(row.finding_classes, `${label}.finding_classes`) !== summary.total) {
    throw new Error(`${label}.finding_classes does not equal summary.total`);
  }
  countTotal(coverage.gap_codes, `${label}.coverage.gap_codes`);
  const templates = requireObject(row.template_multiplicity, `${label}.template_multiplicity`);
  const prompt = requireObject(templates.prompt_metadata, `${label}.template_multiplicity.prompt_metadata`);
  if (!Number.isInteger(prompt.distinct_templates) || prompt.distinct_templates < 0
    || !Number.isInteger(prompt.largest_multiplicity) || prompt.largest_multiplicity < 0) {
    throw new Error(`${label}.template_multiplicity.prompt_metadata is invalid`);
  }
  countTotal(prompt.multiplicity_histogram, `${label}.template_multiplicity.prompt_metadata.multiplicity_histogram`);
}

function inputFingerprint(row) {
  const candidates = [
    row.input_sha256,
    row.manifest_sha256,
    row.research && row.research.input_fingerprint_sha256,
    row.artifact && row.artifact.sha256,
  ];
  return candidates.find(value => typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)) || null;
}

function summarizeRows(rows, options = {}) {
  if (!Array.isArray(rows) || rows.length === 0) throw new Error('input must contain at least one result row');
  rows.forEach((row, index) => {
    if (!isObject(row)) throw new Error(`row ${index + 1} must be a JSON object`);
    if (![FULL_PROTOCOL, SUMMARY_PROTOCOL].includes(row.protocol)) throw new Error(`row ${index + 1}.protocol is unsupported`);
  });
  const sourceModes = new Set(rows.map(row => row.protocol === SUMMARY_PROTOCOL ? 'summary_only' : 'full_local_results'));
  if (sourceModes.size > 1) throw new Error('do not mix summary-only rows with full local result rows');
  const sourceMode = [...sourceModes][0] || 'full_local_results';
  const decisions = new Map();
  const rules = new Map();
  const findingClasses = new Map();
  const coverageStatuses = new Map();
  const coverageGaps = new Map();
  const scannerVersions = new Map();
  const rulesetVersions = new Map();
  const inputTemplates = new Map();
  const metadataTemplates = new Map();
  const summaryPromptHistogram = new Map();
  const reviewItemCodes = new Map();
  let unavailableInputFingerprints = 0;
  let summaryPromptDistinct = 0;
  let summaryPromptLargest = 0;

  rows.forEach((row, index) => {
    if (sourceMode === 'summary_only') validateSummaryRow(row, index);
    else validateFullRow(row, index);
    increment(decisions, row.decision);
    increment(scannerVersions, row.scanner && row.scanner.version);
    increment(rulesetVersions, row.ruleset && row.ruleset.version);
    const fingerprint = inputFingerprint(row);
    if (fingerprint) increment(inputTemplates, fingerprint);
    else unavailableInputFingerprints += 1;
    if (sourceMode === 'summary_only') {
      addObjectCounts(rules, row.rule_histogram, `row ${index + 1}.rule_histogram`);
      for (const [findingClass, value] of Object.entries(row.finding_classes)) {
        if (value.count > 0) increment(findingClasses, findingClass, value.count);
      }
      const prompt = row.template_multiplicity && row.template_multiplicity.prompt_metadata;
      summaryPromptDistinct += prompt.distinct_templates;
      summaryPromptLargest = Math.max(summaryPromptLargest, prompt.largest_multiplicity);
      addObjectCounts(summaryPromptHistogram, prompt.multiplicity_histogram, `row ${index + 1}.template_multiplicity.prompt_metadata.multiplicity_histogram`);
    } else {
      const rowMetadataTemplates = new Map();
      for (const finding of row.findings) {
        increment(rules, finding && finding.id);
        increment(findingClasses, finding && finding.finding_class);
        const templates = finding && finding.metadata_template_summary && finding.metadata_template_summary.templates;
        for (const template of Array.isArray(templates) ? templates : []) {
          if (template && typeof template.sha256 === 'string' && Number.isInteger(template.multiplicity) && template.multiplicity > 0) {
            rowMetadataTemplates.set(template.sha256, Math.max(rowMetadataTemplates.get(template.sha256) || 0, template.multiplicity));
          }
        }
      }
      for (const [templateHash, multiplicity] of rowMetadataTemplates) increment(metadataTemplates, templateHash, multiplicity);
    }
    const coverage = row.coverage;
    increment(coverageStatuses, coverage.status);
    if (sourceMode === 'summary_only') addObjectCounts(coverageGaps, coverage.gap_codes, `row ${index + 1}.coverage.gap_codes`);
    else for (const gap of coverage.gaps) increment(coverageGaps, gap && gap.code);
    for (const item of row.review_items) increment(reviewItemCodes, item && item.code);
  });

  const promptMultiplicity = sourceMode === 'summary_only'
    ? {
      distinct_templates: summaryPromptDistinct,
      largest_multiplicity: summaryPromptLargest,
      multiplicity_histogram: sortedObject(summaryPromptHistogram),
      unavailable_rows: 0,
      interpretation: 'Within-manifest template instances. Repeated templates across rows cannot be deduplicated because summary-only output omits template identifiers.',
    }
    : { ...multiplicitySummary(metadataTemplates), interpretation: 'Templates deduplicated across rows from full local result identifiers.' };

  return {
    protocol: 'backbond-corpus-summary/v1',
    corpus_date: options.corpusDate || null,
    source_mode: sourceMode,
    rows: rows.length,
    decisions: sortedObject(decisions),
    rules: sortedObject(rules),
    finding_classes: sortedObject(findingClasses),
    coverage: {
      statuses: sortedObject(coverageStatuses),
      gap_codes: sortedObject(coverageGaps),
    },
    review_item_codes: sortedObject(reviewItemCodes),
    versions: {
      scanner: sortedObject(scannerVersions),
      ruleset: sortedObject(rulesetVersions),
    },
    template_multiplicity: {
      exact_input: multiplicitySummary(inputTemplates, unavailableInputFingerprints),
      prompt_metadata: promptMultiplicity,
    },
    privacy: {
      server_ids_included: false,
      tool_names_included: false,
      template_hashes_included: false,
    },
    assurance: 'Aggregate static pre-attachment metadata results only. Summary-only rows cannot support cross-row template deduplication. This is not a representative ecosystem score, runtime attestation, safety determination, or insurance decision.',
  };
}

function formatCounts(value) {
  const entries = Object.entries(value);
  return entries.length ? entries.map(([key, count]) => `${key}: ${count}`).join(', ') : 'none';
}

function renderMarkdown(summary) {
  const corpusDate = summary.corpus_date || 'not supplied';
  const lines = [
    '# MCP tool-manifest corpus summary',
    '',
    `Corpus date: ${corpusDate}  `,
    `Source mode: ${summary.source_mode}  `,
    `Scanner versions: ${formatCounts(summary.versions.scanner)}  `,
    `Ruleset versions: ${formatCounts(summary.versions.ruleset)}`,
    '',
    `The local dataset contains ${summary.rows} static pre-attachment results. Decisions: ${formatCounts(summary.decisions)}.`,
    '',
    '## Rule histogram',
    '',
    formatCounts(summary.rules),
    '',
    '## Coverage',
    '',
    `Statuses: ${formatCounts(summary.coverage.statuses)}. Coverage-gap codes: ${formatCounts(summary.coverage.gap_codes)}.`,
    `Review-item codes: ${formatCounts(summary.review_item_codes)}.`,
    '',
    '## Template multiplicity',
    '',
    `Exact input templates: ${summary.template_multiplicity.exact_input.distinct_templates}; largest multiplicity: ${summary.template_multiplicity.exact_input.largest_multiplicity}; rows without a compatible fingerprint: ${summary.template_multiplicity.exact_input.unavailable_rows}.`,
    `Prompt-metadata templates: ${summary.template_multiplicity.prompt_metadata.distinct_templates}; largest multiplicity: ${summary.template_multiplicity.prompt_metadata.largest_multiplicity}. ${summary.template_multiplicity.prompt_metadata.interpretation}`,
    '',
    summary.assurance,
    '',
  ];
  return lines.join('\n');
}

function parseArgs(argv) {
  const options = { format: 'json' };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--input') options.input = argv[++index];
    else if (argument === '--format') options.format = argv[++index];
    else if (argument === '--corpus-date') options.corpusDate = argv[++index];
    else throw new Error(`unknown option: ${argument}`);
  }
  if (!options.input) throw new Error('use --input <results.jsonl>');
  if (!['json', 'markdown'].includes(options.format)) throw new Error('--format must be json or markdown');
  if (options.corpusDate && !/^\d{4}-\d{2}-\d{2}$/.test(options.corpusDate)) throw new Error('--corpus-date must be YYYY-MM-DD');
  return options;
}

function readJsonLines(filename) {
  return fs.readFileSync(filename, 'utf8').split(/\r?\n/).filter(line => line.trim()).map((line, index) => {
    try { return JSON.parse(line); }
    catch (error) { throw new Error(`line ${index + 1} is not valid JSON: ${error.message}`); }
  });
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const summary = summarizeRows(readJsonLines(options.input), options);
  process.stdout.write(options.format === 'markdown' ? renderMarkdown(summary) : `${JSON.stringify(summary, null, 2)}\n`);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    process.stderr.write(`corpus summary error: ${error.message}\n`);
    process.exitCode = 2;
  }
}

module.exports = { renderMarkdown, summarizeRows };
