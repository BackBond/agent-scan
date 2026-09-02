'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { renderMarkdown, summarizeRows } = require('../scripts/summarize-corpus-results.js');
const {
  EXACT_BASELINE,
  ZERO_ERROR_VALIDATION_FIELDS,
  renderMarkdown: renderRerunMarkdown,
  validateBaselineVerification,
} = require('../scripts/rerun-enriched-corpus.js');

function severitySummary(high, medium = 0) {
  return { total: high + medium, by_severity: { critical: 0, high, medium, low: 0 } };
}

test('corpus summary emits aggregates and multiplicity without identities or hashes', () => {
  const repeatedHash = 'a'.repeat(64);
  const promptHash = 'b'.repeat(64);
  const rows = [
    {
      protocol: 'backbond-pre-attach/v1',
      server_id: 'PRIVATE_SERVER_ONE',
      input_sha256: repeatedHash,
      decision: 'block',
      scanner: { version: '0.6.2' },
      ruleset: { version: 'backbond-local-rules/2.0.1' },
      findings: [
        {
          id: 'BB013', severity: 'high', finding_class: 'prompt_injection_indicator', affected_tools: ['PRIVATE_TOOL_ONE'],
          metadata_template_summary: { templates: [{ sha256: promptHash, multiplicity: 2 }] },
        },
        {
          id: 'BB009', severity: 'high', finding_class: 'prompt_injection_indicator', affected_tools: ['PRIVATE_TOOL_ONE'],
          metadata_template_summary: { templates: [{ sha256: promptHash, multiplicity: 2 }] },
        },
      ],
      summary: severitySummary(2),
      finding_classes: { prompt_injection_indicator: { count: 2 } },
      coverage: { status: 'complete', gaps: [] },
      review_items: [],
    },
    {
      protocol: 'backbond-pre-attach/v1',
      server_id: 'PRIVATE_SERVER_TWO',
      manifest_sha256: repeatedHash,
      decision: 'review',
      scanner: { version: '0.6.2' },
      ruleset: { version: 'backbond-local-rules/2.0.1' },
      findings: [
        { id: 'BB004', severity: 'medium', finding_class: 'capability_exposure', affected_tools: ['PRIVATE_TOOL_TWO'] },
        {
          id: 'BB009', severity: 'high', finding_class: 'prompt_injection_indicator', affected_tools: ['PRIVATE_TOOL_TWO'],
          metadata_template_summary: { templates: [{ sha256: promptHash, multiplicity: 1 }] },
        },
      ],
      summary: severitySummary(1, 1),
      finding_classes: { capability_exposure: { count: 1 }, prompt_injection_indicator: { count: 1 } },
      coverage: { status: 'partial', gaps: [{ code: 'BB-VET-MISSING-INPUT-SCHEMA' }] },
      review_items: [{ code: 'BB-VET-MISSING-INPUT-SCHEMA' }],
    },
  ];
  const summary = summarizeRows(rows, { corpusDate: '2026-08-31' });
  assert.deepEqual(summary.decisions, { block: 1, review: 1 });
  assert.deepEqual(summary.rules, { BB004: 1, BB009: 2, BB013: 1 });
  assert.equal(summary.template_multiplicity.exact_input.distinct_templates, 1);
  assert.equal(summary.template_multiplicity.exact_input.largest_multiplicity, 2);
  assert.equal(summary.template_multiplicity.prompt_metadata.largest_multiplicity, 3);
  const serialized = JSON.stringify(summary);
  assert.doesNotMatch(serialized, /PRIVATE_|aaaaaaaa|bbbbbbbb/);
  assert.deepEqual(summary.privacy, {
    server_ids_included: false,
    tool_names_included: false,
    template_hashes_included: false,
  });
  const markdown = renderMarkdown(summary);
  assert.match(markdown, /Corpus date: 2026-08-31/);
  assert.match(markdown, /not a representative ecosystem score/i);
  assert.doesNotMatch(markdown, /PRIVATE_|aaaaaaaa|bbbbbbbb/);
});

test('corpus summary aggregates summary-only rows without recovering identities or cross-row template hashes', () => {
  const rows = [
    {
      protocol: 'backbond-vet-summary/v1',
      decision: 'review',
      scanner: { version: '0.6.2' },
      ruleset: { version: 'backbond-local-rules/2.0.1' },
      summary: severitySummary(0, 1),
      finding_classes: { capability_exposure: { count: 1 }, prompt_injection_indicator: { count: 0 } },
      rule_histogram: { BB004: 1 },
      coverage: { status: 'partial', gap_codes: { 'BB-VET-AMBIGUOUS-DESTINATION': 1 } },
      review_items: [{ code: 'BB004', reason: 'PRIVATE_REASON' }, { code: 'BB-VET-AMBIGUOUS-DESTINATION', reason: 'PRIVATE_REASON' }],
      template_multiplicity: { prompt_metadata: { distinct_templates: 0, largest_multiplicity: 0, multiplicity_histogram: {} } },
    },
    {
      protocol: 'backbond-vet-summary/v1',
      decision: 'block',
      scanner: { version: '0.6.2' },
      ruleset: { version: 'backbond-local-rules/2.0.1' },
      summary: severitySummary(1),
      finding_classes: { capability_exposure: { count: 0 }, prompt_injection_indicator: { count: 1 } },
      rule_histogram: { BB013: 1 },
      coverage: { status: 'complete', gap_codes: {} },
      review_items: [],
      template_multiplicity: { prompt_metadata: { distinct_templates: 1, largest_multiplicity: 2, multiplicity_histogram: { 2: 1 } } },
    },
  ];
  const summary = summarizeRows(rows, { corpusDate: '2026-09-01' });
  assert.equal(summary.source_mode, 'summary_only');
  assert.deepEqual(summary.rules, { BB004: 1, BB013: 1 });
  assert.deepEqual(summary.finding_classes, { capability_exposure: 1, prompt_injection_indicator: 1 });
  assert.deepEqual(summary.coverage.gap_codes, { 'BB-VET-AMBIGUOUS-DESTINATION': 1 });
  assert.deepEqual(summary.review_item_codes, { BB004: 1, 'BB-VET-AMBIGUOUS-DESTINATION': 1 });
  assert.equal(summary.template_multiplicity.prompt_metadata.distinct_templates, 1);
  assert.match(summary.template_multiplicity.prompt_metadata.interpretation, /cannot be deduplicated/i);
  assert.doesNotMatch(JSON.stringify(summary), /PRIVATE/);
});

test('corpus summary rejects mixed full and summary-only rows', () => {
  assert.throws(() => summarizeRows([
    { protocol: 'backbond-pre-attach/v1', decision: 'review' },
    { protocol: 'backbond-vet-summary/v1', decision: 'review' },
  ]), /do not mix summary-only rows/i);
});

test('corpus summary rejects unknown protocols and truncated or inconsistent rows', () => {
  assert.throws(() => summarizeRows([]), /at least one result row/i);
  assert.throws(() => summarizeRows([{ protocol: 'backbond-vet-summry/v1' }]), /protocol is unsupported/i);
  assert.throws(() => summarizeRows([{
    protocol: 'backbond-vet-summary/v1',
    decision: 'review',
    scanner: { version: '0.6.2' },
    ruleset: { version: 'backbond-local-rules/2.0.1' },
    summary: severitySummary(0, 1),
    finding_classes: { capability_exposure: { count: 1 } },
    rule_histogram: { BB004: 1 },
    coverage: { status: 'partial', gap_codes: {} },
    review_items: [],
  }]), /template_multiplicity/i);
  assert.throws(() => summarizeRows([{
    protocol: 'backbond-vet-summary/v1',
    decision: 'review',
    scanner: { version: '0.6.2' },
    ruleset: { version: 'backbond-local-rules/2.0.1' },
    summary: severitySummary(0, 2),
    finding_classes: { capability_exposure: { count: 1 } },
    rule_histogram: { BB004: 1 },
    coverage: { status: 'partial', gap_codes: {} },
    review_items: [],
    template_multiplicity: { prompt_metadata: { distinct_templates: 0, largest_multiplicity: 0, multiplicity_histogram: {} } },
  }]), /rule_histogram does not equal summary.total/i);
});

function exactBaselineVerification() {
  const decisions = { block: 2, no_blocking_finding: 1, review: 1 };
  const ruleHistogram = { BB004: 2, BB008: 1 };
  return {
    expected: {
      rows: 4,
      csvSha256: 'a'.repeat(64),
      archiveSha256: 'b'.repeat(64),
      decisions,
      ruleHistogram,
    },
    verification: {
      protocol: 'backbond-corpus-delta/v1',
      sources: { csv: { sha256: 'a'.repeat(64) }, archive: { sha256: 'b'.repeat(64) } },
      corpus: { rows: 4 },
      validation: {
        csv_rows: 4,
        distinct_manifest_keys: 4,
        manifest_files: 4,
        ...Object.fromEntries(ZERO_ERROR_VALIDATION_FIELDS.map(field => [field, 0])),
      },
      baseline: { decisions, rule_histogram: ruleHistogram },
      current: {
        source_commit: EXACT_BASELINE.source_commit,
        scanner: { version: EXACT_BASELINE.scanner_version },
        ruleset: { version: EXACT_BASELINE.ruleset_version, sha256: EXACT_BASELINE.ruleset_sha256 },
        profile: { version: EXACT_BASELINE.profile_version, sha256: EXACT_BASELINE.profile_sha256 },
        decisions,
        rule_histogram: ruleHistogram,
      },
      delta: { changed_rows: 0 },
    },
  };
}

test('baseline verifier binds the replay to exact histograms, digests, commit, and clean validation', () => {
  const { verification, expected } = exactBaselineVerification();
  const result = validateBaselineVerification(verification, expected);
  assert.equal(result.exact_tag_replay, true);
  assert.equal(result.source_commit, EXACT_BASELINE.source_commit);

  for (const mutate of [
    value => { value.current.rule_histogram.BB004 += 1; },
    value => { value.current.ruleset.sha256 = 'c'.repeat(64); },
    value => { value.current.source_commit = 'd'.repeat(40); },
    value => { value.validation.tool_count_mismatches = 1; },
  ]) {
    const invalid = structuredClone(verification);
    mutate(invalid);
    assert.throws(() => validateBaselineVerification(invalid, expected), /does not prove an exact/i);
  }
});

test('corpus rerun markdown labels the current scanner version dynamically', () => {
  const markdown = renderRerunMarkdown({
    corpus: { date: '2026-08-31', rows: 1 },
    sources: { csv: { sha256: 'a'.repeat(64) }, archive: { sha256: 'b'.repeat(64) } },
    validation: { csv_rows: 1, distinct_manifest_keys: 1, manifest_files: 1, csv_rows_without_manifest: 0, manifests_without_csv_row: 0, json_parse_failures: 0, tool_count_mismatches: 0 },
    baseline: { decisions: { block: 1 }, rule_histogram: { BB001: 1 }, verification: { exact_tag_replay: true } },
    current: {
      scanner: { version: '9.8.7' },
      ruleset: { version: 'rules/1', sha256: 'c'.repeat(64) },
      profile: { version: 'profile/1', sha256: 'd'.repeat(64) },
      decisions: { review: 1 },
      rule_histogram: {},
      template_multiplicity: {
        exact_input: { distinct_templates: 1, largest_multiplicity: 1 },
        exact_tool_schema: { distinct_templates: 1, largest_multiplicity: 1 },
      },
    },
    delta: { changed_rows: 1, changed_row_percent: 100, transitions: { 'block->review': 1 }, current_rules_by_transition: {} },
  });
  assert.match(markdown, /^# MCP corpus precision rerun: 0\.5\.15 baseline to 9\.8\.7/m);
  assert.match(markdown, /\| Decision \| CSV baseline \| 9\.8\.7 rerun \| Change \|/);
  assert.match(markdown, /\| Rule \| CSV baseline \| 9\.8\.7 rerun \| Change \|/);
  assert.doesNotMatch(markdown, /0\.6\.1 rerun/);
});
