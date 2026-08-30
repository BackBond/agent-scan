'use strict';

const { buildExposurePaths } = require('./exposure-paths.js');
const { meetsThreshold } = require('./rules.js');
const { safeInline } = require('./text.js');

const VET_PROFILE = 'backbond-pre-attach/v1';
const VET_DECISIONS = Object.freeze(['block', 'review', 'no_blocking_finding']);
const VET_EXIT_CODES = Object.freeze({ block: 1, review: 3, no_blocking_finding: 0 });
const VET_RULE_IDS = new Set(['BB001', 'BB002', 'BB004', 'BB007', 'BB008', 'BB009', 'BB010', 'BB011', 'BB012', 'BB013']);
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
  return { status: unique.length ? 'partial' : 'complete', gaps: unique };
}

function createVetResult(scan, evidence) {
  const findings = scan.findings.filter(item => VET_RULE_IDS.has(item.id));
  const coverage = profileCoverage(scan, evidence);
  const blocking = meetsThreshold(findings, 'high');
  const decision = blocking ? 'block' : coverage.status === 'complete' ? 'no_blocking_finding' : 'review';
  return {
    protocol: VET_PROFILE,
    scanned_at: scan.scanned_at,
    scanner: scan.scanner,
    ruleset: scan.ruleset,
    decision,
    threshold: 'high',
    summary: summarize(findings),
    findings,
    coverage,
    exposure_paths: buildExposurePaths(findings),
    scope: {
      tool_count: evidence.facts.tools.length,
      assessed: ['tool identities', 'tool descriptions', 'supplied input schemas', 'same-manifest tool composition'],
      not_assessed: ['runtime permission enforcement', 'approval enforcement', 'audit behavior', 'runtime traces', 'actual tool execution'],
      excluded_rule_ids: ['BB003', 'BB005', 'BB006'],
    },
    assurance: 'Static pre-attachment metadata check only. A no-blocking-finding decision is not a safety determination or runtime attestation.',
  };
}

function vetExitCode(decision) {
  if (!Object.prototype.hasOwnProperty.call(VET_EXIT_CODES, decision)) throw new Error(`unknown pre-attachment decision: ${decision}`);
  return VET_EXIT_CODES[decision];
}

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
  lines.push(`Agent decision: ${result.decision === 'block' ? 'do not attach automatically; isolate or review the toolset.' : result.decision === 'review' ? 'do not attach automatically; the manifest is insufficient for this profile.' : 'this profile found no reason to block; runtime policy still controls attachment.'}`);
  lines.push('Not assessed: runtime enforcement, approval, audit behavior, traces, or actual execution.');
  lines.push('BackBond combines deeper evaluation, continuous runtime evidence, and—where approved—financial protection: https://backbond.ai');
  return `${lines.map(line => safeInline(line)).join('\n')}\n`;
}

module.exports = { VET_DECISIONS, VET_PROFILE, VET_RULE_IDS, createVetResult, profileCoverage, renderVetHuman, vetExitCode };
