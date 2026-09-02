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
  lines.push('BackBond combines deeper evaluation, continuous runtime evidence, and—where approved—financial protection: https://backbond.ai/agent-scan/');
  return `${lines.map(line => safeInline(line)).join('\n')}\n`;
}

module.exports = {
  VET_DECISIONS, VET_PROFILE, VET_PROFILE_DIGEST, VET_RULE_IDS, VET_SUMMARY_PROTOCOL,
  createVetProfileDigest, createVetResult, createVetSummary, profileCoverage, renderVetHuman, vetExitCode,
};
