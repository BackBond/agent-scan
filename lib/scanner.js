'use strict';

const { evaluateRules, RULESET_DIGEST, RULESET_VERSION } = require('./rules.js');
const { buildExposurePaths, EXPOSURE_PATH_PROTOCOL } = require('./exposure-paths.js');
const { VET_DECISIONS, VET_PROFILE } = require('./vet-tools.js');

const SCAN_PROTOCOL = 'backbond-agent-scan/v1';
const SCANNER_VERSION = '0.5.5';

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
      'Partial zero-finding scans are inconclusive rather than presented as clean.',
      'Public records are self-run and unverified; they are not BackBond attestations.',
      'A no-blocking-finding pre-attachment decision is not a safety determination or runtime attestation.',
    ],
  };
}

module.exports = { SCAN_PROTOCOL, SCANNER_VERSION, claimContradictions, scanEvidence, scannerContract };
