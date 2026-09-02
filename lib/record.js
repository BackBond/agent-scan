'use strict';

const { canonicalize, sha256 } = require('./canonical.js');
const { safeInline } = require('./text.js');
const { POSTURE_LABEL } = require('./teaser.js');

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
      posture_label: POSTURE_LABEL,
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
    `Posture: ${record.assurance.posture_label}`,
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
