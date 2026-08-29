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
