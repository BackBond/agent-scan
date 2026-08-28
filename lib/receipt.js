'use strict';

const fs = require('node:fs');
const { createPublicKey, sign, verify } = require('node:crypto');
const { canonicalize, sha256 } = require('./canonical.js');

const RECEIPT_PROTOCOL = 'backbond-capture-receipt/v1';

function addIntegrity(payload, signingKeyPath = null) {
  const canonical = canonicalize(payload);
  const integrity = { canonicalization: 'lexicographic-json/v1', sha256: sha256(canonical), signature: null };
  if (signingKeyPath) {
    const privateKey = fs.readFileSync(signingKeyPath);
    const publicKey = createPublicKey(privateKey);
    const publicDer = publicKey.export({ type: 'spki', format: 'der' });
    integrity.signature = {
      algorithm: 'Ed25519',
      key_fingerprint_sha256: sha256(publicDer),
      public_key_spki_base64: publicDer.toString('base64'),
      value_base64: sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64'),
    };
  }
  return { ...payload, integrity };
}

function createCaptureReceipt(submission, evidence, options = {}) {
  return addIntegrity({
    protocol: RECEIPT_PROTOCOL,
    issued_at: (options.now || new Date()).toISOString(),
    observed_at: evidence.captured_at,
    collector: evidence.collector,
    runtime: evidence.runtime,
    artifacts: evidence.artifacts,
    claim_document_sha256: sha256(submission),
    analysis: { status: 'not_performed_by_public_client' },
  }, options.signingKeyPath || null);
}

function verifyEvidenceReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || !receipt.integrity) return false;
  const { integrity, ...payload } = receipt;
  const canonical = canonicalize(payload);
  if (sha256(canonical) !== integrity.sha256) return false;
  if (!integrity.signature) return true;
  try {
    return verify(
      null,
      Buffer.from(canonical, 'utf8'),
      { key: Buffer.from(integrity.signature.public_key_spki_base64, 'base64'), type: 'spki', format: 'der' },
      Buffer.from(integrity.signature.value_base64, 'base64'),
    );
  } catch {
    return false;
  }
}

module.exports = { RECEIPT_PROTOCOL, createCaptureReceipt, verifyEvidenceReceipt };
