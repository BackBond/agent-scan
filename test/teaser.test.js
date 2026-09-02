'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MIN_PUBLIC_ID_BITS,
  POSTURE_LABEL,
  TRUST_BOUNDARY,
  teaserContract,
} = require('../lib/teaser.js');

test('teaser contract labels claims as unverified posture without a score', () => {
  const contract = teaserContract();
  assert.equal(contract.trust_boundary.posture_label, POSTURE_LABEL);
  assert.equal(contract.trust_boundary.result_kind, 'optional_claim_hypotheses');
  assert.equal(contract.trust_boundary.scoring, 'none');
  assert.equal(contract.trust_boundary.higher_is_stronger, null);
});

test('teaser evidence classes cannot earn safeguard credit', () => {
  assert.deepEqual(TRUST_BOUNDARY.evidence_credit, {
    observed_runtime_enforcement: 0,
    deterministically_derived: 0,
    agent_asserted: 0,
    unknown: 0,
  });
});

test('teaser keeps behavioral checks and hosted public claims outside the package', () => {
  assert.equal(TRUST_BOUNDARY.behavioral_checks, 'separate_indicative_disclosed_smoke_checks');
  assert.equal(TRUST_BOUNDARY.public_report, 'not_emitted_by_this_package');
  assert.equal(TRUST_BOUNDARY.public_badge, 'not_emitted_by_this_package');
  assert.equal(TRUST_BOUNDARY.public_identifier_minimum_entropy_bits, MIN_PUBLIC_ID_BITS);
  assert.equal(MIN_PUBLIC_ID_BITS, 128);
});

test('teaser declares a fail-closed privacy boundary', () => {
  assert.equal(TRUST_BOUNDARY.transmitted_data, 'none');
  for (const prohibited of ['evidence_text', 'behavioral_prompts', 'behavioral_responses', 'transcripts', 'source_code', 'logs', 'environment_variables', 'credentials']) {
    assert.equal(TRUST_BOUNDARY.prohibited_transmission.includes(prohibited), true);
  }
});
