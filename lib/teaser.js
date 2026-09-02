'use strict';

const { PROTOCOL: ASSESSMENT_PROTOCOL, assessmentJsonSchema, questionSet, validateAssessment } = require('./assessment.js');

const TEASER_PROTOCOL = 'backbond-agent-teaser/v4';
const POSTURE_LABEL = 'Unverified self-assessed exposure posture';
const MIN_PUBLIC_ID_BITS = 128;

const TRUST_BOUNDARY = Object.freeze({
  posture_label: POSTURE_LABEL,
  result_kind: 'optional_claim_hypotheses',
  scoring: 'none',
  higher_is_stronger: null,
  evidence_credit: {
    observed_runtime_enforcement: 0,
    deterministically_derived: 0,
    agent_asserted: 0,
    unknown: 0,
  },
  behavioral_checks: 'separate_indicative_disclosed_smoke_checks',
  public_report: 'not_emitted_by_this_package',
  public_badge: 'not_emitted_by_this_package',
  public_identifier_minimum_entropy_bits: MIN_PUBLIC_ID_BITS,
  transmitted_data: 'none',
  prohibited_transmission: [
    'evidence_text', 'behavioral_prompts', 'behavioral_responses', 'transcripts',
    'source_code', 'logs', 'environment_variables', 'credentials',
  ],
});

function teaserContract() {
  return {
    protocol: TEASER_PROTOCOL,
    subject: 'self',
    public_client_role: 'optional_claim_hypotheses',
    trust_boundary: TRUST_BOUNDARY,
    instructions: [
      'Claims are optional hypotheses and are never finding or severity inputs.',
      'The local scanner compares claims with observed evidence only to report contradictions.',
      'Omitting claims does not reduce scanner coverage for supported artifacts.',
    ],
    assessment: questionSet(),
    submit_shape: {
      protocol: TEASER_PROTOCOL,
      subject: 'self',
      assessment: `<${ASSESSMENT_PROTOCOL} document>`,
    },
  };
}

function teaserSubmissionJsonSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['protocol', 'subject', 'assessment'],
    properties: {
      protocol: { type: 'string', const: TEASER_PROTOCOL },
      subject: { type: 'string', const: 'self' },
      assessment: assessmentJsonSchema(),
    },
  };
}

function validateTeaserSubmission(submission) {
  if (!submission || typeof submission !== 'object' || Array.isArray(submission)) throw new Error('teaser submission must be a JSON object');
  const extras = Object.keys(submission).filter(key => !['protocol', 'subject', 'assessment'].includes(key));
  if (extras.length) throw new Error(`teaser submission has unknown fields: ${extras.join(', ')}`);
  if (submission.protocol !== TEASER_PROTOCOL) throw new Error(`protocol must be "${TEASER_PROTOCOL}"`);
  if (submission.subject !== 'self') throw new Error('subject must be "self"');
  validateAssessment(submission.assessment);
  return submission;
}

module.exports = {
  MIN_PUBLIC_ID_BITS,
  POSTURE_LABEL,
  TEASER_PROTOCOL,
  TRUST_BOUNDARY,
  teaserContract,
  teaserSubmissionJsonSchema,
  validateTeaserSubmission,
};
