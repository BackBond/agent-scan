'use strict';

const { PROTOCOL: ASSESSMENT_PROTOCOL, assessmentJsonSchema, questionSet, validateAssessment } = require('./assessment.js');

const TEASER_PROTOCOL = 'backbond-agent-teaser/v4';

function teaserContract() {
  return {
    protocol: TEASER_PROTOCOL,
    subject: 'self',
    public_client_role: 'optional_claim_hypotheses',
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

module.exports = { TEASER_PROTOCOL, teaserContract, teaserSubmissionJsonSchema, validateTeaserSubmission };
