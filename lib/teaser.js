'use strict';

const { PROTOCOL: ASSESSMENT_PROTOCOL, assessmentJsonSchema, questionSet, validateAssessment } = require('./assessment.js');
const { EVIDENCE_PROTOCOL } = require('./runtime-evidence.js');

const TEASER_PROTOCOL = 'backbond-agent-teaser/v4';

function teaserContract() {
  return {
    protocol: TEASER_PROTOCOL,
    subject: 'self',
    public_client_role: 'capture_validate_bridge',
    instructions: [
      'The public client captures hashes and validates schemas; it does not contain or perform proprietary analysis.',
      'Exact offline analysis requires a separately licensed private analyzer pinned by SHA-256.',
      'Without the private analyzer, fail closed and do not enable privileged tools based on self-authored claims.',
      'No network request occurs unless --publish is explicitly supplied after private analysis.',
    ],
    assessment: questionSet(),
    artifact_inputs: {
      protocol: EVIDENCE_PROTOCOL,
      tool_schema: 'JSON file supplied with --tool-schema',
      permissions: 'JSON file supplied with --permissions',
      trace: 'JSON file supplied with --trace',
    },
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
