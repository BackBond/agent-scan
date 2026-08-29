'use strict';

const PROTOCOL = 'backbond-agent-self-assessment/v1';
const SOURCES = ['observed', 'derived', 'agent_asserted', 'unknown'];

const QUESTIONS = [
  ['name', 'What runtime name or stable identifier describes you?', { type: 'string', minLength: 1, maxLength: 200 }],
  ['framework', 'Which framework or runtime are you executing in?', { type: 'string', minLength: 1, maxLength: 200 }],
  ['exec_code', 'Can you execute code, shell commands, or dynamically generated programs?', { type: 'boolean' }],
  ['browse_web', 'Can you fetch arbitrary URLs, use a browser, or make outbound web requests?', { type: 'boolean' }],
  ['filesystem', 'Can you read or write files outside a runtime-enforced sandbox?', { type: 'boolean' }],
  ['exposure', 'Who can supply instructions or content to you?', { type: 'string', enum: ['public', 'internal', 'local'] }],
  ['handles_payments', 'Can you move money, use payment credentials, or create a financial commitment?', { type: 'boolean' }],
  ['human_approval', 'How often does a runtime-enforced human approval gate block consequential actions?', { type: 'string', enum: ['always', 'sometimes', 'never'] }],
  ['persistent_memory', 'Can information you write influence later sessions through memory, a vector store, or a database?', { type: 'boolean' }],
  ['tool_count', 'How many distinct tools or functions can you invoke in this runtime?', { type: 'integer', minimum: 0 }],
  ['guardrails', 'Does the runtime enforce prompt-injection, moderation, or input/output safety controls outside your own instructions?', { type: 'boolean' }],
  ['audit_logging', 'Are your tool calls and consequential actions recorded in an audit log?', { type: 'boolean' }],
  ['incident_plan', 'Can you identify a documented shutdown and incident-response procedure for this deployment?', { type: 'boolean' }],
].map(([key, prompt, value]) => ({ key, prompt, value }));

const QUESTION_BY_KEY = Object.fromEntries(QUESTIONS.map(question => [question.key, question]));

function questionSet() {
  return {
    protocol: PROTOCOL,
    subject: 'self',
    role: 'unverified_claims',
    instructions: [
      'Answer from the current runtime without asking a person.',
      'These answers are optional hypotheses, not score or finding inputs.',
      'The local scanner may compare them with artifact evidence only to report contradictions.',
      'Use source="unknown" when evidence is unavailable.',
    ],
    sources: SOURCES,
    questions: QUESTIONS.map(question => ({
      ...question,
      answer: {
        type: 'object',
        required: ['source'],
        properties: {
          value: question.value,
          source: { type: 'string', enum: SOURCES },
          evidence: { type: 'string', minLength: 1, maxLength: 500 },
        },
      },
    })),
  };
}

function assessmentJsonSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['protocol', 'subject', 'answers'],
    properties: {
      protocol: { type: 'string', const: PROTOCOL },
      subject: { type: 'string', const: 'self' },
      answers: {
        type: 'object',
        additionalProperties: false,
        required: QUESTIONS.map(question => question.key),
        properties: Object.fromEntries(QUESTIONS.map(question => [question.key, {
          type: 'object',
          additionalProperties: false,
          required: ['source'],
          properties: {
            value: question.value,
            source: { type: 'string', enum: SOURCES },
            evidence: { type: 'string', minLength: 1, maxLength: 500 },
          },
        }])),
      },
    },
  };
}

function validateValue(question, value) {
  const schema = question.value;
  if (schema.type === 'boolean' && typeof value !== 'boolean') throw new Error(`answers.${question.key}.value must be a boolean`);
  if (schema.type === 'integer' && (!Number.isInteger(value) || value < 0)) throw new Error(`answers.${question.key}.value must be a non-negative integer`);
  if (schema.type === 'string') {
    if (typeof value !== 'string' || !value.trim()) throw new Error(`answers.${question.key}.value must be a non-empty string`);
    if (schema.maxLength && value.length > schema.maxLength) throw new Error(`answers.${question.key}.value is too long`);
    if (schema.enum && !schema.enum.includes(value)) throw new Error(`answers.${question.key}.value must be one of ${schema.enum.join(', ')}`);
  }
}

function validateAssessment(assessment) {
  if (!assessment || typeof assessment !== 'object' || Array.isArray(assessment)) throw new Error('assessment must be a JSON object');
  if (assessment.protocol !== PROTOCOL) throw new Error(`protocol must be "${PROTOCOL}"`);
  if (assessment.subject !== 'self') throw new Error('subject must be "self"');
  if (!assessment.answers || typeof assessment.answers !== 'object' || Array.isArray(assessment.answers)) throw new Error('answers must be a JSON object');
  const extras = Object.keys(assessment.answers).filter(key => !QUESTION_BY_KEY[key]);
  if (extras.length) throw new Error(`unknown answer fields: ${extras.join(', ')}`);
  for (const question of QUESTIONS) {
    const answer = assessment.answers[question.key];
    if (!answer || typeof answer !== 'object' || Array.isArray(answer)) throw new Error(`answers.${question.key} must be an object`);
    const answerExtras = Object.keys(answer).filter(key => !['value', 'source', 'evidence'].includes(key));
    if (answerExtras.length) throw new Error(`answers.${question.key} has unknown fields: ${answerExtras.join(', ')}`);
    if (!SOURCES.includes(answer.source)) throw new Error(`answers.${question.key}.source is invalid`);
    if (answer.source === 'unknown') {
      if (answer.value !== undefined && answer.value !== null) throw new Error(`answers.${question.key}.value must be omitted when source is unknown`);
      continue;
    }
    validateValue(question, answer.value);
    if (typeof answer.evidence !== 'string' || !answer.evidence.trim() || answer.evidence.length > 500) throw new Error(`answers.${question.key}.evidence is required and must be 500 characters or fewer`);
  }
  return assessment;
}

module.exports = { PROTOCOL, QUESTIONS, SOURCES, assessmentJsonSchema, questionSet, validateAssessment };
