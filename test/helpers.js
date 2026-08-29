'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PROTOCOL, QUESTIONS } = require('../lib/assessment.js');
const { TEASER_PROTOCOL } = require('../lib/teaser.js');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'agent-scan.js');

function fixturePaths(name) {
  const directory = path.join(ROOT, 'fixtures', name);
  return {
    directory,
    tools: path.join(directory, 'tool-schema.json'),
    permissions: path.join(directory, 'permissions.json'),
    trace: path.join(directory, 'trace.json'),
  };
}

function tempDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-scan-054-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeJson(directory, name, value) {
  const target = path.join(directory, name);
  fs.writeFileSync(target, JSON.stringify(value));
  return target;
}

function claimSubmission(overrides = {}) {
  const values = {
    name: 'test-runtime', framework: 'custom', exec_code: true, browse_web: true,
    filesystem: true, exposure: 'public', handles_payments: false, human_approval: 'never',
    persistent_memory: true, tool_count: 5, guardrails: false, audit_logging: false, incident_plan: false,
    ...overrides,
  };
  return {
    protocol: TEASER_PROTOCOL,
    subject: 'self',
    assessment: {
      protocol: PROTOCOL,
      subject: 'self',
      answers: Object.fromEntries(QUESTIONS.map(question => [question.key, {
        value: values[question.key], source: 'agent_asserted', evidence: `hypothesis for ${question.key}`,
      }])),
    },
  };
}

module.exports = { CLI, ROOT, claimSubmission, fixturePaths, tempDirectory, writeJson };
