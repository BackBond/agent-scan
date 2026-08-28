'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { submitPayload } = require('../lib/client.js');

test('client sends JSON to the teaser endpoint with the compatibility identity', async () => {
  let captured;
  const payload = {
    client: 'backbond-agent-scan/0.1.0',
    submitted_at: '2026-08-28T10:00:00.000Z',
    profile: { name: 'test-agent' },
  };
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return { ok: true, status: 200, json: async () => ({ score: 88 }) };
  };

  const result = await submitPayload(payload, { apiBase: 'https://example.test', fetchImpl });
  assert.deepEqual(result, { score: 88 });
  assert.equal(captured.url, 'https://example.test/v1/teaser/scan');
  assert.equal(captured.options.headers['user-agent'], payload.client);
  assert.deepEqual(JSON.parse(captured.options.body), payload);
});

test('client reports bounded API error detail', async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 422,
    text: async () => 'invalid profile',
  });
  await assert.rejects(
    submitPayload({ client: 'backbond-agent-scan/0.1.0' }, { apiBase: 'https://example.test', fetchImpl }),
    /BackBond API returned 422: invalid profile/,
  );
});
