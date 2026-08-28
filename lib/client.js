'use strict';

const SCAN_ENDPOINT = '/v1/teaser/scan';

async function submitPayload(payload, options = {}) {
  const apiBase = options.apiBase || process.env.BACKBOND_API_BASE || 'https://api.backbond.ai';
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('Node.js 18 or newer is required');

  const response = await fetchImpl(apiBase + SCAN_ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': payload.client,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let detail = '';
    try { detail = await response.text(); } catch { /* response body is optional */ }
    const suffix = detail ? `: ${detail.slice(0, 300)}` : '';
    throw new Error(`BackBond API returned ${response.status}${suffix}`);
  }
  return response.json();
}

module.exports = { SCAN_ENDPOINT, submitPayload };
