'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { sha256 } = require('./canonical.js');

const ANALYZER_PROTOCOL = 'backbond-private-analyzer/v1';
const MAX_ANALYZER_OUTPUT_BYTES = 8 * 1024 * 1024;

function analyzerIdentity(filename) {
  const absolute = path.resolve(filename);
  const stat = fs.statSync(absolute);
  if (!stat.isFile()) throw new Error(`analyzer is not a file: ${filename}`);
  return { absolute, sha256: sha256(fs.readFileSync(absolute)), bytes: stat.size };
}

function runPrivateAnalyzer(options) {
  if (!options.analyzerPath) throw new Error('a separately distributed private analyzer is required');
  if (!/^[a-f0-9]{64}$/i.test(options.expectedSha256 || '')) throw new Error('--analyzer-sha256 must be a 64-character SHA-256 digest');
  const identity = analyzerIdentity(options.analyzerPath);
  if (identity.sha256.toLowerCase() !== options.expectedSha256.toLowerCase()) throw new Error('private analyzer SHA-256 does not match the pinned digest');
  const extension = path.extname(identity.absolute).toLowerCase();
  const sourceScript = ['.js', '.cjs', '.mjs'].includes(extension);
  const command = sourceScript ? process.execPath : identity.absolute;
  const args = sourceScript ? [identity.absolute] : [];
  const child = spawnSync(command, args, {
    input: JSON.stringify(options.request),
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
    maxBuffer: MAX_ANALYZER_OUTPUT_BYTES,
  });
  if (child.error) throw new Error(`private analyzer could not start: ${child.error.message}`);
  if (child.status !== 0) throw new Error(`private analyzer failed: ${(child.stderr || '').trim().slice(0, 500) || `exit ${child.status}`}`);
  let output;
  try { output = JSON.parse(child.stdout); }
  catch (error) { throw new Error(`private analyzer returned invalid JSON: ${error.message}`); }
  if (output.protocol !== ANALYZER_PROTOCOL || !output.result || !output.payload) throw new Error('private analyzer returned an incompatible result envelope');
  return {
    identity: {
      sha256: identity.sha256,
      bytes: identity.bytes,
      digest_verification: 'matches_caller_supplied_pin',
      publisher_authenticity: 'not_established_by_public_client',
    },
    output,
  };
}

module.exports = { ANALYZER_PROTOCOL, MAX_ANALYZER_OUTPUT_BYTES, analyzerIdentity, runPrivateAnalyzer };
