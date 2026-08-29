'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256 } = require('./canonical.js');

const EVIDENCE_PROTOCOL = 'backbond-evidence-capture/v1';
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;

function captureArtifact(kind, filename) {
  const absolute = path.resolve(filename);
  const stat = fs.statSync(absolute);
  if (!stat.isFile()) throw new Error(`${kind} artifact is not a file: ${filename}`);
  if (stat.size > MAX_ARTIFACT_BYTES) throw new Error(`${kind} artifact exceeds ${MAX_ARTIFACT_BYTES} bytes: ${filename}`);
  const bytes = fs.readFileSync(absolute);
  try { JSON.parse(bytes.toString('utf8')); }
  catch (error) { throw new Error(`${kind} artifact is not valid JSON (${filename}): ${error.message}`); }
  return { kind, name: path.basename(absolute), bytes: stat.size, sha256: sha256(bytes) };
}

function collectRuntimeEvidence(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const env = options.env || process.env;
  const artifacts = [];
  for (const [kind, filename] of [
    ['tool_schema', options.toolSchemaPath],
    ['permissions', options.permissionsPath],
    ['trace', options.tracePath],
  ]) {
    if (filename) artifacts.push(captureArtifact(kind, filename));
  }
  return {
    protocol: EVIDENCE_PROTOCOL,
    captured_at: (options.now || new Date()).toISOString(),
    collector: { name: '@backbond/agent-scan', version: '0.4.1', role: 'neutral_capture_only' },
    runtime: {
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      cwd_sha256: sha256(cwd),
      environment_key_names_sha256: sha256(Object.keys(env).sort()),
    },
    artifacts: artifacts.sort((a, b) => a.kind.localeCompare(b.kind)),
  };
}

module.exports = { EVIDENCE_PROTOCOL, MAX_ARTIFACT_BYTES, collectRuntimeEvidence };
