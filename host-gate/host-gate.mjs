// Internal BackBond host-gate candidate. Not deployed. Node.js >=18.
// Accepts an already connected MCP SDK client. Keep that client private to the host.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';

export const SCANNER_SHA256 = 'dd35cdb9bebb62d53a6c633e902121a319e4030e5b9cd65ff32e77731336b509';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const MAX_BYTES = 256 * 1024;

export class GateError extends Error {
  constructor(code, report = null, snapshot = null) {
    super(`Agent Scan attachment gate: ${code}`);
    this.name = 'GateError';
    this.code = code;
    // Aggregate scanner output only. Snapshot is local approval metadata.
    this.report = report;
    this.snapshot = snapshot;
  }
}

async function within(operation, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new GateError('timeout')), milliseconds); }),
    ]);
  } finally { clearTimeout(timer); }
}

export async function scanManifest(raw, scannerPath, timeoutMs = 8000) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 10000) throw new GateError('timeout');
  // Read, verify and execute the same bytes inside the child. Keeping the loader
  // short also avoids Windows command-line length limits for the standalone file.
  const loader = `
    const fs = require('node:fs'), crypto = require('node:crypto');
    let bytes;
    try { bytes = fs.readFileSync(process.argv[1]); } catch { process.exit(20); }
    if (crypto.createHash('sha256').update(bytes).digest('hex') !== '${SCANNER_SHA256}') process.exit(21);
    const source = bytes.toString('utf8').replace(/^#![^\\n]*\\n/, '');
    new Function('require', 'module', 'exports', source)(require, module, exports);
  `;
  return new Promise((resolveResult, reject) => {
    const child = execFile(process.execPath,
      ['-e', loader, '--', scannerPath, 'vet-tools', '--stdin', '--summary-only'],
      { timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024, windowsHide: true },
      (error, stdout) => {
        const exit = error ? error.code : 0;
        if (exit === 20) return reject(new GateError('scanner_unavailable'));
        if (exit === 21) return reject(new GateError('scanner_checksum_mismatch'));
        if (error?.killed || ![0, 1, 3].includes(exit)) return reject(new GateError('scanner_failure'));
        let result;
        try { result = JSON.parse(stdout); } catch { return reject(new GateError('invalid_scanner_output')); }
        const codes = { no_blocking_finding: 0, block: 1, review: 3 };
        if (codes[result.decision] !== exit || result.scanner?.version !== '0.6.2'
            || result.ruleset?.version !== 'backbond-local-rules/2.0.2'
            || result.ruleset?.sha256 !== 'bcfa6d47ad68b1fda89b61834fa70dfb7b0e17dcb7d2a8e38d63f045687c492e'
            || result.profile?.sha256 !== '3edfb2bc97a68af345e1df5802e6028d8c32092d3dea379157581847bc2bf140'
            || result.protocol !== 'backbond-vet-summary/v1') return reject(new GateError('scanner_identity_or_decision_mismatch'));
        resolveResult(result);
      });
    child.stdin.on('error', () => {}); // The exit callback handles early process termination.
    child.stdin.end(raw);
  });
}

/**
 * getTools(): lists all pages, scans locally, returns approved definitions + snapshot.
 * callTool(request, snapshot): re-lists and re-scans before invocation; rejects drift.
 * An upstream client must implement listTools(params) and callTool(request).
 * Host permissions and user authorization must also allow any invocation.
 */
export function createAttachmentGate({ client, scannerPath, discoveryTimeoutMs = 8000 }) {
  if (!client || typeof client.listTools !== 'function' || typeof client.callTool !== 'function') {
    throw new TypeError('An already connected MCP client is required.');
  }
  if (!Number.isFinite(discoveryTimeoutMs) || discoveryTimeoutMs <= 0) throw new TypeError('Invalid timeout.');
  const localScanner = resolve(scannerPath);
  let approvedSnapshot = null;
  let queue = Promise.resolve();
  const serial = operation => {
    const next = queue.then(operation);
    queue = next.catch(() => {});
    return next;
  };

  async function inspect() {
    const tools = [];
    let cursor;
    const seen = new Set();
    const deadline = Date.now() + discoveryTimeoutMs;
    for (let pageCount = 0; ; pageCount++) {
      if (pageCount >= 100 || Date.now() >= deadline) throw new GateError('discovery_limit');
      let page;
      try { page = await within(() => client.listTools(cursor === undefined ? {} : { cursor }), deadline - Date.now()); }
      catch (error) { throw error instanceof GateError ? error : new GateError('discovery_failed'); }
      if (!page || !Array.isArray(page.tools)) throw new GateError('invalid_tools_list');
      // Detach from mutable SDK cache objects before scanning or returning definitions.
      try { tools.push(...JSON.parse(JSON.stringify(page.tools))); }
      catch { throw new GateError('invalid_tools_list'); }
      if (tools.length > 200) throw new GateError('tool_limit');
      if (Buffer.byteLength(JSON.stringify({ tools })) > MAX_BYTES) throw new GateError('input_limit');
      if (page.nextCursor === undefined) break;
      if (typeof page.nextCursor !== 'string' || !page.nextCursor || seen.has(page.nextCursor)) {
        throw new GateError('invalid_pagination');
      }
      cursor = page.nextCursor; seen.add(cursor);
    }
    const raw = JSON.stringify({ tools });
    const report = await scanManifest(raw, localScanner);
    if (report.decision !== 'no_blocking_finding') throw new GateError(report.decision, report, sha(raw));
    if (report.coverage?.status !== 'complete') throw new GateError('incomplete_coverage', report, sha(raw));
    return { tools, snapshot: sha(raw), report };
  }

  return Object.freeze({
    getTools() {
      return serial(async () => {
        approvedSnapshot = null;
        const checked = await inspect();
        approvedSnapshot = checked.snapshot;
        return checked;
      });
    },
    callTool(request, snapshot) {
      // Copy caller data before waiting on concurrent operations.
      const name = request?.name;
      let args;
      try { args = JSON.parse(JSON.stringify(request?.arguments ?? {})); }
      catch { return Promise.reject(new GateError('invalid_arguments')); }
      return serial(async () => {
        if (!approvedSnapshot || snapshot !== approvedSnapshot) throw new GateError('attachment_required');
        const prior = approvedSnapshot;
        approvedSnapshot = null;
        const checked = await inspect();
        if (checked.snapshot !== prior) throw new GateError('manifest_changed');
        if (!checked.tools.some(tool => tool.name === name)) throw new GateError('unknown_tool');
        approvedSnapshot = checked.snapshot;
        return client.callTool({ name, arguments: args });
      });
    },
  });
}
