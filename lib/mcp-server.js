'use strict';

const { discover } = require('./discovery.js');
const { collectEvidence, MAX_ARTIFACT_BYTES } = require('./evidence.js');
const { renderHuman } = require('./output.js');
const { liveToolsNextAction, renderNextAction } = require('./next-action.js');
const { suggestPolicy } = require('./policy.js');
const { createPublicScanRecord, renderCompactRecord } = require('./record.js');
const { createScanReceipt } = require('./receipt.js');
const { scanEvidence, SCANNER_VERSION } = require('./scanner.js');
const { safeInline } = require('./text.js');
const { POSTURE_LABEL } = require('./teaser.js');
const { createVetResult, renderVetHuman } = require('./vet-tools.js');

const TOOL = {
  name: 'scan_my_runtime',
  title: 'Scan my runtime tools',
  description: `Statically scans a supplied live tool manifest, or bounded local agent config discovery when omitted. ${POSTURE_LABEL}; no network requests or tool execution.`,
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  inputSchema: {
    type: 'object',
    properties: {
      tools: {
        type: 'array',
        description: 'Optional live MCP or supported function-tool list. Omit to scan recognized local agent configs.',
        items: { type: 'object' },
      },
      suggest_policy: { type: 'boolean', description: 'Include non-enforcing disable/wrap suggestions.' },
      emit_record: { type: 'boolean', description: 'Return only a redacted self-run scan record and compact text. No discovery paths, artifact names, or tool names are returned.' },
    },
    additionalProperties: false,
  },
};

const VET_TOOL = {
  name: 'vet_tools_before_attach',
  title: 'Vet tools before attaching them',
  description: 'Runs a scoped static pre-attachment gate over a proposed live tool list. Returns block, review, or no_blocking_finding; never a runtime safety determination.',
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  inputSchema: {
    type: 'object',
    properties: {
      tools: {
        type: 'array',
        description: 'Proposed live MCP or supported function tools to vet before attachment.',
        items: { type: 'object' },
      },
    },
    required: ['tools'],
    additionalProperties: false,
  },
};

function validateRuntimeArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be an object');
  const allowed = new Set(['tools', 'suggest_policy', 'emit_record']);
  const unknown = Object.keys(args).find(key => !allowed.has(key));
  if (unknown) throw new Error(`unknown argument: ${unknown}`);
  if (args.tools !== undefined && !Array.isArray(args.tools)) throw new Error('tools must be an array');
  if (args.suggest_policy !== undefined && typeof args.suggest_policy !== 'boolean') throw new Error('suggest_policy must be a boolean');
  if (args.emit_record !== undefined && typeof args.emit_record !== 'boolean') throw new Error('emit_record must be a boolean');
}

function validateVetArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be an object');
  const unknown = Object.keys(args).find(key => key !== 'tools');
  if (unknown) throw new Error(`unknown argument: ${unknown}`);
  if (!Array.isArray(args.tools)) throw new Error('tools must be an array');
}

function runtimeScan(args = {}, options = {}) {
  validateRuntimeArgs(args);
  const now = options.now || new Date();
  let plan = null;
  const documents = [];
  const artifactPaths = [];
  if (Array.isArray(args.tools)) {
    documents.push({ kind: 'tool_schema', name: '<mcp-runtime>', document: { tools: args.tools } });
  } else {
    plan = discover({ cwd: options.cwd || process.cwd() });
    artifactPaths.push(...plan.files);
  }
  const evidence = collectEvidence({ now, documents, artifactPaths, discovery: plan });
  const scan = scanEvidence(evidence, { now });
  const receipt = createScanReceipt(scan);
  const policy = args.suggest_policy ? suggestPolicy(scan) : null;
  const record = args.emit_record === true ? createPublicScanRecord(scan, receipt, {
    mode: Array.isArray(args.tools) ? 'live-manifest' : 'discovery',
  }) : null;
  const nextAction = Array.isArray(args.tools) ? null : liveToolsNextAction(SCANNER_VERSION);
  return { scan, receipt, policy, record, next_action: nextAction };
}

function runtimeVet(args, options = {}) {
  validateVetArgs(args);
  const now = options.now || new Date();
  const evidence = collectEvidence({
    now,
    documents: [{ kind: 'tool_schema', name: '<mcp-pre-attach>', document: { tools: args.tools } }],
  });
  return createVetResult(scanEvidence(evidence, { now }), evidence);
}

function response(id, result) { return { jsonrpc: '2.0', id, result }; }
function errorResponse(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

function oversizedRequestResponse() {
  return errorResponse(null, -32600, `Request exceeds ${MAX_ARTIFACT_BYTES} bytes`);
}

function handleMessage(message) {
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return errorResponse(message && message.id, -32600, 'Invalid Request');
  if (message.id === undefined) return null;
  if (message.method === 'initialize') {
    return response(message.id, {
      protocolVersion: '2025-06-18',
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: '@backbond/agent-scan', version: SCANNER_VERSION },
      instructions: 'Static-only local scan. Inferred facts are marked derived. No traces or config bodies are uploaded.',
    });
  }
  if (message.method === 'ping') return response(message.id, {});
  if (message.method === 'tools/list') return response(message.id, { tools: [TOOL, VET_TOOL] });
  if (message.method === 'tools/call') {
    if (!message.params || ![TOOL.name, VET_TOOL.name].includes(message.params.name)) return errorResponse(message.id, -32602, 'Unknown tool');
    const args = message.params.arguments === undefined ? {} : message.params.arguments;
    try {
      if (message.params.name === VET_TOOL.name) {
        const result = runtimeVet(args);
        return response(message.id, {
          content: [{ type: 'text', text: renderVetHuman(result).trimEnd() }],
          structuredContent: result,
          isError: false,
        });
      }
      const result = runtimeScan(args);
      if (result.record) {
        const text = [renderCompactRecord(result.record), result.next_action ? renderNextAction(result.next_action) : null]
          .filter(Boolean).join('\n\n');
        return response(message.id, {
          content: [{ type: 'text', text }],
          structuredContent: { record: result.record, ...(result.next_action ? { next_action: result.next_action } : {}) },
          isError: false,
        });
      }
      return response(message.id, {
        content: [{ type: 'text', text: [
          renderHuman(result.scan, { policy: result.policy }).trimEnd(),
          result.next_action ? renderNextAction(result.next_action) : null,
        ].filter(Boolean).join('\n\n') }],
        structuredContent: result,
        isError: false,
      });
    } catch (error) {
      if (message.params.name === TOOL.name && args && typeof args === 'object' && !Array.isArray(args) && args.emit_record === true) {
        return response(message.id, { content: [{ type: 'text', text: 'agent-scan: scan failed; no public record was created' }], isError: true });
      }
      return response(message.id, { content: [{ type: 'text', text: safeInline(`agent-scan: ${error.message}`) }], isError: true });
    }
  }
  return errorResponse(message.id, -32601, 'Method not found');
}

function startMcpServer(input = process.stdin, output = process.stdout) {
  input.setEncoding('utf8');
  let buffer = '';
  input.on('data', chunk => {
    buffer += chunk;
    let newline = buffer.indexOf('\n');
    while (newline >= 0) {
      const rawLine = buffer.slice(0, newline);
      const line = rawLine.trim();
      buffer = buffer.slice(newline + 1);
      if (line) {
        let outgoing;
        if (Buffer.byteLength(rawLine, 'utf8') > MAX_ARTIFACT_BYTES) outgoing = oversizedRequestResponse();
        else {
          try { outgoing = handleMessage(JSON.parse(line)); }
          catch { outgoing = errorResponse(null, -32700, 'Parse error'); }
        }
        if (outgoing) output.write(`${JSON.stringify(outgoing)}\n`);
      }
      newline = buffer.indexOf('\n');
    }
    if (Buffer.byteLength(buffer, 'utf8') > MAX_ARTIFACT_BYTES) {
      output.write(`${JSON.stringify(oversizedRequestResponse())}\n`);
      buffer = '';
    }
  });
}

module.exports = { TOOL, VET_TOOL, handleMessage, runtimeScan, runtimeVet, startMcpServer };
