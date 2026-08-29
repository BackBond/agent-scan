'use strict';

const { discover } = require('./discovery.js');
const { collectEvidence } = require('./evidence.js');
const { renderHuman } = require('./output.js');
const { suggestPolicy } = require('./policy.js');
const { createScanReceipt } = require('./receipt.js');
const { scanEvidence, SCANNER_VERSION } = require('./scanner.js');

const TOOL = {
  name: 'scan_my_runtime',
  title: 'Scan my runtime tools',
  description: 'Statically scans a supplied live tool manifest, or bounded local agent config discovery when omitted. No network requests or tool execution.',
  inputSchema: {
    type: 'object',
    properties: {
      tools: {
        type: 'array',
        description: 'Optional live MCP/OpenAI/Anthropic tool list. Omit to scan recognized local agent configs.',
        items: { type: 'object' },
      },
      suggest_policy: { type: 'boolean', description: 'Include non-enforcing disable/wrap suggestions.' },
    },
    additionalProperties: false,
  },
};

function runtimeScan(args = {}, options = {}) {
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
  return { scan, receipt, policy };
}

function response(id, result) { return { jsonrpc: '2.0', id, result }; }
function errorResponse(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

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
  if (message.method === 'tools/list') return response(message.id, { tools: [TOOL] });
  if (message.method === 'tools/call') {
    if (!message.params || message.params.name !== TOOL.name) return errorResponse(message.id, -32602, 'Unknown tool');
    try {
      const result = runtimeScan(message.params.arguments || {});
      return response(message.id, {
        content: [{ type: 'text', text: renderHuman(result.scan, { policy: result.policy }).trimEnd() }],
        structuredContent: result,
        isError: false,
      });
    } catch (error) {
      return response(message.id, { content: [{ type: 'text', text: `agent-scan: ${error.message}` }], isError: true });
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
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line) {
        let outgoing;
        try { outgoing = handleMessage(JSON.parse(line)); }
        catch { outgoing = errorResponse(null, -32700, 'Parse error'); }
        if (outgoing) output.write(`${JSON.stringify(outgoing)}\n`);
      }
      newline = buffer.indexOf('\n');
    }
  });
}

module.exports = { TOOL, handleMessage, runtimeScan, startMcpServer };
