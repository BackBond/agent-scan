'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256 } = require('./canonical.js');

const EVIDENCE_PROTOCOL = 'backbond-scan-evidence/v1';
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const ARTIFACT_KINDS = ['tool_schema', 'permissions', 'trace'];
const CAPABILITIES = new Set([
  'code_execution', 'secret_read', 'network_egress', 'destructive_action',
  'financial_action', 'persistent_write', 'privileged_action', 'filesystem_access',
]);
const INPUT_TRUST = new Set(['trusted', 'untrusted', 'mixed', 'unknown']);
const APPROVAL = new Set(['enforced', 'advisory', 'none', 'unknown']);
const AUDIT = new Set(['observable', 'none', 'unknown']);

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
}

function readJsonArtifact(kind, filename) {
  const absolute = path.resolve(filename);
  const stat = fs.statSync(absolute);
  if (!stat.isFile()) throw new Error(`${kind} artifact is not a file: ${filename}`);
  if (stat.size > MAX_ARTIFACT_BYTES) throw new Error(`${kind} artifact exceeds ${MAX_ARTIFACT_BYTES} bytes: ${filename}`);
  const bytes = fs.readFileSync(absolute);
  let document;
  try { document = JSON.parse(bytes.toString('utf8')); }
  catch (error) { throw new Error(`${kind} artifact is not valid JSON (${filename}): ${error.message}`); }
  return {
    document,
    metadata: { kind, name: path.basename(absolute), bytes: stat.size, sha256: sha256(bytes), dialect: null },
  };
}

function ref(artifact, pointer) {
  return { artifact_kind: artifact.kind, artifact_name: artifact.name, pointer };
}

function validateEnum(value, allowed, label) {
  if (value !== undefined && !allowed.has(value)) throw new Error(`${label} must be one of ${[...allowed].join(', ')}`);
  return value === undefined ? 'unknown' : value;
}

function validateCapabilities(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  for (const capability of value) {
    if (!CAPABILITIES.has(capability)) throw new Error(`${label} contains unsupported capability: ${capability}`);
  }
  return [...new Set(value)].sort();
}

function searchableToolText(tool) {
  const schema = tool.parameters || tool.input_schema || tool.inputSchema || {};
  const propertyNames = schema && schema.properties && typeof schema.properties === 'object'
    ? Object.keys(schema.properties) : [];
  return [tool.name, tool.description, tool.title, ...propertyNames]
    .filter(value => typeof value === 'string').join(' ').toLowerCase().replace(/[_-]+/g, ' ');
}

function inferCapabilities(tool) {
  const text = searchableToolText(tool);
  const matches = [
    ['code_execution', /\b(shell|bash|terminal|exec(?:ute)?|command|subprocess|powershell|python|javascript|run[_ -]?code)\b/],
    ['secret_read', /\b(secret|credential|password|token|keychain|vault|api[_ -]?key|environment variable)\b/],
    ['network_egress', /\b(http|fetch|request|browser|web|network|upload|email|slack|send|post[_ -]?message)\b/],
    ['destructive_action', /\b(delete|remove|destroy|drop|terminate|cancel|revoke|wipe|purge)\b/],
    ['financial_action', /\b(pay|payment|purchase|transfer|wire|trade|order)\b/],
    ['persistent_write', /\b(memory|remember|vector|database|datastore|store|save|persist|write[_ -]?(record|memory))\b/],
    ['privileged_action', /\b(admin|sudo|privilege|permission|iam|deploy|publish|merge|revoke|payment|transfer|delete)\b/],
    ['filesystem_access', /\b(file|filesystem|directory|folder|path|read[_ -]?file|write[_ -]?file)\b/],
  ];
  return matches.filter(([, pattern]) => pattern.test(text)).map(([capability]) => capability).sort();
}

function normalizeTool(tool, index, artifact, basePointer, dialect, canonical = false, pointerOverride = null) {
  assertObject(tool, `${artifact.kind} tool ${index}`);
  if (typeof tool.name !== 'string' || !tool.name.trim()) throw new Error(`${artifact.kind} tool ${index}.name must be a non-empty string`);
  const extension = tool['x-backbond'];
  if (extension !== undefined) assertObject(extension, `${artifact.kind} tool ${index}.x-backbond`);
  const controls = canonical ? tool : (extension || {});
  const explicitCapabilities = validateCapabilities(controls.capabilities, `${artifact.kind} tool ${index}.capabilities`);
  const capabilities = [...new Set([...inferCapabilities(tool), ...explicitCapabilities])].sort();
  const toolPointer = pointerOverride || `${basePointer}/${index}`;
  return {
    name: tool.name,
    dialect,
    capabilities,
    input_trust: validateEnum(controls.input_trust, INPUT_TRUST, `${artifact.kind} tool ${index}.input_trust`),
    approval: validateEnum(controls.approval, APPROVAL, `${artifact.kind} tool ${index}.approval`),
    audit: validateEnum(controls.audit, AUDIT, `${artifact.kind} tool ${index}.audit`),
    refs: {
      identity: ref(artifact, `${toolPointer}/name`),
      capabilities: ref(artifact, `${toolPointer}${canonical ? '/capabilities' : ''}`),
      input_trust: ref(artifact, `${toolPointer}${canonical ? '/input_trust' : '/x-backbond/input_trust'}`),
      approval: ref(artifact, `${toolPointer}${canonical ? '/approval' : '/x-backbond/approval'}`),
      audit: ref(artifact, `${toolPointer}${canonical ? '/audit' : '/x-backbond/audit'}`),
    },
  };
}

function normalizeToolSchema(document, artifact) {
  if (document && document.protocol === 'backbond-tool-schema/v1') {
    assertObject(document, 'tool schema');
    if (!Array.isArray(document.tools)) throw new Error('backbond-tool-schema/v1 tools must be an array');
    artifact.dialect = 'backbond-tool-schema/v1';
    return document.tools.map((tool, index) => normalizeTool(tool, index, artifact, '/tools', artifact.dialect, true));
  }

  let tools;
  let basePointer;
  let dialect;
  if (Array.isArray(document)) {
    tools = document;
    basePointer = '';
  } else if (document && Array.isArray(document.tools)) {
    tools = document.tools;
    basePointer = '/tools';
  } else if (document && document.result && Array.isArray(document.result.tools)) {
    tools = document.result.tools;
    basePointer = '/result/tools';
    dialect = 'mcp-tools-list/v1';
  } else {
    return null;
  }
  if (!dialect && tools.length > 0 && tools.every(tool => tool && tool.type === 'function' && tool.function)) {
    dialect = 'openai-function-tools/v1';
    artifact.dialect = dialect;
    return tools.map((entry, index) => normalizeTool(entry.function, index, artifact, basePointer, dialect, false, `${basePointer}/${index}/function`));
  }
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && tool.input_schema)) dialect = 'anthropic-tools/v1';
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && tool.inputSchema)) dialect = 'mcp-tools-list/v1';
  if (!dialect) return null;
  artifact.dialect = dialect;
  return tools.map((tool, index) => normalizeTool(tool, index, artifact, basePointer, dialect));
}

function scopeIsWildcard(value) {
  if (value === true) return true;
  if (typeof value === 'string') return ['*', '**', '/*', 'all', 'any'].includes(value.toLowerCase());
  if (Array.isArray(value)) return value.some(scopeIsWildcard);
  if (value && typeof value === 'object') return value.unrestricted === true;
  return false;
}

function validateScope(value, label) {
  if (value === undefined) return;
  if (typeof value === 'string') {
    if (!value.trim()) throw new Error(`${label} must not be empty`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.some(item => typeof item !== 'string' || !item.trim())) throw new Error(`${label} must contain only non-empty strings`);
    return;
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && value.unrestricted === true) return;
  throw new Error(`${label} must be a string array or {"unrestricted":true}`);
}

function normalizePermissions(document, artifact) {
  if (!document || document.protocol !== 'backbond-permissions/v1') return null;
  assertObject(document, 'permissions');
  artifact.dialect = 'backbond-permissions/v1';
  const inputTrust = validateEnum(document.input_trust, INPUT_TRUST, 'permissions.input_trust');
  const tools = [];
  if (document.tools !== undefined) assertObject(document.tools, 'permissions.tools');
  for (const [name, controls] of Object.entries(document.tools || {})) {
    if (!name.trim()) throw new Error('permissions.tools keys must be non-empty tool names');
    assertObject(controls, `permissions.tools.${name}`);
    tools.push({
      name,
      capabilities: validateCapabilities(controls.capabilities, `permissions.tools.${name}.capabilities`),
      input_trust: validateEnum(controls.input_trust, INPUT_TRUST, `permissions.tools.${name}.input_trust`),
      approval: validateEnum(controls.approval, APPROVAL, `permissions.tools.${name}.approval`),
      audit: validateEnum(controls.audit, AUDIT, `permissions.tools.${name}.audit`),
      refs: {
        identity: ref(artifact, `/tools/${escapePointer(name)}`),
        capabilities: ref(artifact, `/tools/${escapePointer(name)}/capabilities`),
        input_trust: ref(artifact, `/tools/${escapePointer(name)}/input_trust`),
        approval: ref(artifact, `/tools/${escapePointer(name)}/approval`),
        audit: ref(artifact, `/tools/${escapePointer(name)}/audit`),
      },
    });
  }
  const scopes = [
    ['filesystem', 'read'], ['filesystem', 'write'], ['subprocess', 'allow'],
    ['credentials', 'read'], ['network', 'egress'],
  ];
  const wildcards = [];
  for (const [domain, field] of scopes) {
    const container = document[domain];
    if (container !== undefined) assertObject(container, `permissions.${domain}`);
    if (container) validateScope(container[field], `permissions.${domain}.${field}`);
    if (container && scopeIsWildcard(container[field])) {
      wildcards.push({ domain, field, ref: ref(artifact, `/${domain}/${field}`) });
    }
  }
  return {
    input_trust: inputTrust,
    input_trust_ref: ref(artifact, '/input_trust'),
    tools,
    wildcards,
    secret_access_unrestricted: wildcards.some(item => item.domain === 'credentials'),
    network_egress_unrestricted: wildcards.some(item => item.domain === 'network'),
    network_scope_observed: Boolean(document.network && document.network.egress !== undefined),
  };
}

function normalizeTrace(document, artifact) {
  if (!document || document.protocol !== 'backbond-trace/v1') return null;
  assertObject(document, 'trace');
  if (!Array.isArray(document.events)) throw new Error('backbond-trace/v1 events must be an array');
  artifact.dialect = 'backbond-trace/v1';
  const calls = [];
  document.events.forEach((event, index) => {
    assertObject(event, `trace event ${index}`);
    if (event.type !== 'tool_call') return;
    if (typeof event.tool !== 'string' || !event.tool.trim()) throw new Error(`trace event ${index}.tool must be a non-empty string`);
    calls.push({
      name: event.tool,
      capabilities: validateCapabilities(event.capabilities, `trace event ${index}.capabilities`),
      input_trust: validateEnum(event.input_trust, INPUT_TRUST, `trace event ${index}.input_trust`),
      approval: validateEnum(event.approval, APPROVAL, `trace event ${index}.approval`),
      audit: validateEnum(event.audit, AUDIT, `trace event ${index}.audit`),
      refs: {
        identity: ref(artifact, `/events/${index}/tool`),
        capabilities: ref(artifact, `/events/${index}/capabilities`),
        input_trust: ref(artifact, `/events/${index}/input_trust`),
        approval: ref(artifact, `/events/${index}/approval`),
        audit: ref(artifact, `/events/${index}/audit`),
      },
    });
  });
  return calls;
}

function escapePointer(value) {
  return value.replace(/~/g, '~0').replace(/\//g, '~1');
}

function mergeTrust(values, fallback = 'unknown') {
  const known = values.filter(value => value && value !== 'unknown');
  if (known.some(value => value === 'untrusted' || value === 'mixed')) return 'untrusted';
  if (known.length && known.every(value => value === 'trusted')) return 'trusted';
  return fallback === 'mixed' ? 'untrusted' : fallback;
}

function mergeApproval(values) {
  const known = values.filter(value => value && value !== 'unknown');
  if (known.some(value => value === 'none' || value === 'advisory')) return 'not_enforced';
  if (known.some(value => value === 'enforced')) return 'enforced';
  return 'unknown';
}

function mergeAudit(values) {
  const known = values.filter(value => value && value !== 'unknown');
  if (known.some(value => value === 'none')) return 'not_observable';
  if (known.some(value => value === 'observable')) return 'observable';
  return 'unknown';
}

function uniqueRefs(refs) {
  const seen = new Set();
  return refs.filter(item => {
    const key = `${item.artifact_kind}:${item.artifact_name}:${item.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mergeToolFacts(sources, globalInputTrust) {
  const grouped = new Map();
  for (const source of sources) {
    if (!grouped.has(source.name)) grouped.set(source.name, []);
    grouped.get(source.name).push(source);
  }
  return [...grouped.entries()].map(([name, entries]) => ({
    name,
    capabilities: [...new Set(entries.flatMap(entry => entry.capabilities))].sort(),
    input_trust: mergeTrust(entries.map(entry => entry.input_trust), globalInputTrust),
    approval: mergeApproval(entries.map(entry => entry.approval)),
    audit: mergeAudit(entries.map(entry => entry.audit)),
    refs: {
      identity: uniqueRefs(entries.map(entry => entry.refs.identity)),
      capabilities: uniqueRefs(entries.filter(entry => entry.capabilities.length).map(entry => entry.refs.capabilities)),
      input_trust: uniqueRefs(entries.filter(entry => entry.input_trust !== 'unknown').map(entry => entry.refs.input_trust)),
      approval: uniqueRefs(entries.filter(entry => entry.approval !== 'unknown').map(entry => entry.refs.approval)),
      audit: uniqueRefs(entries.filter(entry => entry.audit !== 'unknown').map(entry => entry.refs.audit)),
    },
  })).sort((a, b) => a.name.localeCompare(b.name));
}

function gap(kind, status, code, message, artifact = null) {
  return {
    code,
    artifact_kind: kind,
    status,
    message,
    artifact_name: artifact ? artifact.name : null,
  };
}

function collectEvidence(options = {}) {
  const paths = {
    tool_schema: options.toolSchemaPath,
    permissions: options.permissionsPath,
    trace: options.tracePath,
  };
  const artifacts = [];
  const coverageGaps = [];
  let tools = [];
  let permissions = null;
  let traceCalls = [];

  for (const kind of ARTIFACT_KINDS) {
    const filename = paths[kind];
    if (!filename) {
      coverageGaps.push(gap(kind, 'missing', `BB-COV-MISSING-${kind.toUpperCase()}`, `${kind} evidence was not supplied`));
      continue;
    }
    const loaded = readJsonArtifact(kind, filename);
    let normalized;
    if (kind === 'tool_schema') normalized = normalizeToolSchema(loaded.document, loaded.metadata);
    else if (kind === 'permissions') normalized = normalizePermissions(loaded.document, loaded.metadata);
    else normalized = normalizeTrace(loaded.document, loaded.metadata);
    if (normalized === null) {
      loaded.metadata.dialect = 'unsupported';
      coverageGaps.push(gap(kind, 'unsupported', `BB-COV-UNSUPPORTED-${kind.toUpperCase()}`, `${kind} JSON does not match a supported dialect`, loaded.metadata));
    } else if (kind === 'tool_schema') tools = normalized;
    else if (kind === 'permissions') permissions = normalized;
    else traceCalls = normalized;
    artifacts.push(loaded.metadata);
  }

  const globalInputTrust = permissions ? permissions.input_trust : 'unknown';
  const facts = {
    tools: mergeToolFacts([...tools, ...(permissions ? permissions.tools : []), ...traceCalls], globalInputTrust),
    global_input_trust: globalInputTrust,
    global_input_trust_ref: permissions ? permissions.input_trust_ref : null,
    wildcards: permissions ? permissions.wildcards : [],
    secret_access_unrestricted: permissions ? permissions.secret_access_unrestricted : false,
    network_egress_unrestricted: permissions ? permissions.network_egress_unrestricted : false,
    network_scope_observed: permissions ? permissions.network_scope_observed : false,
  };
  return {
    protocol: EVIDENCE_PROTOCOL,
    collected_at: (options.now || new Date()).toISOString(),
    artifacts: artifacts.sort((a, b) => a.kind.localeCompare(b.kind)),
    coverage_gaps: coverageGaps,
    facts,
  };
}

function publicEvidence(evidence) {
  return {
    protocol: evidence.protocol,
    collected_at: evidence.collected_at,
    artifacts: evidence.artifacts,
    coverage_gaps: evidence.coverage_gaps,
    observations: {
      tool_count: evidence.facts.tools.length,
      tools: evidence.facts.tools.map(tool => ({
        name: tool.name,
        capabilities: tool.capabilities,
        input_trust: tool.input_trust,
        approval: tool.approval,
        audit: tool.audit,
      })),
      wildcard_permission_count: evidence.facts.wildcards.length,
    },
  };
}

module.exports = {
  ARTIFACT_KINDS, CAPABILITIES, EVIDENCE_PROTOCOL, MAX_ARTIFACT_BYTES,
  collectEvidence, publicEvidence, readJsonArtifact,
};
