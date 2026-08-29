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

function readJsonArtifact(kind, filename, adapter = null) {
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
    metadata: { kind, name: path.basename(absolute), bytes: stat.size, sha256: sha256(bytes), dialect: null, adapter },
  };
}

function memoryArtifact(kind, name, document, raw, adapter = null) {
  const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || JSON.stringify(document), 'utf8');
  if (bytes.length > MAX_ARTIFACT_BYTES) throw new Error(`${kind} artifact exceeds ${MAX_ARTIFACT_BYTES} bytes: ${name}`);
  return { document, metadata: { kind, name, bytes: bytes.length, sha256: sha256(bytes), dialect: null, adapter } };
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

function schemaText(value, depth = 0) {
  if (!value || depth > 5) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(item => schemaText(item, depth + 1)).join(' ');
  if (typeof value !== 'object') return '';
  return Object.entries(value)
    .filter(([key]) => !['default', 'example', 'examples', 'const'].includes(key))
    .map(([key, item]) => `${key} ${schemaText(item, depth + 1)}`).join(' ');
}

function inputSchema(tool) {
  return tool.parameters || tool.input_schema || tool.inputSchema || tool.schema || {};
}

function normalizedWords(value) {
  return String(value).replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().replace(/[_-]+/g, ' ');
}

function hasPositiveExecutionDescription(description) {
  const withoutNegatedPhrases = description.replace(
    /\b(?:does not|doesn't|do not|don't|never|cannot|can't|without)\s+(?:actually\s+)?(?:exec(?:ute|uting)?|run(?:ning)?|launch(?:ing)?|invok(?:e|ing)|evaluat(?:e|ing))\b.{0,50}?(?=\s+\b(?:and|but|however)\b|[.;!?]|$)/g,
    ' ',
  );
  return /\b(?:exec(?:ute|utes|uting)?|run(?:s|ning)?|launch(?:es|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?)\b.{0,50}\b(?:shell|bash|terminal|commands?|code|scripts?|powershell|expressions?|sql|subprocess)\b/.test(withoutNegatedPhrases);
}

function searchableToolText(tool) {
  return [tool.name, tool.description, tool.title, schemaText(inputSchema(tool))]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
}

function schemaHasExecutionInput(value, toolContext, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 5) return false;
  if (value.properties && typeof value.properties === 'object') {
    for (const [name, child] of Object.entries(value.properties)) {
      if (executionInputField(normalizedWords(name), child, toolContext)) return true;
      if (schemaHasExecutionInput(child, toolContext, depth + 1)) return true;
    }
  }
  if (value.items && schemaHasExecutionInput(value.items, toolContext, depth + 1)) return true;
  for (const keyword of ['anyOf', 'oneOf', 'allOf']) {
    if (Array.isArray(value[keyword]) && value[keyword].some(child => schemaHasExecutionInput(child, toolContext, depth + 1))) return true;
  }
  return false;
}

function usefulSchemaPattern(node) {
  return typeof node.pattern === 'string' && !['.*', '^.*$', '.+'].includes(node.pattern.trim());
}

function freeTextSchemaField(node) {
  if (!node || typeof node !== 'object') return false;
  const constrained = Array.isArray(node.enum) || Object.hasOwn(node, 'const') || usefulSchemaPattern(node);
  return (node.type === 'string' || node.type === undefined) && !constrained;
}

function executionInputField(name, node, toolContext) {
  if (!freeTextSchemaField(node)) return false;
  const strong = /^(cmd|python|shell|sql|eval|sql query|shell command|command text|source code|python code)$/.test(name);
  const ambiguous = /^(command|code|script|expression)$/.test(name);
  const fieldContext = normalizedWords(`${typeof node.description === 'string' ? node.description : ''} ${toolContext}`);
  const executableContext = /\b(?:run|runner|exec(?:ute|ution)?|shell|terminal|bash|powershell|subprocess|interpreter|evaluate|eval|source code|script|program|command)\b/.test(fieldContext);
  return strong || (ambiguous && executableContext);
}

function inferCapabilities(tool) {
  const text = searchableToolText(tool);
  const identity = [tool.name, tool.title].filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const description = typeof tool.description === 'string' ? normalizedWords(tool.description) : '';
  const toolContext = `${identity} ${description}`;
  const executionIdentity = /\b(shell|bash|terminal|exec(?:ute)?|subprocess|powershell|run code|eval)\b/.test(identity);
  const executionField = schemaHasExecutionInput(inputSchema(tool), toolContext);
  const executionDescription = hasPositiveExecutionDescription(description);
  const documentationIdentity = /\b(doc|docs|documentation|handbook|reference|catalog|list)\b/.test(identity);
  const documentationDescription = /\b(document(?:ation|ed)?|handbook|reference|catalog|guide|explains?|describes?|examples?)\b/.test(description);
  const matches = [
    ['secret_read', /\b(secret|credential|password|1password|onepassword|token|keychain|vault|api key|environment variable)\b/],
    ['network_egress', /\b(http|https|url|uri|fetch|request|browser|webhook|network|upload|email|slack|send|post message)\b/],
    ['destructive_action', /\b(delete|remove|destroy|drop|terminate|cancel|revoke|wipe|purge)\b/],
    ['financial_action', /\b(pay|payment|purchase|transfer|wire|trade|order)\b/],
    ['persistent_write', /\b(memory|remember|vector|database|datastore|store|save|persist|write record|write memory)\b/],
    ['privileged_action', /\b(admin|sudo|privilege|permission|iam|deploy|publish|merge|revoke|payment|transfer|delete)\b/],
    ['filesystem_access', /\b(file|filesystem|directory|folder|path|read file|write file)\b/],
  ];
  const capabilities = matches.filter(([, pattern]) => pattern.test(text)).map(([capability]) => capability);
  if (executionField || (executionIdentity && !(documentationIdentity && documentationDescription && !executionDescription)) || executionDescription) {
    capabilities.push('code_execution');
  }
  if (tool.annotations && tool.annotations.destructiveHint === true) capabilities.push('destructive_action', 'privileged_action');
  if (tool.annotations && tool.annotations.openWorldHint === true) capabilities.push('network_egress');
  return [...new Set(capabilities)].sort();
}

function semanticRisks(tool, artifact, toolPointer) {
  const schema = inputSchema(tool);
  const risks = [];
  const toolContext = [tool.name, tool.title, tool.description]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  function walk(node, pointer, propertyName = '') {
    if (!node || typeof node !== 'object') return;
    const description = typeof node.description === 'string' ? node.description.toLowerCase() : '';
    const label = `${propertyName.replace(/[_-]+/g, ' ')} ${description}`;
    const constrained = Array.isArray(node.enum) || Object.hasOwn(node, 'const') || usefulSchemaPattern(node);
    if ((node.type === 'string' || node.type === undefined) && !constrained) {
      const interpreterField = executionInputField(normalizedWords(propertyName), node, toolContext);
      if (interpreterField || /\b(sql|sql query|eval|expression|source code|script|shell command|command text)\b/.test(label)) {
        risks.push({ id: 'arbitrary_interpreter_input', reason: `${propertyName || 'input'} accepts unconstrained command, expression, or SQL text`, ref: ref(artifact, pointer) });
      }
      if (/\b(url|uri|endpoint|webhook|callback url|destination url)\b/.test(label)) {
        risks.push({ id: 'unvalidated_destination', reason: `${propertyName || 'input'} accepts a destination without an allowlist`, ref: ref(artifact, pointer) });
      }
    }
    if (node.properties && typeof node.properties === 'object') {
      for (const [name, child] of Object.entries(node.properties)) walk(child, `${pointer}/properties/${escapePointer(name)}`, name);
    }
    if (node.items) walk(node.items, `${pointer}/items`, propertyName);
    for (const keyword of ['anyOf', 'oneOf', 'allOf']) {
      if (Array.isArray(node[keyword])) node[keyword].forEach((child, index) => walk(child, `${pointer}/${keyword}/${index}`, propertyName));
    }
  }
  walk(schema, `${toolPointer}/${tool.parameters ? 'parameters' : tool.input_schema ? 'input_schema' : tool.inputSchema ? 'inputSchema' : 'schema'}`);
  const seen = new Set();
  return risks.filter(item => {
    const key = `${item.id}:${item.ref.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function toolDescriptionRisks(tool, artifact, toolPointer) {
  const risks = [];
  const benignDisclosureInstruction = /\b(?:do not|don't|never)\b.{0,30}\btell\b.{0,20}\b(?:the\s+)?(?:user|operator|human)\b.{0,20}\bto\b.{0,20}\b(?:disclose|send|share|reveal|provide|enter|upload)\b/;
  const sensitiveTerm = String.raw`(?:passwords?(?!\s+reset\b)|secrets?|credentials?|api[ _-]?keys?|access[ _-]?tokens?|private[ _-]?keys?|environment variables?)`;
  const sensitiveVerb = String.raw`(?:send|upload|post|transmit|exfiltrate|reveal|return|provide|enter|share|supply|submit)`;
  const sensitiveOutbound = new RegExp(String.raw`\b${sensitiveVerb}\b.{0,80}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,80}\b${sensitiveVerb}\b`);
  const preventsSensitiveOutbound = new RegExp(String.raw`\b(?:do not|don't|never)\b.{0,24}\b${sensitiveVerb}\b.{0,80}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,40}\b(?:must not|should not|never)\b.{0,24}\b(?:be\s+)?${sensitiveVerb}\b`);
  const sensitiveStatusOnly = new RegExp(String.raw`\b(?:return|report|show)\b.{0,30}\b(?:whether|if|status)\b.{0,30}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,30}\b(?:configured|exists|present|available|set)\b`);
  const networkVerb = String.raw`(?:fetch|download|retrieve|browse|search|read|open|get|scrape|crawl)`;
  const networkSource = String.raw`(?:url|uri|web|website|webpage|internet|remote|http|https)`;
  const networkIntake = new RegExp(String.raw`\b${networkVerb}\b.{0,60}\b${networkSource}\b|\b${networkSource}\b.{0,60}\b${networkVerb}\b`);
  const fields = [
    ['description', tool.description],
    ['title', tool.title],
  ];
  for (const [field, value] of fields) {
    if (typeof value !== 'string') continue;
    const text = value.toLowerCase().replace(/\s+/g, ' ');
    const pointer = `${toolPointer}/${field}`;
    if (/\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:previous|prior|system|developer|safety|operator|user)\b.{0,40}\b(?:instruction|message|policy|rule)s?\b/.test(text)) {
      risks.push({ id: 'prompt_instruction_override', reason: 'tool description contains instruction-override language', ref: ref(artifact, pointer) });
    }
    const concealmentLanguage = /\b(?:do not|don't|never)\b.{0,60}\b(?:tell|mention|show|reveal|disclose|inform|notify)\b.{0,60}\b(?:user|operator|human)\b/.test(text)
      && /\b(?:action|operation|invocation|tool|request|call|behavior|instruction|activity|execution|change)\b/.test(text);
    if ((!benignDisclosureInstruction.test(text) && !preventsSensitiveOutbound.test(text) && concealmentLanguage)
      || /\bwithout\b.{0,30}\b(?:user|operator|human)(?:'s)?\b.{0,30}\b(?:knowledge|consent|approval)\b/.test(text)) {
      risks.push({ id: 'prompt_concealed_behavior', reason: 'tool description asks that behavior be concealed from the operator', ref: ref(artifact, pointer) });
    }
    if (sensitiveOutbound.test(text) && !preventsSensitiveOutbound.test(text) && !sensitiveStatusOnly.test(text)) {
      risks.push({ id: 'prompt_sensitive_data_request', reason: 'tool description directs sensitive data into a tool result or transmission', ref: ref(artifact, pointer) });
    }
  }
  for (const [field, value] of [['name', tool.name], ...fields]) {
    if (typeof value !== 'string') continue;
    const text = normalizedWords(value).replace(/\s+/g, ' ');
    if (networkIntake.test(text)) {
      risks.push({ id: 'untrusted_network_fetch', reason: 'tool retrieves content from a network-controlled source', ref: ref(artifact, `${toolPointer}/${field}`) });
      break;
    }
  }
  return risks;
}

function normalizeTool(tool, index, artifact, basePointer, dialect, options = {}) {
  assertObject(tool, `${artifact.kind} tool ${index}`);
  if (typeof tool.name !== 'string' || !tool.name.trim()) throw new Error(`${artifact.kind} tool ${index}.name must be a non-empty string`);
  const extension = tool['x-backbond'];
  if (extension !== undefined) assertObject(extension, `${artifact.kind} tool ${index}.x-backbond`);
  const controls = options.canonical ? tool : (extension || {});
  const explicitCapabilities = validateCapabilities(controls.capabilities, `${artifact.kind} tool ${index}.capabilities`);
  const derivedCapabilities = [...new Set([...inferCapabilities(tool), ...(options.forceCapabilities || [])])].sort();
  const capabilities = [...new Set([...derivedCapabilities, ...explicitCapabilities])].sort();
  const toolPointer = options.pointerOverride || `${basePointer}/${index}`;
  const explicitTrust = controls.input_trust !== undefined;
  const inputTrust = explicitTrust
    ? validateEnum(controls.input_trust, INPUT_TRUST, `${artifact.kind} tool ${index}.input_trust`)
    : (options.canonical ? 'unknown' : 'mixed');
  const risks = [...semanticRisks(tool, artifact, toolPointer), ...toolDescriptionRisks(tool, artifact, toolPointer)];
  return {
    name: tool.name,
    dialect,
    capabilities,
    semantic_risks: risks,
    input_trust: inputTrust,
    approval: validateEnum(controls.approval !== undefined ? controls.approval : options.approval, APPROVAL, `${artifact.kind} tool ${index}.approval`),
    audit: validateEnum(controls.audit, AUDIT, `${artifact.kind} tool ${index}.audit`),
    provenance: {
      capabilities: Object.fromEntries(capabilities.map(capability => [capability, explicitCapabilities.includes(capability) ? 'explicit' : 'derived'])),
      input_trust: explicitTrust ? 'explicit' : (options.canonical ? 'unknown' : 'derived'),
      semantic_risks: risks.length ? 'derived' : 'none',
    },
    refs: {
      identity: ref(artifact, `${toolPointer}/name`),
      capabilities: ref(artifact, `${toolPointer}${options.canonical ? '/capabilities' : ''}`),
      input_trust: ref(artifact, `${toolPointer}${options.canonical ? '/input_trust' : ''}`),
      approval: ref(artifact, `${toolPointer}${options.canonical ? '/approval' : ''}`),
      audit: ref(artifact, `${toolPointer}${options.canonical ? '/audit' : ''}`),
    },
  };
}

function normalizeToolSchema(document, artifact) {
  if (document && document.protocol === 'backbond-tool-schema/v1') {
    assertObject(document, 'tool schema');
    if (!Array.isArray(document.tools)) throw new Error('backbond-tool-schema/v1 tools must be an array');
    artifact.dialect = 'backbond-tool-schema/v1';
    return document.tools.map((tool, index) => normalizeTool(tool, index, artifact, '/tools', artifact.dialect, { canonical: true }));
  }
  let tools;
  let basePointer;
  let dialect;
  if (Array.isArray(document)) { tools = document; basePointer = ''; }
  else if (document && Array.isArray(document.tools)) { tools = document.tools; basePointer = '/tools'; }
  else if (document && document.result && Array.isArray(document.result.tools)) { tools = document.result.tools; basePointer = '/result/tools'; dialect = 'mcp-tools-list/v1'; }
  else return null;
  if (!dialect && tools.length > 0 && tools.every(tool => tool && tool.type === 'function' && tool.function)) {
    dialect = 'openai-function-tools/v1';
    artifact.dialect = dialect;
    return tools.map((entry, index) => normalizeTool(entry.function, index, artifact, basePointer, dialect, { pointerOverride: `${basePointer}/${index}/function` }));
  }
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && tool.input_schema)) dialect = 'anthropic-tools/v1';
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && (tool.inputSchema || tool.parameters))) dialect = 'mcp-tools-list/v1';
  if (!dialect && tools.length === 0) dialect = 'generic-tool-list/v1';
  if (!dialect) return null;
  artifact.dialect = dialect;
  return tools.map((tool, index) => normalizeTool(tool, index, artifact, basePointer, dialect));
}

function normalizeOpenApi(document, artifact) {
  if (!document || typeof document !== 'object' || (!document.openapi && !document.swagger) || !document.paths) return null;
  const dialect = document.openapi ? `openapi/${document.openapi}` : `swagger/${document.swagger}`;
  artifact.dialect = dialect;
  const tools = [];
  const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);
  for (const [route, routeItem] of Object.entries(document.paths)) {
    if (!routeItem || typeof routeItem !== 'object') continue;
    for (const [method, operation] of Object.entries(routeItem)) {
      if (!methods.has(method.toLowerCase()) || !operation || typeof operation !== 'object') continue;
      const properties = {};
      for (const parameter of [...(routeItem.parameters || []), ...(operation.parameters || [])]) {
        if (!parameter || typeof parameter !== 'object' || !parameter.name) continue;
        properties[parameter.name] = parameter.schema || { type: parameter.type || 'string', description: parameter.description };
      }
      const requestContent = operation.requestBody && operation.requestBody.content;
      const requestSchema = requestContent && Object.values(requestContent).find(item => item && item.schema);
      if (requestSchema && requestSchema.schema && requestSchema.schema.properties) Object.assign(properties, requestSchema.schema.properties);
      const tool = {
        name: operation.operationId || `${method.toLowerCase()}_${route.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '')}`,
        description: [operation.summary, operation.description, `${method.toUpperCase()} ${route}`].filter(Boolean).join(' '),
        parameters: { type: 'object', properties },
      };
      const forced = ['network_egress'];
      if (method.toLowerCase() === 'delete') forced.push('destructive_action', 'privileged_action');
      tools.push(normalizeTool(tool, tools.length, artifact, `/paths/${escapePointer(route)}/${method}`, dialect, {
        pointerOverride: `/paths/${escapePointer(route)}/${method}`,
        forceCapabilities: forced,
      }));
    }
  }
  return tools;
}

function scopeIsWildcard(value) {
  if (value === true) return true;
  if (typeof value === 'string') return ['*', '**', '/*', '/', 'all', 'any'].includes(value.toLowerCase()) || /^[a-z]:[\\/]?$/i.test(value);
  if (Array.isArray(value)) return value.some(scopeIsWildcard);
  if (value && typeof value === 'object') return value.unrestricted === true;
  return false;
}

function validateScope(value, label) {
  if (value === undefined) return;
  if (typeof value === 'string') { if (!value.trim()) throw new Error(`${label} must not be empty`); return; }
  if (Array.isArray(value)) { if (value.some(item => typeof item !== 'string' || !item.trim())) throw new Error(`${label} must contain only non-empty strings`); return; }
  if (value && typeof value === 'object' && !Array.isArray(value) && value.unrestricted === true) return;
  throw new Error(`${label} must be a string array or {"unrestricted":true}`);
}

function emptyPermissionFacts() {
  return { input_trust: 'unknown', input_trust_ref: null, tools: [], wildcards: [], secret_access_unrestricted: false, network_egress_unrestricted: false, network_scope_observed: false };
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
      capabilities: validateCapabilities(controls.capabilities, `permissions.tools.${name}.capabilities`), semantic_risks: [],
      input_trust: validateEnum(controls.input_trust, INPUT_TRUST, `permissions.tools.${name}.input_trust`),
      approval: validateEnum(controls.approval, APPROVAL, `permissions.tools.${name}.approval`),
      audit: validateEnum(controls.audit, AUDIT, `permissions.tools.${name}.audit`),
      provenance: { capabilities: Object.fromEntries((controls.capabilities || []).map(item => [item, 'explicit'])), input_trust: controls.input_trust === undefined ? 'unknown' : 'explicit', semantic_risks: 'none' },
      refs: {
        identity: ref(artifact, `/tools/${escapePointer(name)}`), capabilities: ref(artifact, `/tools/${escapePointer(name)}/capabilities`),
        input_trust: ref(artifact, `/tools/${escapePointer(name)}/input_trust`), approval: ref(artifact, `/tools/${escapePointer(name)}/approval`), audit: ref(artifact, `/tools/${escapePointer(name)}/audit`),
      },
    });
  }
  const scopes = [['filesystem', 'read'], ['filesystem', 'write'], ['subprocess', 'allow'], ['credentials', 'read'], ['network', 'egress']];
  const wildcards = [];
  for (const [domain, field] of scopes) {
    const container = document[domain];
    if (container !== undefined) assertObject(container, `permissions.${domain}`);
    if (container) validateScope(container[field], `permissions.${domain}.${field}`);
    if (container && scopeIsWildcard(container[field])) wildcards.push({ domain, field, provenance: 'explicit', ref: ref(artifact, `/${domain}/${field}`) });
  }
  return {
    input_trust: inputTrust, input_trust_ref: ref(artifact, '/input_trust'), tools, wildcards,
    secret_access_unrestricted: wildcards.some(item => item.domain === 'credentials'),
    network_egress_unrestricted: wildcards.some(item => item.domain === 'network'),
    network_scope_observed: Boolean(document.network && document.network.egress !== undefined),
  };
}

function normalizeClaudeSettings(document, artifact) {
  if (artifact.adapter !== 'claude-code' || !document || typeof document !== 'object' || Array.isArray(document)) return null;
  artifact.dialect = 'claude-code-settings/v1';
  const permission = emptyPermissionFacts();
  const tools = [];
  if (document.permissions !== undefined) assertObject(document.permissions, 'Claude Code permissions');
  const controls = document.permissions || {};
  for (const field of ['allow', 'ask']) {
    if (controls[field] !== undefined && !Array.isArray(controls[field])) throw new Error(`Claude Code permissions.${field} must be an array`);
    if (Array.isArray(controls[field]) && controls[field].some(rule => typeof rule !== 'string' || !rule.trim())) {
      throw new Error(`Claude Code permissions.${field} must contain only non-empty strings`);
    }
  }
  if (controls.defaultMode !== undefined && typeof controls.defaultMode !== 'string') throw new Error('Claude Code permissions.defaultMode must be a string');
  const permissionObserved = Array.isArray(controls.allow) || Array.isArray(controls.ask) || controls.defaultMode !== undefined;
  for (const [field, approval] of [['allow', 'none'], ['ask', 'enforced']]) {
    if (!Array.isArray(controls[field])) continue;
    controls[field].forEach((rule, index) => {
      const name = rule.trim().split(/[(:]/, 1)[0].trim();
      if (!name) return;
      const pointer = `/permissions/${field}/${index}`;
      const bodyMatch = rule.trim().match(/^[^(]+\((.*)\)$/);
      const body = bodyMatch ? bodyMatch[1].trim() : '';
      const normalizedName = name.toLowerCase();
      const allInvocations = !bodyMatch || !body;
      const globalPath = allInvocations || scopeIsWildcard(body) || /^(?:\/{1,2}\*{1,2}|[a-z]:[\\/]\*{1,2})$/i.test(body);
      const forcedCapabilities = [];
      if (['read', 'edit', 'write'].includes(normalizedName)) forcedCapabilities.push('filesystem_access');
      if (normalizedName === 'bash') forcedCapabilities.push('code_execution');
      if (normalizedName === 'webfetch') forcedCapabilities.push('network_egress');
      tools.push(normalizeTool({ name, description: rule, inputSchema: { type: 'object' } }, index, artifact, `/permissions/${field}`, artifact.dialect, { pointerOverride: pointer, approval, forceCapabilities: forcedCapabilities }));
      if (normalizedName === 'bash' && (allInvocations || scopeIsWildcard(body))) permission.wildcards.push({ domain: 'subprocess', field: 'allow', provenance: 'derived', ref: ref(artifact, pointer) });
      if (normalizedName === 'read' && globalPath) permission.wildcards.push({ domain: 'filesystem', field: 'read', provenance: 'derived', ref: ref(artifact, pointer) });
      if (['edit', 'write'].includes(normalizedName) && globalPath) permission.wildcards.push({ domain: 'filesystem', field: 'write', provenance: 'derived', ref: ref(artifact, pointer) });
      if (normalizedName === 'webfetch' && (allInvocations || /^(?:domain\s*:\s*)?\*$/i.test(body))) {
        permission.wildcards.push({ domain: 'network', field: 'egress', provenance: 'derived', ref: ref(artifact, pointer) });
        permission.network_scope_observed = true;
      }
    });
  }
  if (controls.defaultMode === 'bypassPermissions') {
    permission.wildcards.push({ domain: 'subprocess', field: 'allow', provenance: 'derived', ref: ref(artifact, '/permissions/defaultMode') });
  }
  permission.secret_access_unrestricted = permission.wildcards.some(item => item.domain === 'credentials');
  permission.network_egress_unrestricted = permission.wildcards.some(item => item.domain === 'network');
  return {
    tools,
    permission,
    permissionObserved,
    gaps: tools.length ? [] : [gap('tool_schema', 'missing', 'BB-COV-CLAUDE-TOOLS-NOT-EXPORTED', 'Claude Code settings were found, but no allow/ask tool identities were exported', artifact)],
  };
}

function normalizeAgentConfig(document, artifact) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return null;
  const containers = [];
  if (document.mcpServers && typeof document.mcpServers === 'object') containers.push({ servers: document.mcpServers, pointer: '/mcpServers' });
  if (document.servers && typeof document.servers === 'object') containers.push({ servers: document.servers, pointer: '/servers' });
  if (document.mcp && document.mcp.servers && typeof document.mcp.servers === 'object') containers.push({ servers: document.mcp.servers, pointer: '/mcp/servers' });
  if (document.projects && typeof document.projects === 'object') {
    for (const [projectName, projectConfig] of Object.entries(document.projects)) {
      if (projectConfig && projectConfig.mcpServers && typeof projectConfig.mcpServers === 'object') {
        containers.push({ servers: projectConfig.mcpServers, pointer: `/projects/${escapePointer(projectName)}/mcpServers` });
      }
    }
  }
  if (!containers.length) return normalizeClaudeSettings(document, artifact);
  artifact.dialect = `${artifact.adapter || 'generic'}-mcp-config/v1`;
  const tools = [];
  const permission = emptyPermissionFacts();
  const gaps = [];
  const addWildcard = (domain, field, pointer) => permission.wildcards.push({ domain, field, provenance: 'derived', ref: ref(artifact, pointer) });
  const sandbox = document.sandbox || {};
  const filesystem = sandbox.filesystem || {};
  const network = sandbox.network || {};
  if (filesystem.allowRead !== undefined) validateScope(filesystem.allowRead, 'config sandbox.filesystem.allowRead');
  if (filesystem.allowWrite !== undefined) validateScope(filesystem.allowWrite, 'config sandbox.filesystem.allowWrite');
  if (scopeIsWildcard(filesystem.allowRead)) addWildcard('filesystem', 'read', '/sandbox/filesystem/allowRead');
  if (scopeIsWildcard(filesystem.allowWrite)) addWildcard('filesystem', 'write', '/sandbox/filesystem/allowWrite');
  if (network.allowedDomains !== undefined) {
    validateScope(network.allowedDomains, 'config sandbox.network.allowedDomains');
    permission.network_scope_observed = true;
  }
  if (scopeIsWildcard(network.allowedDomains)) addWildcard('network', 'egress', '/sandbox/network/allowedDomains');
  for (const container of containers) {
    for (const [serverName, server] of Object.entries(container.servers)) {
      if (!server || typeof server !== 'object') continue;
      const pointer = `${container.pointer}/${escapePointer(serverName)}`;
      const autoApprovedNames = [
        ...(Array.isArray(server.alwaysAllow) ? server.alwaysAllow : []),
        ...(Array.isArray(server.autoApprove) ? server.autoApprove : []),
      ].filter(item => typeof item === 'string' && item.trim());
      const approval = server.trust === true || server.autoApprove === true ? 'none' : undefined;
      const manifests = Array.isArray(server.tools) ? server.tools : Array.isArray(server.toolSchemas) ? server.toolSchemas : null;
      if (manifests) {
        manifests.forEach((tool, index) => tools.push(normalizeTool(tool, index, artifact, `${pointer}/tools`, artifact.dialect, { approval })));
      } else if (Array.isArray(server.includeTools) || autoApprovedNames.length) {
        const namedTools = [...new Set([...(Array.isArray(server.includeTools) ? server.includeTools : []), ...autoApprovedNames])];
        const namedPointer = Array.isArray(server.includeTools) ? 'includeTools' : Array.isArray(server.alwaysAllow) ? 'alwaysAllow' : 'autoApprove';
        namedTools.forEach((name, index) => {
          if (typeof name !== 'string' || !name.trim()) return;
          const namedApproval = autoApprovedNames.includes(name) ? 'none' : approval;
          tools.push(normalizeTool({ name, description: `Tool exported by MCP server ${serverName}`, inputSchema: { type: 'object' } }, index, artifact, `${pointer}/${namedPointer}`, artifact.dialect, { approval: namedApproval }));
        });
      } else {
        gaps.push(gap('tool_schema', 'missing', 'BB-COV-MCP-TOOLS-NOT-EXPORTED', `MCP server ${serverName} is configured, but its live tools are not exported`, artifact));
      }
      const serverArgs = Array.isArray(server.args) ? server.args.filter(item => typeof item === 'string') : [];
      const roleArgs = serverArgs.filter(item => /mcp|server|shell|bash|terminal|exec|fetch|browser|filesystem|database|postgres|mysql|sqlite|1password|onepassword|vault/i.test(item));
      const command = typeof server.command === 'string'
        ? server.command.trim().replace(/^["']|["']$/g, '').split(/[\\/]/).pop()
        : '';
      const roleText = `${serverName} ${command || ''} ${roleArgs.join(' ')}`;
      const forced = inferCapabilities({ name: serverName, description: roleText, inputSchema: { type: 'object' } });
      if (server.url || server.httpUrl) {
        forced.push('network_egress');
        permission.network_scope_observed = true;
        if (scopeIsWildcard(server.url || server.httpUrl)) addWildcard('network', 'egress', `${pointer}/${server.url ? 'url' : 'httpUrl'}`);
      }
      const serverDomains = server.allowedDomains !== undefined
        ? server.allowedDomains
        : server.network && server.network.allowedDomains;
      if (serverDomains !== undefined) {
        validateScope(serverDomains, `config MCP server ${serverName}.allowedDomains`);
        permission.network_scope_observed = true;
        if (scopeIsWildcard(serverDomains)) addWildcard('network', 'egress', `${pointer}/allowedDomains`);
      } else if (forced.includes('network_egress') && /\b(fetch|browser|web|http|request)\b/i.test(normalizedWords(roleText))) {
        permission.network_scope_observed = true;
        addWildcard('network', 'egress', pointer);
      }
      const envKeys = server.env && typeof server.env === 'object' ? Object.keys(server.env) : [];
      if (envKeys.some(key => /token|secret|password|credential|api.?key/i.test(key))) {
        gaps.push(gap('permissions', 'insufficient_evidence', 'BB-COV-MCP-CREDENTIAL-EXPOSURE', `MCP server ${serverName} has credential-shaped environment names, but tool access to their values is not observable`, artifact));
      }
      if (forced.length && !manifests && !Array.isArray(server.includeTools) && !autoApprovedNames.length) {
        tools.push(normalizeTool({ name: `mcp_server_${serverName}`, description: `Configured MCP server ${serverName}`, inputSchema: { type: 'object' } }, tools.length, artifact, pointer, artifact.dialect, { pointerOverride: pointer, forceCapabilities: forced, approval }));
      }
      if (forced.includes('filesystem_access') && serverArgs.some(scopeIsWildcard)) {
        addWildcard('filesystem', 'read', `${pointer}/args`);
        if (!serverArgs.some(item => /^(?:--)?read[-_]?only(?:=true)?$/i.test(item))) addWildcard('filesystem', 'write', `${pointer}/args`);
      }
    }
  }
  permission.secret_access_unrestricted = permission.wildcards.some(item => item.domain === 'credentials');
  permission.network_egress_unrestricted = permission.wildcards.some(item => item.domain === 'network');
  const permissionObserved = permission.wildcards.length > 0
    || permission.network_scope_observed
    || tools.some(tool => tool.approval !== 'unknown');
  return { tools, permission, permissionObserved, gaps };
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
      name: event.tool, capabilities: validateCapabilities(event.capabilities, `trace event ${index}.capabilities`), semantic_risks: [],
      input_trust: validateEnum(event.input_trust, INPUT_TRUST, `trace event ${index}.input_trust`), approval: validateEnum(event.approval, APPROVAL, `trace event ${index}.approval`), audit: validateEnum(event.audit, AUDIT, `trace event ${index}.audit`),
      provenance: { capabilities: Object.fromEntries((event.capabilities || []).map(item => [item, 'explicit'])), input_trust: event.input_trust === undefined ? 'unknown' : 'explicit', semantic_risks: 'none' },
      refs: { identity: ref(artifact, `/events/${index}/tool`), capabilities: ref(artifact, `/events/${index}/capabilities`), input_trust: ref(artifact, `/events/${index}/input_trust`), approval: ref(artifact, `/events/${index}/approval`), audit: ref(artifact, `/events/${index}/audit`) },
    });
  });
  return calls;
}

function otelAttributeMap(attributes) {
  const result = {};
  for (const attribute of attributes || []) {
    if (!attribute || !attribute.key || !attribute.value) continue;
    const value = attribute.value;
    result[attribute.key] = value.stringValue ?? value.boolValue ?? value.intValue ?? value.doubleValue ?? null;
  }
  return result;
}

function normalizeOtel(document, artifact) {
  const resourceSpans = document && (document.resourceSpans || document.resource_spans);
  if (!Array.isArray(resourceSpans)) return null;
  artifact.dialect = 'opentelemetry-otlp-json/v1';
  const tools = [];
  resourceSpans.forEach((resource, resourceIndex) => {
    const scopes = resource.scopeSpans || resource.scope_spans || resource.instrumentationLibrarySpans || [];
    scopes.forEach((scope, scopeIndex) => (scope.spans || []).forEach((span, spanIndex) => {
      const attrs = otelAttributeMap(span.attributes);
      const operation = attrs['gen_ai.operation.name'] || attrs['gen_ai.operation_name'];
      const toolName = attrs['gen_ai.tool.name'] || attrs['gen_ai.tool_name'] || attrs['tool.name'];
      if (!toolName && !/tool/i.test(span.name || '') && !/execute_tool|tool_call/i.test(operation || '')) return;
      const name = String(toolName || span.name || `tool_span_${spanIndex}`);
      const pointer = `/resourceSpans/${resourceIndex}/scopeSpans/${scopeIndex}/spans/${spanIndex}`;
      tools.push(normalizeTool({ name, description: String(span.name || ''), inputSchema: { type: 'object' } }, tools.length, artifact, pointer, artifact.dialect, { pointerOverride: pointer }));
    }));
  });
  return tools;
}

function escapePointer(value) { return String(value).replace(/~/g, '~0').replace(/\//g, '~1'); }

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
  return refs.flat().filter(Boolean).filter(item => {
    const key = `${item.artifact_kind}:${item.artifact_name}:${item.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mergeToolFacts(sources, globalInputTrust) {
  const grouped = new Map();
  for (const source of sources) { if (!grouped.has(source.name)) grouped.set(source.name, []); grouped.get(source.name).push(source); }
  return [...grouped.entries()].map(([name, entries]) => {
    const capabilities = [...new Set(entries.flatMap(entry => entry.capabilities))].sort();
    const semantic = entries.flatMap(entry => entry.semantic_risks || []);
    const inventoryObservations = entries.map(entry => {
      const identity = entry.refs && entry.refs.identity;
      const inventory = identity ? `${identity.artifact_kind}:${identity.artifact_name}` : 'unknown';
      return {
        inventory,
        capabilities: [...entry.capabilities],
        semantic_risks: [...(entry.semantic_risks || [])],
        input_trust: mergeTrust([entry.input_trust], globalInputTrust),
        refs: entry.refs,
      };
    });
    return {
      name, capabilities, semantic_risks: semantic,
      inventory_observations: inventoryObservations,
      input_trust: mergeTrust(entries.map(entry => entry.input_trust), globalInputTrust),
      approval: mergeApproval(entries.map(entry => entry.approval)), audit: mergeAudit(entries.map(entry => entry.audit)),
      provenance: {
        capabilities: Object.fromEntries(capabilities.map(capability => [capability, entries.some(entry => entry.provenance && entry.provenance.capabilities[capability] === 'explicit') ? 'explicit' : 'derived'])),
        input_trust: entries.some(entry => entry.provenance && entry.provenance.input_trust === 'explicit') ? 'explicit' : entries.some(entry => entry.provenance && entry.provenance.input_trust === 'derived') ? 'derived' : 'unknown',
        semantic_risks: semantic.length ? 'derived' : 'none',
      },
      refs: {
        identity: uniqueRefs(entries.map(entry => entry.refs.identity)), capabilities: uniqueRefs(entries.filter(entry => entry.capabilities.length).map(entry => entry.refs.capabilities)),
        input_trust: uniqueRefs(entries.filter(entry => entry.input_trust !== 'unknown').map(entry => entry.refs.input_trust)), approval: uniqueRefs(entries.filter(entry => entry.approval !== 'unknown').map(entry => entry.refs.approval)), audit: uniqueRefs(entries.filter(entry => entry.audit !== 'unknown').map(entry => entry.refs.audit)),
      },
    };
  }).sort((a, b) => a.name.localeCompare(b.name));
}

function gap(kind, status, code, message, artifact = null) {
  return { code, artifact_kind: kind, status, message, artifact_name: artifact ? artifact.name : null };
}

function mergePermissions(items) {
  if (!items.length) return emptyPermissionFacts();
  return {
    input_trust: mergeTrust(items.map(item => item.input_trust)),
    input_trust_ref: items.find(item => item.input_trust_ref)?.input_trust_ref || null,
    tools: items.flatMap(item => item.tools), wildcards: items.flatMap(item => item.wildcards),
    secret_access_unrestricted: items.some(item => item.secret_access_unrestricted),
    network_egress_unrestricted: items.some(item => item.network_egress_unrestricted),
    network_scope_observed: items.some(item => item.network_scope_observed),
  };
}

function collectEvidence(options = {}) {
  const sources = [];
  if (options.toolSchemaPath) sources.push({ kind: 'tool_schema', path: options.toolSchemaPath });
  if (options.permissionsPath) sources.push({ kind: 'permissions', path: options.permissionsPath });
  if (options.tracePath) sources.push({ kind: 'trace', path: options.tracePath });
  for (const item of options.artifactPaths || []) sources.push(item);
  const loadedSources = sources.map(item => readJsonArtifact(item.kind || 'config', item.path, item.adapter || null));
  for (const item of options.documents || []) loadedSources.push(memoryArtifact(item.kind || 'tool_schema', item.name || '<memory>', item.document, item.raw, item.adapter || null));
  const totals = new Map();
  for (const loaded of loadedSources) {
    const key = `${loaded.metadata.kind}:${loaded.metadata.name}`;
    totals.set(key, (totals.get(key) || 0) + 1);
  }
  const ordinals = new Map();
  for (const loaded of loadedSources) {
    const key = `${loaded.metadata.kind}:${loaded.metadata.name}`;
    if (totals.get(key) <= 1) continue;
    const ordinal = (ordinals.get(key) || 0) + 1;
    ordinals.set(key, ordinal);
    loaded.metadata.name = `${loaded.metadata.name}#${ordinal}`;
  }

  const artifacts = [];
  const coverageGaps = [];
  const toolSources = [];
  const permissionSources = [];
  let toolEvidenceSeen = false;
  let permissionEvidenceSeen = false;
  let traceEvidenceSeen = false;

  for (const loaded of loadedSources) {
    const { document, metadata } = loaded;
    let recognized = false;
    const canonicalPermissions = normalizePermissions(document, metadata);
    if (canonicalPermissions) { permissionSources.push(canonicalPermissions); permissionEvidenceSeen = true; recognized = true; }
    if (!recognized) {
      const canonicalTrace = normalizeTrace(document, metadata);
      const otelTrace = canonicalTrace === null ? normalizeOtel(document, metadata) : null;
      if (canonicalTrace !== null || otelTrace !== null) {
        toolSources.push(...(canonicalTrace || otelTrace)); traceEvidenceSeen = true; recognized = true;
      }
    }
    if (!recognized) {
      const schema = normalizeToolSchema(document, metadata);
      const openapi = schema === null ? normalizeOpenApi(document, metadata) : null;
      if (schema !== null || openapi !== null) { toolSources.push(...(schema || openapi)); toolEvidenceSeen = true; recognized = true; }
    }
    if (!recognized) {
      const config = normalizeAgentConfig(document, metadata);
      if (config) {
        toolSources.push(...config.tools); permissionSources.push(config.permission); coverageGaps.push(...config.gaps);
        toolEvidenceSeen = config.tools.length > 0 || toolEvidenceSeen;
        permissionEvidenceSeen = config.permissionObserved === true || permissionEvidenceSeen;
        recognized = true;
      }
    }
    if (!recognized) {
      metadata.dialect = 'unsupported';
      coverageGaps.push(gap(metadata.kind, 'unsupported', `BB-COV-UNSUPPORTED-${metadata.kind.toUpperCase()}`, `${metadata.kind} JSON does not match a supported dialect`, metadata));
    }
    artifacts.push(metadata);
  }

  if (!toolEvidenceSeen) coverageGaps.push(gap('tool_schema', 'missing', 'BB-COV-MISSING-TOOL_SCHEMA', 'No live tool schema or recognized tool manifest was observed'));
  if (!permissionEvidenceSeen) coverageGaps.push(gap('permissions', 'missing', 'BB-COV-MISSING-PERMISSIONS', 'No supported approval or permission map was observed'));
  if (!traceEvidenceSeen) coverageGaps.push(gap('trace', 'missing', 'BB-COV-MISSING-TRACE', 'No supported runtime trace was observed'));
  const permissions = mergePermissions(permissionSources);
  const facts = {
    tools: mergeToolFacts([...toolSources, ...permissions.tools], permissions.input_trust),
    global_input_trust: permissions.input_trust, global_input_trust_ref: permissions.input_trust_ref,
    wildcards: permissions.wildcards, secret_access_unrestricted: permissions.secret_access_unrestricted,
    network_egress_unrestricted: permissions.network_egress_unrestricted, network_scope_observed: permissions.network_scope_observed,
  };
  return {
    protocol: EVIDENCE_PROTOCOL, collected_at: (options.now || new Date()).toISOString(),
    artifacts: artifacts.sort((a, b) => `${a.kind}:${a.name}`.localeCompare(`${b.kind}:${b.name}`)), coverage_gaps: coverageGaps,
    discovery: options.discovery ? {
      protocol: options.discovery.protocol,
      scanned_locations: options.discovery.scanned_locations,
      files: options.discovery.files.map(item => ({ name: path.basename(item.path), adapter: item.adapter, location: item.location })),
      instruction_files: options.discovery.instruction_files.map(item => path.basename(item)),
    } : null,
    facts,
  };
}

function publicEvidence(evidence) {
  return {
    protocol: evidence.protocol, collected_at: evidence.collected_at, artifacts: evidence.artifacts,
    discovery: evidence.discovery, coverage_gaps: evidence.coverage_gaps,
    observations: {
      tool_count: evidence.facts.tools.length,
      tools: evidence.facts.tools.map(tool => ({ name: tool.name, capabilities: tool.capabilities, semantic_risks: tool.semantic_risks.map(item => item.id), input_trust: tool.input_trust, approval: tool.approval, audit: tool.audit, provenance: tool.provenance })),
      wildcard_permission_count: evidence.facts.wildcards.length,
    },
  };
}

module.exports = {
  ARTIFACT_KINDS, CAPABILITIES, EVIDENCE_PROTOCOL, MAX_ARTIFACT_BYTES,
  collectEvidence, inferCapabilities, publicEvidence, readJsonArtifact, semanticRisks,
};
