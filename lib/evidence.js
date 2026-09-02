'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256 } = require('./canonical.js');

const EVIDENCE_PROTOCOL = 'backbond-scan-evidence/v1';
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_SCHEMA_ANALYSIS_DEPTH = 64;
const MAX_SCHEMA_ANALYSIS_NODES = 10000;
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

const INPUT_SCHEMA_KEYS = ['parameters', 'input_schema', 'inputSchema', 'schema'];

function inputSchemaEntries(tool) {
  return INPUT_SCHEMA_KEYS
    .filter(key => Object.prototype.hasOwnProperty.call(tool, key))
    .map(key => [key, tool[key]]);
}

function inputSchema(tool) {
  const entry = inputSchemaEntries(tool).find(([, value]) => value && typeof value === 'object' && !Array.isArray(value));
  return entry ? entry[1] : {};
}

function schemaHasReference(value, depth = 0) {
  if (!value || typeof value !== 'object') return false;
  if (depth > 8) return true;
  if (Array.isArray(value)) return value.some(item => schemaHasReference(item, depth + 1));
  if (Object.prototype.hasOwnProperty.call(value, '$ref')) return true;
  return Object.values(value).some(item => schemaHasReference(item, depth + 1));
}

const OPAQUE_SCHEMA_BRANCHES = new Set([
  'patternProperties', 'dependentSchemas', 'if', 'then', 'else', 'contains',
  'prefixItems', 'unevaluatedProperties', 'contentSchema', 'dependencies',
  'additionalItems', 'unevaluatedItems', 'not', 'propertyNames', '$defs', 'definitions',
]);

function schemaHasOpaqueBranch(value, depth = 0) {
  if (!value || typeof value !== 'object') return false;
  if (depth > 8) return true;
  if (Array.isArray(value)) return value.some(item => schemaHasOpaqueBranch(item, depth + 1));
  if (Object.keys(value).some(key => OPAQUE_SCHEMA_BRANCHES.has(key))) return true;
  if (value.additionalProperties && typeof value.additionalProperties === 'object') return true;
  return Object.values(value).some(item => schemaHasOpaqueBranch(item, depth + 1));
}

function hasInputSchema(tool) {
  const entries = inputSchemaEntries(tool);
  if (entries.length !== 1) return false;
  const schema = entries[0][1];
  return Boolean(schema && typeof schema === 'object' && !Array.isArray(schema)
    && schema.type === 'object'
    && schema.properties && typeof schema.properties === 'object' && !Array.isArray(schema.properties)
    && !schemaHasReference(schema)
    && !schemaHasOpaqueBranch(schema));
}

function normalizedWords(value) {
  return String(value)
    .replace(/[’‘]/g, "'")
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ');
}

function normalizedIdentifierReference(value) {
  return normalizedWords(value).replace(/[.:]+/g, ' ').replace(/\s+/g, ' ').trim();
}

function withoutExecutionActionModifiers(value) {
  return String(value).replace(
    /\b(exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b\s*,\s*([^,.;!?]{1,40})\s*,\s*/g,
    (match, action, modifier) => /\b(?:not|never|without|cannot|can't|doesn't|does\s+not|do\s+not|don't)\b/.test(modifier)
      || /\b(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b/.test(modifier)
      ? match
      : `${action} `,
  );
}

function withoutContrastedExecution(value) {
  const action = String.raw`(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)`;
  const language = String.raw`(?:shell|bash|terminal|commands?|code|scripts?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?)`;
  return String(value)
    .replace(
      new RegExp(String.raw`\b(?:rather\s+than|instead\s+of)\s+${action}\b[^,.;!?]{0,40}?\b(${language})\b[^,.;!?]{0,30}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or)\b|[.;!?]|$)`, 'g'),
      '. $1',
    )
    .replace(
      new RegExp(String.raw`\b(?:rather\s+than|instead\s+of)\s+${action}\b[^.!?;]{0,60}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or)\b|[.;!?]|$)`, 'g'),
      ' ',
    );
}

function withoutHypotheticalExecution(value) {
  return String(value)
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b[^,.;!?]{0,40}?\b(?:can|could|may|might|would)\s+be\s+(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/g,
      '. $1',
    )
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+(?:(?:(?:the|an?)\s+)?(?:(?:external|remote)\s+)?(?:runtime|service|tool|worker|component)|another\s+(?:runtime|service|tool|worker|component)|[a-z][a-z0-9]*(?:[.:][a-z0-9]+)+)\s+(?:can|could|may|might|would)\s+(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,40}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b/g,
      '. $1',
    )
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+((?:(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/g,
      '. $1',
    )
    .replace(
      /\b(?:checks?|determines?|assesses?|tests?|reports?|verif(?:y|ies|ied|ying))\s+(?:whether|if)\s+(quer(?:y|ies))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\b/g,
      '. $1',
    );
}

function withoutDocumentationExecutionExamples(value) {
  return String(value)
    .replace(
      /\b(?:examples?\s+(?:showing|demonstrating)\s+how\s+to|tutorial\s+(?:(?:about|on)|(?:showing|explaining|describing)\s+how\s+to)|walkthrough\s+(?:showing|explaining|describing)\s+how\s+to|guide\s+to|instructions?\s+for|(?:reference|readme|quickstart)\s+(?:showing|explaining|describing)\s+how\s+to|(?:documentation|handbook)\s+(?:on|for|about)|(?:explains?|describes?)\s+how\s+to|shows?\s+how\s+to)\s+(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,50}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|quer(?:y|ies)|(?:duckdb|postgres(?:ql)?|mysql|sqlite|sql\s+server)\s+quer(?:y|ies)))\b/gi,
      '. $1',
    )
    .replace(
      /\b(?:(?:an?\s+)?(?:documentation|reference|handbook|readme|quickstart|guide)\s+)?(?:explains?|describes?|shows?|explaining|describing|showing)\s+how\s+((?:(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/gi,
      '. $1',
    )
    .replace(
      /\b(?:(?:an?\s+)?(?:documentation|reference|handbook|readme|quickstart|guide)\s+)?(?:explains?|describes?|shows?|explaining|describing|showing)\s+how\s+(quer(?:y|ies))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\b/gi,
      '. $1',
    );
}

function withoutNegatedExecution(value) {
  return withoutHypotheticalExecution(withoutContrastedExecution(withoutExecutionActionModifiers(value)))
    .replace(
      /\b(?:(?:does\s+not|doesn't|do\s+not|don't|never|cannot|can\s+not|can't|without|isn't|aren't|wasn't|weren't|won't|wouldn't|shouldn't|couldn't)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?|(?:will|must|may|can|could|would|should|is|are|was|were)\s+(?:not|never)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?)(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,50}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b[^,.;!?]{0,30}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or\s+instead|rather)\b|[.;!?]|$)/g,
      '. $1',
    )
    .replace(
      /\b(?:(?:does\s+not|doesn't|do\s+not|don't|never|cannot|can\s+not|can't|without|isn't|aren't|wasn't|weren't|won't|wouldn't|shouldn't|couldn't)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?|(?:will|must|may|can|could|would|should|is|are|was|were)\s+(?:not|never)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?)(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^.!?;]{0,60}?(?=\s*,|\s+\b(?:and|but|however|yet|while|although|or\s+instead|rather)\b|[.;!?]|$)/g,
      ' ',
    )
    .replace(/\bno\s+(?:other\s+|target\s+)?(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python|javascript|java\s+script|wolfram\s+language|sql|hogql|queries?)\s+(?:execution|(?:(?:is|are|will|can|may|must)\s+(?:be\s+)?)?(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned))\b/g, ' ')
    .replace(/\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python|javascript|wolfram\s+language|sql|hogql|queries?))\b(?:\s*,?\s*(?:which|that|it))?\s+(?:(?:isn't|aren't|wasn't|weren't|won't|wouldn't|shouldn't|couldn't|can't|cannot)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?|(?:is|are|was|were|will|can|could|would|may|must|should)\s+(?:not|never)\s+(?:(?:ever|(?!(?:not|never)\b)[a-z]+ly)\s+){0,2}(?:be\s+)?)(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b/g, '. $1');
}

function withoutNominalExecutionTerms(value) {
  return String(value)
    .replace(/\bpoint\s+(?:(?:your|the)\s+)?code\b[^.;!?]{0,50}\brun\s+it\b/g, ' ')
    .replace(/\bshell\s+(?:is\s+)?available\b[^.;!?]{0,50}\brun\s+`?curl\b[^.;!?]*/g, ' ')
    .replace(/\b(?:returns?|provides?)\s+instructions?\b[^.;!?]{0,100}\b(?:curl\s+)?commands?\b[^.;!?]{0,40}\b(?:for\s+(?:the\s+)?user\s+to\s+run|to\s+run)\b/g, ' ')
    .replace(/\bhand\s+the\s+command\s+to\s+(?:the\s+)?user\s+to\s+run\b[^.;!?]*/g, ' ')
    .replace(/\b(?:returns?|provides?)\b[^.;!?]{0,40}\bchecklist\b[^.;!?]{0,100}\bcode\b[^.;!?]{0,50}\brun\s+builds?\b/g, ' ')
    .replace(/\b(?:is\s+|are\s+|was\s+|were\s+)?(?:not|never)\s+(?:an?|the)\s+commands?\s+to\s+run\b/g, ' ')
    .replace(/\b(?:newly|recently|freshly)\s+launched\b/g, ' ')
    .replace(/\b(?:a|the)\s+spawn\b/g, ' ')
    .replace(/\b(?:(?:federal\s+)?grant|security|partnership|assistance|fitness|community|equity\s+offering|atm)\s+programs?\b/g, ' ');
}

function executionDescriptionSignals(description) {
  const withoutNegatedPhrases = withoutNominalExecutionTerms(withoutNegatedExecution(description));
  const active = /\b(?:exec(?:ute|utes|uting)?|run(?:s|ning)?|launch(?:es|ing)?|invoke(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)\b[^,.;!?]{0,50}\b(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess)\b/;
  const passive = /(?:^|[.!?;]\s*)(?:(?:the|an?)\s+)?(?:(?:user[- ]supplied|model[- ]generated|supplied|arbitrary|raw|input)\s+){0,3}\b(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess)\b[^,.;!?]{0,30}\b(?:is|are|can be|will be|may be|must be)\s+(?:exec(?:ute|uted)?|run|launched|invoked|interpreted|spawned)\b/;
  const query = /\b(?:exec(?:ute|utes|uting)?|run(?:s|ning)?|evaluate(?:s|d|ing)?)\b[^,.;!?]{0,50}\b(?:expressions?|sql|queries?)\b|\b(?:expressions?|sql|queries?)\b[^,.;!?]{0,30}\b(?:is|are|can be|will be|may be|must be)\s+(?:executed|run|evaluated)\b/;
  return {
    active: active.test(withoutNegatedPhrases),
    passive: passive.test(withoutNegatedPhrases),
    query: query.test(withoutNegatedPhrases),
  };
}

function searchableToolText(tool) {
  return [tool.name, tool.description, tool.title, schemaText(inputSchema(tool))]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
}

function schemaHasExecutionInput(value, executionContext, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 5) return false;
  if (value.properties && typeof value.properties === 'object') {
    for (const [name, child] of Object.entries(value.properties)) {
      if (executionInputField(normalizedWords(name), child, executionContext)) return true;
      if (schemaHasExecutionInput(child, executionContext, depth + 1)) return true;
    }
  }
  if (value.items && schemaHasExecutionInput(value.items, executionContext, depth + 1)) return true;
  for (const keyword of ['anyOf', 'oneOf', 'allOf']) {
    if (Array.isArray(value[keyword]) && value[keyword].some(child => schemaHasExecutionInput(child, executionContext, depth + 1))) return true;
  }
  return false;
}

function usefulSchemaPattern(node) {
  return typeof node.pattern === 'string' && !['.*', '^.*$', '.+'].includes(node.pattern.trim());
}

function identifierCharacterClass(body) {
  if (!body || body.startsWith('^')) return false;
  let grammar = body
    .replace(/(?:A-Z|a-z|0-9)/g, 'R')
    .replace(/\\[wd._-]/g, 'A');
  if (grammar.includes('\\')) return false;
  if (grammar.slice(1, -1).includes('-')) return false;
  grammar = grammar.replace(/^-|-$/g, 'L');
  return /^[A-Za-z0-9_.]+$/.test(grammar);
}

function executionPatternConstrainsInput(pattern) {
  if (typeof pattern !== 'string') return false;
  const compact = pattern.trim();
  if (!compact) return false;
  if (!(compact.startsWith('^') && compact.endsWith('$'))) return false;
  try {
    new RegExp(compact);
  } catch {
    return false;
  }

  let grammar = compact.slice(1, -1);
  if (!grammar) return false;
  grammar = grammar.replace(/\[[^\]]*\]/g, characterClass => {
    const body = characterClass.slice(1, -1);
    return identifierCharacterClass(body) ? 'A' : '!';
  });
  grammar = grammar
    .replace(/\\[wd._-]/g, 'A')
    .replace(/\{\d+(?:,\d*)?\}/g, '');
  return /^[A-Za-z0-9_+*?-]+$/.test(grammar);
}

function freeTextSchemaField(node) {
  if (!node || typeof node !== 'object') return false;
  const constrained = Array.isArray(node.enum)
    || Object.hasOwn(node, 'const')
    || executionPatternConstrainsInput(node.pattern);
  return (node.type === 'string' || node.type === undefined) && !constrained;
}

function directInterpreterExecutionContext(value, identityAliases = []) {
  const text = withoutNominalExecutionTerms(withoutNegatedExecution(normalizedWords(value)));
  const action = String.raw`(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|evaluate(?:s|d|ing)?|invoke(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?|ejecut(?:a|ar)|exécute(?:r|s)?)`;
  const language = String.raw`(?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python|javascript|wolfram language|sql|hogql|(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db))`;
  const activeLanguage = String.raw`(?:shell|bash|terminal|commands?|code|scripts?|(?:(?:caller|user)[- ]supplied|supplied|arbitrary|raw|executable)\s+programs?|binaries?|powershell|subprocess|python|javascript|wolfram language|sql|hogql|(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db))`;
  const roleSubjects = identityAliases
    .map(normalizedIdentifierReference)
    .map(alias => {
      const words = alias.split(/\s+/).filter(Boolean);
      const role = words.at(-1);
      return /^(?:tool|service|component|validator|runner|executor|interpreter|kernel|worker|processor|handler)$/.test(role)
        ? role
        : '';
    })
    .filter(Boolean)
    .map(role => role.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const roleSubject = roleSubjects.length > 0 ? `|(?:the\\s+)?(?:${[...new Set(roleSubjects)].join('|')})` : '';
  const selfSubject = String.raw`(?:(?:this|the)\s+(?:tool|service|component)|it|we${roleSubject})`;
  const executionAdverb = String.raw`(?:(?!(?:not|never)\b)[a-z]+ly\s+)`;
  const executionObject = String.raw`(?:it|them|the\s+(?:resulting\s+)?(?:query|statement|code|script|command|expression|input|payload)|(?:the\s+)?(?:input|payload))`;
  const selfModal = String.raw`(?:(?:may|will|can|could|would|must)\s+)?`;
  const executionTemporal = String.raw`(?:(?:later|also)\s+)?`;
  const direct = new RegExp(String.raw`\b${action}\b[^,.;!?]{0,30}\b${activeLanguage}\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^,.;!?]{0,20}\b(?:is|are|can be|will be|may be|must be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^,.;!?]{0,50}(?:[,;]\s*(?:(?:and\s+then|and|but|however|yet|then|later|before|after|followed\s+by)\s+)?|\s+\b(?:and\s+then|and|but|however|yet|then|later|before|after|followed\s+by)\s+)(?:${selfSubject}\s+)?${selfModal}${executionTemporal}(?:${executionAdverb}){0,2}${action}\s+${executionObject}\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^.;!?]{0,60}[.;!?]\s*(?:(?:(?:when|if)\s+[a-z]+(?:\s+[a-z]+){0,3}|(?:afterward|subsequently|later|however|yet))\s*,?\s*)?(?:${selfSubject}\s+)?(?:then\s+)?${selfModal}${executionTemporal}(?:${executionAdverb}){0,2}${action}\s+${executionObject}\b`).test(text)
    || new RegExp(String.raw`\b${language}\b[^,.;!?]{0,20}\b(?:executes|runs|launches|evaluates|invokes|interprets|spawns)\b[^,.;!?]{0,30}\b(?:locally|in\s+(?:this|the)\s+(?:tool|service|component)|by\s+(?:this|the)\s+(?:tool|service|component))\b`).test(text)
    || new RegExp(String.raw`\b${action}\b[^,.;!?]{0,50}\b(?:the\s+|an?\s+)?(?:caller[- ]supplied|user[- ]supplied|supplied|raw)\s+(?:quer(?:y|ies)\b[^,.;!?]{0,30}\b(?:database|db)|(?:database|db)\s+quer(?:y|ies))\b`).test(text)
    || new RegExp(String.raw`\b${action}\b[^,.;!?]{0,50}\b(?:the\s+|an?\s+)?(?:database|db)\s+quer(?:y|ies)\b(?:\s+(?:supplied|provided)\s+by\s+(?:the\s+)?(?:caller|user))?`).test(text)
    || new RegExp(String.raw`\b${action}\b[^,.;!?]{0,50}\b(?:the\s+|an?\s+)?quer(?:y|ies)\b\s+(?:supplied|provided)\s+by\s+(?:the\s+)?(?:caller|user)\b[^,.;!?]{0,30}\b(?:database|db)\b`).test(text)
    || new RegExp(String.raw`\b(?:the\s+)?(?:(?:caller[- ]supplied|user[- ]supplied|supplied|provided)\s+)?quer(?:y|ies)\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\b`).test(text)
    || new RegExp(String.raw`\b(?:the\s+|an?\s+)?(?:caller[- ]supplied|user[- ]supplied|supplied|raw)\s+(?:database|db)\s+quer(?:y|ies)\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b`).test(text)
    || new RegExp(String.raw`\b(?:(?:(?:the|every)\s+)?(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)\s+against\s+(?:the\s+)?(?:database|db))\b[^,.;!?]{0,30}\b(?:is|are|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b`).test(text);
  return direct;
}

function executionToolContext(toolContext, toolIdentity = '', identityAliases = []) {
  const text = normalizedWords(toolContext);
  const identity = normalizedWords(toolIdentity);
  const normalizedAliases = new Set(identityAliases.map(normalizedIdentifierReference).filter(alias => alias && alias.length <= 160));
  const attributionText = withoutNegatedExecution(text);
  let aliasAttribution = false;
  if (normalizedAliases.size > 0) {
    const attributionPattern = /\b(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\s+(?:by|via|through)\s+(?:`([^`]{1,160})`|([a-z][a-z0-9]*(?:[._:-][a-z0-9]+)+)|([^`.,;!?]{1,160}))/g;
    for (const match of attributionText.matchAll(attributionPattern)) {
      const target = normalizedIdentifierReference((match[1] || match[2] || match[3]).replace(
        /\s+\b(?:before|after|then|and|but|while|when|during|followed\s+by)\b.*$/,
        '',
      ));
      if (normalizedAliases.has(target)) {
        aliasAttribution = true;
        break;
      }
    }
  }
  const selfExecutionAttribution = aliasAttribution
    || /\b(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\s+(?:by|via|through)\s+(?:this\s+tool|itself|self)\b/.test(attributionText);
  const executorIdentity = /\b(?:runner|executor|interpreter|kernel)\b/.test(identity);
  const mediatedIdentity = /\b(?:check(?:er|list)?|inspect(?:or|ion)?|review(?:er)?|analy[sz](?:e|er|is)|lint(?:er)?|validat(?:e|or|ion)|authoriz(?:e|er|ation)|gate|guard|bind|cert(?:ificate)?|challenge|verif(?:y|ier|ication)|transpil(?:e|er)|format(?:ter)?|convert(?:er)?|conversion|explain(?:er)?|explanation|preview|scan(?:ner)?|classif(?:y|ier|ication)|detect(?:or|ion)?|audit(?:or)?|pars(?:e|er))\b/.test(identity)
    || /\bsql ?guard\b/.test(identity);
  const mediationOnly = mediatedIdentity
    && !executorIdentity
    && !/\b(?:create|run|execute|render|deploy|play|live)\b/.test(identity);
  const mediatedAction = String.raw`(?:runs?|exec(?:ute|utes|uted|uting)?|performs?|evaluate(?:s|d|ing)?)`;
  const mediatedNoun = String.raw`(?:parser|analyzer|scanner|validator|formatter|transpiler|analysis|validation|reviewer?|linter|verification|verifier|conversion|converter|classification|classifier|detection|detector|explanation|explainer|audit|auditor|inspection|inspector|authorization|authorizer|checker|checklist|check)`;
  const executionAction = String.raw`(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?)`;
  const mediatedGap = String.raw`(?:(?![,.;!?]|\b(?:and|but|then|before|after|without|however|yet|while|although|or|rather|${executionAction})\b).)`;
  const normalizedExecutionText = withoutExecutionActionModifiers(text);
  const executionText = mediationOnly
    ? normalizedExecutionText
      .replace(new RegExp(String.raw`\b${mediatedNoun}\b${mediatedGap}{0,30}?\b${mediatedAction}\b${mediatedGap}{0,40}?\b(?:source\s+|python\s+)?(?:code|scripts?|sql)\b`, 'g'), ' ')
      .replace(new RegExp(String.raw`\b${mediatedAction}\b${mediatedGap}{0,30}?\b${mediatedNoun}\b${mediatedGap}{0,40}?\b(?:source\s+|python\s+)?(?:code|scripts?)\b`, 'g'), ' ')
      .replace(new RegExp(String.raw`\b${mediatedAction}\b${mediatedGap}{0,30}?\b(?:python\s+code|source\s+code|code|sql)\s+${mediatedNoun}\b`, 'g'), ' ')
      .replace(new RegExp(String.raw`\b${mediatedAction}\b${mediatedGap}{0,30}?\b${mediatedNoun}\b`, 'g'), ' ')
    : normalizedExecutionText;
  const classificationText = withoutNegatedExecution(executionText);
  return {
    text,
    identity,
    directExecution: selfExecutionAttribution || directInterpreterExecutionContext(executionText, [toolIdentity, ...identityAliases]),
    executorIdentity,
    mediationOnly,
    sqlIdentity: /^(?:query|execute|run|submit)\b.{0,30}\b(?:sql|hogql)\b|^(?:sql|hogql)\b.{0,30}\b(?:query|execute|run|submit)\b/.test(identity),
    databaseOperationIdentity: /^(?:query|execute|run|submit)\b.{0,20}\b(?:database|db)\b/.test(identity)
      || /^(?:database|db)\b.{0,20}\b(?:query|execute|run|submit)\b/.test(identity),
    commandLanguage: /\b(?:shell|terminal|bash|powershell|subprocess|python|javascript|wolfram language|code|scripts?|programs?|commands?)\b/.test(classificationText),
    executableLanguage: /\b(?:python|javascript|typescript|wolfram language|es module|repl|interpreter|kernel)\b/.test(classificationText),
    runtimeSignal: /\b(?:render|deploy|runtime|live code|repl|autoplay|complete python script|code defining)\b/.test(classificationText),
    expressionLanguage: /\b(?:javascript|python|wolfram language|expression engine|interpreter)\b/.test(classificationText),
    sqlLanguage: /\b(?:sql|hogql|database|db|duckdb|postgres(?:ql)?|mysql|sqlite|sql server|query engine|select(?: statement)?|common table expression|cte)\b/.test(classificationText),
  };
}

function executionInputField(name, node, executionContext, { unconstrainedOnly = false } = {}) {
  if (!node || typeof node !== 'object' || !(node.type === 'string' || node.type === undefined)) return false;
  const strong = /^(cmd|python|shell|eval|shell command|command text|source code|python code)$/.test(name);
  const commandLike = /^(command|code|script)$/.test(name);
  const expressionLike = name === 'expression';
  const sqlLike = /^(sql|sql query)$/.test(name);
  const queryLike = /^(query|q)$/.test(name);
  const enumerated = Array.isArray(node.enum) || Object.hasOwn(node, 'const');
  const constrained = !freeTextSchemaField(node);
  if (unconstrainedOnly && constrained) return false;
  if (strong) return !enumerated || executionContext.directExecution || executionContext.executorIdentity;
  if (!(commandLike || expressionLike || sqlLike || queryLike)) return false;
  const fieldContext = normalizedWords(typeof node.description === 'string' ? node.description : '');
  const directFieldContext = fieldContext.replace(
    /\b(?:about|before|after)\s+to\s+(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|evaluate(?:s|d|ing)?|submit(?:s|ted|ting)?)\b[^,.;!?]{0,60}/g,
    ' ',
  );
  const reverseExecution = /\b(?:shell|terminal|bash|powershell|subprocess|commands?|code|scripts?|python|javascript|sql|queries?)\b.{0,20}\bto\s+(?:execute|run|evaluate|submit)\b/.test(fieldContext)
    && !/\b(?:about|before|after)\s+to\s+(?:execute|run|evaluate|submit)\b/.test(fieldContext);
  const fieldExecution = directInterpreterExecutionContext(directFieldContext)
    || reverseExecution;
  const directExecution = executionContext.directExecution || fieldExecution;
  const commandLanguage = executionContext.commandLanguage
    || /\b(?:shell|terminal|bash|powershell|subprocess|python|javascript|wolfram language|code|script|program|command)\b/.test(fieldContext);
  const executableLanguage = executionContext.executableLanguage
    || /\b(?:python|javascript|typescript|wolfram language|es module|repl|interpreter|kernel)\b/.test(fieldContext);
  const runtimeSignal = executionContext.runtimeSignal
    || /\b(?:render|deploy|runtime|live code|repl|autoplay|complete python script|code defining)\b/.test(fieldContext);
  const expressionLanguage = executionContext.expressionLanguage
    || /\b(?:javascript|python|wolfram language|expression engine|interpreter)\b/.test(fieldContext);
  const sqlLanguage = executionContext.sqlLanguage
    || /\b(?:sql|hogql|database|db|duckdb|postgres(?:ql)?|mysql|sqlite|sql server|query engine|select(?: statement)?|common table expression|cte)\b/.test(fieldContext);
  const explicitExecution = directExecution || (executableLanguage && runtimeSignal);
  if (constrained && !(explicitExecution || executionContext.executorIdentity)) return false;
  const mediationOnly = executionContext.mediationOnly && !explicitExecution;
  const declaredSqlInput = sqlLike
    && !mediationOnly
    && sqlLanguage;
  const commandContext = directExecution && commandLanguage;
  const executableCodeContext = !mediationOnly
    && executableLanguage
    && runtimeSignal;
  const expressionContext = directExecution && expressionLanguage;
  const queryContext = (directExecution
      || executionContext.sqlIdentity
      || ((sqlLike || queryLike) && executionContext.databaseOperationIdentity)
      || declaredSqlInput)
    && sqlLanguage;
  return (commandLike && (commandContext || executableCodeContext || executionContext.executorIdentity))
    || (expressionLike && expressionContext)
    || ((sqlLike || queryLike) && queryContext);
}

function withoutDelegatedQueryReferences(rawDescription, identityAliases) {
  return String(rawDescription).replace(/\s+/g, ' ')
    .replace(
      /\b(?:call|use|invoke|then|ask|delegate(?:\s+to)?|route(?:\s+to)?)\s+(?:`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?)\s+to\s+(?:run|execute|evaluate)\b(?:(?![,.;!?]|\b(?:and|but|then|before|after|prior\s+to|followed\s+by|after\s+which|however|yet|while|although|or|rather)\b).){0,30}?\b(sql|queries?)\b(?:(?![,.;!?]|\b(?:and|but|then|before|after|prior\s+to|followed\s+by|after\s+which|however|yet|while|although|or|rather)\b).){0,80}/gi,
      (match, singleTarget, multiWordTarget, structuredTarget, language) => {
        const target = singleTarget || multiWordTarget || structuredTarget;
        return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language} `;
      },
    )
    .replace(
      /\b(?:forwards?|routes?|delegates?)\s+(quer(?:y|ies))\s+to\s+(?:`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?)\s*[.!?]\s*the\s+quer(?:y|ies)\b[^.!?]{0,60}\b(?:executed|run|evaluated|invoked|submitted|launched|interpreted)\b[^.!?]{0,60}\bthere\b/gi,
      (match, language, singleTarget, multiWordTarget, structuredTarget) => {
        const target = singleTarget || multiWordTarget || structuredTarget;
        return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. database ${language} `;
      },
    );
}

function withoutExternalExecutionAttribution(rawDescription, identityAliases) {
  const normalized = String(rawDescription).replace(/\s+/g, ' ');
  const withoutDatabasePassiveAttribution = normalized.replace(
    /\b((?:(?:database|db)\s+quer(?:y|ies)|quer(?:y|ies)))\b[^,.;!?]{0,30}\b(?:is|are|was|were|gets?|got|can\s+be|will\s+be|may\s+be|must\s+be)?\s*(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\b[^,.;!?]{0,30}\b(?:against|on)\s+(?:(?:the|its|our|this|remote|an?)\s+)?(?:databases?|db)\s+(?:by|via|through)\s+(?:`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?|`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|((?:another|(?:(?:an?|the)\s+)?external)\s+(?:service|tool|runtime|worker|runner|component)))(?=\W|$)/gi,
    (match, language, structuredTarget, singleTarget, multiWordTarget, externalActor) => {
      if (externalActor) return `. ${language}`;
      const target = structuredTarget || singleTarget || multiWordTarget;
      return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language}`;
    },
  );
  const withoutPassiveAttribution = withoutDatabasePassiveAttribution.replace(
    /\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql(?:\s+(?:queries?|statements?))?|hogql|queries?))\b[^,.;!?]{0,50}?\b(?:is|are|was|were|gets?|got|(?:will|can|could|would|may|must|should)(?:\s+(?!(?:not|never)\b)[a-z]+ly){0,2}\s+be)\s+(?:(?!(?:not|never)\b)[a-z]+ly\s+){0,2}(?:be\s+)?(?:executed|run|evaluated|invoked|submitted|launched|interpreted|spawned)\s+(?:by|via|through)\s+(?:`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?|`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|((?:another|(?:(?:an?|the)\s+)?external)\s+(?:service|tool|runtime|worker|runner|component)))(?=\W|$)/gi,
    (match, language, structuredTarget, singleTarget, multiWordTarget, externalActor) => {
      if (externalActor) return `. ${language}`;
      const target = structuredTarget || singleTarget || multiWordTarget;
      return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language}`;
    },
  );
  return withoutPassiveAttribution.replace(
    /\b(?:`?([a-z][a-z0-9]*(?:[-_:.][a-z0-9]+)+)`?|`([a-z][a-z0-9]*)`|`([a-z][a-z0-9]*(?:\s+[a-z0-9][a-z0-9]*){1,7})`|((?:another|(?:(?:an?|the)\s+)?external)\s+(?:service|tool|runtime|worker|runner|component)))\s+(?:(?!(?:not|never)\b)[a-z]+ly\s+){0,2}(?:exec(?:ute|utes|uted|uting)?|run(?:s|ning)?|launch(?:es|ed|ing)?|invoke(?:s|d|ing)?|evaluate(?:s|d|ing)?|interpret(?:s|ed|ing)?|spaw[n](?:s|ed|ing)?|submit(?:s|ted|ting)?)\b[^,.;!?]{0,50}?\b((?:shell|bash|terminal|commands?|code|scripts?|programs?|powershell|subprocess|python(?:\s+code)?|javascript(?:\s+code)?|wolfram\s+language|sql|hogql|queries?))\b/gi,
    (match, structuredTarget, singleTarget, multiWordTarget, externalActor, language) => {
      if (externalActor) return `. ${language}`;
      const target = structuredTarget || singleTarget || multiWordTarget;
      return identityAliases.includes(normalizedIdentifierReference(target)) ? match : `. ${language}`;
    },
  );
}

function inferredPersistentWrite(tool, identity, description) {
  const writeAction = String.raw`(?:save|remember|memorize|persist|store|write|upsert|insert|append|cache|index)`;
  const writeObject = String.raw`(?:data|content|text|notes?|memory|memories|records?|entries|documents?|artifacts?|context|knowledge|preferences?|state|values?)`;
  const actionIdentity = new RegExp(String.raw`^(?:${writeAction})\b`).test(identity)
    || new RegExp(String.raw`\b(?:create|add|update)\b.{0,30}\b(?:memory|note|record|entry|document|artifact|knowledge)\b`).test(identity);
  if (actionIdentity) return true;
  if (tool.annotations && tool.annotations.readOnlyHint === true) return false;
  const imperativeDescription = new RegExp(String.raw`(?:^|[.!?;]\s*)(?:(?:this|the)\s+tool\s+)?${writeAction}\b.{0,60}\b${writeObject}\b`).test(description);
  const activeDescription = new RegExp(String.raw`\b(?:saves|remembers|memorizes|persists|stores|writes|upserts|inserts|appends|caches|indexes)\b.{0,60}\b${writeObject}\b`).test(description);
  return imperativeDescription || activeDescription;
}

function inferCapabilities(tool) {
  const text = searchableToolText(tool);
  const identity = [tool.name, tool.title].filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const rawDescription = typeof tool.description === 'string' ? tool.description : '';
  const description = normalizedWords(rawDescription);
  const toolContext = `${identity} ${description}`;
  const identityAliases = [tool.name, tool.title]
    .filter(value => typeof value === 'string')
    .map(normalizedIdentifierReference);
  const directDescription = normalizedWords(withoutDocumentationExecutionExamples(
    withoutExternalExecutionAttribution(
      withoutDelegatedQueryReferences(rawDescription, identityAliases),
      identityAliases,
    ),
  ));
  const directToolContext = `${identity} ${directDescription}`;
  const executionContext = executionToolContext(directToolContext, identity, identityAliases);
  const executionIdentity = /\b(shell|bash|terminal|exec(?:ute)?|subprocess|powershell|run code|eval)\b/.test(identity);
  const executionField = schemaHasExecutionInput(inputSchema(tool), executionContext);
  const executionDescription = executionDescriptionSignals(directDescription);
  const queryExecutionContext = executionContext.directExecution;
  const documentationIdentity = /\b(doc|docs|documentation|handbook|reference|readme|quickstart|catalog|list|examples?|tutorial|walkthrough|guide|instructions?|explain|describe|lint|analy[sz](?:e|er)|pars(?:e|er)|inspect|preview|check(?:list)?|audit|vet|scan|classify|review|authorize|gate)\b/.test(identity);
  const documentationDescription = /\b(document(?:ation|ed)?|handbook|reference|catalog|guide|explains?|describes?|examples?|read[ -]only|prose(?: only)?|text only|classification|risk analysis|authorization|authorize)\b/.test(description);
  const passiveDocumentationOnly = documentationIdentity && documentationDescription
    && (executionDescription.passive || executionDescription.query) && !executionDescription.active && !executionField;
  const checklistDocumentationOnly = /\bchecklist\b/.test(identity)
    && /\b(?:returns?|provides?|shows?|gives?)\b[^.!?]{0,40}\b(?:steps?|instructions?|requirements?|checklist)\b/.test(description)
    && !executionField;
  const proceduralDocumentationOnly = executionContext.mediationOnly
    && /\b(?:recipe|returned\s+steps?|provided\s+steps?|instructions?|commands?)\b/.test(description)
    && /\b(?:this\s+)?server\s+(?:performs?\s+no\s+computation|does\s+not\s+(?:run|execute|invoke|launch))\b/.test(description)
    && !/\b(?:this\s+tool|server)\s+(?:executes?|runs?|launch(?:es)?|interprets?|spawns?)\b/.test(directDescription)
    && !executionField;
  const documentationOnly = passiveDocumentationOnly || proceduralDocumentationOnly || checklistDocumentationOnly;
  const matches = [
    ['secret_read', /\b(secret|credential|password|1password|onepassword|token|keychain|vault|api key|environment variable)\b/],
    ['network_egress', /\b(http|https|url|uri|fetch|request|browser|webhook|network|upload|email|slack|send|post message)\b/],
    ['destructive_action', /\b(delete|remove|destroy|drop|terminate|cancel|revoke|wipe|purge)\b/],
    ['financial_action', /\b(pay|payment|purchase|transfer|wire|trade|order)\b/],
    ['privileged_action', /\b(admin|sudo|privilege|permission|iam|deploy|publish|merge|revoke|payment|transfer|delete)\b/],
    ['filesystem_access', /\b(file|filesystem|directory|folder|path|read file|write file)\b/],
  ];
  const capabilities = matches.filter(([, pattern]) => pattern.test(text)).map(([capability]) => capability);
  if (inferredPersistentWrite(tool, identity, description)) capabilities.push('persistent_write');
  const descriptionExecutionAllowed = !executionContext.mediationOnly
    || executionContext.directExecution
    || executionField;
  if (executionField
    || (executionIdentity && !(documentationIdentity && documentationDescription && !executionDescription.active) && !documentationOnly)
    || (executionContext.directExecution && descriptionExecutionAllowed && !documentationOnly)
    || ((executionDescription.active
      || executionDescription.passive
      || (executionDescription.query && queryExecutionContext)) && descriptionExecutionAllowed && !documentationOnly)) {
    capabilities.push('code_execution');
  }
  if (tool.annotations && tool.annotations.destructiveHint === true) capabilities.push('destructive_action', 'privileged_action');
  if (tool.annotations && tool.annotations.openWorldHint === true) capabilities.push('network_egress');
  return [...new Set(capabilities)].sort();
}

function compositionPrivilegeEvidence(tool, artifact, toolPointer, explicitCapabilities, forcedCapabilities = []) {
  const privilegedCapabilities = new Set(['privileged_action', 'destructive_action', 'financial_action']);
  const explicit = explicitCapabilities.some(capability => privilegedCapabilities.has(capability));
  const forced = forcedCapabilities.some(capability => privilegedCapabilities.has(capability));
  const destructiveHint = Boolean(tool.annotations && tool.annotations.destructiveHint === true);
  const identity = normalizedWords(typeof tool.name === 'string' ? tool.name : '').trim();
  const readOnlyIdentity = /^(?:status|list|get|read|search|query|inspect|preview|help|docs?|documentation|explain|describe)\b/.test(identity);
  const sequencedPrivilege = /^(?:status|list|get|read|search|query|inspect|preview|help|docs?|documentation|explain|describe)\b.{0,40}\b(?:and|then|to)\b.{0,30}\b(?:deploy|iam|admin|sudo|revoke|delete|remove|destroy|drop|terminate|wipe|purge|publish|merge|payment|transfer)\b/.test(identity);
  const privilegedIdentity = /\b(?:deploy|iam|admin|sudo|revoke|delete|remove|destroy|drop|terminate|wipe|purge|publish|merge|payment|transfer)\b/.test(identity)
    && (!readOnlyIdentity || sequencedPrivilege);
  if (!(explicit || forced || destructiveHint || privilegedIdentity)) {
    return { observed: false, provenance: 'none', ref: null };
  }
  const pointer = destructiveHint
    ? `${toolPointer}/annotations/destructiveHint`
    : explicit
      ? `${toolPointer}/${tool['x-backbond'] ? 'x-backbond/' : ''}capabilities`
      : `${toolPointer}/name`;
  return {
    observed: true,
    provenance: explicit || destructiveHint ? 'explicit' : 'derived',
    ref: ref(artifact, pointer),
  };
}

function destinationPatternConstrainsHost(pattern) {
  if (!usefulSchemaPattern({ pattern })) return false;
  if (!pattern.startsWith('^') || /(^|[^\\])\|/.test(pattern)) return false;
  const readable = pattern.slice(1).replace(/\\\//g, '/');
  const scheme = readable.match(/^https?\??:\/\//i);
  if (!scheme) return false;
  const authorityPattern = readable.slice(scheme[0].length);
  const delimiter = authorityPattern.match(/(?:\\[?#]|[/?#])/);
  const exactAuthority = !delimiter && authorityPattern.endsWith('$');
  if (!delimiter && !exactAuthority) return false;
  const hostPattern = delimiter
    ? authorityPattern.slice(0, delimiter.index)
    : authorityPattern.slice(0, -1);
  if (!hostPattern || /[()[\]{}*+?|@$^]/.test(hostPattern)) return false;
  if (/(^|[^\\])\./.test(hostPattern)) return false;
  const literalHost = hostPattern.replace(/\\\./g, '.').replace(/\\-/g, '-');
  if (literalHost.includes('\\')) return false;
  return /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?::\d+)?$/i.test(literalHost);
}

function destinationIsConstrained(node) {
  if (Array.isArray(node.enum) && node.enum.length > 0) return true;
  if (Object.hasOwn(node, 'const')) return true;
  return typeof node.pattern === 'string' && destinationPatternConstrainsHost(node.pattern);
}

function networkActionContext(toolContext) {
  return /\b(?:fetch|download|retrieve|browse|search|read|open|get|scrape|crawl|send|post|upload|request|call|navigate|proxy|webhook|callback|deploy|publish)\b/.test(toolContext);
}

function destinationInputClass(propertyName, node, toolContext) {
  if (!node || typeof node !== 'object' || destinationIsConstrained(node)) return null;
  if (!(node.type === 'string' || node.type === undefined)) return null;
  const name = normalizedWords(propertyName).trim();
  const description = normalizedWords(typeof node.description === 'string' ? node.description : '');
  const label = `${name} ${description}`.trim();
  const strongName = /^(?:url|uri|webhook|webhook url|callback url|destination url|target url|request url|remote url)$/.test(name);
  const strongDescription = /\b(?:webhook url|callback url|destination url|target url|request url|remote url)\b/.test(description)
    || /\b(?:publicly reachable|user supplied|operator supplied|supplied|arbitrary|external|remote)\b[^.]{0,80}\b(?:url|uri)\b/.test(description)
    || /\b(?:url|uri)\b[^.]{0,40}\b(?:to|for)\s+(?:fetch|download|open|browse|scrape|crawl|request|navigate|load|retrieve|send|post|upload)\b/.test(description);
  const ambiguous = /\b(?:endpoint|href|path|host|hostname|destination|target)\b/.test(label)
    || /(?:^|\s)(?:url|uri)$/.test(name);
  if (!(strongName || strongDescription || ambiguous)) return null;
  const documentationLocator = /\b(?:doc|docs|documentation|reference|schema|specification)\b/.test(label);
  const explicitDestinationAction = /\b(?:fetch|download|open|browse|scrape|crawl|request|navigate|webhook|callback)\b/.test(toolContext);
  if (documentationLocator && !explicitDestinationAction) return 'ambiguous_destination_reference';
  return (strongName || strongDescription) && networkActionContext(toolContext)
    ? 'unvalidated_destination'
    : 'ambiguous_destination_reference';
}

function semanticRisks(tool, artifact, toolPointer) {
  const schema = inputSchema(tool);
  const risks = [];
  const observedRiskIds = new Set();
  const addRisk = risk => {
    if (observedRiskIds.has(risk.id)) return;
    observedRiskIds.add(risk.id);
    risks.push(risk);
  };
  const toolIdentity = [tool.name, tool.title]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const identityAliases = [tool.name, tool.title]
    .filter(value => typeof value === 'string')
    .map(normalizedIdentifierReference);
  const directDescription = withoutDocumentationExecutionExamples(
    withoutExternalExecutionAttribution(
      withoutDelegatedQueryReferences(
        typeof tool.description === 'string' ? tool.description : '',
        identityAliases,
      ),
      identityAliases,
    ),
  );
  const toolContext = [tool.name, tool.title, directDescription]
    .filter(value => typeof value === 'string').map(normalizedWords).join(' ');
  const executionContext = executionToolContext(toolContext, toolIdentity, identityAliases);
  const formalQuerySignal = /\b(?:sql|hogql|expression|query language|where clause|filter expression|text to sql|lucene|solr|openfda|jsonpath|regular expression|cron expression|formula expression)\b/;
  const toolHasFormalQueryContext = formalQuerySignal.test(toolContext);
  const rootPointer = `${toolPointer}/${tool.parameters ? 'parameters' : tool.input_schema ? 'input_schema' : tool.inputSchema ? 'inputSchema' : 'schema'}`;
  const pending = [{ node: schema, pointer: rootPointer, propertyName: '', depth: 0 }];
  const visited = new WeakSet();
  let analyzedNodes = 0;
  let analysisIncomplete = false;
  let unresolvedSchema = false;
  while (pending.length) {
    const { node, pointer, propertyName, depth } = pending.pop();
    if (!node || typeof node !== 'object' || visited.has(node)) continue;
    if (depth > MAX_SCHEMA_ANALYSIS_DEPTH || analyzedNodes >= MAX_SCHEMA_ANALYSIS_NODES) {
      analysisIncomplete = true;
      continue;
    }
    visited.add(node);
    analyzedNodes += 1;
    if (typeof node.$ref === 'string' || node['x-backbond-analysis-incomplete'] === true) unresolvedSchema = true;
    const description = typeof node.description === 'string' ? node.description.toLowerCase() : '';
    const label = `${propertyName.replace(/[_-]+/g, ' ')} ${description}`;
    const constrained = Array.isArray(node.enum) || Object.hasOwn(node, 'const');
    if ((node.type === 'string' || node.type === undefined) && !constrained) {
      const interpreterField = executionInputField(normalizedWords(propertyName), node, executionContext, { unconstrainedOnly: true });
      const normalizedPropertyName = normalizedWords(propertyName).trim();
      const formalQueryName = /^(?:query|q|sql|sql query|statement|expression|filter|where|where clause)$/.test(normalizedPropertyName);
      const queryExpression = formalQuerySignal.test(label) || (formalQueryName && toolHasFormalQueryContext);
      if (interpreterField) {
        addRisk({ id: 'arbitrary_interpreter_input', reason: `${propertyName || 'input'} accepts unconstrained command, expression, or SQL text`, ref: ref(artifact, pointer) });
      } else if (freeTextSchemaField(node) && queryExpression) {
        addRisk({ id: 'ambiguous_query_expression', reason: `${propertyName || 'input'} accepts query or expression text whose execution semantics are not observable`, ref: ref(artifact, pointer) });
      }
    }
    const destinationClass = destinationInputClass(propertyName, node, toolContext);
    if (destinationClass) {
      const reason = destinationClass === 'unvalidated_destination'
        ? `${propertyName || 'input'} accepts a network destination without a host allowlist`
        : `${propertyName || 'input'} may identify a destination, but network action and host constraints are not both observable`;
      addRisk({ id: destinationClass, reason, ref: ref(artifact, pointer) });
    }
    if (node.properties && typeof node.properties === 'object') {
      const entries = Object.entries(node.properties);
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const [name, child] = entries[index];
        pending.push({ node: child, pointer: `${pointer}/properties/${escapePointer(name)}`, propertyName: name, depth: depth + 1 });
      }
    }
    if (node.items) pending.push({ node: node.items, pointer: `${pointer}/items`, propertyName, depth: depth + 1 });
    for (const keyword of ['allOf', 'oneOf', 'anyOf']) {
      if (!Array.isArray(node[keyword])) continue;
      for (let index = node[keyword].length - 1; index >= 0; index -= 1) {
        pending.push({ node: node[keyword][index], pointer: `${pointer}/${keyword}/${index}`, propertyName, depth: depth + 1 });
      }
    }
  }
  if (analysisIncomplete || unresolvedSchema) {
    addRisk({
      id: 'schema_analysis_incomplete',
      reason: unresolvedSchema
        ? 'input schema contains an unresolved reference or input shape that was not safely flattened'
        : `input schema exceeds the local analysis budget (${MAX_SCHEMA_ANALYSIS_DEPTH} levels or ${MAX_SCHEMA_ANALYSIS_NODES} nodes)`,
      ref: ref(artifact, rootPointer),
    });
  }
  return risks;
}

function normalizedPromptMetadata(value) {
  return String(value).toLowerCase().replace(/\s+/g, ' ').trim();
}

function withoutQuotedOrExampleText(value) {
  let text = normalizedPromptMetadata(value);
  text = text
    .replace(/`[^`\r\n]{0,500}`/g, ' ')
    .replace(/"[^"\r\n]{0,500}"/g, ' ')
    .replace(/“[^”\r\n]{0,500}”/g, ' ')
    .replace(/‘[^’\r\n]{0,500}’/g, ' ')
    .replace(/'(?:(?:ignore|disregard|forget|override|do not|don't|never|always|must|send|provide)[^'\r\n]{0,300})'/g, ' ');
  text = text.replace(/\(([^()\r\n]{0,300})\)/g, (match, _content, offset, source) => {
    const prefix = source.slice(Math.max(0, offset - 100), offset);
    return /\b(?:examples?|e\.g\.|for example|such as|detect(?:ed|s|ing)?|screen(?:s|ed|ing)?|signature corpus|detected classes?)\b/.test(prefix)
      ? ' '
      : match;
  });
  text = text.replace(
    /\b(?:examples?|e\.g\.|for example|such as|detected classes?|signature corpus)\s*(?::|-)?\s*[^.!?\r\n]{0,300}/g,
    ' ',
  );
  return text.replace(/\s+/g, ' ').trim();
}

function promptClauses(value) {
  return withoutQuotedOrExampleText(value).split(/[.!?;\r\n]+/).map(item => item.trim()).filter(Boolean);
}

function promptMetadataReviewSignal(value, toolLevelMetadata) {
  const raw = normalizedPromptMetadata(value)
    .replace(/[`"“”‘’']/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const filtered = withoutQuotedOrExampleText(value);
  const suppressed = raw !== filtered;
  const override = /\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:instruction|message|policy|rule)s?\b/.test(raw);
  const concealed = /\b(?:do not|don't|never)\b.{0,50}\b(?:tell|mention|show|reveal|disclose|inform|notify)\b.{0,80}\b(?:user|operator|human)\b/.test(raw);
  const sensitive = /\b(?:send|upload|post|transmit|reveal|provide|enter|share|submit|request)\b.{0,100}\b(?:password|secret|credential|api[ _-]?key|access[ _-]?token|private[ _-]?key)s?\b/.test(raw);
  const globalSelection = toolLevelMetadata && /\b(?:always|must|required)\b.{0,50}\b(?:call|use|invoke|select|choose)\b.{0,40}\b(?:this|the)\s+tool\b/.test(raw);
  const scopedResponseOrdering = toolLevelMetadata
    && /\b(?:this|the)\s+tool\b.{0,40}\b(?:must|should|required|needs?)\b.{0,35}\b(?:used|called|invoked|selected|chosen)\b.{0,60}\b(?:before|prior to)\b.{0,50}\b(?:answering|responding|replying|handling)\b/.test(raw);
  return (suppressed && (override || concealed || sensitive || globalSelection)) || scopedResponseOrdering;
}

function securityAnalysisContext(hasSecuritySubject, clause) {
  if (!hasSecuritySubject) return false;
  const analysisAction = /\b(?:detect(?:s|ed|ing)?|scan(?:s|ned|ning)?|screen(?:s|ed|ing)?|audit(?:s|ed|ing)?|identify|identifies|flag(?:s|ged|ging)?|signature corpus|guardrail)\b/;
  return analysisAction.test(clause);
}

function instructionOverrideSignal(hasSecuritySubject, clause) {
  const target = /\b(?:previous|prior|system|developer|safety|operator|user)\b.{0,40}\b(?:instruction|message|policy|rule)s?\b/;
  if (!target.test(clause) || securityAnalysisContext(hasSecuritySubject, clause)) return false;
  const action = String.raw`(?:ignore|disregard|forget|override)`;
  const direct = new RegExp(String.raw`^(?:(?:important|instruction|note)\s*:\s*)?(?:(?:please|always)\s+)*${action}\b`);
  const addressed = new RegExp(String.raw`\b(?:you|agent|assistant|model)\s+(?:must|should|need(?:s)?\s+to|is\s+required\s+to|has\s+to)\s+${action}\b`);
  return direct.test(clause) || addressed.test(clause);
}

function concealmentSignal(clause) {
  const hide = String.raw`(?:do\s+not|don't|never)\s+(?:tell|mention|show|reveal|disclose|inform|notify)`;
  const audience = String.raw`(?:the\s+)?(?:user|operator|human)`;
  const behavior = String.raw`(?:this|the)?\s*(?:action|operation|invocation|tool|request|call|behavior|instruction|activity|execution|change)`;
  const preventsUnapprovedAction = new RegExp(String.raw`\b(?:do\s+not|does\s+not|will\s+not|cannot|can't|never|must\s+not)\b.{0,60}\b(?:execute|run|invoke|call|perform|proceed)\b.{0,50}\bwithout\b.{0,20}\b${audience}(?:'s)?\b.{0,20}\b(?:knowledge|consent|approval)\b`);
  if (preventsUnapprovedAction.test(clause)) return false;
  const audienceThenBehavior = new RegExp(String.raw`\b${hide}\b.{0,45}\b${audience}\b.{0,45}\b${behavior}\b`);
  const behaviorThenAudience = new RegExp(String.raw`\b${hide}\b.{0,45}\b${behavior}\b.{0,45}\b${audience}\b`);
  const hiddenAction = new RegExp(String.raw`\b(?:hide|conceal|withhold)\b.{0,45}\b${behavior}\b.{0,45}\bfrom\s+${audience}\b`);
  const withoutKnowledge = new RegExp(String.raw`(?:\b${behavior}\b.{0,45})?\bwithout\b.{0,20}\b${audience}(?:'s)?\b.{0,20}\b(?:knowledge|consent|approval)\b`);
  return audienceThenBehavior.test(clause) || behaviorThenAudience.test(clause)
    || hiddenAction.test(clause) || (withoutKnowledge.test(clause) && new RegExp(String.raw`\b${behavior}\b`).test(clause));
}

function sensitiveDataRequestClass(clause) {
  const sensitiveTerm = String.raw`(?:passwords?(?!\s+reset\b)|secrets?|credentials?|api[ _-]?keys?|access[ _-]?tokens?|private[ _-]?keys?|environment variables?)`;
  const transferVerb = String.raw`(?:send|upload|post|transmit|exfiltrate|reveal|return|provide|enter|share|supply|submit|include|collect|request)`;
  const transferredVerb = String.raw`(?:sent|uploaded|posted|transmitted|exfiltrated|revealed|returned|provided|entered|shared|supplied|submitted|included|collected|requested)`;
  const preventsTransfer = new RegExp(String.raw`\b(?:do not|don't|never|must not|should not)\b.{0,35}\b${transferVerb}\b.{0,90}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,45}\b(?:must not|should not|never)\b.{0,30}\b(?:be\s+)?${transferVerb}\b`);
  const statusOnly = new RegExp(String.raw`\b(?:return|report|show)\b.{0,35}\b(?:whether|if|status)\b.{0,35}\b${sensitiveTerm}\b|\b${sensitiveTerm}\b.{0,35}\b(?:configured|exists|present|available|set)\b`);
  if (preventsTransfer.test(clause) || statusOnly.test(clause)) return null;
  const direct = new RegExp(String.raw`(?:^|\b(?:and|then)\s+)(?:(?:please|always)\s+)*(?:${transferVerb})\b.{0,100}\b${sensitiveTerm}\b`);
  const addressed = new RegExp(String.raw`\b(?:you|user|agent|assistant|model)\s+(?:must|should|need(?:s)?\s+to|is\s+required\s+to|has\s+to)\s+${transferVerb}\b.{0,100}\b${sensitiveTerm}\b`);
  const askUser = new RegExp(String.raw`^(?:(?:please|always)\s+)*(?:ask(?:s)?|prompt(?:s)?)\b.{0,30}\b(?:the\s+)?user\b(?:(?:.{0,30}\b(?:to\s+)?${transferVerb}\b.{0,60}\b${sensitiveTerm}\b)|(?:.{0,45}\bfor\b.{0,20}\b${sensitiveTerm}\b))`);
  const requiredPassive = new RegExp(String.raw`\b${sensitiveTerm}\b.{0,35}\b(?:must|should|needs?\s+to|is\s+required\s+to)\b.{0,25}\b(?:be\s+)?(?:${transferVerb}|${transferredVerb})\b`);
  if (!(direct.test(clause) || addressed.test(clause) || askUser.test(clause) || requiredPassive.test(clause))) return null;
  const emission = new RegExp(String.raw`\b(?:return|reveal|send|upload|post|transmit|exfiltrate)\b.{0,100}\b${sensitiveTerm}\b`);
  return emission.test(clause) ? 'emits_or_transmits_credential' : 'solicits_secret';
}

function forcedInvocationSignal(clause) {
  const invoke = String.raw`(?:call|use|invoke|select|choose)`;
  const tool = String.raw`(?:this|the)\s+tool`;
  const globalResponse = String.raw`(?:answer(?:ing)?|respond(?:ing)?|reply(?:ing)?|handling)(?:\s+to)?\s+(?:any|every|all)`;
  const beforeGlobalResponse = new RegExp(String.raw`^(?:before|prior\s+to)\s+${globalResponse}\b.{0,80}\b(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b`);
  const reverseGlobalResponse = new RegExp(String.raw`^(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b.{0,50}\b(?:before|prior\s+to)\b.{0,50}\b${globalResponse}\b`);
  const passiveGlobalResponse = new RegExp(String.raw`^${tool}\s+(?:must|should|needs?\s+to|is\s+required\s+to|has\s+to)\s+be\s+(?:used|called|invoked|selected|chosen)\b.{0,50}\b(?:before|prior\s+to)\b.{0,50}\b${globalResponse}\b`);
  const first = new RegExp(String.raw`^(?:always|must)\s+${invoke}\b.{0,30}\b${tool}\b.{0,12}\bfirst\b`);
  const addressedFirst = new RegExp(String.raw`\b(?:you|agent|assistant|model)\s+(?:must|should|need(?:s)?\s+to|is\s+required\s+to|has\s+to)\s+(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b.{0,12}\bfirst\b`);
  const globalEveryRequest = new RegExp(String.raw`\b(?:for|on)\s+(?:any|every|all)\s+(?:question|request|prompt|task)\b.{0,60}\b(?:always\s+)?${invoke}\b.{0,30}\b${tool}\b`);
  const exclusivePreference = new RegExp(String.raw`\b(?:prefer|always\s+use|must\s+use)\b.{0,30}\b${tool}\b.{0,40}\b(?:over|instead\s+of|rather\s+than)\b.{0,24}\b(?:any|all|other|another|competing)\b`);
  const excludeOthers = new RegExp(String.raw`\b(?:do not|don't|never|avoid)\b.{0,30}\b${invoke}\b.{0,30}\b(?:any|all|other|another|competing)\s+tools?\b`);
  return beforeGlobalResponse.test(clause) || reverseGlobalResponse.test(clause) || passiveGlobalResponse.test(clause) || first.test(clause)
    || addressedFirst.test(clause) || globalEveryRequest.test(clause)
    || exclusivePreference.test(clause) || excludeOthers.test(clause);
}

function toolDescriptionRisks(tool, artifact, toolPointer) {
  const risks = [];
  const networkVerb = String.raw`(?:fetch|download|retrieve|browse|search|read|open|get|scrape|crawl)`;
  const networkSource = String.raw`(?:url|uri|web|website|webpage|internet|remote|http|https)`;
  const networkIntake = new RegExp(String.raw`\b${networkVerb}\b.{0,60}\b${networkSource}\b|\b${networkSource}\b.{0,60}\b${networkVerb}\b`);
  const fields = [
    ['description', tool.description],
    ['title', tool.title],
  ];
  const securityIdentity = [tool.name, tool.title, tool.description]
    .filter(value => typeof value === 'string').map(normalizedPromptMetadata).join(' ');
  const hasSecuritySubject = /\b(?:prompt[ -]?injection|instruction[ -]?override|jailbreak|malware|tool poisoning|adversarial instruction)\b/.test(securityIdentity);
  const schemaEntry = inputSchemaEntries(tool).find(([, value]) => value && typeof value === 'object' && !Array.isArray(value));
  const visitedSchemaNodes = new WeakSet();
  function addSchemaMetadata(node, pointer, depth = 0) {
    if (!node || typeof node !== 'object' || depth > 8) return;
    if (visitedSchemaNodes.has(node)) return;
    visitedSchemaNodes.add(node);
    if (Array.isArray(node)) {
      node.forEach((child, index) => addSchemaMetadata(child, `${pointer}/${index}`, depth + 1));
      return;
    }
    for (const field of ['description', 'title']) {
      if (typeof node[field] === 'string') fields.push([`${pointer}/${field}`, node[field]]);
    }
    for (const [key, child] of Object.entries(node)) {
      if (child && typeof child === 'object') addSchemaMetadata(child, `${pointer}/${escapePointer(key)}`, depth + 1);
    }
  }
  if (schemaEntry) addSchemaMetadata(schemaEntry[1], `${toolPointer}/${schemaEntry[0]}`);
  for (const [field, value] of fields) {
    if (typeof value !== 'string') continue;
    const text = normalizedPromptMetadata(value);
    const clauses = promptClauses(value);
    const pointer = field.startsWith('/') ? field : `${toolPointer}/${field}`;
    const metadataSha256 = sha256(text);
    const instructionOverride = clauses.some(clause => instructionOverrideSignal(hasSecuritySubject, clause));
    const concealedBehavior = clauses.some(concealmentSignal);
    const sensitiveClasses = clauses.map(sensitiveDataRequestClass).filter(Boolean);
    const sensitiveRequest = sensitiveClasses.length > 0;
    const toolLevelMetadata = field === 'description' || field === 'title';
    const forcedInvocation = toolLevelMetadata && clauses.some(forcedInvocationSignal);
    const permissionRequirement = toolLevelMetadata
      && /\b(?:requires?|needs?|must have)\b.{0,45}\b(?:permission|authorization|privilege|administrator|admin role)\b/.test(text);
    if (instructionOverride) {
      risks.push({ id: 'prompt_instruction_override', reason: 'tool description contains directed instruction-override language', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (concealedBehavior) {
      risks.push({ id: 'prompt_concealed_behavior', reason: 'tool description directly asks that tool behavior be concealed from the operator', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (sensitiveRequest) {
      risks.push({
        id: 'prompt_sensitive_data_request',
        subtype: sensitiveClasses.includes('emits_or_transmits_credential') ? 'emits_or_transmits_credential' : 'solicits_secret',
        reason: 'tool description directly solicits or emits sensitive data for a result or transmission',
        ref: ref(artifact, pointer),
        metadata_sha256: metadataSha256,
      });
    }
    if (forcedInvocation) {
      risks.push({ id: 'prompt_forced_invocation', reason: 'tool description attempts to control global tool selection or force invocation', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (permissionRequirement) {
      risks.push({ id: 'permission_requirement_unverified', reason: 'tool metadata claims a permission requirement whose runtime enforcement is not observable', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
    }
    if (!(instructionOverride || concealedBehavior || sensitiveRequest || forcedInvocation)
      && promptMetadataReviewSignal(value, toolLevelMetadata)) {
      risks.push({ id: 'prompt_metadata_review', reason: 'tool metadata contains ambiguous directive-like language that requires operator review', ref: ref(artifact, pointer), metadata_sha256: metadataSha256 });
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
  if (inputSchemaEntries(tool).length > 1) {
    throw new Error(`tool manifest tool ${index} contains multiple supported input schema aliases`);
  }
  const extension = tool['x-backbond'];
  if (extension !== undefined) assertObject(extension, `${artifact.kind} tool ${index}.x-backbond`);
  const controls = options.canonical ? tool : (extension || {});
  const explicitCapabilities = validateCapabilities(controls.capabilities, `${artifact.kind} tool ${index}.capabilities`);
  const derivedCapabilities = [...new Set([...inferCapabilities(tool), ...(options.forceCapabilities || [])])].sort();
  const capabilities = [...new Set([...derivedCapabilities, ...explicitCapabilities])].sort();
  const toolPointer = options.pointerOverride || `${basePointer}/${index}`;
  const compositionPrivilege = compositionPrivilegeEvidence(tool, artifact, toolPointer, explicitCapabilities, options.forceCapabilities || []);
  const explicitTrust = controls.input_trust !== undefined;
  const inputTrust = explicitTrust
    ? validateEnum(controls.input_trust, INPUT_TRUST, `${artifact.kind} tool ${index}.input_trust`)
    : (options.canonical ? 'unknown' : 'mixed');
  const risks = [...semanticRisks(tool, artifact, toolPointer), ...toolDescriptionRisks(tool, artifact, toolPointer)];
  return {
    name: tool.name,
    dialect,
    capabilities,
    input_schema_observed: hasInputSchema(tool),
    semantic_metadata_observed: [tool.description, tool.title].some(value => typeof value === 'string' && value.trim()),
    semantic_risks: risks,
    composition_privilege: compositionPrivilege,
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
  const openApiMarked = document && typeof document === 'object' && !Array.isArray(document)
    && Boolean((document.openapi || document.swagger) && document.paths);
  const toolListMarked = Array.isArray(document)
    || Boolean(document && typeof document === 'object' && !Array.isArray(document)
      && (Array.isArray(document.tools) || (document.result && Array.isArray(document.result.tools))));
  if (openApiMarked && (toolListMarked || document.protocol === 'backbond-tool-schema/v1')) {
    throw new Error('tool manifest mixes OpenAPI and tool-list dialect markers');
  }
  if (document && document.protocol === 'backbond-tool-schema/v1') {
    assertObject(document, 'tool schema');
    if (!Array.isArray(document.tools)) throw new Error('backbond-tool-schema/v1 tools must be an array');
    artifact.dialect = 'backbond-tool-schema/v1';
    return document.tools.map((tool, index) => normalizeTool(tool, index, artifact, '/tools', artifact.dialect, { canonical: true }));
  }
  let tools;
  let basePointer;
  let dialect;
  const candidates = [];
  if (Array.isArray(document)) candidates.push({ tools: document, basePointer: '' });
  else if (document && typeof document === 'object') {
    if (Array.isArray(document.tools)) candidates.push({ tools: document.tools, basePointer: '/tools' });
    if (document.result && Array.isArray(document.result.tools)) candidates.push({ tools: document.result.tools, basePointer: '/result/tools', dialect: 'mcp-tools-list/v1' });
  }
  if (candidates.length > 1) throw new Error('tool manifest contains multiple supported tool-list locations');
  if (!candidates.length) return null;
  ({ tools, basePointer, dialect } = candidates[0]);
  if (!dialect && tools.length > 0 && tools.every(tool => tool && tool.type === 'function' && tool.function)) {
    dialect = 'openai-function-tools/v1';
    artifact.dialect = dialect;
    return tools.map((entry, index) => normalizeTool(entry.function, index, artifact, basePointer, dialect, { pointerOverride: `${basePointer}/${index}/function` }));
  }
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && tool.input_schema)) dialect = 'anthropic-tools/v1';
  if (!dialect && tools.length > 0 && tools.every(tool => tool && typeof tool.name === 'string' && (tool.inputSchema || tool.parameters))) dialect = 'mcp-tools-list/v1';
  if (!dialect && tools.length === 0) dialect = 'generic-tool-list/v1';
  if (!dialect) {
    const entryDialects = tools.map(tool => {
      const matches = [];
      if (tool && tool.type === 'function' && tool.function) matches.push('openai');
      if (tool && typeof tool.name === 'string' && tool.input_schema) matches.push('anthropic');
      if (tool && typeof tool.name === 'string' && (tool.inputSchema || tool.parameters)) matches.push('mcp');
      return matches;
    });
    if (entryDialects.some(matches => matches.length > 0)) {
      throw new Error('tool manifest contains mixed supported tool entry dialects');
    }
    return null;
  }
  artifact.dialect = dialect;
  return tools.map((tool, index) => normalizeTool(tool, index, artifact, basePointer, dialect));
}

function isAmbiguousToolManifestError(error) {
  return error instanceof Error && ([
    'tool manifest mixes OpenAPI and tool-list dialect markers',
    'tool manifest contains multiple supported tool-list locations',
    'tool manifest contains mixed supported tool entry dialects',
  ].includes(error.message) || error.message.startsWith('tool manifest tool ') && error.message.endsWith(' contains multiple supported input schema aliases'));
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
      let analysisIncomplete = false;
      const routeParameters = Array.isArray(routeItem.parameters) ? routeItem.parameters : [];
      const operationParameters = Array.isArray(operation.parameters) ? operation.parameters : [];
      if (routeItem.parameters !== undefined && !Array.isArray(routeItem.parameters)) analysisIncomplete = true;
      if (operation.parameters !== undefined && !Array.isArray(operation.parameters)) analysisIncomplete = true;
      for (const parameter of [...routeParameters, ...operationParameters]) {
        if (!parameter || typeof parameter !== 'object') {
          analysisIncomplete = true;
          continue;
        }
        if (typeof parameter.$ref === 'string' || !parameter.name) {
          analysisIncomplete = true;
          continue;
        }
        properties[parameter.name] = parameter.schema || { type: parameter.type || 'string', description: parameter.description };
      }
      const requestContent = operation.requestBody && operation.requestBody.content;
      const requestSchema = requestContent && Object.values(requestContent).find(item => item && item.schema);
      if (operation.requestBody && typeof operation.requestBody.$ref === 'string') analysisIncomplete = true;
      if (requestContent && !requestSchema) analysisIncomplete = true;
      let parameters = { type: 'object', properties };
      if (requestSchema && requestSchema.schema) {
        parameters = { allOf: [parameters, requestSchema.schema] };
      }
      if (analysisIncomplete) parameters['x-backbond-analysis-incomplete'] = true;
      const tool = {
        name: operation.operationId || `${method.toLowerCase()}_${route.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '')}`,
        description: [operation.summary, operation.description, `${method.toUpperCase()} ${route}`].filter(Boolean).join(' '),
        parameters,
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
      const directServerDomains = server.allowedDomains !== undefined;
      const serverDomains = directServerDomains ? server.allowedDomains : server.network && server.network.allowedDomains;
      const serverDomainsPointer = `${pointer}/${directServerDomains ? 'allowedDomains' : 'network/allowedDomains'}`;
      if (serverDomains !== undefined) {
        validateScope(serverDomains, `config MCP server ${serverName}.allowedDomains`);
        permission.network_scope_observed = true;
        if (scopeIsWildcard(serverDomains)) addWildcard('network', 'egress', serverDomainsPointer);
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
        composition_privilege: entry.composition_privilege || { observed: false, provenance: 'none', ref: null },
        input_trust: mergeTrust([entry.input_trust], globalInputTrust),
        refs: entry.refs,
      };
    });
    return {
      name, capabilities, semantic_risks: semantic,
      composition_privilege: entries.find(entry => entry.composition_privilege && entry.composition_privilege.observed)?.composition_privilege
        || { observed: false, provenance: 'none', ref: null },
      observation_count: entries.length,
      input_schema_observed: entries.every(entry => entry.input_schema_observed === true),
      semantic_metadata_observed: entries.every(entry => entry.semantic_metadata_observed === true),
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
      let schema;
      let openapi;
      try {
        schema = normalizeToolSchema(document, metadata);
        openapi = schema === null ? normalizeOpenApi(document, metadata) : null;
      } catch (error) {
        if (!options.reviewAmbiguousToolManifest || !isAmbiguousToolManifestError(error)) throw error;
        metadata.dialect = 'ambiguous-tool-manifest';
        coverageGaps.push(gap(metadata.kind, 'insufficient_evidence', 'BB-VET-AMBIGUOUS-MANIFEST', `Tool manifest is ambiguous: ${error.message}`, metadata));
        recognized = true;
      }
      if (!recognized && (schema !== null || openapi !== null)) { toolSources.push(...(schema || openapi)); toolEvidenceSeen = true; recognized = true; }
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
