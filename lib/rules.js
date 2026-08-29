'use strict';

const fs = require('node:fs');
const { sha256 } = require('./canonical.js');

const RULESET_VERSION = 'backbond-local-rules/1.2.0';
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

function uniqueRefs(refs) {
  const seen = new Set();
  return refs.flat(Infinity).filter(Boolean).filter(item => {
    const key = `${item.artifact_kind}:${item.artifact_name}:${item.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => `${a.artifact_kind}:${a.pointer}`.localeCompare(`${b.artifact_kind}:${b.pointer}`));
}

function finding(rule, tools, refs, detail) {
  const derived = ['BB007', 'BB008', 'BB009', 'BB010', 'BB011'].includes(rule.id) || tools.some(tool => tool.provenance && (
    tool.provenance.input_trust === 'derived'
    || Object.values(tool.provenance.capabilities || {}).includes('derived')
    || tool.provenance.semantic_risks === 'derived'
  ));
  return {
    id: rule.id,
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    detail,
    affected_tools: [...new Set(tools.map(tool => tool.name))].sort(),
    evidence: uniqueRefs(refs),
    evidence_quality: derived ? 'derived' : 'explicit',
    stop: rule.stop,
    remediation: rule.remediation,
  };
}

function coverage(rule, code, message, kind = 'combined') {
  return { code, rule_id: rule.id, artifact_kind: kind, status: 'insufficient_evidence', message, artifact_name: null };
}

const RULES = [
  {
    id: 'BB001', severity: 'high', title: 'Untrusted input can reach code execution',
    description: 'A code or shell execution capability accepts content classified as untrusted.',
    stop: 'Disable the named executor for this session, or wrap it with a narrow argument allowlist and runtime sandbox.',
    remediation: 'Restrict executable inputs to trusted sources, validate against a narrow allowlist, and isolate execution in a runtime-enforced sandbox.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.includes('code_execution'));
      const exposed = capable.filter(tool => tool.input_trust === 'untrusted');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.input_trust]), `Untrusted input reaches ${exposed.length} code-execution tool(s).`) };
      if (capable.some(tool => tool.input_trust === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB001-INPUT-TRUST', 'Code execution is present, but its accepted input trust is not observable.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB002', severity: 'critical', title: 'Secret access is combined with unrestricted egress',
    description: 'The runtime can access secrets and has an unrestricted outbound network scope.',
    stop: 'Do not attach secret-reading and unrestricted network tools to the same agent; split the roles or allowlist destinations.',
    remediation: 'Scope credential access to named secrets and restrict outbound destinations to an explicit allowlist; separate secret-reading and network-sending roles.',
    evaluate(facts, rule) {
      const secretTools = facts.tools.filter(tool => tool.capabilities.includes('secret_read'));
      const secretAccess = facts.secret_access_unrestricted || secretTools.length > 0;
      if (secretAccess && facts.network_egress_unrestricted) {
        const refs = [
          secretTools.flatMap(tool => tool.refs.capabilities),
          facts.wildcards.filter(item => item.domain === 'credentials' || item.domain === 'network').map(item => item.ref),
        ];
        return { finding: finding(rule, secretTools, refs, 'Secret-reading capability and unrestricted network egress are both available.') };
      }
      if (secretAccess && !facts.network_scope_observed) return { gaps: [coverage(rule, 'BB-COV-BB002-EGRESS-SCOPE', 'Secret access is present, but a supported network-egress scope was not observed.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB003', severity: 'high', title: 'Consequential action lacks enforced approval',
    description: 'A destructive or financial capability can run without a runtime-enforced approval gate.',
    stop: 'Disable the consequential tool until the runtime enforces approval outside the model.',
    remediation: 'Place the named consequential tools behind a runtime-enforced approval gate and test that bypass attempts are blocked.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.some(capability => ['destructive_action', 'financial_action'].includes(capability)));
      const exposed = capable.filter(tool => tool.approval === 'not_enforced');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.approval]), `${exposed.length} consequential tool(s) lack enforced approval.`) };
      if (capable.some(tool => tool.approval === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB003-APPROVAL', 'Consequential capability is present, but approval enforcement is not observable.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB004', severity: 'medium', title: 'Untrusted content can reach persistent memory',
    description: 'A persistent write capability accepts content classified as untrusted.',
    stop: 'Disable persistent writes for untrusted content or quarantine them for operator review.',
    remediation: 'Validate and provenance-tag memory writes, segregate untrusted content, and require review before untrusted data influences later sessions.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.includes('persistent_write'));
      const exposed = capable.filter(tool => tool.input_trust === 'untrusted');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.input_trust]), `Untrusted content reaches ${exposed.length} persistent-write tool(s).`) };
      if (capable.some(tool => tool.input_trust === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB004-INPUT-TRUST', 'Persistent writes are present, but input trust is not observable.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB005', severity: 'medium', title: 'Privileged action lacks observable audit evidence',
    description: 'A privileged capability is configured without observable audit recording.',
    stop: 'Do not run the privileged action until invocation, approval, and outcome are recorded outside the agent.',
    remediation: 'Record privileged tool invocation, approval identity, outcome, and stable correlation IDs in an operator-controlled audit sink.',
    evaluate(facts, rule) {
      const capable = facts.tools.filter(tool => tool.capabilities.includes('privileged_action'));
      const exposed = capable.filter(tool => tool.audit === 'not_observable');
      if (exposed.length) return { finding: finding(rule, exposed, exposed.flatMap(tool => [tool.refs.capabilities, tool.refs.audit]), `${exposed.length} privileged tool(s) lack observable audit evidence.`) };
      if (capable.some(tool => tool.audit === 'unknown')) return { gaps: [coverage(rule, 'BB-COV-BB005-AUDIT', 'Privileged capability is present, but audit observability is not described.', 'permissions')] };
      return {};
    },
  },
  {
    id: 'BB006', severity: 'high', title: 'Runtime permission scope contains wildcards',
    description: 'Filesystem, subprocess, credential, or network permissions use an unrestricted wildcard scope.',
    stop: 'Replace each wildcard with the smallest explicit path, executable, credential, or destination allowlist.',
    remediation: 'Replace wildcard permissions with the smallest explicit path, executable, credential, and destination allowlists required by the runtime.',
    evaluate(facts, rule) {
      if (!facts.wildcards.length) return {};
      const scopes = [...new Set(facts.wildcards.map(item => `${item.domain}.${item.field}`))].sort();
      const item = finding(rule, [], facts.wildcards.map(entry => entry.ref), `Wildcard scopes: ${scopes.join(', ')}.`);
      item.evidence_quality = facts.wildcards.some(entry => entry.provenance === 'derived') ? 'derived' : 'explicit';
      return { finding: item };
    },
  },
  {
    id: 'BB007', severity: 'high', title: 'Tool accepts unconstrained interpreter or query text',
    description: 'A tool schema accepts raw command, expression, code, or SQL text without an observable constraint.',
    stop: 'Disable the tool or replace the free-form field with an enum or validated, parameterized operation.',
    remediation: 'Use parameterized queries and named operations; reject arbitrary commands, scripts, expressions, and SQL before tool dispatch.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.input_trust === 'untrusted' && tool.semantic_risks.some(item => item.id === 'arbitrary_interpreter_input'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'arbitrary_interpreter_input').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool(s) accept unconstrained interpreter or query text.`) };
    },
  },
  {
    id: 'BB008', severity: 'high', title: 'Tool accepts an unvalidated network destination',
    description: 'A network-capable tool accepts a URL, URI, endpoint, or webhook destination without an observable allowlist.',
    stop: 'Disable arbitrary destinations or wrap the tool with an explicit scheme-and-host allowlist.',
    remediation: 'Resolve destinations from operator-owned identifiers or enforce an explicit scheme and hostname allowlist before dispatch.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.input_trust === 'untrusted' && tool.semantic_risks.some(item => item.id === 'unvalidated_destination'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'unvalidated_destination').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool(s) accept an unvalidated network destination.`) };
    },
  },
  {
    id: 'BB009', severity: 'high', title: 'Tool description contains instruction-override language',
    description: 'A tool description contains language that attempts to replace system, developer, safety, operator, or user instructions.',
    stop: 'Do not attach the tool until the description is removed or rewritten and the server source is reviewed.',
    remediation: 'Treat tool metadata as untrusted input; reject instruction-override phrases and keep behavioral policy outside tool descriptions.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_instruction_override'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_instruction_override').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool description(s) contain instruction-override language.`) };
    },
  },
  {
    id: 'BB010', severity: 'high', title: 'Tool description asks to conceal behavior',
    description: 'A tool description tells the agent to hide an action or instruction from the user, operator, or human reviewer.',
    stop: 'Do not attach the tool until the concealment instruction is removed and the server source is reviewed.',
    remediation: 'Reject tool metadata that suppresses operator visibility; require user-visible intent, invocation, and outcome for consequential actions.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_concealed_behavior'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_concealed_behavior').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool description(s) request concealed behavior.`) };
    },
  },
  {
    id: 'BB011', severity: 'high', title: 'Tool description solicits sensitive data',
    description: 'A tool description directs passwords, secrets, credentials, tokens, private keys, or environment values into a result or transmission.',
    stop: 'Do not attach the tool or provide credentials until the sensitive-data instruction is removed and the destination is independently trusted.',
    remediation: 'Keep credentials out of tool descriptions and model-visible arguments; use runtime secret injection scoped to an allowlisted destination.',
    evaluate(facts, rule) {
      const exposed = facts.tools.filter(tool => tool.semantic_risks.some(item => item.id === 'prompt_sensitive_data_request'));
      if (!exposed.length) return {};
      const refs = exposed.flatMap(tool => tool.semantic_risks.filter(item => item.id === 'prompt_sensitive_data_request').map(item => item.ref));
      return { finding: finding(rule, exposed, refs, `${exposed.length} tool description(s) solicit sensitive data.`) };
    },
  },
  {
    id: 'BB012', severity: 'high', title: 'Untrusted network fetch shares an agent with privileged tools',
    description: 'A tool that retrieves untrusted network content is available in the same agent as a privileged action.',
    stop: 'Separate network retrieval from privileged tools, or quarantine fetched content before any privileged tool can consume it.',
    remediation: 'Use separate agent roles or a runtime-enforced trust boundary that prevents fetched content from influencing privileged tool selection and arguments.',
    evaluate(facts, rule) {
      const observations = facts.tools.flatMap(tool => (tool.inventory_observations || []).map(observation => ({ tool, observation })));
      const fetchObservations = observations.filter(({ observation }) => observation.input_trust === 'untrusted'
        && observation.semantic_risks.some(item => item.id === 'untrusted_network_fetch'));
      const privilegedObservations = observations.filter(({ observation }) => observation.capabilities.includes('privileged_action'));
      const privilegedInventories = new Set(privilegedObservations.map(item => item.observation.inventory));
      const sharedInventories = new Set(fetchObservations
        .filter(fetch => privilegedInventories.has(fetch.observation.inventory))
        .map(item => item.observation.inventory));
      if (!sharedInventories.size) return {};
      const matchedFetch = fetchObservations.filter(item => sharedInventories.has(item.observation.inventory));
      const matchedPrivileged = privilegedObservations.filter(item => sharedInventories.has(item.observation.inventory));
      const tools = [...matchedFetch, ...matchedPrivileged].map(item => item.tool);
      const refs = [
        matchedFetch.flatMap(({ observation }) => [
          observation.refs.input_trust,
          ...observation.semantic_risks.filter(item => item.id === 'untrusted_network_fetch').map(item => item.ref),
        ]),
        matchedPrivileged.flatMap(({ observation }) => observation.refs.capabilities),
      ];
      return { finding: finding(rule, tools, refs, `${matchedFetch.length} untrusted fetch tool observation(s) share an inventory with ${matchedPrivileged.length} privileged tool observation(s).`) };
    },
  },
];

const RULESET_DIGEST = sha256(fs.readFileSync(__filename));

function evaluateRules(facts) {
  const findings = [];
  const coverageGaps = [];
  for (const rule of RULES) {
    const result = rule.evaluate(facts, rule);
    if (result.finding) findings.push(result.finding);
    if (result.gaps) coverageGaps.push(...result.gaps);
  }
  return { findings, coverage_gaps: coverageGaps };
}

function meetsThreshold(findings, threshold) {
  if (threshold === 'none') return false;
  const minimum = SEVERITY_ORDER[threshold];
  return findings.some(item => SEVERITY_ORDER[item.severity] >= minimum);
}

module.exports = { RULES, RULESET_DIGEST, RULESET_VERSION, SEVERITY_ORDER, evaluateRules, meetsThreshold };
