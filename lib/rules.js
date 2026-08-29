'use strict';

const fs = require('node:fs');
const { sha256 } = require('./canonical.js');

const RULESET_VERSION = 'backbond-local-rules/1.0.0';
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

function uniqueRefs(refs) {
  const seen = new Set();
  return refs.flat().filter(Boolean).filter(item => {
    const key = `${item.artifact_kind}:${item.artifact_name}:${item.pointer}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => `${a.artifact_kind}:${a.pointer}`.localeCompare(`${b.artifact_kind}:${b.pointer}`));
}

function finding(rule, tools, refs, detail) {
  return {
    id: rule.id,
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    detail,
    affected_tools: [...new Set(tools.map(tool => tool.name))].sort(),
    evidence: uniqueRefs(refs),
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
    remediation: 'Replace wildcard permissions with the smallest explicit path, executable, credential, and destination allowlists required by the runtime.',
    evaluate(facts, rule) {
      if (!facts.wildcards.length) return {};
      const scopes = facts.wildcards.map(item => `${item.domain}.${item.field}`).sort();
      return { finding: finding(rule, [], facts.wildcards.map(item => item.ref), `Wildcard scopes: ${scopes.join(', ')}.`) };
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
