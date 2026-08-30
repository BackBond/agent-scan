'use strict';

const EXPOSURE_PATH_PROTOCOL = 'backbond-exposure-paths/v1';

const DEFINITIONS = [
  {
    id: 'EP001',
    trigger: 'BB012',
    title: 'Untrusted retrieval shares context with privileged tools',
    chain: ['untrusted network retrieval', 'shared agent context', 'privileged tool availability'],
    supporting: ['BB001', 'BB007', 'BB012'],
    action: 'Split retrieval and privileged execution into isolated contexts, or enforce a runtime trust boundary between them.',
  },
  {
    id: 'EP002',
    trigger: 'BB002',
    title: 'Secret access is combined with unrestricted egress',
    chain: ['secret access', 'shared agent authority', 'unrestricted network egress'],
    supporting: ['BB002', 'BB006'],
    action: 'Separate secret-reading and network-sending roles, and restrict both secrets and destinations to explicit allowlists.',
  },
  {
    id: 'EP003',
    trigger: 'BB001',
    title: 'Untrusted input can reach code execution',
    chain: ['untrusted input', 'model-selected tool call', 'code or shell execution'],
    supporting: ['BB001', 'BB007'],
    action: 'Disable the executor or place it behind narrow argument validation and a runtime-enforced sandbox.',
  },
];

function buildExposurePaths(findings) {
  const byId = new Map(findings.map(item => [item.id, item]));
  const paths = DEFINITIONS.filter(definition => byId.has(definition.trigger)).map(definition => {
    const triggerFinding = byId.get(definition.trigger);
    const triggerTools = new Set(triggerFinding.affected_tools);
    const linked = definition.supporting.filter(id => {
      const finding = byId.get(id);
      return finding && (id === definition.trigger || finding.affected_tools.some(tool => triggerTools.has(tool)));
    });
    const linkedFindings = linked.map(id => byId.get(id));
    return {
      id: definition.id,
      kind: 'potential_exposure_path',
      title: definition.title,
      chain: [...definition.chain],
      finding_ids: linked,
      affected_tools: [...new Set(linkedFindings.flatMap(item => item.affected_tools))].sort(),
      evidence_quality: linkedFindings.some(item => item.evidence_quality === 'derived') ? 'derived' : 'explicit',
      action: definition.action,
      caveat: 'Potential composition inferred from static co-residence; not an observed runtime data flow.',
    };
  });
  return { protocol: EXPOSURE_PATH_PROTOCOL, paths };
}

module.exports = { EXPOSURE_PATH_PROTOCOL, buildExposurePaths };
