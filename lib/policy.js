'use strict';

const HIGH_RISK = new Set(['critical', 'high']);

function actionForFinding(finding, tool) {
  if (['BB001', 'BB002', 'BB003', 'BB007', 'BB008'].includes(finding.id)) {
    return {
      action: HIGH_RISK.has(finding.severity) ? 'disable' : 'wrap',
      tool,
      finding_id: finding.id,
      until: finding.stop,
    };
  }
  return { action: 'wrap', tool, finding_id: finding.id, until: finding.stop };
}

function suggestedPatches(scan) {
  const patches = [];
  for (const finding of scan.findings) {
    if (finding.id === 'BB006') {
      for (const evidence of finding.evidence) {
        patches.push({
          artifact_name: evidence.artifact_name,
          operations: [{ op: 'replace', path: evidence.pointer, value: ['<explicit-allowlist-entry>'] }],
          template: true,
          safe_to_apply_automatically: false,
          finding_id: finding.id,
        });
      }
    }
    if (finding.id === 'BB003') {
      for (const evidence of finding.evidence.filter(item => item.pointer.endsWith('/approval'))) {
        patches.push({
          artifact_name: evidence.artifact_name,
          operations: [{ op: 'replace', path: evidence.pointer, value: 'enforced' }],
          template: true,
          safe_to_apply_automatically: false,
          finding_id: finding.id,
        });
      }
    }
  }
  return patches;
}

function suggestPolicy(scan) {
  const actions = [];
  for (const finding of scan.findings) {
    for (const tool of finding.affected_tools) actions.push(actionForFinding(finding, tool));
  }
  const seen = new Set();
  return {
    protocol: 'backbond-policy-suggestion/v1',
    mode: 'suggestion_only',
    enforced: false,
    actions: actions.filter(item => {
      const key = `${item.action}:${item.tool}:${item.finding_id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
    patches: suggestedPatches(scan),
    warning: 'Review against the runtime configuration. Template placeholders and inferred findings must not be auto-applied.',
  };
}

module.exports = { suggestPolicy };
