'use strict';

const { safeInline } = require('./text.js');

function countSummary(summary) {
  const parts = Object.entries(summary.by_severity)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`);
  return `${summary.total} finding${summary.total === 1 ? '' : 's'}${parts.length ? ` (${parts.join(', ')})` : ''}`;
}

function findingSubject(item) {
  if (item.affected_tools.length) return item.affected_tools.join(' + ');
  const wildcard = item.detail.match(/^Wildcard scopes: (.+)\.$/);
  return wildcard ? wildcard[1] : item.title;
}

function renderHuman(scan, options = {}) {
  const lines = [scan.status === 'inconclusive' ? `INCONCLUSIVE — ${countSummary(scan.summary)}` : countSummary(scan.summary)];
  if (scan.discovery) {
    const labels = scan.discovery.files.map(item => `${item.adapter}:${item.name}`);
    const shown = labels.slice(0, 4).join(', ') || 'no recognized configs';
    lines.push(`Scanned: ${shown}${labels.length > 4 ? `, +${labels.length - 4} more` : ''}; ${scan.discovery.instruction_files.length} instruction file${scan.discovery.instruction_files.length === 1 ? '' : 's'} noted`);
  }
  for (const item of scan.findings) {
    lines.push(`${item.id} ${findingSubject(item)}${item.evidence_quality === 'derived' ? ' [derived]' : ''}`);
    lines.push(`  Stop: ${item.stop}`);
  }
  if (scan.coverage.gaps.length) {
    const messages = [...new Set(scan.coverage.gaps.map(item => item.message))];
    const shown = messages.slice(0, 2).join('; ');
    lines.push(`Coverage: ${shown}${messages.length > 2 ? `; +${messages.length - 2} more gap${messages.length - 2 === 1 ? '' : 's'}` : ''}`);
  } else {
    lines.push('Coverage: complete');
  }
  if (options.policy) {
    const disabled = options.policy.actions.filter(item => item.action === 'disable').map(item => item.tool);
    const wrapped = options.policy.actions.filter(item => item.action === 'wrap').map(item => item.tool);
    if (disabled.length) lines.push(`Suggested deny: ${[...new Set(disabled)].join(', ')}`);
    if (wrapped.length) lines.push(`Suggested wrap: ${[...new Set(wrapped)].join(', ')}`);
    lines.push('Policy suggestions are not enforced or automatically applied.');
  }
  if (options.receiptPath) lines.push(`Receipt: ${options.receiptPath}`);
  return `${lines.map(line => safeInline(line)).join('\n')}\n`;
}

module.exports = { renderHuman };
