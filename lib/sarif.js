'use strict';

const { RULES } = require('./rules.js');

function level(severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function location(evidence) {
  return {
    physicalLocation: { artifactLocation: { uri: evidence.artifact_name } },
    logicalLocations: [{ fullyQualifiedName: evidence.pointer, kind: 'json-pointer' }],
  };
}

function toSarif(scan) {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: '@backbond/agent-scan',
          version: scan.scanner.version,
          informationUri: 'https://github.com/BackBond/agent-scan',
          rules: RULES.map(rule => ({
            id: rule.id,
            name: rule.title.replace(/[^a-z0-9]+/gi, '_'),
            shortDescription: { text: rule.title },
            fullDescription: { text: rule.description },
            help: { text: rule.remediation },
            helpUri: `https://backbond.ai/agent-scan/rules/#${rule.id}`,
            properties: { securitySeverity: String({ critical: 9.5, high: 8, medium: 5, low: 2 }[rule.severity]) },
          })),
        },
      },
      results: scan.findings.map(item => ({
        ruleId: item.id,
        level: level(item.severity),
        message: { text: `${item.title}. ${item.detail} Stop: ${item.stop}` },
        locations: item.evidence.slice(0, 10).map(location),
        properties: { severity: item.severity, evidenceQuality: item.evidence_quality, affectedTools: item.affected_tools },
      })),
      invocations: [{ executionSuccessful: true }],
      properties: { coverageStatus: scan.coverage.status, coverageGaps: scan.coverage.gaps.map(item => item.code) },
    }],
  };
}

module.exports = { toSarif };
