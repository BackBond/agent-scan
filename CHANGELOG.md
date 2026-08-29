# Changelog

All notable changes to `@backbond/agent-scan` are recorded here.

## 0.5.0 — 2026-08-29

- Replace the capture-only analyzer bridge with a dependency-free local deterministic scanner.
- Add the public `backbond-local-rules/1.0.0` rule pack with named findings BB001–BB006, evidence pointers, severity, and remediation.
- Support canonical BackBond tool, permission, and trace dialects plus OpenAI, Anthropic, and MCP tool schemas.
- Add explicit coverage gaps for missing, unsupported, and insufficient evidence instead of inventing findings or passes.
- Add stable CI exit codes and `--fail-on critical|high|medium|low|none`.
- Add tamper-evident and optionally Ed25519-signed receipts for input hashes, ruleset identity, and findings.
- Keep raw artifact bodies, prompts, trace arguments, secret values, and environment values out of output and receipts.
- Make legacy claims optional hypotheses that can annotate contradictions but never affect findings or severity.
- Ship vulnerable and hardened fixtures that prove the entire local rule pack.
- Remove analyzer execution, hosted POST, score, badge, and analyzer-dependent GitHub Action paths.

## 0.4.1 — 2026-08-29

- State prominently that the public package is evidence capture, not a
  standalone scan or quick exposure check.
- Document that 0.4.x is not a drop-in replacement for the 0.2.0 teaser.
- Clarify that a caller-supplied SHA-256 pin establishes byte identity only;
  it does not authenticate the analyzer publisher or make executable code safe.
- Label analyzer output as analyzer-reported rather than verified by the client.
- Remove scanner, risk-score, MCP, and self-assessment discovery keywords that
  no longer describe the public package.

## 0.4.0 — 2026-08-29

- Split proprietary analysis into a private, separately distributed core.
- Remove scoring, classification, detector, calibration, and policy-decision implementations from the public package.
- Make the public client a neutral artifact-hashing, receipt, and analyzer-bridge layer.
- Require an explicit SHA-256 pin before executing a private analyzer.
- Fail closed with `analysis_required` when the private analyzer is absent.
- Add current-tree and Git-history publication gates.
- Require public v0.4 releases to originate from a new, history-clean repository.

Earlier prototype history is intentionally excluded from the history-clean public v0.4 repository.
