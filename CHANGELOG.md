# Changelog

All notable changes to `@backbond/agent-scan` are recorded here.

## 0.5.2 — 2026-08-29

- Add privacy-safe `backbond-scan-record/v1` public records through `--record-public`, with compact pasteable output and self-run/unverified assurance language.
- Redact tool names and input fingerprints by default; require separate explicit disclosure flags and never include paths, basenames, descriptions, bodies, or evidence pointers.
- Report partial zero-finding scans as `inconclusive` and add `--require-coverage`, which exits `3` when required coverage is incomplete.
- Add MCP `emit_record` mode that returns only compact text and the redacted record, without the full scan, receipt, discovery paths, or tool names.
- Add derived tool-description prompt lint: `BB009` instruction override, `BB010` concealed behavior, and `BB011` sensitive-data solicitation.
- Add `BB012` when a fetch-like untrusted network tool shares an agent with a privileged tool.
- Encode control characters in human, MCP text, and compact-record rendering so artifact-supplied tool names cannot forge output lines or terminal state.
- Document direct ingestion of a captured MCP `tools/list` response through `scan --stdin`; do not spawn commands found in agent configuration.
- Clarify that scanner execution is local and network-free while first-time package installation may contact the configured npm registry.
- Stop cleanly when npm cannot resolve the registry and document a verified offline transfer path using the exact npm tarball and SHA-256 attached to the official GitHub release.
- Make tag publishing fail closed unless the tagged package contents match npm, then attach the registry-authoritative tarball and its exact SHA-256 to the GitHub release.

## 0.5.1 — 2026-08-29

- Make `scan` with no artifact arguments discover bounded project and user MCP configuration for Claude, Cursor, VS Code, Windsurf, and Gemini.
- Add `scan_my_runtime` over a dependency-free MCP stdio server and accept live tool manifests through `--stdin`.
- Add OpenAPI 3.x tool ingestion and OpenTelemetry OTLP JSON trace ingestion.
- Conservatively infer capabilities and input exposure from tool names, descriptions, and parameter schemas; label every inferred finding as `derived`.
- Add semantic rules `BB007` for unconstrained command/expression/SQL input and `BB008` for unvalidated destinations.
- Replace verbose default output with finding IDs, affected tools, immediate `Stop` instructions, and compact coverage gaps.
- Add non-enforcing `--suggest-policy` actions and review-required patch templates; no automatic mutation is implemented.
- Add SARIF 2.1.0 output and fix receipts to bind evidence to both artifact kind and name when multiple inputs are scanned.
- Add three anonymized non-BackBond fixtures for MCP tool lists, VS Code wildcard sandbox scopes, and Gemini trusted tools.
- Ship pinned `AGENTS.md` and `SKILL.md` instructions that keep traces local and distinguish this package from similarly named scanners.

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
