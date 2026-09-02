# Changelog

All notable changes to `@backbond/agent-scan` are recorded here.

## Unreleased

- Add a security-reporting policy with a private contact route, sensitive-data boundary, supported-version scope, and current-release verification guidance.
- Point the CLI and README follow-up link to the live Agent Scan page instead of the placeholder BackBond homepage.

## 0.6.2 — 2026-09-02

- Advance the public ruleset to `backbond-local-rules/2.0.1` after a saved-output audit of all 191 manifests whose BB001 presence changed between 0.5.15 and 0.6.1.
- Require direct interpreter context for generic `query`, `code`, and `expression` fields. Database catalog search, referral codes, quoted executor names, delegated SQL references, arithmetic expressions, and SQL authorization gates no longer become high BB001/BB007 findings from a nearby keyword alone; unconstrained formal query or expression syntax remains an explicit REVIEW gap.
- Restore high BB001/BB007 findings for direct Wolfram Language, SQL, HogQL, DataCanvas, Iceberg, QuickBooks, and nested analytics-query inputs, including active Spanish and French execution descriptions observed in the frozen corpus.
- Treat only a syntactically valid, anchored, narrowly parsed identifier schema `pattern` as an execution-input constraint. Unanchored, malformed, wildcard, unsafe-range, negated-class, match-any, and length-only patterns retain high findings; explicit runner/executor identities and direct query-execution descriptions fail closed.
- Coalesce repeated schema-risk evidence per tool and skip interpreter analysis for unrelated field names, preventing adversarial wide schemas from amplifying one query phrase into an unbounded evidence object or unnecessary regex work.
- Add eight redacted corpus-derived regression boundaries: four direct executors, two formal-query REVIEW cases, and two clean identifier/search cases. The fixture metadata records the 191-row delta digest and does not claim representative prevalence or independent runtime validation.
- Lock the read-only documentation boundary against argument-name sensitivity (BEAAA-28649/F2). `explain_shell`-shaped tools that state they do not execute anything now return the same clean decision whether the single property is named `command` or `text`; both spellings are pinned as corpus-regression boundaries so the verdict can no longer be driven by the property name alone.
- Make the offline corpus rerun report label its current package version dynamically. The scanner remains local and static: this release adds no registry collection, live server spawn, tool invocation, hosted upload, score, auto-fix, or insurance decision.

## 0.6.1 — 2026-09-01

- Publish the 0.6 precision release after the `v0.6.0` tag workflow stopped during tests, before npm, GitHub Release, or MCP Registry publication.
- Define the bundled public-record example checksum over canonical LF bytes so the release boundary test is consistent on Windows and Linux, and update public installation pins to the corrected `0.6.1` release.

## 0.6.0 — 2026-09-01

- Advance the public ruleset to `backbond-local-rules/2.0.0` after the 2026-08-31 corpus precision review; no new BB rule is added. The major ruleset version marks materially narrower pre-attachment semantics while package 0.6 remains the same local static scanner.
- Make BB004 a medium REVIEW finding for a standalone untrusted persistent write and raise it to high only when untrusted network intake or an unallowlisted destination appears in the same supplied inventory.
- Require active network context plus a URL-like unconstrained field for BB008. Route ambiguous endpoint, href, path, host, destination, documentation/reference URL without explicit fetch action, GIS query, filter, and calculator-expression metadata to explicit pre-attachment REVIEW coverage instead of a high finding or a clean result.
- Require fetch-shaped evidence plus explicit capabilities, a destructive annotation, an OpenAPI DELETE method, or an action-shaped tool identity for BB012. Privilege words such as permission or delete in help text do not complete the composition signal.
- Preserve high BB007 for recognizable shell, code, evaluator, and database-interpreter inputs while removing generic query/expression collisions from the block path.
- Route quoted directives to REVIEW, retain direct unquoted prompt directives as high findings, classify BB011 matches as secret solicitation or credential emission/transmission, and report claimed permission requirements as unverified coverage.
- Make any scoped medium finding return REVIEW in `vet-tools`; add explicit profile coverage states showing that runtime permissions, approval, audit, and execution are unobservable or not performed.
- Bind the pre-attachment profile digest to the ruleset version and digest, so a ruleset change cannot retain the same gate identity.
- Add ten synthetic precision-boundary fixtures and a regression test. The raw corpus was recovered and replayed, but promotion of copied corpus rows remains pending two independent blinded adjudications, so the shipped cases are not represented as human-adjudicated registry rows.
- Add a research-only JSONL summarizer that emits decision/rule/coverage histograms and template multiplicity without server IDs, tool names, or template hashes. It does not collect from the Registry and is not included as a packaged CLI command.
- Add `vet-tools --summary-only` for large operator-staged runs. The new `backbond-vet-summary/v1` output preserves decision exits and version/count histograms while omitting tool and server identities, descriptions, artifact names, evidence pointers, and template hashes.
- Add structured `review_items` to the pre-attachment profile and summary-only output. Each medium finding or coverage gap now states its stable code, affected-tool count when observable, reason, evidence needed, and next operator step without changing detector severity or applying remediation.
- Let the research JSONL summarizer consume either full local results or summary-only rows, reject mixed-mode input, aggregate review-item codes, and disclose when privacy-safe rows prevent cross-manifest template deduplication.
- Remove the non-standard top-level `skills` field from both Agent Plugin manifests. The skill remains discoverable from the standard `skills/agent-scan/` directory, and the public-boundary test now enforces both the v1.0 manifest shape and the on-disk skill path.
- Update the package, site, skill, Action, plugin, and installation copy to one exact `0.6.0` pin. Keep the scanner local and static: no registry URL intake, live probing, `tools/call`, hosted upload, score, or insurance decision.

## 0.5.15 — 2026-08-31

- Advance the public ruleset to `backbond-local-rules/1.4.0` after a focused false-positive review of model-facing tool descriptions.
- Narrow `BB009`–`BB011` and `BB013` to directed behavior: suppress quotations only in explicit example or security-analysis context, preserve standalone quoted directives, exclude authentication mentions without solicitation, and distinguish scoped routing guidance from passive or active global forced invocation.
- Add `finding_class` and an honest `precision_note` to findings and SARIF, plus separate capability-exposure and prompt-injection-indicator counts in JSON and compact human output. These fields do not change severities or exit-code semantics.
- Add normalized metadata-template hashes and multiplicity to full local JSON for offline deduplication of repeated prompt copy. Receipts and public records continue to omit those hashes, descriptions, and tool metadata.
- Make the pre-attachment profile return `review` rather than a false non-blocking decision when directive-like text is presented as an example or scoped response-ordering instruction, or when a schema exceeds the bounded local depth/node analysis budget.
- Add a canonical pre-attachment profile digest that binds the fixed rule set, threshold, exit mapping, supported dialects, confusable-name map, and coverage/decision functions independently from the general ruleset digest.
- Keep `BB001`–`BB008` and `BB012` capability/data-flow behavior, protocols, the static-only execution model, and the scanner's no-network boundary unchanged.

## 0.5.14 — 2026-08-31

- Declare the bundled `agent-scan` skill explicitly in both Agent Plugin manifests so marketplace lint validates the skill at its real directory instead of treating the staging directory as a skill.
- Keep the dedicated marketplace source root introduced in 0.5.13 and keep BB001–BB013 detector behavior, ruleset `backbond-local-rules/1.3.0`, protocols, exit codes, Action behavior, and the scanner's no-network boundary unchanged.

## 0.5.13 — 2026-08-31

- Add a dedicated `plugins/backbond-agent-scan` source root for external Agent Plugin marketplaces so the immutable release installs without treating the repository root as an absolute path.
- Keep the marketplace bundle skill-only, with the same `agent-scan` skill instructions and no hooks, commands, or plugin-level MCP configuration.
- Keep BB001–BB013 detector behavior, ruleset `backbond-local-rules/1.3.0`, protocols, exit codes, Action behavior, and the scanner's no-network boundary unchanged from 0.5.12.

## 0.5.12 — 2026-08-31

- Add a skill-only Agent Plugin manifest and ship the standard `skills/agent-scan` folder in the npm package. Installing the plugin or skill cannot start a process, attach an MCP server, or run a scan.
- Rewrite Agent Skill discovery metadata around pre-attachment tool vetting, tool poisoning, forced invocation, confusable identities, unconstrained execution inputs, and risky tool composition.
- Add canonical website and first-party icon metadata to the MCP Registry card, plus read-only, non-destructive, idempotent annotations to both local MCP tools.
- Give every SARIF rule a stable `https://backbond.ai/agent-scan/rules/#BB...` help link and add an explicit, local-only `sarif-path` output for the Action's `vet-tools` mode. The Action never uploads SARIF automatically.
- Add a reusable repository policy block and version-pinned skill installation path for agent-native distribution.
- Keep BB001–BB013 detector behavior, ruleset `backbond-local-rules/1.3.0`, scan/record protocols, exit codes, and the scanner's no-network boundary unchanged from 0.5.11.

## 0.5.11 — 2026-08-31

- Present the official Action in GitHub Marketplace as **BackBond Agent Scan**, with a pre-attachment MCP manifest description and unchanged Action execution behavior.
- Point npm and the packaged discovery card at `https://backbond.ai/agent-scan/`, and add explicit MCP, Agent Skills, and tool-security discovery keywords.
- Advance current commands, the bundled Agent Skill, Action examples, and registry metadata to the exact `0.5.11` pin.
- Keep scanner code, Action code, BB001–BB013 detector behavior, ruleset `backbond-local-rules/1.3.0`, protocols, exit codes, fixtures, and the local/no-network boundary byte-identical to 0.5.10.

## 0.5.10 — 2026-08-30

- Add a strict `mode: vet-tools` path to the official Action. It accepts exactly one committed tool manifest, preserves the CLI's `block`/`review`/`no_blocking_finding` exit codes, emits privacy-safe workflow outputs and a job summary, and creates no public record.
- Add a dynamic **BackBond Schema Check** workflow badge kit. The badge links to workflow evidence and is explicitly a static committed-manifest status—not independent verification, runtime assurance, deployed-state proof, insurance coverage, or a permanently green certification image.
- Add structured, review-only BB007 and BB013 remediation templates through `vet-tools --suggest-policy --json`. Templates retain placeholders, require environment-specific review, are marked unsafe for automatic application, and have no mutation path.
- Add a restrained next step after the coverage disclaimer for users seeking deeper assessment, continuous runtime evidence, or information about financial protection where approved.
- Keep BB001–BB013 detector behavior, ruleset `backbond-local-rules/1.3.0`, scan/record protocols, zero scanner-network boundary, and the existing five-external-run launch gate unchanged. Existing pinned 0.5.9 runs still count; new instructions pin 0.5.10.

## 0.5.9 — 2026-08-30

- Remove third-party company, product, reviewer, and person references from public prose; identify the scanner only by its exact scoped package name and pinned version. Retain external names only inside technical URLs, protocol IDs, source adapters, tests, and release automation where compatibility requires them.
- Keep the scanner implementation, BB001–BB013 rules, ruleset `backbond-local-rules/1.3.0`, findings, thresholds, protocols, and offline/network boundaries unchanged from 0.5.8.

## 0.5.8 — 2026-08-30

- Derive the public ruleset digest from canonical rule definitions, shared rule helpers, and the normalized evidence-detector source hash instead of the physical `lib/rules.js` file, so equivalent packaged and standalone builds retain one ruleset identity without hiding behavioral changes.
- Build and publish an unminified, dependency-free `agent-scan.cjs` release asset and its SHA-256 for environments where remote package and source registries cannot be reached from the agent sandbox; verify its `scan`, `vet-tools`, and `mcp` behavior against the packaged CLI and exercise it in a no-network namespace during release.
- Add derived `BB013` prompt lint for tool descriptions that demand mandatory selection, invocation before responding, or exclusion of competing tools. It blocks in `vet-tools` and remains on the general scan's separate `--fail-on-prompt` threshold.
- Make `vet-tools` return `review`/exit `3` for case-, compatibility-, separator-, and common cross-script-confusable tool identities; any non-ASCII tool identity also requires review instead of receiving a non-blocking result.
- Return structured `review`/exit `3` for ambiguous, mixed-dialect, or multiple-schema-alias pre-attachment manifests while preserving exit `2` for the same invalid input in the broader scanner.
- Suppress the derived BB001 execution inference for clearly non-executing, read-only explanation, description, lint, and analysis tools unless their description or parameter schema still indicates execution.
- Advance the public ruleset to `backbond-local-rules/1.3.0`; keep receipt/public-record protocols, static-only behavior, and local/network boundaries unchanged.
- Keep the official MCP Registry entrypoint as the local stdio `mcp` command exposing `scan_my_runtime` and `vet_tools_before_attach`; it does not probe or execute registered servers.
- Lead the README with trusted-host delivery and document the network-isolated no-egress case without suggesting that operators weaken the sandbox.
- Deprecate npm version `0.5.6` during the protected release because it carried an MCP Registry identity outside BackBond's case-sensitive namespace.

## 0.5.7 — 2026-08-30

- Correct the case-sensitive official MCP Registry identity to `io.github.BackBond/agent-scan`, matching the namespace granted to the BackBond source repository by Registry OIDC.
- Keep the scanner, ruleset, findings, thresholds, receipt protocols, public-record protocols, and local/network boundary unchanged from 0.5.6.

## 0.5.6 — 2026-08-30

- Add the package `mcpName` ownership marker and a version-locked `server.json` for an official MCP Registry name. The initial lowercase source owner did not match the case-sensitive OIDC namespace and was corrected in 0.5.7.
- Publish registry metadata only after the exact package artifact and source release have been verified, using source-workflow OIDC and a checksum-pinned official `mcp-publisher` binary.
- Keep the scanner, public ruleset, findings, thresholds, receipt protocols, public-record protocols, and local/network boundary unchanged from 0.5.5.

## 0.5.5 — 2026-08-30

- Add the scoped `vet-tools` pre-attachment profile for MCP, supported function-tool, and OpenAPI manifests, with fixed `block`/`review`/`no_blocking_finding` decisions and exit codes `1`/`3`/`0`.
- Require complete tool metadata for a non-blocking profile result and state explicitly that profile completeness is not a safety determination, runtime attestation, policy enforcement fact, or insurance decision.
- Expose the same strict profile as `vet_tools_before_attach` over the dependency-free MCP stdio server; do not fall back to discovery or accept record, receipt, threshold, or policy arguments.
- Add `EP001`–`EP003` potential exposure-path summaries over existing findings without adding rules, changing severity, changing thresholds, or changing receipt/public-record protocols.
- Put the pinned pre-attachment command in `--help` and incomplete-discovery next actions alongside the broader strict scan command.
- Keep the public ruleset at `backbond-local-rules/1.2.1`; this release changes presentation and scoped workflow, not detector logic.
- Clarify that the free package is local awareness and triage, while BackBond's separate complete solution combines deeper evaluation, continuous runtime evidence, and—where approved—financial protection. Running the package creates no coverage or eligibility implication.

## 0.5.4 — 2026-08-29

- Make every generated and `--help` live `tools/list` command retain strict coverage gating with `--require-coverage`.
- Label v2 commit metadata as caller-supplied and unverified without changing the record protocol shape.
- Add a dependency-free official CI Action that verifies `HEAD` and every explicit tracked input against `github.sha`, runs the scanner bundled with the selected Action version, and writes a redacted record plus job summary while preserving scanner exit codes.
- Keep the public ruleset at `backbond-local-rules/1.2.1`; this release adds no findings or inference changes.

## 0.5.3 — 2026-08-29

- Make inconclusive zero-argument and argument-free MCP scans return an exact, pinned `next_action` for captured live `tools/list` input.
- Put a five-step, cross-shell live tool export recipe directly in `--help`.
- Separate runtime exposure gating (`--fail-on`) from description-only prompt lint (`--fail-on-prompt`) without hiding `BB009`–`BB011` findings.
- Add opt-in commit-bound `backbond-scan-record/v2` records through `--record-commit`, while leaving unbound records on v1.
- Infer capabilities from configured MCP server names, commands, and arguments so shell, fetch, filesystem, database, and credential-server identities cannot disappear behind a missing live export.
- Map recognized command, root-file-access, and unrestricted-fetch permissions into derived wildcard scopes; distinguish writable root mounts from read-only mounts.
- Reject undeclared or mistyped `scan_my_runtime` arguments instead of silently falling back to discovery.
- Reduce execution false positives for explicitly read-only documentation tools and recognize executable `cmd`, `python`, and `code` parameters.
- Distinguish constrained data fields such as country codes from executable inputs while recognizing active execution descriptions in ordinary prose.
- Recognize passive and contrastive execution descriptions without turning explanatory documentation into execution findings.
- Fail closed on malformed network allowlists, preserve permission coverage gaps for empty supported settings, and recognize bare tool permissions plus mixed positive/negative execution descriptions.
- Bound CLI stdin manifests and MCP JSON-RPC messages to 4 MiB before parsing.
- Keep near-limit wide schemas stack-safe and restrict configured server-command inference to the documented command basename.
- Advance the public ruleset identity to `backbond-local-rules/1.2.1` so changed rule bytes never reuse the 1.2.0 receipt identity.
- Document known derived-rule overreach and keep the release free of new rules, live command execution, automatic fixes, and custom rulesets.

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
- Stop cleanly when the package client cannot resolve its registry and document a verified offline transfer path using the exact package tarball and SHA-256 attached to the official source release.
- Make tag publishing fail closed unless the tagged package contents match the registry, then attach the registry-authoritative tarball and its exact SHA-256 to the source release.

## 0.5.1 — 2026-08-29

- Make `scan` with no artifact arguments discover bounded project and user MCP configuration for supported desktop and coding-agent clients.
- Add `scan_my_runtime` over a dependency-free MCP stdio server and accept live tool manifests through `--stdin`.
- Add OpenAPI 3.x tool ingestion and OpenTelemetry OTLP JSON trace ingestion.
- Conservatively infer capabilities and input exposure from tool names, descriptions, and parameter schemas; label every inferred finding as `derived`.
- Add semantic rules `BB007` for unconstrained command/expression/SQL input and `BB008` for unvalidated destinations.
- Replace verbose default output with finding IDs, affected tools, immediate `Stop` instructions, and compact coverage gaps.
- Add non-enforcing `--suggest-policy` actions and review-required patch templates; no automatic mutation is implemented.
- Add SARIF 2.1.0 output and fix receipts to bind evidence to both artifact kind and name when multiple inputs are scanned.
- Add three anonymized non-BackBond fixtures for MCP tool lists, wildcard sandbox scopes, and trusted-tool settings.
- Ship pinned `AGENTS.md` and `SKILL.md` instructions that keep traces local and distinguish this package from similarly named scanners.

## 0.5.0 — 2026-08-29

- Replace the capture-only analyzer bridge with a dependency-free local deterministic scanner.
- Add the public `backbond-local-rules/1.0.0` rule pack with named findings BB001–BB006, evidence pointers, severity, and remediation.
- Support canonical BackBond tool, permission, and trace dialects plus MCP and supported function-tool schemas.
- Add explicit coverage gaps for missing, unsupported, and insufficient evidence instead of inventing findings or passes.
- Add stable CI exit codes and `--fail-on critical|high|medium|low|none`.
- Add tamper-evident and optionally Ed25519-signed receipts for input hashes, ruleset identity, and findings.
- Keep raw artifact bodies, prompts, trace arguments, secret values, and environment values out of output and receipts.
- Make legacy claims optional hypotheses that can annotate contradictions but never affect findings or severity.
- Ship vulnerable and hardened fixtures that prove the entire local rule pack.
- Remove analyzer execution, hosted POST, score, badge, and analyzer-dependent CI Action paths.

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
