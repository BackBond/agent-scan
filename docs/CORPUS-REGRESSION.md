# Corpus regression and publication boundary

The 2026-08-31 MCP Registry report is a precision-discovery input, not a representative ecosystem score. It records a selected, reachable, unauthenticated subset and static tool metadata. It does not establish deployed behavior, runtime controls, operator intent, exploitability, or eligibility for financial protection.

The analysis-ready CSV and raw-manifest archive were recovered on 2026-09-01. The CSV contains 7,749 rows and the archive contains 7,749 unique JSON manifests. Every row joins to exactly one manifest. Both exports parse cleanly, their tool counts and tool-name lists match, and a local replay of package 0.5.15 / ruleset 1.4.0 reproduced every decision and rule count with zero mismatches. The fixture index records the export checksums and this baseline verification.

The fixture directory now contains ten synthetic precision boundaries from 0.6.0 and eight redacted BB001 boundaries derived from the 191-row saved-output delta audit. The corpus-derived cases retain only the metadata needed to reproduce the rule boundary and record the delta export digest; they omit server names and URLs. They are regression evidence, not representative prevalence evidence, runtime validation, or an independently blinded corpus sample.

The current 18-case boundary set locks seven BLOCK cases, five `no_blocking_finding` cases, five semantic REVIEW cases, and one incomplete-schema REVIEW case. It protects the distinctions introduced through package 0.6.2 / ruleset `backbond-local-rules/2.0.1`:

- active unallowlisted URL input versus ambiguous endpoint/path language;
- fetch-shaped plus real privilege composition versus privilege words appearing only in help text;
- executable interpreter input versus generic GIS/query/expression text;
- direct prompt directives versus quoted or example-framed directives;
- asserted permission requirements versus observable runtime enforcement; and
- global forced tool selection versus scoped routing guidance.

Focused unit tests outside the fixture pack separately lock BB004's standalone-write REVIEW boundary, the same-inventory network-intake BLOCK boundary, and BB001/BB007 exclusions for referral codes, quoted executor names, delegated SQL references, arithmetic expressions, and authorization-only SQL metadata.

Run the pack with:

```bash
npm run test:corpus-regression
```

Before promoting real corpus rows into regression fixtures, remove identifiers, collapse repeated templates for sampling, and have two reviewers adjudicate the expected decision without seeing the scanner result. Keep a template-deduplicated calibration set separate from an untouched holdout. The scanner's prior output is not a label. The recovered archive makes this review possible; it does not complete it.

For registry-scale analysis, run the scanner only against operator-staged local manifests and prefer the identity-free output for each row:

```bash
npx -y @backbond/agent-scan@0.6.2 vet-tools --tool-schema staged-manifest.json --summary-only
```

Store same-mode rows as JSONL, then generate an aggregate rather than publishing raw full-profile output:

```bash
node scripts/summarize-corpus-results.js --input scan_results.jsonl --corpus-date 2026-08-31 --format markdown
```

For the recovered CSV plus a staged local manifest directory, the internal reproducibility runner validates the join, replays the current scanner, and writes an identity-free delta report:

```bash
node scripts/rerun-enriched-corpus.js \
  --csv enriched.csv \
  --manifest-dir staged-manifests \
  --scanner-source-commit <scanner-commit> \
  --baseline-verification-json v0.5.15-verification.json \
  --archive-sha256 <sha256> \
  --corpus-date 2026-08-31 \
  --output-json delta.json \
  --output-markdown delta.md
```

The summarizer accepts either summary-only rows or full local result rows, but rejects a mixed file. It emits counts, rule, review-item, and coverage histograms, version counts, and template-multiplicity statistics. It omits server IDs, tool names, and template hashes. With summary-only rows, template multiplicity is limited to within-manifest instances because cross-row identifiers were never emitted; full local rows can support internal cross-row deduplication before the aggregate strips identifiers. The summarizer does not collect from the Registry and is intentionally outside the packaged CLI. Collection code must remain separate, bounded, and operator-run; the scanner must not accept a registry URL or invoke `tools/call`.

Any later article should be generated from the aggregate and state the package version, ruleset version, corpus date, reachability/authentication selection, and collection limitations together. The existing report says TLS verification was disabled during collection, so it cannot support strong claims about endpoint authenticity and that limitation must be disclosed. Do not publish a named-server leaderboard. If a named example is ever necessary, contact the operator first, describe the result as a metadata match, provide a correction channel, and separate any correction from the immutable aggregate snapshot.
