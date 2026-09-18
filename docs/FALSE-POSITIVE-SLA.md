# False-positive response path

There are two intake routes and both are in scope. A disputed scanner result belongs in the **False-positive report** form at `.github/ISSUE_TEMPLATE/false-positive.yml`; a broader scan problem belongs in the **Scan feedback or bug** form at `.github/ISSUE_TEMPLATE/scan-feedback.yml`. A report filed on the wrong form is still a report and still starts the clock. Public and warm-list reports use the same routes. Do not request raw manifests, traces, prompts, config files, paths, tool names, or fingerprints.

## First response: within 72 hours

Measure from the reporter's first submission time, using `report_received_at` when a report was forwarded from another channel. A maintainer's first response must:

1. confirm receipt and the measured deadline;
2. cite the exact package version and disputed rule code supplied by the reporter;
3. state whether the report is awaiting blinded adjudication or lacks a privacy-safe reproduction; and
4. name the next action and owner.

Acknowledgement without those four fields does not meet the SLA. Track counts and response times, never private report bodies or raw batches.

## Blinded adjudication

The intake owner creates an identifier-free candidate containing only the minimum metadata needed to reproduce the disputed boundary. Two reviewers independently record the expected decision without seeing the scanner output or each other's decision. The scanner's prior decision is not a label.

- Agreement that the report is right: preserve both reviewer decisions, add the redacted case under `fixtures/corpus-regression/`, update `fixtures/corpus-regression/cases.json`, add the focused regression test where needed, implement the rule fix, and add a changelog line for the next patch release.
- Agreement that the report is wrong: reply with the reason and cite the applicable public text in `docs/RULES.md`. Do not add a fixture or schedule a release.
- Reviewer disagreement or insufficient safe evidence: keep the report in review and request only the minimum privacy-safe clarification. Do not infer a label from scanner output.

A patch is report-driven, not calendar-driven. Existing coverage is recorded as `verified closed on <version>, test <path>, no release`.

## 2026-08-30 provenance gap

The source reports for homoglyph tool-name shadowing, forced-invocation language, and the verb-named read-only false positive are not retrievable from an agent seat. Do not reconstruct or guess their contents. Each item below is dispositioned against the behaviour its short name describes, which is what a "verified closed on <version>, test <path>" disposition asserts. It does not assert that the original report said only that. If a source report is later supplied and describes a boundary other than the one cited, re-adjudicate it through the path above.

Against package `@backbond/agent-scan@0.6.2`, source commit `5d229346137fdc1c332603126c9456009e9de37a`, ruleset `backbond-local-rules/2.0.1` (`bcfa6d47ad68b1fda89b61834fa70dfb7b0e17dcb7d2a8e38d63f045687c492e`), and corpus `2026-08-31`:

- forced-invocation language: verified closed on 0.6.2; test `fixtures/corpus-regression/block-global-forced-tool.json`; no release;
- verb-named read-only false positive: **reproduces on 0.6.2**, fixed after it. A tool whose name begins with a write verb could not suppress BB004 with `readOnlyHint: true`, because the name-derived inference returned before the annotation was consulted. The fix is on `main` at `d25c6756` — `lib/evidence.js` now consults the `readOnlyHint` annotation before the name-derived inference, unless the tool's input schema carries a persistent-write field — with the ruleset bump to `backbond-local-rules/2.0.2` and the regression fixture in `b14f3d416`; tests `test/vet-tools.test.js` (both boundary directions: a read-only-hinted `write_audit_note` is clean, a `write_file` with a `path`/`content` schema still reports) and `fixtures/corpus-regression/pass-read-only-audit-note.json`. It shipped in `@backbond/agent-scan@0.6.3`, the current npm `latest`; `0.6.2` still carries the pre-fix behaviour; and
- homoglyph tool-name shadowing: verified closed on 0.6.2; rule `BB-VET-CONFUSABLE-TOOL-NAME` at `lib/vet-tools.js:61`; test `test/vet-tools.test.js:844-852`; no release. Checked by execution, not inspection: a manifest pairing `get_weather` with `get_w\u0435ather` (Cyrillic U+0435) exits 3 and decides `review`, raising both `BB-VET-NON-ASCII-TOOL-NAME` and `BB-VET-CONFUSABLE-TOOL-NAME`.

If the missing source report is later supplied, adjudicate it through this same path.
