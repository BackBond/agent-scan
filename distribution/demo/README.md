# Sanitized 0.5.12 demos

These deliberately synthetic manifests are safe to publish. They are not examples of customer or BackBond production configuration.

The browser-ready 1280×720 source scene is [`terminal-demo.html`](terminal-demo.html); it contains only the sanitized cases below. Record or screenshot that source only after verifying its displayed package pin matches the current release.

Run each case from the repository root.

## Benign typed tool

```bash
node bin/agent-scan.js vet-tools --stdin < distribution/demo/benign-tools-list.json
```

Expected decision and exit:

```text
NO BLOCKING FINDING — 0 findings
Profile: pre-attachment tool manifest only
Profile coverage: complete
Agent decision: this profile found no reason to block; runtime policy still controls attachment.
Not assessed: runtime enforcement, approval, audit behavior, traces, or actual execution.
```

Exit `0`. This is a scoped metadata result, not proof that an implementation or runtime is safe.

## Forced invocation

```bash
node bin/agent-scan.js vet-tools --stdin < distribution/demo/forced-invocation-tools-list.json
```

Expected decision and exit:

```text
BLOCK — 1 finding (1 high)
Profile: pre-attachment tool manifest only
BB013 mail_sync [derived]
  Stop: Do not attach the tool until the selection-manipulation language is removed and the server source is reviewed.
Profile coverage: complete
Agent decision: do not attach automatically; isolate or review the toolset.
```

Exit `1`.

## Confusable-name shadowing

The second tool in this manifest contains Cyrillic `е` in a name that is visually similar to `get_weather`.

```bash
node bin/agent-scan.js vet-tools --stdin < distribution/demo/confusable-shadow-tools-list.json
```

Expected decision and exit:

```text
REVIEW — 0 findings
Profile: pre-attachment tool manifest only
Profile coverage: partial — 1 tool-name group(s) become indistinguishable after compatibility, case, separator, and common-script confusable normalization.; 1 tool name(s) contain non-ASCII characters that require operator review.
Agent decision: do not attach automatically; the manifest is insufficient for this profile.
```

Exit `3`. Name ambiguity is a coverage reason, so the scanner refuses to emit a non-blocking result.

## Twenty-second recording sequence

Record a terminal at 1280×720 with no usernames or local paths visible:

1. Show the pinned command and benign result for five seconds.
2. Run the forced-invocation case and pause on `BB013` plus the `Stop` line for seven seconds.
3. Run the confusable-name case and pause on `REVIEW` plus exit `3` for seven seconds.
4. End on: `Static only · no tool execution · no upload · exit 0 is not proof of safety`.

Do not record a real manifest, raw trace, receipt path, shell history, environment variable, or account name.
