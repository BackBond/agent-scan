# First-five-runs launch gate

Do not run a multi-post campaign yet. Publish one initial post from [`launch-copy.md`](launch-copy.md), then wait until five external users have attempted the pinned `@backbond/agent-scan@0.5.13` command.

The initial post must contain:

- `npx -y @backbond/agent-scan@0.5.13 vet-tools --stdin < tools-list.json`;
- one named finding example, `BB013`;
- exit `1` = block, exit `3` = review, exit `0` = scoped metadata result;
- the statement that exit `0` is not a certificate, runtime attestation, insurance decision, or coverage.

Record only these five fields. Do not add names, organizations, manifests, or free-form notes.

Organic reports use the repository's [external-run form](https://github.com/BackBond/agent-scan/issues/new?template=external-run.yml). Do not recruit named testers, add telemetry, or treat downloads as completed runs.

| Run | Pin started Y/N | Decision | Attach changed Y/N | OS / Node | Sanitized FP |
| --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |
| 2 |  |  |  |  |  |
| 3 |  |  |  |  |  |
| 4 |  |  |  |  |  |
| 5 |  |  |  |  |  |

Use `scan_not_run` as the decision when the pinned package did not start. Use `block`, `review`, or `no_blocking_finding` only when the scanner actually returned that decision. A sanitized false-positive reproducer must be minimized and contain no raw production metadata.

Do not collect raw manifests, prompts, traces, configurations, JSON reports, path-bearing receipts, or secret values. Compact output reduces disclosure; it is not a zero-disclosure guarantee.

After five attempted external runs, choose exactly one next action from the evidence: fix installation, fix one false `block`, or document one common `review`. Do not publish a second marketing post before that action is complete. Stars, impressions, downloads, and directory views do not satisfy the gate.
