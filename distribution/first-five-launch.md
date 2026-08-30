# First-five-runs launch gate

Do not run a multi-post campaign yet. Publish one initial post from [`launch-copy.md`](launch-copy.md), then wait until five external users have completed a pinned `@backbond/agent-scan@0.5.9` run.

The initial post must contain:

- `npx -y @backbond/agent-scan@0.5.9 vet-tools --stdin < tools-list.json`;
- one named finding example, `BB013`;
- exit `1` = block, exit `3` = review, exit `0` = scoped metadata result;
- the statement that exit `0` is not a certificate, runtime attestation, insurance decision, or coverage.

For each of the first five external runs, record only:

1. whether the exact pinned package started;
2. the decision category: block, review, or no blocking finding;
3. whether the result changed an attach, disable, wrap, or isolate decision;
4. the operating system, shell, Node version, and error category when installation failed; and
5. any false positive or false non-blocking result as a minimized, sanitized reproducer.

Do not collect raw manifests, prompts, traces, configurations, JSON reports, path-bearing receipts, or secret values. Compact output reduces disclosure; it is not a zero-disclosure guarantee.

After five completed external runs, choose the next action from evidence: fix installation, fix precision, document a common coverage gap, or publish one follow-up result. Stars, impressions, npm downloads, and Registry views do not satisfy the gate.
