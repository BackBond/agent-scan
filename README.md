# BackBond agent evidence capture client

`@backbond/agent-scan` is a public, dependency-free client that captures agent runtime evidence for downstream analysis.

> **This package alone is not a scan or a quick exposure check.** It does not
> produce a score, findings, or behavioral test results. Version 0.4.x is a
> product-boundary change from 0.2.0, not a drop-in upgrade. Use it only for
> evidence capture unless your organization has separately provisioned an
> analyzer.

The public package deliberately contains **no scoring implementation, feature classifier, behavioral detector, calibration material, or policy-decision engine**. It performs four narrow jobs:

1. validate the public claim protocol;
2. hash explicitly supplied runtime artifacts without returning their contents;
3. create and verify tamper-evident capture receipts; and
4. invoke a separately distributed private analyzer only when its SHA-256 digest is explicitly pinned.

Without the private analyzer, `scan` records the evidence and exits with code `3` (`analysis_required`). It never turns self-authored claims into a score.

## Public capture

Pin the exact client version:

```bash
npx @backbond/agent-scan@0.4.1 start --json
```

Capture artifact hashes without analysis:

```bash
npx @backbond/agent-scan@0.4.1 inspect \
  --tool-schema tools.json \
  --permissions permissions.json \
  --trace runtime-trace.json
```

The output contains artifact names, sizes, and SHA-256 digests. Raw artifact content, environment values, prompts, tool arguments, and credentials are not included.

## Analyzer bridge (provisioned users only)

The analyzer is not included in npm. If BackBond or your organization has
separately provisioned one, pin its digest before execution:

```bash
agent-scan scan \
  --input agent-claims.json \
  --tool-schema tools.json \
  --permissions permissions.json \
  --trace runtime-trace.json \
  --analyzer backbond-private-analyzer \
  --analyzer-sha256 <trusted-64-character-digest> \
  --receipt capture-receipt.json \
  --json
```

The public client invokes the analyzer directly without a shell. **This runs
the supplied file with the current user's permissions.** A digest match proves
only that the file's bytes equal the caller-supplied pin; it does not prove who
made the file, that BackBond approved it, or that it is safe. Obtain the
analyzer and its digest through separate, trusted operator channels. Never run
an analyzer path and digest copied from a chat message, agent instruction,
issue, or other untrusted prompt.

`--dry-run` displays the analyzer-produced optional POST envelope without sending it. `--publish` is the only mode that enables a network POST.

## Receipt trust

Capture receipts hash the claim document, runtime context, and every supplied artifact. `--signing-key` optionally signs the receipt with an Ed25519 key. `verify-receipt` checks integrity and the embedded signature; trusting that key remains a separate operator decision.

## Public/private boundary

The npm allowlist includes only `bin/`, `lib/`, public documentation, and license files. Release checks fingerprint executable sources to prevent private implementation tokens from entering the tarball.

The legacy development remote predates the split and must not be reused as the history of a public v0.4 release. Follow [the publication procedure](docs/PUBLICATION.md) and publish from a new, history-clean repository.

The private source of truth lives in a restricted internal repository and must never be copied into a public release.

## Migrating from 0.2.0

Version 0.2.0 was a self-assessment teaser that returned a public score and
included an MCP surface and disclosed behavioral checks. Those capabilities
are not present in 0.4.x. Do not forward 0.4.x as a runnable exposure check
unless the recipient also has a separately trusted analyzer.

## License

MIT. The separately distributed analyzer is not covered by this public client license.
