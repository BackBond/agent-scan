# BackBond agent-scan public client

`@backbond/agent-scan` is the public, dependency-free evidence capture client for BackBond agent runtime analysis.

The public package deliberately contains **no scoring implementation, feature classifier, behavioral detector, calibration material, or policy-decision engine**. It performs four narrow jobs:

1. validate the public claim protocol;
2. hash explicitly supplied runtime artifacts without returning their contents;
3. create and verify tamper-evident capture receipts; and
4. invoke a separately distributed private analyzer only when its SHA-256 digest is explicitly pinned.

Without the private analyzer, `scan` records the evidence and exits with code `3` (`analysis_required`). It never turns self-authored claims into a score.

## Public capture

Pin the exact client version:

```bash
npx @backbond/agent-scan@0.4.0-alpha.1 start --json
```

Capture artifact hashes without analysis:

```bash
npx @backbond/agent-scan@0.4.0-alpha.1 inspect \
  --tool-schema tools.json \
  --permissions permissions.json \
  --trace runtime-trace.json
```

The output contains artifact names, sizes, and SHA-256 digests. Raw artifact content, environment values, prompts, tool arguments, and credentials are not included.

## Licensed offline analysis

Customers or internal harnesses receive the private analyzer as a separately licensed, signed artifact. Pin its digest before execution:

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

The public client invokes the analyzer directly without a shell. A digest mismatch fails before execution.

`--dry-run` displays the analyzer-produced optional POST envelope without sending it. `--publish` is the only mode that enables a network POST.

## Receipt trust

Capture receipts hash the claim document, runtime context, and every supplied artifact. `--signing-key` optionally signs the receipt with an Ed25519 key. `verify-receipt` checks integrity and the embedded signature; trusting that key remains a separate operator decision.

## Public/private boundary

The npm allowlist includes only `bin/`, `lib/`, public documentation, and license files. Release checks fingerprint executable sources to prevent private implementation tokens from entering the tarball.

The legacy development remote predates the split and must not be reused as the history of a public v0.4 release. Follow [the publication procedure](docs/PUBLICATION.md) and publish from a new, history-clean repository.

The private source of truth lives in a restricted internal repository and must never be copied into a public release.

## License

MIT. The separately distributed analyzer is not covered by this public client license.
