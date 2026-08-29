# BackBond agent scan

`@backbond/agent-scan` is a dependency-free, local deterministic security scanner for AI-agent tool schemas, runtime permissions, and exported traces.

Version 0.5.0 runs an open rule pack from npm and returns named findings with evidence references and remediation. It needs no private analyzer, makes no network request, and does not turn agent claims into a score.

## Run a scan

Pin the version in local and CI runs:

```bash
npx @backbond/agent-scan@0.5.0 scan \
  --tool-schema tools.json \
  --permissions permissions.json \
  --trace runtime-trace.json \
  --fail-on high \
  --receipt backbond-scan-receipt.json \
  --json
```

Exit codes are stable for CI:

- `0`: no finding meets the selected threshold;
- `1`: at least one finding meets the selected threshold; and
- `2`: invalid input or scanner failure.

`--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none` and defaults to `high`. A normal local scan always finishes without an external analysis phase.

## What it checks

The 0.5.0 rule pack is public and version-pinned:

- `BB001` — untrusted input can reach code or shell execution;
- `BB002` — secret access is combined with unrestricted egress;
- `BB003` — a consequential action lacks enforced approval;
- `BB004` — untrusted content can reach persistent memory;
- `BB005` — a privileged action lacks observable audit evidence; and
- `BB006` — filesystem, subprocess, credential, or network permission scopes contain wildcards.

Every finding includes severity, evidence pointers, affected tool identities when available, and a concrete remediation. The rules describe detected configuration exposure; they do not claim to enforce the remediation.

See [docs/RULES.md](docs/RULES.md) for the complete rule contract.

## Supported evidence

Tool schemas:

- `backbond-tool-schema/v1`;
- OpenAI function-tool arrays;
- Anthropic tool arrays; and
- MCP `tools/list` results.

Runtime controls and traces use the explicit `backbond-permissions/v1` and `backbond-trace/v1` dialects. Plain tool formats do not normally encode runtime-enforced approval, audit, or permission scope. When those facts are absent, the scanner reports a coverage gap instead of inventing a finding or a pass.

The canonical formats are documented in [docs/PROTOCOL.md](docs/PROTOCOL.md). Working examples ship in [`fixtures/vulnerable`](fixtures/vulnerable) and [`fixtures/hardened`](fixtures/hardened).

## Prove the engine locally

From this repository:

```bash
node bin/agent-scan.js scan \
  --tool-schema fixtures/vulnerable/tool-schema.json \
  --permissions fixtures/vulnerable/permissions.json \
  --trace fixtures/vulnerable/trace.json
```

That fixture exits `1` and reports `BB001` through `BB006`. Replacing `vulnerable` with `hardened` exits `0`, produces no findings, and reports complete coverage.

## Privacy and receipts

Artifact JSON is read and normalized locally. Raw prompts, trace arguments, file bodies, secret values, and environment values are not placed in scan output or receipts and never leave the machine through this package. Receipts contain input basenames, sizes, SHA-256 hashes, detected dialects, the ruleset digest, finding IDs, severities, and evidence pointers.

`--signing-key` optionally signs the receipt with Ed25519. The embedded key proves integrity under that key; deciding whether to trust the key remains an operator responsibility.

```bash
agent-scan verify-receipt --input backbond-scan-receipt.json
```

## Optional claims

A `backbond-agent-teaser/v4` claim document may be supplied with `--input`. Claims are hypotheses only. They can produce contradiction annotations such as “claimed approval always, evidence shows no enforced gate.” Claims cannot create, suppress, or reduce a finding or its severity, and omitting them does not reduce artifact rule execution.

## Deliberate 0.5.0 limits

This release performs static deterministic analysis of exported evidence. It has no score, behavioral challenge harness, MCP server, hosted upload, SARIF exporter, or bundled GitHub Action. Seeded runtime challenges and trace grading belong in a later release; a hosted service, if added, must consume the same finding IDs and stay opt-in.

## License

MIT.
