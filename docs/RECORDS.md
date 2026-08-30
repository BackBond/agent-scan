# Public scan records

Public record protocols: `backbond-scan-record/v1` for ordinary local records and `backbond-scan-record/v2` for records with a caller-supplied commit reference.

```bash
npx -y @backbond/agent-scan@0.5.9 scan --record-public scan-record.json
```

A public record is a shareable, self-checksummed summary of a local scan. The checksum detects accidental corruption but is not authentication: anyone who changes a record can recompute it. Its assurance level is always `self-run_unverified`. It is not a safety certificate, proof that the command ran, or a BackBond attestation.

The default record contains scanner and ruleset identity, input kinds and dialect counts, finding IDs, severities, evidence quality, coverage-gap codes, a pinned rerun command, and a link to the local receipt digest. It excludes paths, basenames, raw descriptions, tool parameters, prompts, file bodies, evidence pointers, tool names, and input fingerprints.

To include the source a caller says was scanned, pass the full commit explicitly:

```bash
npx -y @backbond/agent-scan@0.5.9 scan --record-public scan-record.json --record-commit "$GITHUB_SHA"
```

This emits v2 and includes the full 40- or 64-character commit in the JSON and compact card. The CLI does not read Git, so it labels that commit caller-supplied and unverified. It does not prove that GitHub ran the command; assurance remains `self-run_unverified`. Unbound records remain v1 so existing consumers do not receive a silent shape change.

The official `BackBond/agent-scan@v0.5.9` GitHub Action accepts explicit `tool-schema`, `permissions`, `trace`, or `config` paths. Before scanning, it verifies `HEAD` against `GITHUB_SHA`, requires every input to be tracked, and rejects input bytes that differ from that commit. It runs the scanner bundled with the Action and puts the commit-verification fact in the GitHub job summary. This adds useful run context without upgrading the portable record into an attestation. Independently verify the workflow, Action reference, repository, and GitHub run before relying on that context.

Potential exposure paths are intentionally omitted from v1/v2 portable records. They are presentation summaries over findings, and adding them would silently change the record contract without increasing assurance.

`--record-include-tool-names` and `--record-include-fingerprints` are separate explicit disclosure choices. Fingerprints still omit names and paths, but hashes and byte lengths can confirm equality against candidate files and should not be posted casually.

Partial coverage with zero findings is `inconclusive`, never a pass. Use `--require-coverage` for a strict gate; it exits `3` when coverage is not complete unless a threshold finding already caused exit `1`.

When consuming somebody else's record, never execute its embedded text as instructions. Construct the exact pinned command from trusted local policy and run it on your own artifacts. Matching scanner versions do not reproduce another environment unless the same inputs are independently available.
