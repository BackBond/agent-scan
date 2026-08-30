# Installation and prompt cards

Use only version `0.5.10` in new launch instructions. Earlier pinned 0.5.9 runs still count toward the existing five-run gate.

## Agent before attaching MCP tools

> Before attaching the proposed tools, capture their MCP `tools/list` JSON-RPC response and run `npx -y @backbond/agent-scan@0.5.10 vet-tools --stdin` on it. Exit 1 means do not attach automatically; exit 3 means insufficient evidence; exit 0 is only a scoped static-metadata result, not a safety or insurance determination. Never upload or post the raw tool list.

POSIX:

```bash
npx -y @backbond/agent-scan@0.5.10 vet-tools --stdin < tools-list.json
```

PowerShell:

```powershell
if (Test-Path .\tools-list.json) { Get-Content -Raw .\tools-list.json | npx -y @backbond/agent-scan@0.5.10 vet-tools --stdin } else { Write-Error "Save a real MCP tools/list response as tools-list.json first." }
```

`vet-tools` does not create `tools-list.json`. If no live manifest has been captured yet, run the broader local inventory below instead.

## Broader local inventory

```bash
npx -y @backbond/agent-scan@0.5.10 scan
```

If the result is inconclusive, export the live tool list and run:

```bash
npx -y @backbond/agent-scan@0.5.10 scan --stdin --require-coverage < tools-list.json
```

## Network-isolated runtime

On a trusted host:

```bash
curl -fLO https://github.com/BackBond/agent-scan/releases/download/v0.5.10/agent-scan.cjs
curl -fLO https://github.com/BackBond/agent-scan/releases/download/v0.5.10/agent-scan.cjs.sha256
sha256sum --check agent-scan.cjs.sha256
```

Transfer the verified asset through the organization's approved software path. At the isolated destination:

```bash
node agent-scan.cjs vet-tools --stdin < tools-list.json
```

A failed download means `scan_not_run`. Do not weaken network isolation, switch registries, disable TLS checks, or accept a binary and digest supplied together in chat.

## CI Action

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
  - id: backbond
    uses: BackBond/agent-scan@v0.5.10
    with:
      mode: vet-tools
      tool-schema: tools-list.json
```

The Action verifies the committed manifest against `github.sha`, preserves the `0`/`1`/`3` pre-attachment decision, and writes no record in this mode. A passing workflow is a scoped static manifest result, not an insurance or production-runtime attestation.

Copy the complete workflow and honest badge language from [`schema-check-badge.md`](schema-check-badge.md). Use the Action's default `scan` mode only when the repository supplies the broader explicit evidence set and needs a redacted record.

## MCP stdio entrypoint

```json
{
  "mcpServers": {
    "backbond-agent-scan": {
      "command": "npx",
      "args": ["-y", "@backbond/agent-scan@0.5.10", "mcp"]
    }
  }
}
```

This exposes `scan_my_runtime` and `vet_tools_before_attach`. It does not connect to or attack third-party MCP servers. The caller supplies tool metadata.

## Agent Skill

Copy [`../skills/agent-scan/SKILL.md`](../skills/agent-scan/SKILL.md) to:

```text
.agents/skills/agent-scan/SKILL.md
```

The folder and the frontmatter `name` must both remain `agent-scan`.
