# Installation and prompt cards

Use only version `0.5.9` in this launch cycle.

## Agent before attaching MCP tools

> Before attaching the proposed tools, capture their MCP `tools/list` JSON-RPC response and run `npx -y @backbond/agent-scan@0.5.9 vet-tools --stdin` on it. Exit 1 means do not attach automatically; exit 3 means insufficient evidence; exit 0 is only a scoped static-metadata result, not a safety or insurance determination. Never upload or post the raw tool list.

POSIX:

```bash
npx -y @backbond/agent-scan@0.5.9 vet-tools --stdin < tools-list.json
```

PowerShell:

```powershell
if (Test-Path .\tools-list.json) { Get-Content -Raw .\tools-list.json | npx -y @backbond/agent-scan@0.5.9 vet-tools --stdin } else { Write-Error "Save a real MCP tools/list response as tools-list.json first." }
```

`vet-tools` does not create `tools-list.json`. If no live manifest has been captured yet, run the broader local inventory below instead.

## Broader local inventory

```bash
npx -y @backbond/agent-scan@0.5.9 scan
```

If the result is inconclusive, export the live tool list and run:

```bash
npx -y @backbond/agent-scan@0.5.9 scan --stdin --require-coverage < tools-list.json
```

## Network-isolated runtime

On a trusted host:

```bash
curl -fLO https://github.com/BackBond/agent-scan/releases/download/v0.5.9/agent-scan.cjs
curl -fLO https://github.com/BackBond/agent-scan/releases/download/v0.5.9/agent-scan.cjs.sha256
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
  - uses: BackBond/agent-scan@v0.5.9
    with:
      tool-schema: tools-list.json
      fail-on: high
      fail-on-prompt: high
      record-path: backbond-scan-record.json
```

The Action verifies committed inputs against `github.sha`. Its public record remains a scoped static record, not an insurance or production-runtime attestation.

## MCP stdio entrypoint

```json
{
  "mcpServers": {
    "backbond-agent-scan": {
      "command": "npx",
      "args": ["-y", "@backbond/agent-scan@0.5.9", "mcp"]
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
