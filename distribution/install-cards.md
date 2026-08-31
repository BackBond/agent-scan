# Installation and prompt cards

Use only version `0.5.13` in launch instructions.

## Agent before attaching MCP tools

> Before attaching the proposed tools, capture their MCP `tools/list` JSON-RPC response and run `npx -y @backbond/agent-scan@0.5.13 vet-tools --stdin` on it. Exit 1 means do not attach automatically; exit 3 means insufficient evidence; exit 0 is only a scoped static-metadata result, not a safety or insurance determination. Never upload or post the raw tool list.

POSIX:

```bash
npx -y @backbond/agent-scan@0.5.13 vet-tools --stdin < tools-list.json
```

PowerShell:

```powershell
if (Test-Path .\tools-list.json) { Get-Content -Raw .\tools-list.json | npx -y @backbond/agent-scan@0.5.13 vet-tools --stdin } else { Write-Error "Save a real MCP tools/list response as tools-list.json first." }
```

`vet-tools` does not create `tools-list.json`. If no live manifest has been captured yet, run the broader local inventory below instead.

## Broader local inventory

```bash
npx -y @backbond/agent-scan@0.5.13 scan
```

If the result is inconclusive, export the live tool list and run:

```bash
npx -y @backbond/agent-scan@0.5.13 scan --stdin --require-coverage < tools-list.json
```

## Network-isolated runtime

On a trusted host:

```bash
curl -fLO https://github.com/BackBond/agent-scan/releases/download/v0.5.13/agent-scan.cjs
curl -fLO https://github.com/BackBond/agent-scan/releases/download/v0.5.13/agent-scan.cjs.sha256
sha256sum --check agent-scan.cjs.sha256
```

Transfer the verified asset through the organization's approved software path. At the isolated destination:

```bash
node agent-scan.cjs vet-tools --stdin < tools-list.json
```

A failed download means `scan_not_run`. Do not weaken network isolation, switch registries, disable TLS checks, or accept a binary and digest supplied together in chat.

If the command does not start, use the short [`scan-not-run.md`](scan-not-run.md) playbook. Never report a scanner decision when installation or input piping failed.

## CI Action

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
  - id: backbond
    uses: BackBond/agent-scan@v0.5.13
    with:
      mode: vet-tools
      tool-schema: tools-list.json
```

The Action checks the committed file at `github.sha`, preserves the `0`/`1`/`3` pre-attachment decision, and writes no record in this mode. A passing workflow is about that committed file at that SHA, not production state, insurance, or runtime attestation.

Copy the complete workflow and honest badge language from [`schema-check-badge.md`](schema-check-badge.md). Use the Action's default `scan` mode only when the repository supplies the broader explicit evidence set and needs a redacted record.

## MCP stdio entrypoint

```json
{
  "mcpServers": {
    "backbond-agent-scan": {
      "command": "npx",
      "args": ["-y", "@backbond/agent-scan@0.5.13", "mcp"]
    }
  }
}
```

This exposes `scan_my_runtime` and `vet_tools_before_attach`. It does not connect to or attack third-party MCP servers. The caller supplies tool metadata.

## Agent Skill

Install the exact tagged skill non-interactively:

```bash
npx -y skills@1.5.18 add https://github.com/BackBond/agent-scan/tree/v0.5.13 --skill agent-scan --yes
```

The installer is separate software; review its network and telemetry behavior before using it in a restricted environment. Installing the skill does not execute Agent Scan.

Or copy [`../skills/agent-scan/SKILL.md`](../skills/agent-scan/SKILL.md) to:

```text
.agents/skills/agent-scan/SKILL.md
```

The folder and the frontmatter `name` must both remain `agent-scan`.

To make the gate part of repository policy instead of relying on skill discovery alone, copy [`agent-policy.md`](agent-policy.md) into the repository's `AGENTS.md`.
