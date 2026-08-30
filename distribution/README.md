# BackBond Agent Scan 0.5.8 distribution kit

This is BackBond's `@backbond/agent-scan@0.5.8` distribution kit, not Snyk's agent-scanning feature. Keep every command version-pinned. Do not substitute `@latest` in posts, prompts, skills, demos, or support replies.

## Campaign objective

Within 30 days of launch:

- confirm 25 successful human- or agent-initiated runs;
- confirm 10 uses of `vet-tools` before a proposed attachment;
- see five repositories adopt the version-pinned GitHub Action or pinned CLI gate;
- collect ten privacy-safe product feedback reports;
- begin three qualified conversations about runtime evidence, the listener, or financial protection.

Downloads, stars, and impressions are supporting indicators. They do not prove that a scan ran or influenced a tool decision.

## Audiences and message

| Audience | Problem | Lead message | Next action |
| --- | --- | --- | --- |
| Agent and MCP builders | They cannot tell whether a proposed tool description or schema expands the agent's blast radius. | Vet MCP tools locally before attaching them. | Run `vet-tools` on a captured `tools/list` response. |
| Platform and security teams | They need repeatable findings and honest incomplete-coverage handling in CI. | Use stable finding IDs and deterministic exit codes without uploading raw evidence. | Run `scan --stdin --require-coverage` or the pinned Action. |
| Risk and insurance owners | Static metadata cannot show what happened after deployment. | Use the free scan to identify exposure; talk to BackBond when continuous runtime evidence or financial protection is needed. | Contact `hello@backbond.ai`. |

Do not lead developer channels with insurance. Lead with the tool decision they need to make now. Keep the commercial boundary visible on the landing page and in risk-owner material.

## Canonical message

> This is BackBond Agent Scan, not Snyk's agent-scanning feature. Vet MCP and AI-agent tools before attachment with a local deterministic static scan. Exit 1 means do not attach automatically, exit 3 means insufficient evidence, and exit 0 is a scoped metadata result—not a safety, runtime-attestation, or insurance decision.

## Canonical commands

Before attachment:

```bash
npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin < tools-list.json
```

Broader inventory and coverage gate:

```bash
npx -y @backbond/agent-scan@0.5.8 scan --stdin --require-coverage < tools-list.json
```

PowerShell:

```powershell
Get-Content -Raw .\tools-list.json | npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin
```

## Distribution order

1. Publish `https://backbond.ai/agent-scan/` and verify the live command, links, CSP, `llms.txt`, and `/.well-known/agent.json`.
2. Run the design-partner outreach in [`design-partner-outreach.md`](design-partner-outreach.md).
3. Publish the founder/company launch copy in [`launch-copy.md`](launch-copy.md).
4. List the existing Action in GitHub Marketplace after an organization owner accepts the Marketplace terms.
5. Share the standard skill in [`../skills/agent-scan`](../skills/agent-scan) for compatible agents.
6. Submit the existing MCP Registry entry to downstream directories without changing the pinned version or product claims.

## Privacy rules for distribution

Share only:

- compact `vet-tools` output, with sensitive tool names redacted; or
- the compact card from `--record-public`.

Never request or post raw `tools-list.json`, configuration, traces, prompts, `--json` output, path-bearing receipts, secret values, or input fingerprints. Compact output reduces disclosure; it is not a zero-disclosure guarantee.

## Product boundary

The open package is a static pre-screen. It does not execute tools, launch configured MCP servers, observe runtime enforcement, upload scan inputs, create insurance coverage, determine eligibility, or imply that BackBond verified an environment.

BackBond's broader product is deeper assessment, continuous runtime evidence from the listener, and, where approved, financial protection. Do not describe the public record as a certificate, passport, proof of safety, or proof of coverage.

## Kit contents

- [`install-cards.md`](install-cards.md): copy-paste installation and agent prompts.
- [`launch-copy.md`](launch-copy.md): channel-specific public copy.
- [`design-partner-outreach.md`](design-partner-outreach.md): controlled-launch email and feedback questions.
- [`content-calendar.md`](content-calendar.md): two-week launch sequence and owners.
- [`demo/`](demo): sanitized runnable manifests and exact demo instructions.
- [`assets/terminal-demo-0.5.8.webm`](assets/terminal-demo-0.5.8.webm): 20-second 1280×720 demo generated from the sanitized scenarios.
- [`assets/public-record-example.txt`](assets/public-record-example.txt): safe share-card example.
