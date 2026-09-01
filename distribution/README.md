# BackBond Agent Scan 0.6.1 distribution kit

This is the distribution kit for BackBond's `@backbond/agent-scan@0.6.1`. Keep every new command version-pinned. Do not substitute `@latest` in posts, prompts, skills, demos, or support replies.

## Campaign objective

The first launch stage ends only after five external users attempt the pinned 0.6.1 command and the checklist in [`first-five-launch.md`](first-five-launch.md) is complete. Until then:

- publish one canonical post containing the pinned command and a named finding ID;
- do not start a multi-post content calendar;
- prioritize installation failures, false non-blocking results, and false positives over reach.

After the first-five gate, the 30-day goals are:

- confirm 25 successful human- or agent-initiated runs;
- confirm 10 uses of `vet-tools` before a proposed attachment;
- see five repositories adopt the version-pinned CI Action or pinned CLI gate;
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

> BackBond Agent Scan vets MCP and AI-agent tools before attachment with a local deterministic static scan. Exit 1 means do not attach automatically, exit 3 means a medium finding or incomplete/ambiguous evidence requires operator review, and exit 0 is a scoped metadata result, not a safety, runtime-attestation, or insurance decision.

## Canonical commands

Before attachment:

```bash
npx -y @backbond/agent-scan@0.6.1 vet-tools --stdin < tools-list.json
```

Broader inventory and coverage gate:

```bash
npx -y @backbond/agent-scan@0.6.1 scan --stdin --require-coverage < tools-list.json
```

PowerShell:

```powershell
Get-Content -Raw .\tools-list.json | npx -y @backbond/agent-scan@0.6.1 vet-tools --stdin
```

## Distribution order

1. Publish `https://backbond.ai/agent-scan/` and verify the live command, links, CSP, `llms.txt`, and `/.well-known/agent.json`.
2. Run the design-partner outreach in [`design-partner-outreach.md`](design-partner-outreach.md).
3. Publish the single initial post in [`launch-copy.md`](launch-copy.md), then stop public campaign posting until five external users complete a pinned run.
4. List the existing Action in the source host's marketplace after an organization owner accepts its terms.
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
- [`first-five-launch.md`](first-five-launch.md): the launch gate before any follow-up content.
- [`scan-not-run.md`](scan-not-run.md): the short install-failure playbook for a command that never started.
- [`demo/`](demo): sanitized runnable manifests and exact demo instructions.
- [`schema-check-workflow.yml`](schema-check-workflow.yml): strict committed-manifest workflow template.
- [`schema-check-badge.md`](schema-check-badge.md): honest dynamic status badge language and commercial boundary.
- [`agent-policy.md`](agent-policy.md): copy-ready repository instruction that requires pre-attachment vetting and stops unknown.
- [`agent-plugin.md`](agent-plugin.md): skill-only Agent Plugin identity and immutable installation path.
- [`supply-chain-proof.md`](supply-chain-proof.md): reproducible package and standalone verification commands.
- [`demo/terminal-demo.html`](demo/terminal-demo.html): browser-ready 20-second scene built from sanitized scenarios; record only from the current pinned source.
- [`assets/public-record-example.txt`](assets/public-record-example.txt): safe share-card example.
