# Launch copy

All copy below is pinned to `@backbond/agent-scan@0.5.8`.

Publish only the initial post below before five external users complete a pinned 0.5.8 run. The remaining channel variants are held drafts, not a posting calendar.

## Two-sentence canonical announcement

This is BackBond Agent Scan, not Snyk's agent-scanning feature. Before attaching a new MCP tool, vet its `tools/list` metadata locally with `npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin`. A forced-invocation description can produce `BB013`; the deterministic gate returns block, review, or no blocking finding without executing the tool or uploading the manifest. Exit 0 is not proof of runtime safety or insurance.

## Founder LinkedIn post

BackBond Agent Scan is not Snyk's agent-scanning feature. An agent should not attach a third-party MCP tool just because its description sounds useful.

We released `@backbond/agent-scan@0.5.8`, a free local pre-attachment gate for MCP and AI-agent tools. Pipe in the captured `tools/list` response and it checks dangerous capabilities, tool-description manipulation, confusable tool names, and unsafe tool combinations.

```text
npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin < tools-list.json
```

- exit 1: block automatic attachment
- exit 3: insufficient evidence; stop unknown
- exit 0: no configured blocking rule fired on the supplied metadata

Example: `BB013` tells the agent to stop when a tool description tries to force its own selection or invocation.

Static only. No tool execution. No scan-input upload. Open rules, MIT license, exact version pinned.

This is a pre-screen, not a safety certificate or insurance decision. When static exposure is not enough, BackBond is working on deeper assessment, continuous runtime evidence from the listener, and, where approved, financial protection.

https://backbond.ai/agent-scan/

## Held draft: Short X / Bluesky post

BackBond Agent Scan is not Snyk's agent-scanning feature.

Vet MCP tools before attachment:

`npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin < tools-list.json`

1 = block · 3 = review · 0 = no blocking finding on supplied metadata.

Local, static, no tool execution, no upload. Exit 0 is not proof of runtime safety.

https://backbond.ai/agent-scan/

## Held draft: Hacker News / community post

**Title:** Show HN: A local pre-attachment gate for MCP tool manifests

This is BackBond Agent Scan, not Snyk's agent-scanning feature. We built an MIT-licensed, dependency-free Node CLI that vets a captured MCP `tools/list` response before an agent attaches the tools. It uses deterministic public rules for dangerous schemas, prompt-like manipulation in tool descriptions, confusable tool names, and dangerous same-agent composition.

The command is version-pinned:

```text
npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin < tools-list.json
```

The result is deliberately tri-state: block/1, review/3 for ambiguous or incomplete metadata, or no_blocking_finding/0. It does not launch the MCP server, execute tools, upload the manifest, or claim that exit 0 proves runtime safety.

Source and reproducible release assets: https://github.com/BackBond/agent-scan

The feedback we want most: false positives, manifests that should produce review but do not, and installation failures in hardened environments. Please share only compact output, never raw manifests or traces.

## Held draft: MCP community post

This is BackBond Agent Scan, not Snyk's agent-scanning feature. If you maintain or attach MCP tools, we would like feedback on a deterministic pre-attachment check:

```text
npx -y @backbond/agent-scan@0.5.8 vet-tools --stdin < tools-list.json
```

It reviews tool identities, descriptions, input schemas, and same-manifest composition without launching the server. Incomplete or ambiguous manifests return review/exit 3 rather than a pass.

Please do not post raw `tools/list` JSON in feedback. Compact output is enough: https://github.com/BackBond/agent-scan/issues/new?template=scan-feedback.yml

## GitHub release / repository description

BackBond Agent Scan, not Snyk's agent-scanning feature: vet MCP and AI-agent tools before attachment. Local deterministic static scanning with no tool execution, plus strict coverage gates, CI records, and an offline single-file release.

## Language to avoid

Do not use:

- antivirus or immune system;
- safety passport, certified, verified safe, or proof of safety;
- self-healing or automatically remediated;
- insured, insurable, approved for coverage, or pre-approved;
- runtime protection or runtime monitoring when describing this package;
- zero disclosure or no IP risk.

Use “static pre-screen,” “scoped metadata result,” “potential exposure path,” “review required,” and “continuous runtime evidence is a separate BackBond capability.”
