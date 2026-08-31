# Repository policy: vet tools before attachment

Copy this block into a repository's `AGENTS.md` when agents are allowed to propose or attach MCP or function tools:

```md
## Tool attachment gate

Before attaching, enabling, or delegating to a new MCP or function tool, obtain the real exported `tools/list` manifest and run:

`npx -y @backbond/agent-scan@0.5.13 vet-tools --stdin < tools-list.json`

- Exit 1 (`block`): do not attach automatically. Remove, constrain, or isolate the named exposure.
- Exit 3 (`review`): evidence is incomplete or ambiguous. Stop unknown and obtain a better manifest or human decision.
- Exit 0 (`no_blocking_finding`): no configured blocking rule fired on the supplied static metadata. This is not a safety determination, runtime attestation, or insurance decision.

If `tools-list.json` does not exist, do not invent it and do not report a decision. Run `npx -y @backbond/agent-scan@0.5.13 scan` for bounded local discovery and follow its exact next action.

Never post or upload raw tool manifests, prompts, traces, configurations, JSON reports, or path-bearing receipts. Share only compact `vet-tools` text after redaction or a compact `--record-public` card.
```

This policy tells the agent when to invoke the scanner. It does not install an enforcement hook, automatically modify configuration, or grant BackBond any access to the repository or runtime.
