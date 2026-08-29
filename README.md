# BackBond agent scan

Static only: `@backbond/agent-scan@0.5.1` inspects the tool and agent configuration already on your machine. It does not run tools, probe a live agent, upload traces, contact a hosted service, or execute a second binary.

```bash
npx @backbond/agent-scan@0.5.1 scan
```

From this repository, prove the whole rule pack with the two fixtures:

```bash
node bin/agent-scan.js scan --tool-schema fixtures/vulnerable/tool-schema.json --permissions fixtures/vulnerable/permissions.json --trace fixtures/vulnerable/trace.json
node bin/agent-scan.js scan --tool-schema fixtures/hardened/tool-schema.json --permissions fixtures/hardened/permissions.json --trace fixtures/hardened/trace.json
```

The vulnerable case exits `1` with `BB001`–`BB008`. The hardened case exits `0` with no findings and complete coverage.

## Zero-config first run

`scan` with no artifact arguments performs bounded discovery. It checks project ancestors and known user paths for:

- Claude Desktop and Claude Code MCP settings;
- Cursor `.cursor/mcp.json`;
- VS Code `.vscode/mcp.json`, portable `.mcp.json`, and user MCP settings;
- Windsurf `~/.codeium/windsurf/mcp_config.json`;
- Gemini CLI `.gemini/settings.json`; and
- nearby `AGENTS.md`, `SKILL.md`, `.claude`, and `.cursor` instruction files, which are listed but never interpreted as security controls.

Discovery reads exact known files; it does not recursively crawl the home directory. A configured MCP server without an exported live tool list produces `BB-COV-MCP-TOOLS-NOT-EXPORTED`, not a silent pass.

The default output is deliberately short:

```text
3 findings (1 critical, 2 high)
BB002 vault_read [derived]
  Stop: Do not attach secret-reading and unrestricted network tools to the same agent.
BB001 shell_exec [derived]
  Stop: Disable the named executor for this session, or wrap it with a narrow allowlist.
Coverage: approval enforcement is not observable for 4 tools
```

`[derived]` means a capability, trust boundary, wildcard, or schema risk was inferred from names, descriptions, or parameter schemas. Derived evidence is useful triage, not a claim that the runtime declared that fact.

## Scan the live tool list

Pipe an MCP `tools/list` response, an OpenAI function-tool list, or an Anthropic tool list directly:

```bash
agent-scan scan --stdin < tools.json
```

Or expose the dependency-free MCP stdio server:

```json
{
  "mcpServers": {
    "backbond-agent-scan": {
      "command": "npx",
      "args": ["-y", "@backbond/agent-scan@0.5.1", "mcp"]
    }
  }
}
```

It provides `scan_my_runtime` with no required arguments. A caller may supply its live `tools` array; otherwise the tool uses the same bounded discovery plan. Pin `0.5.1`—do not replace it with `@latest`.

## Inputs and adapters

Explicit inputs remain available when discovery cannot see the runtime:

```bash
agent-scan scan \
  --config claude_desktop_config.json \
  --tool-schema tools.json \
  --permissions permissions.json \
  --trace otel-export.json \
  --fail-on high
```

Supported tool inputs are `backbond-tool-schema/v1`, MCP `tools/list`, OpenAI/Anthropic tool arrays, and OpenAPI 3.x JSON. Supported traces are `backbond-trace/v1` and OpenTelemetry OTLP JSON. Raw span attributes, prompts, tool arguments, environment values, and config bodies are not copied into results or receipts.

Raw evidence bodies never leave the machine through this package.

LangChain, CrewAI, and AutoGen can use the scanner today by exporting their runtime tool list to one of the generic formats or stdin. Version 0.5.1 does not execute or import arbitrary framework code to discover tools; first-party code extractors need framework-specific isolation and belong after this deterministic intake.

## Findings

The public `backbond-local-rules/1.1.0` pack contains:

- `BB001` — untrusted input can reach code or shell execution;
- `BB002` — secret access is combined with unrestricted egress;
- `BB003` — a consequential action lacks enforced approval;
- `BB004` — untrusted content can reach persistent memory;
- `BB005` — a privileged action lacks observable audit evidence;
- `BB006` — filesystem, subprocess, credential, or network scopes contain wildcards;
- `BB007` — a tool accepts unconstrained command, expression, code, or SQL text; and
- `BB008` — a tool accepts an unvalidated URL or destination.

Each finding includes a stable ID, severity, affected tools, evidence pointers, evidence quality, an immediate `Stop` instruction, and remediation. See [docs/RULES.md](docs/RULES.md).

Three anonymized non-BackBond examples in [`fixtures/wild`](fixtures/wild) prove that findings fire on MCP, VS Code, and Gemini-shaped files rather than only on canonical fixtures.

## Agent-safe remediation loop

`--suggest-policy` adds a machine-readable `backbond-policy-suggestion/v1` object:

```bash
agent-scan scan --suggest-policy --json
```

It identifies tools to disable or wrap and emits review-required JSON Patch templates for supported findings. Suggestions are never applied automatically and never claim to be enforced. Placeholder patches have `safe_to_apply_automatically: false`.

## CI and SARIF

Exit codes are stable:

- `0`: no finding meets `--fail-on`;
- `1`: at least one finding meets it; and
- `2`: invalid input or scanner failure.

`--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none` and defaults to `high`. Use `--json` for CI data or `--sarif` for SARIF 2.1.0 suitable for GitHub Code Scanning and IDE consumers.

## Receipts and permission gates

`--receipt receipt.json` writes input hashes, ruleset identity, findings, and coverage gaps. `--signing-key` optionally signs the receipt with Ed25519. The signature proves integrity under that key; it does not make an inferred finding true or prove the environment safe.

A gatekeeper should accept a zero-finding receipt only when coverage is `complete`, the input set matches the requested action, the exact scanner/ruleset is allowed, and the signing key is independently trusted. Partial coverage plus zero findings is not proof of safety.

```bash
agent-scan verify-receipt --input receipt.json
```

This package is `@backbond/agent-scan`. It is not the Snyk CLI's agent scanning feature; pin the package name and version in agent instructions so the two are not confused.

## Deliberate 0.5.1 limits

There is no score, hosted upload, automatic fix mode, runtime middleware, or active probe. Active challenges must execute in an isolated harness and grade runtime traces, not model self-reports; that trust boundary is intentionally deferred to v0.6.

## License

MIT.
