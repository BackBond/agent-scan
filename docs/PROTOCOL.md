# Scanner protocol v1

## Result envelope

`scan` emits `backbond-agent-scan/v1`. Results include scanner and ruleset identities, named findings, evidence quality, coverage gaps, optional discovery and claim contradictions, and hashed input metadata. There is no numeric score. A zero-finding result with partial coverage has status `inconclusive`; `no_findings` is reserved for complete coverage.

## Canonical tool schema

`backbond-tool-schema/v1` contains a `tools` array. Each tool requires `name` and may declare:

```json
{
  "protocol": "backbond-tool-schema/v1",
  "tools": [{
    "name": "shell_exec",
    "description": "Run an allowlisted command",
    "capabilities": ["code_execution", "privileged_action"],
    "input_trust": "trusted",
    "approval": "enforced",
    "audit": "observable"
  }]
}
```

Supported capabilities are `code_execution`, `secret_read`, `network_egress`, `destructive_action`, `financial_action`, `persistent_write`, `privileged_action`, and `filesystem_access`.

`input_trust` is `trusted`, `untrusted`, `mixed`, or `unknown`. Approval is `enforced`, `advisory`, `none`, or `unknown`. Audit is `observable`, `none`, or `unknown`.

OpenAI, Anthropic, MCP, and OpenAPI 3.x JSON are normalized by stable name, description, operation, and parameter-schema heuristics. They may add the same declarations under an `x-backbond` object. Generic tool inputs conservatively derive input trust as mixed because model-generated arguments can reach them; the output labels this fact `derived`. Absent approval and audit controls remain unknown and create coverage gaps when a rule needs them.

Schema heuristics detect unconstrained command, expression, code, SQL, URL, URI, endpoint, and webhook fields. Narrow tool-description heuristics detect instruction override, concealed behavior, sensitive-data solicitation, and fetch-like network intake. A local enum, pattern, validator, sandbox, or allowlist declaration suppresses the relevant parameter heuristic. Heuristics never inspect default or example values and never retain a schema body or raw tool description.

## Agent config discovery

With no explicit artifact and no stdin, the result includes `backbond-discovery-plan/v1`. Discovery checks exact, bounded project and user paths for Claude Desktop/Code, Cursor, VS Code, Windsurf, and Gemini MCP settings. Instruction files are listed as context but never parsed as permissions.

`mcpServers` and VS Code `servers` are normalized. Inline `tools`, `toolSchemas`, and Gemini `includeTools` are accepted. Server commands are never executed or presented as live tool exports, but names, command basenames, and arguments may produce a synthetic server-role observation for recognizable shell, fetch/browser, filesystem, database, and credential servers. Root filesystem mounts, Claude Code `Bash(*)`, root `Read`/`Write`/`Edit`, and `WebFetch(domain:*)` become derived wildcard facts. A server with no exported tool list still creates `BB-COV-MCP-TOOLS-NOT-EXPORTED`.

## Canonical permissions

`backbond-permissions/v1` declares global input trust, per-tool controls, and scopes:

```json
{
  "protocol": "backbond-permissions/v1",
  "input_trust": "trusted",
  "tools": {
    "shell_exec": {
      "input_trust": "trusted",
      "approval": "enforced",
      "audit": "observable"
    }
  },
  "filesystem": { "read": ["/workspace/input"], "write": ["/workspace/output"] },
  "subprocess": { "allow": ["/usr/bin/git"] },
  "credentials": { "read": ["deploy/status-token"] },
  "network": { "egress": ["status.internal.example:443"] }
}
```

The values `*`, `**`, `/*`, `/`, a drive root, `all`, `any`, or `{ "unrestricted": true }` are wildcard scopes for `BB006`. Recognized VS Code sandbox fields and filesystem-server root arguments may also create a `derived` wildcard observation.

## Canonical trace

`backbond-trace/v1` is a locally exported summary. Tool call entries deliberately omit raw arguments:

```json
{
  "protocol": "backbond-trace/v1",
  "events": [{
    "type": "tool_call",
    "tool": "shell_exec",
    "input_trust": "trusted",
    "approval": "enforced",
    "audit": "observable"
  }]
}
```

Extra event fields are ignored. The scanner never copies them into output or receipts.

OpenTelemetry OTLP JSON is accepted when it contains `resourceSpans`. Tool spans are identified from GenAI semantic attributes such as `gen_ai.operation.name` and `gen_ai.tool.name`, or a tool-shaped span name. Only the stable tool identity and derived capability facts survive normalization; raw attributes do not.

## MCP tool

`agent-scan mcp` speaks newline-delimited JSON-RPC over stdio and exposes `scan_my_runtime`. The tool has no required arguments. Its optional `tools` array accepts the same generic tool shapes; omitting the array uses bounded discovery and returns a machine-readable `next_action` containing the exact accepted `tools/list` envelope and pinned stdin commands. Undeclared arguments and nonconforming `tools`, `suggest_policy`, or `emit_record` values return an error rather than being ignored. `emit_record: true` returns compact text and a redacted `backbond-scan-record/v1` in structured output; when live tools were omitted, the safe built-in `next_action` is returned alongside it. It omits the full scan, local receipt, discovery paths, artifact names, and tool names. The MCP server performs no network requests and does not execute scanned tools.

The CLI also accepts a captured MCP `tools/list` JSON-RPC response through `scan --stdin`. It does not launch a server or execute a command discovered in configuration.

## Policy suggestions and SARIF

`--suggest-policy` adds `backbond-policy-suggestion/v1`. Its disable/wrap actions and JSON Patch templates are suggestions only. Every patch is marked `safe_to_apply_automatically: false`; no mutation path exists in this version.

`--sarif` emits SARIF 2.1.0. Finding IDs are SARIF rule IDs, JSON pointers are logical locations, and evidence quality and affected tools are result properties.

## Coverage semantics

Malformed JSON or a malformed supported dialect is invalid input and exits `2`. Valid JSON that does not match a supported dialect is retained as a hashed input and reported as `unsupported`. Missing artifacts and facts needed by a rule are coverage gaps. Coverage gaps are not findings and do not create a false security score. `--require-coverage` exits `3` when coverage is incomplete unless a threshold finding already takes precedence with exit `1`.

## Public scan record

`--record-public <file>` writes `backbond-scan-record/v1` without overwriting. Adding `--record-commit <sha>` emits `backbond-scan-record/v2` and binds the full lowercase 40- or 64-character Git commit into the checksummed JSON and compact card. Its assurance level remains `self-run_unverified`; neither version is proof of execution nor a BackBond attestation.

By default, the record contains only scanner/ruleset identity, counts of input kinds and dialects, finding IDs, severities, evidence quality, coverage codes, a trusted pinned rerun command, and integrity linkage to the local receipt. It excludes paths, basenames, descriptions, parameters, bodies, pointers, tool names, and input fingerprints. Tool names and fingerprints require separate explicit disclosure flags. Consumers must construct the pinned command from trusted local policy rather than execute record text.

## CI thresholds

`--fail-on` gates runtime-exposure findings `BB001`–`BB008` and `BB012`. Description-only prompt lint `BB009`–`BB011` is always reported but uses the independent `--fail-on-prompt` threshold, which defaults to `none`. This prevents capability CI from failing solely on aggressive tool copy while allowing repositories to adopt strict prompt lint explicitly.

## Optional claim protocol

`backbond-agent-teaser/v4` and `backbond-agent-self-assessment/v1` remain accepted only for optional contradiction annotations. Claims are never rule predicates or threshold inputs.
