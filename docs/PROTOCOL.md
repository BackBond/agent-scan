# Scanner protocol v1

## Result envelope

`scan` emits `backbond-agent-scan/v1`. Results include scanner and ruleset identities, named findings, evidence quality, coverage gaps, optional discovery and claim contradictions, and hashed input metadata. Each finding includes `finding_class` (`capability_exposure` or `prompt_injection_indicator`) and a non-numeric `precision_note`; the top-level `finding_classes` object reports separate counts and rule IDs for those two classes. There is no numeric score or fabricated precision percentage. A zero-finding result with partial coverage has status `inconclusive`; `no_findings` is reserved for complete coverage.

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

MCP, supported function-tool arrays, and OpenAPI 3.x JSON are normalized by stable name, description, operation, and parameter-schema heuristics. They may add the same declarations under an `x-backbond` object. Generic tool inputs conservatively derive input trust as mixed because model-generated arguments can reach them; the output labels this fact `derived`. Absent approval and audit controls remain unknown and create coverage gaps when a rule needs them.

Schema heuristics detect unconstrained command, expression, code, SQL, URL, URI, endpoint, and webhook fields. Narrow tool-description heuristics detect directed instruction override, concealed tool behavior, sensitive-data solicitation, global forced tool selection, and fetch-like network intake. Quoted examples, explicitly introduced example/signature text, descriptive security-analysis language, authentication mentions without solicitation, and scoped task-routing guidance are excluded from prompt-copy findings. In the pre-attachment profile, directive-like text excluded only because it is framed as an example or scoped response-ordering instruction remains ambiguous evidence and returns `review`; it is not silently treated as clean. A local enum, pattern, validator, sandbox, or allowlist declaration suppresses the relevant parameter heuristic. Heuristics never inspect schema default/example values and never retain a schema body or raw tool description. Full local JSON includes only normalized SHA-256 template identifiers and multiplicity for prompt-copy findings so an offline aggregator can deduplicate repeated copy; receipts and public records omit those identifiers.

## Agent config discovery

With no explicit artifact and no stdin, the result includes `backbond-discovery-plan/v1`. Discovery checks exact, bounded project and user paths for supported desktop and coding-agent MCP settings. Instruction files are listed as context but never parsed as permissions.

Recognized MCP server containers and inline tool declarations are normalized. Server commands are never executed or presented as live tool exports, but names, command basenames, and arguments may produce a synthetic server-role observation for recognizable shell, fetch/browser, filesystem, database, and credential servers. Root filesystem mounts and supported wildcard rules for execution, file access, and web fetches become derived wildcard facts. A server with no exported tool list still creates `BB-COV-MCP-TOOLS-NOT-EXPORTED`.

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

`agent-scan mcp` speaks newline-delimited JSON-RPC over stdio and exposes `scan_my_runtime` and `vet_tools_before_attach`. `scan_my_runtime` has no required arguments. Its optional `tools` array accepts the same generic tool shapes; omitting the array uses bounded discovery and returns a machine-readable `next_action` containing the exact accepted `tools/list` envelope and pinned stdin commands for both `scan --stdin --require-coverage` and `vet-tools --stdin`. Undeclared arguments and nonconforming `tools`, `suggest_policy`, or `emit_record` values return an error rather than being ignored. CLI stdin manifests and individual MCP JSON-RPC messages are capped at 4 MiB before JSON parsing. `emit_record: true` returns compact text and a redacted `backbond-scan-record/v1` in structured output; when live tools were omitted, the safe built-in `next_action` is returned alongside it. It omits the full scan, local receipt, discovery paths, artifact names, and tool names.

`vet_tools_before_attach` requires exactly one `tools` array, does not fall back to discovery, and accepts no record, receipt, threshold, or policy-suggestion arguments. It returns the same `backbond-pre-attach/v1` result as the CLI profile. The MCP server performs no network requests and does not execute scanned tools.

The CLI also accepts a captured MCP `tools/list` JSON-RPC response through `scan --stdin`. It does not launch a server or execute a command discovered in configuration.

## Pre-attachment profile

`vet-tools --stdin` and `vet-tools --tool-schema <manifest>` emit `backbond-pre-attach/v1`. This profile is intentionally narrower than `scan`: it assesses tool identities, descriptions, supplied input schemas, and same-manifest composition using `BB001`, `BB002`, `BB004`, and `BB007`–`BB013`. A non-blocking result requires unambiguous tool names, a description or title, and one analyzable object input schema per tool. Opaque references or branches, conflicting schema aliases, duplicate identities, non-ASCII identities, confusable-name collisions, missing metadata, mixed supported dialect markers, directive-like example text, scoped response-ordering instructions, and schemas beyond 64 levels or 10,000 analyzed nodes return `review`. Names are compared after NFKC compatibility normalization, case and separator folding, and a conservative common Greek/Cyrillic confusable skeleton; any remaining non-ASCII identity still requires operator review. The result includes `profile.version` and `profile.sha256`; that canonical digest binds the fixed profile's decisions, exits, included/excluded rules, threshold, supported dialects, confusable map, and coverage/decision functions. It does not assess permission enforcement, approval enforcement, audit behavior, runtime traces, or actual execution; `BB003`, `BB005`, and `BB006` are excluded from the profile.

The fixed profile threshold is high. Therefore `BB009`–`BB011` and `BB013` block by default in this pre-attachment context even though the general scan keeps prompt lint on the separate `--fail-on-prompt` threshold. The decision and exit mapping is:

- `block`, exit `1`: at least one scoped high-or-critical finding;
- `review`, exit `3`: no blocking finding, but the supplied profile evidence is incomplete or unsupported; and
- `no_blocking_finding`, exit `0`: no scoped high-or-critical finding and complete coverage of the metadata profile.

Profile completeness is not environment completeness. `no_blocking_finding` is never a safety determination, runtime attestation, policy enforcement fact, or insurance decision. `vet-tools` intentionally cannot create a receipt or public record.

## Potential exposure paths

Scan and pre-attachment JSON may include `backbond-exposure-paths/v1`. `EP001`–`EP003` group existing BB findings into concise potential chains: untrusted retrieval plus privileged tools, secret access plus unrestricted egress, and untrusted input plus code execution. Paths do not add findings, severity, thresholds, receipt fields, or public-record fields. Each path states that it is inferred from static co-residence and is not an observed runtime data flow.

## Policy suggestions and SARIF

`--suggest-policy` adds `backbond-policy-suggestion/v1`. Its disable/wrap actions and JSON Patch templates are suggestions only. `vet-tools --suggest-policy --json` can emit review-only BB007 templates for constraining free-form operations and BB013 templates for rewriting selection-manipulation text. Placeholder values are never inferred from the application. Every patch is marked `safe_to_apply_automatically: false`; no mutation path exists in this version.

`--sarif` emits SARIF 2.1.0. Finding IDs are SARIF rule IDs, JSON pointers are logical locations, and evidence quality and affected tools are result properties.

## Coverage semantics

Malformed JSON or a malformed supported dialect is invalid input and exits `2` in the general scanner. In the pre-attachment profile, an otherwise parseable manifest with conflicting supported dialect locations or markers returns structured `review`/exit `3`, because an unattended agent must treat that ambiguity as insufficient evidence rather than a scanner crash. Valid JSON that does not match a supported dialect is retained as a hashed input and reported as `unsupported`. Missing artifacts and facts needed by a rule are coverage gaps. Coverage gaps are not findings and do not create a false security score. `--require-coverage` exits `3` when coverage is incomplete unless a threshold finding already takes precedence with exit `1`.

## Public scan record

`--record-public <file>` writes `backbond-scan-record/v1` without overwriting. Adding `--record-commit <sha>` emits `backbond-scan-record/v2` and includes the caller-supplied full lowercase 40- or 64-character Git commit in the checksummed JSON and compact card. The CLI does not verify Git state and labels this value unverified. Its assurance level remains `self-run_unverified`; neither version is proof of execution nor a BackBond attestation.

By default, the record contains only scanner/ruleset identity, counts of input kinds and dialects, finding IDs, severities, evidence quality, coverage codes, a trusted pinned rerun command, and integrity linkage to the local receipt. It excludes paths, basenames, descriptions, parameters, bodies, pointers, tool names, and input fingerprints. Tool names and fingerprints require separate explicit disclosure flags. Consumers must construct the pinned command from trusted local policy rather than execute record text.

## CI thresholds

`--fail-on` gates runtime-exposure findings `BB001`–`BB008` and `BB012`. Description-only prompt lint `BB009`–`BB011` and `BB013` is always reported but uses the independent `--fail-on-prompt` threshold, which defaults to `none`. This prevents capability CI from failing solely on aggressive tool copy while allowing repositories to adopt strict prompt lint explicitly.

The official Action supports `mode: scan` and `mode: vet-tools`. Scan mode retains the configurable thresholds, requires complete relevant coverage, verifies explicit committed inputs, and writes a redacted v2 record. Vet mode accepts exactly one committed tool manifest, uses the fixed pre-attachment rule set and high threshold, emits privacy-safe decision, coverage, finding-count, ruleset, profile-digest, and commit outputs, and preserves the CLI's `0`/`1`/`3` decision exits. Vet mode does not create a public record or claim independent BackBond verification.

## Optional claim protocol

`backbond-agent-teaser/v4` and `backbond-agent-self-assessment/v1` remain accepted only for optional contradiction annotations. Claims are never rule predicates or threshold inputs.
