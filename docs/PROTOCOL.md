# Scanner protocol v1

## Result envelope

`scan` emits `backbond-agent-scan/v1`. Results include scanner and ruleset identities, named findings, coverage gaps, optional claim contradictions, and hashed input metadata. There is no numeric score.

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

OpenAI, Anthropic, and MCP tool formats are normalized by stable name/description/schema heuristics. They may add the same declarations under an `x-backbond` object. Inference discovers capability candidates only; absent control fields stay unknown.

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

The values `*`, `**`, `/*`, `all`, `any`, or `{ "unrestricted": true }` are wildcard scopes for `BB006`.

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

## Coverage semantics

Malformed JSON or a malformed supported dialect is invalid input and exits `2`. Valid JSON that does not match a supported dialect is retained as a hashed input and reported as `unsupported`. Missing artifacts and facts needed by a rule are coverage gaps. Coverage gaps are not findings and do not create a false security score.

## Optional claim protocol

`backbond-agent-teaser/v4` and `backbond-agent-self-assessment/v1` remain accepted only for optional contradiction annotations. Claims are never rule predicates or threshold inputs.
