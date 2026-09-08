# Host configuration and evidence

Reviewed 8 September 2026. Examples below are illustrative connection shapes.
Replace paths with operator-controlled absolute paths and preserve the existing
server environment and host permissions. None of these examples activates itself.
The [installation and decision policy](../README.md) applies to every host.

| Host or test surface | Evidence available for this release |
| --- | --- |
| OpenClaw 2026.6.1 embedded runtime, MCP SDK 1.29.0 | One real internal server: vetted list in model context, successful model response, deliberately induced same-connection stale-call refusal. Modular wrapper, temporary instrumentation; no business call or standalone-bundle activation. [Record](RECORDS.md). |
| Official MCP SDK 1.30.0, Windows | Synthetic stdio client/server interop against source and bundled executable; not a native host acceptance test. |
| Linux and Windows synthetic suites | Real pinned scanner with synthetic server; decision, lifecycle, protocol, timeout and review-policy checks. CI logs report environment and skips. |
| Claude Code | Configuration example only. Native acceptance unverified. |
| Cursor | Configuration example only. Native acceptance unverified. |
| Codex | CLI connection shape only. Native acceptance unverified. |

Do not wrap a server that requires resources, prompts, roots, sampling,
elicitation or tasks. HTTP/SSE servers are outside this release. Windows test
success does not establish descendant-process containment or production ACLs.

## Claude Code

For a project-scoped `.mcp.json`, the single-server fragment is:

```json
{
  "mcpServers": {
    "reviewed-server": {
      "type": "stdio",
      "command": "/absolute/path/to/node",
      "args": ["/operator/path/agent-scan-gate.mjs", "--config", "/operator/path/server.json"]
    }
  }
}
```

Merge only the intended entry and retain its existing environment settings;
do not replace the whole file. Keep project approval and workspace trust checks.
Use `/mcp` to inspect the connection and tool availability. See the official
[Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

## Cursor

The project file is `.cursor/mcp.json`. Its `mcpServers` entry uses the same
`command` and `args` shown above; the `type` field is not needed in this example.
Retain the existing environment and approval controls, reconnect that one server,
and inspect the exposed tools. See the official
[Cursor MCP configuration documentation](https://prod.cursor.com/help/customization/mcp).

## Codex

The local `codex mcp add --help` checked for this release accepts a stdio command
after `--`. The illustrative registration shape is:

```text
codex mcp add reviewed-server -- /absolute/path/to/node /operator/path/agent-scan-gate.mjs --config /operator/path/server.json
```

This command writes configuration: do not run it blindly over an existing entry.
Back up and inspect the current entry, preserve its environment and permission
fields, and use the installed host's supported mechanism for the single-entry
replacement. Do not leave a direct-server duplicate. Verify the visible list in
a new connection before relying on enforcement. CLI syntax verification is not
proof of native attachment behavior. No production Codex entry was changed for
this release.

## OpenClaw

Native configuration uses `mcp.servers`, not the Claude/Cursor `mcpServers` key.
An illustrative fragment is:

```json
{
  "mcp": {
    "servers": {
      "reviewed-server": {
        "command": "/absolute/path/to/node",
        "args": ["/operator/path/agent-scan-gate.mjs", "--config", "/operator/path/server.json"]
      }
    }
  }
}
```

Preserve existing enablement, tool filters, timeouts and environment fields. The
pilot applied a single-entry patch only after its test operation matched the
live entry. Reconnection depends on how that host session is launched: do not
invent a service restart. See the official
[OpenClaw MCP documentation](https://docs.openclaw.ai/cli/mcp) and the installed
version's configuration reference. Current upstream documentation is not a
substitute for checking the installed host version.

## Operator acceptance checklist

Confirm the actual agent sees only the vetted list; a cached call after attachment
invalidation is refused with a visible reason; a fresh list is required before
reuse; and no direct-server duplicate remains. Use a controlled, non-business
test connection for refusal checks. Do not perform a business action just to
prove installation. Keep real manifests, names, hashes, credentials and logs
private. Publish a redacted observation with its limits, never a raw host trace.
