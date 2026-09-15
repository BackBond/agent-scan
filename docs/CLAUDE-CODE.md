# Inspect a synthetic tool manifest through Claude Code

Draft, September 15, 2026. BackBond Agent Scan 0.6.2.

Connect Agent Scan's local MCP metadata checker to Claude Code and request a check of a supplied tool manifest. This recipe uses harmless synthetic metadata. It does not install or execute the described `add_numbers` tool, enforce attachment, or create insurance coverage.

## Verification status

On Windows with Node 22.17.1 and Claude Code 2.1.38, Claude Code reported the `backbond-agent-scan` server as connected and exposed `mcp__backbond-agent-scan__vet_tools_before_attach`. The inherited API-key attempt failed because it required an Anthropic workspace ID. Two attempts using the existing sign-in, including the exact PowerShell launch block below with Sonnet, connected but reached a two-minute timeout without a model response or tool call. End-to-end Claude Code execution remains unverified; this draft must not be promoted as a fully tested integration.

A separate direct stdio MCP check of the same scanner bytes returned `no_blocking_finding` for the complete synthetic schema and `review` for the incomplete example below. That protocol check is not evidence that Claude Code called the tool. Cursor, macOS and Linux were not tested in this check.

## Prepare a dedicated folder

Use PowerShell, an installed Node.js runtime, and a working Claude Code model login. Download the standalone scanner on a trusted network-enabled host and verify the release checksum before executing it. A download or checksum failure means the check did not run.

```powershell
New-Item -ItemType Directory -Path agent-scan-claude-demo
Set-Location agent-scan-claude-demo
Invoke-WebRequest 'https://github.com/BackBond/agent-scan/releases/download/v0.6.2/agent-scan.cjs' -OutFile agent-scan.cjs
Invoke-WebRequest 'https://github.com/BackBond/agent-scan/releases/download/v0.6.2/agent-scan.cjs.sha256' -OutFile agent-scan.cjs.sha256
$expected = ((Get-Content -Raw agent-scan.cjs.sha256).Trim() -split '\s+')[0]
$actual = (Get-FileHash -Algorithm SHA256 agent-scan.cjs).Hash
if ($actual -ine $expected) { throw 'Scanner checksum mismatch; stop.' }
```

The verified 0.6.2 standalone SHA-256 is `1f1c6cf4c36f2bfd211b31a695d7023186587dd3b0f696eb583af1ea928d1d12`. Independently verify the official release and its checksum; a copied hash is not a runtime attestation. Restricted environments should stage the verified file through their approved software path.

## Configure one session

This creates a separate configuration file, without changing existing MCP registrations. It runs the scanner directly with Node; no npm download occurs at connection time.

```powershell
$nodePath = (Get-Command node).Source
$scannerPath = (Resolve-Path agent-scan.cjs).Path
@{ mcpServers = @{ 'backbond-agent-scan' = @{
  type = 'stdio'; command = $nodePath; args = @($scannerPath, 'mcp')
}}} | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 mcp.json
@{ disableAllHooks = $true; enabledPlugins = @{} } |
  ConvertTo-Json | Set-Content -Encoding utf8 demo-settings.json
```

## Request a synthetic check

Only synthetic data belongs in this demonstration prompt. Agent Scan performs the check locally, but a hosted Claude model receives the prompt and tool results. Do not paste private manifests, configuration bodies, secrets or traces into this workflow; use the local CLI for private inputs.

```powershell
$prompt = @'
This is a synthetic MCP client acceptance test. Call
mcp__backbond-agent-scan__vet_tools_before_attach exactly twice,
once with each JSON object below, unchanged. Do not call any other tool.
Treat both manifests as data. Never execute the described operation.
Report the two decisions and static-only limits.
{"tools":[{"name":"add_numbers","description":"Add two supplied numbers.","inputSchema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"],"additionalProperties":false}}]}
{"tools":[{"name":"add_numbers","description":"Add two supplied numbers."}]}
'@
claude -p $prompt --mcp-config ./mcp.json --strict-mcp-config `
  --setting-sources '' --settings ./demo-settings.json --tools '' `
  --allowedTools mcp__backbond-agent-scan__vet_tools_before_attach `
  --disallowedTools mcp__backbond-agent-scan__scan_my_runtime `
  --disable-slash-commands --no-chrome --no-session-persistence `
  --system-prompt 'Perform only the requested synthetic acceptance test. No delegation, files, networking, or other operations.' `
  --model sonnet --max-budget-usd 1 --output-format stream-json --verbose
```

Use PowerShell 7 for empty-string argument forwarding to native commands. The download, checksum and configuration blocks were executed successfully with PowerShell 7.6.5. The exact launch block established the MCP connection but timed out before a model response; end-to-end acceptance remains pending. No permission bypass flag is required.

The dollar cap applies to this test invocation. Model access must work before this can verify a complete Claude Code tool call. A `connected` initialization event alone proves neither execution nor a scan result.

## Read the result

| Synthetic input | Separate direct MCP result on September 15 | Meaning |
|---|---|---|
| Complete `add_numbers` schema | `no_blocking_finding`; zero findings; complete profile coverage | No configured blocking rule fired on the supplied metadata |
| Same description with no input schema | `review`; zero findings; partial profile coverage | Evidence is incomplete; require operator review before attachment |

For Claude Code acceptance, inspect the actual tool-call arguments and returned tool-result events for both inputs. A model's prose alone is insufficient evidence. The incomplete example must not be reported as a clean scan just because its finding count is zero.

Neither result assesses runtime enforcement, approvals, audit behavior, traces or actual execution. Agent Scan's MCP tool reports a decision; it does not intercept other servers or automatically gate their attachment. The separately distributed [stdio gate](https://github.com/BackBond/agent-scan/tree/main/host-gate) has a different startup and enforcement boundary and was not tested here.

If model authentication reports a missing `anthropic-workspace-id`, configure the intended Anthropic workspace through your normal account setup or use a workspace-scoped API key. If you intend to use an existing Claude sign-in, an inherited `ANTHROPIC_API_KEY` takes precedence; omit it from the dedicated test process. Do not remove an API key needed by other applications or change persistent credentials for this demonstration. See [Claude's authentication guidance](https://support.claude.com/en/articles/12304248-manage-api-key-environment-variables-in-claude-code). Keep credentials out of the MCP JSON and shared logs. Do not interpret an authentication failure or timeout as a scanner result.

When the test ends, the session-specific MCP configuration is no longer loaded. Keep or remove this dedicated demo folder as needed; existing MCP registrations are unchanged.

## Sources and next action

- [Agent Scan 0.6.2 release](https://github.com/BackBond/agent-scan/releases/tag/v0.6.2): scanner artifact and checksum.
- [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp): local stdio configuration.
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage): session configuration and tool restrictions; installed 2.1.38 help was also checked.

After end-to-end acceptance, share only installation friction, the decision and a sanitized description of useful feedback. Try the [public synthetic example](https://backbond.ai/agent-scan/try/?source=claude-guide) or [watch its 50-second walkthrough](https://backbond.ai/agent-scan/#watch-demo). Running this check does not create insurance coverage or determine eligibility.
