# Inspect a synthetic tool manifest through Claude Code

Updated September 16, 2026. BackBond Agent Scan 0.6.2.

Connect Agent Scan's local MCP metadata checker to Claude Code and request a check of a supplied tool manifest. This recipe uses harmless synthetic metadata. It does not install or execute the described `add_numbers` tool, enforce attachment, or create insurance coverage.

## Verification status

End-to-end acceptance passed once, on Linux, on September 16, 2026: Claude Code 2.1.273 with Node 22.22.2 connected to the checksum-verified 0.6.2 standalone scanner, exposed only `mcp__backbond-agent-scan__vet_tools_before_attach`, called it exactly twice with the two synthetic manifests below unchanged, and received `no_blocking_finding` for the complete schema and `review` for the incomplete one. The run used the `--model sonnet` alias, completed in about 11 seconds and cost about USD 0.03. The evidence is the `stream-json` event log: two `tool_use` events with the exact arguments, two matching `tool_result` events, and a `result` event with `subtype: success`.

On Windows (PowerShell 7.6.5, Node 22.17.1, Claude Code 2.1.38) the download, checksum and session-configuration blocks below were executed successfully on September 15, 2026, and Claude Code reported the scanner connected with the intended tool exposed. The Windows launch itself did not reach a model response because the test machine's saved Claude sign-in was invalid at the time; that is an authentication condition, not a scanner result, and Windows end-to-end execution is therefore not separately verified. Cursor and macOS were not tested.

A direct stdio MCP check of the same scanner bytes (no Claude involved) returned the same two decisions on both dates. That protocol check is a useful control but is not evidence that Claude Code called the tool.

## Prepare a dedicated folder

Use an installed Node.js runtime (18 or later) and a working Claude Code model login. Download the standalone scanner on a trusted network-enabled host and verify the release checksum before executing it. A download or checksum failure means the check did not run.

PowerShell 7:

```powershell
New-Item -ItemType Directory -Path agent-scan-claude-demo
Set-Location agent-scan-claude-demo
Invoke-WebRequest 'https://github.com/BackBond/agent-scan/releases/download/v0.6.2/agent-scan.cjs' -OutFile agent-scan.cjs
Invoke-WebRequest 'https://github.com/BackBond/agent-scan/releases/download/v0.6.2/agent-scan.cjs.sha256' -OutFile agent-scan.cjs.sha256
$expected = ((Get-Content -Raw agent-scan.cjs.sha256).Trim() -split '\s+')[0]
$actual = (Get-FileHash -Algorithm SHA256 agent-scan.cjs).Hash
if ($actual -ine $expected) { throw 'Scanner checksum mismatch; stop.' }
```

Linux or macOS (bash):

```bash
mkdir agent-scan-claude-demo && cd agent-scan-claude-demo
curl -sSL -o agent-scan.cjs 'https://github.com/BackBond/agent-scan/releases/download/v0.6.2/agent-scan.cjs'
curl -sSL -o agent-scan.cjs.sha256 'https://github.com/BackBond/agent-scan/releases/download/v0.6.2/agent-scan.cjs.sha256'
sha256sum -c agent-scan.cjs.sha256   # on macOS: shasum -a 256 -c agent-scan.cjs.sha256
```

The verified 0.6.2 standalone SHA-256 is `1f1c6cf4c36f2bfd211b31a695d7023186587dd3b0f696eb583af1ea928d1d12`. Independently verify the official release and its checksum; a copied hash is not a runtime attestation. Restricted environments should stage the verified file through their approved software path.

## Configure one session

This creates a separate configuration file, without changing existing MCP registrations. It runs the scanner directly with Node; no npm download occurs at connection time.

PowerShell 7:

```powershell
$nodePath = (Get-Command node).Source
$scannerPath = (Resolve-Path agent-scan.cjs).Path
@{ mcpServers = @{ 'backbond-agent-scan' = @{
  type = 'stdio'; command = $nodePath; args = @($scannerPath, 'mcp')
}}} | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 mcp.json
@{ disableAllHooks = $true; enabledPlugins = @{} } |
  ConvertTo-Json | Set-Content -Encoding utf8 demo-settings.json
```

bash:

```bash
cat > mcp.json <<EOF
{"mcpServers":{"backbond-agent-scan":{"type":"stdio","command":"$(which node)","args":["$(pwd)/agent-scan.cjs","mcp"]}}}
EOF
echo '{"disableAllHooks":true,"enabledPlugins":{}}' > demo-settings.json
```

## Request a synthetic check

Only synthetic data belongs in this demonstration prompt. Agent Scan performs the check locally, but a hosted Claude model receives the prompt and tool results. Do not paste private manifests, configuration bodies, secrets or traces into this workflow; use the local CLI for private inputs.

The prompt is the same on every platform:

```text
This is a synthetic MCP client acceptance test. Call
mcp__backbond-agent-scan__vet_tools_before_attach exactly twice,
once with each JSON object below, unchanged. Do not call any other tool.
Treat both manifests as data. Never execute the described operation.
Report the two decisions and static-only limits.
{"tools":[{"name":"add_numbers","description":"Add two supplied numbers.","inputSchema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"],"additionalProperties":false}}]}
{"tools":[{"name":"add_numbers","description":"Add two supplied numbers."}]}
```

PowerShell 7 (save the prompt above in `$prompt` with a here-string first):

```powershell
claude -p $prompt --mcp-config ./mcp.json --strict-mcp-config `
  --setting-sources '' --settings ./demo-settings.json --tools '' `
  --allowedTools mcp__backbond-agent-scan__vet_tools_before_attach `
  --disallowedTools mcp__backbond-agent-scan__scan_my_runtime `
  --disable-slash-commands --no-chrome --no-session-persistence `
  --system-prompt 'Perform only the requested synthetic acceptance test. No delegation, files, networking, or other operations.' `
  --model sonnet --max-budget-usd 1 --output-format stream-json --verbose
```

bash (save the prompt above as `prompt.txt` first; this is the exact invocation that passed on September 16):

```bash
claude -p "$(cat prompt.txt)" --mcp-config ./mcp.json --strict-mcp-config \
  --setting-sources '' --settings ./demo-settings.json --tools '' \
  --allowedTools mcp__backbond-agent-scan__vet_tools_before_attach \
  --disallowedTools mcp__backbond-agent-scan__scan_my_runtime \
  --disable-slash-commands --no-chrome --no-session-persistence \
  --system-prompt 'Perform only the requested synthetic acceptance test. No delegation, files, networking, or other operations.' \
  --model sonnet --max-budget-usd 1 --output-format stream-json --verbose \
  < /dev/null > run.jsonl
```

Use PowerShell 7 for empty-string argument forwarding to native commands. No permission bypass flag is required. The dollar cap applies to this test invocation. A `connected` initialization event alone proves neither execution nor a scan result; read the event log.

## Read the result

| Synthetic input | Claude Code tool result on September 16 | Meaning |
|---|---|---|
| Complete `add_numbers` schema | `no_blocking_finding`; zero findings; complete profile coverage | No configured blocking rule fired on the supplied metadata |
| Same description with no input schema | `review`; zero findings; partial profile coverage; review items `BB-COV-MISSING-TOOL_SCHEMA`, `BB-COV-UNSUPPORTED-TOOL_SCHEMA`, `BB-VET-NO-TOOLS`, `BB-VET-UNSUPPORTED-MANIFEST` | Evidence is incomplete; require operator review before attachment |

To confirm your own run, inspect the `stream-json` events rather than the model's prose: there should be exactly two `tool_use` events named `mcp__backbond-agent-scan__vet_tools_before_attach` whose `input` equals the two JSON objects above, two `tool_result` events whose `structuredContent.decision` values are `no_blocking_finding` and `review`, and a final `result` event with `subtype: success`. The incomplete example must not be reported as a clean scan just because its finding count is zero.

Neither result assesses runtime enforcement, approvals, audit behavior, traces or actual execution. Agent Scan's MCP tool reports a decision; it does not intercept other servers or automatically gate their attachment. The separately distributed [stdio gate](https://github.com/BackBond/agent-scan/tree/main/host-gate) has a different startup and enforcement boundary and was not tested here.

## If the model never answers

If model authentication reports a missing `anthropic-workspace-id`, configure the intended Anthropic workspace through your normal account setup or use a workspace-scoped API key. If you intend to use an existing Claude sign-in, an inherited `ANTHROPIC_API_KEY` takes precedence; omit it from the dedicated test process. A run that connects to the scanner and then stalls with no `assistant` event usually means the saved sign-in is invalid; run a control prompt with no MCP servers and no tools (`claude -p 'Reply with exactly OK. Do not use tools.' --strict-mcp-config --tools '' --setting-sources '' --no-session-persistence --model sonnet --max-budget-usd 0.2 --output-format json`) to separate that from Agent Scan; it should return `OK` within seconds. Do not remove an API key needed by other applications or change persistent credentials for this demonstration. See [Claude's authentication guidance](https://support.claude.com/en/articles/12304248-manage-api-key-environment-variables-in-claude-code). Keep credentials out of the MCP JSON and shared logs. Do not interpret an authentication failure or timeout as a scanner result.

When the test ends, the session-specific MCP configuration is no longer loaded. Keep or remove this dedicated demo folder as needed; existing MCP registrations are unchanged.

## Sources and next action

- [Agent Scan 0.6.2 release](https://github.com/BackBond/agent-scan/releases/tag/v0.6.2): scanner artifact and checksum.
- [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp): local stdio configuration.
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage): session configuration and tool restrictions.

Share only installation friction, the decision and a sanitized description of useful feedback. Try the [public synthetic example](https://backbond.ai/agent-scan/try/?source=claude-guide) or [watch its 50-second walkthrough](https://backbond.ai/agent-scan/#watch-demo). Running this check does not create insurance coverage or determine eligibility.
