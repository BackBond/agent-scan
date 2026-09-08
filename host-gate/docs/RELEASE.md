# Agent Scan stdio gate 0.1.0

A separately versioned, dependency-free stdio wrapper for operator-controlled MCP
attachment. Download `agent-scan-gate.mjs` and the adjacent pinned
`agent-scan.cjs`, then verify both SHA-256 sidecars before configuring one server.
The scanner stays at 0.6.2; this is not an npm or MCP Registry scanner update.

[Installation and checksums](https://github.com/BackBond/agent-scan/blob/host-gate-v0.1.0/host-gate/README.md) ·
[Host configuration and evidence](https://github.com/BackBond/agent-scan/blob/host-gate-v0.1.0/host-gate/docs/HOSTS.md) ·
[Redacted attachment record](https://github.com/BackBond/agent-scan/blob/host-gate-v0.1.0/host-gate/docs/RECORDS.md)

The gate vets the full tool list before exposing definitions and before each
call. List changes invalidate attachment and require relisting. Errors and
timeouts fail closed. BLOCK has no override; REVIEW can use a protected operator
decision bound to the manifest and policy hashes, with optional expiry and
persistent revocation. That decision survives unchanged sessions.

Evidence includes synthetic source/bundle tests and official MCP SDK interop.
The real-host record is an instrumented OpenClaw embedded run using the modular
wrapper, not standalone-bundle activation or native Claude Code, Cursor or Codex
acceptance. The record includes a vetted list, model acknowledgement and a
deliberately induced stale-call refusal; no business-tool execution is claimed.

Tools-only stdio. Resources, prompts and HTTP/SSE are not proxied. The configured
server must already be authorized to start. This is not a startup sandbox or
runtime attestation, does not produce a BackBond Score, and creates no insurance
coverage. Installation never activates itself; host changes remain with operators.

`build.json` records source and executable hashes. Rebuild with
`node host-gate/scripts/build-release.mjs` from this exact tag. Assets are
published separately from the scanner release workflow; no npm provenance is
claimed for the wrapper. Existing scanner release assets are unchanged.
