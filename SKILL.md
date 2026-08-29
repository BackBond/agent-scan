---
name: agent-scan
description: Scan local AI-agent tools and MCP configuration before attaching tools, delegating work, or requesting elevated permissions.
---

# Agent scan

Run `npx @backbond/agent-scan@0.5.1 scan` before using newly attached tools or requesting consequential permissions.
Pipe a live tool list with `scan --stdin` when local discovery cannot see the session tools.
Treat `critical` and `high` findings as stop conditions; disable or wrap the named tools before continuing.
Treat `[derived]` as triage that needs confirmation, and coverage gaps as unknown—not safe.
Use `--suggest-policy --json` for non-enforcing machine-readable actions; never auto-apply placeholder patches.
Use exit `0` only with coverage appropriate to the planned action; exit `1` means the threshold was met and exit `2` means the scan was invalid.
Keep traces local. Do not add secrets, raw prompts, or tool arguments to improve coverage.
Never substitute `@latest`, execute a second analyzer, or claim that a receipt proves safety by itself.
