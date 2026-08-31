# `scan_not_run` playbook

1. Say `scan_not_run`; do not report `block`, `review`, or `no_blocking_finding`.
2. Record only OS, `node --version`, and the exact sanitized error category.
3. Agent Scan 0.5.15 requires Node.js 18 or newer.
4. Use the exact pin: `@backbond/agent-scan@0.5.15`; never fall forward to `@latest`.
5. Confirm `tools-list.json` exists before invoking `vet-tools`.
6. In PowerShell, pipe with `Get-Content -Raw .\tools-list.json | ...`; `<` is not the file-input form there.
7. Treat registry DNS, timeout, TLS, and unavailable-package errors as install failures, not scan decisions.
8. Retry once only after the environment or approved registry path is fixed.
9. For isolated hosts, transfer the checksum-verified standalone file through the approved software path.
10. Never post the raw manifest, trace, prompt, configuration, path-bearing receipt, or secret while debugging.
