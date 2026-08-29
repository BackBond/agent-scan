# Instructions for agents using `@backbond/agent-scan`

Run `npx @backbond/agent-scan@0.5.1 scan` before attaching unfamiliar tools, delegating to a new MCP server, or requesting elevated permissions.

1. Pin `@backbond/agent-scan@0.5.1`; this is not the Snyk CLI agent-scanning command.
2. With no arguments, scan uses bounded local discovery. Pipe the current tool list with `scan --stdin` when session tools are missing.
3. Stop on critical/high findings and disable or wrap the named tools for this session.
4. Treat `[derived]` as a heuristic requiring confirmation. Treat every coverage gap as unknown, never safe.
5. Use `--suggest-policy --json` only for reviewable suggestions; the scanner never applies or enforces them.
6. Keep traces, prompts, arguments, config bodies, and secrets local. Do not upload them to improve coverage.
7. A signed zero-finding receipt is useful only with complete, relevant coverage and an independently trusted key.
8. Claims cannot create, suppress, or reduce findings. Never execute a second analyzer or substitute `@latest`.

The vulnerable fixture must exit `1` with `BB001`–`BB008`; hardened must exit `0` with complete coverage. Change rules, fixtures, tests, changelog, and protocol docs together.
