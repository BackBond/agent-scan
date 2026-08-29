# Instructions for agents using `@backbond/agent-scan`

Version 0.5.0 is a local deterministic scanner. It parses intentionally exported JSON evidence and runs the public rules in `lib/rules.js`; it does not execute an analyzer, contact a hosted service, or assign a score.

1. Pin the exact package version in local and CI commands.
2. Export tool schemas, permission scopes, and traces intentionally. Do not add raw secret values merely to improve coverage.
3. Treat unsupported or missing evidence as a coverage gap, not as proof that a control is safe.
4. Use `--fail-on high` for the default CI gate and inspect medium findings separately.
5. Store raw traces locally. Receipts contain hashes and evidence pointers, not trace arguments or prompt bodies.
6. Verify a receipt before relying on it and establish trust in any signing key separately.
7. Treat the optional 13 claims as hypotheses. Claims cannot create, suppress, or reduce findings or severity.
8. Do not claim that suggested remediation is enforced unless the runtime actually implements and tests the control.

The `fixtures/vulnerable` case must exit `1` with `BB001`–`BB006`; `fixtures/hardened` must exit `0` with complete coverage. If either contract changes, update the ruleset version, tests, fixtures, changelog, and protocol documentation together.
