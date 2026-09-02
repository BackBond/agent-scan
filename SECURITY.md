# Security policy

## Report a security issue

Email **hello@backbond.ai** with the subject `agent-scan security` if you find a way to make the current release of `@backbond/agent-scan`:

- miss a finding it should raise;
- execute or upload data despite its documented local, static boundary; or
- produce a receipt or public record that misrepresents what was scanned.

Please do not open a public issue for an exploitable problem before BackBond has had a reasonable opportunity to investigate and address it.

## Protect sensitive data

Do not send raw tool manifests, prompts, traces, agent configuration, full JSON output, receipts containing paths or fingerprints, secrets, or data from a system you do not own. A minimal manifest you wrote yourself that reproduces the problem is preferred.

## Supported version

Security fixes are made against the current release published on npm. Upgrade to the current release before reporting a problem that affects only an older version.

False positives and rule-precision questions are not security vulnerabilities. Use the [scan feedback form](https://github.com/BackBond/agent-scan/issues/new?template=scan-feedback.yml) for those reports.

## Verify a release

The [current GitHub release](https://github.com/BackBond/agent-scan/releases/latest) publishes SHA-256 sidecars for the npm package tarball and standalone file. The npm package also carries registry provenance. From a project with an npm lockfile, `npm audit signatures` checks registry signatures and supported provenance attestations using the installed npm version.
