# Attachment records

These are redacted, operator-reported attachment observations, not independent
verification, scanner public scan-records, or runtime attestations.

## 8 September 2026 - successful guarded native OpenClaw embedded acceptance

**Observed:** OpenClaw 2026.6.1 (2e08f0f), with its installed MCP SDK 1.29.0, placed
one real internal stdio server's vetted tool into the actual agent context.
The real Agent Scan 0.6.2 receipt reported `no_blocking_finding`, zero findings and
complete metadata-profile coverage. Ruleset: 2.0.1; profile: backbond-pre-attach/v1.
No review override was used. The upstream server was not a fixture.

**Model response:** In the successful follow-up, the host's one authorized model
request returned HTTP 200. The model confirmed one matching vetted tool, with
a successful stop and no error in the persisted transcript. No model-requested
business call occurred; the transcript contains zero agent tool calls.

**Controlled refusal:** Temporary operator instrumentation used the native host's
same MCP client connection to send an unsupported diagnostic method. This
invalidated attachment through the deployed wrapper's existing protocol-error
path. A cached call was refused with `attachment_required` (-32001).
A diagnostic guard observed zero upstream tools/call attempts and did not trigger.
A fresh real tools/list restored the original vetted catalog.

**Limits beside the result:** This used the native embedded host runtime with
temporary instrumentation, not an uninstrumented session or the running gateway
process. Staleness was deliberately induced; this is not evidence of a naturally
emitted list_changed event. No successful business-tool execution is claimed.
All tracked live configuration/source files and auth-store bytes stayed unchanged
during this successful run. Temporary test scripts were removed.

The host ran the reviewed modular wrapper. The standalone release is built from
the exact same source hashes and is tested separately; it was not the executable
activated in this observation. Other native host clients remain unverified.

**Earlier attempts:** Model requests failed before separately approved provider
routing and credential-selection corrections. Independent minimal requests
isolated a credential-dependent failure before the corrected native run succeeded.
Failed attempts remain in the private audit history and are not counted as passes.

The record intentionally excludes server/tool names, manifests and their hashes,
wrapper instance identifiers, private paths, task content, and credentials.
The operator retains correlated receipts and evidence privately. It is a report
of observed attachment enforcement, not an independently reproducible public proof.

Tools-only stdio scope. Resources, prompts and HTTP transports are not proxied.
Server startup must already be authorized; this wrapper is not a startup sandbox.
Metadata checks do not prove runtime behavior, produce a BackBond Score, or create
insurance coverage.
