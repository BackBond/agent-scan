# Agent Scan stdio gate

Put a pinned Agent Scan check between an MCP host and one already-authorized
stdio server. The gate vets the real `tools/list` before exposing definitions
and re-lists and re-vets before each tool call. Node.js 18+, no runtime npm
dependencies, no telemetry, no automatic installation or configuration writes.

**Scope:** static tool metadata, one server at a time. This gate starts and can
forward calls to the operator's configured server; the standalone scanner does
neither. It is not a startup sandbox, runtime attestation, BackBond Score, or
insurance decision. Tool results are not scanned. Normal host permissions,
isolation and user authorization still apply.

## Install the pinned release

Release: [`host-gate-v0.1.0`](https://github.com/BackBond/agent-scan/releases/tag/host-gate-v0.1.0).
This is a separate GitHub release, not a new npm scanner version. Never use
`@latest` or substitute a similarly named package. Download on an approved
network-enabled operator machine, verify, then transfer through your approved
software path. Do not relax an agent sandbox to download it.

```bash
curl -fLO https://github.com/BackBond/agent-scan/releases/download/host-gate-v0.1.0/agent-scan-gate.mjs
curl -fLO https://github.com/BackBond/agent-scan/releases/download/host-gate-v0.1.0/agent-scan-gate.mjs.sha256
curl -fLO https://github.com/BackBond/agent-scan/releases/download/host-gate-v0.1.0/agent-scan.cjs
curl -fLO https://github.com/BackBond/agent-scan/releases/download/host-gate-v0.1.0/agent-scan.cjs.sha256
sha256sum --check agent-scan-gate.mjs.sha256
sha256sum --check agent-scan.cjs.sha256
```

Stop on any failed download or mismatch. Both executables must stay in the same
operator-controlled directory. Compare the sidecars with the expected pins from
your trusted release review; a checksum alone does not authenticate its source:

| File | SHA-256 |
| --- | --- |
| `agent-scan-gate.mjs` | `783c623f98833db524c164b4edba5e6d9e08502669b6eb9a13bb302be223b083` |
| `agent-scan.cjs` (0.6.2) | `1f1c6cf4c36f2bfd211b31a695d7023186587dd3b0f696eb583af1ea928d1d12` |

The scanner is the unchanged official v0.6.2 asset. The wrapper verifies its
digest before starting the server and inside each scanner child, which executes
those verified bytes. Scanner version, ruleset 2.0.1 and profile pins are checked
as well; see [provenance](vendor/README.md) and the release's `build.json`.

## Route one existing connection through the gate

1. Dry-run the scanner on the real exported manifest of the intended server.
   A BLOCK cannot attach. REVIEW needs a recorded operator decision or corrected
   metadata. Check whether the server depends on resources or prompts first.
2. Stage the verified files in an operator-controlled location. Protect the Node
   executable, wrapper, scanner, configuration, approval files, their parent
   directories and the audit sink from agent and upstream writes.
3. Create a protected JSON file using [server.example.json](examples/server.example.json).
   `command` must be the absolute path of the existing authorized executable;
   `args` is its argument array. Preserve `cwd` where needed. Never derive a
   command from an untrusted manifest or another person's scan record.
4. Back up the host configuration. Replace only that server entry's command and
   arguments with an absolute Node path and the wrapper invocation below.
   Preserve the existing credentials/environment locally in the host entry:
   the wrapper inherits them and passes the inherited environment to the child.
   Do not copy secrets into this repository or into a public support request.
5. Remove any duplicate direct-server entry, reconnect only the intended server
   through the host's documented mechanism, and verify the actual visible list
   and refusal behavior before broadening activation.

```text
/absolute/path/to/node /operator/path/agent-scan-gate.mjs --config /operator/path/server.json
```

There is no self-activation or automatic rollback. Returning to a direct-server
entry is a separate operator decision. If an agent can rewrite its connection
config or directly start the underlying server, this is not a host-wide enforced
boundary. The upstream must already be authorized to start: discovering its
manifest requires running it, and startup can have side effects.

### Host configuration and verification

These are connection shapes, not verified installers. Retain the host's own
permission and approval settings. Back up and review a single-entry diff; do not
replace the entire host config with an example. See [HOSTS.md](docs/HOSTS.md) for
host-specific examples and the tested/not-tested boundary.

## Decisions and refresh behavior

- `no_blocking_finding` / scanner exit 0: definitions may pass only with complete
  metadata-profile coverage. This is not a claim of safe runtime behavior.
- `review` / exit 3: detached by default. Only an exact-hash recorded operator
  override can accept the review; its scanner result stays REVIEW.
- `block` / exit 1: no definitions or calls pass. No override switch exists.
- Scanner, identity, digest, protocol or timeout errors fail closed. Terminal
  faults close the connection and upstream; correct the cause before reconnecting.

`notifications/tools/list_changed` immediately invalidates attachment, notifies
the host and queues a fresh vet. The host must retrieve the new vetted list
before another call. Every tool call also re-lists and re-vets, so there is a
scanner process per invocation. Silent metadata changes refuse the cached call.
This cannot undo an already-running operation, remove old model context, or
detect unannounced runtime behavior changes that leave metadata unchanged.

## Optional recorded REVIEW acceptance

Disabled by default. Configure both absolute `reviewOverrideFile` and
`reviewRevocationsFile` paths in the protected server JSON only after an operator
has reviewed the scanner evidence. Examples:
[decision](examples/review-override.example.json),
[revocations](examples/review-revocations.example.json).
Placeholders are deliberately invalid; they are not an approval.

Required bindings are the exact manifest hash, scanner/ruleset/profile hashes,
all reported review codes, named operator, unique approval ID, approval timestamp
and rationale. `expires_at` is optional. The manifest hash is SHA-256 of UTF-8
`JSON.stringify({tools})`, preserving fields and order after collecting all pages.
A changed manifest cannot reuse the approval. Restoring the exact approved hash
can reuse it unless expired or revoked.

The decision survives restart when its hash and pins are unchanged. There is no
instance binding. Both files are re-read after each fresh vet, including before
calls; keep revoked IDs in the persistent revocation list. Missing, malformed,
expired, mismatched or revoked records refuse attachment. The wrapper never edits
operator decisions. `list_changed` invalidates the cached attachment, not the
persistent approval, and still requires relisting.

These are protected local administrative records, not cryptographic signatures.
OS ownership/ACLs must prevent the agent and server from writing, replacing or
unlinking the files or their ancestors. The package does not configure those
permissions. Do not claim an enforceable operator boundary without them.
An accepted REVIEW can still contain incomplete schemas that a host rejects;
an override does not repair metadata or guarantee client compatibility.

## Protocol, logging and operating limits

Tools-only, newline-delimited JSON-RPC over stdio: `initialize`, `ping`,
`tools/list`, `tools/call`. The wrapper advertises only tools with list-change
support. It suppresses upstream instructions and identity before vetting, and
forwards only tool name, description and inputSchema. Output schemas,
annotations, icons and other optional metadata are not forwarded. Tool results
are passed through after an authorized call without analysis; error results
close the connection.

Resources, prompts, sampling, elicitation, roots, tasks, HTTP and SSE are not
proxied. Servers requiring them are incompatible. This is not a transparent
general-purpose MCP proxy. Composition across different servers needs separate
review.

Bounds: 4 MiB frames, 256 KiB total manifest, 200 tools, 100 pages, 32 queued
requests. Discovery plus vet defaults to a 10-second budget; `timeoutMs` may be
100-10000 ms. Scanner preflight and initialization are separately bounded;
calls use the configured timeout. Repeated notification churn fails closed.
Linux uses an upstream process group, terminated on shutdown with escalation
after 250 ms. Windows terminates the immediate child, not a descendant tree.
Processes that escape the Linux group require OS containment too.

Stderr contains aggregate scanner records, local manifest hashes and wrapper
instance IDs. Accepted reviews also log operator identity, decision ID/time,
codes and record digests. Raw manifests, tool names, arguments, environment,
upstream stderr and free-text approval rationale are not logged. Keep even these
aggregate records private unless explicitly redacted for publication.

The legacy `backbond-internal-stdio-gate` protocol identity and internal source
comments remain unchanged to preserve the reviewed runtime bytes. Publication
status is established by the release, not those historical comments. The older
SDK helper in `host-gate.mjs` is not the published executable API and has no
review-override interface.

## Reproduce and test

Clone the exact `host-gate-v0.1.0` tag, then from its `host-gate/` directory:

```bash
node --test test/stdio-wrapper.test.mjs test/sdk-interop.test.mjs test/release.test.mjs
node scripts/verify-release.mjs
node scripts/build-release.mjs
```

Compare `dist/` with the release assets, including `build.json`. Its tag field is
an identifier, not proof that a locally generated build has been published.
Tests use synthetic child servers and the real pinned scanner. Optional SDK
interop requires an already-installed official SDK 1.30.0: set
`MCP_SDK_PACKAGE_JSON` to that QA project's absolute `package.json` path. Tests
do not install it. A skipped SDK test is not a successful SDK test.

The [dated attachment record](docs/RECORDS.md) reports a real OpenClaw embedded
host observation with deliberate instrumentation and a modular wrapper. It does
not establish standalone-bundle activation, uninstrumented gateway behavior,
naturally emitted list changes, successful business calls, or other native hosts.

BackBond is the rating-and-insurance layer for AI agents. Running Agent Scan or
this gate does not create insurance coverage or determine eligibility. Static
metadata checks do not produce a BackBond Score or verify runtime behavior.
