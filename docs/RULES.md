# Open local rule pack

Ruleset `backbond-local-rules/1.3.0` is implemented in `lib/rules.js` and fed by the evidence inference in `lib/evidence.js`. Its SHA-256 digest is computed from canonical public rule definitions, shared rule helpers, and the normalized evidence-detector source hash, so packaging the same logic does not change its identity while behavioral changes do. A test binds the source manifest to the current evidence implementation. The digest is emitted in every scan, receipt, and public record.

| ID | Severity | Requires | Finding condition |
|---|---|---|---|
| BB001 | high | tool capability + input trust | Code execution accepts untrusted or mixed input. |
| BB002 | critical | secret capability/scope + network scope | Secret access and unrestricted egress coexist. |
| BB003 | high | consequential capability + approval | Destructive or financial action has `none` or `advisory` approval. |
| BB004 | medium | persistent write + input trust | Persistent writes accept untrusted or mixed input. |
| BB005 | medium | privileged capability + audit | Privileged actions explicitly have no observable audit evidence. |
| BB006 | high | supported permission or sandbox scope | A filesystem, subprocess, credential, or egress scope is unrestricted. |
| BB007 | high | tool parameter schema + input trust | Untrusted or mixed input can supply unconstrained command, expression, code, or SQL text. |
| BB008 | high | tool parameter schema + input trust | Untrusted or mixed input can supply a URL, URI, endpoint, or webhook without an observable destination allowlist. |
| BB009 | high | tool description | Tool metadata contains instruction-override language. |
| BB010 | high | tool description | Tool metadata asks the agent to conceal behavior from the user or operator. |
| BB011 | high | tool description | Tool metadata directs sensitive data into a result or transmission. |
| BB012 | high | tool inventory + input trust | A fetch-like untrusted network tool shares an agent with a privileged tool. |
| BB013 | high | tool description | Tool metadata demands mandatory selection, invocation before responding, or exclusion of competing tools. |

Rules only fire from observed supported evidence. An unknown approval or audit value causes a coverage gap for the relevant rule; it is not silently treated as safe or unsafe. Findings derived from generic schemas or config heuristics have `evidence_quality: "derived"` and are displayed with `[derived]`.

`BB009`–`BB011` inspect tool titles, descriptions, and schema metadata using narrow local patterns. `BB013` is deliberately restricted to the top-level tool title and description so ordinary parameter requirements are not mistaken for forced tool selection. Raw text is discarded after derived risk IDs and evidence pointers are created. `BB012` requires fetch-like metadata rather than treating all outbound HTTP tools as network intake, and both sides must appear in the same observed tool inventory; tools found in separate agent-client manifests are not paired.

### Potential exposure paths

`EP001`–`EP003` are not rules. They summarize existing BB findings into potential composition paths for an agent or operator:

- `EP001`: untrusted network retrieval → shared agent context → privileged tool availability;
- `EP002`: secret access → shared agent authority → unrestricted network egress; and
- `EP003`: untrusted input → model-selected tool call → code or shell execution.

They do not affect severity or exit status and do not claim observed taint, sanitization, exploitability, or runtime data flow. The rule pack is `backbond-local-rules/1.3.0`.

### Known heuristic overreach

Derived findings can be wrong. In particular, broad third-party copy that says an image-search tool will “save” or “store” results can make an otherwise read-only `search_images` tool look like an untrusted persistent write (`BB004`). Aggressive marketing language can also resemble `BB009`–`BB011` or `BB013`. Explicitly read-only/no-execution explanation, description, lint, analysis, and documentation language suppresses the narrow execution-description heuristic, but cannot override an executable parameter schema. Confirm derived capabilities against the implementation or runtime policy; do not suppress explicit findings or coverage gaps because a neighboring derived finding overreached.

Every finding has an immediate `stop` instruction and longer remediation. Version 0.5.9 can emit non-enforcing policy and patch templates, but it does not apply them and does not claim to enforce approval, sandbox, allowlist, or audit controls.
