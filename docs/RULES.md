# Open local rule pack

Ruleset `backbond-local-rules/1.2.1` is implemented in `lib/rules.js`. Its SHA-256 digest is emitted in every scan, receipt, and public record.

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

Rules only fire from observed supported evidence. An unknown approval or audit value causes a coverage gap for the relevant rule; it is not silently treated as safe or unsafe. Findings derived from generic schemas or config heuristics have `evidence_quality: "derived"` and are displayed with `[derived]`.

`BB009`–`BB011` inspect only top-level tool titles and descriptions using narrow local patterns. Raw text is discarded after derived risk IDs and evidence pointers are created. `BB012` requires fetch-like metadata rather than treating all outbound HTTP tools as network intake, and both sides must appear in the same observed tool inventory; tools found in separate agent-client manifests are not paired.

### Potential exposure paths

`EP001`–`EP003` are not rules. They summarize existing BB findings into potential composition paths for an agent or operator:

- `EP001`: untrusted network retrieval → shared agent context → privileged tool availability;
- `EP002`: secret access → shared agent authority → unrestricted network egress; and
- `EP003`: untrusted input → model-selected tool call → code or shell execution.

They do not affect severity or exit status and do not claim observed taint, sanitization, exploitability, or runtime data flow. The rule pack remains `backbond-local-rules/1.2.1`.

### Known heuristic overreach

Derived findings can be wrong. In particular, broad third-party copy that says an image-search tool will “save” or “store” results can make an otherwise read-only `search_images` tool look like an untrusted persistent write (`BB004`). Aggressive marketing language can also resemble `BB009`–`BB011`. Explicitly read-only/no-execution documentation language suppresses the narrow execution-description heuristic, but cannot override an executable parameter schema. Confirm derived capabilities against the implementation or runtime policy; do not suppress explicit findings or coverage gaps because a neighboring derived finding overreached.

Every finding has an immediate `stop` instruction and longer remediation. Version 0.5.7 can emit non-enforcing policy and patch templates, but it does not apply them and does not claim to enforce approval, sandbox, allowlist, or audit controls.
