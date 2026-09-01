# Open local rule pack

Ruleset `backbond-local-rules/2.0.0` is implemented in `lib/rules.js` and fed by the evidence inference in `lib/evidence.js`. Its SHA-256 digest is computed from canonical public rule definitions, shared rule helpers, and the normalized evidence-detector source hash, so packaging the same logic does not change its identity while behavioral changes do. A test binds the source manifest to the current evidence implementation. The digest is emitted in every scan, receipt, and public record.

| ID | Severity | Requires | Finding condition |
|---|---|---|---|
| BB001 | high | tool capability + input trust | Code execution accepts untrusted or mixed input. |
| BB002 | critical | secret capability/scope + network scope | Secret access and unrestricted egress coexist. |
| BB003 | high | consequential capability + approval | Destructive or financial action has `none` or `advisory` approval. |
| BB004 | medium/high | persistent write + input trust + same-inventory network intake | A standalone untrusted persistent write is review-level; an untrusted fetch or unallowlisted destination in the same supplied inventory raises it to high. |
| BB005 | medium | privileged capability + audit | Privileged actions explicitly have no observable audit evidence. |
| BB006 | high | supported permission or sandbox scope | A filesystem, subprocess, credential, or egress scope is unrestricted. |
| BB007 | high | executable tool context + parameter schema + input trust | Untrusted or mixed input can supply an unconstrained shell, code, evaluator, or database-interpreter value. |
| BB008 | high | active network context + parameter schema + input trust | Untrusted or mixed input can supply a URL, URI, or webhook without an observable hostname allowlist. |
| BB009 | high | tool description | Tool metadata directly instructs the agent to override protected instructions. |
| BB010 | high | tool description | Tool metadata directly asks the agent to conceal tool behavior from the user or operator. |
| BB011 | high | tool description | Tool metadata directly solicits sensitive data for a result or transmission. |
| BB012 | high | tool inventory + input trust + privilege evidence | A fetch-like untrusted network tool shares an inventory with explicit, destructive-hint, OpenAPI DELETE, or action-shaped privilege evidence. |
| BB013 | high | tool description | Tool metadata demands global selection, invocation before universal responses, or exclusion of competing tools. |

Rules only fire from observed supported evidence. An unknown approval or audit value causes a coverage gap for the relevant rule; it is not silently treated as safe or unsafe. Findings derived from generic schemas or config heuristics have `evidence_quality: "derived"` and are displayed with `[derived]`.

Every finding also reports `finding_class` and a non-numeric `precision_note`. `capability_exposure` covers `BB001`–`BB008` and `BB012`; `prompt_injection_indicator` covers `BB009`–`BB011` and `BB013`. The top-level `finding_classes` summary keeps those counts separate. Precision notes state the observable limits of the rule and do not claim a universal percentage from one corpus.

`BB009`–`BB011` inspect tool titles, descriptions, and schema metadata using narrow local patterns. Before matching, the scanner removes quoted directives, quoted examples, and explicitly introduced example/signature text, then requires directed imperative language rather than a mere mention. Security-analysis descriptions are suppressed when they describe detection rather than instructing the agent. In `vet-tools`, directive-like text suppressed because it is quoted, framed as an example, or scoped to response ordering creates a review gap instead of a finding or clean result. `BB011` requires a directed solicitation, emission, or transfer instruction and labels the observed class; an OAuth/account/API-key requirement by itself is not a finding. `BB013` is deliberately restricted to the top-level tool title and description and requires global invocation, universal-response ordering, or exclusion of other tools, so ordinary scoped task-routing guidance is not treated as forced selection. Raw text is discarded after derived risk IDs, evidence pointers, and normalized metadata-template hashes are created. Template hashes and multiplicity appear only in the full local finding JSON so offline corpus analysis can deduplicate repeated copy; receipts and public records omit them. `BB012` requires fetch-like metadata rather than treating all outbound HTTP tools as network intake. Its privilege side requires an explicit privileged/destructive/financial capability, a destructive annotation, an OpenAPI DELETE method, or an action-shaped tool identity such as deploy, IAM, or destructive mutation. Permission or delete appearing only in help text is insufficient. Both sides must appear in the same observed tool inventory; tools found in separate agent-client manifests are not paired.

`BB007` distinguishes executable interpreter context from generic query, filter, GIS, and calculator expressions. Ambiguous query/expression fields produce a pre-attachment review gap rather than a high finding. `BB008` likewise requires an active network context and a URL-like unconstrained field. Generic `endpoint`, `href`, `path`, `host`, and `destination` fields produce review gaps. A documentation/reference URL without explicit fetch, download, open, browse, request, or navigation context also routes to review; explicit fetch-the-URL prose remains high. A scheme-only pattern such as `^https://` is not a hostname allowlist; `const`, nonempty `enum`, or a pattern that fixes a hostname can suppress the destination finding. Vendor names or hosts mentioned only in prose do not establish enforcement.

### Potential exposure paths

`EP001`–`EP003` are not rules. They summarize existing BB findings into potential composition paths for an agent or operator:

- `EP001`: untrusted network retrieval → shared agent context → privileged tool availability;
- `EP002`: secret access → shared agent authority → unrestricted network egress; and
- `EP003`: untrusted input → model-selected tool call → code or shell execution.

They do not affect severity or exit status and do not claim observed taint, sanitization, exploitability, or runtime data flow. The rule pack is `backbond-local-rules/2.0.0`.

### Known heuristic overreach

Derived findings can be wrong. In particular, broad third-party copy that says an image-search tool will “save” or “store” results can make an otherwise read-only `search_images` tool look like an untrusted persistent write (`BB004`). Aggressive marketing language can also resemble `BB009`–`BB011` or `BB013`. For BB013, distinguish scoped first-party guidance such as “always use this tool for weather” from metadata that demands invocation before any reply or excludes competing tools. Explicitly read-only/no-execution explanation, description, lint, analysis, and documentation language suppresses the narrow execution-description heuristic, but cannot override an executable parameter schema. Confirm derived capabilities against the implementation or runtime policy; do not suppress explicit findings or coverage gaps because a neighboring derived finding overreached.

Every finding has an immediate `stop` instruction and longer remediation. Version 0.6.1 can emit non-enforcing policy and review-only patch templates, but it does not apply them and does not claim to enforce approval, sandbox, allowlist, or audit controls. BB007 and BB013 templates are deliberately incomplete until a human or authorized agent supplies environment-specific constraints and reviews the result.

In the pre-attachment profile, medium findings and coverage gaps also produce structured `review_items`. These items identify the review code, affected-tool count when observable, why review is required, what evidence would resolve it, and the next operator step. They do not suppress a finding, change severity, manufacture runtime evidence, or apply remediation. `--summary-only` retains this identity-free worklist while omitting the underlying tool names and evidence pointers.
