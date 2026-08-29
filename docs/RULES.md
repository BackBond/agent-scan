# Open local rule pack

Ruleset `backbond-local-rules/1.0.0` is implemented in `lib/rules.js`. Its SHA-256 digest is emitted in every scan and receipt.

| ID | Severity | Requires | Finding condition |
|---|---|---|---|
| BB001 | high | tool capability + input trust | Code execution accepts untrusted or mixed input. |
| BB002 | critical | secret capability/scope + network scope | Secret access and unrestricted egress coexist. |
| BB003 | high | consequential capability + approval | Destructive or financial action has `none` or `advisory` approval. |
| BB004 | medium | persistent write + input trust | Persistent writes accept untrusted or mixed input. |
| BB005 | medium | privileged capability + audit | Privileged actions explicitly have no observable audit evidence. |
| BB006 | high | canonical permissions | A filesystem, subprocess, credential, or egress scope is unrestricted. |

Rules only fire from observed supported evidence. An unknown approval or audit value causes a coverage gap for the relevant rule; it is not silently treated as safe or unsafe.

Remediation text is guidance. Version 0.5.0 does not ship a policy wrapper and does not claim to enforce approval, sandbox, allowlist, or audit controls.
