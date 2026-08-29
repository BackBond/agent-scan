# Scan receipts

Receipt protocol: `backbond-scan-receipt/v1`.

A receipt records:

- scanner version and deterministic ruleset digest;
- each input basename, byte size, SHA-256 digest, and detected dialect;
- finding IDs, severities, and JSON Pointer evidence references;
- coverage-gap codes and optional claim-contradiction codes; and
- canonical payload integrity, optionally signed with Ed25519.

It does not record raw tool schemas, permission values, prompts, trace arguments, file bodies, secrets, or environment values.

`agent-scan verify-receipt --input receipt.json` recomputes the canonical digest and verifies the embedded signature when present. Verification proves integrity of the receipt under the embedded public key. It does not establish the identity or trustworthiness of the signer.
