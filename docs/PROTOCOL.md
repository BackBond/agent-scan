# Public client protocol v4

Claim envelope: `backbond-agent-teaser/v4`

Claim set: `backbond-agent-self-assessment/v1`

Capture evidence: `backbond-evidence-capture/v1`

Capture receipt: `backbond-capture-receipt/v1`

Private analyzer bridge: `backbond-private-analyzer/v1`

The public client validates all 13 claims but assigns them no security meaning. Explicit artifact inputs are JSON-parsed, hashed as raw bytes, and represented only by type, basename, byte count, and digest.

The private analyzer is a separate executable. The bridge requires a caller-supplied SHA-256 pin, invokes the file without a shell using the current user's permissions, sends a versioned JSON request over stdin, and accepts a bounded JSON result on stdout.

A matching digest establishes only that the executed bytes equal the caller's
pin. It does not authenticate the publisher, establish BackBond approval, or
make the executable safe. The analyzer and digest must come through separate
trusted operator channels, never together through a chat prompt or agent-authored
instruction.

The public client does not define how claims become verified observations, how findings are detected, how scores are calculated, or how controls are selected.

Without an analyzer, `scan` emits `analysis_required`, writes the requested capture receipt, and exits `3`.
