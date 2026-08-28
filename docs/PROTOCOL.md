# Public client protocol v4

Claim envelope: `backbond-agent-teaser/v4`

Claim set: `backbond-agent-self-assessment/v1`

Capture evidence: `backbond-evidence-capture/v1`

Capture receipt: `backbond-capture-receipt/v1`

Private analyzer bridge: `backbond-private-analyzer/v1`

The public client validates all 13 claims but assigns them no security meaning. Explicit artifact inputs are JSON-parsed, hashed as raw bytes, and represented only by type, basename, byte count, and digest.

The private analyzer is a separate executable. The bridge requires a caller-supplied SHA-256 pin, invokes the file without a shell, sends a versioned JSON request over stdin, and accepts a bounded JSON result on stdout.

The public client does not define how claims become verified observations, how findings are detected, how scores are calculated, or how controls are selected.

Without an analyzer, `scan` emits `analysis_required`, writes the requested capture receipt, and exits `3`.
