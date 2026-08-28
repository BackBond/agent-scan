# Instructions for agents using the public client

This package captures evidence; it does not analyze or score the runtime.

1. Complete the 13 claims yourself and use `unknown` where evidence is unavailable.
2. Supply only artifact files intentionally exported by the harness.
3. Use `inspect` to capture hashes without analysis.
4. Treat `scan` without a private analyzer as a fail-closed result. Do not enable privileged tools based on the claims.
5. Invoke a private analyzer only when the operator supplies both its path and a trusted SHA-256 digest.
6. Use `--publish` only with explicit operator authorization.

Never copy private analyzer source, rule material, detector fixtures, calibration data, private prompts, credentials, or signing keys into this repository or its npm tarball.
