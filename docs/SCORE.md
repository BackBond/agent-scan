# Score availability

The public package cannot calculate a score. Scores and control recommendations are produced only by the separately distributed private analyzer or an authorized BackBond service.

This boundary is intentional: publishing executable scoring or detection logic in a JavaScript package would disclose the implementation regardless of minification or obfuscation.

The public client may display a private analyzer result and may show its exact optional POST envelope with `--dry-run`. It does not contain enough information to reproduce that result independently.

A matching caller-supplied analyzer digest is not independent verification. The
client reports that the bytes matched the pin, but it does not authenticate the
analyzer publisher or establish that the result is a BackBond-approved score.
