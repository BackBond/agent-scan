# Verify the published scanner bytes

The release workflow publishes package-registry provenance and attaches the registry-authoritative package tarball, its SHA-256 file, the deterministic standalone build, and its SHA-256 file to the matching source tag.

For version `0.5.10`, a reviewer can reproduce both shipped artifacts from the public tag:

```bash
git clone --depth 1 --branch v0.5.10 https://github.com/BackBond/agent-scan.git
cd agent-scan
npm pack --ignore-scripts
sha256sum backbond-agent-scan-0.5.10.tgz
node scripts/build-standalone.js agent-scan.cjs
sha256sum agent-scan.cjs
```

Compare both computed digests with the two `.sha256` files on the official `v0.5.10` source release. A mismatch is a stop condition. The page must not hard-code hashes before the protected release has produced and independently verified the final artifacts.

Package-registry provenance and the source workflow establish how the published artifact was built. Reproducibility independently shows that the tagged source produces the same bytes. Neither fact makes scanner output a runtime attestation or insurance decision.

Do not use `npm audit signatures` as proof of this package's own bytes: this package has zero runtime and development dependencies, while that command audits registry signatures for packages in a dependency tree. Link reviewers to the exact package provenance and source-release checksums instead.
