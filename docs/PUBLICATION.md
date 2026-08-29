# History-clean public release procedure

## Mandatory boundary

The public repository must pass the history gate below. Earlier legacy development history contained material outside the public product boundary; deleting files in a later commit would not remove old blobs from clones, forks, caches, or commit URLs.

## Required release process

1. Run `node --test` and confirm both fixture release gates.
2. Run `npm run test:public-boundary` and `node scripts/assert-clean-history.js`.
3. Review `npm pack --dry-run --json`; the open engine, rules, public-record writer, docs, and fixtures must be present and no analyzer executable or network client may be present.
4. Confirm the package version equals the intended immutable release tag.
5. Push the immutable version tag. The protected GitHub workflow publishes the tagged package contents to npm with provenance, re-downloads and content-checks the registry-authoritative tarball, and creates the official GitHub release with those exact registry bytes and their SHA-256 file.
6. Install the exact tarball with npm offline mode in a clean directory; rerun the vulnerable and hardened fixture scans, the incomplete coverage gate, and a public-record redaction smoke test.

If infrastructure fails after npm accepts an immutable version, an authorized `publish-v<version>` tag (or `publish-v<version>-rN` for another attempt) may retry that existing `v<version>` release. The workflow always checks out the original version tag and refuses registry content that differs beyond npm's CRLF-to-LF text normalization.

Never use history rewriting alone as proof that previously public material is secret again.
