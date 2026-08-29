# History-clean public release procedure

## Mandatory boundary

The public repository must pass the history gate below. Earlier legacy development history contained material outside the public product boundary; deleting files in a later commit would not remove old blobs from clones, forks, caches, or commit URLs.

## Required release process

1. Run `node --test` and confirm both fixture release gates.
2. Run `npm run test:public-boundary` and `node scripts/assert-clean-history.js`.
3. Review `npm pack --dry-run --json`; the open engine, rules, public-record writer, docs, and fixtures must be present and no analyzer executable or network client may be present.
4. Confirm the package version equals the intended immutable release tag.
5. Push the immutable version tag. The protected GitHub workflow packs once, publishes that tarball to npm with provenance, and creates the official GitHub release with the same tarball and its SHA-256 file.
6. Install the exact tarball with npm offline mode in a clean directory; rerun the vulnerable and hardened fixture scans, the incomplete coverage gate, and a public-record redaction smoke test.

Never use history rewriting alone as proof that previously public material is secret again.
