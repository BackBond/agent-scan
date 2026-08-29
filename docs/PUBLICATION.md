# History-clean public release procedure

## Mandatory boundary

The public repository must pass the history gate below. Earlier legacy development history contained material outside the public product boundary; deleting files in a later commit would not remove old blobs from clones, forks, caches, or commit URLs.

## Required release process

1. Run `node --test` and confirm both fixture release gates.
2. Run `npm run test:public-boundary` and `node scripts/assert-clean-history.js`.
3. Review `npm pack --dry-run --json`; the open engine, rules, docs, and fixtures must be present and no analyzer executable or network client may be present.
4. Confirm the package version equals the intended immutable release tag.
5. Publish through the protected GitHub environment with provenance enabled.
6. Install the exact tarball in a clean directory and rerun the vulnerable and hardened fixture scans.

Never use history rewriting alone as proof that previously public material is secret again.
