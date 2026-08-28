# History-clean public release procedure

## Mandatory boundary

Do not publish v0.4 from the legacy development history. Earlier reachable commits contain implementation material that is no longer allowed in the public product boundary. Deleting files in a new commit does not remove old blobs from clones, forks, caches, or commit URLs. A valid clean public repository must pass the history gate below.

## Required release process

1. Keep the analyzer core in a separate private repository with restricted access.
2. Run `node --test` and `npm run test:public-boundary` in the public client.
3. Run `node scripts/assert-clean-history.js`. The current legacy repository is expected to fail this check.
4. Export the sanitized current tree with `node scripts/export-clean-public.js <empty-target-directory>`.
5. Initialize a new Git repository in that target directory; do not copy `.git` data, bundles, tags, or branches from the legacy repository.
6. Review the first commit and npm dry-run file list independently.
7. Create a new public remote, enable branch protection and npm trusted publishing, and verify its release workflow passes the history gate.
8. Make the legacy remote private or remove it after preserving an internal copy. Assume already-fetched historical material cannot be recalled.

Never use history rewriting alone as proof that previously public material is secret again.
