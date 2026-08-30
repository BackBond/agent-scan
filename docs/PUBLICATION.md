# History-clean public release procedure

## Mandatory boundary

The public repository must pass the history gate below. Earlier legacy development history contained material outside the public product boundary; deleting files in a later commit would not remove old blobs from clones, forks, caches, or commit URLs.

## Required release process

1. Run `node --test` and confirm both fixture release gates.
2. Run `npm run test:public-boundary` and `node scripts/assert-clean-history.js`.
3. Review `npm pack --dry-run --json`; the open engine, rules, public-record writer, `server.json`, docs, and fixtures must be present, and release-only network helpers must not be included.
4. Confirm the package version equals the intended immutable release tag.
5. Push the immutable version tag. The protected GitHub workflow publishes the tagged package contents to npm with provenance, re-downloads and content-checks the npm-registry-authoritative tarball, and creates the official GitHub release with those exact npm bytes and their SHA-256 file.
6. The same workflow validates `server.json` with a checksum-pinned official publisher, authenticates to the official MCP Registry using GitHub OIDC, publishes the exact server version, and verifies its complete package launch descriptor, remote transports, repository identity, and npm coordinates.
7. Install the exact tarball with npm offline mode in a clean directory; rerun the vulnerable and hardened fixture scans, the incomplete coverage gate, the MCP `initialize`/`tools/list` exchange, and a public-record redaction smoke test.

If infrastructure fails after npm accepts an immutable version, an authorized `publish-v<version>` tag (or `publish-v<version>-rN` for another attempt) may retry that existing `v<version>` release. The workflow always checks out the original version tag, refuses npm registry content that differs beyond npm's CRLF-to-LF text normalization, and skips an existing MCP Registry version only when its immutable launch metadata matches exactly.

Never use history rewriting alone as proof that previously public material is secret again.
