# MacGuard YARA Channel — starter

Daily GitHub Actions source review, separate manually approved Ed25519 release, and four-language light/dark GitHub Pages site.

**Not deployed:** GitHub connector cannot create a new repository. Create a repository and upload this directory to `main`.

## Configure
1. Enable Pages via Settings → Pages → GitHub Actions.
2. Create protected environment `stable-signing` with required reviewer approval.
3. Add secret `MACGUARD_ED25519_PRIVATE_KEY_B64` (base64 encoding of raw 32-byte Ed25519 private seed) to that environment, not the repository. Generate and protect the key offline; embed its public counterpart in the app.
4. Run `Daily source review` and inspect validation and licenses before any publication.
5. Publish manually only after review, supplying the successful daily run ID.

## Boundaries
- Nextron and YARA-Rules provide rules; VirusTotal/yara-x is tracked as an **engine**, not a third rule feed.
- Normalization creates consistent metadata and paths, but does not rewrite rule semantics.
- The current validator rejects incompatible candidates rather than silently excluding them. Curated allowlists, fixtures, safe resource isolation, licensing review, rollback protection and pinned GitHub Actions SHAs are needed before production.
- The signing workflow is not a substitute for secure key custody; a GitLab account is not an Ed25519 signing key.
- Upstream repositories are not asserted to endorse the project or sign these releases.
- The website reports architecture, not fabricated production statistics.
