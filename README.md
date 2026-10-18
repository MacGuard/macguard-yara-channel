# MacGuard YARA Channel — starter

Daily GitHub Actions source review, separate manually approved keyless (Sigstore) release, and four-language light/dark GitHub Pages site.

**Not deployed:** GitHub connector cannot create a new repository. Create a repository and upload this directory to `main`.

## Configure
1. Enable Pages via Settings → Pages → GitHub Actions.
2. Create protected environment `stable-signing` with required reviewer approval.
3. No signing key exists. The publish workflow signs `manifest.json` and each log checkpoint with `cosign sign-blob` using its GitHub OIDC identity (`id-token: write`). Clients accept a signature only from `https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main` issued by `https://token.actions.githubusercontent.com`. `scripts/verify_release.py` performs the full client check: signatures, file hashes, rules root and log inclusion proof.
4. Run `Daily source review` and inspect validation and licenses before any publication.
5. Publish manually only after review, supplying the successful daily run ID.

## Boundaries
- Nextron and YARA-Rules provide rules; VirusTotal/yara-x is tracked as an **engine**, not a third rule feed.
- Normalization creates consistent metadata and paths, but does not rewrite rule semantics.
- The current validator rejects incompatible candidates rather than silently excluding them. Curated allowlists, fixtures, safe resource isolation, licensing review, rollback protection and pinned GitHub Actions SHAs are needed before production.
- the app still has to implement Sigstore bundle verification (Fulcio chain, Rekor inclusion, identity).
- Upstream repositories are not asserted to endorse the project or sign these releases.
- The website reports architecture, not fabricated production statistics.
