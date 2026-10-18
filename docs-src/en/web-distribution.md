---
title: Website and distribution
summary: Public URLs, what each site serves and the real state of the Cloudflare deployment.
---
## Public addresses

| What | GitHub Pages (primary) | Cloudflare Pages (mirror) |
|---|---|---|
| Web | https://macguard.github.io/macguard-yara-channel/ | https://macguard-rules.pages.dev/ |
| YARA rules | https://macguard.github.io/macguard-yara-channel/rules.html | https://macguard-rules.pages.dev/rules |
| Transparency | https://macguard.github.io/macguard-yara-channel/transparency.html | https://macguard-rules.pages.dev/transparency |
| Documentation | https://macguard.github.io/macguard-yara-channel/docs/index.html | https://macguard-rules.pages.dev/docs/index.html |

Both serve the same bytes; GitHub Releases is the canonical archive. The data shown on the site (catalog, history, transparency) is derived from signed manifests.

## What `site.yml` does

1. Downloads the release and history, builds the site and verifies the release exactly as a client would (`verify_release.py`).
2. Deploys GitHub Pages and then checks the public URL with `verify_live.py`: package, every rule file, catalog, signatures, proofs and links.
3. Tries Cloudflare Pages only if the credentials exist and pass a preflight that prints no secrets.
4. Records the result in the transparency log.

> **CURRENT** **Cloudflare Pages is deployed automatically by the workflow** (since 2026-10-18, run with `site.cloudflare_deployed` in the log) using the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets, with no dependence on any local machine. The project `macguard-rules` lives in the account whose id is in `config/cloudflare_account_id.txt`. The `pages.dev` site, documentation and verifier are checked with `verify_live.py` and serve the same bytes as GitHub Pages. Before that date the mirror was deployed by hand with a local `wrangler` session; that is no longer used. If the credential fails, the preflight classifies it, the workflow logs `site.cloudflare_blocked` and no deployment is attempted.

The site is rebuilt and deployed to both services after every release, on every web or documentation change and every 24 hours (04:17 UTC).

## Share preview

Every page carries Open Graph and X card metadata with a 1200 × 630 image and absolute URLs of the host serving it; `scripts/og_inject.py` writes them for GitHub Pages and for the mirror.
