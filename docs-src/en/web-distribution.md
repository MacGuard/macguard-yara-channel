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

> **LIMIT** **Cloudflare is not automated.** The repository secret `CLOUDFLARE_API_TOKEN` is not a valid Cloudflare token and the workflow classifies it as `site.cloudflare_blocked`. The `pages.dev` site was deployed **by hand** with the maintainer's local `wrangler` login; that is not the same as a correct automatic deployment. The problem stays open until a valid credential is configured (`CLOUDFLARE_API_TOKEN` with Cloudflare Pages: Edit permission and `CLOUDFLARE_ACCOUNT_ID`).

## Share preview

Every page carries Open Graph and X card metadata with a 1200 × 630 image and absolute URLs of the host serving it; `scripts/og_inject.py` writes them for GitHub Pages and for the mirror.
