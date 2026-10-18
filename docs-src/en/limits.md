---
title: Limits and pending work
summary: What is implemented, what is only proposed, what is blocked and the known defects.
---
## Status per component

| Component | Status |
|---|---|
| Collection, static and dynamic validation, decision, signing, publication, site | **CURRENT**: proven in production with automatic publication (`AUTO_PUBLISH=true`). |
| Public verifier | **CURRENT**: 29 tests and run against the real releases. |
| Quarantine service and panel | Implemented and tested locally; **not deployed**. |
| Automatic Cloudflare Pages | **Blocked**: the repository credential is not valid. |
| Independent macOS virtual machine | **Not available**: needs a self-hosted physical Mac. |
| Developer ID signing and notarization of the app | Pending. |
| GitHub immutable releases | Disabled; need authorization. |
| SLSA / in-toto attestations | **Do not exist.** |
| Verifier signed and attached to every release | **PROPOSED** |

## Known defects

Registered separately; this documentation describes the real behaviour and does not silently fix them.

- The Linux gate uses YARA 4.5.0 (Ubuntu) while the app ships {{tool.yara}}; 4 files classify differently.
- `manifest.rejected` is always empty in new releases: rejections are counted in the log, not in the manifest.
- The first cataloged release has no `checkpoint.txt` or signature among its artifacts; the verifier falls back to the repository checkpoint.
- The meaning of `expanded` in the statistics is the size of the decompressed rule files, which does not equal the total bytes of the tar archive.

## Blocked and waiting for a person

- A valid Cloudflare token (`CLOUDFLARE_API_TOKEN` with Cloudflare Pages: Edit) and `CLOUDFLARE_ACCOUNT_ID` as repository secrets.
- Workers and D1 credentials and a GitHub OAuth app to deploy the private panel; then the `QUARANTINE_URL` variable.
- Developer ID certificate and notarization.
- Enabling immutable releases.
- A self-hosted physical Mac for the independent virtual machine test.
