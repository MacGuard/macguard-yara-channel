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
| Automatic Cloudflare Pages | **CURRENT**: deployed by the workflow and verified with `verify_live.py`. |
| Independent macOS virtual machine | **Not available**: needs a self-hosted physical Mac. |
| Developer ID signing and notarization of the app | Pending. |
| GitHub immutable releases | Disabled; need authorization. |
| SLSA / in-toto attestations | **Do not exist.** |
| Verifier signed and attached to every release | **PROPOSED** |

## Known defects

Registered separately; this documentation describes the real behaviour and does not silently fix them.

- Ten files of the first release have been withheld since the second: 6 fail static classification (reproduced outside CI) and 4 depend on a library file that the CI review excluded; that exclusion could not be reproduced locally and the detailed reason only exists in the private store, which is not deployed yet.
- The Linux gate uses Ubuntu YARA 4.5.0 and the app {{tool.yara}}: static classification matches with both, so the engine difference does not explain those 4 files.
- `manifest.rejected` is always empty in new releases: rejections are counted in the log, not in the manifest.
- The first cataloged release has no `checkpoint.txt` or signature among its artifacts; the verifier falls back to the repository checkpoint.
- The meaning of `expanded` in the statistics is the size of the decompressed rule files, which does not equal the total bytes of the tar archive.

- `evidence` in the manifest is the publishing workflow's signed statement that the dynamic measurement belongs to the published set. It is not an independent in-toto or SLSA attestation of the whole process; those are not produced.

## Blocked and waiting for a person

- Workers and D1 credentials and a GitHub OAuth app to deploy the private panel; then the `QUARANTINE_URL` variable.
- Developer ID certificate and notarization.
- Enabling immutable releases.
- A self-hosted physical Mac for the independent virtual machine test.
