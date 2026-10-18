---
title: Operations and tests
summary: How the pipeline runs, which variables control it and how it is tested.
---
## Workflows

| Workflow | When | Purpose |
|---|---|---|
| `daily.yml` | 03:17 UTC and manual | Candidate review, reference-engine job on macOS (`macos`), publication request; `app-compat` reports MacGuard compatibility without blocking. |
| `publish.yml` | Requested by `daily.yml` | Signs and publishes. |
| `site.yml` | After publishing and when the web or documentation changes | Builds, verifies and deploys the site. |
| `chain-test.yml` | Manual and on pipeline changes | Synthetic end-to-end chain with 27 checks. |
| `build-engine.yml` | Manual | Builds the universal YARA engine. |
| `app-tests.yml` | On app changes | macOS app tests. |

## Publication control

- The variable `AUTO_PUBLISH=true` selects the `stable-signing-auto` environment (no approver); without it `stable-signing` with a human approver is used. Technical checks, the OIDC identity and the protected branch are identical in both.
- `allow_large_change` in `daily.yml` allows a publication that exceeds the anomaly guard, after human review.
- `QUARANTINE_URL` points to the private service once it exists.

## What the documentation triggers

A change only to `docs-src/` or the generator files rebuilds and deploys the site, but does **not** run the rule review or create a release. If the documentation tests fail the site is not deployed.

## Tests

```bash
python3 -m unittest discover -s tests
python3 scripts/docs_check.py
```

- `tests/test_docs.py`: consistency between documentation, code and real manifests, ES/EN parity and absence of private data.
- `scripts/docs_check.py`: renders the pages and diagrams in headless Chrome, on desktop and mobile.
- `tests/test_verify_public_release.py`: 29 verifier tests, including artifact tampering.
