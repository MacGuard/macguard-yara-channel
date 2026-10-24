---
title: Threat model
summary: Which attacks are considered, what stops them today and what is not covered.
---
| Threat | What stops it today | What is not covered |
|---|---|---|
| Compromised or force-pushed upstream source | Pinned commit, quarantine of new rules with findings, anomaly guard (15 % removed / 40 % touched) and the dynamic test. | A malicious rule that compiles, performs well and uses no flagged construct. |
| Rule that hangs or uses lots of memory | Measurement against the previous release, absolute limits, per-file timeout and culprit isolation. | Pathological inputs the corpus does not contain. |
| File altered in transit or on the host | Signed per-file SHA-256 and `rules_root`; the app and the verifier check them. | Nothing if the attacker also controls the workflow identity. |
| Site serving an old (rollback) or different (fork) release | Verified and saved checkpoint; the app refuses smaller sizes or different roots at the same size. | A new client with no earlier checkpoint has no rollback protection on its first verification. |
| Publishing from another workflow or branch | The signed identity names `publish.yml@refs/heads/main`; protected main branch, minimal permissions. | A malicious change to `publish.yml` on `main` that passes review. |
| Leak of quarantined rules | Public artifacts, logs and site carry counts only; details go only to the private service. | The private service is deployed. Its authorization was tested on a local harness and on the real Workers runtime with a real D1; what the real GitHub OAuth app, real user tokens and Cloudflare rate limits do in production has not been independently verified (owner to confirm). |
| Malicious archive on extraction | Limits on members, sizes and depth; no links, absolute paths or duplicates. | — |

Rekor and Fulcio are public Sigstore infrastructures trusted during verification; the trust root is pinned in the app and can rotate.
