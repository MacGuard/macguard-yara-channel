### sigstore-lab run 40792835425

- commit: `3b71641b94ba6ec37f422192d12ff1ad4e592ebf`
- cosign: `v3.0.6` (signing runner) / `v3.0.6` (verifying runner)
- authorised identity of this lab: `https://github.com/MacGuard/macguard-yara-channel/.github/workflows/sigstore-lab.yml@refs/heads/exp/sigstore-lab`
- issuer: `https://token.actions.githubusercontent.com`

- checkpoint digest (SHA-256): `6896338605effbe8abb01ba2f3f07482df9f40ead09c7b527ed8534f61d54f45`

| check | result | detail |
|---|---|---|
| C1 bytes: repo file = signed = downloaded = digest inside the bundle | PASS | 6896338605effbe8abb01ba2f3f07482df9f40ead09c7b527ed8534f61d54f45 |
| C2 certificate SAN = authorised workflow identity, OIDC issuer extension present, Rekor entry with inclusion proof | PASS | {"san":"URI:https://github.com/MacGuard/macguard-yara-channel/.github/workflows/sigstore-lab.yml@refs/heads/exp/sigstore-lab","issuer_dn":"O=sigstore.dev, CN=sigstore-intermediate","valid_from":"Oct 29 00:15:26 2026 GMT","valid_to":"Oct 29 00:25:26 2026 GMT","fingerprint256":"DB:B9:8C:0D:BA:CF:17:D8 |
| P1 verify with the exact authorised identity and issuer | PASS (rc=0 as required) | - |
| P2 the OTHER workflow's signature is genuine for ITS identity (so the rejections below are about identity, not damage) | PASS (rc=0 as required) | - |
| N1 altered checkpoint (count 3 -> 2), original signature | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N2 altered signature (1 bit flipped inside the bundle) | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N3 wrong identity (the production checkpoint workflow, which did not sign this) | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N4 issuer not authorised (accounts.google.com) | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N5 a valid signature of the same bytes by a DIFFERENT workflow, verified against the authorised one | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N6a transparency evidence absent (tlogEntries removed) | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N6b transparency evidence AND signed timestamps absent | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N7 certificate of another workflow swapped into the bundle | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |
| N8 no bundle at all (unsigned checkpoint) | PASS (rc=1 as required) | FAIL: the checkpoint has no signature bundle (--bundle): an unsigned checkpoint is not accepted |
| N9 forged head with a bundle that does not cover it | PASS (rc=1 as required) | FAIL: the checkpoint signature does not verify for the authorised identity |

Informational (cosign called directly, not the product's verifier):

- cosign default policy, bundle without transparency evidence: rc=1
- cosign with --insecure-ignore-tlog=true, same bundle: rc=0 (the product's verifier never passes this flag)
- Rekor entry: logIndex=3553153190 integratedTime=1793232927 kind=hashedrekord

verdict: ALL-AS-REQUIRED
