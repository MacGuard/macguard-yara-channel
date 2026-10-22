# Intelligence channels: what is real

*Resumen: un canal operativo (YARA clásico), uno experimental (IOC, sin fuentes reales autorizadas) y siete planificados.*

| # | Channel | Status | What exists | What blocks the next step |
|---|---|---|---|---|
| 1 | **YARA** (classic YARA, `yarac`) | **operational** | daily validated and signed releases, transparency log, independent verifier | none for operation; redistribution notices are pending legal review |
| 1b | **YARA-X compatibility gate** | planned | nothing: `yara-x` is only an engine entry; manifests record `validation.engine: yara` | needs a YARA-X build in CI and a compatibility policy (designed in `VALIDATION-PLAN.md`) |
| 2 | **Sigma** | planned | design only | pySigma bench and the licence decision for the rule source |
| 3 | **IOC** (hashes, IP, domains, URLs) | **experimental** | pipeline + manifest + catalog + verifier; one real source wired (Feodo Tracker: 5 records read, 0 publishable because all are older than the TTL) | threat feeds that need credentials (ThreatFox, URLhaus, MalwareBazaar) are blocked by their terms; owner confirmation and a signing/publication workflow do not exist |
| 3b | **Vulnerabilities (CISA KEV)** | **experimental** | wired end to end: 1754 of 1754 records validated, original preserved | owner confirmation and signing/publication workflow |
| 4 | **Antivirus / ClamAV signatures** | planned | design only | redistribution terms of the databases (see `LICENSE-MATRIX.md`); original CVD signatures must be kept, never re-signed |
| 5 | **Own heuristics** | planned | design only | test sets, threshold policy |
| 6 | **Behaviour detections** | planned | design only | sensors on macOS/Linux and event fixtures |
| 7 | **ML models** | planned | design only | independent test data, model licences, infrastructure |
| 8 | **Sandbox profiles/policies/results** | planned | design only | isolated infrastructure; real malware is never run on shared CI |

Common to every channel (enforced by the manifest and verifier for those that exist): independent version, identified sources, licence record, canonical manifest, SHA-256 of every artifact, signed publication (workflow pending), a slot for the signed test attestation, approval state, compatibility, revocation policy and an append-only history of versions.

Order of work (see `ROADMAP.md`): P0 audit and compatibility, P1 IOC, P2 software provenance, P3 Sigma, P4 ClamAV (legal gate), P5 heuristics and behaviour, P6 sandbox and ML.
