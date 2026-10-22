# Subscriptions and MacGuard Cloud: roadmap

*Resumen: P3 es un contrato (`AssetExposureMatch v1`) con un comparador de referencia ejecutable; no hay inventario, agente ni servicio Cloud. Orden sin fechas.*

| Step | What | Status |
|---|---|---|
| 1 | `AssetExposureMatch v1` (`docs/intelligence/schemas/asset-exposure-match.schema.json`, `alerts/exposure.py`): CONFIRMED_AFFECTED, POTENTIALLY_AFFECTED, NOT_AFFECTED, UNKNOWN, NOT_EVALUATED, with evidence kinds and invariants | **done** (tested) |
| 2 | Rules a producer must keep: name-only never matches; a Linux package is judged by distribution data (`intel vulns assess`), never by upstream ranges (backports); open-ended ranges and lone versions are only "potentially"; `UNKNOWN`/`NOT_EVALUATED` are never "unaffected"; a fleet summary always says how many assets were evaluated and how many lacked information | **done** (tested) |
| 3 | Inventory ingestion (software, versions, SBOM, provenance, baselines, attestations) from the Cloud contracts | planned: depends on `cloud-file-inventory`, `cloud-host-attestation` |
| 4 | Device groups tied to inventories (the `DEVICE_GROUP` scope exists; groups are empty names today) | planned |
| 5 | Exposure derived from authorised inventories (never from a port alone) | planned |
| 6 | Contextualised fleet alerts ("12 of 40 evaluated, 3 confirmed, 9 lack information") | planned |
| 7 | OIDC/SSO and a policy engine behind `authz.can` | planned |
| 8 | Hosted deployment, mail relay, shared rate limiter, secret store | planned: needs owner decisions and credentials |
