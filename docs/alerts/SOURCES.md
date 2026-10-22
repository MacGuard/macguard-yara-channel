# Intelligence sources for alerts: register

*Resumen: de las fuentes pedidas, una (los registros de versiones de reglas de MacGuard) alimenta alertas públicas hoy; cuatro están integradas y probadas con datos reales pero sin permiso de redistribución; el resto está pendiente o bloqueado. El estado «activa» solo existe si hay adaptador, importación reciente y datos.* The machine-readable form is `web/intelligence/alerts/data/sources.json` (generated) and `config/intel/sources.registry.json` (the decision record).

| Source | Official endpoint | Format | Expected update | Licence / terms (read 2026-10-22/23) | Redistribution | Adapter | State |
|---|---|---|---|---|---|---|---|
| MacGuard YARA release log | `logs/log.jsonl` of this repository | JSON lines | each release (daily check) | first-party metadata | allowed; `owner_confirmed: true` is the maintainer's call to review | yes | **active** (3 alerts) |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | JSON | ≤ 7 days | CC0 / US Government work | cleared by status, **not owner-confirmed** | yes | implemented, not published |
| ENISA EUVD | `euvdservices.enisa.europa.eu/api/search` | JSON API (100 per page, no key) | ≤ 3 days | no EUVD terms found; ENISA IPR policy covers its publications (CC BY 4.0) | **pending-legal** | yes | implemented, not published |
| ENISA EU KEV (EUVD `exploited=true`) | same API | JSON | ≤ 3 days | same; reported to be largely fed by CISA KEV | **pending-legal** | yes | implemented, not published |
| CERT-EU advisories | `cert.europa.eu/publications/security-advisories-rss` | RSS (latest 10) | daily | CC BY 4.0 per its legal notice, "unless otherwise noted" | allowed with conditions, **not owner-confirmed** | yes | implemented, not published |
| CCN-CERT | `ccn-cert.cni.es` | unknown | unknown | not read: plain requests get an HTTP 403 bot challenge, not bypassed | blocked | no | **blocked** |
| INCIBE-CERT | `incibe.es/incibe-cert/alerta-temprana` | RSS | daily | no commercial use; distribution and transformation prohibited | blocked | no | **blocked** |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | JSON API | ≤ 3 days | US Government work; API terms not evaluated | not evaluated | no | pending |
| OSV / GHSA | `api.osv.dev` | JSON API | ≤ 3 days | per-record licences | not evaluated | no | pending |
| Debian Security Tracker | `security-tracker.debian.org/tracker/data/json` | JSON | ≤ 3 days | not read | not evaluated | no | pending |
| Ubuntu Security | `ubuntu.com/security/cves.json` | JSON | ≤ 3 days | not read | not evaluated | no | pending |
| Red Hat Security Data | `access.redhat.com/hydra/rest/securitydata/cve.json` | JSON | ≤ 3 days | not read | not evaluated | no | pending |
| ThreatFox, URLhaus, MalwareBazaar | abuse.ch | JSON | n/a | Auth-Key required; terms bar derivative works without consent | blocked | no | **blocked** |
| SigmaHQ (new/changed rules) | `github.com/SigmaHQ/sigma` | git | n/a | DRL 1.1 (attribution) | allowed with conditions | no | pending (needs a git-diff job) |

Per source the system records: endpoint, format, expected frequency (`max_snapshot_age_days`), licence text, redistribution status, owner confirmation, provenance (originals kept byte for byte with SHA-256), identifiers, snapshot time, import failures (`import_runs`) and coverage (alerts per source). A snapshot older than its limit is **stale**: its exploitation statements stop counting as current.
