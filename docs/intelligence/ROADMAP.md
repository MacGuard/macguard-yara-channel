# MacGuard Security Intelligence: roadmap

*Resumen: sin fechas ni porcentajes. Cada fase indica qué está hecho, qué falta y qué necesita autorización.*

| Phase | Scope | Done (evidence) | Missing / needs authorisation |
|---|---|---|---|
| **P0** | repository audit, compatibility, contracts, continuity of the YARA channel | state report (`STATE-2026-10-22.md`); catalog and channel contracts with schemas and a verifier (`intel/`, 42 tests); legacy YARA channel referenced unchanged; `mgctl evidence verify` PASS against the live release | owner decisions on the open PRs; the JSON Schemas for the channel manifest, catalog and IOC record exist as files (`schemas/`) but are not validated against a JSON Schema engine in CI (no such package is installed) |
| **P1** | IOC channel and signed publication | two real sources wired end to end (abuse.ch Feodo Tracker, CISA KEV) with the original kept and counts recorded (`SOURCES-STATUS.md`); IOC pipeline (normalise, validate, dedupe, TTL, confidence, report), manifest, catalog, verifier, CLI (`python3 -m intel`, `mgctl intelligence …`), 42 tests in `tests/test_intel.py` plus 4 `mgctl` integration tests | a cleared source (licence and access decision, credentials the owner must create); a signing/publishing workflow (a change to a publication workflow needs authorisation); allowlist curation; real-feed false-positive review |
| **P2** | Software Provenance v1 (macOS/Linux) and per-file inventory | design, evidence matrix from real macOS experiments, JSON Schema (`PROVENANCE-DESIGN.md`); **first engine** `intel/provenance/` + `mgctl provenance file`: collectors for Homebrew formula and cask, pkgutil, quarantine/codesign, pip, dpkg; 224 tests with 11 real macOS runs (experimental) | Linux real-host test (dpkg collector is fixture-only), online checks, rpm/pacman/npm/cargo/go/containers, host-wide `provenance --all` and per-file inventory (planned), history across runs |
| **EU-Vuln** | European and Spanish vulnerability sources next to CISA KEV (ENISA EUVD, EU exploited list, CERT-EU; INCIBE-CERT and CCN-CERT recorded as blocked) | adapters and validators run against the real APIs (2928 + 1770 + 10 records, 0 merge conflicts); identifiers CVE/EUVD/GHSA; per-source exploitation; distribution-aware Linux assessment; independent channels pinned by the catalog; PR #37 (`EU-VULNERABILITIES.md`) | EUVD reuse terms (pending-legal); owner confirmation; signing workflow; NVD, OSV, CCN-CERT and distribution feeds have no adapter |
| **Alerts** | Subscriptions and Alerts: alert model, closed filter language, matching engine, public and private RSS, e-mail, webhooks, organisations and roles, web section ES/EN | P0 static pages and public feeds with first-party data (`docs/alerts/ARCHITECTURE.md`); reference backend for accounts, subscriptions, tokens, delivery, tenancy and RBAC with tests and a real-browser end-to-end including WCAG 2.2 AA; `AssetExposureMatch v1` contract and reference matcher | no hosted service, mail relay or identity provider; no third-party vulnerability data is published (sources not cleared); inventory-based correlation (P3) needs MacGuard Cloud |
| **P3** | Sigma and sensor compatibility | validation design only | pySigma bench; licence decision |
| **P4** | ClamAV integration | licence/terms analysis (`LICENSE-MATRIX.md`) | legal review; original CVD signature preservation |
| **P5** | heuristics and behaviour | validation design only | test sets and sensors |
| **P6** | sandbox and ML | validation design only | isolated infrastructure, independent datasets |
| **Web** | Security Intelligence site | plan with real data sources per page (`WEB-PLAN.md`) | nothing is deployed; each stage ends at an owner approval |
| **Cloud** | versioned contracts for tenants, fleets, evidence | draft contracts and schemas (`CLOUD-CONTRACTS.md`) | nothing exists; TSA and key custody decisions |
| **Install** | `mgctl` via Homebrew (macOS and Linux), DEB, RPM, signed binaries | install script, deterministic archive, pure-Python DEB, Homebrew and RPM templates (`docs/cli/mgctl-install.md`) | publishing any package; `dpkg`/`rpmbuild`/`brew` verification on real systems; signing |

## Order and dependencies (no dates)

The diagram shows what must exist before what. The axis is **order only**: a bar is not a schedule and its length is not an estimate.

```mermaid
gantt
    title Dependency order, no calendar
    dateFormat X
    axisFormat %s
    section Intelligence
    P0 contracts and verifier (done)                  :done, p0, 0, 1
    P1 IOC and KEV channels (experimental)            :done, p1, after p0, 1
    P2 file provenance engine (experimental)          :done, p2, after p0, 1
    EU vulnerability sources (experimental)           :done, eu, after p1, 1
    Owner decisions on licences and signing           :crit, dec, after eu, 1
    Publish cleared channels                          :pub, after dec, 1
    P3 Sigma, P4 ClamAV (legal gate)                  :p34, after dec, 1
    P5 heuristics and behaviour, P6 sandbox and ML    :p56, after p34, 1
    section Alerts
    Alert model, filters, engine (experimental)       :done, a0, after eu, 1
    Public feeds and Explore, first-party data        :done, a1, after a0, 1
    Reference backend: accounts, subscriptions        :done, a2, after a0, 1
    Organisations, roles, webhooks (core)             :done, a3, after a2, 1
    Hosted service, mail relay, identity provider     :crit, a4, after a3, 1
    Third-party alerts in public feeds                :a5, after dec, 1
    section Cloud
    AssetExposureMatch contract and matcher           :done, c0, after a0, 1
    Inventory, groups, exposure, fleet alerts         :c1, after a4, 1
```
