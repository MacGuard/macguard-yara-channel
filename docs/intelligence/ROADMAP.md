# MacGuard Security Intelligence: roadmap

*Resumen: sin fechas ni porcentajes. Cada fase indica qué está hecho, qué falta y qué necesita autorización.*

| Phase | Scope | Done (evidence) | Missing / needs authorisation |
|---|---|---|---|
| **P0** | repository audit, compatibility, contracts, continuity of the YARA channel | state report (`STATE-2026-10-22.md`); catalog and channel contracts with schemas and a verifier (`intel/`, 42 tests); legacy YARA channel referenced unchanged; `mgctl evidence verify` PASS against the live release | owner decisions on the open PRs; the JSON Schemas for the channel manifest, catalog and IOC record exist as files (`schemas/`) but are not validated against a JSON Schema engine in CI (no such package is installed) |
| **P1** | IOC channel and signed publication | IOC pipeline (normalise, validate, dedupe, TTL, confidence, report), manifest, catalog, verifier, CLI (`python3 -m intel`, `mgctl intelligence …`), 42 tests in `tests/test_intel.py` plus 4 `mgctl` integration tests | a cleared source (licence and access decision, credentials the owner must create); a signing/publishing workflow (a change to a publication workflow needs authorisation); allowlist curation; real-feed false-positive review |
| **P2** | Software Provenance v1 (macOS/Linux) and per-file inventory | design, evidence matrix from real macOS experiments, JSON Schema (`PROVENANCE-DESIGN.md`) | implementation (not started) |
| **P3** | Sigma and sensor compatibility | validation design only | pySigma bench; licence decision |
| **P4** | ClamAV integration | licence/terms analysis (`LICENSE-MATRIX.md`) | legal review; original CVD signature preservation |
| **P5** | heuristics and behaviour | validation design only | test sets and sensors |
| **P6** | sandbox and ML | validation design only | isolated infrastructure, independent datasets |
| **Web** | Security Intelligence site | plan with real data sources per page (`WEB-PLAN.md`) | nothing is deployed; each stage ends at an owner approval |
| **Cloud** | versioned contracts for tenants, fleets, evidence | draft contracts and schemas (`CLOUD-CONTRACTS.md`) | nothing exists; TSA and key custody decisions |
| **Install** | `mgctl` via Homebrew (macOS and Linux), DEB, RPM, signed binaries | install script, deterministic archive, pure-Python DEB, Homebrew and RPM templates (`docs/cli/mgctl-install.md`) | publishing any package; `dpkg`/`rpmbuild`/`brew` verification on real systems; signing |
