# European and Spanish vulnerability sources

*Resumen: se añaden al canal de vulnerabilidades las fuentes de la UE (ENISA EUVD, su lista de explotadas y CERT-EU) junto a CISA KEV. Cada fuente conserva su propia afirmación; «explotada» solo sale de un campo estructurado de la fuente (una puntuación crítica es severidad); un paquete de Linux nunca se considera vulnerable sin datos de su distribución; y no se publica nada de terceros hasta que el registro lo autorice y el propietario lo confirme. INCIBE-CERT y CCN-CERT están bloqueadas.*

Status: EXPERIMENTAL. Real code, real runs on 2026-10-22, nothing published. Branch `feat/intelligence-eu` on top of `feat/intelligence-live` (PR #36). The CISA KEV channel is unchanged (its `kev-index.jsonl` keeps its shape); it only gains one additive file.

## 1. What was built

| Part | Where | What it does |
|---|---|---|
| Source registry | `config/intel/sources.registry.json` | Region (`US`, `EU`, `ES`), licence text, redistribution status, `owner_confirmed`, update frequency (`max_snapshot_age_days`), exploitation field, and the exact blocker for each source |
| Identifiers | `intel/vulns/ids.py` | CVE, EUVD and GHSA: one canonical spelling, strict syntax; text mentions are kept apart from aliases |
| Affected versions | `intel/vulns/versions.py` | Parses the shapes EUVD really uses (`A <B`, `A ≤B`, `A <publication`, `patch: X`, one version); keeps anything else verbatim; Debian version order |
| EUVD adapter | `intel/vulns/euvd.py`, `live_eu.py` | Pages the public search API (100 per page), checks completeness against the declared total, keeps every page byte for byte |
| CERT-EU adapter | `intel/vulns/certeu.py` | RSS; refuses DTD/entity declarations; advisories become references that mention CVEs |
| KEV in the same format | `intel/vulns/kev.py` | Adds `vuln-records.jsonl` next to the unchanged `kev-index.jsonl` |
| Cross-source merge | `intel/vulns/merge.py` | One entry per vulnerability, each source's statement kept side by side |
| Package assessment | `intel/vulns/assess.py` | Distribution-aware verdicts (dpkg order) |
| Independent packages | `intel/vulns/live_eu.py` | Channels `vulns-euvd`, `vulns-eukev`, `vulns-certeu`, plus the derived `vulns-merged` |
| Catalog | existing `intel/catalog.py` | Pins the exact version and manifest hash of each channel, unchanged |
| Web | `web/intelligence/vulns.html`, `web/api/v1/vulns.json`, `scripts/gen_intel_vulns.py` | Sources by region with filters, real counts, overlap, rules, and a card viewer |
| CLI | `mgctl intelligence vulns sources / lookup / assess`, `python3 -m intel vulns build / merge / sources / lookup / assess` | |
| Schemas | `docs/intelligence/schemas/vuln-record`, `vuln-merged`, `vuln-card`, `distro-fixes` | |

## 2. The sources, exactly

| Source | Region | Access | Terms read on 2026-10-22 | Status |
|---|---|---|---|---|
| ENISA EUVD | EU | public API, no key | no terms for the API or the data found; the site is a single-page app that serves no legal text to a plain request; ENISA's IPR policy covers its *publications* under CC BY 4.0 and does not say it covers this data | pending-legal |
| EUVD exploited list ("EU KEV") | EU | same API, `exploited=true` | same | pending-legal |
| CERT-EU advisories | EU | RSS, latest 10, refreshed daily (`ttl` 1440) | `cert.europa.eu/legal-notice`: CC BY 4.0 under Commission Decision 2011/833/EU, "unless otherwise noted"; third-party content excluded | allowed-with-conditions, not owner-confirmed |
| INCIBE-CERT | ES | RSS exists | `incibe.es/aviso-legal`: reproduction allowed only with integrity, attribution and compatible purpose, no commercial use; **distribution, public communication and transformation prohibited** | blocked: no adapter |
| CCN-CERT | ES | plain requests get HTTP 403 "browser test" | not read | blocked: not integrated. Bypassing a bot check is not done. Needs an official feed or a written agreement |
| NVD, OSV | US, global | public APIs | not evaluated | registered only; no adapter in this delivery |

"EU KEV" is not a separate catalogue. It is the EUVD search filtered to records that carry `exploitedSince`. The API does not say who observed the exploitation, and on 2026-10-22 all 1754 CISA KEV CVEs were also in the EUVD exploited list (plus 16 only in EUVD). That is overlap. It is not independent confirmation, and the data never calls it that.

## 3. Rules and where they are enforced

1. **Critical is not exploited.** `exploitation.asserted` is true only when a structured field says so (`exploitedSince`, KEV membership). Scores, EPSS and prose never set it. Tests: `test_a_critical_score_is_severity_never_exploitation`, `test_prose_about_exploitation_is_never_read_as_an_assertion`, `test_a_record_that_only_rates_severity_stays_not_exploited_next_to_a_kev_entry`.
2. **Per-source exploitation.** Every merged entry has `exploitation[source]`, `asserted_by`, `asserted_by_current` (excluding stale snapshots) and `independent_confirmation: "unknown"` when two sources agree.
3. **Date meanings are stated.** KEV's date is when CISA listed it; EUVD's `exploitedSince` is ENISA's date. Neither is called "when exploitation began".
4. **Identifiers.** Records join only through ids a source declares as its own. A record naming two CVEs, or a GHSA attached to two different CVEs, is not merged and goes to `conflicts`. Mentions, URLs and similar product names never join.
5. **Evidence stays.** Each record has `evidence`: the original file (kept byte for byte, hashed), the position in it, and the hash of the raw item. Evidence and references are per source.
6. **Versions.** `affected[].version.kind` is `range`, `fixed-marker`, `single`, `unspecified` or `unparsed`. A single version is flagged as ambiguous (affected or fixed is not stated). `fixes[]` is vendor text and says nothing about a distribution.
7. **Linux.** `assess` answers only from a `macguard.distro-fixes/1` table for the same distro, release, package and CVE. Without a row: `NOT_ASSESSED`. `rpm` is not implemented: `NOT_ASSESSED`. The verdict never says anything about exploitation.
8. **No publication.** A channel is publishable only if the registry clears every source and the owner confirmed, and the snapshot is complete. The merged view is never more publishable than its inputs. `scripts/gen_intel_vulns.py` drops the data of any source that is not cleared from a card, even on a vulnerability that another source clears.
9. **Stale data.** A snapshot older than the source's `max_snapshot_age_days` stays visible but is excluded from `asserted_by_current`.

## 4. Packages, hashes, signatures, attestations

Each channel directory has a canonical `manifest.json` with the SHA-256 and size of every file, the Merkle root, the sources and their licence status, and the approval block. The originals are marked `origin: original`. The global catalog (`python3 -m intel catalog build --channel .../manifest.json ...`) pins each channel's exact version and manifest hash, and `catalog verify` detects a changed byte (tested). 

There is **no signature and no attestation** for any of these channels: a signing workflow does not exist, and creating one needs the owner's authorisation. The verifier says "consistent, signature not checked" (exit 5) and never "verified".

## 5. Real runs (2026-10-22, evidence in `docs/intelligence/live-evidence/2026-10-22/`)

| Channel | Records | Pages | Accepted | Rejected | Complete | Publishable |
|---|---|---|---|---|---|---|
| `vulns-euvd` (2-day window) | 2928 | 30 | 2928 | 0 | yes | no (pending-legal) |
| `vulns-eukev` | 1770 | 18 | 1770 | 0 | yes | no (pending-legal) |
| `vulns-certeu` | 10 | 1 | 10 | 0 | yes | no (owner not confirmed) |
| `vulns` (KEV) | 1754 | 1 | 1754 | 0 | yes | no (owner not confirmed) |
| `vulns-merged` | 4708 entries from 6462 records | | | 0 conflicts | | no |

Merge result: 1754 entries have both CISA and EUVD-exploited; 16 only EUVD-exploited; 2928 only EUVD (window); 10 CERT-EU advisories without an identifier of their own.

A real run found a bug that the first tests had missed: the GHSA pattern was applied to a lower-cased string and rejected every real GHSA alias. It is fixed and `test_canonical_spellings` covers it.

## 6. How to run it

```bash
python3 -m intel vulns build enisa-euvd-exploited --out ROOT --version 1
python3 -m intel vulns build enisa-euvd --out ROOT --version 1 --window-days 2
python3 -m intel vulns build cert-eu-advisories --out ROOT --version 1
python3 -m intel vulns build cisa-kev --out ROOT --version 1
python3 -m intel vulns merge --channel ROOT/vulns/1 --channel ROOT/vulns-eukev/1 --channel ROOT/vulns-euvd/1 --channel ROOT/vulns-certeu/1 --out ROOT --version 1
python3 -m intel vulns lookup CVE-2026-0001 --merged ROOT/vulns-merged/1/merged.json
mgctl intelligence vulns assess CVE-2026-5001 --package apache2 --installed 2.4.52-1+deb12u1 --distro debian --release bookworm --rows distro-fixes.json
```

The EUVD builds wait one second between pages. A build that fails halfway leaves nothing behind.

## 7. Compatibility

- **CISA KEV channel:** `kev-index.jsonl`, `build-report.json` and the manifest shape are unchanged; `vuln-records.jsonl` is added. A test checks the legacy shape.
- **mgctl:** new experimental commands only (the command snapshot grows; none removed or changed).
- **MacGuard Intelligence (the existing YARA/macOS side):** untouched. The YARA channel, its workflows and its signatures are not modified.
- **Linux Intelligence Guard:** no repository, interface or code with that name exists in this checkout or in the files read, so no integration was written or tested. What exists is a stable contract it can consume: `macguard.vuln-record/1`, `macguard.vuln-merged/1`, `macguard.distro-fixes/1` (its input for `assess`) and the exit codes of `intel vulns assess` (0 patched or not affected, 1 affected and unpatched, 5 not assessed; `mgctl` maps them to 0, 2 and 4).

## 8. What is not done

- No publication, signing or attestation of any of these channels.
- No NVD or OSV adapter, no INCIBE-CERT or CCN-CERT adapter (blocked, see section 2).
- No distribution advisory feeds (Debian, Ubuntu, Red Hat) are downloaded: `assess` needs a `distro-fixes` table that something has to produce; the rpm version scheme is not implemented.
- `mgctl audit file --checks vulns` still reports `not_implemented`: judging a file needs its provenance and version, which this work does not connect.
- The country dimension of the web filters is the region of the *source* (US, EU, ES). The data does not say where a vulnerability is exploited or which country is affected, so no such filter exists.
- The EUVD API is documented by third parties only; fields beyond those seen on 2026-10-22 are unknown to this code and are ignored.
