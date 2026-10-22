# Source-by-source status (2026-10-22)

*Resumen: cinco fuentes reales están conectadas de extremo a extremo en local (Feodo Tracker, CISA KEV, ENISA EUVD con su lista de explotadas, y CERT-EU); ninguna se publica todavía. INCIBE-CERT y CCN-CERT están bloqueadas. ThreatFox, URLhaus, MalwareBazaar y ClamAV están bloqueadas por credenciales y por términos. «Conectada» no significa «operativa».*

Legend: **FUNCTIONAL** = runs today against the real source and is tested; **EXPERIMENTAL** = real code and real run, but not publishable; **PENDING** = not done; **BLOCKED** = cannot be done without a decision or credential the owner must provide. Nothing in this table is signed by a new publication workflow, because none exists.

| Source | Download | Authentication | Licence / commercial use (evidence: `LICENSE-MATRIX.md`) | Validation | Functional tests | Signature | Publication | Independent verification | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| **YARA rules: signature-base, Yara-Rules** (legacy channel) | implemented (`scripts/prepare.py`, daily) | none (git, public) | DRL-1.1 with per-rule overrides (13 files non-commercial CC BY-NC: must be filtered per rule); GPL-2.0 (legal review pending); no licence notices ship in releases | classic YARA compile, static and dynamic gates | the repository suite (447 tests, 1 skip) | Sigstore keyless signature of the manifest and checkpoint (identity of the workflow; not authorship of the rules) | published, daily | `mgctl evidence verify --latest`: PASS on 2026-10-22 | **FUNCTIONAL** (licence redistribution **PENDING-LEGAL**) |
| **YARA-X** | none: `yara-x` is only an engine entry (`kind: engine`) | none | BSD-3-Clause (engine) | **no YARA-X gate exists**; manifests say `validation.engine: yara` | none | none | none | none | **PENDING** |
| **abuse.ch Feodo Tracker** (IOC) | implemented (`intel/live.py`, HTTPS, no key) | none | stated as CC0 in the abuse.ch terms ("currently"); `owner_confirmed: false` in the registry | IP syntax, global-address check, TTL (30 d), dedupe, drop report | 2 tests with a local server (plus 4 for the fetch layer); one real run: 5 records read, **0 published** (all last seen before 2026-03-07, older than the TTL; the feed header says last updated 2026-03-04) | none | **blocked**: owner confirmation and signing workflow missing | `python3 -m intel catalog verify` / `mgctl intelligence catalog verify`: consistent, unsigned (exit 5) | **EXPERIMENTAL** |
| **abuse.ch ThreatFox, URLhaus, MalwareBazaar** (IOC) | none: the old bulk URLs return HTTP 410; the replacements need an Auth-Key | Auth-Key required: **not available, and this work creates no accounts** | terms bar derivative works without consent; commercial use needs a paid subscription | none | none | none | none | none | **BLOCKED** |
| **SigmaHQ/sigma** | none | none (git, public) | DRL-1.1: allowed with conditions (attribution) | needs pySigma, which is not installed (the repository is standard-library only) | none | none | none | none | **PENDING** |
| **ClamAV databases (Cisco Talos)** | none: scripted `curl` got HTTP 403 and the FAQ denies scripted use; only freshclam/cvdupdate mirrors are supported | none documented for freshclam | no licence or redistribution grant found for the CVD files; they carry Cisco's signature, which must never be repacked or re-signed | none | none | original CVD `dsig` only | none | none | **BLOCKED** (needs a written answer from Cisco/Talos) |
| **CISA KEV** (vulnerabilities) | implemented (`intel/live.py`, HTTPS, no key) | none | CC0 / US Government work; `owner_confirmed: false` | required fields, CVE-id format, dates, duplicates; count check | 5 tests with a local server; one real run: **1754 of 1754 accepted, 0 rejected**, declared count matches | none | **blocked**: owner confirmation and signing workflow missing | consistent, unsigned (exit 5) | **EXPERIMENTAL** |
| **ENISA EUVD** (recent window, `enisa-euvd`) | implemented (`intel/vulns/euvd.py`, `live_eu.py`; public API, no key) | none | no terms found; `pending-legal` | schema, ids, dates, score range, duplicates, completeness check against the declared total | `tests/test_vulns_eu.py` (local server, no network); one real run: **2928 of 2928 accepted** (2-day window, 30 pages) | none | **blocked**: legal terms + owner confirmation + signing workflow | consistent, unsigned (exit 5) | **EXPERIMENTAL** |
| **ENISA EUVD exploited list** ("EU KEV", `enisa-euvd-exploited`) | implemented (same adapter, `exploited=true`) | none | same as above | as above, plus every entry must carry `exploitedSince` | one real run: **1770 of 1770 accepted** (18 pages); 1754 of them are exactly the CISA KEV CVEs, 16 are only in EUVD | none | **blocked**: as above | consistent, unsigned | **EXPERIMENTAL** |
| **CERT-EU advisories** (`cert-eu-advisories`) | implemented (RSS, latest 10) | none | CC BY 4.0 per its legal notice, `owner_confirmed: false` | XML (DTD/entity refused), advisory number agrees between title and link, dates | one real run: **10 of 10 accepted**, 0 exploitation asserted (prose is never read as a statement) | none | **blocked**: owner confirmation + signing workflow | consistent, unsigned | **EXPERIMENTAL** |
| **INCIBE-CERT** (Spain) | no adapter | none | INCIBE legal notice forbids distribution and transformation | none | none | none | none | none | **BLOCKED** |
| **CCN-CERT** (Spain) | no adapter: plain requests get an HTTP 403 browser challenge, not defeated | none | not read | none | none | none | none | none | **BLOCKED** (access and terms unverified) |
| **NVD** | none | none | not evaluated | none | none | none | none | none | **PENDING** |
| **OSV** | none | none for the public API | per-record licences (some CC-BY-SA origins need review) | none | none | none | none | none | **PENDING** |
| **Linux distribution security data** (Debian, Ubuntu, Red Hat) | none | none | not evaluated | none | none | none | none | none | **PENDING** |

## What was really downloaded on 2026-10-22

* CISA KEV: 1,803,428 bytes; catalog version 2026.10.21; 1754 records declared, 1754 accepted. The original file is preserved byte for byte (`origin: original`) next to a derived CVE index.
* Feodo Tracker: 5 records; all expired by TTL, so the IOC channel built from it has 0 indicators.
* ENISA EUVD, 2-day window: 2928 records in 30 pages of 100; all accepted. EUVD exploited list: 1770 records in 18 pages; all accepted (every entry carries `exploitedSince`). CERT-EU advisories RSS: 10 items; all accepted. Overlap on the same day: all 1754 CISA KEV CVEs are also in the EUVD exploited list, plus 16 only in EUVD, and the merge found 0 identifier conflicts (`live-evidence/2026-10-22/vulns-merged-1.json`). That is overlap, not independent confirmation: the EUVD API does not say who observed the exploitation.
* Nothing else was downloaded. No third-party data is hosted or published by MacGuard.

## How to reproduce

```bash
python3 -m intel live cisa-kev --out /tmp/intel-run --version 1
python3 -m intel live abusech-feodo --out /tmp/intel-run --version 1
python3 -m intel vulns build enisa-euvd-exploited --out /tmp/intel-run --version 1
python3 -m intel vulns build enisa-euvd --out /tmp/intel-run --version 1 --window-days 2
python3 -m intel vulns build cert-eu-advisories --out /tmp/intel-run --version 1
```

Both print the retrieval record (URL, time, size, SHA-256), the accepted/rejected counts and why the channel is not publishable.
