# MacGuard Security Intelligence - Licence and Source-Terms Matrix

Status: DRAFT for owner and legal review. Read date: 2026-10-22 (all sources below were read on that date unless stated). This document is information, not legal advice and not an authorization to publish. MacGuard does not own, and must not claim to own or relicense, any third-party content listed here.

## Resumen en espanol

- Fuentes europeas añadidas el 2026-10-22: ENISA EUVD y su lista de explotadas (sin términos de reutilización encontrados: PENDING-LEGAL), CERT-EU (CC BY 4.0, con condiciones), INCIBE-CERT (BLOCKED: prohíbe distribución y transformación) y CCN-CERT (no se pudo leer: desafío anti-bot, no se elude).
- Se revisaron 30+ fuentes candidatas (YARA, Sigma, IOC, ClamAV, MITRE ATT&CK, NVD/OSV/GHSA, ML). Ninguna publicacion esta autorizada por este documento; solo registra la evidencia.
- Redistribuibles con condiciones (atribucion/aviso de licencia): Sigma (DRL 1.1), reglas DRL de signature-base, ReversingLabs (MIT), ESET malware-ioc (BSD-2), CISA KEV (CC0), Feodo Tracker y SSL Blacklist de abuse.ch (CC0 segun sus Terms), MITRE ATT&CK (copiar aviso + licencia), GHSA (CC BY 4.0).
- Bloqueadas o pendientes: abuse.ch MalwareBazaar/URLhaus/ThreatFox (Auth-Key obligatoria; Terms prohiben obras derivadas sin consentimiento, uso comercial requiere suscripcion, prohibido entrenar IA), OpenPhish (sin redistribucion ni uso comercial), OTX y PhishTank (requieren credencial), Elastic (ELv2, limitacion de servicio gestionado), Yara-Rules y CAPE (copyleft GPL), ClamAV CVD (no hay licencia/termino publico de redistribucion de la base; solo mirror privado documentado), NVD (terminos no verificables en vivo).
- Trampa clave: signature-base declara DRL 1.1 por defecto pero 13 ficheros llevan CC BY-NC 4.0, otros OGL v3, Volexity, GPL/BSD/MIT propios: el registro debe filtrar por regla, no por repositorio.
- Las URLs masivas sin autenticacion de abuse.ch (`/export/txt/...`, `/downloads/text/`, ThreatFox `/export/json/recent/`) devuelven HTTP 410 (verificado); las sustituye el acceso con Auth-Key (portal auth.abuse.ch) y los lotes `datalake.abuse.ch`. No se creo ninguna cuenta ni clave.

## 0. Method and limits

- Evidence: `gh api` on public repos (LICENSE files, README, per-rule meta of a shallow clone of signature-base at commit `3ce6640c26046da8e6d8094af3eaaee3ee84e648`), `curl` GET (HTTP status only for gated endpoints), WebFetch summaries of vendor pages. WebFetch summaries are model-generated; quotes below are short phrases and must be re-verified against the stored source text (hash in the registry) before reliance.
- No account created, no API key requested, no terms accepted, no credential used. Where a source requires one, that is recorded as a blocker.
- Not verified (explicitly): the full text of several ToS pages that render client-side (NVD, OTX), Cisco/PhishTank EULA text, OpenPhish community-feed-specific terms, blocklist.de terms page, Malpedia, per-file headers of every repository other than signature-base.
- "Verified" in the signature column for git means GitHub's `commit.verification.verified` flag on the last 10 commits; it is mixed (GitHub web-flow merge signatures vs author keys) and is NOT an upstream release signature. See section 4.

Verdict legend: ALLOWED-WITH-CONDITIONS / PENDING-LEGAL / BLOCKED / NOT-VERIFIED.

## 1. Verdict table (brief)

| # | Source | Licence as stated | Verdict |
|---|---|---|---|
| 1 | Neo23x0/signature-base (YARA, IOC lists) | DRL 1.1 default; per-rule exceptions | ALLOWED-WITH-CONDITIONS for DRL-tagged rules only; BY-NC rules BLOCKED; OGL/Volexity/others PENDING-LEGAL |
| 2 | Yara-Rules/rules | GPL-2.0 | PENDING-LEGAL |
| 3 | ReversingLabs YARA rules | MIT | ALLOWED-WITH-CONDITIONS |
| 4 | Elastic protections-artifacts (YARA) | Elastic License 2.0 | PENDING-LEGAL |
| 5 | ESET malware-ioc | BSD-2-Clause | ALLOWED-WITH-CONDITIONS |
| 6 | VirusTotal/yara-x | BSD-3-Clause (engine, not a rule source) | ALLOWED-WITH-CONDITIONS (engine only) |
| 7 | CAPEv2 YARA (data/yara) | GPL-3.0 repo (Cuckoo Foundation text), per-rule author headers | PENDING-LEGAL |
| 8 | Malpedia and other rule hubs | not read | NOT-VERIFIED |
| 9 | SigmaHQ/sigma | DRL 1.1 | ALLOWED-WITH-CONDITIONS |
| 10 | abuse.ch MalwareBazaar / URLhaus / ThreatFox | abuse.ch Terms of Use; Auth-Key | BLOCKED (redistribution) until written consent/subscription |
| 11 | abuse.ch Feodo Tracker, SSL Blacklist, YARAify | CC0 "currently" per Terms of Use | ALLOWED-WITH-CONDITIONS |
| 12 | CISA KEV | CC0 1.0 (cisagov/kev-data) | ALLOWED-WITH-CONDITIONS |
| 13 | Other US gov feeds (NVD CVE, CISA advisories) | not verified live | NOT-VERIFIED |
| 14 | MISP default feeds (108 entries) | per feed, heterogeneous | PENDING-LEGAL per feed (no blanket verdict) |
| 15 | CIRCL OSINT feed | CC BY 4.0 by default "unless a repository or dataset states otherwise" | PENDING-LEGAL (leaning ALLOWED-WITH-CONDITIONS after per-event check) |
| 16 | OpenPhish community feed | Terms of Use | BLOCKED |
| 17 | PhishTank | registration/key; Cisco EULA; no licence stated | NOT-VERIFIED (credential blocker) |
| 18 | Emerging Threats Open | GPLv2 / BSD by SID range; Pro excluded | PENDING-LEGAL (BSD SID range ALLOWED-WITH-CONDITIONS) |
| 19 | AlienVault OTX | API key required (HTTP 403 unauthenticated) | BLOCKED (credential) / NOT-VERIFIED terms |
| 20 | Spamhaus DROP | free use + attribution; redistribution not addressed | PENDING-LEGAL |
| 21 | blocklist.de | no licence; "as they are" | PENDING-LEGAL |
| 22 | ClamAV engine | GPL-2.0 | ALLOWED-WITH-CONDITIONS (engine, as GPL) |
| 23 | ClamAV signature DBs (main/daily/bytecode.cvd) | no DB licence or redistribution grant found | PENDING-LEGAL (public redistribution), private mirror documented |
| 24 | MITRE ATT&CK STIX | MITRE licence (copy notice + licence) | ALLOWED-WITH-CONDITIONS |
| 25 | NVD / CVE API | live terms not retrievable | NOT-VERIFIED |
| 26 | OSV (aggregate) | per upstream source; osv.dev code Apache-2.0 | ALLOWED-WITH-CONDITIONS per record origin; CC-BY-SA origins PENDING-LEGAL |
| 27 | GitHub Advisory Database (GHSA) | CC-BY-4.0 | ALLOWED-WITH-CONDITIONS |
| 28 | ML model sources | differ per model | NOT-VERIFIED (checklist only) |
| 29 | ENISA EUVD (database and public API) | no EUVD-specific terms found (2026-10-22); ENISA's IPR policy says CC BY 4.0 for ENISA publications, and that this covers the EUVD data is NOT confirmed | PENDING-LEGAL |
| 30 | ENISA EUVD exploited list ("EU KEV") | same as 29; the list is reported to be largely fed by CISA KEV | PENDING-LEGAL |
| 31 | CERT-EU security advisories (RSS) | CC BY 4.0 per cert.europa.eu/legal-notice (Commission Decision 2011/833/EU), "unless otherwise noted"; third-party content excluded | ALLOWED-WITH-CONDITIONS |
| 32 | INCIBE-CERT early-warning feeds (Spain) | INCIBE legal notice: no commercial use; distribution, public communication and transformation expressly prohibited | BLOCKED |
| 33 | CCN-CERT alerts and bulletins (Spain) | not read: plain requests get an HTTP 403 browser challenge, which this project does not defeat | NOT-VERIFIED (access blocker) |

## 2. Detailed records

Common fields for each: URL, provides/format, licence as stated, redistribution rights, access terms, per-item licence differences, original signature, verdict.

### 2.1 YARA sources

#### 1. Neo23x0/signature-base
- URL: https://github.com/Neo23x0/signature-base (read 2026-10-22; HEAD cloned `3ce6640c...`; last push 2026-10-17).
- Provides: 753 `.yar` files under `yara/`, IOC lists (`iocs/*.txt`: hashes, filenames, C2, keywords), `vendor/yara/airbnb_binaryalert.yar`.
- Licence as stated: README: switched on 13.08.2021 to "Detection Rule License (DRL) 1.1"; "All signatures and IOC files ... except the YARA rules that explicitly indicate a different license (see 'license' meta data)". Older releases (<= v2.0) are CC BY-NC.
- DRL 1.1 rights (LICENSE text): permission to use, copy, modify, merge, publish, distribute, sublicense and/or sell the Rules, subject to retaining: author identification ("author" field), a URI/hyperlink to the rule set or rule, and an indication that the Rules are under the DRL with the licence text or URI. Matches produced by use of the Rules must carry the same author attribution. Commercial use allowed. No share-alike. No non-commercial limit.
- Per-item licences differ (measured on the clone): 410 of 753 files carry no `license` meta (fall under the repository default per README); the rest carry per-rule `license` strings, including DRL 1.1 (majority), `https://creativecommons.org/licenses/by-nc/4.0/` (13 files containing "by-nc": apt_apt27_hyperbro, apt_apt41, apt_exile_rat, crime_nansh0u, crime_malware_generic, gen_excel_auto_open_evasion, gen_excel_xll_addin_suspicious, gen_github_net_redteam_tools_names, crime_xbash, gen_excel_xor_obfuscation_velvetsweatshop, generic_anomalies, thor-hacktools, hktl_HvS_nfs_security_tooling), UK Open Government Licence v3 (apt_cisco_asa_lineviper_rayinitiator_sep25), "See license at https://github.com/volexity/threat-intel/LICENSE.txt" (9 files), CAPEv2 LICENSE pointer, "BSD 2-Clause", "MIT", "CC BY 4.0". The vendored airbnb_binaryalert.yar has its own provenance header and no licence meta read here.
- Access: public git, no key. Release tags exist.
- Original signature: git commits only (10 latest: 9 GitHub-verified, mixed web-flow/author); no release artefact signature found.
- Verdict: ALLOWED-WITH-CONDITIONS for rules whose resolved licence is DRL 1.1 (retain author, URI, DRL notice; keep the `license`, `author`, `reference` meta untouched). BLOCKED for CC BY-NC 4.0 rules in a commercial channel (non-commercial restriction). PENDING-LEGAL for OGL v3, Volexity (licence text not read), BSD/MIT/CC BY rules (attribution mechanics), and any rule with no resolvable licence meta when the repo default is assumed (README says default applies; confirm with legal that the per-file absence is sufficient).
- Condition: the registry must resolve licence per rule, not per repository.

#### 2. Yara-Rules/rules
- URL: https://github.com/Yara-Rules/rules (read 2026-10-22; last push 2024-04-17).
- Provides: community YARA rules by category (malware, cve_rules, exploit_kits, maldocs, packers, webshells ...), index files.
- Licence as stated: GPL-2.0 (LICENSE); README: "Our Yara ruleset is under the GNU-GPLv2 license ... as long as you use it under this license". Sample file header repeats GPLv2.
- Redistribution: GPL-2.0 allows redistribution of originals and modifications under GPL-2.0 with notices and source; copyleft consequences for any combined/derived work. Whether a signed channel bundle combining GPL rules with other-licensed rules is a "derived work" is a legal question.
- Per-item: rules are community contributions (e.g. an APT1 rule credits "AlienVault Labs"); individual authors' terms not verified; upstream appears unmaintained since 2024.
- Original signature: git commits (about half GitHub-verified); none otherwise.
- Verdict: PENDING-LEGAL (copyleft interaction with the channel format and with mixing other licences; stale content).

#### 3. ReversingLabs YARA rules
- URL: https://github.com/reversinglabs/reversinglabs-yara-rules (read 2026-10-22; last push 2025-11-03).
- Provides: `yara/` rule files. Licence: MIT ("Copyright (c) 2020 ReversingLabs"; README "licensed under the MIT License").
- Rights: use/copy/modify/merge/publish/distribute/sublicense/sell; condition: keep the copyright and permission notice in all copies. Per-file headers not scanned.
- Signature: none on commits (0 of 10 verified).
- Verdict: ALLOWED-WITH-CONDITIONS (ship copyright + MIT text; scan per-file headers before first publish).

#### 4. Elastic protections-artifacts
- URL: https://github.com/elastic/protections-artifacts (read 2026-10-22; active).
- Provides: `yara/rules/*.yar`, `behavior/`, `ransomware/`. Licence: Elastic License 2.0 ("you may not use these artifacts except in compliance with the Elastic License 2.0").
- ELv2 key terms (LICENSE.txt): non-exclusive, royalty-free, non-sublicensable, non-transferable licence to use, copy, distribute, make available, prepare derivative works; limitation: "You may not provide the software to third parties as a hosted or managed service, where the service provides users with access to any substantial set of the features or functionality of the software"; must not remove licensing/copyright notices; recipients must get the terms; modified copies need prominent modification notices; no sublicensing.
- Open question: whether a signed rule feed consumed by an endpoint product is a "hosted or managed service providing access to a substantial set of the features" is ambiguous; non-sublicensable also affects downstream relicensing. Not an OSI licence.
- Signature: git commits partially GitHub-verified (mixed).
- Verdict: PENDING-LEGAL. Do not include until legal answers question Q3.

#### 5. ESET malware-ioc
- URL: https://github.com/eset/malware-ioc (read 2026-10-22; active). Licence: BSD-2-Clause ("Copyright (c) 2014-2018 ESET spol. s r.o."). Provides: IOCs, YARA and other rules per malware family.
- Rights: redistribution and use with or without modification; keep copyright notice, conditions and disclaimer (source and binary). Per-directory licence differences not verified.
- Signature: none (0 of 10 commits verified).
- Verdict: ALLOWED-WITH-CONDITIONS (retain BSD notice; per-folder check).

#### 6. VirusTotal/yara-x
- URL: https://github.com/VirusTotal/yara-x. Licence: BSD-3-Clause. This is the YARA-X engine, not a rule feed (rules are a different matter; no VirusTotal community rule set was read). Verdict: ALLOWED-WITH-CONDITIONS for the engine (keep notice; non-endorsement clause). No source of rules identified here.

#### 7. CAPEv2 (kevoreilly/CAPEv2, data/yara)
- URL: https://github.com/kevoreilly/CAPEv2 (read 2026-10-22). LICENSE text: "Cuckoo Sandbox is copyrighted by the Cuckoo Foundation and is licensed under the ... GNU General Public License version 3"; GitHub API reports NOASSERTION. Provides: sandbox plus YARA rules in `data/yara/{CAPE,binaries,macro,memory,monitor,urls}`; sample rule header has only author/description/cape_type meta (no licence meta). signature-base carries some CAPE rules with a pointer to the CAPE LICENSE.
- Verdict: PENDING-LEGAL (GPL-3.0 vs GPL-2.0-only compatibility with other channel content; whether the YARA subtree is covered by the repository licence).
- Signature: git (mixed).

#### 8. Malpedia, others
- Not read. Malpedia rule access normally needs an account; not pursued. Verdict: NOT-VERIFIED. Any other YARA source must pass section 5 before listing.

### 2.2 Sigma

#### 9. SigmaHQ/sigma
- URL: https://github.com/SigmaHQ/sigma, licence repo https://github.com/SigmaHQ/Detection-Rule-License (`LICENSE.Detection.Rules.md`). Read 2026-10-22.
- Provides: YAML rules (`rules`, `rules-emerging-threats`, `rules-threat-hunting`, `rules-compliance`, `rules-dfir`, `deprecated`, `unsupported`), tests, regression data. README: "The content of this repository is released under the Detection Rule License (DRL) 1.1." GitHub reports NOASSERTION (custom text).
- Rights: same DRL 1.1 text as above (permission incl. commercial; conditions: author identification, URI to rule/rule set, DRL notice/text/URI; matches on data must retain author attribution if supplied in the rule). No share-alike, no NC.
- Per-item: rules have `author`, `date`, `references`; some rules may reference third-party content or have own notes; per-rule licence meta not scanned. Repository `LICENSE` file also present.
- Access: public git; no key. Releases are tagged (Releases.md).
- Signature: git commits all 10 recent GitHub-verified (mixed). Release signing not checked.
- Verdict: ALLOWED-WITH-CONDITIONS. Condition: preserve the `author` field and rule `id`, include DRL link/text, and do not modify the rule text without marking it modified in the registry. Note the matching clause: product output (alerts) derived from Sigma matches must carry the author attribution if the product exposes matches.

### 2.3 IOC feeds

#### 10. abuse.ch MalwareBazaar, URLhaus, ThreatFox
- URLs: https://bazaar.abuse.ch/api/, https://bazaar.abuse.ch/export/, https://threatfox.abuse.ch/export/, https://urlhaus.abuse.ch/api/, https://abuse.ch/terms-of-use/ (read 2026-10-22).
- Observed 2026-10-22 (curl GET): `https://bazaar.abuse.ch/export/txt/sha256/recent/` -> 410; `https://urlhaus.abuse.ch/downloads/text/` -> 410; `https://threatfox.abuse.ch/export/json/recent/` -> 410 ("The requested resource is no longer available ... Please remove all references to this resource."). Feodo Tracker `ipblocklist.json` and SSL Blacklist `sslipblacklist.csv` still returned 200 without key.
- Replacement: Auth-Key required. API pages: "you must include the HTTP header `Auth-Key`"; free keys from the abuse.ch Authentication Portal (https://auth.abuse.ch/). Export pages: "In order to access the datasets listed below, you need to obtain an `Auth-Key` first" (MalwareBazaar: CSV, plain text, Daily MISP events, Code Signing Certificate Blocklist, YARA rule statistics; ThreatFox: Suricata ruleset, RPZ, host file, JSON, CSV, MISP daily). MalwareBazaar batches: https://datalake.abuse.ch/malware-bazaar/hourly/ and /daily/ (ZIP password "infected"). IOCs older than six months are excluded from API and exports (ThreatFox page). Rate limits: "a daily limit for file downloads", figures not published; hunting.abuse.ch is a new cross-dataset query site. Not verified: whether datalake batches require a key (not fetched without credential).
- Licence/terms (Terms of Use): CC0 is stated only for Feodo Tracker, SSL Blacklist and YARAify. For MalwareBazaar, URLhaus, ThreatFox: commercial or for-profit use "may require a paid subscription, which will be managed by Spamhaus"; free commercial use only after six months of consistent contribution plus a commercial review; copying, adapting or making "derivative works based on the Platforms" without express consent is prohibited; "AI Training" use requires Spamhaus' express prior written consent; high-volume automated harvesting is prohibited; free access subject to fair use and can be restricted "WITHOUT NOTICE"; terms may change at any time. Redistribution and attribution are not explicitly addressed; mirroring/caching not addressed. Blog (29 Jul 2025): Spamhaus Technology to offer data commercially; contributors keep free access.
- Signature: none (bare data); MISP daily events unsigned.
- Verdict: BLOCKED for redistribution in a MacGuard channel. To unblock: written consent or commercial agreement from abuse.ch/Spamhaus, and an owner decision on holding an Auth-Key (a credential this agent did not request).

#### 11. abuse.ch Feodo Tracker, SSL Blacklist, YARAify
- URLs: https://feodotracker.abuse.ch/downloads/ipblocklist.json (HTTP 200 without key, observed; JSON array with ip_address, port, status, as_number, country, first_seen, last_online, malware), https://feodotracker.abuse.ch/blocklist/, https://sslbl.abuse.ch/blacklist/sslipblacklist.csv (200).
- Licence: Terms of Use: "currently free to use without limitations according to Creative Commons principles (CC0)"; provided "as it is on best effort"; no liability for false positives. Fair use applies. "Currently" implies terms can change; the wording is "Creative Commons principles" rather than an SPDX dedication on the data files themselves (no per-file licence header read).
- Verdict: ALLOWED-WITH-CONDITIONS: store a hash of the ToU text and the retrieval date per release; label each as upstream data with retrieved-at; do not imply endorsement; re-check at each refresh. Legal to confirm the wording suffices as a CC0 dedication (Q5).

#### 12. CISA KEV
- URLs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed `/sites/default/files/feeds/known_exploited_vulnerabilities.json`, CSV, JSON schema); mirror repo https://github.com/cisagov/kev-data (read 2026-10-22).
- Licence: repo README/LICENSE: "The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner but note that information provided at any 3rd party links ... are bound by the policies and licenses of those 3rd party websites." No use of CISA logo/DHS seal or implied endorsement.
- Access: unauthenticated; no key. Signature: none (git commits unverified).
- Verdict: ALLOWED-WITH-CONDITIONS (no CISA logo; no endorsement claim; linked third-party content excluded; verbatim original retained).

#### 13. Other US government data
- NVD and others: see item 25. Verdict: NOT-VERIFIED here.

#### 14. MISP default feeds
- Source: https://github.com/MISP/MISP `app/files/feed-metadata/defaults.json` (108 entries, read 2026-10-22). This is a catalogue of third-party feeds, not a licence grant. Entries include CIRCL OSINT, Botvrij.eu, abuse.ch Feodo, OpenPhish, PhishTank, Emerging Threats compromised IPs, Tor exit lists (dan.me.uk), AlienVault reputation, blocklist.de, CINS, DataPlane, Bambenek (one entry labelled "requires a valid license"), ELLIO, Snort IP block list, and others.
- Rights: each feed has its own terms, many unstated; being listed as a MISP default does not authorise MacGuard to republish. Verdict: PENDING-LEGAL per feed; no blanket decision. Each feed adopted must get its own registry row.

#### 15. CIRCL OSINT feed
- URL: https://www.circl.lu/doc/misp/feed-osint/ (manifest HTTP 200; directory of per-event MISP JSON files). Licence statement on https://www.circl.lu/opendata/: "Unless a repository or dataset states otherwise, the open data described here is licensed under the Creative Commons Attribution 4.0 International licence"; page TLP:CLEAR. That page does not name this feed; the feed-specific statement was not found.
- Per-item: events aggregate third-party OSINT reports (contributed by various orgs); per-event rights unclear.
- Signature: none. Verdict: PENDING-LEGAL (probable CC BY 4.0 with attribution to CIRCL; confirm feed-specific licence and third-party content).

#### 16. OpenPhish
- URLs: https://openphish.com/phishing_feeds.html, https://openphish.com/terms.html (read 2026-10-22). Community feed free, updated every 12 hours (text); premium/platinum on contact.
- Terms: sharing information obtained from the Services with third parties (distribute, transfer) not permitted without written permission; use limited to personal, academic or independent research; no commercial purposes without prior written consent; derivative works not permitted. (Summarised from the general Terms; the community feed page says "By using the Community Feed, you accept the Terms of Use".)
- Verdict: BLOCKED.

#### 17. PhishTank
- URL: https://phishtank.org/developer_info.php (read 2026-10-22). Application key recommended for automated use; without key "limited to a few downloads per day"; Cisco end-user licence agreement linked; no data licence stated; whether registration is open not stated.
- Verdict: NOT-VERIFIED; credential/registration needed and not pursued. Note that MISP lists the `data.phishtank.com` feed URL.

#### 18. Emerging Threats Open
- URL: https://rules.emergingthreats.net/open/suricata/rules/LICENSE (read 2026-10-22; HTTP 200). Text: "This distribution may contain rules under three different licenses": sids 1-3464 and 100000000-100000908 GPLv2; sids 2000000-2799999 BSD (copyright 2003-2026 Emerging Threats; redistribution with notice and disclaimer; no endorsement use of names); sids 2800000-2900000 ET Pro under a separate licence (not for redistribution).
- Scope: Suricata/Snort network rules, not a listed channel; the "compromised-ips.txt" blockrules file used by MISP was not licence-checked.
- Verdict: PENDING-LEGAL (GPL range); BSD range ALLOWED-WITH-CONDITIONS; Pro range excluded.

#### 19. AlienVault OTX
- Observed: `GET https://otx.alienvault.com/api/v1/pulses/subscribed` unauthenticated -> HTTP 403. Terms page rendered only a loading shell; terms not read. Pulses are user-contributed; per-pulse rights unknown.
- Verdict: BLOCKED (account/API key required, none created) and NOT-VERIFIED (terms).

#### 20. Spamhaus DROP
- URLs: https://www.spamhaus.org/blocklists/do-not-route-or-peer/; JSON: `https://www.spamhaus.org/drop/drop_v4.json`, `drop_v6.json`, `asndrop.json` (TXT versions legacy, to be deprecated) (read 2026-10-22).
- Terms (page): available "at no cost, regardless of size or business type"; "credit must be given to Spamhaus Project" when used in a product; keep date and copyright text with the data; automated downloads at least one hour apart (FAQ: not more than once per day - use the conservative one); excess downloads may be blocked. Redistribution not separately addressed. Commercial-focused alternative via Spamhaus Technology.
- Verdict: PENDING-LEGAL (republishing a copy is not addressed; attribution is required). Not signed.

#### 21. blocklist.de
- URL: https://www.blocklist.de/en/export.html (read 2026-10-22). Statement: files "are as they are, and to be used at your own risk"; copyright line only; generated every 30 minutes; no licence, redistribution, commercial or attribution terms on the page; the terms page was not read. Verdict: PENDING-LEGAL (no grant found; absence of terms is not a permission).

### 2.4 ClamAV

#### 22. ClamAV engine
- URL: https://github.com/Cisco-Talos/clamav (read 2026-10-22). README: "ClamAV is licensed for public/open source use under the GNU General Public License, Version 2 (GPLv2)"; bundled components carry other licences (e.g. Yara: Apache 2.0, listed in README). Contributions assign copyright to Cisco (cvdupdate README).
- Verdict: ALLOWED-WITH-CONDITIONS as GPL-2.0 software (source offer, notices; scope of linking to be confirmed by legal if bundled).

#### 23. ClamAV signature databases (main.cvd, daily.cvd, bytecode.cvd)
- URLs: https://database.clamav.net/{main,daily,bytecode}.cvd, https://docs.clamav.net/faq/faq-cvd.html, /faq/faq-freshclam.html, /appendix/CvdPrivateMirror.html, https://github.com/Cisco-Talos/cvdupdate (Apache-2.0) (read 2026-10-22).
- Observed: plain `curl -I` of the three CVD URLs and www.clamav.net/downloads returned HTTP 403 (consistent with the FAQ statement that scripted Wget/Curl use is "explicitly denied"). No workaround attempted.
- Format: CVD container: 512-byte text header (name, build time, version, signature count, functionality level, MD5, digital signature field `dsig`, builder) + tar.gz of signature files; incremental CDIFF patches; CLD uncompressed variant. libclamav (`cvd.c`) parses and verifies the `dsig` field, so the signature is Cisco/Talos's, over the original bytes.
- Licence/terms: no signature-database licence or Talos redistribution terms found in the docs read (FAQ "Signature Database" and freshclam FAQ do not cover licence; www.clamav.net/about states website content under CC BY-NoDerivs and the engine as GPL, and does not mention the databases). The engine's GPL-2.0 does not by itself say what governs the database content. Documented position: FreshClam and cvdupdate are "the two supported download methods"; other methods "may be rate limited, or blocked at our discretion"; shared-hosting IPs are likely rate limited (429); outdated engines limited to 6 checks per day; the "Private Local Mirrors" page describes mirrors for your own network ("each new installation will download a copy ... waste of bandwidth ... for our mirrors network"); manual download is "discouraged". Not stated: any permission or prohibition of a public mirror or republication of CVD files.
- Preserving the signature: a byte-identical CVD (and CDIFFs) retains the upstream `dsig`; MacGuard must not unpack/repack, rename content, or re-sign, and must say the signature is Cisco Talos's, not MacGuard's. A downstream client verifies via ClamAV (`sigtool --info`, freshclam).
- Verdict: PENDING-LEGAL for public redistribution (neither permitted nor forbidden in found text). Private/own-network mirroring is documented. Ask Cisco/Talos in writing (Q6). Until then ClamAV channel content must come from MacGuard-authored signatures or each client's own freshclam.

### 2.5 MITRE ATT&CK

#### 24. MITRE ATT&CK STIX data
- URLs: https://github.com/mitre-attack/attack-stix-data (STIX 2.1 in `enterprise-attack`, `mobile-attack`, `ics-attack`; `index.json`), terms https://attack.mitre.org/resources/terms-of-use/ (page text not parsed; the repository `LICENSE.txt` was read 2026-10-22).
- Licence: "MITRE hereby grants you a non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy." Copyright designation shown: "(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." Disclaimers: no coverage guarantee; AS IS.
- Rights: copies for commercial purposes permitted with notice + licence. Derivative-work wording is not explicit in the lines read. Not an SPDX licence; GitHub reports NOASSERTION.
- Access: public git/GitHub raw; no key. TAXII server not assessed. Signature: git (partial verification); STIX bundles unsigned.
- Verdict: ALLOWED-WITH-CONDITIONS (reproduce copyright designation and licence in every copy; hash the licence text in the registry; legal to confirm derivative handling, Q7).

### 2.6 Vulnerability data

#### 25. NVD / CVE
- URLs: https://nvd.nist.gov/developers/start-here, /general/FAQ-Sections/General-FAQs, /vuln/data-feeds; API `https://services.nvd.nist.gov/rest/json/cves/2.0` (a single unauthenticated request returned HTTP 200 on 2026-10-22).
- The NVD pages are JavaScript-rendered and neither WebFetch nor curl returned their text, so terms, rate limits and required disclaimers could not be verified. Recollection, NOT verified in this session: US-government work, public-domain treatment, request-key tiers (low unauthenticated limits, higher with a free key), a "not endorsed or certified by the NVD" notice, and retirement of legacy JSON feeds. MITRE CVE Program terms of use are a separate document not read.
- Verdict: NOT-VERIFIED. A key is optional for NVD but must not be requested without owner approval.

#### 26. OSV
- URLs: https://google.github.io/osv.dev/data/, https://github.com/google/osv.dev (Apache-2.0 code), bucket https://osv-vulnerabilities.storage.googleapis.com/ (HTTP 200 unauthenticated; `all.zip`, per-ecosystem `all.zip`, per-record JSON), https://github.com/ossf/osv-schema (read 2026-10-22).
- Licence: OSV is an aggregator; each record keeps its source's licence. Docs list: GitHub Advisory DB CC-BY 4.0, PyPI Advisory DB CC-BY 4.0, Go vulndb CC-BY 4.0, RustSec CC0 1.0, Drupal MIT, GSD CC0 1.0, OSS-Fuzz CC-BY 4.0, Rocky BSD, AlmaLinux MIT, Haskell CC0 1.0, R Consortium Apache-2.0, OpenSSF Malicious Packages Apache-2.0, Bitnami Apache-2.0, Ubuntu CC-BY-SA 4.0, opam CC0, Erlang CNA CC-BY 4.0; converted data (Debian, Alpine, NVD-derived) with their own conditions.
- API rate limits/attribution for api.osv.dev: not stated on the pages read -> NOT-VERIFIED for API use; the bucket is the documented bulk path.
- Verdict: ALLOWED-WITH-CONDITIONS per record origin (attribution for CC-BY; keep notices). CC-BY-SA 4.0 (Ubuntu) share-alike and converted NVD/Debian/Alpine data: PENDING-LEGAL.

#### 27. GitHub Advisory Database
- URL: https://github.com/github/advisory-database (read 2026-10-22). Licence: README "licensed under the terms of the CC-BY 4.0 open source license"; LICENSE.md present; GitHub terms section 12 linked. Provides OSV-format advisory JSON.
- Rights: attribution, indicate changes, link the licence. No NC or SA. Signature: none (0 of 10 commits verified).
- Verdict: ALLOWED-WITH-CONDITIONS.

### 2.7 ML model sources (checklist only; no model researched)

For each model or dataset, record and verify before any use: model licence (SPDX or custom text hash, e.g. Apache-2.0, MIT, OpenRAIL, Llama-style community licences, CC BY-NC); whether weights, code and training data are licensed separately; non-commercial and field-of-use restrictions; redistribution of weights and of derivatives or fine-tunes (and naming/attribution obligations); training-data provenance and its terms (note abuse.ch forbids "AI Training" without consent); acceptable-use policy; gated access or click-through acceptance (a blocker for automation); export-control and privacy constraints (no personal or health data); model card claims about evaluation data; signature/hash of weights (safetensors vs pickle) and supply-chain provenance. Verdict: NOT-VERIFIED for all.

## 3. Per-channel summary

| Channel | Could feed today (subject to conditions and legal review) | Blocked or pending |
|---|---|---|
| YARA-X | signature-base DRL-resolved rules; ReversingLabs (MIT); ESET malware-ioc (BSD-2) | signature-base BY-NC rules (BLOCKED); OGL/Volexity rules, Yara-Rules (GPL-2.0), CAPEv2 (GPL), Elastic (ELv2) PENDING-LEGAL; Malpedia NOT-VERIFIED |
| Sigma | SigmaHQ/sigma (DRL 1.1) | none identified (per-rule meta not scanned) |
| IOC | CISA KEV (CC0); abuse.ch Feodo Tracker and SSL Blacklist (CC0 per ToU); signature-base IOC files (DRL, per default); ESET IOCs (BSD-2) | MalwareBazaar/URLhaus/ThreatFox and OpenPhish BLOCKED; OTX and PhishTank need credentials; Spamhaus DROP, blocklist.de, CIRCL OSINT, MISP feeds, ET Open PENDING-LEGAL |
| ClamAV | engine as GPL-2.0 software | CVD redistribution PENDING-LEGAL (no public grant found; 403 to scripted fetch; only freshclam/cvdupdate supported) |
| heuristics | MITRE ATT&CK (technique mapping, with notice); CISA KEV for prioritisation; GHSA/OSV (CC-BY, per record) | NVD NOT-VERIFIED |
| behaviour | Sigma, ATT&CK mapping; Elastic behaviour rules would be ELv2 (PENDING-LEGAL) | CAPEv2 GPL PENDING-LEGAL |
| vulnerabilities | CISA KEV (CC0); CERT-EU advisories (CC BY 4.0, with credit and change notes); GHSA (CC-BY-4.0) | ENISA EUVD and its exploited list PENDING-LEGAL (no terms found); INCIBE-CERT BLOCKED (no derivative or distribution); CCN-CERT NOT-VERIFIED; NVD NOT-VERIFIED; OSV per record origin |
| ML | nothing verified | all NOT-VERIFIED; abuse.ch data cannot be used for AI training without consent |
| sandbox | CAPEv2 as a tool/rules source only after legal review | same as above; sample feeds (MalwareBazaar) BLOCKED |

## 4. Signatures and how originals are preserved without re-signing

| Source | Upstream signature | Preservation approach |
|---|---|---|
| ClamAV CVD/CDIFF | Cisco/Talos digital signature in the CVD header (`dsig`), verified by libclamav | Store/serve byte-identical files; record SHA-256 and `dsig`; never unpack/repack or re-sign; attribute to Cisco Talos. |
| Git repos (signature-base, Sigma, Yara-Rules, Elastic, CAPE, ATT&CK) | Git commits; GitHub "verified" flag is mixed (author keys vs web-flow) | Pin the commit SHA, archive the source tarball at that SHA, record `commit.verification` output and tag; MacGuard's own detached signature covers MacGuard's bundle only and is labelled as such, not as upstream's. |
| ReversingLabs, ESET, GHSA, KEV repos | none observed (0/10 verified) | Pin commit SHA + content hash; no upstream signature to claim. |
| abuse.ch, OpenPhish, Spamhaus, blocklist.de, CIRCL | none | Hash of the retrieved bytes, retrieved-at, licence/ToU hash. |
| MITRE ATT&CK STIX | none (git only) | Pin release tag/commit; keep copyright designation and licence file with the data. |

Rule: MacGuard's signature on a channel manifest asserts only "MacGuard published these bytes with this provenance". It must never be presented as the upstream's signature or endorsement.

## 5. What the source registry must record per source

1. `id` (stable slug) and `kind` (yara, sigma, ioc, cvd, stix, vuln, model).
2. `upstream_url` (canonical page and the fetch URL) and `upstream_ref` (commit SHA, tag, version, or none).
3. `licence`: SPDX id where one exists, else the verbatim text hash (SHA-256 of the stored licence/ToU text); plus `licence_scope` (repository / per-rule / per-file) and the per-rule resolved licence for mixed sources.
4. `retrieved_at` (UTC) and `content_sha256` of the retrieved bytes.
5. `redistribution_status`: ALLOWED-WITH-CONDITIONS / PENDING-LEGAL / BLOCKED / NOT-VERIFIED, plus the structured conditions (attribution, notice preservation, share-alike, non-commercial, no-derivatives, no-AI-training).
6. `attribution_text` (exact string and link to ship) and `notices_to_preserve` (files/headers).
7. `access_method` (git clone, HTTPS GET, API, bucket, freshclam) and `rate_limit_policy` observed or stated.
8. `credential_required` y/n and, if y, the blocker note (no credential held by default).
9. `original_signature_kind` (cvd-dsig, git-commit, none, other) and the verification result recorded.
10. `terms_snapshot` (hash and retrieval date of the ToU text) and `review_by` (re-check date), because terms such as abuse.ch's "currently CC0" can change.
11. `modified` flag and description if MacGuard altered any byte (default: no).
12. `human_approver` and approval date (per the engineering exception policy).

## 6. Owner decisions and legal questions

Owner decisions
- O1. Commercial or non-commercial: is the multi-channel product commercial (paid, ad-supported, or company-run)? This decides BY-NC, OpenPhish, abuse.ch and Spamhaus questions.
- O2. May the project obtain and hold credentials (abuse.ch Auth-Key, NVD key, OTX, PhishTank)? Default recorded here: no.
- O3. Is a contributor-based or paid abuse.ch/Spamhaus arrangement acceptable, or are those feeds dropped?
- O4. Mixed-licence policy: ship only permissive (MIT/BSD/DRL/CC0/CC-BY) content in the default channels and treat copyleft (GPL-2.0/3.0), ELv2 and share-alike content as opt-in separate channels, or exclude it?
- O5. Rule-level filtering: accept dropping signature-base rules whose licence is BY-NC or unresolved.
- O6. Attribution UX: where attribution text and licence texts are shown (client UI, manifest, repository).

Legal questions (not answered here; no legal advice given)
- Q1. DRL 1.1: does the "matches ... must retain author" clause apply to alerts shown in a client UI, and does repackaging rules into a signed bundle count as "modified form"?
- Q2. Does a signed channel bundle that includes GPL-2.0 (Yara-Rules, ET Open SIDs 1-3464) or GPL-3.0 (CAPEv2) rules together with other-licensed rules create a combined/derived work, and what source/notice obligations follow? Is the combination of GPL-2.0-only and GPL-3.0 content permissible?
- Q3. ELv2: is a signed rule feed delivered to a security product a "hosted or managed service" that provides "a substantial set of the features or functionality", and is passing the rules on compatible with the non-sublicensable licence?
- Q4. signature-base: for files with no `license` meta, does the repository-level DRL 1.1 apply as the README states; how should OGL v3, Volexity (text unread) and CC BY / BSD / MIT rule-level licences be handled?
- Q5. abuse.ch: is "free to use without limitations according to Creative Commons principles (CC0)" a sufficient CC0 grant for Feodo Tracker / SSL Blacklist / YARAify redistribution, and does the ToU's general clause barring "derivative works based on the Platforms" conflict with it? For MalwareBazaar/URLhaus/ThreatFox, what consent would allow redistribution of IOCs?
- Q6. Cisco/Talos: is redistribution or public mirroring of main/daily/bytecode.cvd (or CDIFFs) allowed, under what conditions, and is a freshclam-compatible mirror served to third parties covered?
- Q7. MITRE: is the licence wording ("use ... Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license") enough for redistributing STIX data and derived mappings?
- Q8. CC BY-SA 4.0 (OSV/Ubuntu) and CC BY 4.0 (GHSA, CIRCL): attribution and indication-of-changes mechanics for aggregated data and the share-alike scope on a bundled channel.
- Q9. Spamhaus DROP and blocklist.de: is republishing a copy permitted given the attribution/frequency limits and the absence of stated redistribution terms?
- Q10. ML: licence and training-data conditions for any model, including whether data from sources that forbid AI training (abuse.ch) leaks into datasets.
- Q12. ENISA EUVD: which terms govern reuse and redistribution of EUVD records through the public API, does the ENISA CC BY 4.0 policy for publications extend to the database, and how are the third-party records it aggregates (CVE, vendor text, CISA-derived flags) credited?
- Q13. CERT-EU: does "unless otherwise noted" CC BY 4.0 cover the RSS advisory feed, and how are vendor texts quoted inside advisories excluded?
- Q14. INCIBE and CCN-CERT: written authorisation (or an official machine-readable feed with reuse terms) is needed before any adapter or republication; INCIBE's notice prohibits distribution and transformation.
- Q11. Data protection: indicators and rule metadata may include personal data (IPs, URLs, author names); GDPR basis for republication.

## 7. Follow-ups and caveats

- Re-read NVD and OTX terms from a JS-capable browser (read-only) or have the owner supply the terms text; record hashes.
- Scan per-file headers for ReversingLabs, ESET, Elastic, CAPEv2, Yara-Rules and Sigma before any publication (only signature-base was scanned per rule).
- Snapshot all licence/ToU texts (store text and SHA-256) at the time of each approval; many are "currently" worded or subject to change without notice.
- A shallow clone of signature-base used for the per-rule scan was left in an untracked directory `sb/` in the primary working directory by mistake; it is not part of this deliverable and should be removed by the owner or the caller.
