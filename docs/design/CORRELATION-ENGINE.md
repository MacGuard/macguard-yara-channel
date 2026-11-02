# Threat Intelligence Hub: correlation engine (high-assurance contract)

Status: **DESIGN v3**, after two independent reviews against the effective schema (§10). Nothing here is deployed.

INTEL 0007 is **not** created until the owner approves this contract. Every mechanism marked **New (0007)** does not exist today. Everything else is cited from the effective schema: branch `feat/correlation-engine` = main + INTEL 0004 (`dff6854`) + 0005 (`feat/r1-canonical`) + `feat/hub-search-index` (#86).

Guiding rule: **show "relation not verified" rather than publish a false connection.**

## 1. Reused pieces (no parallel system)

| Piece | Where (effective schema) | Role |
|---|---|---|
| Entities `intel_entities` | 0004:20-33. Id is `type:namespace:key` (0004:31); key is 1–512 characters (0004:24) | canonical entity registry |
| Relationships `intel_relationships` | 0004:59-78. **Immutable**: UPDATE and DELETE are refused. Endpoint types are checked against `intel_relationship_types` (0004:75) | typed relation catalogue (30 types: 17 in 0004 + 13 in 0005) |
| Evidence `intel_relationship_evidence` | 0004:80-93. **Append-only.** Kinds include `source_statement`, `content_match`, `test_run` | evidence registry |
| Assessments `intel_relationship_assessments` | 0004:95-110. **Append-only.** Confidence {CONFIRMED, REPORTED, INFERRED, DISPUTED, UNKNOWN} × verification {VERIFIED, UNVERIFIED, FAILED}; REPORTED needs `source_statement` **or** `document` evidence (0004:107; `linkGcve0`, intel_vuln.js:78-82, relies on `document`) | revision history |
| State projection `intel_relationship_state` | 0004:113. Direct writes outside the projection triggers are refused (0004:118, 0004:120, 0005:181) | current state |
| ALIAS_OF guards | 0005:38-39: method limited to `asserted_by_source` or `manual`; aliases must cross namespaces | no alias merge without a source |
| `RULE_DETECTS_CVE` needs a `test_run` | 0005:40 | partial critical-type guard |
| Severity only on vulnerabilities | trigger `intel_severity_vuln_only` (0005:77) | rule 6 |
| Source registry `config/intel/sources.registry.json` | JSON only, **not** in the database. Today one source is `APPROVED_PUBLIC`: `cisa-kev` | source admission |
| Normalisers | `scripts/intel_ids.py` (Python, #86) for search and ingestion; `normalizeKey` (`intel_graph.js:57-79`, JS) on the database write path | identifier syntax (two implementations: see A5) |
| `scripts/rule_index.py` (#86) | assertions taken from each signed rule's own `meta:` block, with `match: whole_value \| embedded` | input of the YARA rules (§5) |

**Database.** D1 is sufficient: queries are one hop and the constraints are triggers. Sizes are estimates, measured in C8. A graph database adds nothing because transitivity is forbidden (rule 4).

## 2. Identifiers and STIX 2.1 mapping

| Entity (type:namespace:key) | STIX 2.1 | Notes |
|---|---|---|
| `vulnerability:cve:CVE-…` | SDO `vulnerability` + `external_references` | key is upper case. Both normalisers **must** share one grammar (C3b). Today they differ: JS accepts `CVE-2024-01234` and `CWE-0`, Python rejects them. |
| `weakness:cwe:CWE-n` | `external_references` (cwe) | |
| `rule:yara:<path>#<name>` | SDO `indicator` (`pattern_type: yara`) | `intel_ids` returns `yara:<path>#<name>`; the key is everything after `yara:`. A path is ≤ 400 characters and a name ≤ 128, so a key can reach **529 > 512** (0004:24). **Decision:** a rule whose key exceeds 512 characters is **refused at ingestion** and reported. It is never truncated, and the cap is not raised: raising it would mean rebuilding `intel_entities`, because a CHECK cannot be altered. |
| `sample:sha256:<hex>` | SCO `file.hashes` | MD5/SHA-1 mentions have **no** sample identity. They stay rule assertions with no relation until a source gives a record with the SHA-256 (A12). |
| `malware_family:…`, `indicator:…` | SDO `malware`, SCO/SDO `indicator` | |
| `poc_reference:…` | `external_references` | metadata only |

**Confidence.** The schema vocabulary (CONFIRMED / REPORTED / INFERRED / DISPUTED / UNKNOWN) is the **only** one. The 0–100 STIX value is used only on export:

| Schema value | STIX export |
|---|---|
| CONFIRMED | 85 |
| REPORTED | 50 |
| INFERRED | 15 |
| DISPUTED / UNKNOWN | 0 |

## 3. Normative state mapping (§4 states ↔ schema)

The mapping is **total**. It applies to the latest assessment, and the rules are tried **in this order**; the first that matches wins.

| Order | Latest assessment (+ conditions) | Contract state | Public? |
|---|---|---|---|
| 0 | **New (0007):** lifecycle marker `retracted`, set only by the original source or the proposer. Today a retraction cannot be told from "never assessed" (A2). | retracted | history only |
| 1 | verification FAILED (any confidence) | rejected | never |
| 2 | confidence DISPUTED, or sibling relations that contradict each other (§4.2) | disputed | yes, with every statement shown |
| 3 | CONFIRMED / VERIFIED. For a critical type, also an approved review (New, 0007). | verified | yes |
| 4 | CONFIRMED / UNVERIFIED (the default of `assess()`) **or** REPORTED / any non-FAILED verification, with ≥1 `source_statement` or `document` evidence from an approved source | asserted | yes, labelled "according to <source>" |
| 5 | everything else (UNKNOWN, INFERRED, REPORTED or CONFIRMED without evidence from an approved source, no assessment) | candidate | never |

### 4.1 Mandatory rules: enforcement today vs New (0007)

| # | Rule | Today (proved on a scratch database built from 0001→0005) | New (0007) |
|---|---|---|---|
| 1 | No LLM as source of truth | **Not enforced.** An `ai:llm` source, method `correlated`, reached CONFIRMED/VERIFIED with raw SQL. The `correlated` guard exists only in JS `assess` (`intel_graph.js:125-129`). | Proposer and origin recorded at creation in an append-only side table written in the same batch. VERIFIED only by an approver from an **allow-list of authenticated human admins** (like 0002 `actor_id`), not a deny-list. `correlated` guard as a trigger. |
| 2 | No text-similarity-only correlation | By convention only | Engine rule: identifiers from `intel_ids` only; exact key allow-lists (§5); `embedded` mentions never become asserted |
| 3 | Search hits are not relations | Holds by construction: the search index has no writer to `intel_relationships`. The engine reads **rule_index assertions** (rule-metadata statements), never search results. | — |
| 4 | No automatic transitivity | Holds: 0 triggers write relationships; `neighbours` is one hop (`intel_graph.js:139`) | engine test only |
| 5 | No alias merge without evidence | ALIAS_OF method and cross-namespace guards (0005:38-39). But ALIAS_OF can be inserted with no evidence, and a `correlated` HASH_IDENTIFIES_SAMPLE was accepted. | ALIAS_OF and HASH_IDENTIFIES_SAMPLE need `source_statement` or `document` evidence at creation (`linkGcve0` uses `document`). Method stays `asserted_by_source` or `manual` (0005:38), with this added: a `manual` ALIAS_OF is critical, so it needs an approved review (rule 10). `correlated` is refused. |
| 6 | No CVSS on hashes or rules | **Enforced by trigger** `intel_severity_vuln_only` (0005:77); `intel_epss_latest` also has one (`intel_epss_latest_vuln_only`, 0005:94). `intel_epss_history` has none and allows DELETE. | vuln-only trigger and DELETE guard on `intel_epss_history`; DELETE guards on `intel_epss_latest` and `intel_version_ranges` |
| 7 | A rule that detects an artefact does not detect a CVE's exploitation | Distinct types exist. `RULE_DETECTS_CVE` needs a `test_run` (0005:40); `RULE_DETECTS_CVE_BEHAVIOUR` and `INDICATOR_ASSOCIATED_WITH_CVE` do not. | Extend the `test_run` + review trigger to both. The engine emits only `RULE_ASSOCIATED_WITH_CVE` from metadata. |
| 8 | No publication without evidence, provenance and method | **Not enforced.** A public UNKNOWN relation with zero evidence was accepted. `vulnerabilityRecord` (`intel_vuln.js:171-183`) filters on exposure only. Exposure is fixed at insert because relations are immutable. | View `intel_relationship_public` (state asserted/verified + evidence + approved source). **Every** reader (`vulnerabilityRecord`, `neighbours`, gateway search refresh) uses the view. Optionally refuse `exposure='public'` at insert. |
| 9 | Keep retractions, contradictions and history | Relations immutable; evidence and assessments append-only (enforced). Retraction marker missing. Contradiction detection exists only for ALIAS_OF in JS (`intel_vuln.js:55-75`). | Retraction marker; contradiction view (§4.2) |
| 10 | Proposer ≠ approver for critical relations | **Not enforced**: relationships have no proposer or actor column | `intel_relationship_reviews` with `approver <> proposer`. Proposer comes from the creation side table. The approver must be on the allow-list and equal NEW.actor of the VERIFIED assessment. |

**Critical types:** `RULE_DETECTS_CVE`, `RULE_DETECTS_CVE_BEHAVIOUR`, `INDICATOR_ASSOCIATED_WITH_CVE`, `ALIAS_OF`, and the future "exploits" types. The future types do not exist; adding them is New (0007+).

### 4.2 Contradictions and de-duplication
- **Contradiction.** `source_id` is part of a relationship's identity. Two sources asserting the same (type, from, to) therefore make two sibling relationships. They are in contradiction when their latest assessments disagree (one CONFIRMED or REPORTED, the other DISPUTED or FAILED).
  - Today there is no negative statement ("does not detect"); a source expresses one through a DISPUTED assessment with `source_statement` evidence.
  - **New (0007):** a view that groups siblings and flags disagreement.
- **De-duplication.** **New (0007):**
  - `original_source_id` on evidence, required on new rows;
  - evidence `source_id` NOT NULL;
  - uniqueness on (relationship_id, kind, ref, sha256).
  - Today two identical evidence rows are accepted and counted twice.

## 5. Deterministic rules (engine output uses existing types)

| Rule id | Input | Output type (existing) | Initial state |
|---|---|---|---|
| R-KEV-CWE-1 | KEV entry `cwes` | `VULN_HAS_WEAKNESS` | asserted (`cisa-kev`, `source_statement`) |
| R-YARA-HASH-1 | rule_index `rule_meta_mentions_hash`, match `whole_value`, SHA-256 only, meta key on the allow-list `hash`, `hash<N>`, `sha256`, `sample`, `samples` | `RULE_REFERENCES_SAMPLE` (0004:43) | asserted (rule author, through the signed release) |
| R-YARA-CVE-1 | rule_index `rule_meta_mentions_cve`, match `whole_value`, meta key on the allow-list `cve`, `cves`, `vuln`, `vulnerability`, `reference` (when the value is a whole CVE id) | `RULE_ASSOCIATED_WITH_CVE` (0004:42), **never** `RULE_DETECTS_CVE*` | asserted |

**Meta keys** are matched **case-insensitively** after ASCII lower-casing, as `rule_index` already does (`re.I`). The allow-list is exact on the lower-cased key: `Hash`, `SHA256` and `hash3` match; `hashes_of_sample` and `sha256sum` do not. The original case is kept in the evidence locator.

The rules never produce a relation from any of these:
- an `embedded` mention (a CVE or hash inside free text);
- an MD5 or SHA-1;
- a key over 512 characters;
- a rule name.

Each case goes to the rejection report with a reason. Same snapshot means the same bytes.

**Source of the YARA release.** The registry has no entry for it. **Owner decision:** add `macguard-yara-release` to the registry, with licences DRL-1.1 / GPL-2.0 kept per source collection, approved for metadata-only assertions. Until then rule 8 hides every R-YARA relation.

## 6. AI (restricted)

AI may extract candidate entities, propose relations, search for evidence, flag contradictions, and summarise **verified** relations, citing the relation id.

It never writes REPORTED or CONFIRMED and never approves. Enforcement today: none. **New (0007):** origin and proposer recorded, plus the approver allow-list (rules 1 and 10).

## 7. Sheet API (`macguard.intel-sheet/1`)

For each relation the sheet returns:
- type, from, to;
- contract state (§3) and confidence (schema vocabulary);
- method and rule_id;
- evidence: source_id, original_source_id (New), kind, ref, sha256, observed_at;
- assessment history, verified_at, reviewed_by (critical types only).

Relations are grouped as **verified / asserted / disputed / hypotheses**. Hypotheses go only to authenticated analysts.

**The sheet reads only the public view in anonymous and static builds.**

## 8. Validation corpus and acceptance

The corpus is synthetic, plus public data under its licence: KEV is CC0, and YARA metadata is used as identifiers and locators only. It must cover:
- verified relations;
- unrelated entities;
- ambiguous aliases;
- similar or malformed hashes;
- Unicode digits;
- CVEs with similar products;
- generic rules;
- wrong references (a CVE inside a URL);
- contradicting sources;
- retracted data;
- duplicate evidence from one original source;
- false transitivity.

The engine is **not ready** until all of these hold:
- every row of §4.1 has a passing adversarial test, at the database level for "New (0007)" rows once 0007 exists;
- zero false relations at asserted or verified;
- JS↔Python normaliser parity;
- an independent Codex review of the logic, the triggers and the tests with no BLOCKER/HIGH.

## 9. Task specs

| Id | Scope | Depends on | Acceptance |
|---|---|---|---|
| C0 | This contract | — | **owner approval** (v2) |
| C1 | `intel_ids.py` (#86) | — | done on #86 (`938bf26`, extraordinary Codex review MEDIUM fixed); **not yet** in the base `feat/correlation-engine` (`54af836` has `dad1a56`) |
| C2 | INTEL 0004 + 0005 to main in small PRs | owner GO | migrations and rollback tested; nothing applied remotely |
| C3 | **INTEL 0007**, after C0 approval and only then. Contents: (a) freeze `intel_entity_types` and `intel_relationship_types` (no UPDATE/DELETE); (b) per-namespace key checks for cve, cwe, sha256, yara, plus the key-length decision; (c) creation side table with proposer and origin; (d) human-approver allow-list; (e) `intel_relationship_reviews`; (f) `correlated` guard; (g) critical-type triggers covering `_BEHAVIOUR` and `INDICATOR_*`; (h) `original_source_id`, evidence uniqueness, `source_id` NOT NULL; (i) source approval represented in the database; (j) retraction and lifecycle marker; (k) EPSS and version-range guards; (l) public view and contradiction view | C0, C2 | every forbidden write in §4.1 refused by a test |
| C3b | JS `normalizeKey` `yara` case, plus a JS↔Python parity test with shared vectors | C1 | disagreements (CVE-2024-01234, CWE-0) resolved |
| C4 | Pure engine R-KEV-CWE-1 / R-YARA-HASH-1 / R-YARA-CVE-1 | C1 | in progress (`feat/correlation-engine`, no migrations) |
| C5 | Readers switched to the public view; sheet contract tests | C3 | anonymous output has no hypotheses |
| C6 | Adversarial corpus and tests | C3, C4 | zero false relations |
| C7 | Codex independent review | C6 | 0 BLOCKER/HIGH |
| C8 | D1 sizing measurement | C4 | numbers recorded |

## 10. Review record

The v1 (`1ff0bb3`) was reviewed by an independent reviewer (AgC, 2026-11-02) against scratch databases built from 0001→0005, with forbidden writes attempted. Its amendments and where v2 addresses them:

| Amendment | Addressed in |
|---|---|
| A1: type names that do not exist | §5 uses the existing 0004 types |
| A2: no state mapping | §3 |
| A3: two confidence vocabularies | §2: one vocabulary, export-only mapping |
| A4: rule key 529 > 512 | §2, C3(b) |
| A5: two normalisers | §1, C3b |
| A6: source approval not in the database; no YARA release source | §5, C3(i) |
| A7: no proposer/origin; deny-list approvers; critical-type gaps | rules 1, 7 and 10; C3(c)(d)(f)(g) |
| A8: no evidence de-duplication | §4.2, C3(h) |
| A9: type tables and EPSS guards | C3(a)(k) |
| A10: readers bypass the public view | rule 8, §7, C5 |
| A11: key lists and `embedded` policy not pinned | §5 |
| A12: MD5/SHA-1 sample identity | §2 |
| A13: "New" not marked; wording errors | throughout. The evidence kind is `test_run`; rule 6 is enforced by a trigger, not a CHECK. |

The re-review of v2 (`77c65f3`) asked for edits E1–E8. All eight are applied in v3:
- E1: total, ordered state mapping (§3);
- E2: key over 512 characters refused at ingestion;
- E3: the two normalisers differ today;
- E4: `intel_epss_latest` already has its trigger;
- E5: meta keys matched case-insensitively;
- E6/E7: `source_statement|document`, and `manual` ALIAS_OF kept but reviewed;
- E8: C1 location.
