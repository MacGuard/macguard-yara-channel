# Threat Intelligence Hub: correlation engine (high-assurance contract)

Status: **DESIGN**. Nothing in this document is deployed. It defines the contract that the code and the adversarial tests must meet before any correlation is shown as verified on rules.mac-guard.com.

Guiding rule: **show "relation not verified" rather than publish a false connection.**

## 1. What already exists and is reused (no parallel system)

| Piece | Where | Reused for |
|---|---|---|
| Canonical graph: `intel_entities`, `intel_relationships` (immutable), `intel_relationship_evidence` (append-only), `intel_relationship_assessments` (append-only), `intel_relationship_state` (projection), 17 relationship types | INTEL 0004, `admin/worker/migrations-intel/0004_canonical_graph.sql`, `admin/worker/src/intel_graph.js` (branch `feat/intel-canonical-model` `dff6854`, **not on main**) | entity registry, typed relations, evidence registry, revision history |
| Vulnerability model: weakness, package, `ALIAS_OF`, `VULN_HAS_WEAKNESS`, `RULE_DETECTS_CVE`, `RULE_DETECTS_CVE_BEHAVIOUR`, `INDICATOR_ASSOCIATED_WITH_CVE`, exploitation evidence (KEV), EPSS, severity assessments, version ranges | INTEL 0005 (`feat/r1-canonical` `59f2eae`, unreleased) | vulnerability side of the catalogue |
| Source registry `macguard.intel-sources/1` (licences, APPROVED_PUBLIC / RETAINED) | `config/intel/sources.registry.json` (main) | source admission; nothing from a RETAINED source is published |
| Shared identifier normaliser | `scripts/intel_ids.py` (`feat/hub-search-index`, in progress) | one normaliser for search **and** correlation (today there are five, with no shared test) |
| Assertions extracted from signed YARA rule metadata | `scripts/rule_index.py` (`feat/hub-search-index`, in progress) | first real, verifiable assertions: rule ↔ hash and rule ↔ CVE **mentions** |

**Database.** Cloudflare D1 (SQLite) is enough. These sizes are order-of-magnitude estimates to be confirmed by measurement in C8:

| Data | Approximate size |
|---|---|
| CVE records | ~3×10⁵ |
| KEV entries | ~1.8×10³ |
| YARA rules | ~10⁴ (10 021 declarations in `rules-20261101-41271797671`) |
| Hashes in rule metadata | ~10⁴ (5 314 SHA-256 / 1 882 SHA-1 / 2 739 MD5) |
| Edges | < 10⁷, with typical fan-out < 100 per entity |

- No query needs path traversal beyond one hop. Transitivity is **forbidden** (§3.4), so a graph database adds no capability.
- The constraints that must hold are triggers and CHECKs, which D1 supports.
- If C8 measures read-row budgets above the D1 quota, the answer is precomputed read models (as `intel_vuln_search` already does), not a new store.

## 2. Model (STIX 2.1 conceptual mapping)

| MacGuard (INTEL 0004/0005) | STIX 2.1 | Notes |
|---|---|---|
| `vulnerability` (`vulnerability:cve:CVE-…`) | SDO `vulnerability` + `external_references` (source_name `cve`) | |
| `weakness` | `external_references` (source_name `cwe`) | STIX has no CWE SDO |
| `rule` (`rule:yara:<path>#<name>`) | SDO `indicator` (`pattern_type: yara`) | Identity is **path + name**. A rule name alone is not an id: 10 021 declarations but 8 022 unique names. |
| `sample` (`sample:sha256:<hex>`) | SCO `file.hashes` | |
| `indicator` (ip/domain/url) | SCO `ipv4-addr` / `domain-name` / `url` (+ SDO `indicator` when it is a detection) | |
| `malware_family` | SDO `malware` (`is_family: true`) | |
| `poc_reference` | SDO `vulnerability` `external_references` / custom `x-macguard-poc-reference` | **Metadata only**, never code |
| `source`, `source_version` | SDO `identity` (`created_by_ref`) | |
| relationship + evidence + assessment | SRO `relationship` (`relationship_type`, `created_by_ref`, `confidence`, `revoked`, `external_references`) | |
| assessment `DISPUTED` / `UNKNOWN` | `revoked: true` is **only** for a retraction by the same creator; a contradiction stays visible | |

**Confidence.** The levels are named and are mapped to the STIX 0–100 scale only for export:
- `HIGH` = 85;
- `MEDIUM` = 50;
- `LOW` = 15;
- `NONE` = 0.

The UI always shows the name **and** the method, never a bare number.

## 3. Mandatory rules and how each is enforced

| # | Rule | Enforcement (where) | Test (C6 corpus) |
|---|---|---|---|
| 1 | No LLM as source of truth | `method` enum has no LLM value that can reach `verified`. `origin = 'ai_proposed'` rows can only be `candidate` (CHECK + trigger). | `ai_cannot_verify` |
| 2 | No correlation by text similarity alone | Rule engine predicates operate only on **normalised identifiers** (`intel_ids.normalize`) and source-asserted fields; there is no fuzzy predicate. | `similar_names_not_linked`, `cve_similar_product_not_linked` |
| 3 | Search hits are not relations | The search read model is a separate table and never writes `intel_relationships`. Search results carry `match: exact\|prefix\|partial` and no `relationship_type`. | `search_hit_creates_no_relation` |
| 4 | No automatic transitivity | The API returns one-hop relations only. A path A→B→C is shown as "related via B (not a relation)" and is never materialised. There is no trigger or job that composes edges. | `transitive_false_positive` (rule→hash→CVE must NOT yield rule→CVE) |
| 5 | No alias merge without evidence | `ALIAS_OF` requires evidence whose source states the alias explicitly (CVE record, GHSA aliases, source mapping). Same-name products, MD5/SHA-1/SHA-256 of "the same sample" without a single source record listing all three → no link. | `ambiguous_alias`, `hash_triplet_without_record` |
| 6 | No CVSS for hashes or rules | Severity rows are allowed only for `vulnerability` (CHECK on entity type); a rule or sample sheet shows no CVSS. | `no_cvss_on_rule` |
| 7 | A YARA rule that detects an artefact is not proof that it detects exploitation of a CVE | Two distinct types. `RULE_META_REFERENCES_CVE` (asserted by the rule's own metadata) and `RULE_DETECTS_CVE` / `RULE_DETECTS_CVE_BEHAVIOUR` (critical: need evidence of kind `test_evidence` against an exploitation artefact, or an explicit statement from the rule author/vendor, **plus** independent approval). | `meta_reference_is_not_detection` |
| 8 | No relation published without evidence, provenance and method | Publication view `intel_relationship_public` = state `VERIFIED` or `ASSERTED` + ≥1 evidence row + source `APPROVED_PUBLIC` + method ∈ allowed set. Anything else is invisible to the static build and the anonymous API. | `no_evidence_not_published`, `retained_source_not_published` |
| 9 | Retractions, contradictions and history are kept | Relationships are immutable, evidence and assessments append-only (INTEL 0004 triggers). Retraction = new assessment. Contradiction = two assessments from different sources, displayed as `DISPUTED` with both. | `retraction_kept`, `contradiction_both_visible` |
| 10 | Proposer ≠ approver for critical relations | **New** (INTEL 0007): `intel_relationship_reviews(rel_id, proposer, approver, decision, at)` with CHECK `approver <> proposer`. Trigger: a critical type reaches `VERIFIED` only through an approved review. Approver identities `ai:*` are refused. | `same_actor_cannot_approve`, `ai_cannot_approve` |

**Critical relation types** (rule 10 applies): `RULE_DETECTS_CVE`, `RULE_DETECTS_CVE_BEHAVIOUR`, `INDICATOR_ASSOCIATED_WITH_CVE`, `ALIAS_OF`, any type that links a PoC to a vulnerability as "exploits", and any malware ↔ vulnerability "exploits".

## 4. Verification states (per relationship, current projection)

```
candidate ──(source states it)──▶ asserted ──(independent method + review if critical)──▶ verified
    │                                 │                                                    │
    └──────────────▶ rejected         └──────▶ disputed (contradicting source) ◀───────────┘
                                                        └──▶ retracted (creator withdrew; STIX revoked)
```

The states mean the following:
- **candidate:** proposed by a rule, an analyst or AI. Never public.
- **asserted:** a single approved source states it, and the evidence is that statement (locator + content hash). Public, labelled "according to <source>".
- **verified:** confirmed by a second independent method; for critical types, also approved by another actor.
- **disputed:** sources disagree. Public with all statements shown.
- **retracted:** the creator withdrew it. History stays visible.

**Evidence de-duplication.** Every evidence row carries `original_source_id`. Two feeds that republish the same original (for example KEV copied by an aggregator) count as **one** independent source.

## 5. Deterministic rule engine

A rule is `(id, version, input entity kinds, predicate over normalised fields, output relationship_type, initial state)`. Rules are versioned in the repository and produce the same output for the same snapshot.

First rule set, all **source-asserted**:

| Rule id | Input | Output | Initial state |
|---|---|---|---|
| R-KEV-CWE-1 | KEV entry with a `cwes` field | `VULN_HAS_WEAKNESS` | asserted (CISA KEV) |
| R-YARA-HASH-1 | rule `meta:` value matching a hash (via `intel_ids`), with key ∈ {hash, sha256, md5, sha1, sample, …} | `RULE_META_MENTIONS_SAMPLE` | asserted (rule author, through the signed release) |
| R-YARA-CVE-1 | rule `meta:` / name / reference containing a normalised CVE | `RULE_META_REFERENCES_CVE` | asserted; **never** `RULE_DETECTS_CVE` |

Unknown or malformed values produce **no** relation and an entry in the ingestion report.

## 6. AI (allowed role only)

AI may only do the following, and nothing more:
- extract candidate entities;
- propose relations (`origin = 'ai_proposed'`, state `candidate`);
- search for evidence;
- flag contradictions;
- summarise **verified** relations, with each statement citing a relation id.

It never writes `asserted` or `verified`, and never approves. Rules 1 and 10 enforce this in the database, not only by convention.

## 7. Sheet API contract (`macguard.intel-sheet/1`, extends `contracts/v1/intel-vulnerability.schema.json`)

For each relation the sheet returns:
- `relationship_type`, `from`, `to`;
- `state` (§4) and `confidence` (named);
- `method`, `rule_id` (if engine-made);
- `evidence[]` (`source_id`, `original_source_id`, `locator`, `content_sha256`, `retrieved_at`);
- `assessments[]` (history), `verified_at`, `reviewed_by` (critical only).

Relations are grouped into "verified", "asserted by a source", "disputed" and "hypotheses (not verified)". The last group is shown only to authenticated analysts, never in the public build.

## 8. Validation corpus (C6) and acceptance

The corpus is synthetic, plus real public data under its licence: KEV CC0, plus YARA rules from the signed release under DRL-1.1 / GPL-2.0, used only as identifiers and locators. The required cases are:
- verified relations;
- unrelated entities;
- ambiguous aliases;
- similar or malformed hashes;
- CVEs with similar products;
- generic rules;
- wrong references;
- contradicting sources;
- retracted data;
- duplicate evidence from one original source;
- false transitive paths.

The engine is **not ready** until all of the following hold:
- every row of §3 has a passing adversarial test;
- the corpus shows zero false relations at the `asserted`/`verified` level;
- every published relation in the corpus can be traced to evidence;
- the logic, the triggers and the tests have had an independent Codex review with no BLOCKER/HIGH.

## 9. Task specs (small, ordered)

| Id | Scope | Depends on | Acceptance |
|---|---|---|---|
| C0 | This contract (docs only) | — | owner review |
| C1 | `scripts/intel_ids.py` shared normaliser + adversarial tests | — | in progress on `feat/hub-search-index` |
| C2 | Land INTEL 0004 (+0005) on main in small PRs (T7) | owner GO | migrations tested with rollback; nothing applied remotely |
| C3 | INTEL 0007: reviews table, proposer≠approver CHECK, ai-approver refusal, critical-type trigger, `origin` column, `original_source_id` on evidence, public view | C2 | triggers proven by tests that attempt every forbidden write |
| C4 | Rule engine R-KEV-CWE-1, R-YARA-HASH-1, R-YARA-CVE-1 (deterministic, versioned) | C1, C3, rule_index | same snapshot ⇒ same bytes; malformed values ⇒ no relation |
| C5 | Sheet read model + `macguard.intel-sheet/1` contract tests | C3 | grouping by state; hypotheses never in anonymous output |
| C6 | Adversarial corpus + tests for every §3 row | C3, C4 | zero false relations |
| C7 | Codex independent review of C3–C6 | C6 | 0 BLOCKER/HIGH |
| C8 | D1 sizing measurement (rows, read units per sheet) | C4 | numbers recorded; read models if over quota |

Nothing here is applied to production, published, or used to make an "exploits"/"detects" claim without the gates above.
