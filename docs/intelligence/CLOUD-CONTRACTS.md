# MacGuard Cloud: versioned data contracts (PLANNED)

**Resumen (ES).** Diseño de contratos de datos para una futura «MacGuard Cloud». **Nada de esto existe**: no hay servicio, ni agente, ni esquema publicado; `mgctl agent` y `mgctl cloud` están «planned» y salen con código 4 (`mgctl/tree.py`, `README.md`). Este documento fija 11 contratos JSON Schema (draft 2020-12, ids con `/1`, carpeta `docs/intelligence/schemas/cloud-*.schema.json`) y los requisitos que cualquier implementación futura debe cumplir (aislamiento por tenant, minimización, funcionamiento sin conexión de las herramientas gratuitas, opt-in explícito, sin telemetría por defecto, ingestión idempotente, reglas de compatibilidad, firma de envíos del agente), cada uno con una idea de prueba. Es información de diseño, no una autorización de construir ni de desplegar nada.

Status of everything below: **planned**. Status vocabulary: `planned` (design only), `experimental` (code exists, unproven), `operational` (produced by the pipeline today and tested). Nothing in this document is `operational`.

## 1. What exists today (verified in this repository)

- `bin/mgctl` and `mgctl/`: implemented `version`, `help`, `doctor`, `scan`, `audit file` (experimental), `audit --tui`, `evidence verify`, `intelligence status|update|verify`, `alias`. Planned and exiting 4: `inventory`, `provenance`, `audit system`, `baseline *`, `attest verify`, `report`, `agent`, `cloud` (README.md, section "mgctl, the MacGuard command"; command tree in `mgctl/tree.py`).
- Signed rule channel with keyless Sigstore (`.github/workflows/publish.yml`), Merkle transparency log (`scripts/tlog.py`), independent verifier (`scripts/verify_public_release.py`).
- There is **no** Cloud service, tenant store, agent, enrolment, TSA integration, or telemetry endpoint. The private panel under `admin/worker/` is the rule-quarantine panel of the pipeline; it is not a customer Cloud and must not be reused as one without its own design review.

## 2. Principles

1. Cloud only consumes documents that `mgctl` already produces or will produce locally. Nothing in `mgctl` requires Cloud.
2. Opt-in, off by default, no telemetry by default.
3. Metadata and hashes only; never file contents.
4. Tenant isolation is a property of the data model (every record), of the keys (per tenant) and of the queries (always scoped), not of the UI.
5. Honest states: `skip`, `error`, `not_implemented` and `no_data` are never counted as `pass`.

## 3. Contract catalogue

All files live in `docs/intelligence/schemas/`. `$id` base `https://schemas.macguard.example/cloud/<name>/1` is a placeholder on the reserved `.example` domain: **no schema is published at that URL**. Shared definitions: `cloud-common.schema.json` (tenant_id, ids, SHA-256, UTC datetime, path reference, signature envelope, trusted timestamp, record header).

| Contract | File | Purpose | Status |
|---|---|---|---|
| Organization and tenant | `cloud-tenant.schema.json` | Legal customer and isolation unit; opt-in record; data policy (path mode, retention) | planned |
| Host group | `cloud-host-group.schema.json` | Named set of hosts in one tenant | planned |
| Identity and permission | `cloud-identity-permission.schema.json` | Principals, roles, explicit permission list, scope, expiry | planned |
| File inventory (per file) | `cloud-file-inventory.schema.json` | One record per observed file; hashes and metadata; references `file-provenance.schema.json` | planned |
| Cryptographic baseline | `cloud-crypto-baseline.schema.json` | Sealed, hash-chained expected state with Merkle root | planned |
| Host attestation | `cloud-host-attestation.schema.json` | Signed self-report: versions, intelligence release, self-checks | planned |
| Audit request | `cloud-audit-request.schema.json` | Bounded read-only audit pulled by the agent | planned |
| Audit result | `cloud-audit-result.schema.json` | Per-check outcomes and findings | planned |
| Evidence | `cloud-evidence.schema.json` | Hash of a subject + UTC date + trusted timestamp | planned |
| Fleet consolidated result | `cloud-fleet-result.schema.json` | Tenant roll-up with `no_data` kept separate | planned |
| Agent status and capabilities | `cloud-agent-status.schema.json` | State, declared capabilities (supported / experimental / unsupported) | planned |

`cloud-file-inventory.schema.json` references `file-provenance.schema.json` by relative name only; that file is written by another agent and is not part of this deliverable. Until it exists the reference does not resolve and the inventory schema cannot be fully validated (open question 3).

The schemas parse as JSON. They were **not** checked against the draft 2020-12 metaschema or exercised with sample documents in this session (the `jsonschema` package is not installed here); a CI check is part of the test ideas below.

### 3.1 Cross-cutting fields

Every record carries (via `record_header`): `schema`, `schema_version`, `tenant_id`, `created_utc`, optional `idempotency_key` and `status`. Documents are signed over their RFC 8785 (JCS) canonical form with the `signature` property removed.

## 4. Evidence, UTC date and trusted timestamp

- Every evidence record carries `recorded_utc` (service clock, informational) and `trusted_timestamp` (authoritative).
- **Choice: RFC 3161 Time-Stamp Protocol** as the primary proof of time. Why: (a) open standard verifiable offline with common tools (`openssl ts -verify`); (b) only the SHA-256 of the canonical document is sent to the TSA, so no tenant data leaves; (c) it does not depend on a public append-only log, whereas Sigstore Rekor is public and would expose tenant metadata; (d) the TSA certificate chain can be pinned by the customer.
- **Equivalent alternative:** a Sigstore Rekor signed entry timestamp (`type: rekor-set`) is acceptable only for artefacts that are already public (for example rule releases). The existing channel already relies on Rekor via `cosign verify-blob` (`.github/workflows/publish.yml`, `site.yml`); that is evidence for public artefacts, not a TSA integration.
- The choice of TSA provider, its contract and its availability are undecided (open question 2). Until a TSA is chosen, an implementation must label evidence as `no trusted timestamp`, never fill the field with a local clock value.

## 5. Requirements and test ideas

Each requirement is a **planned** obligation for a future implementation. The test idea says how it would be proved; none of these tests exist.

| # | Requirement | Test idea |
|---|---|---|
| R1 | **Strict tenant isolation.** Every record carries `tenant_id`; storage keys and queries are always prefixed by tenant; no endpoint returns data of another tenant; each tenant has its own keys (path HMAC/encryption key, signing keys for service outputs). | Create tenants A and B with overlapping `host_id` values and identical file hashes. As a principal of A, request every read endpoint with B's ids, expect 403/404 and zero bytes of B. Property test: a query builder refuses to execute without a tenant predicate. Key test: a path hashed under A's key does not match under B's key. |
| R2 | **Data minimisation.** No file contents are accepted or stored. Paths are `hashed` (HMAC-SHA-256, per-tenant key) or `encrypted` (AEAD, per-tenant key) unless the tenant policy explicitly says `clear`. | Schema test: `additionalProperties`/`unevaluatedProperties` reject content-like fields. Ingestion test with a payload containing a `content` field: rejected. Inspect stored rows of a test tenant: no clear paths when `path_mode=hashed`. |
| R3 | **Offline operation of the free tools.** No `mgctl` command requires Cloud; Cloud only consumes documents already produced locally. | Run the `mgctl` test suite (`tests/test_mgctl.py`) in a network-denied sandbox with Cloud environment variables unset; every implemented command behaves as today. Grep test: no import of a Cloud client from the non-agent code paths. |
| R4 | **Explicit opt-in.** Nothing is sent until a recorded opt-in exists (`tenant.opt_in`, `agent.opt_in.enabled`). Revocation stops submission and is honoured on the next cycle. | Fresh install: assert zero network connections to Cloud hosts with a socket-level capture. Enrol, revoke, assert agent stops and queued submissions are discarded or held per policy. |
| R5 | **No telemetry by default.** The contracts have no telemetry field (`data_policy.telemetry` is `const false`). Operational metrics about the agent are the explicit `agent-status` document, sent only under opt-in. This is consistent with the existing pipeline stance: no download telemetry exists (README.md, "Site"). | Fresh install network capture (as R4). Schema test: `data_policy.telemetry: true` is invalid. |
| R6 | **Idempotent ingestion.** Re-sending the same document (same canonical body, same `idempotency_key`) creates no second record and returns the original receipt. | Submit twice, count rows, compare receipts. Submit after a simulated timeout; same result. Concurrent submissions: exactly one row. |
| R7 | **Schema compatibility.** Additive changes (new optional property, new documented enum value consumers must tolerate) keep `/N`. Removing/renaming a property, tightening a type or making an optional property required is breaking and bumps to `/N+1`; the service accepts `/N` and `/N+1` during a published overlap period. | CI job diffing each schema against the previous released one: classify the change, fail on a breaking change without a new id. Fixture documents of version N must still validate against the latest N schema. |
| R8 | **Signature of agent submissions.** Each submission is signed (Ed25519, per-agent key enrolled at opt-in, key id in the envelope) over the JCS canonical body. The service verifies signature, `tenant_id` binding of the key, and freshness (nonce or `created_utc` window) before storing. Revoked keys are rejected. | Tamper one byte: rejected. Valid signature from tenant A's agent with tenant B's `tenant_id`: rejected. Revoked key: rejected. Replay with an old nonce: rejected. |
| R9 | **Least privilege.** Roles are explicit permission lists; no wildcard; agents can only submit audit data. Role changes are critical policy changes approved by a human. | Matrix test: each role against each permission; an agent principal calling `identity.write` is denied. |
| R10 | **Honest outcomes.** `skip`, `error`, `not_implemented` make an audit `incomplete`; hosts without data are `no_data` in fleet results; invariant `pass+fail+incomplete+no_data = hosts_total`. | Property test on the aggregator; fixture where a host skipped every check is never counted as pass. |
| R11 | **Evidence integrity.** Evidence chains (`chain_previous_sha256`) are append-only; the timestamp token verifies against the TSA chain and its imprint equals the subject hash. | Verify a sample token offline with `openssl ts`; break one chain link, expect detection by a verifier. |
| R12 | **No secrets in documents.** Keys, tokens and credentials never appear in any contract; only key ids. | Secret-scanning step over all fixtures and stored sample documents. |

## 6. Mapping to what mgctl could produce (planned)

| Cloud contract | Local source | State of the source today |
|---|---|---|
| file inventory | `mgctl inventory` | planned (exit 4) |
| baseline | `mgctl baseline *` | planned (exit 4) |
| host attestation | `mgctl attest`, `mgctl doctor` fields | `attest verify` planned; `doctor` implemented but is not an attestation |
| audit result | `mgctl audit file` / `audit system` | `audit file` experimental (hash, integrity and YARA run; provenance and vulnerabilities report `not_implemented`); `audit system` planned |
| agent status | `mgctl agent` | planned |
| intelligence release identity | `mgctl intelligence status` | implemented |

## 7. Open points

See the final report of this work item; in short: TSA provider, schema hosting URL, the `file-provenance` schema, key custody for agent keys, and whether `clear` path mode should exist at all.
