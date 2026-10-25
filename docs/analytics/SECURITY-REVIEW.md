# Security review of the gateway administration model (2026-10-23)

Own review, no outside audit. Evidence is local tests unless marked REMOTE.

| Topic | Finding | Status |
|---|---|---|
| Single administrator + TOTP | One role (platform admin). Key and a TOTP code are required on **every** call; a code is single-use per 30-second step; failures for unknown id, wrong key and wrong code give the same response; unknown ids cost no D1 write. The `admins` table has no role column, so analyst/read-only roles do not exist. | Works as designed; **limitation**: no separation of duties, no second administrator (policy changes that need two approvals cannot be completed with one admin). |
| Tenant/key lifecycle | **Gap closed in this branch**: admin routes now create tenants, issue a scoped key (shown once, `no-store`), revoke, rotate with an overlap window (keeps scopes and actor kind) and suspend; all audited without key material. Before, these were library functions only. | IMPLEMENTED, tested locally; not deployed |
| Machine-to-machine access | Tenant API keys carry scopes and an actor kind (`authenticated_service`, `api_key_client`, `device_identity`). The **administrator** API is human-oriented (TOTP per call): there is no machine credential for automation of admin tasks. | Not needed for launch; owner decision if automation is wanted |
| Tenant isolation | Tenant identity comes only from the verified key; query parameters such as `?tenant=` are ignored on tenant routes; tenant dashboards omit GitHub, CRM and platform alerts; costs allocated to another tenant are invisible. | Tested locally |
| Enumeration | Tenant routes give the same 401 for malformed and unknown keys; administrator failures are indistinguishable; the admin tenant list is behind key + TOTP. An administrator can naturally enumerate tenants. | Tested locally |
| Key rotation | Per-key rotation with overlap exists. Rotating the **peppers** (`KEY_PEPPER`, `ADMIN_PEPPER`, `TOTP_SEAL_KEY`) invalidates all keys/administrators and is documented as a break-glass procedure (`BACKUP-RECOVERY.md`); there is no dual-pepper rolling rotation. | Limitation |
| Audit | Append-only hash chain; verified over the real production rows. Chain integrity does not stop an attacker with D1 write access from re-hashing the chain (no external anchoring of the head). | Limitation: anchor the chain head externally (e.g. in the backups manifest or a signed note) |
| Secrets | Generated locally, kept in the Keychain, uploaded with `wrangler secret put`, never printed; encrypted off-machine backup tool added. The admin credentials were never in the chat. | Done |
| Webhooks / Stripe | Signature, tolerance, dedupe by event id; not configured in production (no Stripe secret). | LOCAL_HTTP_FAKE only; STR-01..10 blocked |
| Telemetry | Counts only; actor = keyed hash; unauthenticated traffic is excluded from commercial KPIs; known test rows are identified (not deleted) via `telemetry_exclusions`. | Tested locally; the migration for the live D1 is pending |
| Defects found and fixed during this review | request bodies were read before the size check (now streamed and bounded); every anonymous admin attempt wrote an audit row; the GitHub collector lost a variation when two syncs ran in the same second; key rotation dropped the actor kind. | Fixed, regression tests added |
