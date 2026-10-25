# Migration trial 0003 / 0004 / 0005 on an isolated copy (2026-10-26)

**Environment**: a temporary Cloudflare D1 database created for the trial (`macguard-quarantine-migration-trial`), loaded from the last verified, age-encrypted backup of the panel database
(`panel/20261025T210624Z`; plaintext SHA-256 matched its manifest). Production (`macguard-quarantine`) was not touched. The temporary database was deleted at the end. Script: `admin/worker/tools/migration_trial.sh`.

| Step | Result |
|---|---|
| Import of the production copy | ok; 9 tables, 10 candidates, 2 decisions, 19 audit entries, 1 session |
| Apply 0003 → 0004 → 0005 with `wrangler d1 execute --file` (the way production would) | all three ok; new tables `policies`, `policy_lifts`, `policy_events`, `audit_anchor`, `source_proposals`, `source_proposal_events`; the five triggers exist |
| Existing rows | counts identical before and after |
| Re-apply of the three files | ok (idempotent) |
| Append-only anchors | an INSERT was accepted, an UPDATE was refused by the trigger |
| Rollback 0005 → 0004 → 0003 | table set equal to the original; counts unchanged |
| Roll forward again | ok |
| Export of the migrated copy, loaded locally | `integrity_check` ok; audit hash chain verified by the Worker's own code: 19 entries, complete |

**Not covered**: the Worker was not run against this copy (the Worker suites run against the schema; `pre-migration.test.js` covers the Worker deployed before the migrations).
A request that needs a table the database does not have yet answers 503 naming the migration, and changes nothing.
