# Restore and recovery center (panel tab "Restauración")

What it is: a tab of `panel.mac-guard.com` (REVIEWER and ADMIN) with the recovery status taken from real records, a step-by-step assistant with the real commands and their expected outputs, and an inventory of the copies. It **executes nothing and receives no private key**: the operator runs the commands on their own machine and pastes the output to be checked; only identifiers (procedure, step, a random run id) reach the audit log.

## Parts
| Part | Where | Notes |
|---|---|---|
| Runbook data (60 steps, 4 procedures, typed parameters) | `admin/worker/src/restore_procedures.js` | served only after sign-in at `GET /api/restore/procedures` (REVIEWER+); not a public asset |
| Safe rendering and checks | `admin/worker/public/restore/engine.js` | no runbook content; placeholders are declared, validated and shell-quoted |
| Status from records | `admin/worker/src/restore.js`, `GET /api/restore/status` | GitHub Actions runs/jobs of `backup.yml`, the trust policy, verifier files, optional `evidence/backups.jsonl`; states VERIFIED, FAILED, STALE, UNKNOWN, NOT_RUN; an unreadable source is UNKNOWN |
| Audited progress | `POST /api/restore/event` | allow-listed events; protected procedures need ADMIN; idempotent; no output, command or secret is stored |
| UI | `admin/worker/public/views/restore.js` | ES/EN, keyboard and screen-reader tested (axe, WCAG 2.2 AA), light/dark, phone/desktop |
| Offline package | `admin/worker/tools/build_recovery_guide.mjs`, `.github/workflows/recovery-guide.yml` | one HTML file with no external resource (CSP pins its script and style), RUNBOOK.md, trust policy, verifier hashes, SHA256SUMS signed with Sigstore keyless |

## Procedures
1. Recover D1 only. 2. Recover the full service (phases A code, B infrastructure, C data, D identities, E validation, F resumption). 3. Recover after a security compromise (declare, contain, preserve evidence, rotate, verify provenance, restore in isolation, inspect, rebuild, reopen in phases). 4. Recovery drill (touches nothing in production).

Order that cannot be broken (tested): verify hashes, signature (Sigstore, or the frozen historical Ed25519), identity and external checkpoint -> authenticity gate -> decrypt -> isolated restore -> snapshot and explicit authorisation -> new D1 -> cutover. A valid signature does not prove clean content: the compromise procedure restores in isolation and inspects before anything is rebuilt.

## What the status can and cannot know
It knows what GitHub Actions records: the last export, signing, copies per provider and read-back. It cannot know the owner's restores, the durable external copy of the checkpoint or the environment secrets: those are UNKNOWN or NOT_RUN until an evidence record exists. A copy that exists in a bucket is `AUTHENTICATED` at best; only a recorded restore makes it `PROVEN`.

## Gaps stated plainly
* The panel's own D1 (`macguard-quarantine`: decisions, audit) is not covered by `backup.yml`; take an export before each deploy (`wrangler d1 export`).
* The evidence file `evidence/backups.jsonl` has a reader but no automatic writer yet; the inventory shows run-level facts and `-` for sequence, hash and transparency index until records exist.
* Destructive steps are only text here. Real restores still need a human at a terminal.
