# Quarantine: decision memory, persistent policy and withdrawal of a published rule (design specification)

Status: finalized with the owner's decisions of section 19 (wired rejections, fail-safe publication, urgent withdrawal and recovery are sections 14-18). **DESIGN ONLY, nothing is implemented, no SQL has been run, nothing was deployed.** Every item marked *(proposal)* is new behaviour that does not exist in the
code today. Everything else cites the code it was read from (`file:line`, at the commit this file is committed on). Placeholders (`<rule>`, `<sha>`, `<tag>`,
`<policy>`, `<admin>`) stand for real values on purpose: this document never names a real quarantined rule, path, hash or reason.

Scope of the design: `admin/worker` (Worker + D1), `scripts/decide.py`, `scripts/dynamic_gate.py` (pass-through only), `scripts/quarantine_client.py`,
`daily.yml` (one argument) and `publish.yml` (one step). The contract of RELEASED in `docs/audit/quarantine-released-evidence-spec.md` is reused, not changed.

---

## 1. What the code does today (verified), and the gaps this design closes

| # | Fact (verified) | Where |
|---|---|---|
| F0 | Review state is one column with a CHECK of five values. Adding a sixth state needs a table rebuild in SQLite, so **no new candidate state is introduced** | `schema.sql:11`, `core.js:2` |
| F1 | A candidate is unique by `(sha256, path)`; an unchanged pair keeps its state, and `REJECTED`/`RELEASED` rows are never re-opened or even updated by the pipeline | `schema.sql:23`, `store.js:44-48` |
| F2 | Approval is keyed by **content hash only**: the Worker sends `{sha256: {state, by, at, reason}}` and `decide.py` looks up `decisions.get(c['sha256'])`. A different SHA-256 therefore finds no decision: it never inherits an approval | `store.js:162-171`, `decide.py:39-45` |
| F3 | A changed file is a new row `PENDING`, with the previous version of the same path linked as `related` ("earlier version of the same file", with its state) and listed in `history`. That is today's *precedent* | `store.js:50-54`, `store.js:91` |
| F4 | A human rejection of any row with the same hash wins over approvals of identical bytes at other paths | `store.js:163-167`, runtime test `test-runtime/runtime.test.mjs:152-161` |
| F5 | The decision map filters `archived_at IS NULL`. **Gap G1:** archiving a rejected candidate would silently drop the rejection | `store.js:166` |
| F6 | `decide()` already returns `new_rejected_hashes` and `dynamic_gate.py` already accepts `--rejected`, but **no workflow passes `--rejected` and nothing persists the list**. Persistence of a rejection therefore rests only on the Worker's decision map. **Gap G2** | `decide.py:37,67`, `dynamic_gate.py:130,138`, `daily.yml:72-77` |
| F7 | If the quarantine service is unreachable `decisions.json` is `{}` (safe default for approvals) but a human rejection is then unknown. A rejected rule that became technically clean (the benchmark-fix scenario) would be published. **Gap G3** | `quarantine_client.py:80-84`, `decide.py:39-41` |
| F8 | `publish.yml` consumes the **artifact of the daily run** and re-verifies classification and dynamic evidence, but never asks the Worker again for decisions. The window between daily and publish includes a human environment approval. **Gap G4** | `publish.yml:67-72,77-93`, `publish.yml:46-49` |
| F9 | The only way to leave `REJECTED` is none: there is no human or pipeline transition out of it | `core.js:16-23`, `core.js:84-88` |
| F10 | A release is evidenced by the Worker itself: `fetchPublication` reads the public release (or the latest when `tag` is null), downloads `manifest.json`, checks the GitHub digest, recomputes `rules_root`. Sigstore signatures are **not** verified by the Worker (they are by `publish.yml` and `site.yml`) | `publication.js:25-54`, `core.js:100-118`, evidence spec "What this does not verify" |
| F11 | `markReleased` is the model for every new write: re-read rows, guarded `UPDATE ... WHERE id AND version AND state`, `SELECT CASE WHEN changes()=1 ... json('not-json')` abort guard, one audit insert with `prev_hash`, retry up to 3 times | `store.js:191-219`, `schema.sql:63` |
| F12 | Releases are immutable by workflow design ("Releases are never edited: a correction is a new release") | `publish.yml:141` |
| F13 | Dependencies: `decide.py` removes, transitively and after approvals, any included file that needs a path not included, adding the **waivable** code `dependency-not-validated`; the panel mirrors it in `dependencyEffect` | `decide.py:49-56`, `core.js:33-77` |

---

## 2. Four separate planes (the core of the contract)

| Plane | Question it answers | Storage | Mutated by | Never mixed with |
|---|---|---|---|---|
| **Review state** | Where is this candidate in human review? | `candidates.state` (5 values, **unchanged**) | humans (`decisions`), pipeline (`pipelineTransition`, `releaseTransition`) | publication or policy |
| **Current publication state** | Does the latest *public, verified* release list this exact `(path, sha256)`? | **derived** at read time from the verified manifest + the policy's baseline/confirmation columns (never a free-hand flag) | only by evidence from `fetchPublication` | review state |
| **Persistent administrative policy** | Is there a valid prohibition on this identity, who set it, why, when, which version? | new table `policies` (mutable *head*, version-guarded) | ADMIN endpoints; the confirmation is written only by evidence | candidates |
| **Decision history** | What was decided, by whom, in what order? | existing `decisions` + `audit`; new append-only `policy_events` | append only (triggers abort UPDATE/DELETE) | everything else |

A published rule keeps `candidates.state = RELEASED` after a confirmed withdrawal. `RELEASED` keeps its documented meaning ("a verified public release listed this exact
content at the time", evidence spec); *"is it still in the current release"* is answered by the publication plane. This avoids lying to history and avoids a new state.

---

## 3. State and transition tables

### 3.1 Review state (existing; one proposed addition)

| From | To | Who | On what evidence | Status |
|---|---|---|---|---|
| `PENDING`,`UNDER_REVIEW` | `APPROVED_PENDING_VALIDATION` | REVIEWER+ (`approve`) | no technical finding, approval can take effect, **and no ACTIVE policy on the candidate** | existing + *(proposal)* policy check |
| `PENDING`,`UNDER_REVIEW`,`APPROVED_PENDING_VALIDATION` | `REJECTED` | REVIEWER+ (`reject`, reason) | human decision | existing |
| `PENDING`,`UNDER_REVIEW`,`APPROVED_PENDING_VALIDATION` | `UNDER_REVIEW`/`PENDING` | REVIEWER+ (`hold`,`review`,`release_review`) | human decision | existing |
| `APPROVED_PENDING_VALIDATION`,`PENDING`,`UNDER_REVIEW` | `RELEASED` | publish workflow (OIDC) | verified manifest lists exact `(path, sha256)` **and no ACTIVE policy matches** | existing + *(proposal)* policy conflict |
| `RELEASED`,`APPROVED_PENDING_VALIDATION` | `PENDING` | pipeline `revalidation_failed` | technical revalidation failed | existing |
| `REJECTED` | `PENDING` | **ADMIN only** (`reopen`, reason mandatory) | explicit lift of a rejection; no ACTIVE policy on it; the next daily run revalidates technically | *(proposal)* |
| `RELEASED` | `PENDING` | **ADMIN only**, as part of lifting a policy (section 3.2) | lift of a prohibition; the next release must list it again to re-earn `RELEASED` | *(proposal)* |

A person still has **no** action that yields `RELEASED` (`core.js:15`, `index.js:48`): `reopen` and policy lift go to `PENDING`, never past the technical gates.

### 3.2 Persistent policy (`policies` row; proposal)

`status` x `withdrawal` (the DB CHECK constraints in section 8 allow only these combinations):

| # | status | withdrawal | Meaning shown in the panel | Entered by | On what evidence |
|---|---|---|---|---|---|
| P0 | (no row) | | not prohibited | | |
| P1 | `ACTIVE` | `REQUESTED` | **Withdrawal pending** (the current public release still lists it) | ADMIN `POST /api/policies/withdrawals` | candidate is `RELEASED`, and the Worker itself read the latest public release and found the exact `(path, sha256)` in its verified manifest (the *baseline*) |
| P2 | `ACTIVE` | `CONFIRMED` | **Withdrawn** (confirmed in `<tag>`) | publish callback or ADMIN reconcile; **never a person's word** | a verified public release `R`, `R.published_at` strictly newer than the baseline's, whose manifest (`rules_root` recomputed) does **not** list the scope |
| P3 | `LIFTED` | `CANCELLED` | block lifted before it took effect | ADMIN `POST /api/policies/{id}/lift` from P1 | reason mandatory; candidate `RELEASED -> PENDING`; revalidation by the next run |
| P4 | `LIFTED` | `CONFIRMED` | block lifted after the withdrawal | ADMIN `lift` from P2 | same |

`LIFTED` is final (trigger): a new prohibition is a new row. There is no transition P2 -> P1, nor P3/P4 -> anything.

### 3.3 Publication state (derived, not stored)

| Derived value | Rule |
|---|---|
| `published` | candidate `RELEASED`, no policy |
| `withdrawal_pending` | policy P1 |
| `withdrawn` | policy P2 (evidence: `confirmed_tag`, `confirmed_manifest_sha256`, `confirmed_rules_root`) |
| `listed_despite_policy` | a verified release published after the policy's baseline lists the scope while the policy is ACTIVE; recorded as a conflict in the audit entry (same idea as `published_despite_rejection`, `core.js:122`) |

### 3.4 Who may do what (summary)

| Action | VIEWER | REVIEWER | ADMIN | publish.yml (OIDC) | daily.yml (OIDC) |
|---|---|---|---|---|---|
| read candidates/policies | yes | yes | yes | policies via `GET /api/pipeline/decisions` | same |
| approve/reject/hold/review | no | yes | yes | no | no |
| `reopen` a rejection | no | no | **yes** | no | no |
| request withdrawal | no | no | **yes** | no | no |
| lift a policy | no | no | **yes** | no | no |
| confirm a withdrawal | no | no | only through `reconcile` (Worker-fetched evidence) | **yes** (callback) | no (403) |

---

## 4. Requirements traceability (all twelve)

| # | Requirement | Mechanism | Evidence in code / test to add |
|---|---|---|---|
| 1 | rejection of identical SHA-256 persists | unchanged: `REJECTED` row + `decisionsMap` by sha, the rejection wins over approvals. Gaps G1/G2/G3 closed by 6.3, 7.1 and 5.4 | F1, F4, F5; tests S-04, S-05, PY-06 |
| 2 | an administratively blocked rule does not reappear while a valid prohibition exists | `blocked-by-policy` (severity `block`, not in `WAIVABLE`) is applied in `decide.py` before approvals can act; also checked again in `publish.yml` | section 5; tests PY-01..PY-05, W-12 |
| 3 | a different SHA does not inherit approval; precedent only shown | unchanged keying by sha (F2) + new row `PENDING` with `related` (F3). The policy scope `content` never matches another sha; scope `path` *blocks* the new version instead of approving it | tests S-01, PY-07 |
| 4 | each persistent policy records source identity, path, scope, author, reason, date, version | `policies` columns `source`, `path`, `scope`, `scope_key`, `sha256`, `author`, `author_id`, `author_role`, `reason`, `created_at`, `version`; identity frozen by trigger. For rejections the same facts already exist in `candidates` + `decisions` (source, path, sha256, actor, reason, at, candidate_version) | section 8 |
| 5 | "request withdrawal" ADMIN only, reason mandatory | `POST /api/policies/withdrawals` -> `atLeast(role,'ADMIN')`, reason 5-2000 visible chars (same rule as `core.js:139`), DB CHECK on `author_role='ADMIN'` and `length(trim(reason))>=5` | N-01..N-06 |
| 6 | withdrawal excludes the rule from the NEXT technically validated release | `decide.py` forces the file out of `approved` (section 5); the release only exists if `publishable` (`decide.py:86`) | PY-01, PY-10 |
| 7 | while the release still contains it, "withdrawal pending" | P1 is displayed until P2 | S-10, UI test |
| 8 | CONFIRMED only after verifying the new release's signed manifest | confirmation reuses `fetchPublication` + `verifyManifest`; DB CHECK forbids `CONFIRMED` without tag, published_at, manifest sha, rules_root | W-05..W-09, M-04 |
| 9 | historical releases never modified or deleted | no code path writes to releases or `release_tag` history; the Worker has no GitHub write permission (`publication.js:27-29` only GETs); `release_tag` of other candidates is untouched | W-14 |
| 10 | idempotency, concurrency, append-only audit | section 9 | I-*, C-* |
| 11 | no bypass of technical tests | a policy can only **remove** files; no policy, approval or lift adds a file or skips a check (section 5.5) | PY-11 |
| 12 | explicit audited ADMIN path to lift a block, with technical revalidation | `reopen` (rejections) and `lift` (policies); both only reach `PENDING` | S-12, S-13, PY-08 |

---

## 5. How `scripts/decide.py` consumes the policy

### 5.1 Input *(proposal)*

New optional argument `policies` of `decide()` (default `None`: behaviour **byte-identical** to today, which keeps every existing test valid). Shape, produced by the
Worker, ACTIVE policies only, no reasons:

```json
{ "schema": 1, "available": true, "policy_set_sha256": "<digest>", "policies": [
  { "id": "<policy>", "version": 1, "scope": "path", "source": "<source>", "path": "<rule>", "sha256": "<sha>", "withdrawal": "REQUESTED", "created_at": "<iso>" } ] }
```

Matching (deterministic): a classified file `c` matches a policy `p` when `p.scope == 'content' and p.sha256 == c['sha256']` or
`p.scope == 'path' and p.source == c['source'] and p.path == c['path']`. If several match, the lowest `id` is cited. `c['source']` exists (used at `decide.py:66`).

### 5.2 Exact change, and what stays unchanged

Inserted in the per-file loop **after** the `previously_rejected` check (`decide.py:37-38`) and **before** the reviewer decision lookup (`decide.py:39`):

```python
hit = policy_for(c, active_policies)                                     # None when policies is None/empty
if hit and state in (VALIDATED, QUARANTINED):                            # a REJECTED/DEPRECATED file is not resurrected
    reasons.append({'code': 'blocked-by-policy', 'severity': 'block', 'detail': f"administrative prohibition {hit['id']} v{hit['version']}"})
    state = QUARANTINED
```

* Severity `block` is in the blocking set of the approval branch (`decide.py:43`), so `d.state in APPROVING` can never waive it, even if the candidate was approved earlier.
  The code is **not** in `WAIVABLE` (`decide.py:16` / `core.js:27`); the parity test `service.test.js:620-623` stays valid. No new waivable code.
* The file goes to `excluded` with state `QUARANTINED` (not `REJECTED`) on purpose: `decide.py:65-66` then **submits** it, so a new version of a withdrawn path appears in the panel
  as a `PENDING` candidate with a visible, non-approvable reason instead of vanishing. The Worker already refuses to approve a blocking reason (`store.js:125`).
* Unchanged: static classification, `generic`/benign corpus, `dyn_bad`, `previously_rejected`, reviewer rejection, the waiver logic, the dynamic requirements
  (`set_root` match, verdict, canaries, `decide.py:81-85`), the anomaly guard (`decide.py:76-80`), accounting invariants (`decide.py:87-95`; state `QUARANTINED` is already counted).
* `new_rejected_hashes` (`decide.py:67`) is not affected (the file is not `REJECTED`).
* `previously_published_failing` (`decide.py:58-61`): entries whose cause is `blocked-by-policy` go to a new private list `res['withdrawn']` (`path`, `was`, `policy_id`) instead, so a
  withdrawal is not reported as "failing". The public figure `previously_published_failing` is not incremented by it. Nothing new is published about policies (the public stats keep
  counting the file under `quarantined`).
* New private outputs in `decision.json`: `policy_applied` (policy id, version, path, sha256) and `policy_set_sha256` (copied from the input), so a run records which prohibitions it saw.

### 5.3 Effect on the dependency closure

The existing loop (`decide.py:49-56`) already does the right thing once the policy-blocked file is out of `included`: every included file whose `depends_on` names a missing path is
moved to `QUARANTINED` with the waivable `dependency-not-validated`, repeatedly (transitive). So:

* dependents of a withdrawn rule **leave the next release too** (they appear in `changes.removed`), and are submitted to the panel with `reasons=['dependency-not-validated']`
  and their `depends_on`; they need no approval of their own (`core.js:34`) and **return automatically** once the prohibition is lifted and the rule revalidates;
* a rule the withdrawn rule *needs* is untouched;
* the withdrawal request therefore **previews the collateral** (6.1) and requires `confirm_collateral == N`, the same pattern as `confirm_count` (`core.js:140`);
* the panel needs the same view: `dependencyRows` (`store.js:74-76`) is extended with the active policies and `permanentlyBlocked` (`core.js:35`) treats a policy-matched row as blocked,
  so `dependencyEffect` reports `ineffective` / `blocked_by` for approvals that need a withdrawn rule (existing 409 `dependency_blocked`, `store.js:127-130`). `tests/test_dependency_parity.py`
  is extended so the Python and JS closures agree on policy-blocked inputs.

### 5.4 Unavailable or unsupported policy service (fail safe; owner decision 8)

Replaced by section 15: `decide()` receives `policy_mode` (`normal`, `snapshot`, `unknown`). In `unknown` mode the set is not publishable if it contains any `added` or `modified` file; removals-only is allowed
(blocker added next to the other blockers at `decide.py:72-80`). Default `policy_mode='normal'` keeps every existing call unchanged.

### 5.5 What a withdrawal can never do (requirement 11)

A policy only moves a file from `approved` to `excluded`. No policy, approval, reopen or lift adds a file to `approved` or alters a check. A lifted file re-enters through the same loop,
needs `state == VALIDATED` after all static and dynamic gates, and the release still needs `publishable`, `set_root` equal to the dynamic evidence and the engine canaries. A human can
therefore delay or remove a rule, never publish one that fails. If a removal-only set is not publishable (dynamic failure, anomaly guard `max_removed_fraction` when many rules go at once,
`decide.py:76-80`) the withdrawal stays *pending*: there is no emergency path around the gates (section 16).

### 5.6 Plumbing *(proposal)*

* `GET /api/pipeline/decisions` adds `policy_schema: 1`, `policies`, `policy_set_sha256` next to `decisions` and `retest` (`index.js:32`). An older client ignores them.
* `quarantine_client.py decisions` also writes `dist/policies.json` (`quarantine_client.py:80-84`); a new subcommand `policy-check --candidate dist/candidate.json` exits non-zero
  (the one deliberate exception to "always exits 0") when any file of the final set matches an ACTIVE policy, or when the service is unreachable.
* `dynamic_gate.py` gets `--policies` and passes `policies=` to `decide.decide` in `decide_now` (`dynamic_gate.py:77-78,129-138`); `daily.yml` adds `--policies dist/policies.json` to the gate step (`daily.yml:72-77`).
* `publish.yml` adds a step **before** "Write and sign the manifest" (`publish.yml:106`): `python3 scripts/quarantine_client.py policy-check --candidate dist/candidate.json`. This closes G4 up to the
  seconds between that step and `gh release edit --draft=false` (`publish.yml:150`); what remains is covered by "pending" semantics (section 10).

---

## 6. API *(all proposals; existing routes unchanged except where stated)*

All `/api/*` routes below inherit session, role refresh on unsafe methods, same-origin and CSRF checks (`index.js:82-92`) and the generic 500 that claims nothing (`index.js:158-162`).

### 6.1 `POST /api/policies/withdrawals` (ADMIN)

Request: `{ candidate_id, scope: "path"|"content", reason, request_id, expect_version, confirm_collateral }`.
Validation mirrors `validateDecisionRequest`: ADMIN (403 otherwise), reason 5-2000 visible chars, `request_id` 16-80 url-safe, integer `expect_version`, `scope` explicit (no silent default
in the API; the UI preselects `path`, Open Decision 1, 19.2), `confirm_collateral` integer equal to the computed collateral count.

Server steps (all before any write): replay by `policies.request_id` (same candidate -> 200 `replay:true`; other -> 409) -> candidate exists, not archived, `state = RELEASED`, `version == expect_version`
-> **the Worker reads the latest public release itself** (`fetchPublication(env, deps, null)`) and requires its verified manifest to list the candidate's exact `(path, sha256)`
(else 409 `not_in_current_release`: nothing to withdraw; use `reject`); GitHub unreachable -> 502 `nothing was changed` -> compute collateral (reverse dependency closure over rows that are in the release).
Response 200: `{ policy: {...}, collateral: [{id, path}], baseline: {tag, published_at, manifest_sha256, rules_root} }`. Errors 400/403/404/409/502 never change anything.

`GET /api/policies/preview?candidate_id=...&scope=...` (ADMIN) returns the collateral list without writing, so the UI can show it before the confirmation.

### 6.2 `POST /api/policies/{id}/lift` (ADMIN)

Request: `{ reason, request_id, expect_version }` (reason 5-2000 visible chars). 409 if the policy is not `ACTIVE` or its version moved. Effect: policy `LIFTED` (`withdrawal`: `REQUESTED -> CANCELLED`, `CONFIRMED` stays),
candidate `RELEASED -> PENDING` with a `decisions` row (`action='lift_policy'`) when it is `RELEASED`, one `policy_events` row, one audit entry. Nothing is published by this call; the next daily run decides.

### 6.3 `POST /api/decisions` with `action:"reopen"` (ADMIN; extends `core.js:16-23,128-143`)

`HUMAN.reopen = { from: ['REJECTED'], to: 'PENDING' }`; reason mandatory (add to the list at `core.js:139`); ADMIN required (the role check at `core.js:130` is REVIEWER for the other actions);
refused with 409 `blocked_by_policy` when an ACTIVE policy covers the candidate (lift the policy first). Response lists `still_rejected_same_content`: other rows with the same sha that remain `REJECTED`
and keep the block (F4), so an admin never believes content is unblocked when it is not.
Also *(proposal, closes G1)*: `decisionsMap` stops filtering `archived_at IS NULL` for `REJECTED` rows (`store.js:166`); archived `REJECTED` rows are not in production per the repo evidence (the four
archived acceptance rows were `UNDER_REVIEW`/`PENDING` at export, `docs/audit/evidence/quarantine-acceptance-synthetic-2026-10-20.json`), so this changes no current output.

### 6.4 `POST /api/publication/reconcile` (ADMIN)

Fallback when the publish callback was lost (`publish.yml:151-153` runs only `if: success()`): the Worker reads the latest public release by itself and applies exactly the same two functions
as the callback (`markReleased`, `reconcilePolicies`) with `trigger:"reconcile"` and `role:"ADMIN"` in the audit. The caller supplies no tag and no hash. Bounded by the existing fetch timeouts (`publication.js:7-18`).

### 6.5 Extended existing routes

* `POST /api/pipeline/released` (`index.js:45-54`): after `markReleased`, call `reconcilePolicies(db, pub, ctx, actor, now)`. `markReleased` also treats a candidate that matches an ACTIVE `content`/`path` policy as a
  conflict `published_despite_policy` (not moved), as it does for `REJECTED` (`core.js:122`, `store.js:201`). Only `publish.yml` may call it (`index.js:48`, unchanged).
* `GET /api/candidates/{id}` (`store.js:83-93`): adds `policy` (current row + `policy_events`), `publication` (derived value, 3.3) and keeps `related`/`history` as the **precedent** block, labelled
  "precedent, not an approval" in the UI (i18n es/en keys required by `i18n.test.js`).
* `GET /api/stats` / `/public/stats`: `released_after_review` (`store.js:100`, `core.js:190`) excludes candidates with a `CONFIRMED` policy so the public counter does not claim a withdrawn rule is released (Open Decision 5, 19.2).

---

## 7. `reconcilePolicies` (confirmation) *(proposal)*

Inputs: `pub` from `fetchPublication` (never from the request), as in `markReleased` (`store.js:191`). For each policy `ACTIVE` with `withdrawal='REQUESTED'`:

1. eligible only if `pub.release.published_at` is **strictly later** than `baseline_published_at` and `pub.tag != baseline_tag` (both are GitHub timestamps, so the Worker's clock plays no part);
2. scope check on the verified manifest: `content` -> no manifest entry has `sha256 == policy.sha256`; `path` -> no manifest entry at `source/path` at all (any hash). (The manifest paths are release paths; the mapping from
   `source`+`path` to manifest path is the one `markReleased` already uses, `pub.files.get(r.path)`, `store.js:197`.)
3. if absent: guarded `UPDATE policies SET withdrawal='CONFIRMED', confirmed_* = ..., version=version+1, updated_at=? WHERE id=? AND version=? AND status='ACTIVE' AND withdrawal='REQUESTED'`, followed by the
   `SELECT CASE WHEN changes()=1 ...` guard and a `policy_events` row; if present: no change, listed in the audit entry as `still_listed` (this is the "pending" outcome);
4. for **every** ACTIVE policy (any `withdrawal`), a release published after the baseline that lists the scope is recorded in the same audit entry as a `conflict` (`published_despite_policy` /
   `listed_after_request`), and the policy is left as it is;
5. one audit entry `policy.reconciled`, written in the same `db.batch` as the updates (same retry loop as `store.js:203-218`). `always` semantics as in `markReleased`: a retry with nothing to change records `receipt:"idempotent_retry"`.

What this does not prove: that the release was *built because of* the policy (it proves the rule is absent from a verified public release newer than the request). Optional hardening in Open Decision 6.

---

## 8. Migration 0003 (text only; **not run, not to be run by this task**)

Style follows `migrations/0002_member_identity.sql` / `0002_rollback.sql`: additive, idempotent (`IF NOT EXISTS`), no `BEGIN`, triggers on one line (the test splitter and `wrangler` split at `;` + newline,
`test-runtime/runtime.test.mjs:56`), and `schema.sql` receives the same statements so a fresh database equals a migrated one. **No `ALTER`, `INSERT`, `UPDATE` or `DELETE` on any existing table.**

File `admin/worker/migrations/0003_policies.sql`:

```sql
-- 0003: persistent administrative policy (withdrawal of a published rule) and its append-only history.
-- Additive only: two new tables, their indexes and triggers. No existing table or row is touched; the previous Worker version ignores them.
-- Apply once:  wrangler d1 execute <db> --remote --file migrations/0003_policies.sql
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('path','content')),
  scope_key TEXT NOT NULL,
  source TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  candidate_id TEXT NOT NULL,
  author TEXT NOT NULL,
  author_id INTEGER NOT NULL,
  author_role TEXT NOT NULL CHECK (author_role = 'ADMIN'),
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5),
  created_at TEXT NOT NULL,
  request_id TEXT NOT NULL UNIQUE,
  baseline_tag TEXT NOT NULL,
  baseline_published_at TEXT NOT NULL,
  baseline_manifest_sha256 TEXT NOT NULL,
  baseline_rules_root TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','LIFTED')),
  withdrawal TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (withdrawal IN ('REQUESTED','CONFIRMED','CANCELLED')),
  version INTEGER NOT NULL DEFAULT 1,
  confirmed_tag TEXT,
  confirmed_published_at TEXT,
  confirmed_manifest_sha256 TEXT,
  confirmed_rules_root TEXT,
  confirmed_at TEXT,
  lifted_by TEXT,
  lifted_by_id INTEGER,
  lifted_reason TEXT,
  lifted_at TEXT,
  updated_at TEXT NOT NULL,
  CHECK (scope_key = CASE scope WHEN 'content' THEN 'content:' || sha256 ELSE 'path:' || source || ':' || path END),
  CHECK (withdrawal != 'CONFIRMED' OR (confirmed_tag IS NOT NULL AND confirmed_published_at IS NOT NULL AND confirmed_manifest_sha256 IS NOT NULL AND confirmed_rules_root IS NOT NULL AND confirmed_at IS NOT NULL)),
  CHECK (status != 'LIFTED' OR (lifted_by IS NOT NULL AND lifted_by_id IS NOT NULL AND lifted_reason IS NOT NULL AND length(trim(lifted_reason)) >= 5 AND lifted_at IS NOT NULL)),
  CHECK (status = 'LIFTED' OR withdrawal IN ('REQUESTED','CONFIRMED')),
  CHECK (withdrawal != 'CANCELLED' OR status = 'LIFTED')
);
CREATE UNIQUE INDEX IF NOT EXISTS policies_active_key ON policies (scope_key) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS policies_candidate ON policies (candidate_id);
CREATE INDEX IF NOT EXISTS policies_status ON policies (status, withdrawal);
CREATE TABLE IF NOT EXISTS policy_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('WITHDRAWAL_REQUESTED','WITHDRAWAL_CONFIRMED','LIFTED')),
  actor TEXT NOT NULL,
  actor_id INTEGER,
  role TEXT NOT NULL,
  reason TEXT NOT NULL,
  release_tag TEXT,
  evidence TEXT NOT NULL DEFAULT '{}',
  request_id TEXT NOT NULL,
  at TEXT NOT NULL,
  UNIQUE (policy_id, policy_version),
  UNIQUE (policy_id, event, request_id)
);
CREATE INDEX IF NOT EXISTS policy_events_policy ON policy_events (policy_id);
CREATE TRIGGER IF NOT EXISTS policy_events_no_update BEFORE UPDATE ON policy_events BEGIN SELECT RAISE(ABORT, 'policy events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS policy_events_no_delete BEFORE DELETE ON policy_events BEGIN SELECT RAISE(ABORT, 'policy events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS policies_no_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT, 'policies are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS policies_identity_frozen BEFORE UPDATE OF id, scope, scope_key, source, path, sha256, candidate_id, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root ON policies BEGIN SELECT RAISE(ABORT, 'policy identity and provenance are immutable'); END;
CREATE TRIGGER IF NOT EXISTS policies_version_step BEFORE UPDATE ON policies WHEN NEW.version != OLD.version + 1 BEGIN SELECT RAISE(ABORT, 'policy version must increase by exactly one'); END;
CREATE TRIGGER IF NOT EXISTS policies_lifted_is_final BEFORE UPDATE ON policies WHEN OLD.status = 'LIFTED' BEGIN SELECT RAISE(ABORT, 'a lifted policy is final'); END;
CREATE TRIGGER IF NOT EXISTS policies_withdrawal_forward BEFORE UPDATE ON policies WHEN NEW.withdrawal != OLD.withdrawal AND NOT (OLD.withdrawal = 'REQUESTED' AND NEW.withdrawal IN ('CONFIRMED','CANCELLED')) BEGIN SELECT RAISE(ABORT, 'withdrawal only moves forward'); END;
```

Read-only checks that go with it (also text): before `SELECT COUNT(*) FROM candidates; SELECT COUNT(*) FROM decisions; SELECT COUNT(*) AS n, MAX(seq) AS head FROM audit;`, after the same three, and
`SELECT name FROM sqlite_master WHERE name LIKE 'polic%' ORDER BY name;` (expect 2 tables, 4 indexes incl. autoindexes, 6 triggers).

### 8.1 What the existing 10 candidates and 1 decision look like afterwards

*(Counts are the owner's brief; this task cannot and did not query D1. The repo's own evidence file shows one `hold` decision among four since-archived acceptance rows.)*

Proof that no data change is needed, in three independent layers:

1. **Static:** the migration contains only `CREATE TABLE/INDEX/TRIGGER IF NOT EXISTS` on the names `policies`, `policy_events` and their indexes/triggers. No statement names `candidates`, `decisions`,
   `audit`, `members`, `blobs`, `sessions`, `metrics` or `pipeline_runs`. Test M-01 asserts this by parsing the file: every statement must match `^CREATE (UNIQUE )?(TABLE|INDEX|TRIGGER) IF NOT EXISTS (policies|policy_events)` and
   no other table name may appear outside those statements. The new triggers fire only `ON policies` / `ON policy_events`; the existing triggers (`schema.sql:72-75`) are untouched.
2. **Behavioural:** with an empty `policies` table the derived read model is the identity: `policies: []`, `policy_set_sha256 = sha256(canonical([]))`, `decide(policies=[])` equals `decide(policies=None)`
   field by field (PY-02), `GET /api/pipeline/decisions` returns the same `decisions` and `retest` as before (S-14), `/public/stats` unchanged (the `CONFIRMED` exclusion matches zero rows).
3. **Mechanical:** test M-02 builds the v1 schema, applies 0002, seeds 10 candidates and 1 decision with their audit chain, records `COUNT(*)`, a row checksum of each table and `verifyChain`, applies 0003,
   and asserts all are identical; M-03 applies 0003 twice (idempotent); M-04 inserts rows violating each CHECK and each trigger and asserts the abort.

Operationally the 10 candidates keep their states and versions; `RELEASED` ones become *withdrawable* by an ADMIN (a new action, no data), and a `REJECTED` one becomes *reopenable* by an ADMIN. Nothing else changes until someone acts.
Deployment order: migration -> Worker (reads `policies`) -> `quarantine_client.py`/`decide.py`/`dynamic_gate.py` + `daily.yml`/`publish.yml`. The previous Worker works against the migrated schema (it ignores both tables). A new client against an
old Worker sees no `policy_schema` and goes to `unknown` mode (15.1), never to "no policies".

### 8.2 Rollback SQL (text only) and Time Travel

File `admin/worker/migrations/0003_rollback.sql` (schema only; the audit chain keeps a full copy of every policy event in `audit.detail`, so no history is lost):

```sql
-- Rollback of 0003. Roll the Worker and the pipeline files back first, and read the precondition below.
-- Precondition (run before, expect 0 rows; otherwise export them with SELECT * FROM policies and decide): SELECT id FROM policies WHERE status = 'ACTIVE';
DROP TRIGGER IF EXISTS policies_withdrawal_forward;
DROP TRIGGER IF EXISTS policies_lifted_is_final;
DROP TRIGGER IF EXISTS policies_version_step;
DROP TRIGGER IF EXISTS policies_identity_frozen;
DROP TRIGGER IF EXISTS policies_no_delete;
DROP TRIGGER IF EXISTS policy_events_no_delete;
DROP TRIGGER IF EXISTS policy_events_no_update;
DROP INDEX IF EXISTS policy_events_policy;
DROP TABLE IF EXISTS policy_events;
DROP INDEX IF EXISTS policies_status;
DROP INDEX IF EXISTS policies_candidate;
DROP INDEX IF EXISTS policies_active_key;
DROP TABLE IF EXISTS policies;
```

Dropping with ACTIVE policies silently re-allows the prohibited rules at the next daily run (the old `decide.py` does not know policies): hence the precondition, and rollback level 2 below.

**D1 Time Travel (last resort).** Before applying 0003, record the current bookmark (read-only): `wrangler d1 time-travel info macguard-quarantine` (flags of the pinned wrangler to be confirmed with `--help`
before use; also confirm the retention window of the plan from Cloudflare's documentation, which this task did not fetch). To go back: `wrangler d1 time-travel restore macguard-quarantine --bookmark=<bookmark>`; the command
reports the previous bookmark, which is the way to undo the restore. A restore is **in place and loses everything written after the bookmark, including audit rows, decisions and sessions**: the surviving chain is a valid
prefix but silently shorter, so a restore needs a human decision, the Worker in maintenance (rolled back, no pipeline run in flight), and a note in the incident log with both bookmarks. It is not the first choice: the SQL rollback above is.

---

## 9. Idempotency, concurrency and audit

All writes follow `markReleased`/`decide` (F11): guarded update -> `changes()` guard -> event row -> audit row in **one** `db.batch`; `audit_prev` (`schema.sql:63`) keeps the chain linear; a `UNIQUE` or guard failure aborts the whole batch and answers 409 `nothing was changed` + `retry`.

| Operation | Per-row guard | Idempotency key |
|---|---|---|
| request withdrawal | `UPDATE candidates SET version=version+1 ... WHERE id=? AND version=? AND state='RELEASED'`, then `INSERT INTO policies ... SELECT ... WHERE changes()=1`, then `INSERT INTO policy_events ... WHERE changes()=1`; `policies_active_key` makes a second ACTIVE policy for the same scope impossible | `policies.request_id UNIQUE`; replay returns 200 `replay:true` |
| lift | `UPDATE policies ... WHERE id=? AND version=? AND status='ACTIVE'` (+ candidate `WHERE version=? AND state='RELEASED'` + `decisions` row `WHERE changes()=1`) | `UNIQUE(policy_id, event, request_id)` and `UNIQUE(policy_id, policy_version)` |
| confirm | `UPDATE policies ... WHERE id=? AND version=? AND status='ACTIVE' AND withdrawal='REQUESTED'` + guard | the second callback finds no `REQUESTED` row and records `idempotent_retry` |
| reopen | existing `decide()` batch (`store.js:132-151`), `UNIQUE(request_id, candidate_id)` | `request_id` |

### 9.1 Audit entries (append-only; all follow `appendAudit`/`chainHash` of `store.js:8-20`, `core.js:175`)

Common envelope: `at`, `actor`, `role`, `action`, `target`, `detail` (JSON string, canonicalised for the hash), `prev_hash`, `hash`.

| `action` | `target` | `detail` |
|---|---|---|
| `policy.withdrawal_requested` | policy id | `request_id`, `policy_id`, `policy_version` (1), `scope`, `scope_key`, `source`, `path`, `sha256`, `candidate_id`, `candidate_version_before`/`after`, `reason`, `baseline{tag, published_at, manifest_sha256, rules_root, evidence}`, `collateral[{id, path}]`, `confirm_collateral` |
| `policy.reconciled` | release tag | `tag`, `trigger` (`publish`\|`reconcile`), `receipt` (`first`\|`idempotent_retry`), `release{id, published_at, evidence, asset_digest_checked}`, `manifest_sha256`, `rules_root`, `manifest_files`, `confirmed[{policy_id, version_from, version_to, scope, path, sha256}]`, `still_listed[{policy_id, scope, path}]`, `conflicts[{policy_id, reason}]`, `run_url`, `token_run_id`, `run_attempt` (the last three from the verified token, as `store.js:212`) |
| `policy.lifted` | policy id | `request_id`, `policy_id`, `version_from`/`to`, `reason`, `withdrawal_at_lift`, `candidate{id, from, to}` |
| `decision.reopen` | candidate id or `batch:N` | same shape as `decision.<action>` (`store.js:147-148`) |

`policy_events` repeats the facts per policy version (`actor`, `actor_id`, `role`, `reason`, `release_tag`, `evidence` JSON) so one policy's history is a single indexed read; the audit stays the authority for the chain.

---

## 10. Race analysis

| Scenario | What happens | Why it is safe | Test |
|---|---|---|---|
| Withdrawal requested **before** the daily review reads decisions | the rule is excluded from that run's `approved` | normal path (5.2) | PY-01 |
| Requested **after the daily snapshot, before publish** (the publish environment approval can take long, `publish.yml:46-49`) | `policy-check` step fails the publish job before signing | closes G4; the stale artifact is not signed. Daily re-runs and builds a corrected candidate | W-11 |
| Requested **between `policy-check` and the release becoming public** | the release lists the rule; policy stays P1 "pending"; the callback records it as `still_listed` / `listed_after_request`; the next release confirms | requirement 7 by construction; nothing is rewritten (F12) | W-12 |
| Requested while the release is being made public: baseline = previous release `P`, new release `N` lists it | callback for `N`: `N.published_at > baseline`, but `N` lists the scope -> `still_listed`, no confirmation | confirmation needs **absence** in a verified manifest | W-06 |
| `N` does **not** list it though built before the request | confirmed on the evidence of absence in `N` (true statement: it is not in the latest public release) | recorded as absence evidence; Open Decision 6 can strengthen it | W-07 |
| Callback arrives for a release **older** than the baseline | not eligible (`published_at` not after the baseline) | GitHub timestamps only | W-08 |
| Late callback for older tag `A` after newer `B` | confirmation is monotone (`REQUESTED -> CONFIRMED` once); if `B` lists the scope while the policy is ACTIVE it is a recorded conflict | trigger `policies_withdrawal_forward` | W-09 |
| Two admins request the same withdrawal at once | one `INSERT` wins; the other hits `policies_active_key` or the candidate `version` guard -> 409 | per-row guards + unique index | C-01 |
| Two admins, two scopes (`path` and `content`) | two ACTIVE policies with different `scope_key`; both valid, lifted independently | intended; the UI shows both | C-02 |
| Same admin double-clicks | same `request_id` -> 200 `replay` | `policies.request_id UNIQUE` | I-01 |
| Lift and confirm callback at once | both `CAS` on `policies.version`; if the lift wins the confirm affects 0 rows, its batch (and its audit) rolls back and the callback re-reads (3 attempts, `store.js:203-218`); if the confirm wins the lift answers 409 and the admin reloads | single linear version per policy | C-03 |
| Withdrawal request vs `markReleased` on the same candidate | both guard on `candidates.version`; the loser retries or answers 409 | `store.js:206-216` pattern | C-04 |
| Two callbacks for the same tag concurrently | one commits, the other's guard aborts its batch; it re-reads and records `idempotent_retry`; `audit_prev` prevents forked chain | F11 | C-05, I-03 |
| Callback retried after success | nothing to change; `receipt:"idempotent_retry"`; no second confirmation (`UNIQUE(policy_id, policy_version)`) | idempotent | I-02 |
| Callback lost (`if: success()`) | policy remains P1; ADMIN `reconcile` re-derives everything from the public release | 6.4 | W-13 |
| GitHub unreachable at request time | 502, nothing written | evidence before state | W-15 |
| Release not publishable (dynamic gate, anomaly guard) | rule stays published, policy stays pending; no override | requirement 11 | PY-10 |

The exposure that cannot be removed (the seconds between the last check and `--draft=false`) always resolves towards "pending, then confirmed by the next release", never towards a false CONFIRMED.

---

## 11. Test matrix *(all proposed; names are placeholders)*

Levels: **U** unit (`admin/worker/test`, pure `core.js`), **S** service on the D1 shim (`test/d1shim.js`, real SQL via `node:sqlite`), **RT** runtime on workerd + real D1 (`test-runtime/`), **PY** Python (`tests/`).

| ID | Level | Case | Expected |
|---|---|---|---|
| U-01 | U | `validateWithdrawalRequest`: missing/short/invisible reason (`\p{Cf}`), bad `request_id`, bad scope, collateral mismatch | 400 each; role check first (403) |
| U-02 | U | `humanTransition('reopen', ...)` only from `REJECTED` to `PENDING`; ADMIN only | other states refused |
| U-03 | U | `permanentlyBlocked` with policy overlay; `dependencyEffect` returns `ineffective`/`blocked_by` for a dependent of a policy-blocked row; collateral function = reverse closure | matches expected sets |
| U-04 | U | `releaseTransition`/`markReleased` input with an ACTIVE policy | `published_despite_policy`, not moved |
| S-01 | S | new SHA at a path whose old SHA was approved/released | new row `PENDING`, `related` shows the old one, **no approval**, absent from the decision map |
| S-02 | S | withdraw -> row, event, audit written atomically; chain verifies | `verifyChain` ok |
| S-03 | S | withdraw a candidate not in the latest manifest | 409 `not_in_current_release`, nothing written |
| S-04 | S | reject then archive the candidate | still in the decision map (closes G1) |
| S-05 | S | identical hash rejected at path A, approved at path B | rejection wins (existing F4) |
| S-10 | S | policy P1 | candidate sheet `publication = withdrawal_pending`; P2 -> `withdrawn` |
| S-11 | S | approve a candidate under an ACTIVE policy; approve a dependent of one | 409 `blocked_by_policy` / `dependency_blocked` |
| S-12 | S | lift P1 and P2 | `LIFTED`, candidate `PENDING`, `decisions` row, event, audit |
| S-13 | S | `reopen` with another `REJECTED` row of the same sha | candidate `PENDING`, response lists `still_rejected_same_content` |
| S-14 | S | empty `policies` | `GET /api/pipeline/decisions` equals the pre-change output; `/public/stats` identical |
| S-15 | S | `released_after_review` with a `CONFIRMED` policy | excluded (if Open Decision 5 of 19.2 is accepted) |
| N-01 | S | REVIEWER, VIEWER, no-role, anonymous call withdraw / lift / reopen / reconcile | 403 / 403 / 403 / 401, nothing changes |
| N-02 | S | CSRF missing/wrong, cross-origin | 403 (existing middleware) |
| N-03 | S | `daily.yml` token on `/api/pipeline/released` | 403 (existing) |
| N-04 | S | a `publish.yml` token on `/api/policies/*` | 401 (not a session) |
| N-05 | S | a user whose GitHub permission was downgraded after login calls withdraw | role is refreshed on unsafe methods (`index.js:85`), 403 |
| N-06 | S | reason absent/whitespace on withdraw, lift, reopen | 400 |
| W-05 | RT | confirmation with a release whose manifest lacks the scope | `CONFIRMED`, evidence columns set, audit entry |
| W-06 | RT | newer release still lists it | stays `REQUESTED`, `still_listed` |
| W-07 | RT | newer release absent for unrelated reasons | confirmed with absence evidence |
| W-08 | RT | release not newer than baseline | not eligible |
| W-09 | RT | out-of-order callbacks `B` then `A` | monotone; conflict recorded when a release lists an ACTIVE-policy scope |
| W-10 | RT | forged manifest (bad `rules_root`), draft release, missing manifest | 422/409, nothing changed (existing `fetchPublication` behaviour) |
| W-11 | RT/PY | `policy-check` with a candidate containing a policy-matched file; with service down | exit non-zero before signing |
| W-12 | RT | listed after request | pending, never CONFIRMED |
| W-13 | RT | `reconcile` after a lost callback | same result as the callback |
| W-14 | RT | no write to any other candidate's `release_tag`, no GitHub write request (fake fetch asserts GET only) | holds |
| W-15 | RT | GitHub outage on request / on callback | 502, nothing changed |
| C-01..C-05 | RT | the concurrent cases of section 10 with `Promise.all` | exactly one winner; no forked chain; no audit entry without its state change |
| I-01..I-03 | S/RT | replay of request, callback and lift | 200 replay / `idempotent_retry`; counts unchanged |
| M-01..M-04 | S/RT | migration: static statement check; v1+0002+seed -> 0003 leaves checksums and chain equal; applied twice; CHECK/trigger violations abort; schema.sql equals migrated schema (compare `sqlite_master`) | as described in 8.1 |
| M-05 | S | rollback SQL on the migrated database | removes only the two tables; v1+0002 schema equal to before |
| PY-01 | PY | policy `path` on a clean VALIDATED file | out of `approved`, state `QUARANTINED`, code `blocked-by-policy`, submitted |
| PY-02 | PY | `policies=[]` vs `None` on the existing fixtures | identical output |
| PY-03 | PY | approved decision + policy | still excluded (no waiver) |
| PY-04 | PY | `content` scope, same sha at another path | excluded; different sha at the same path **not** excluded (content scope) |
| PY-05 | PY | `path` scope, new sha at the path | excluded and visible in `submissions` |
| PY-06 | PY | rejected-by-reviewer file that became clean, service unavailable | not publishable in `unknown` mode (G3, NF-02) |
| PY-07 | PY | decisions contain approval of old sha only | new sha gets no `waived-by-review` |
| PY-08 | PY | policy removed (lifted) | file re-enters only if all technical gates pass; with a failing gate it does not |
| PY-09 | PY | dependent chain `C -> B -> A`, policy on `A` | `B` and `C` excluded with `dependency-not-validated`; return together when lifted; JS/Python closure parity |
| PY-10 | PY | removal-only set with failing dynamic verdict / anomaly | `publishable=false`, withdrawal not forced |
| PY-11 | PY | property test: for random policies, `approved(policies) is a subset of approved(none)` | holds (a policy never adds a file) |
| PY-12 | PY | `quarantine_client` writes `policies.json`; missing `policy_schema` -> `unknown` mode; `policy-check` exit codes | as described |
| WF-01 | PY | `tests/test_workflow_prereqs.py`-style static checks: `daily.yml` passes `--policies`; `publish.yml` runs `policy-check` before `seal.py` | present |

---

## 12. Rollback plan (levels, cheapest first)

1. **Worker only:** `wrangler rollback` to the previous version. New tables stay, ignored. Pipeline files are tolerant (missing fields -> `unknown` mode, section 15.1). No data loss.
2. **Pipeline files only:** revert `decide.py`/`dynamic_gate.py`/`quarantine_client.py`/workflow changes. With ACTIVE policies this *re-allows* the prohibited rules at the next release: before doing it, list ACTIVE policies and either lift them (audited) or keep the old Worker answering `policies` to a pinned client. Do not do this silently.
3. **Schema:** `0003_rollback.sql` (8.2) only after levels 1-2 and with zero ACTIVE policies (or an exported copy).
4. **Time Travel restore:** catastrophic corruption only; costs the audit rows after the bookmark (8.2).
5. Releases already published are never touched at any level (F12). A rule withdrawn by mistake is restored by lifting the policy; it re-enters through the normal gates in a **new** release.

---

## 13. Risks

| Risk | Mitigation / note |
|---|---|
| Fail-safe mode (15) turns an outage of the private service into delayed additions | decided (D8); removals still flow; no alert is enabled without a tested channel (project rule) |
| A withdrawn rule cannot be pulled quickly when the removal-only set fails a gate or the anomaly guard | by design (no bypass); `allow_large_change` is the existing human input of `daily.yml` and is not a test bypass |
| CONFIRMED proves absence, not causation | recorded as such; the snapshot pin (15.2) shows which policy view the build used |
| `path` scope blocks upstream updates until an ADMIN lifts | visible in the panel as `PENDING` with a non-approvable reason; Open Decision 1 (19.2) |
| batch size | `reject`/`approve` batches are unchanged; withdraw and lift are single-candidate; `reopen` uses the existing batch shape; RT test with 500 ids for `reopen` |
| `reconcile` fetches GitHub on demand | ADMIN only, existing 10 s timeouts and retries (`publication.js:7-18`); add a minimum interval |
| Worker does not verify Sigstore | same limitation and same mitigation as RELEASED (workflows verify before and after publication) |
| Two truths for one block: `decisions` (rejections) and `policies` (withdrawals) | intentional: rejections stay as they are (smaller change); the decide.py input is the union; the sheet shows both |
| Public counters (`released_after_review`) drifting from reality after withdrawals | Open Decision 5 (19.2) |
| Documentation of the states (`docs-src/diagrams/quarantine-states.json`) not updated here | touching `docs-src/` redeploys the public site; separate deliberate change |

---

## 14. Persistent rejections wired into the pipeline (owner decision 7)

**Verified today:** `dynamic_gate.py` accepts `--rejected` and passes it as `previously_rejected` to `decide.decide` (`dynamic_gate.py:130,138,78`), and `decide.py:37-38` turns a file whose hash is in that set into `REJECTED`
(tested at `tests/test_decide.py:27-32`). But `daily.yml:74-77` never passes `--rejected`, nothing writes such a file, and in `dynamic_gate.py:131` the loader is
`load = lambda p: ... if p and pathlib.Path(p).exists() else None`: **a missing file is silently ignored**. So the wiring is dead code today; a human rejection is honoured only through the decision map
(`decisions[sha].state == 'REJECTED'`, `decide.py:39-41`), which is empty whenever the service is unreachable (`quarantine_client.py:80-84`).

**Exact changes *(proposal)*:**

| File | Change |
|---|---|
| `admin/worker/src/store.js` | new `rejectedHashes(db)`: `SELECT DISTINCT sha256 FROM candidates WHERE state = 'REJECTED'` **without** the `archived_at` filter of `store.js:166` |
| `admin/worker/src/index.js:32` | `GET /api/pipeline/decisions` also returns `rejected: [<sha>...]` and the policy view (15.2). `decisions` and `retest` unchanged |
| `scripts/quarantine_client.py` (`decisions`, lines 80-84) | after the verification of section 15 writes `dist/rejected.json` (a JSON list, **always written**, `[]` when nothing is known), `dist/policies.json` (`{mode, policies, ...}`) and keeps `dist/decisions.json` |
| `scripts/dynamic_gate.py` (lines 129-138) | new `--policies`; for `--rejected` and `--policies` the loader **fails the run** (`sys.exit`) when the argument is given and the file is missing or not valid JSON; passes `previously_rejected`, `policies`, `policy_mode` to `decide_now` (lines 77-78) |
| `.github/workflows/daily.yml:74-77` | gate step gets `--rejected dist/rejected.json --policies dist/policies.json` |
| `scripts/decide.py` | `policies` and `policy_mode` parameters (5.1, 15.1); the `previously_rejected` logic (line 37) is **unchanged** |
| `.github/workflows/publish.yml` | before `seal.py` (line 106): `policy-check` (5.6), which fails when any file of `dist/candidate.json` has a hash in the rejected set or matches an ACTIVE policy |

**Tests that a rejected hash cannot be published (none of these exists today):**

* PY-13 `decide`: a clean VALIDATED file whose hash is in `previously_rejected`, **with** an approval for the same hash in `decisions` and a passing dynamic result -> not in `approved`, state `REJECTED`. Changed bytes (new hash) are still allowed (existing test, kept).
* PY-14 `dynamic_gate.run(..., previously_rejected={H})` on the fixture set: `final['approved']` lacks H. The CLI with `--rejected <missing file>` exits non-zero (new behaviour).
* PY-15 end to end with the local fake Worker already used by `tests/test_quarantine_client.py`: the fake serves `rejected:[H]`; run `quarantine_client.py decisions`, then the gate on the fixture, then `policy-check` on a candidate that contains H: the gate excludes it; `policy-check` exits 1.
* WF-01/WF-02 static workflow tests (pattern of `tests/test_workflow_prereqs.py`): `daily.yml` passes `--rejected` and `--policies` to the gate and the client step precedes it; `publish.yml` runs `policy-check` before `seal.py`.
* S-04 (an archived rejected row stays in `rejectedHashes`) and S-05 (hash rejected at path A, approved at path B, is rejected).

---

## 15. Fail-safe publication (owner decision 8; replaces the old "publication never depends on the service")

This **reverses** the principle written at `decide.py:10` and `quarantine_client.py:4-5`. Both docstrings, and the message at `quarantine_client.py:83`, are rewritten with the change.

### 15.1 Definition

*Fail safe* means: **whatever fails (service down, slow, 5xx, wrong schema, truncated, regressed, emptied, tampered), no build can add or modify a file unless the pipeline holds a verified view
of every prohibition; and no failure can remove a prohibition the pipeline has already verified.** A removal can never violate a prohibition, so removals are always allowed.

The pipeline computes a **policy mode** (written in `dist/policies.json`, read by `decide()` through `policy_mode`):

| Mode | When | What `decide()` does |
|---|---|---|
| `normal` | live view accepted by 15.3 | applies the live view united with the verified snapshot (ratchet, 15.3) |
| `snapshot` | live view unavailable or rejected, a verified fresh snapshot exists | applies the snapshot only; additions allowed; no new approvals are known (safe default of `decide.py:39`) |
| `unknown` | neither (no snapshot, stale, tampered, pin mismatch, regressed live view) | `publishable = false` if the change against the previous release has any `added` or `modified` file (blocker `policy view unavailable: only removals can be published`); removals-only allowed. With no previous release everything is "added", so the first release needs a verified view |

`publish.yml` is stricter: `policy-check` needs a **live** accepted view, or a removals-only change; otherwise the publish job fails before signing (a human-gated job can wait; nothing is lost).

### 15.2 Snapshot *(proposal)*

Content (canonical JSON, sorted keys, as `core.js:165-168` / `tlog.py:116`): `schema`, `generated_at`, `service_audit_head {seq, hash}`, `decisions_max_id`, `policy_set_sha256`,
`rejected[]` (hashes), `policies[]` (every policy, ACTIVE **and** LIFTED, with `id`, `version`, `scope`, `source`, `path`, `sha256`, `status`, `withdrawal`). No reasons, no actors.
The Worker adds these fields to `GET /api/pipeline/decisions` (`index.js:32`).

Lifecycle, in the daily run after `decide` succeeded in mode `normal` (a snapshot is **never** refreshed from another snapshot, so staleness cannot be laundered):

1. write `policy-snapshot.json`; `cosign sign-blob --bundle` keyless with the workflow identity (cosign is already installed in `daily.yml:49` and used the same way in `publish.yml:102,109`);
2. `actions/cache` save under `policy-snapshot-v1-${run_id}` (the cache action is already used, `daily.yml:150,195`). The cache is only **transport**; eviction is possible (to be confirmed against GitHub's current cache rules), which is the "no snapshot" case and is safe;
3. **hash pin in the repository log:** `tlog.py event --code policy.snapshot --detail snapshot_sha256=<hex> --detail audit_seq=<n>` (`tlog.py:257,342-366` accept any code and key=value details; only a hash and counts), committed by `commit_logs.sh` to `main` like every other log entry.

Verification before use (in `quarantine_client.py decisions`, on the runner):

1. `cosign verify-blob --bundle` with certificate identity regexp `^https://github.com/<repo>/.github/workflows/(daily|publish)\.yml@refs/heads/main$` and issuer `https://token.actions.githubusercontent.com` (same shape as `site.yml:56`);
2. `sha256(snapshot)` equals the **newest** `policy.snapshot` event of `logs/` checked out from `main` (defeats replay of an older, validly signed snapshot);
3. age <= **MAX_AGE = 48 h**, measured from the signature's transparency-log time inside the bundle, not from a field the file controls (the daily cron is `17 3 * * *`, `daily.yml:5`; 48 h tolerates one missed day);
4. any failure means "no snapshot".

### 15.3 Accepting a live view (the ratchet)

The live response is accepted only if: HTTP 200, valid JSON, `policy_schema == 1`, required fields present, `policy_set_sha256` equals the digest recomputed locally from `policies`, and, **if a verified snapshot S exists**:
`audit_head.seq >= S.audit_head.seq`, `decisions_max_id >= S.decisions_max_id`, and every ACTIVE policy and every rejected hash of S is still present in the live view (same policy id with `version >= S.version`, status `ACTIVE` or a lift
accepted by 15.4; the hash still in `rejected`, or a recorded `reopen` of it). Anything else is **`regressed`**: the mode becomes `unknown` with blocker
`policy store regressed against the last verified snapshot: a person must reconcile (17.4)`, **and S's blocks are still applied**. Effective blocks are always `live ∪ S`, minus validly lifted ones.

### 15.4 Why an attacker who controls the Worker or D1 cannot bypass it

| Attacker move | Result |
|---|---|
| serve empty/truncated/odd JSON, 5xx, hang | treated as unavailable (`quarantine_client.py:32-44` already returns status 0 on failure; the call timeout is 60 s, line 40); `snapshot` or `unknown` mode |
| serve an emptied policy set or rejected list | ratchet: S's blocks are missing -> `regressed`, and the union keeps them. With no S -> `unknown`: nothing can be added |
| serve an older state (D1 restored or replayed) | `audit_head.seq` / `decisions_max_id` / version regression -> `regressed` |
| forge a snapshot or tamper with the cache | needs a Sigstore certificate for a `daily` or `publish` run on `refs/heads/main`; plus the pin in the repository log |
| replay an old valid snapshot | pin mismatch (not the newest `policy.snapshot`) and age limit |
| mark a block `LIFTED` | **Level A (baseline of this design): accepted.** The Worker is the authority for lifts, so a compromised Worker can forge a lift. Bounded: the file must still pass every technical gate (`decide.py:43`, dynamic gate, canaries), and the Worker can already forge approvals of waivable findings today (`decide.py:42-45`). **Level B (hardening, Open Decision 13):** the pipeline honours a lift only if the log holds `policy.lift.authorized` (policy id and version) written by a `policy-lift.yml` run approved through an `environment` with required reviewers (a GitHub-authenticated human, outside the Worker); otherwise the block stays and the run reports `lift_unauthorized` |
| deny the service (DoS) | fail safe: nothing is added or modified; removals still flow |

Residual risk, stated plainly: whoever can change workflows on `main` or compromise the Actions identity is outside this model. The Worker is trusted to **add** blocks; it is not trusted to **remove** them silently.

---

## 16. Urgent withdrawal (owner decision 9)

**Design:** reuse the existing manual trigger of `daily.yml` (`workflow_dispatch`, `daily.yml:6-15`) instead of a new publishing workflow. It already runs the *same* chain: classification -> dynamic gate -> `macos` check -> `request-publish` -> `publish.yml`
(environment, signing, release, callback) (`daily.yml:218-231`, `publish.yml`). A new workflow would duplicate the gates; reusing this one guarantees they cannot diverge. No new OIDC identity is needed (`auth.js:126-129`, `PIPELINE_WORKFLOWS`).

* **Trigger:** `workflow_dispatch` of `daily.yml` with a new input `urgent_policy_id` (opaque id of an ACTIVE, `REQUESTED` policy; never a rule name). Mutually exclusive with `acceptance` (the first step fails if both are set, because `acceptance` suppresses `request-publish`, `daily.yml:220`).
* **Authentication, two independent checks before anything runs:** (1) a first step reads `gh api repos/$GITHUB_REPOSITORY/collaborators/$GITHUB_TRIGGERING_ACTOR/permission` and fails unless the permission is `admin` (GitHub-authenticated; plain write access is enough to dispatch today's manual run but not an urgent one); (2) the Worker, called with the run's OIDC token, confirms the policy exists, is `ACTIVE`/`REQUESTED` and was authored by an ADMIN (`author_role = 'ADMIN'` is a DB CHECK) through a new read-only `GET /api/pipeline/policy/{id}`, and records `pipeline.urgent_run` in the audit (actor, run id, attempt, policy id).
* **What it adds beyond a manual run:** an assertion after the gate (the policy's scope is absent from `approved`, otherwise the run fails with a clear blocker), and a prompt build instead of waiting for the `17 3 * * *` cron.
* **No second concurrent publish:** (1) `daily.yml` and `publish.yml` share `concurrency: group: macguard-log, cancel-in-progress: false` (`daily.yml:17-19`, `publish.yml:9-11`), so reviews and publications are serialized; GitHub keeps at most one *pending* run per group and a newer pending run replaces an older pending one (to confirm against current GitHub behaviour; the replaced run would be the cron, which runs again the next day); (2) *(proposal)* a stale-base check in the `precheck` job of `publish.yml`: the artifact's `changes.json` records `previous_rules_root` (`changes.py:19`, written by `daily.yml:87`); if it is not the `rules_root` of the **current** latest release, the job fails with "candidate built on a superseded release; run the review again". Two candidates built on the same base therefore cannot both publish; (3) the Worker callback is idempotent (section 9).
* **What it can never do:** skip or weaken any gate (`publishable` is still required, `daily.yml:220`); publish when the dynamic gate, canaries, anomaly guard or the `macos` job fail (the withdrawal then stays *pending*, section 10); add, modify or approve a rule; lift anything; edit or delete a historical release (`publish.yml:141`); skip the `stable-signing` environment approval (urgent does not set `AUTO_PUBLISH`; Open Decision 14); run for a non-admin, for an unknown or non-ACTIVE policy, or together with `acceptance`.
* **Confirmation** is unchanged: the callback of the resulting release confirms the withdrawal on its verified manifest (section 7). Urgent changes only *when* the next build happens.

---

## 17. Recovery from loss of D1 or the Worker (owner decision 10)

### 17.1 What is lost in each failure

| Failure | Effect | Safe behaviour |
|---|---|---|
| Worker code or deploy lost | no panel, no API | pipeline runs in `snapshot`/`unknown` mode (15.1); redeploy from git (`wrangler deploy --keep-vars`); the OAuth and `TOKEN_ENC_KEY` secrets only affect sessions, never policy |
| D1 unavailable | same | same |
| D1 lost or restored to an older point | blocks may be missing | the ratchet reports `regressed` (15.3); the verified snapshot's blocks still apply; **lift nothing until 17.4 is done** |

### 17.2 Backups and cadence

1. **Per run, free:** the signed snapshot (15.2) is a policy-complete backup of rejected hashes and policies, pinned in the repository log. It is the first thing to use.
2. **D1 Time Travel:** continuous point-in-time recovery for the retention of the plan (retention to be confirmed in Cloudflare's documentation; not fetched here). Record the bookmark in the deploy log before every migration (8.2) and every Worker release.
3. **Logical export, daily and encrypted *(proposal, Open Decision 15)*:** a scheduled workflow exports `policies`, `policy_events`, `decisions` and `audit` (no sessions, no tokens), encrypts with `age` to a recipient public key held in a repository variable (the private key stays with the owner, offline) and uploads it as an artifact with the longest retention. The ciphertext is safe in the artifacts of a public repository. An export may lock the database while it runs, so it is scheduled outside the daily window (to be measured in staging).
4. **The audit chain** is the intrinsic record: every policy event copies its full facts into `audit.detail` (9.1) and rejections copy `sha256` (`store.js:147-148`), so the policy table and the rejected set are **re-derivable** from a verified chain.

### 17.3 Re-derivation of policy from the audit

A pure function `derivePolicies(auditRows)` (new, in `core.js`, unit-tested) replays `policy.withdrawal_requested`, `policy.reconciled`, `policy.lifted`, `decision.reject` and `decision.reopen` in `seq` order after `verifyChain` (`core.js:176`) succeeded, and returns the expected `policies` rows and rejected hashes with versions.
It is used (a) by the restore drill, (b) by an offline, human-run repair that prints reviewed SQL (never an endpoint), (c) by a read-only consistency check `GET /api/audit/policy-consistency` (ADMIN).

### 17.4 When audit and policy table disagree

Rule: **when in doubt, blocked.** The effective block set is the union of the table, the audit-derived set and the verified snapshot.

| Case | Action |
|---|---|
| table has a policy the audit lacks | keep it ACTIVE (policies are never deleted, trigger `policies_no_delete`); open an incident; investigate before any change |
| audit has a policy the table lacks (restored to an older point) | re-create it from the audit with the repair script; the audit-derived block applies meanwhile |
| versions differ | the higher audit-derived version wins for history; any ACTIVE side stays ACTIVE until a person resolves it |
| `LIFTED` in the table but not in the audit | not a lift: treated as ACTIVE (a lift without its audit entry and event is untrustworthy) |
| the audit chain fails `verifyChain` | stop; restore in staging from Time Travel to the last verified bookmark first; the snapshot pin in the log shows which `audit_seq` and hash were true on which day |

Every reconciliation is itself recorded with a new audit entry (`policy.reconciliation`), never by editing rows.

### 17.5 Restore drill (quarterly, and after any change to the policy schema)

On **staging** only (`admin/worker/STAGING.md`): (1) export production read-only; (2) import into a fresh staging D1; (3) `verifyChain`; (4) `derivePolicies` equals the table; (5) the snapshot pin of the day matches `audit_head`; (6) run the tests of section 18 against the restored copy; (7) restore staging to an earlier bookmark and confirm `regressed` is raised and the blocks hold; (8) record duration and findings with `lessons-review`. Nothing in the drill touches production.

---

## 18. Negative and fail-safe tests (all proposed; each must fail before the change and pass after)

| ID | Level | Scenario | Expected |
|---|---|---|---|
| NF-01 | PY+RT | rule forbidden, then the service down (connection refused, 503, timeout), fresh valid snapshot | rule excluded in `snapshot` mode; other additions allowed |
| NF-02 | PY | same, **no snapshot** | `unknown`: any `added`/`modified` -> not publishable; removals-only publishable |
| NF-03 | PY | snapshot older than 48 h by bundle time | treated as no snapshot |
| NF-04 | PY | snapshot tampered (one byte; bad bundle; signed by another workflow, branch or repository) | rejected; `unknown` |
| NF-05 | PY | older but validly signed snapshot (pin mismatch) | rejected |
| NF-06 | PY+RT | D1 restored to an older point lacking a block (lower `audit_head.seq`, missing policy, lower version) | `regressed`; the block still applies; not publishable until reconciled |
| NF-07 | PY | Worker returns empty `policies` and `rejected` with a higher audit head | ratchet keeps S's blocks; with no S -> `unknown` |
| NF-08 | PY | Worker returns 200 with wrong `policy_schema`, wrong `policy_set_sha256`, truncated JSON | unavailable |
| NF-09 | PY | Worker marks a block `LIFTED` with no authorization (Level B on) | block kept, `lift_unauthorized` reported |
| NF-10 | PY | `--rejected` given but file missing or invalid | `dynamic_gate.py` exits non-zero (today it continues silently, `dynamic_gate.py:131`) |
| NF-11 | PY | rejected hash + approval decision + clean + dynamic ok | excluded (PY-13) |
| NF-12 | RT+WF | withdrawal requested after the daily snapshot, before signing | `policy-check` fails the publish job |
| NF-13 | RT | withdrawal requested during the publish, after `policy-check` | release lists it; policy stays pending; the next release confirms; never a false CONFIRMED |
| NF-14 | WF | two urgent dispatches, or urgent plus cron | serialized by the group; the second candidate fails the stale-base check |
| NF-15 | WF | urgent by a write-only actor; with `acceptance=true`; unknown, LIFTED or CONFIRMED policy id | refused before any gate runs |
| NF-16 | WF | urgent while the removal-only set fails the dynamic gate | no release; policy stays pending |
| NF-17 | PY | publish `policy-check` with the service down and a change that has additions | job fails before signing; removals-only passes |
| NF-18 | S | D1 audit and `policies` disagree (the cases of 17.4) | `policy-consistency` reports each case; blocks hold |
| NF-19 | S | `derivePolicies` on a chain with a broken link | refuses |
| NF-20 | RT | callback retried, duplicated, out of order, concurrent with a lift | no double confirmation, no forked chain, no false CONFIRMED (C-03, C-05, I-02) |

---

## 19. Owner decisions applied, and what is still open

### 19.1 Decided by the owner (binding)

| # | Decision | Where it lands |
|---|---|---|
| D1 | an ADMIN withdrawal persists across runs | `policies` (section 8), `decide.py` input (5.1), snapshot (15.2) |
| D2 | a withdrawn rule cannot reappear automatically while the block is in force | `blocked-by-policy` (5.2), `policy-check` (5.6), fail safe (15) |
| D3 | reason, user, date, source, path, SHA and audit are recorded | `policies` columns, `policy_events`, audit entries (9.1) |
| D4 | effective for the NEXT build, CONFIRMED in the next signed release | sections 7 and 10 |
| D5 | historical releases are never modified | W-14, section 12 |
| D6 | an approval is never inherited by a different SHA | F2/F3, S-01, PY-07 |
| D7 | persistent rejections really wired to the pipeline | section 14 |
| D8 | publication fails safe when the service fails | section 15 (replaces the old principle) |
| D9 | validated urgent withdrawal through the same gates | section 16 |
| D10 | recovery policy for D1/Worker loss | section 17; tests in 18 |

Effect on the 12 earlier open decisions: old **2 resolved** by D8; old **7 resolved** by D9 (no gate bypass; the urgent path is the manual `daily.yml` chain); old **4 resolved** by D7 (the pipeline reads the rejected list directly, including archived rows, so legacy rejections need no backfill into `policies`);
old **6 superseded** by the repository-log pin of the snapshot (15.2), which proves which policy view a build used, without changing release artifacts.

### 19.2 Still open (numbering kept from the earlier list; 13-17 are new)

1. **Default scope of a withdrawal:** `path` (recommended: a later upstream version stays blocked and visible until lifted) or `content`.
3. **Two-person rule** for a withdrawal or a lift. The design implements one ADMIN, as the brief states.
5. **Public counters:** exclude `CONFIRMED` withdrawals from `released_after_review`? Publish a counts-only "withdrawn" figure?
8. **Lift semantics:** a lift returns the candidate to `PENDING`, so a former waiver approval is not remembered (recommended).
9. **Standalone prohibition** of a never-published path or hash (not just rejecting a candidate): not included.
10. **Expiry or periodic review** of policies: not included (no alert without a tested notification channel).
11. **Collateral:** preview plus `confirm_collateral` (current) versus requiring each dependent to be withdrawn explicitly.
12. **`reconcile`:** rate limit; ADMIN only.
13. **Lift authorization Level B** (`policy-lift.yml`, environment with required reviewers, `policy.lift.authorized` in the log): needed to resist a compromised Worker forging lifts; costs a second step for every lift and publishes, with an opaque id, that a lift happened.
14. **Urgent runs:** must they always require the manual-approval `stable-signing` environment even when `AUTO_PUBLISH=true`?
15. **Encrypted daily export (17.2.3):** accept artifacts as the off-site copy, with an `age` key held by the owner, or another destination.
16. **MAX_AGE** (48 h proposed) and whether `snapshot` mode may allow additions at all (proposed: yes, since unknown approvals are simply unused).
17. **Docstrings:** confirm that the principle "publication never depends on the service" is withdrawn in `decide.py`, `quarantine_client.py` and the evidence spec, per D8.
