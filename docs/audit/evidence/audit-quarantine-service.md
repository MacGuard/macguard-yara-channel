# Audit: admin/worker (quarantine service) + scripts/quarantine_client.py + scripts/decide.py

Commit audited: aa8fa2a (detached worktree). Method: full read of src/*, schema.sql, public/admin.js, test harness, both Python scripts, the relevant workflow steps; 18 adversarial tests run against the local harness (in-memory node:sqlite shim, no network, no server started).
Existing suite: `cd admin/worker && npm test` -> 29/29 pass (5.1 s). Adversarial suite: `node --test adversarial.test.js` -> 18/18 pass (tests named FINDING assert the current, buggy behaviour; they will fail once fixed).

Totals: CRITICAL 0, HIGH 1, MEDIUM 5, LOW 9 (plus 11 discarded/by-design notes).

## Answers to the logic questions
- Can an unapproved/rejected/quarantined rule end up released by the service state machine? No for a single candidate: RELEASED is reachable only APPROVED_PENDING_VALIDATION -> RELEASED via `pipelineTransition` (core.js:30-35), called only from `/api/pipeline/released`, which needs an OIDC token whose `job_workflow_ref` is `publish.yml@refs/heads/main` (index.js:36). Humans cannot produce RELEASED (test "logic: humans cannot release..." passes; every human action on RELEASED/REJECTED returns 409). REJECTED/PENDING candidates are untouched by `released` (verified). BUT see H-1: because the pipeline consumes decisions keyed by sha256 only, identical bytes at another path can inherit an approval/RELEASED state.
- Authority for "released": the service's RELEASED is a *record*, set by publish.yml after the GitHub release is created (publish.yml:150-152). The real release authority is decide.py + dynamic gate + the signing workflow; the service only supplies "approved" hints. decide.py treats `APPROVED_PENDING_VALIDATION` and `RELEASED` as approving (decide.py:17) but never lets approval waive blocking technical findings (decide.py:43-45) - good.

## Findings

### H-1 HIGH - decisions are keyed by sha256 only; a REJECTED path can be shadowed by a RELEASED/APPROVED path with the same bytes
- store.js:113-118 (`decisionsMap`, `out[r.sha256] = ...` overwritten per row), consumed at decide.py:39-45; candidate uniqueness is (sha256, path) (schema.sql:22) so the same bytes at two paths = two candidates.
- Root cause: the pipeline-facing map collapses N candidates to 1 entry per hash; winner = last row returned by an unordered query (observed to follow the `candidates_state` index scan = alphabetical state: APPROVED < REJECTED < RELEASED, plan-dependent, not policy).
- Repro: `adversarial.test.js` "FINDING DECISIONSMAP-COLLISION". Submit same sha at rules/a/dup.yar and rules/b/dup.yar; reject A, approve B, release B (publish.yml). `decisionsMap` -> `RELEASED` for that hash. decide.py: `d.state == RELEASED` is in APPROVING, so the path-A file (a human REJECT) goes QUARANTINED->VALIDATED via waiver (if only waivable findings) and is published. With REJECTED+APPROVED (no release yet) REJECTED happens to win with SQLite's plan, which is accidental; D1 plan may differ.
- Impact: a human rejection can be overridden silently by an unrelated approval of identical content at another path (vendored duplicates are common in YARA repos). Technical blockers still apply (decide.py:43), so it can only bypass the judgement-level reject.
- Fix: in `decisionsMap` aggregate deterministically per hash with REJECTED dominating (`CASE state WHEN 'REJECTED' THEN 0 ...` / `ORDER BY` + keep-first), or key by `sha256|path` and have decide.py look up by (sha, path) and apply "any REJECTED for this hash wins". Add a regression test.

### M-1 MEDIUM - blob content is never verified against its sha256; first writer wins
- store.js:36-39 (`INSERT OR IGNORE INTO blobs (sha256, content)`), core.js:54-62 (no check), client sends bytes it read from disk without hashing (quarantine_client.py:39-40).
- Repro: "FINDING BLOB-UNVERIFIED": submit sha(c) with content `rule Evil...`; a later submission of the same sha with different content is ignored, and the reviewer sees the first content for both. Reviewer approves "what they saw" while the approval binds to the hash.
- Impact: reviewer sees bytes that need not hash to the approved sha (requires a compromised/buggy daily.yml@main, so integrity of the review evidence rather than an external attack).
- Fix: in `upsertCandidate` compute SHA-256 of the decoded bytes and reject (400) if != `item.sha256`; use the verified bytes only.

### M-2 MEDIUM - audit entries can claim a decision that was never recorded (same-action race)
- store.js:89-101. The guard (store.js:94-95) checks "row currently has state=to and version=v+1", which is also true when *another* actor's identical decision produced that state. The second batch's UPDATE affects 0 rows, its decisions INSERT is skipped (`WHERE changes()=1`), but the guard passes and its audit row is inserted.
- Repro: "FINDING AUDIT-FABRICATION" (B reads rows before A commits and the audit head after): both get HTTP 200; `decisions` has 1 row (rita), `audit` has 2 `decision.approve` entries (rita, rob). The hash chain stays valid so verify cannot detect it.
- Impact: the "who decided" trail attributes an approval to a person whose decision did not take effect; the reviewer gets a success response. Window is narrow (needs interleaving between the pre-check and audit-head read) but the audit chain is the stated source of truth.
- Fix: make the guard bind the *result of this batch*, e.g. make the audit INSERT conditional (`INSERT ... SELECT ... WHERE (SELECT COUNT(*) FROM decisions WHERE request_id=? )=N`), or include `request_id` rows count in the guard SELECT instead of the candidate state/version.

### M-3 MEDIUM - audit/verify and unbounded audit growth by read-only users
- index.js:74: `GET /api/candidates/:id` appends an audit row for every view, allowed for VIEWER (and any GitHub-write user). "FINDING VIEW-AUDIT-SPAM": 200 GETs -> 200 rows. index.js:87 + store.js:21 `auditRows(db, 100000)` is `ORDER BY seq ASC LIMIT 100000`: once the log exceeds 100k rows the verifier silently checks only the first 100k and reports ok with `head` of the 100000th entry, never the real head; also loads 100k rows in one Worker invocation (CPU/memory limit).
- Impact: a low-privileged member can bloat the audit and (after 100k views) blind `verify` to all later tampering; real D1 row/time limits make verify fail rather than pass at scale.
- Fix: rate-limit/dedupe view audits (e.g. one per actor+candidate per 10 min), paginate verification with a stored checkpoint, and return `{ok:false, error:'truncated'}` when `rows.length === limit`.

### M-4 MEDIUM - OAuth `state` is not bound to the initiating browser (login CSRF); unauthenticated state writes never purged
- auth.js:47-52, 53-56; index.js:46-52. "FINDING LOGIN-CSRF": a browser with no cookie completes `/auth/callback?code=<attacker code>&state=<attacker's state>` and receives a session for the attacker's GitHub identity (state is single-use and server-side only). Victim ends up using the panel as the attacker (actions are attributed to the attacker, victim may view/enter data under attacker identity). Exploitability is limited because victim needs panel access and gains nothing privileged, hence not HIGH.
- Same test "FINDING UNAUTH-STATE-GROWTH": `GET /auth/login` writes a D1 row per request with no auth or rate limit; expired `oauth_states` and expired `sessions` (which hold the GitHub access token in clear, schema.sql:60-63) are never deleted.
- Fix: set a short-lived `__Host-mg_oauth` HttpOnly SameSite=Lax cookie = hash(state) at /auth/login and require it at the callback; purge expired rows opportunistically (`DELETE ... WHERE expires_at < ?` on login) and add a Cloudflare rate-limiting rule on /auth/*. Consider hashing session ids and deleting the GitHub token after the first permission fetch, or revoking it at logout.

### M-5 MEDIUM (functional, UNVERIFIED on real D1) - batch limit incompatible with D1 bound-parameter limit
- core.js:5 `MAX_BATCH = 500`; store.js:70-71, 74, 94-95 build `IN (?,?,...)` with N params and a guard with 3N params; the pipeline `hashes`/submit loops are per-row so fine. Cloudflare documents a 100 bound-parameter cap per statement, so a batch of >~33 ids (guard statement) fails in D1 -> caught -> HTTP 409/500 ("nothing was changed"). Fails closed, but advertised 500-per-request batches would never work. The node:sqlite shim has a much higher limit so tests cannot see it. NOT RUN (no real D1; prohibited).
- Fix: build the guard as a single `SELECT COUNT(*) FROM candidates WHERE (id,state,version) IN (VALUES ...)` is still N params -> instead chunk to <=30 ids, or guard with a per-batch temp marker (`request_id`) and compare counts.

### L-1 LOW - replayed request_id with a different action returns "already applied" (200)
- store.js:74-75. "FINDING REPLAY-DIFFERENT-ACTION": approve with request_id X, then reject with the same X -> 200 `replay:true`, state stays APPROVED. A caller (or buggy client) believes it rejected. Fix: store `action` in decisions and compare (409 if different); also bind `actor_id`.

### L-2 LOW - OIDC audience check fails open when `OIDC_AUDIENCE` is unset; no `jti` replay protection; repository matched by name not id
- auth.js:77 (`claims.aud !== env.OIDC_AUDIENCE`): "FINDING OIDC-AUD" - with the var deleted, a validly signed token without `aud` is accepted. wrangler.toml ships a REPLACE-WITH placeholder so a forgotten replacement is fail-open for any token whose audience is the placeholder string. Also valid tokens are replayable until `exp` (test "pipeline workflow scoping"; short-lived, same-repo, so low). Fix: `if (!env.OIDC_AUDIENCE || claims.aud !== ...) fail`; refuse start-up while placeholders remain; optionally compare `repository_id`/`repository_owner_id`. JWKS is fetched on every call (auth.js:72) with no cache or size guard: an availability cost, not an auth flaw.

### L-3 LOW - de-privileged user keeps access up to 60 s (600 s if GitHub is down)
- auth.js:31, 39. "FINDING REVOKE-WINDOW": permission removed on GitHub, 30 s later POST /api/decisions still 200. Documented design ("cached 60 s"); the 600 s stale grace during a GitHub outage allows write actions on a stale grant, contradicting "fail closed". Fix: state-changing endpoints (decisions, members, retest) should force a fresh check (skip cache), stale grace read-only.

### L-4 LOW - role keyed by mutable GitHub login, not numeric id
- auth.js:43 `memberRole(db, session.login)`, store.js:136-140. A renamed/released login re-registered by someone else inherits an explicit VIEWER/REVIEWER/ADMIN grant. Fix: store `user_id` in `members` and match on it.

### L-5 LOW - input validation gaps
- Reason of five zero-width characters (`\u200b`) accepted (core.js:48, `trim()` doesn't strip U+200B) -> effectively empty justification recorded in the audit (test: HTTP 200). Fix: require >=5 chars after `\p{Cf}`/`\s` stripping.
- Submission paths: `rules/%2e%2e/x.yar`, RTL override `\u202E`, newline, NUL, `rules//x`, `./x`, `C:/x` are accepted (core.js:57); rendered with textContent so no XSS, but they can spoof names in UI and logs. `..` check also rejects benign `a..b`. Fix: allow-list `^[A-Za-z0-9._\-/]+$`, segment-wise no `.`/`..`/empty.
- `metrics`, `reasons` string lengths, `depends_on`, `commit`, `bytes`, `tag`, `run_url`, `reason` (revalidation) are unvalidated: a 5 MB `metrics` object was accepted and stored; body size is bounded only by the platform (100 MB) before parsing. members `login` as array -> 500 (index.js:93-94 `b.login.toLowerCase`). Fix: schema-validate, cap field lengths, cap `Content-Length`.
- Duplicate JSON keys: last wins (JSON.parse), confirmed not a bypass (test "dup keys" -> action `reject` validated as given). Not a finding.

### L-6 LOW - pipeline writes are not atomic and not individually audited
- store.js:121-134 `pipelineEvent`: per-row UPDATEs in a loop then one audit row (counts only, no hashes); a failure mid-way leaves a partial state change and a 500. States changed by the pipeline (released/revalidation_failed) have no `decisions` row, so the per-candidate history (`getCandidate`) shows no entry for RELEASED/demotion. store.js:36 submit loop: invalid base64 -> 500 after the candidate row is inserted; a bad item after good ones -> 400 but earlier items stay ("FINDING SUBMIT-PARTIAL"). Fix: one `db.batch` per call with audit including hashes; validate all items first; decode base64 before insert.

### L-7 LOW - audit immutability is detection-only; tail truncation undetectable
- schema.sql:46-59 has no triggers forbidding UPDATE/DELETE on `audit`/`decisions`; `verifyChain` (core.js:76-85) cannot detect deletion of the newest entries (no external head anchor). Fix: `CREATE TRIGGER ... BEFORE UPDATE/DELETE ... RAISE(ABORT)`, and periodically commit the head hash to the repo/transparency log (the project already has tlog.py).

### L-8 LOW - client (scripts/quarantine_client.py)
- Accepts `http://` QUARANTINE_URL and sends the OIDC bearer over it (no scheme check, line 13/27); urllib follows redirects and re-sends `Authorization` to the redirect target. The token is audience-bound and short-lived, so impact is low. Fix: require https and install a no-redirect opener.
- `build_submissions` reads `dist/<path>` with no containment check (line 38); a path like `../../secret` or an absolute path (pathlib join replaces the base) would be base64-uploaded to the service. Paths come from the repo's own classification so not currently attacker-controlled. Fix: `resolve()` and assert it stays under `dist`.
- `submit` sends all candidates (up to thousands, each up to 1 MB content) in one request (line 60): 100 MB Worker body cap and the server's 2000-item cap make large first runs fail as "quarantine UNAVAILABLE" (fail-safe, but silent loss of review data). Fix: chunk by 50-100 items.
- Failure of `released`/`failed` only prints and exits 0 (by design, documented): service state can drift from reality; consider a retry step.

### L-9 LOW - no rate limiting anywhere; HSTS minimal
- No rate limit in code or wrangler.toml for /auth/*, /api/*, pipeline endpoints. Only mitigations are GitHub auth and CF platform defaults. Fix: Cloudflare WAF rate-limiting rules for /auth/login, /auth/callback and /api/decisions. HSTS lacks `includeSubDomains` (cosmetic).

## Checked and OK (tests pass; documented so they are not re-audited)
- Route x role matrix on all 9 session routes + 4 pipeline routes for anon / no-role GitHub user / VIEWER / REVIEWER / ADMIN: all as designed ("route x role matrix" test). Role is checked server-side before id lookup (no existence oracle). Pipeline routes reject human cookies (401). `submit` only daily.yml, `released` only publish.yml; aud-array, PR ref, similarly-named workflow, `alg:none` tokens refused.
- CSRF: unsafe methods require same-origin `Origin` AND per-session `X-CSRF-Token` (timing-safe); cookie `__Host-` prefix, HttpOnly, Secure, SameSite=Strict, Path=/, no Domain; no state-changing GET except the audit write in M-3. Malformed/uppercase/duplicated cookies -> 401; expiry boundary exact; logout deletes server-side row; new session id on every login (no fixation).
- Batch atomicity: stale or invalid member makes the whole batch 409 with nothing changed; duplicate ids (also case variants) and wrong `confirm_count` rejected; concurrent approve vs reject: loser changes nothing (pre-existing test + mine).
- SQL injection: all statements parameterised; `q`/`state`/`source` probes inert; the only interpolated pieces are `?` placeholder lists and a fixed `WHERE` clause.
- Headers: CSP default-src 'none', nosniff, no-store, no-referrer, COOP on all responses including 404/OPTIONS/302; no CORS headers emitted; generic 500 message, no stack/SQL leakage.
- XSS: admin.js builds DOM with textContent (only mention of "innerHTML" is none; grep clean); CSP blocks inline script anyway. The harness has an `onerror` payload candidate and its test passes.
- Leak to public outputs: client sends only to QUARANTINE_URL; make_public_candidate.py exports approved files + aggregate stats only (reviewer names/reasons are not copied; `waived-by-review` detail with the reviewer login stays in dist/decision.json which is not uploaded as an artifact - only `dist-public/`). `/public/stats` returns four counts. Not audited: dynamic_gate.py prints `reasons` to stderr (workflow log of a public repo) - out of scope, worth a look.

## Discarded / by design (not findings)
1. Reviewer can approve alone (no 4-eyes): policy choice, mention only.
2. Humans cannot revoke a RELEASED rule (only pipeline revalidation can): design gap, no bypass. An emergency "pull" would need a pipeline-side path.
3. `access.view` audit on GET: intentional (flagged only for its volume, M-3).
4. `/api/me` returns the CSRF token: same-origin GET, needed by the SPA.
5. GITHUB token stored in D1: needed for the permission re-check; flagged under M-4 for retention only.
6. OAuth scope `read:user` is minimal; repo permission read works only because the repo is public.
7. `Origin` missing -> 403: strict but correct for non-browser callers.
8. Replay of a pipeline token inside its lifetime: low value (same repo, same endpoints idempotent); folded into L-2.
9. Role downgrade of an ADMIN by another ADMIN is possible except self - intended.
10. `released` called by daily.yml refused, but `revalidation-failed` may be called by either workflow - intended (README/test).
11. `HEAD` requests to /api fall to 404 and do not execute handlers.

## Adversarial tests written
`/private/tmp/claude-501/-Users-dmuino-Downloads-macguard-yara-channel/82cd2f90-db22-4237-8d88-d9b30daab0c1/scratchpad/wt-admin-tests/adversarial.test.js` (18 tests): route x role matrix; pipeline workflow scoping/alg-none/aud-array/ref; OIDC aud fail-open; decisionsMap collision; blob unverified; partial submit; request_id replay with another action; audit fabrication race (gate-delayed audit read); view-audit spam; unauth state growth; login CSRF + cookie flags; permission revoke window; human/pipeline state machine incl. REJECTED/RELEASED terminality; batch atomicity; unicode/dup-key/huge-body/path inputs; SQLi probes; headers/CORS/CSRF/error leakage; cookie/session expiry. Imports from `../wt-admin/admin/worker/` (override with `WORKER_DIR=file:///.../admin/worker/`); the worktree was removed, recreate it with `git worktree add <dir> aa8fa2a --detach` to re-run.

## NOT RUN
- Real Cloudflare D1 / Workers runtime (not deployed; forbidden): D1 parameter limit (M-5), CPU/memory limits on verify (M-3), real SQL planner order for `decisionsMap` (H-1), `request.cf`/rate limiting behaviour.
- Real GitHub OAuth/OIDC endpoints (mocked by the harness); JWKS key rotation/caching.
- Browser UI test (`test/run_ui_check.sh`, ui_e2e.js): needs a browser/port; not executed, UI reviewed by reading admin.js only.
- Python scripts were read, not executed (decide.py end-to-end with the H-1 data is argued from the code at decide.py:39-45, not run).
- Load/DoS on the shim, dynamic_gate.py and make_public_candidate.py beyond a read (outside scope).
