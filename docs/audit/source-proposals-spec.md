# Propose a source from the admin panel: design specification (V1.1)

Status: **PROPOSAL, design only.** Nothing here is implemented, deployed or applied. No D1 command, `wrangler` call, token creation or GitHub write was run to produce this document. Every statement about current behaviour cites `file:line` in this repository (state at `cc37633`); every statement that starts with "Proposal" is a design proposal. Owner decisions D1-D7 of 2026-10-21 are recorded and applied in section 16.1; what is still open is in 16.2 and 16.3. No current source is changed and no new source is activated by this document.

Privacy: this document names no real quarantined rule, path, hash or reason. Examples use `acme/yara-feed` (fictitious).

## 0. Owner requirements (both mandatory, both drive every choice below)

* R1. The panel must **not** put an arbitrary repository directly into the publication process. A new source reaches the daily run only through a merged change to `config/sources.json` (and `config/policy.json`) on `main`, reviewed by a human.
* R2. The Worker must **not** get general write permission on GitHub. Target of this design: the Worker holds **no GitHub write credential of any kind**.

## 1. What exists today (verified)

| Fact | Evidence |
|---|---|
| The only source list is `config/sources.json`: `{id, repo, kind, paths}`; kinds `rules` and `engine`. | `config/sources.json:3-7` |
| `prepare.py` reads that file and nothing else to decide what to fetch. | `scripts/prepare.py:7`, `:52` |
| For each source it queries the newest commit (`commits/HEAD`) on `api.github.com`, then downloads the tarball of **that exact commit**. There is **no per-source pin in config**: upstream HEAD is followed every day and the commit is only recorded. | `scripts/prepare.py:54-56`, `:63` |
| Download cap 90 MB, 25,000 archive entries, symlinks/hardlinks/devices/absolute and `..` members refused, per-file cap 1,000,000 bytes, NUL bytes refused, only `.yar`/`.yara` under the declared `paths`, 3 attempts with back-off, 40 s timeout. | `scripts/prepare.py:8`, `:28`, `:32-33`, `:43-47`, `:68-73` |
| The GitHub token is attached only for host `api.github.com` and is stripped on any redirect to another host. | `scripts/prepare.py:13-24` |
| `engine` sources contribute no files. | `scripts/prepare.py:62` |
| The licence check calls `GET /repos/{repo}/license` and hashes the text; `verdict()` compares with `policy.licenses[repo]` (`expected_spdx`, `expected_marker`, optional pinned `sha256`). **A source with no policy entry gets `ok:false, "no licence policy for this source"`.** | `scripts/licensing.py:6-22`, `scripts/prepare.py:57-60` |
| A failed licence check adds finding `license-changed` (severity `review`) to **every file of that source**. `license-changed` is **not** in `WAIVABLE`, so no approval in the panel can waive it. The pipeline mirrors the list and a test keeps both identical. | `scripts/rulecheck.py:147-148`; `scripts/decide.py:15`; `admin/worker/src/core.js:27-28` |
| Consequence (verified by reading, not run): a repository added to `sources.json` **without** a `policy.json` licence entry is fully quarantined and cannot be approved by a reviewer. The licence entry in `policy.json` is today the de-facto admission gate. | same lines |
| **Verified gap:** once such an entry is merged and the licence verdict is `ok`, the new source's files are admitted by the **same automatic gates as any other file** (static classification, benign-corpus hit rate, dynamic gate with `new_or_changed` measured, anomaly gate). There is **no "first sight of a new source" hold**. | `scripts/rulecheck.py:131-181`; `scripts/decide.py:21-60`; `scripts/dynamic_gate.py:47`, `:83` |
| Anomaly gate: a run that removes >15% or touches >40% of the previous release is not publishable until a person re-runs with `allow_large_change`. A large new source can trip it; a small one will not. | `config/policy.json:75-79`; `scripts/decide.py:76-79`; `.github/workflows/daily.yml:9-13` |
| Roles: VIEWER (explicit grant), REVIEWER (GitHub `write`/`maintain`), ADMIN (GitHub `admin`). The role is recomputed from GitHub on every state-changing request (`fresh`). | `admin/worker/src/core.js:2-14`; `admin/worker/src/index.js:85`; `docs/OPERATIONS.md:3-9` |
| State-changing calls need same-origin `Origin` and the per-session CSRF token. Strict CSP, `textContent` only. | `admin/worker/src/index.js:8-11`, `:89-92`; `docs/OPERATIONS.md:12-17` |
| Pipeline-to-Worker calls authenticate with GitHub Actions OIDC (RS256, issuer, audience, `repository`, `ref == refs/heads/main`, `job_workflow_ref` in an allow-list `PIPELINE_WORKFLOWS`). No shared secret. | `admin/worker/src/auth.js:114-129`; `admin/worker/wrangler.toml:15` |
| **The Worker has no outbound GitHub write, and a test pins that**: the sources of `index/core/store/auth` must not match `dispatches|/actions/|workflow_dispatch|repository_dispatch` and the only non-GET `deps.fetch` allowed is the OAuth code exchange. | `admin/worker/test/service.test.js:388-393` |
| Outbound fetches the Worker makes today: `api.github.com` (role lookup, account lookup, release/manifest, ops overview), `raw.githubusercontent.com` (log, `sources.json`), the public site `stats.json`, `github.com/login/oauth/access_token`, and the OIDC JWKS. Hosts come from env vars (`GITHUB_API`, `GITHUB_RAW`, `PUBLIC_SITE`, `GITHUB_OAUTH_BASE`, `OIDC_JWKS`), never from a request. | `admin/worker/src/auth.js:64`, `:82`, `:103-106`, `:118`; `admin/worker/src/ops.js:83`, `:98`; `admin/worker/src/publication.js:27` |
| The Worker already reads `config/sources.json` from `main` for the Sources view (read-only). | `admin/worker/src/ops.js:72-75`, `:98`; view `admin/worker/public/views/sources.js` |
| The OAuth scope requested is `read:user`; the admin's token is already used to give the ops overview 5,000 req/h instead of 60 anonymous. | `admin/worker/src/auth.js:96`; `admin/worker/src/ops.js:81` |
| Audit is hash-chained and append-only (`RAISE(ABORT)` triggers on update/delete); decisions are idempotent by `request_id`; migrations come as `NNNN_name.sql` + `NNNN_rollback.sql`. | `admin/worker/schema.sql` (audit, decisions, triggers); `admin/worker/src/store.js:8-20`, `:105-148`; `admin/worker/migrations/0002_*.sql` |
| Docs must list every source: a Python test asserts each `repo` of `sources.json` appears as `` `owner/repo` `` in `docs-src/{es,en}/sources.md`. A PR that adds a source without docs rows therefore fails `python-tests`. | `tests/test_docs.py:212-218` |
| Required checks on `main` (proposed ruleset, **not applied**): `python-tests`, `quarantine-service`; **0 approvals**, code-owner review off; **bypass: GitHub Actions app, always**. There is **no `CODEOWNERS` file** (`.github/` holds `dependabot.yml` and `workflows/` only). | `docs/audit/repo-hardening/ruleset-main.json:6-8`, `:14-26`; `docs/audit/repo-hardening/IMPACT.md:3,12`; `ls .github` |
| Today's real state of `main` protection: no rulesets, classic protection without required checks or reviews, `enforce_admins:false` (read-only check 2026-10-19). | `docs/audit/repo-hardening/IMPACT.md:3`; `docs/audit/SECURITY-FINDINGS.md` FA-28 |
| `ci.yml` runs on `pull_request` and `workflow_dispatch`, `permissions: {}` at top, `contents: read` per job, no secrets. | `.github/workflows/ci.yml:5-17` |
| `daily.yml` job `review` has `contents: write` (logs commit) and `id-token: write`; `request-publish` uses `actions: write` to dispatch `publish.yml`. | `.github/workflows/daily.yml:27-31`, `:218-231` |

## 2. Scope of this feature

In scope: add, modify (change `paths`) and remove a **rules** source hosted on `github.com`. Out of scope for V1.1: `engine` sources, hosts other than `github.com` (GitLab, Codeberg, self-hosted), archives or URLs that are not repositories, private repositories, automatic merge, automatic bumping of pins.

The panel is a **front door for a reviewed pull request**, not a second control plane: it never edits `main`, never triggers a pipeline, never publishes.

## 3. End-to-end flow

```
ADMIN form ──▶ Worker: syntax check ──▶ D1 proposal (proposed)
                    │
                    ▼ ADMIN presses Verify (network, fixed hosts, section 5)
              verified | rejected          (findings, evidence, licence text hash, commit)
                    │
                    ▼ ADMIN reviews exact diff + acknowledges warnings + types owner/repo
              approved_for_pr             (payload and payload_sha256 frozen)
                    │
   (pull model, section 7)  GitHub Actions workflow source-proposals.yml, scheduled / manual,
   authenticates with OIDC, GETs approved payloads, re-validates with repo code, opens PR
                    │
              pr_open ──▶ mandatory CI + CODEOWNERS review by a human (section 9)
                    │
         merged by a human on main ──▶ workflow reports; Worker re-reads main itself
                    │
               merged (in force)  ──▶ next daily run fetches it, ALL existing gates apply (section 10)
                         ▲
              retired (removed or replaced by a later merged change)
```

Nothing before "merged" can influence `prepare.py`: it reads `config/sources.json` from the checked-out `main` (`daily.yml:36-38` checks out `github.ref_name`, `scripts/prepare.py:7`).

## 4. Form "Propose source" (UI contract)

Visible only to ADMIN (the API enforces it regardless of the UI, as `index.js:127` does for members).

| Field | Rule |
|---|---|
| GitHub repository URL | Required. Parsed locally with `new URL()`; accepted shape **only** `https://github.com/{owner}/{repo}` with optional `.git` and optional single trailing `/`. Rejected: any other scheme, any other host (including `www.github.com`, IP literals, punycode, userinfo, explicit port, query, fragment, extra path segments, percent-escapes). `owner` matches `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`; `repo` matches `^[A-Za-z0-9._-]{1,100}$` and is not `.` or `..` and does not end in `.git` after stripping. |
| Source id | Suggested from `repo` lower-cased; editable; `^[a-z0-9][a-z0-9-]{1,31}$`; unique against `sources.json` and open proposals. It becomes a directory name (`scripts/prepare.py:74`), so nothing else is accepted. |
| Kind | Fixed `rules` (read-only field). |
| Paths | 1-20 entries, each `^[A-Za-z0-9._][A-Za-z0-9._/-]{0,99}$`, no `..` segment, no leading `/`, no `//`. At least one is required because `prepare.py:70` keeps nothing when `paths` is empty. |
| Reason | 5-2000 visible characters (same rule as `index.js:142`). Stored and audited; **never copied into the PR**. |
| After verification | The panel shows findings, evidence, and the **exact unified diff** of `config/sources.json`, `config/policy.json`, `docs-src/*/sources.md`. Warnings need an explicit tick each; approval needs the admin to type `owner/repo`. |

Everything is rendered with `textContent` (CSP `script-src 'self'`, `index.js:9`).

## 5. Verification (URL, repository, source type, licence) and SSRF containment

### 5.1 Principle

**No URL supplied by a person is ever fetched.** The URL is parsed and reduced to `(owner, repo)`; the Worker then builds request URLs from the **constant** host `https://api.github.com` (env `GITHUB_API`, as `publication.js:27`) plus validated path components. There is no code path in which a user string reaches the host part of a request.

### 5.2 Exact outbound requests (at most 5 per verification, all `GET`)

| # | Request | Used for | Response cap |
|---|---|---|---|
| F1 | `https://api.github.com/repos/{owner}/{repo}` | exists, public, `id`, canonical `full_name`, `fork`, `archived`, `disabled`, `private`, `size` (KB), `default_branch`, `created_at`, `pushed_at`, `owner.type`, `license.spdx_id` | 256 KB |
| F2 | `https://api.github.com/repos/{owner}/{repo}/license` | licence text (base64), `spdx_id`; same endpoint as `scripts/licensing.py:20` | 512 KB |
| F3 | `https://api.github.com/repos/{owner}/{repo}/commits/HEAD` (same form as `scripts/prepare.py:54`) | 40-hex commit SHA, `commit.verification.verified` (informational) | 256 KB |
| F4 | `https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1` with `{sha}` = the 40-hex from F3 | count `.yar/.yara` under the proposed paths, per-file sizes, other `LICENSE*`/`COPYING*` files inside the paths, `truncated` flag | 5 MB |
| F5 | `https://api.github.com/users/{owner}` | account `created_at`, `type` (informational trust signal) | 64 KB |

Headers: `Accept: application/vnd.github+json`, `User-Agent: macguard-admin`, `Authorization: Bearer <admin's own OAuth token>` (opened with `openToken`, `index.js:110`; the same pattern as `ops.js:81`). The token is therefore sent **only** to `api.github.com`; it is never sent on a redirect (see 5.3), never logged and never stored in a proposal.

Not fetched, ever: the tarball or `codeload.github.com`, `raw.githubusercontent.com` for the candidate repo, any rule content, any URL found inside F1-F5 responses (`html_url`, `clone_url`, `tarball_url`, `homepage`, README links are ignored).

### 5.3 Allow-list, redirects, limits, refusals

* **Allow-list:** exactly one host, `api.github.com`, scheme `https`, default port, path prefix `/repos/` or `/users/`. Checked with a function `assertAllowedUrl(u)` that is called immediately before every `fetch` and compares `URL.protocol`, `URL.hostname`, `URL.port`, `URL.username/password` (must be empty) and path prefix; a failure aborts the verification with `SSRF_GUARD` and writes an audit event.
* **Redirects:** `fetch(url, { redirect: 'manual' })` on every call (`redirect: 'error'` is not relied on). A 3xx is **never followed**, with one exception: a `301` from F1 whose `Location` matches `^https://api\.github\.com/repositories/[0-9]{1,12}$` is recorded as finding `RENAMED` (block: "repository was renamed or transferred; propose the canonical name") and not followed. Any other 3xx, any `Location` to another host or to an IP literal: finding `REDIRECT_REFUSED` (block).
* **Timeouts:** 10 s per request (`AbortSignal.timeout(10_000)`, as `publication.js:21`), 25 s total deadline per verification. No retry loops beyond one retry on 5xx (publication.js retries on 404 because a release may be propagating; a proposal has no such case).
* **Size:** body read through a counting reader; a response above its cap is aborted: `RESPONSE_TOO_LARGE` (block). `Content-Length` is a hint only.
* **Content type:** must be `application/json`; anything else is `UNEXPECTED_CONTENT` (block). The Worker parses JSON only; it never renders or executes anything from the response.
* **Rate limit:** an ADMIN may run at most 10 verifications per hour (counted from `source_proposal_events`); GitHub's own `x-ratelimit-remaining` is recorded; at 403/429 the verification ends `SOURCE_UNAVAILABLE`, which is not a rejection and not a pass.
* **Internal resources:** the request set above contains no hostname that can resolve to a private, loopback, link-local or metadata address, because the only host is a constant. DNS rebinding therefore has nothing to rebind. As defence in depth, not as the control: Cloudflare Workers `fetch` goes out through Cloudflare's network, not from inside a customer VPC, and cannot address RFC 1918 space unless a tunnel/VPC binding is configured (none is, `admin/worker/wrangler.toml`). **Not claimed as proven**: the platform behaviour should be confirmed in the workerd runtime test (section 12, T-S6).
* **Refused outright:** non-GitHub hosts; private repositories (`private:true`, or F1 answering 404 to an authenticated request, which GitHub also returns for private repositories the token cannot see); forks (`fork:true`, with the `parent` full name shown so the admin can propose the canonical upstream); archived or disabled repositories; `size` above 90,000 KB (conservative proxy for the 90 MB archive cap at `prepare.py:8`, which is compressed; value to be calibrated, OPEN DECISION 9); a `truncated:true` tree or more than 25,000 entries (`prepare.py:43`); zero rule files under the proposed paths; a `Location` header as above.

### 5.4 Source-type verification

* `kind` is always `rules`. A repository is accepted as a rules source only if F4 shows at least one `.yar`/`.yara` blob under a proposed path. Individual files above 1,000,000 bytes (`policy.json:5`, `prepare.py:72`) are counted and shown as "will be skipped", not as an error.
* Path overlap with an existing source is a warning (`PATH_OVERLAP`) only if the repo is the same; different repos with identically named files are allowed (rules are namespaced by `source` id in the output path, `prepare.py:74`).
* The Worker never judges rule content. Content is judged only by the existing pipeline after merge (section 10).

### 5.5 Licence verification

Reuses the existing semantics rather than inventing new ones:

1. F1 `license.spdx_id` and F2 `license.spdx_id` must agree (`LIC_MISMATCH` block if not).
2. F2 text is decoded and its SHA-256 computed exactly as `licensing.verdict` does (`licensing.py:8`, UTF-8 with replacement) and stored as `license_sha256`.
3. The SPDX id is looked up in a **licence allow-list kept in the repository** (Proposal: `config/license-allowlist.json`, reviewed in a PR like everything else). Result: `allowed` (policy entry proposed with `expected_spdx`, `spdx`, `redistribution`), or `needs_legal` (`NOASSERTION`, `null`, unknown id, custom licences such as the Nextron one that need `expected_marker`; the proposal may continue but the policy entry cannot be generated automatically and the admin must supply `expected_marker` and `redistribution` text, shown in the diff), or `denied` (e.g. `redistribution` not permitted: block).
4. The generated `policy.licenses[repo]` entry **includes `sha256` of the licence text**, a field `licensing.verdict` already honours (`licensing.py:15-16`): any later edit of the LICENSE text produces `license-changed`, a non-waivable finding for every file of that source (`rulecheck.py:147-148`). This is what turns "licence spoofing by later edit" into a quarantine.
5. Findings (warn): extra `LICENSE*`/`COPYING*` files inside the proposed paths (`EXTRA_LICENSE_FILES`); GitHub licence detection reads the repository root only, so per-file headers are **not** checked by anything in the pipeline today. Stated as residual risk (section 11).

Whether a licence is legally acceptable for redistribution inside a signed release is a legal/product decision, not a technical one: OPEN DECISION 4.

## 6. Provenance and trust-policy check

All items are **evidence recorded with the proposal**, with a severity; none is a substitute for the PR review.

| Code | Check | Severity |
|---|---|---|
| `DUPLICATE` | same `repo_id` (immutable GitHub numeric id) or same lower-cased `owner/repo` as an existing `merged` or open proposal, or already in `sources.json` | block |
| `LOOKALIKE` | normalised name (lower-case, `-_.` removed) equal, or Levenshtein distance <= 2 on owner or on `owner/repo`, to any existing source or to entries of `config/known-sources.json` (Proposal: a reviewed list of recognised upstream organisations) | warn, needs a tick |
| `FORK` / `ARCHIVED` / `DISABLED` / `PRIVATE` | F1 flags | block |
| `YOUNG_REPO` | `created_at` younger than 90 days (Proposal value, OPEN DECISION 5) | warn |
| `YOUNG_ACCOUNT` | owner `created_at` younger than 180 days | warn |
| `STALE` | `pushed_at` older than 24 months | warn |
| `UNVERIFIED_HEAD` | HEAD commit not GitHub-verified-signed | info |
| `LOW_ADOPTION` | stars/forks shown, no threshold applied (popularity is not trust) | info |
| `EXTRA_LICENSE_FILES`, `LIC_*` | section 5.5 | warn / block |
| `TREE_TRUNCATED`, `NO_RULE_FILES`, `TOO_BIG` | section 5.3 | block |
| `RENAMED`, `REDIRECT_REFUSED`, `SSRF_GUARD`, `RESPONSE_TOO_LARGE`, `UNEXPECTED_CONTENT` | section 5.3 | block |
| `SOURCE_UNAVAILABLE` | GitHub rate-limited or unreachable | neither pass nor fail; verify again |

Any `block` moves the proposal to `rejected` (reason code stored). Warnings leave it `verified`; approval requires each warning code in the `acks` array. A verification result expires after 24 h: `approve` refuses a stale one (409) so the licence hash and commit shown are recent.

## 7. Creating the pull request with minimum privilege (the central section)

### 7.1 Why the choice matters

The Worker is internet-facing, holds sealed GitHub OAuth tokens of its users and a D1 database. Any credential stored in it is exposed to a Worker compromise, a leaked deploy token or a logic bug. R2 says it must hold no general write. The alternatives differ mostly in **who holds a GitHub write credential and for how long**.

### 7.2 Comparison

| | (a) GitHub App, single repo | (b) Fine-grained PAT | (c) Pull model: Actions workflow with `GITHUB_TOKEN`, Worker authenticated by OIDC | (d) No automation: ready-to-paste diff |
|---|---|---|---|---|
| **Who holds a GitHub write credential** | The Worker (App private key, RSA, as a Worker secret; installation tokens minted per use, 1 h) | The Worker (token as a Worker secret, up to 1 year) | **Nobody outside GitHub.** The workflow gets an ephemeral `GITHUB_TOKEN` per run. The Worker only holds the **verifier** side of OIDC (JWKS), already deployed | Nobody. A human uses their own session |
| **Exact permission set** | Repository permissions: `Contents: Read and write`, `Pull requests: Read and write`, `Metadata: Read` (implicit). Explicitly **not** granted: `Workflows`, `Administration`, `Actions`, `Secrets`, `Issues`, `Pages`, `Environments`. Installed on this one repository only | Fine-grained, one repository: `Contents: Read and write`, `Pull requests: Read and write`, `Metadata: Read`. Same list as (a) but bound to a **person** (acts as that user, with that user's role, e.g. admin/bypass) | Job-level `permissions: { contents: write, pull-requests: write, id-token: write, actions: write }`. `contents: write` is the one GitHub needs to push a branch; `actions: write` only to start `ci.yml` on the new branch (7.5). Everything else `none` | none beyond the human's own |
| **Can it be limited to a branch namespace?** | **No.** GitHub App permissions are repository-wide; "only `proposal/*`" can be enforced only by a **ruleset** that denies the App everything else, and rulesets are evaluated against what the App does, not what it promises | No, same as (a) | Not by the token either, but the **code that uses the token** is a file on `main` (CODEOWNERS-protected) that pushes only `refs/heads/proposal/<id>` and nothing else; the token never leaves the runner | n/a |
| **Blast radius if the credential leaks** | Anyone with the key can push to every branch the ruleset allows and open/close PRs until the key is rotated; can read all repository contents; can create tags unless a tag ruleset blocks it (`ruleset-release-tags.json` blocks `rules-*` and `v*` only). Cannot edit `.github/workflows/*` (no `workflows` permission; GitHub refuses such pushes) but **can alter `scripts/` and `config/`** on a branch, which `python-tests` would execute in CI on a PR | Same as (a) plus it acts as a human: if that human is the owner/admin the PAT inherits admin and any bypass. A PR authored by the owner cannot be approved by the owner (no second reviewer in a one-owner repository) | The token lives about the duration of one job, is not retrievable from any store, and exists only in a run of a workflow file that was merged to `main`. There is nothing for a Worker compromise to steal | none |
| **Secret handling** | New long-lived secret in the Worker (`wrangler secret`); rotation procedure needed; the deploy token that can read Worker secrets becomes more valuable; violates "no secret in repo/log" only if mishandled | Same, and expiry forces a calendar chore; a PAT is easier to over-scope by mistake | **None added.** OIDC needs no stored secret (`docs/OPERATIONS.md:24`); the only new thing is one entry in `PIPELINE_WORKFLOWS` (`wrangler.toml:15`) | none |
| **Conflict with existing invariants** | Breaks `service.test.js:388-393` (the test forbids any non-GET `fetch`). The test would have to be loosened, i.e. the invariant "the Worker has no outbound write" ends | Same | **Preserves it**: no change to the test; the Worker only gains new `GET`/`POST` endpoints for the pipeline, like `submit`/`released` (`index.js:35-56`) | Preserves it |
| **How the Worker "triggers" the workflow** | Directly (API) | Directly (API) | **It does not.** It cannot: `repository_dispatch` needs a token with Contents write and `workflow_dispatch` needs Actions write, i.e. exactly the credential we want the Worker not to have. So the workflow **pulls** on a schedule or on a human click (`workflow_dispatch`) | A human copies the diff |
| **Failure modes** | Key expiry/rotation outage; App suspended; ruleset mis-scope lets the App write elsewhere; installation token over-scoped by mistake | Token expiry silently stops PRs; token leak = person leak | Latency: up to one schedule interval (Proposal: hourly) or a manual run; `GITHUB_TOKEN` PRs do not start `pull_request` workflows (7.5); repo setting "Allow GitHub Actions to create and approve pull requests" must be enabled; the GitHub Actions app is a **bypass actor on `main`** (7.6) | Slowest, most error-prone (hand-edited JSON, forgotten docs rows, forgotten licence entry), but zero new attack surface |
| **Meets R1 / R2?** | R1 yes (with CODEOWNERS). **R2 no**: the Worker holds write on contents | R1 yes. **R2 no** | R1 yes. **R2 yes** | R1 yes. R2 yes |

### 7.3 Decision and phases

**Decided by the owner (2026-10-21): the Worker gets NO general GitHub write permission. The pull model (c) is adopted; (d) is phase 1.** Reasons are in 7.2: no GitHub write credential outside GitHub, no stored secret, the invariant test `service.test.js:388-393` stays true unchanged, and the Worker reuses the OIDC pipeline pattern (`auth.js:114-129`, `index.js:26-58`). (a) and (b) are rejected because they place a contents-write credential in the Worker.

**Phase 1: manual PR, no new GitHub credential anywhere.** Deliverables:

| # | Deliverable | Notes |
|---|---|---|
| P1-1 | `admin/worker/migrations/0003_source_proposals.sql` + `0003_rollback.sql`; same tables appended to `admin/worker/schema.sql` | section 13 |
| P1-2 | `src/sourceproposals.js` (pure: URL parse, `assertAllowedUrl`, verification, findings, state machine) and store functions with one D1 `batch` per transition | no I/O in the pure part, like `core.js` |
| P1-3 | Endpoints `GET/POST /api/source-proposals`, `/verify`, `/approve`, `/reject`, `GET /patch`, `POST /pr-link`, `POST /refresh` (section 8) | the Worker still has no non-GET `fetch` except the OAuth exchange |
| P1-4 | UI view `public/views/source_proposals.js` + es/en strings; form of section 4 | CSP unchanged (`index.js:9`) |
| P1-5 | `scripts/source_proposal.py` with `validate`, `apply`, `gate` | the **same** code renders the patch shown to the admin and (phase 2) the PR commit, so what was approved is byte-identical to what is proposed |
| P1-6 | `GET /api/source-proposals/{id}/patch` returns the unified diffs of `config/sources.json`, `config/policy.json`, `docs-src/{es,en}/sources.md`, plus a command block: `git switch -c proposal/<id>-<hash8> origin/main`, `git apply`, `git push origin HEAD:refs/heads/proposal/<id>-<hash8>`, `gh pr create --base main --body-file <template>` | the human opens the PR |
| P1-7 | `POST /api/source-proposals/{id}/pr-link` (ADMIN, `{pr_number}`): the Worker GETs `https://api.github.com/repos/{REPO}/pulls/{n}` and `.../pulls/{n}/files` (fixed host, same guard) and accepts only if base is `main`, head is in the same repository (not a fork), head ref is `proposal/<id>-<hash8>`, and the changed files are a subset of the four template files; `approved_for_pr -> pr_open` | the Worker reads, never writes |
| P1-8 | `POST /api/source-proposals/{id}/refresh` (ADMIN): re-reads the PR (closed unmerged -> `pr_closed`) and, for a merged PR, `config/sources.json` of `main` from `raw.githubusercontent.com` (precedent `ops.js:98`); `merged` only if the entry equals the frozen payload | same check as 7.4 step 9 |
| P1-9 | Tests T-S*, T-V*, T-A*, T-D* of section 12 | |

**Phase 2: the pull workflow** (7.4). Deliverables: `.github/workflows/source-proposals.yml`, pipeline endpoints (`GET /api/pipeline/source-proposals`, `POST .../{id}/pr`, `POST .../{id}/sync`), `source-proposals.yml` added to `PIPELINE_WORKFLOWS` (`wrangler.toml:15`, default list in `auth.js:127`), environment `source-proposals` restricted to `main`, repository setting "Allow GitHub Actions to create and approve pull requests", tests T-P*. **Entry criteria:** (i) the ruleset and CODEOWNERS delta of section 9 verified on the sandbox repository by the procedure in 9.6; (ii) T-P5 (CI attaching to a dispatched run) passed; (iii) the `new-source` first-run quarantine of section 10.2 implemented and tested, so that a merged proposal cannot contribute rules without an ADMIN decision.

### 7.4 Specification of the workflow (Proposal, `.github/workflows/source-proposals.yml`)

* Triggers: `schedule` (hourly) and `workflow_dispatch` only. Never `pull_request`, `issue_comment`, `repository_dispatch`.
* Permissions: top-level `permissions: {}`; job `open-prs`: `contents: write`, `pull-requests: write`, `actions: write`, `id-token: write`.
* Environment `source-proposals` restricted to the `main` branch (Settings, Environments, "Deployment branches"). Additionally the Worker refuses any OIDC token whose `ref` is not `refs/heads/main` or whose `job_workflow_ref` is not `.../source-proposals.yml@refs/heads/main` (`auth.js:126-128`), so a copy of the workflow dispatched from a feature branch gets no payload.
* Steps (each uses a repo script, not inline shell; values pass via `env:`, never `${{ }}` inside `run:`, per FA-21 in `SECURITY-FINDINGS.md`):
  1. `GET $QUARANTINE_URL/api/pipeline/source-proposals` with the OIDC bearer: returns `approved_for_pr` proposals `{id, version, payload, payload_sha256}`.
  2. `scripts/source_proposal.py validate`: **re-validates from scratch** with code reviewed in the repo (schema, regexes of section 4, `payload_sha256` recomputed, id not already in `sources.json`, repo not already present, licence entry shape). The Worker's checks are not trusted; a mismatch aborts that proposal and reports `invalid_payload`.
  3. `scripts/source_proposal.py reverify`: re-queries `GET /repos/{repo}` and `/license` with `GITHUB_TOKEN` (read) and compares `repo_id`, licence SHA-256 and that HEAD is a descendant of or equal to the verified commit; a licence text change since verification aborts (`stale_evidence`).
  4. `scripts/source_proposal.py apply`: edits `config/sources.json` (append one object, preserving the one-line-per-source layout of the file), `config/policy.json` (`licenses[repo]` entry) and the two `docs-src/*/sources.md` rows from a fixed template, using `json.dumps` and fixed strings. No free text from the proposal is written anywhere.
  5. `git switch -c proposal/<id>-<payload_sha256[:8]>`; `git push origin HEAD:refs/heads/proposal/<id>-<hash8>` (explicit refspec, no force, no tags).
  6. `gh pr create --base main --head proposal/... --title "<fixed template with validated id and owner/repo>" --body-file <generated from template>`; labels `source-proposal`.
  7. `gh workflow run ci.yml --ref proposal/...` (7.5).
  8. `POST /api/pipeline/source-proposals/{id}/pr` with `{pr_number, pr_url, branch, head_sha, payload_sha256, token_run_id}`; idempotent.
  9. For proposals already `pr_open`: read the PR state with `GITHUB_TOKEN`; `POST .../sync` with `closed_unmerged` or `merged` (+ `merge_commit_sha`). The Worker does **not** take the word of the request: for `merged` it re-reads `config/sources.json` at that commit from `raw.githubusercontent.com` (precedent: `markReleased` verifies against `fetchPublication`, `index.js:49-53`) and accepts only if the entry equals the proposal's payload.
* The workflow never merges, never approves, never enables auto-merge, never touches `main`, tags, releases or secrets.

### 7.5 `GITHUB_TOKEN` and CI

Events created by `GITHUB_TOKEN` do not start `pull_request` workflows (documented GitHub behaviour; **to be re-verified on a throwaway branch before implementation**), so the required checks would stay "pending" forever. Proposal: step 7 dispatches `ci.yml` (it already has `workflow_dispatch`, `ci.yml:5-6`) on the proposal branch; check runs attach to the head commit SHA and so should satisfy the required checks of the PR (**unproven here: to be tested; if not, a human pushes an empty commit or closes/reopens the PR**). The repository setting "Allow GitHub Actions to create and approve pull requests" must be turned on by the owner (OPEN DECISION 2); the workflow itself never approves.

### 7.6 Existing weakness that this design inherits (stated, not hidden)

`ruleset-main.json:6-8` makes the GitHub Actions app a bypass actor **always**, because logs are committed straight to `main` (`daily.yml:27-30`, `IMPACT.md:12`). Consequence: any job holding a `GITHUB_TOKEN` with `contents: write` can write `main` regardless of required reviews, and no ruleset can stop it. A person with write access can already dispatch `daily.yml` from their own branch; the existing exposure is not made larger by this feature, but it does limit what "a proposal PR cannot be merged without a human" can promise against a **malicious insider with write access**. Mitigations in this design: environment restricted to `main`; Worker releases payloads only to `refs/heads/main` runs; CODEOWNERS on `.github/`; the push step uses an explicit `proposal/` refspec. Structural fix (outside this feature): move log commits to a dedicated branch or a dedicated bypass so that the Actions app loses bypass on `main`: OPEN DECISION 3.

### 7.7 What (c) still cannot protect against

* A **legitimate-looking, correctly licensed upstream that later turns hostile or changes**: the proposal is a point-in-time check. After merge the source is followed at HEAD every day (`prepare.py:54`). The protection is the existing gates (section 10), not this feature. A per-source commit pin is a Proposal (section 10.3).
* **Per-file licence differences** inside a repository whose root licence is fine (5.5).
* **Social engineering of the one human** who approves both the proposal and the PR: the two approvals are on different surfaces (panel, GitHub) but may be the same person (OPEN DECISION 6).
* **A compromised admin account or OAuth session**: it can create proposals and approve them; it cannot merge. The PR review and CODEOWNERS are the second barrier.
* **A malicious writer** exploiting the Actions bypass (7.6).
* **Content-level harm that passes the technical gates** (a rule that is valid, cheap, matches clean files rarely, but is wrong): the technical gates measure cost and generic matching, not truthfulness.

## 8. Roles and API (Proposal)

| Role | May |
|---|---|
| VIEWER | nothing on proposals (404 shaped as `no_access`-style 403) |
| REVIEWER (GitHub `write`/`maintain`) | list, detail, diff, events; **create and verify** proposals (owner decision D1: people may propose; reading to confirm, decision 16). Cannot authorise anything: a REVIEWER can already approve rules, but adding a source has a larger blast radius |
| ADMIN | everything REVIEWER may, plus **authorise** (owner decision D2): approve, reject, pr-link, refresh, withdraw, request removal/modification, graduate a source, and approve rules held as `new-source` (10.2) |
| OIDC `source-proposals.yml` on `main` | the pipeline endpoints below, nothing else |

All unsafe verbs inherit: session, CSRF token, same-origin `Origin` (`index.js:82-92`), fresh role check (`index.js:85`), body cap (`index.js:16`; Proposal 20,000 bytes), `request_id` idempotency like decisions, no self-referential privileges. Errors never include response bodies from GitHub.

| Method and path | Role | Effect |
|---|---|---|
| `GET /api/source-proposals?state=&q=&page=` | REVIEWER+ | list |
| `GET /api/source-proposals/{id}` | REVIEWER+ | detail + events |
| `GET /api/source-proposals/{id}/patch` | REVIEWER+ | the exact unified diffs (phase 1 fallback; also what the human reviews before approving) |
| `POST /api/source-proposals` | ADMIN | body `{request_id, action, url, source_id, paths, reason}`: local validation only (section 4), no network; creates `proposed` |
| `POST /api/source-proposals/{id}/verify` | ADMIN | runs section 5/6; `proposed|verified|rejected` -> `verified|rejected`; idempotent per `(id, version)`; rate-limited |
| `POST /api/source-proposals/{id}/approve` | ADMIN | body `{request_id, expect_version, acks[], confirm_repo, reason}`; requires `verified`, verification <= 24 h old, all warning codes acked, `confirm_repo` equal to canonical `owner/repo`; freezes `payload` and `payload_sha256`; -> `approved_for_pr` |
| `POST /api/source-proposals/{id}/reject` | ADMIN | `proposed|verified|approved_for_pr` -> `rejected` (reason >= 5 visible chars); not allowed once a PR exists |
| `POST /api/source-proposals/{id}/withdraw` | ADMIN | `pr_open` -> `pr_closed` bookkeeping only; does **not** close the PR (the Worker cannot); it tells the workflow to close it on its next run (`closing_requested` flag) |
| `POST /api/source-proposals/remove` / `.../modify` | ADMIN | creates a proposal with `action=remove|modify` targeting an in-force source; same flow from `proposed` |
| `GET /api/pipeline/source-proposals` | OIDC `source-proposals.yml` | approved payloads (+ PRs to close) |
| `POST /api/pipeline/source-proposals/{id}/pr` | same | records the PR (`approved_for_pr -> pr_open`), idempotent on `(id, payload_sha256, pr_number)` |
| `POST /api/pipeline/source-proposals/{id}/sync` | same | `merged` (verified by the Worker itself against `main`) or `closed_unmerged` |

Allowed state transitions (everything else answers 409): `proposed -> verified | rejected`; `verified -> verified (re-verify) | rejected | approved_for_pr`; `approved_for_pr -> pr_open | rejected`; `pr_open -> merged | pr_closed`; `pr_closed -> approved_for_pr (re-approve with fresh verification) | rejected`; `merged -> retired` (by a later merged remove/modify, done by the Worker in the same batch as that change). The owner's list (`proposed, verified, rejected, pr_open, merged/active, retired`) is kept; `approved_for_pr` and `pr_closed` are additions needed to separate "admin said yes" from "a PR exists" and "PR closed unmerged".

Baseline: on first reconcile the Worker imports the entries already in `main`'s `sources.json` as `merged` rows with `proposer='baseline'` (event `baseline.import`), so that removal and modification have something to target. No licence evidence is invented for them.

## 9. Mandatory CI, human review, CODEOWNERS and ruleset (Proposal; nothing applied)

Scope of this section: stop any **unauthorized automatic addition** of a source, whether by the proposal workflow, by a log job, by Dependabot or by a stolen `GITHUB_TOKEN`. Nothing below was applied; `docs/audit/repo-hardening/IMPACT.md:3` says no ruleset exists as of 2026-10-19, so these are changes to the **files** `ruleset-main.json` and `apply.sh` before their first application. Re-run `apply.sh verify` first: the live state may have changed since that read.

### 9.1 CI that must be green before merge

* Existing required checks: `python-tests` (includes `test_sources_match_config`, `tests/test_docs.py:212-218`, and the licensing tests) and `quarantine-service` (`ci.yml`).
* New required check `source-proposal-gate`: a job in `ci.yml` with **no path filter** (`ci.yml:2` explains why: a skipped required check stays pending), running `scripts/source_proposal.py gate`. It is trivially green when the PR touches neither `config/sources.json` nor `config/policy.json`. Otherwise: (i) exactly one source added, changed or removed; (ii) the entry passes the validator of 7.4 step 2; (iii) every `rules` source has a `policy.licenses[repo]` entry with `sha256`; (iv) a **new** entry carries `"admission": "probation"` (section 10.2); (v) for a `proposal/*` head branch, no file outside the four template files is touched, and nothing under `.github/`, `scripts/`, `admin/` or `tests/`.
* Dynamic checks need upstream content and run on the first daily run after merge (section 10), not on the PR.

### 9.2 `.github/CODEOWNERS` (exact proposed content)

```
# .github/CODEOWNERS  (PROPOSAL)
# Replace <OWNER> in every line with the owner's GitHub login (or a team handle with write access) before use.
# An invalid owner makes GitHub ignore the line silently: check `gh api repos/MacGuard/macguard-yara-channel/codeowners/errors` after adding the file.
# Last matching pattern wins. /logs/ is deliberately not listed: it is written by the log jobs, not reviewed.
/.github/                       <OWNER>
/config/                        <OWNER>
/scripts/                       <OWNER>
/tests/                         <OWNER>
/admin/worker/src/              <OWNER>
/admin/worker/schema.sql        <OWNER>
/admin/worker/migrations/       <OWNER>
/admin/worker/wrangler.toml     <OWNER>
/docs-src/en/sources.md         <OWNER>
/docs-src/es/sources.md         <OWNER>
/docs/audit/repo-hardening/     <OWNER>
```

`/config/` covers `sources.json`, `policy.json` and the proposed `license-allowlist.json` and `known-sources.json`. Side effect to accept: Dependabot PRs (`.github/dependabot.yml` exists) touch `.github/` or package files and will need the owner's approval.

### 9.3 What breaks today if the Actions bypass is removed (verified by reading)

`ruleset-main.json:6-8` lists the GitHub Actions app (`actor_id 15368`) as a bypass actor, mode `always`. It exists for one reason, stated in `IMPACT.md:12`: three jobs push `logs/` straight to `main`.

| Writer | Where | What it pushes |
|---|---|---|
| `daily.yml` job `review` (`contents: write`, `daily.yml:27-30`) | step "Record the result in the transparency log", `bash scripts/commit_logs.sh "daily review $RUN_ID"` | `logs/` |
| `publish.yml` job `publish` (`contents: write`, `publish.yml:52`) | `publish.yml:165` | `logs/` |
| `site.yml` job `record` (`contents: write`, `site.yml:284`) | `site.yml:330` | `logs/` |

All three call `scripts/commit_logs.sh`, which does `git add logs` only (`commit_logs.sh:6`), commits as `macguard-log[bot]` and runs `git push` with 3 retries (`commit_logs.sh:9-12`). **Without the bypass, a ruleset requiring pull requests rejects that push**; the script ends with `Could not push the log after 3 attempts` and exit 1 (`commit_logs.sh:13`). Consequences: the daily job and `site.yml` finish red, `publish.yml` fails **after** the release is already public (the log commit is its last step), and the transparency log on `main` stops advancing while releases continue. Readers of the log on `main` would see a stale chain: `ops.js:97`, `verify_public_release.py:365,391` (`raw.../main/logs/checkpoints/...`), the site build from the checkout.

So the bypass cannot simply be deleted. There are two ways to keep the log jobs working.

### 9.4 Option Q (structural, recommended end state): logs leave `main`

Move the append-only log to a dedicated branch `logs`; `main` then needs no bypass at all.

* Branch `logs` (orphan, created once by the owner), written only by the Actions app. Ruleset `logs: only the log bot` below.
* `scripts/commit_logs.sh`: commit in a worktree of `origin/logs` and `git push origin HEAD:refs/heads/logs`; each of the three workflows first runs `git fetch origin logs` and materialises `logs/` from it (the jobs checkout `main` for code, `daily.yml:36-38`).
* Readers: `ops.js:97` and `verify_public_release.py:365,391` change the path `main/logs/...` to `logs/logs/...` (branch `logs`, directory `logs`) with a fallback to `main` for releases that predate the move; `site.yml` build and `tlog.py` read the materialised directory.
* One reviewed PR removes `logs/` from `main` (or freezes it at the move point so old verifiers still work).
* Cost: touches 3 workflows, 1 shell script, 2 readers, the verifier and its tests (`tests/test_verify_public_release.py`, `tests/test_tlog*.py`, `chain-test.yml`). Treat it as its own task with the full chain test (`chain-test.yml`) before cutover. **Not part of the V1.1 proposal feature**, but a precondition for the strongest guarantee.

### 9.5 Option R (interim, smaller): keep the bypass, add compensating controls

Keep the Actions bypass exactly as in `ruleset-main.json` and add controls that make an unauthorized addition **detected and unusable**, not impossible:

1. **Provenance guard before use.** `scripts/verify_config_provenance.py`, run as the first step of `daily.yml` job `review` (before `prepare.py`, `daily.yml:56`). For `config/sources.json` and `config/policy.json` it finds the last commit that changed each file (`git log -1`), asks GitHub (`GET /commits/{sha}/pulls`, `GET /pulls/{n}/reviews`, read-only `GITHUB_TOKEN`) and **fails the run, fetching nothing,** unless that commit belongs to a merged PR with an `APPROVED` review by a login listed in `.github/CODEOWNERS`. A direct push by any bypass actor fails this check. Limit: it is a detective control; an actor able to bypass the ruleset could also edit the guard itself (the guard is under `/scripts/`, but a bypass actor skips review). It stops mistakes and a compromised *non-editing* job; it does not stop a malicious writer who edits both.
2. **Write-scope test.** `tests/test_workflow_write_scopes.py`: only the three jobs of 9.3 may declare `contents: write`; no workflow contains `gh pr merge`, `--auto`, `--admin`, `git push --force`, `git push origin main` outside `commit_logs.sh`; `commit_logs.sh` stages only `logs` (pins `commit_logs.sh:6`).
3. **Environment.** The proposal job runs in environment `source-proposals` limited to `main`.

Option R reduces the risk to "an attacker needs to be a workflow author with merge power"; option Q removes the path.

### 9.6 Exact ruleset delta (Proposal; files in `docs/audit/repo-hardening/`, nothing applied)

**Current** `ruleset-main.json` (verified): bypass `Integration 15368 always`; `pull_request`: `required_approving_review_count 0`, `dismiss_stale_reviews_on_push true`, `require_code_owner_review false`, `require_last_push_approval false`, `required_review_thread_resolution true`; required checks `python-tests`, `quarantine-service`.

Unified delta (applies to both options except where marked):

```diff
-  "name": "main: reviewed, checked, no history rewrite",
+  "name": "main: reviewed by a code owner, checked, no history rewrite",
   "bypass_actors": [
-    { "actor_id": 15368, "actor_type": "Integration", "bypass_mode": "always" }
+    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }       # Option Q: Actions app removed
+    # Option R: keep the line  { "actor_id": 15368, "actor_type": "Integration", "bypass_mode": "always" }  and ALSO add the line above
   ],
   "rules": [
     { "type": "deletion" },
     { "type": "non_fast_forward" },
     { "type": "pull_request", "parameters": {
-        "required_approving_review_count": 0,
+        "required_approving_review_count": 1,
         "dismiss_stale_reviews_on_push": true,
-        "require_code_owner_review": false,
-        "require_last_push_approval": false,
+        "require_code_owner_review": true,
+        "require_last_push_approval": true,
         "required_review_thread_resolution": true } },
     { "type": "required_status_checks", "parameters": {
         "strict_required_status_checks_policy": false,
         "required_status_checks": [
           { "context": "python-tests" },
-          { "context": "quarantine-service" } ] } }
+          { "context": "quarantine-service" },
+          { "context": "source-proposal-gate" } ] } }
```

Resulting complete file for Option Q:

```json
{
  "name": "main: reviewed by a code owner, checked, no history rewrite",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "python-tests" },
          { "context": "quarantine-service" },
          { "context": "source-proposal-gate" } ] } }
  ]
}
```

New file for Option Q only, `ruleset-logs-branch.json`:

```json
{
  "name": "logs: only the log bot may write, no history rewrite",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/logs"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 15368, "actor_type": "Integration", "bypass_mode": "always" }
  ],
  "rules": [
    { "type": "update" },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
```

`ruleset-release-tags.json` is unchanged. `apply.sh` gets two extra steps (`POST rulesets` for `ruleset-logs-branch.json`; create `.github/CODEOWNERS` via a PR, not via the script) and `apply.sh verify` gets `gh api repos/$R/codeowners/errors` and `gh api repos/$R/rules/branches/main`.

Points that I could not verify from this repository and that the procedure in 9.7 must settle:

* The numeric `actor_id` of the `RepositoryRole` Admin (I believe `5` in GitHub's documentation); read it back with `GET /repos/{R}/rulesets/{id}` after a dry application on the sandbox.
* Whether `require_code_owner_review: true` is enforced when the approving count is 0. The delta sets the count to 1 so the question does not arise; with one owner, a PR authored by the Actions bot can be approved by the owner (author and approver differ), but a PR **authored by the owner** cannot be approved by the owner; the `RepositoryRole` Admin bypass in `pull_request` mode is what lets the owner merge their own PRs. **Trade-off to decide:** the same bypass lets the owner merge a proposal PR without clicking "Approve". The owner clicking "Merge" is still a human act, but the code-owner approval is then not forced for the owner. Removing the admin bypass forces it for everything and deadlocks owner-authored PRs until a second account exists.
* Whether "file path restriction" push rules could protect `config/**` from direct pushes. They belong to ruleset target `push`, which applies to **all branches**, so they would also block the `proposal/*` branch pushes of phase 2; they are therefore **not** proposed.
* Whether the current plan/visibility of the repository supports every rule type; `apply.sh` fails loudly on an unsupported one (`apply.sh` stops at the first failure).

### 9.7 Verification procedure (design; to run only on a sandbox repository, then once on the real one after the owner authorises)

Sandbox: a private repository `MacGuard/macguard-ruleset-sandbox` with copies of `ci.yml`, a stub of the three log jobs calling the real `commit_logs.sh`, and `.github/CODEOWNERS`. A second GitHub account (or the owner's second identity) plays "non-owner".

| ID | Step | Expected |
|---|---|---|
| H1 | `gh api repos/R/codeowners/errors` | `errors: []` |
| H2 | `apply.sh plan`, then `apply` of the delta on the sandbox; `gh api repos/R/rules/branches/main` | the rules of 9.6 are listed as active; compare with the JSON |
| H3 | A job with `contents: write` appends a change to `config/sources.json` and pushes to `main` | rejected (Option Q); in Option R accepted, and the next `verify_config_provenance.py` run **fails** |
| H4 | The log job (`commit_logs.sh`) pushes a `logs/` change | Q: accepted on branch `logs`, no push to `main` attempted; R: accepted via bypass |
| H5 | PR touching `config/sources.json` by a non-owner without owner approval | merge button blocked |
| H6 | PR authored by the Actions identity touching `config/sources.json`, approved by the owner | mergeable once `python-tests`, `quarantine-service`, `source-proposal-gate` are green |
| H7 | Same PR after a new push | approval dismissed (`dismiss_stale_reviews_on_push`, `require_last_push_approval`) |
| H8 | PR touching `.github/workflows/*` and `scripts/*` | needs the owner (CODEOWNERS) |
| H9 | Dependabot PR | needs the owner's approval (accepted side effect) |
| H10 | Owner-authored PR | mergeable through the admin `pull_request` bypass; record that the approval was not forced |
| H11 | `workflow_dispatch` of a modified copy of the proposal workflow from a feature branch | Worker returns 403 (`auth.js:126-128`); cannot reach `main` unless H3 allows it |
| H12 | Real repository, after authorisation: dispatch `daily.yml` with `acceptance=true` (`daily.yml:17-20`) and confirm the log commit lands, then `site.yml` and a `publish.yml` dry path (`chain-test.yml`) | all three log writers succeed; if not, delete the ruleset (`gh api -X DELETE repos/R/rulesets/<id>`, `IMPACT.md` step 3) |

Static tests in the repository (run in `python-tests`): `tests/test_repo_hardening.py` parses every `ruleset-*.json` and `CODEOWNERS` and asserts (a) in Option Q no `Integration` bypass on a branch rule that targets the default branch; (b) `source-proposal-gate` is in `required_status_checks` and is a job name in `ci.yml`; (c) every CODEOWNERS pattern matches an existing path; (d) the owner placeholder `<OWNER>` is absent from a copy intended for application; (e) `tests/test_workflow_write_scopes.py` of 9.5.

### 9.8 What "cannot be merged without a human" means after this

Merge into `main` needs: the three checks green, a code-owner approval (or, if the owner uses the admin bypass, the owner's own explicit merge), no workflow able to merge or approve (tested), and, in Option Q, no actor outside the owner able to write `main` directly. Under Option R the Actions bypass still lets a job with `contents: write` push `main`; only detection (9.5) applies, which is why Q is the recommended end state.

## 10. After the merge: activation and first sight of a new source

### 10.1 Activation (requirement 9)

A source is active **only** when its entry is on `main`. The Worker marks a proposal `merged` only after reading `sources.json` from `main` itself and finding an entry equal to the frozen payload (7.4 step 9). Until then the daily run cannot see it (`prepare.py:7`). A proposal approved in the panel but never merged has no effect on anything.

### 10.2 First run in quarantine mode: the `new-source` hold (decided by the owner; design below is a Proposal for code)

**What the code does today (verified):** with the licence entry present and the verdict `ok`, a new source's files are classified like any other and become `VALIDATED` unless a static, benign-corpus, dynamic or anomaly gate stops them (`rulecheck.py:131-181`, `decide.py:27-35`, `dynamic_gate.py:47`, `:83`). Nothing asks whether a person has ever authorised rules from this source. Without a licence entry every file is quarantined and nothing can waive it (`rulecheck.py:147-148`, `decide.py:15`).

**Owner requirement:** a new source gets a FIRST RUN IN QUARANTINE MODE and contributes nothing to the publishable set until an ADMIN authorises it in the panel.

#### Where the change goes (and why there)

* **`scripts/decide.py`, not `rulecheck.py`.** The static classification step runs before the previous release is downloaded (`daily.yml:59` classify, then `daily.yml:65` "Latest release and reviewer decisions"; `rulecheck.py:210` is called without `previous`). `decide()` already receives the previous manifest and the decisions (`decide.py:21-23`) and already holds the analogous judgement finding `matches-benign-corpus` right at `decide.py:33-34`. The hold is added next to it.
* **`daily.yml` needs no new step and no reordering.** `dynamic_gate.py` (`daily.yml:72`) runs after the previous release is downloaded (`daily.yml:65`) and calls `decide.decide` through `decide_now` (`dynamic_gate.py:78`), the single call site for all iterations.
* **`scripts/prepare.py:56`**: the source record gains `"admission": source.get("admission")` so it travels in `dist/candidate.json` (`prepare.py:81`) and into the signed manifest `sources` (`release_meta.py:33`). It records the value only; it grants nothing.
* **`config/sources.json`**: a new optional key `admission`, value `"probation"`. The proposal PR (7.4 step 4) always writes it for a new entry; `source-proposal-gate` (9.1 iv) fails a PR that adds a source without it. **The three current entries are not touched** (owner decision 7); an absent key means "established" only for a source that already has files in the previous release (rule below).

#### Rule (pseudocode, Proposal)

```python
NEW_SOURCE = 'new-source'      # added to WAIVABLE in decide.py:15 and core.js:27

def held_sources(classified, previous_files, sources):
    """Source ids whose files may not enter the release without an ADMIN decision."""
    ids = {c['source'] for c in classified}
    held = set()
    for sid in ids:
        rec = (sources or {}).get(sid, {})
        probation = rec.get('admission') == 'probation'
        never_released = bool(previous_files) and not any(p.startswith(f'rules/{sid}/') for p in previous_files)
        if probation or never_released:
            held.add(sid)
    return held
```

`previous_files` are the paths of the previous release manifest, already built at `decide.py:23`; they have the form `rules/<source id>/...` because `prepare.py:74` and `:80` create the inventory path from `OUT/'rules'/source['id']`. Two conditions on purpose:

1. `admission == "probation"` is stateless, lives in Git, does not depend on the previous release and does not expire by accident. It also holds **files added later** by the same source while it is on probation, and it survives a partial approval (some files approved and released, the rest still pending) without the rest falling through.
2. `never_released` is a fail-safe for a source someone adds to `sources.json` by hand without the key: no file of it in the previous release means held. It needs a non-empty previous release, because `daily.yml:65-69` runs with an empty `previous` when the release download fails, and holding every source (including the three current ones) on a transient failure would flood the panel; that case keeps today's behaviour (the anomaly gate is skipped on an empty previous too, `decide.py:76`). Limitation, stated: condition 2 alone does not survive a partial approval, which is why proposals always carry condition 1.

In the loop of `decide.py:30-47`, right after the benign-corpus block and before the decision lookup at `decide.py:38`:

```python
if c['source'] in held and state in (VALIDATED, QUARANTINED):
    reasons.append({'code': NEW_SOURCE, 'severity': 'review',
                    'detail': 'first run of a new source: an ADMIN must authorise its rules'})
    state = QUARANTINED
```

`decide()` gets a new keyword `sources=None` (id -> record from `dist/candidate.json`); `dynamic_gate.main` reads it and passes it through `decide_now`; `decide.py`'s own CLI gets `--sources`. A caller that passes nothing still gets condition 2.

#### How an ADMIN clears it

* The held files are submitted to the private service by the existing path (`decide.py` `submissions`, `quarantine_client.py` submit, `build_submissions`), reason code `new-source`, `source` = the new id, content stored as for any quarantined file. The public log and public stats receive **counts only** (`public_stats`, `decide.py` accounting), never names, paths, hashes or reasons.
* The decision is the existing one: `approve` binds to the exact SHA-256 (`decisionsMap`, `store.js:162-168`), and the next run turns it into `waived-by-review` (`decide.py:42-45`) only if no other blocking reason exists. Bulk approval uses the existing filter by source (`index.js:98`), at most 500 per request with the exact `confirm_count` (`core.js:5`, `:136-140`).
* **ADMIN only.** `validateDecisionRequest(body, role)` (`core.js:128-130`) allows REVIEWER and above for every action. Proposal: in `store.decide` (`store.js:105-148`), after loading the rows, if `action === 'approve'` and any row's `reasons` contain `new-source` and `actor.role !== 'ADMIN'`, return `403 {error: 'admin role required to authorise a new source'}` before any write (so the batch stays atomic). `reject`, `hold`, `review` remain REVIEWER. `new-source` is added to `WAIVABLE` in both files; the parity test already exists (`admin/worker/test/service.test.js:620-623`).
* Identical bytes: a decision is keyed by content hash, so bytes that were already approved or released elsewhere count as authorised (`decisionsMap`, `store.js:162-168`). That is acceptable (nothing new is published) and is pinned by a test.
* An approved file is **not** exempt from measurement: once `VALIDATED` it is part of `approved`, and it is a `new_or_changed` suspect for the dynamic gate (`dynamic_gate.py:83`, `:47`); `decide.py:72-74` still demands a dynamic result for exactly the final set.
* **Graduation** (end of probation) is a reviewed PR that removes the `admission` key. Proposal: an ADMIN "graduate" action in the panel (allowed only when the source has no `PENDING`/`UNDER_REVIEW` candidates and at least N daily runs have passed) records an audit event and, in phase 2, makes the workflow open that PR. Until the PR merges, the source stays held. N is an OPEN DECISION.

#### Interaction with the licence gate

* A licence failure adds `license-changed` (severity `review`, **not waivable**, `rulecheck.py:147-148`, `core.js:28`); `new-source` is waivable. `decide.py:40-41` keeps the candidate quarantined if any non-waivable reason remains, so an ADMIN approval of `new-source` can never override a licence failure, and `core.js:28` marks such a candidate not approvable in the panel. The licence gate still runs first and independently: the policy entry with `sha256` proposed in 5.5 is what makes the licence check pass on the first run.
* Order of evidence in the panel: licence verdict, then `new-source`. Neither masks the other.

#### Interaction with the dependency closure

* A held file is `QUARANTINED`, so it is not in `included`, and every file that depends on it is removed by the closure loop with `dependency-not-validated` (`decide.py:47-55`; static counterpart `rulecheck.py:176-180`). Inside the new source this is wanted: all of its files are held anyway, and the panel's inclusion logic (`core.js` `includedIds`, `outsideBlock`) already tells the ADMIN whether an approval will take effect (a file needing a file that is not approved yet has no effect).
* Cross-source: dependency names are resolved over all candidate files, first definer wins (`rulecheck.py:136-139`) and sources are processed in `sources.json` order (`prepare.py:52`), so a source appended last cannot capture a name already defined by a current source. The residual case is a **current-source file that references a name defined only by the new source**: until now that file did not compile (`compile-dependency`, `rulecheck.py` compile step) and was not published; with the new source held it becomes `dependency-not-validated` instead. No published file can be removed by this, because a published file already compiled without the new source. A test pins it (N10). What happens when two sources define the same rule name when compiled together is **not verified here**; test N11 must establish it before the first real proposal.
* The anomaly gate is not triggered by a held source: held files never enter `approved`, so `added` does not grow (`decide.py:62`, `:76-79`). The release that follows the ADMIN approval can trip it if the approved batch exceeds 40% of the previous release (`policy.json:77`), needing a person to run `daily.yml` with `allow_large_change` (`daily.yml:9-13`), which is the existing, intended safeguard.

#### Negative tests (Proposal, `tests/test_decide.py`, `admin/worker/test/service.test.js`)

| ID | Test | Expected |
|---|---|---|
| N1 | Source with `admission: probation`, all files otherwise valid, no decisions | every file `QUARANTINED` with `new-source`; `approved` empty for that source; the three current sources unchanged; accounting invariant holds |
| N2 | Same, with decisions `{}` because the service is unreachable | still held (decision lookup absent, `decide.py` docstring: nothing depends on the store) |
| N3 | REVIEWER sends `approve` for a `new-source` candidate | 403, no row changed, no audit row; ADMIN succeeds |
| N4 | ADMIN approves; next run, same bytes | `waived-by-review`; file enters `approved`; dynamic gate lists it as `new_or_changed` |
| N5 | ADMIN approves; upstream edits the file | new SHA-256, held again |
| N6 | File with `license-changed` plus `new-source`, ADMIN approves | stays quarantined (non-waivable), panel says not approvable |
| N7 | Source without the key, absent from a non-empty previous release | held by condition 2 |
| N8 | Probation source, half of the files approved and released, upstream adds a file | the new file is held; the unapproved half stays held (condition 1) |
| N9 | Empty previous (download failed), source without key | not held (documented), source with key held |
| N10 | Current-source file referencing a name only the new source defines | not published, no published file removed, `previously_published_failing` empty |
| N11 | New source defining a rule name already defined by a current source | behaviour recorded; must not remove or alter a published file |
| N12 | Dynamic gate: approved new-source file that is a culprit | isolated and quarantined (`dynamic-failure`, block), approval does not override |
| N13 | Anomaly gate: approval of a batch above 40% | `publishable=false` until `allow_large_change` |
| N14 | Source removed then re-added | held again (no files in the previous release) |
| N15 | `WAIVABLE` parity with `new-source` | the existing test passes; adding the code to one file only fails it |
| N16 | Public outputs (`stats.json`, log, release notes, `public_stats`) after a held run | counts only; a scan finds no source file name, path, hash or reason |
| N17 | Source `kind: engine` | contributes no files, never held (`prepare.py:62`) |

### 10.3 Pinned commits (Proposal, OPEN DECISION 7)

Today nothing pins a source: upstream HEAD is followed daily and only recorded (`prepare.py:54-56`; `docs-src/en/sources.md` says the tarball of "that exact commit" is downloaded, which is true per run). Options: (A) keep following HEAD (status quo, protected by gates and the anomaly rule); (B) add optional `pin` to a source entry, honoured by `prepare.py`, set from the verified commit at proposal time, and moved only by a reviewed bump PR; (C) pin during a cooling-off period of N daily runs, then switch to HEAD. B gives the strongest answer to "licensed upstream changes later" but turns the daily upstream review into a PR chore per source.

### 10.4 Removal and modification

Remove: PR deletes the `sources.json` entry (and its policy licence entry and docs rows). On the next run the source's files are absent upstream-from-our-view, so they are reported `retired` (`decide.py:61-63`), and a large removal can trip the 15% anomaly gate, needing a human `allow_large_change` run (`policy.json:76`). Modify `paths`: same PR mechanism, same gate; narrowing removes files, widening adds them (and triggers the `new-source` hold for the added files only if the hold is keyed by source+path; Proposal: key by source only, so widening is not held; OPEN DECISION 1).

## 11. Threat model

| # | Threat | Vector | Control (existing = cite; proposed = Proposal) | Residual |
|---|---|---|---|---|
| 1 | SSRF | URL field pointing at internal host or `file:`/`gopher:` | URL reduced to `(owner, repo)`; only constant host `api.github.com`; `assertAllowedUrl` before every fetch; `redirect:'manual'` (proposed) | none identified; T-S1..T-S6 |
| 2 | Redirect to metadata IP (`169.254.169.254`) | a 3xx from GitHub-shaped response or a redirecting host | no redirect followed; the only recognised 301 (`/repositories/{id}`) is recorded, not followed | none |
| 3 | DNS rebinding | attacker-controlled hostname flipping to a private IP | no attacker-controlled hostname is ever resolved (constant host); platform cannot address RFC 1918 (defence in depth, to be confirmed by T-S6) | platform assumption unproven |
| 4 | Oversized repository / zip bomb | huge repo or tree | metadata-only verification (no tarball in the Worker); response caps; `size`, `truncated`, 25,000-entry check; at fetch time `prepare.py` caps (`:8`, `:43`, `:72`) | pipeline job time for a repo near limits |
| 5 | Typosquat of a known source | `Neo23x0x/signature-base`, `Yara-Rule/rules` | `LOOKALIKE` check against `sources.json` and `known-sources.json`, tick + typed `owner/repo` confirmation; human PR review | a lookalike of an unlisted name; social engineering |
| 6 | Licence spoofing | root LICENSE says permissive, files say otherwise; or LICENSE edited after approval | spdx cross-check F1/F2; allow-list; policy entry with `sha256` of text, so any later edit becomes `license-changed` (`licensing.py:15-16`, `rulecheck.py:147-148`, non-waivable) | per-file headers not checked by anything; spdx allow-list is a legal opinion |
| 7 | PR injection through crafted names | source id or repo with newline, backticks, `../`, markdown, YAML/JSON metacharacters; `reason` text in PR body | strict regexes (section 4) at the Worker, re-validated in repo code (7.4 step 2); JSON written with `json.dumps`; PR title/body from a fixed template with validated fields; `reason` never leaves D1; `--body-file`, no shell interpolation (FA-21 pattern); `gate` check | none identified |
| 8 | Token theft: admin OAuth token | Worker compromise | already sealed AES-GCM bound to the session id (`auth.js` `sealToken/openToken`); verification uses it only toward `api.github.com`; no new token | existing exposure unchanged |
| 9 | Token theft: GitHub write credential | stealing the credential that opens PRs | (c): none exists in the Worker; the `GITHUB_TOKEN` is per-run. (a)/(b): see 7.2 | (c) none new |
| 10 | Replay of an admin request | resend of `approve` | CSRF + `Origin` + `request_id` unique + `expect_version` (optimistic lock) | none |
| 11 | Replay of an OIDC call | resend of a captured workflow request | token `exp`, fixed audience, `ref` and workflow pinned (`auth.js:123-128`); endpoints idempotent on `(id, payload_sha256, pr_number)`; state machine rejects out-of-order | window equal to token lifetime for idempotent calls |
| 12 | Worker lies about the payload | tampered D1 row or Worker bug | workflow recomputes `payload_sha256` and re-validates everything; `reverify` re-queries GitHub; PR diff is human-reviewed | none for integrity of what is merged |
| 13 | Workflow lies about a merge | forged `sync` | the Worker re-reads `main` itself before `merged` | none |
| 14 | Admin impersonation / privilege creep | a REVIEWER or revoked admin approving | role recomputed from GitHub on each unsafe call (`index.js:85`); ADMIN only for write verbs | owner is both admin and sole reviewer |
| 15 | Automation merges a proposal | bot with merge right, auto-merge | no workflow merges; auto-merge off; CODEOWNERS + gate; test greps workflows for `gh pr merge`/`--auto` | Actions bypass (7.6) |
| 16 | Later hostile change in an accepted upstream | upstream edits rules after approval | existing gates; anomaly rule; dynamic gate; benign corpus; `license-changed`; Proposal: `new-source` hold, pin | see 7.7 |
| 17 | Proposal flood / abuse of GitHub quota | repeated verifies | 10 verifications/h/admin; one open proposal per repo and per id (unique partial indexes); body caps | low |
| 18 | Audit tampering | edit of history | hash chain + `RAISE(ABORT)` triggers on audit and on the new events table | DB owner can drop a trigger; chain shows it (same as `schema.sql` comment) |
| 19 | Privacy leak | proposal text or findings exposing quarantined content | proposals concern public repositories only; the Worker never fetches rule content; findings use fixed codes; no rule names anywhere in this feature | none |

## 12. Test matrix (Proposal; none exist yet)

Levels: U = unit (node:test / unittest), I = integration on the D1 shim (`admin/worker/test/d1shim.js`), R = runtime test on workerd with real D1 (`npm run test:runtime`, `ci.yml:45-46`), C = CI/workflow lint (actionlint/zizmor as in FA-21), E = end-to-end on a throwaway fork/repo in a test org (never on production).

| ID | Test | Level | Expected |
|---|---|---|---|
| **URL and SSRF (negative)** | | | |
| T-S1 | URLs: `http://github.com/a/b`, `https://github.com.evil.com/a/b`, `https://evil.com/github.com/a/b`, `https://user:pw@github.com/a/b`, `https://github.com:444/a/b`, `https://127.0.0.1/a/b`, `https://[::1]/a/b`, `https://169.254.169.254/`, `file:///etc/passwd`, `gopher://`, `https://github.com/a/b/tree/x`, `https://github.com/a/b?x=1`, `https://github.com/a/b#x`, `https://github.com/%2e%2e/b`, `https://ｇithub.com/a/b` (fullwidth), `https://github.com/a/b%0d%0aX` | U | all `400`, **zero** `fetch` calls (counting fake) |
| T-S2 | A GitHub JSON response that contains `html_url`/`tarball_url` pointing to `http://169.254.169.254/` | I | never fetched (counting fake sees only the 5 allowed URLs) |
| T-S3 | F1 answers `301` to `https://evil.com/` ; `301` to `https://api.github.com/repositories/1` ; `302` anywhere | I | `REDIRECT_REFUSED` / `RENAMED`; no second request; token never forwarded |
| T-S4 | Response bodies of cap+1 bytes, wrong content-type, slow body (timeout), invalid JSON | I | `RESPONSE_TOO_LARGE` / `UNEXPECTED_CONTENT` / timeout -> `SOURCE_UNAVAILABLE`, nothing stored as verified |
| T-S5 | `assertAllowedUrl` fuzz: host, port, userinfo, scheme, path prefix variants | U | only the allowed shape passes |
| T-S6 | Under workerd: a verification with `GITHUB_API` overridden to a loopback/RFC 1918 literal is refused by the guard; and, separately, record what the platform does on a direct `fetch('http://10.0.0.1/')` (documentation of platform behaviour, not a control) | R | guard refuses; platform behaviour recorded |
| **Verification** | | | |
| T-V1 | Private, fork, archived, disabled, 404, no rule files, truncated tree, too big | I | `rejected` with exact codes |
| T-V2 | Licence: missing, `NOASSERTION`, F1/F2 disagree, not in allow-list, allowed | I | `LIC_*` codes; policy entry only when allowed; `sha256` present |
| T-V3 | Lookalike of each existing source (case, `-`/`_`, distance 1-2, homoglyph) and exact duplicate by `repo_id` after rename | I | `LOOKALIKE` needs ack / `DUPLICATE` blocks |
| T-V4 | GitHub 403/429 | I | `SOURCE_UNAVAILABLE`, not `rejected`, not `verified` |
| T-V5 | 11th verification in an hour | I | 429 |
| **Roles and API (negative)** | | | |
| T-A1 | VIEWER calls every write endpoint; REVIEWER calls approve, reject, pr-link, refresh, withdraw, graduate and the `new-source` approval (403); REVIEWER's create/verify succeed and are audited with role REVIEWER; unauthenticated; no CSRF; wrong Origin | I | 403/401, no row changed |
| T-A2 | OIDC token from `daily.yml`, from `publish.yml`, from a fork, from `refs/heads/feature`, expired, wrong audience calls pipeline endpoints | I | 401/403 |
| T-A3 | `approve` with stale `expect_version`, stale verification (>24 h), missing ack, wrong `confirm_repo`, from `rejected`/`pr_open` | I | 409/400, state unchanged |
| T-A4 | Same `request_id` twice; two admins approving concurrently | I | one applies, second idempotent/409; audit has one entry |
| T-A5 | `sync` claims `merged` while `main` does not contain the entry | I | refused; state unchanged |
| T-A6 | Source files of the Worker still match the invariant regex of `service.test.js:388-393` (phase 2 adds no `fetch` write) | U | passes unchanged |
| **Audit and DB** | | | |
| T-D1 | UPDATE/DELETE on `source_proposal_events` | I/R | `ABORT` |
| T-D2 | Audit chain verifies after a full lifecycle; tamper detected | I | `verifyChain` ok / fails on tamper |
| T-D3 | Unique partial indexes: second open proposal for same repo or id | I | constraint error mapped to 409 |
| T-D4 | Migration 0003 up, rollback, up again on a copy of D1 | R | schema identical to start after rollback |
| **PR generation (workflow, phase 2)** | | | |
| T-P1 | `source_proposal.py validate/apply/gate` on adversarial payloads: newline, backtick, `$()`, `../`, unicode bidi, 10 KB id, duplicate keys, extra fields | U | rejected; `sources.json` byte-identical |
| T-P2 | `apply` output: `sources.json` formatting preserved, valid JSON, `policy.json` licence entry has `sha256`, docs rows present in es and en, `test_sources_match_config` passes | U | pass |
| T-P3 | `gate` check on PRs: touching `.github/`, two sources, missing licence entry, docs-only, unrelated PR | U/C | fail / fail / fail / pass / pass |
| T-P4 | Workflow lint: permissions exactly as 7.4, no `pull_request*` trigger, no `gh pr merge`, no `--force`, only `proposal/` refspec, no `${{ }}` in `run:` | C | pass |
| T-P5 | End to end on a throwaway repo: approved payload -> branch -> PR -> CI dispatched -> required checks attach -> merge by a human -> `merged` | E | PR opens; checks satisfy the ruleset (answers 7.5); merge needs the human |
| T-P6 | Workflow run from a feature branch via `workflow_dispatch` | E | Worker returns 403, no payload |
| **After merge** | | | |
| T-M1 | New source with licence entry and a deliberately broken file, a costly regex, a blocked module | pipeline | quarantined/rejected by existing gates |
| T-M2 | New source, licence text edited after merge | pipeline | `license-changed`, non-waivable, all files quarantined |
| T-M3 | With `new-source` hold (if adopted): all files of the new source quarantined; approval flows; widening paths | pipeline | as specified in 10.2 |
| T-M4 | Large new source against the anomaly gate | pipeline | `publishable=false` until `allow_large_change` |

## 13. D1 schema (text only, never run) and audit schemas

### 13.1 `admin/worker/migrations/0003_source_proposals.sql` (Proposal)

```sql
-- 0003: source proposals. Additive only: no existing table or row is touched.
CREATE TABLE IF NOT EXISTS source_proposals (
  id TEXT PRIMARY KEY,                                   -- uuid
  action TEXT NOT NULL CHECK (action IN ('add','modify','remove')),
  source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 2 AND 32 AND source_id GLOB '[a-z0-9]*' AND source_id NOT GLOB '*[^a-z0-9-]*'),
  repo TEXT NOT NULL CHECK (length(repo) BETWEEN 3 AND 140 AND repo GLOB '*/*'),   -- canonical case from GitHub after verification
  repo_lc TEXT NOT NULL CHECK (repo_lc = lower(repo_lc)),
  repo_id INTEGER,                                       -- immutable GitHub numeric id, set by verification
  kind TEXT NOT NULL CHECK (kind = 'rules'),
  paths TEXT NOT NULL CHECK (json_valid(paths) AND json_type(paths) = 'array' AND json_array_length(paths) BETWEEN 1 AND 20),
  state TEXT NOT NULL CHECK (state IN ('proposed','verified','rejected','approved_for_pr','pr_open','pr_closed','merged','retired')),
  state_reason TEXT,                                     -- fixed codes, e.g. 'LIC_NOT_ALLOWED', 'closed_unmerged', 'replaced'
  version INTEGER NOT NULL DEFAULT 1,                    -- optimistic lock, +1 on every transition
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 5 AND 2000),   -- proposer's text; never copied to a PR
  proposer TEXT NOT NULL,
  proposer_id INTEGER NOT NULL,
  request_id TEXT NOT NULL UNIQUE,
  verification TEXT CHECK (verification IS NULL OR json_valid(verification)),   -- evidence: fetched fields only, no bodies
  verified_at TEXT,
  verified_commit TEXT CHECK (verified_commit IS NULL OR (length(verified_commit) = 40 AND verified_commit NOT GLOB '*[^0-9a-f]*')),
  license_spdx TEXT,
  license_sha256 TEXT CHECK (license_sha256 IS NULL OR (length(license_sha256) = 64 AND license_sha256 NOT GLOB '*[^0-9a-f]*')),
  findings TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(findings)),     -- [{code, severity}]
  acks TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(acks)),
  payload TEXT CHECK (payload IS NULL OR json_valid(payload)),          -- frozen at approval
  payload_sha256 TEXT CHECK (payload_sha256 IS NULL OR (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*')),
  approved_by TEXT, approved_by_id INTEGER, approved_at TEXT,
  closing_requested INTEGER NOT NULL DEFAULT 0,
  pr_number INTEGER, pr_url TEXT, pr_branch TEXT, pr_head_sha TEXT, merge_commit TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS source_proposals_state ON source_proposals (state);
CREATE INDEX IF NOT EXISTS source_proposals_repo ON source_proposals (repo_lc);
-- one open proposal per repository and per source id
CREATE UNIQUE INDEX IF NOT EXISTS source_proposals_open_repo ON source_proposals (repo_lc)
  WHERE state IN ('proposed','verified','approved_for_pr','pr_open') AND action = 'add';
CREATE UNIQUE INDEX IF NOT EXISTS source_proposals_open_id ON source_proposals (source_id)
  WHERE state IN ('proposed','verified','approved_for_pr','pr_open');
-- a repository (by immutable id) is in force at most once
CREATE UNIQUE INDEX IF NOT EXISTS source_proposals_inforce_repo_id ON source_proposals (repo_id)
  WHERE state = 'merged' AND repo_id IS NOT NULL AND action IN ('add','modify');

CREATE TABLE IF NOT EXISTS source_proposal_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  proposal_id TEXT NOT NULL,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  actor_id INTEGER,
  role TEXT NOT NULL,                                    -- ADMIN | PIPELINE
  event TEXT NOT NULL CHECK (event IN ('proposed','verify.ok','verify.rejected','verify.unavailable','approved','rejected','pr.opened','pr.closed_unmerged','merged','retired','baseline.import','closing.requested')),
  from_state TEXT, to_state TEXT NOT NULL,
  version INTEGER NOT NULL,
  payload_sha256 TEXT,
  detail TEXT NOT NULL CHECK (json_valid(detail)),
  audit_hash TEXT NOT NULL                               -- hash of the matching row in the hash-chained `audit` table
);
CREATE INDEX IF NOT EXISTS source_proposal_events_p ON source_proposal_events (proposal_id, seq);
CREATE TRIGGER IF NOT EXISTS spe_no_update BEFORE UPDATE ON source_proposal_events BEGIN SELECT RAISE(ABORT, 'source proposal events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS spe_no_delete BEFORE DELETE ON source_proposal_events BEGIN SELECT RAISE(ABORT, 'source proposal events are append-only'); END;
```

Notes: every transition is one D1 `batch` (state update guarded by `WHERE version = ?`, event insert, guard `SELECT`), like decisions (`store.js:138-148`); the `audit` row is appended by `appendAudit` and its hash stored in the event. D1's bound-parameter ceiling (about 100, FA-06) is respected: no `IN (...)` lists on this table.

### 13.2 `admin/worker/migrations/0003_rollback.sql` (Proposal)

```sql
-- Rollback of 0003. Roll the Worker back first (wrangler rollback), then run this.
-- Drops only objects created by 0003. The hash-chained `audit` table is NOT touched: the audit rows written for source
-- proposals stay in the chain (they are generic rows and verifyChain still passes). The proposal history held in
-- source_proposal_events is lost, so export it first if it is needed (SELECT * FROM source_proposal_events).
DROP TRIGGER IF EXISTS spe_no_update;
DROP TRIGGER IF EXISTS spe_no_delete;
DROP INDEX IF EXISTS source_proposal_events_p;
DROP TABLE IF EXISTS source_proposal_events;
DROP INDEX IF EXISTS source_proposals_inforce_repo_id;
DROP INDEX IF EXISTS source_proposals_open_id;
DROP INDEX IF EXISTS source_proposals_open_repo;
DROP INDEX IF EXISTS source_proposals_repo;
DROP INDEX IF EXISTS source_proposals_state;
DROP TABLE IF EXISTS source_proposals;
```

Also keep `admin/worker/schema.sql` in sync (new installs) and extend `test/schema_v1.sql`-style upgrade test (T-D4).

### 13.3 Audit entries (rows of the existing `audit` table, `schema.sql`; `detail` is JSON)

| `action` | `actor` / `role` | `target` | `detail` |
|---|---|---|---|
| `source.proposed` | admin login / ADMIN | proposal id | `{request_id, action, repo_lc, source_id, paths, reason_len}` (the reason text itself stays in `source_proposals`) |
| `source.verify` | admin / ADMIN | id | `{outcome: verified\|rejected\|unavailable, findings:[codes], repo_id, commit, license_spdx, license_sha256, requests:[the five URLs actually fetched], rate_remaining}` |
| `source.ssrf_guard` | admin / ADMIN | id | `{blocked_url_class: host\|scheme\|port\|userinfo\|path\|redirect}` (no raw URL) |
| `source.approved` | admin / ADMIN | id | `{request_id, version, payload_sha256, acks:[codes], confirm_repo, verification_age_s}` |
| `source.rejected` | admin / ADMIN | id | `{request_id, from_state, reason_len, code}` |
| `source.pr_opened` | `pipeline:source-proposals.yml` / PIPELINE | id | `{pr_number, pr_url, branch, head_sha, payload_sha256, token_run_id, run_attempt}` (same style as `pipeline.submit`, `index.js:31`, `:41`) |
| `source.pr_closed` | pipeline | id | `{pr_number, outcome: closed_unmerged\|closing_requested, token_run_id}` |
| `source.merged` | pipeline | id | `{pr_number, merge_commit, main_entry_sha256 (hash of the entry the Worker read from main), payload_sha256, equal: true}` |
| `source.retired` | pipeline | id | `{replaced_by: id, reason: removed\|replaced}` |
| `source.baseline_import` | pipeline | id | `{source_id, repo}` |

History of additions, removals and changes (requirement 10) is therefore held in three independent places: the append-only events table, the hash-chained audit (verified by `/api/audit/verify`, `index.js:125`), and Git history of `config/sources.json` on `main` (immutable log of merged changes).

## 14. Rollback

* **Feature flag first:** Proposal `SOURCE_PROPOSALS_ENABLED` var in `wrangler.toml`; unset or `"0"` makes every `/api/source-proposals*` and `/api/pipeline/source-proposals*` answer 404. Disabling does not alter any in-force source.
* **Worker:** `wrangler rollback` to the previous version (note the active version before deploying; deploy via the checked per-environment copy and `scripts/check_worker_config.py`, `docs/OPERATIONS.md:23`).
* **D1:** run `0003_rollback.sql` only after the Worker rollback; export events first.
* **Workflow:** delete or disable `source-proposals.yml`; remove it from `PIPELINE_WORKFLOWS`; close any open `proposal/*` PRs by hand and delete their branches.
* **Repository settings:** CODEOWNERS and ruleset changes are independently revertible (`gh api -X DELETE repos/R/rulesets/<id>` as in `IMPACT.md`); the required check `source-proposal-gate` must be removed from the ruleset before the job is deleted, otherwise PRs stay pending forever.
* **A bad source already merged:** a normal remove PR (same flow) or a revert of the merge commit; the next daily run reports its files `retired` and the anomaly gate may need `allow_large_change`. Releases already published are immutable and unaffected until the next release.

## 15. Risks

1. Latency and quirks of the pull model (hourly lag; `GITHUB_TOKEN` PRs not triggering CI; repo setting needed). Mitigation: `workflow_dispatch` for immediate runs; phase 1 manual path.
2. The Actions bypass on `main` (7.6) limits the strength of "no merge without a human" against a malicious writer.
3. The `new-source` hold may create large review queues; bulk approval tooling is not designed here.
4. The licence allow-list is a legal opinion embedded in a JSON file.
5. Typosquat and age/staleness thresholds are heuristics; they inform a human, they do not decide.
6. Per-file licence differences and rule truthfulness are not checked by any control.
7. Verification is point-in-time; upstream moves daily (no pin).
8. New code path in the Worker that talks to GitHub with the admin's token: mitigated by constant host, guard, tests; it widens read surface only.
9. Docs rows generated from a template are minimal and need editorial care (the docs test only checks presence, `tests/test_docs.py:212-218`).
10. Unproven items (platform egress to private ranges, CI attaching to dispatched runs, code-owner enforcement with 0 approvals) are explicit tests T-S6, T-P5 and the 9.3 experiment; none is claimed.
11. Not run: nothing in this document has been executed against D1, Cloudflare or GitHub.

## 16. Decisions

### 16.1 Owner decisions received (2026-10-21) and how they are applied

| # | Owner decision | Where it is applied |
|---|---|---|
| D1 | The panel lets people propose new sources | sections 4, 8 (REVIEWER and ADMIN may create and verify; VIEWER may not: my reading of "people", to confirm in 16.3) |
| D2 | Only ADMIN can authorise proposals | section 8: approve, reject, pr-link, refresh, graduate are ADMIN; also `new-source` approvals (10.2) |
| D3 | Activation needs a PR, licence validation, provenance, security tests and effective human approval | sections 5, 6, 9, 10.1: nothing is active before the entry is on `main`; merge needs checks + code-owner approval; first run is quarantined |
| D4 | The Worker gets no general GitHub write permission | 7.3: pull model; phase 1 and phase 2 deliverables are concrete |
| D5 | Review CODEOWNERS and the ruleset bypass | section 9: exact CODEOWNERS, exact ruleset JSON delta, what breaks, how log commits keep working (Q or R), verification procedure |
| D6 | New source: first run in quarantine mode | 10.2: `new-source` finding, placed in `decide.py`, ADMIN-only clearing, licence and dependency interaction, negative tests |
| D7 | Do not change current sources; do not activate any new one | nothing in `config/` is edited by this document; `sources.json` entries unchanged; the baseline import creates D1 rows only |

### 16.2 The 12 earlier open decisions

| # | Subject | Status |
|---|---|---|
| 1 | First sight of a new source | **RESOLVED** by D6: hold `new-source`, stateless via `admission: probation` plus fail-safe on never-released sources. Sub-decision 13 below |
| 2 | PR mechanism | **RESOLVED** by D4: pull model (c), phase 1 = (d). Operational prerequisites still need the owner's action: repository setting "Allow GitHub Actions to create and approve pull requests", environment `source-proposals` restricted to `main` |
| 3 | Actions bypass on `main` | **DESIGN DELIVERED, CHOICE OPEN**: Option Q (logs to a dedicated branch, bypass removed) vs Option R (keep bypass, detective controls). See 9.4, 9.5 and decision 14 |
| 4 | Licence policy (allow-list, legal acceptance, who maintains `config/license-allowlist.json`) | **OPEN** |
| 5 | Trust thresholds (repo age 90 d, owner age 180 d, staleness 24 months, size 90,000 KB, `known-sources.json`, distance 2) | **OPEN** (values in the document are defaults) |
| 6 | Separation of duties with a single ADMIN | **PARTLY**: effective human approval is the code-owner review on the PR (D3); whether the admin `pull_request` bypass is kept so the owner can merge their own PRs is **OPEN** (9.6 trade-off) |
| 7 | Pinning upstream commits | **OPEN**; `probation` covers the first period only |
| 8 | Role split | **RESOLVED** by D1/D2: ADMIN authorises; REVIEWER proposes and verifies, read-only otherwise; VIEWER none. Confirm that REVIEWER (every GitHub writer) may propose |
| 9 | Ruleset delta | **EXACT DELTA PRODUCED** (9.2, 9.6); **application OPEN**: needs the owner's authorisation and the sandbox procedure 9.7 |
| 10 | Scope (GitHub only, rules only, no private repos, no forks/archived) | **OPEN, default adopted** |
| 11 | Pull schedule | **OPEN**, default hourly plus manual dispatch |
| 12 | Baseline import of the three current sources | **RESOLVED** by D7: import as `merged` rows with `proposer='baseline'`, no invented evidence, D1 only; modifying or removing them through the panel requires a fresh verification first |

### 16.3 New and still-open decisions

13. **Probation length and graduation.** Number of daily runs N and whether graduation is an ADMIN panel action that opens a PR (proposed) or only a manual PR; whether graduated sources keep any extra scrutiny.
14. **Log branch (Option Q).** Authorise the separate task that moves `logs/` to branch `logs`, or stay on Option R for now. Until decided, the bypass stays and 9.8 applies with its stated limit.
15. **Admin bypass for owner-authored PRs.** Keep `RepositoryRole` Admin `pull_request` bypass (owner can merge own PRs, approval not forced) or remove it (forced approval, owner-authored PRs need a second account).
16. **Confirm the reading of D1**: REVIEWER may create and verify proposals (using their own OAuth token's rate limit), or proposals are ADMIN-only to create.
17. **Application order.** Proposed: CODEOWNERS PR -> `source-proposal-gate` job -> ruleset delta on the sandbox (9.7) -> `new-source` hold implemented and tested (10.2) -> Phase 1 -> real ruleset -> Phase 2. Confirm.

## 17. Implementation status (agent A4)

Nothing below is deployed, applied or run against GitHub, Cloudflare or D1. Owner decisions B1-B7 (2026-10-21) are binding and refine sections 7-10 and 16.

### Phase 1, branch `feat/sources-p1` (changes nothing the pipeline publishes; no workflow touched)

| Item | Where | State |
|---|---|---|
| Migration 0005 + rollback (mirrored in `schema.sql`, delimited by `>>> 0005`) | `admin/worker/migrations/0005_*.sql` | tested up, rollback, up again on the node:sqlite shim; never run on D1 |
| States proposed, verified, approved, rejected, pr_open, active, retired (`approved` = authorized by an ADMIN, added to the owner's list) | `src/proposals.js` | done; `pr_open` and `active` are entered by the Phase 2 pipeline endpoints |
| Verification: only `api.github.com`, 5 GETs, `redirect:'manual'`, size/time caps, licence via API, lookalikes | `src/proposals.js` | done, injectable fetch; negative tests T-S1..T-S5, T-V1..T-V5 |
| Roles: REVIEWER and ADMIN propose and verify; ADMIN authorizes, rejects, retires; all roles read | `handleApi` | done |
| `GET /api/pipeline/source-proposals` (only `source-proposals.yml` on main; only approved) | `handlePipeline` | done; inert until the owner adds the workflow to `PIPELINE_WORKFLOWS` |
| Feature flag `SOURCE_PROPOSALS_ENABLED=1` (absent means every endpoint answers 404) | `enabled()` | done |
| Per-row guards: every transition is one batch, each write `WHERE changes() = 1`, guard counts this request's event | `transition`, `create` | tested with concurrent admins and a lost race |
| UI: "Proponer fuente" and the list inside Sources (ES/EN, labels, `textContent`) | `public/views/proposals.js` | done; section absent when the flag is off; UI/Playwright suite NOT run by A4 |
| New-source hold (B5) | `scripts/admission.py`, one hook in `decide.py`, `new-source` in both WAIVABLE lists, ADMIN-only approval in `store.decide` | done; inert unless the caller passes `sources=`; wiring in `dynamic_gate.py` is Phase 2 |
| CODEOWNERS, `ruleset-main-v2.json`, `ruleset-logs-branch.json`, `OPERATIONS.md`, `ruleset_check.py`, `ruleset_probe.sh`, `probe/probe.yml` | `.github/`, `docs/audit/repo-hardening/`, `scripts/` | offline-tested; the real-repository proof is the owner's (OPERATIONS step 2) |

Rollback: revert the merge; `0005_rollback.sql` after `wrangler rollback`; flag to `"0"`.

Open items: (1) `config/sources.json` entries are untouched (B6). The hold's fail-safe (no file in the previous release) would hold an existing source that has never released a file; no explicit `admission` value was added to them; owner to confirm. (2) The licence allow-list is a constant in `proposals.js` (MIT, Apache-2.0, BSD-2/3, ISC, CC0); anything else needs an acknowledged `LIC_NEEDS_LEGAL` (decision 4). (3) `source-proposal-gate` is not yet a required check (Phase 2 adds the job). (4) Admin bypass for owner-authored PRs (decision 15) kept as in 9.6.

### Phase 2, branch `feat/sources-p2` (stacked on p1; changes publication and repository guarantees: NOT to be merged without the owner's specific acceptance)

| Item | Where | State |
|---|---|---|
| Option Q: the log moves to branch `logs` (one commit on top of main whose tree is exactly the `logs/` subtree object of main: byte-identical by construction, no commit rewritten; main keeps `logs/` frozen) | `scripts/migrate_logs_branch.sh` (`check`, `create`, `verify`), `scripts/logs_branch.sh`, `scripts/commit_logs.sh` | proved on a local simulation in `tests/test_logs_migration.py` (tree object equality, checkpoints 20/75/180 and their bundles identical, Merkle roots and consistency still verify, growth only by appending, a writer that lost a race refuses instead of overwriting, main never written). The Sigstore signatures are not re-verified offline: they are byte-identical and `tests/test_verify_public_release.py` (network) re-verifies them |
| The three workflows | `daily.yml` job review, `publish.yml` job publish, `site.yml` jobs build and record | each runs `logs_branch.sh materialize` after the checkout; they still hold `contents: write` because the log branch is written with it |
| Readers | `verify_public_release.py` (logs branch first, then main, always the pair from ONE place), `ops.js`, `acceptance-check.mjs`, `tests/test_verify_public_release.py` | updated, with fallback to main |
| Pull workflow | `.github/workflows/source-proposals.yml`, `scripts/source_proposal.py` | actionlint clean; `list`, `prepare` (re-validation from scratch, GitHub re-check, four template edits and a note), `report`, `sync`, `gate`. Permissions exactly contents, pull-requests, id-token (write); environment `source-proposals`; no secret; no `actions: write`, so it does not dispatch CI: a person closes and reopens the pull request to start the checks (T-P5 unproven) |
| Worker endpoints for it | `POST /api/pipeline/source-proposals/{id}/pr`, `POST .../sync` (merge believed only after the Worker reads `config/sources.json` of main) | tested; `pr_open`, `active`, `pr.closed` |
| Required check | `source-proposal-gate` job in `ci.yml`; `ruleset-main-v2.json` now requires it | tested |
| New-source hold switched on | `dynamic_gate.py --sources config/sources.json` | the three current sources are not held while each has files in the previous release; if one has none, the fail-safe holds it (open item) |

Deviation from the brief, on purpose: the proposal pull request changes `config/sources.json` plus `config/policy.json`, `docs-src/{es,en}/sources.md` and one note. Without the licence entry every file of the new source would be quarantined with a finding nobody can waive, and `tests/test_docs.py` fails a source with no documentation row.

Rollback: revert the Phase 2 merge (workflows write `main/logs` again; the `logs` branch can stay); delete `source-proposals.yml`; `ruleset-main-v2.json` must not be applied before this phase is merged and the migration verified (runbook `docs/audit/repo-hardening/OPERATIONS.md`).
