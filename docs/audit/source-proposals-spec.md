# Propose a source from the admin panel: design specification (V1.1)

Status: **PROPOSAL, design only.** Nothing here is implemented, deployed or applied. No D1 command, `wrangler` call, token creation or GitHub write was run to produce this document. Every statement about current behaviour cites `file:line` in this repository (state at `cc37633`); every statement that starts with "Proposal" is a design decision still to be made by the owner (see OPEN DECISIONS, section 14).

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

### 7.3 Recommendation (Proposal)

**Recommend (c), the pull model, with (d) delivered first as the always-available manual fallback.**

Why: it is the only automated option in which the Worker holds no GitHub write credential at all, it adds no stored secret, it reuses the pipeline-authentication pattern already built and tested (`auth.js:114-129`, `index.js:26-58`), and the existing safety test stays true as written. The price is latency and two GitHub quirks (7.5, 7.6), both manageable and both listed as OPEN DECISIONS. (a) is the right choice only if the owner wants instant PR creation and accepts that the Worker then holds contents write; it would also require rewriting the invariant test.

Phasing (Proposal): **Phase 1** = (d): D1 + verification + approval + `GET /api/source-proposals/:id/patch` returning the three diffs and a prefilled `https://github.com/MacGuard/macguard-yara-channel/compare/main...` hint; the human opens the PR. **Phase 2** = (c): add `source-proposals.yml`.

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
| REVIEWER (GitHub `write`/`maintain`) | **read-only**: list, detail, diff, events. Proposal rationale: a REVIEWER can already approve rules; adding sources has a larger blast radius, and GitHub `write` is a broad population |
| ADMIN | everything REVIEWER may, plus create, verify, approve, reject, withdraw, request removal/modification |
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

## 9. Mandatory CI, human review and branch protection (Proposal; nothing applied)

### 9.1 CI that must be green before merge

* Existing required checks: `python-tests` (includes `test_sources_match_config`, `tests/test_docs.py:212-218`, and the licensing tests) and `quarantine-service` (`ci.yml`).
* New required check `source-proposal-gate` (job in `ci.yml`, **no path filter**, as `ci.yml:2` demands, so it is trivially green when the PR touches neither file) running `scripts/source_proposal.py gate`: if the PR changes `config/sources.json` or `config/policy.json.licenses`, then (i) the change is exactly one source added/changed/removed; (ii) the new entry passes the same validator as 7.4 step 2; (iii) a `licenses[repo]` entry with `sha256` exists for every `rules` source; (iv) no other file outside the template-generated docs rows is touched when the head branch starts with `proposal/`; (v) `.github/**` and `scripts/**` are untouched by a `proposal/*` branch. A Python unit test covers each rule (section 12).
* The heavy dynamic checks are not run on the PR (they need upstream content); they run on the first daily run after merge (section 10).

### 9.2 CODEOWNERS (new file `.github/CODEOWNERS`, Proposal)

```
/config/                 @MacGuard/owners   # or @<owner login>
/.github/                @MacGuard/owners
/scripts/                @MacGuard/owners
/admin/worker/src/       @MacGuard/owners
/docs/audit/repo-hardening/ @MacGuard/owners
```

### 9.3 Ruleset changes on `main` (Proposal, delta against `ruleset-main.json`)

* `require_code_owner_review: true` (currently `false`, line 15-18 region) so that a PR touching `/config/` needs the code owner.
* `required_approving_review_count`: 0 now. With one owner a PR **authored by the owner** could not be approved by anyone else; a PR authored by the Actions bot can be approved by the owner. **Unverified:** whether GitHub enforces code-owner review when the count is 0; test on a throwaway PR (`apply.sh verify` plus a deliberate PR) before relying on it; if not enforced, set the count to 1 and give the owner a `pull_request`-mode bypass for their own PRs (owner-authored PRs then merge without a second pair of eyes, which is the status quo).
* `require_last_push_approval: true`, so a push after approval invalidates it (`dismiss_stale_reviews_on_push` is already true).
* Add `source-proposal-gate` to `required_status_checks`.
* Disable auto-merge on the repository; the proposal workflow never enables it; nothing with `pull-requests: write` is allowed to merge (the workflow has no `gh pr merge`; a test greps for it).
* Bypass: see 7.6 (OPEN DECISION 3).
* Environment `source-proposals`: deployment branch `main` only; Settings, Actions, "Allow GitHub Actions to create and approve pull requests" on (needed so `GITHUB_TOKEN` can open PRs; approval of PRs by the token is never used).

With these, "a proposal PR cannot be merged without a human" holds in the following precise sense: merge needs the CI checks green and a code-owner approval of a person; no workflow in the repository merges or approves. It does not hold against the Actions-bypass path (7.6), which is why OPEN DECISION 3 matters.

## 10. After the merge: activation and first sight of a new source

### 10.1 Activation (requirement 9)

A source is active **only** when its entry is on `main`. The Worker marks a proposal `merged` only after reading `sources.json` from `main` itself and finding an entry equal to the frozen payload (7.4 step 9). Until then the daily run cannot see it (`prepare.py:7`). A proposal approved in the panel but never merged has no effect on anything.

### 10.2 What the pipeline does on first sight (verified behaviour, then Proposal)

Verified today (section 1): with the licence entry present and the verdict `ok`, a new source's files are classified exactly like any other. A file is `VALIDATED` unless static findings, benign-corpus hit rate (`decide.py:27-34`), the dynamic gate (`dynamic_gate.py:47,83`: new or changed files are the suspects that get isolated) or the anomaly gate stop it. The static and dynamic gates are technical (cost, syntax, modules, blocked modules, canaries); **none of them asks whether a person has ever looked at rules from this source**. Quarantine-everything-new does **not** happen today. If the licence entry were missing, everything would be quarantined and non-waivable (rulecheck.py:147-148), but a merged proposal always includes the entry.

Proposal (needs code and tests; OPEN DECISION 1): **`new-source` hold.** `rulecheck.classify` adds a finding `new-source` (severity `review`, waivable) to every file of a source that is not present in the previous release manifest (`previous['sources']`, already recorded per release by `prepare.py:56`). Effect: all files from the new source are `QUARANTINED` on the first run, appear in the panel with source id, and are released by the existing decisions flow (approve for revalidation, `confirm_count`, `MAX_BATCH` 500, `core.js:5`). Changes required in lock-step: `WAIVABLE` in `scripts/decide.py:15` and `admin/worker/src/core.js:27` (a test already keeps them identical), a pipeline test, and a UI label. Trade-off: a source with thousands of files is tedious to approve; a per-source "approve all pending of this source" bulk action (still bound to exact SHA-256 and `confirm_count`) would be a separate design.

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
| T-A1 | VIEWER and REVIEWER call every write endpoint; unauthenticated; no CSRF; wrong Origin | I | 403/401, no row changed |
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

## 16. OPEN DECISIONS for the owner

1. **First sight of a new source.** (A) Keep today's behaviour (PR review plus existing gates only), (B) add the waivable `new-source` hold (sections 10.2), (C) cooling-off of N daily runs. Also whether widening `paths` is held. Recommendation: B.
2. **PR mechanism.** Approve (c) pull model with (d) as phase 1, or choose (a) accepting that the Worker holds contents write and the invariant test is rewritten. If (c): enable the repository setting "Allow GitHub Actions to create and approve pull requests" and the `source-proposals` environment restricted to `main`.
3. **Actions bypass on `main`.** Keep (status quo, logs push directly), or move log commits to a dedicated branch/ruleset so the Actions app loses bypass on `main` (needs a change to `commit_logs.sh`, `daily.yml`, `publish.yml`, `site.yml` and a re-test of the whole chain).
4. **Licence policy.** Which SPDX ids are redistributable in a signed release (and how `needs_legal` cases are decided); who maintains `config/license-allowlist.json`.
5. **Trust thresholds.** Repo age (90 days), owner age (180 days), staleness (24 months), maximum size (90,000 KB), `known-sources.json` contents, Levenshtein distance 2.
6. **Separation of duties.** With one ADMIN the panel approval and the PR approval are the same person. Accept, or require a second human once a second ADMIN exists (proposer != approver).
7. **Pinning.** Follow HEAD (status quo), per-source `pin` with bump PRs, or pin during a cooling-off period.
8. **Role split.** REVIEWER read-only (proposed) versus allowing REVIEWER to propose (not approve).
9. **Ruleset delta.** Approve CODEOWNERS paths (9.2), `require_code_owner_review`, `require_last_push_approval`, the new required check `source-proposal-gate`, and the approvals-count approach once the 0-approvals behaviour is tested. None applied until the owner authorises `apply.sh`.
10. **Scope.** Confirm V1.1 covers GitHub-hosted rules sources only (no GitLab, no engines, no private repositories) and the document's list of refused repositories (forks, archived).
11. **Schedule.** Hourly pull, or manual dispatch only.
12. **Baseline import.** Import the three current sources as `merged` rows without evidence, or require a fresh verification of each before they can be removed or modified through the panel.
