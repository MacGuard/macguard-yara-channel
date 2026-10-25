# GitHub 403 in the hourly collector: investigation

## What the production data shows (read-only queries of the live D1, 2026-10-24 04:50Z)
Ten collector runs since deployment (one manual at 19:27:39Z, nine by the hourly cron):

| Run (UTC) | Result | | Run (UTC) | Result |
|---|---|---|---|---|
| 10-23 19:27:39 (manual) | ok | | 10-24 00:17:59 | ok |
| 10-23 20:18:00 | 403 → `github_rate_limited` | | 10-24 01:17:59 | 403 |
| 10-23 21:17:59 | ok | | 10-24 02:18:00 | 403 |
| 10-23 22:18:00 | 403 | | 10-24 03:18:00 | 403 |
| 10-23 23:18:00 | 403 | | 10-24 04:17:59 | ok |

Four ok, six refused: **intermittent (60% of the cron runs fail), never permanent**, with up to three failures in a row (01:17–03:18). When a run succeeds the variation is computed correctly: 48 `delta` observations are stored (bundle +6 at 21:17 against the 19:27 baseline, +4 at 04:17 against 00:17), each with the right `prev_observed_at`, and zero discontinuities. So **scheduling, timestamps, persistence and variation arithmetic are verified in production**; what fails is obtaining the data.

## A correction to my earlier report
I wrote that `rate_remaining 21` with a reset time already in the past suggested the 403 was not a plain rate limit. **That inference was wrong.** The deployed code (`4d9b1ff`) updates the rate fields only on success, so those values belonged to the *previous successful* sync (19:27, window reset 19:39). On the failed runs no header was stored at all. The latest success (04:17:59) shows `rate_remaining 23` with reset 04:32:08: the anonymous allowance is 60 requests per hour **per source address**, and 37 of them had already been used by someone else in that window.

## Candidate causes
| Cause | For | Against / unknown |
|---|---|---|
| Primary rate limit of the anonymous API (60/h per IP), exhausted because Cloudflare Workers share egress addresses with many other Workers | success runs show only 23 of 60 left with 15 minutes to reset; failures cluster; success is intermittent; GitHub documents the limit as per IP | no failed response body or `x-ratelimit-remaining` was captured |
| Secondary rate limit (burst/abuse heuristics) | possible on shared addresses | one request per hour from this client; not provable without the message |
| Missing permission | none: the repository is public and the endpoint needs no authentication | a 403 for lack of permission would be permanent, not 40% of runs |
| Missing headers | `User-Agent` and API version are sent; success runs use the same code | none |
| IP reputation / network | possible | indistinguishable from the above without the response |
Most likely: the first row. **Not proven**: the evidence needed is the response body and rate headers of a failing run, which the deployed code does not keep.

## Evidence gathered on 2026-10-24 (read-only)
- **GitHub's documentation** (REST rate limits, fetched today): unauthenticated requests get **60 per hour, keyed on the originating IP address**; authenticated users 5,000 per hour. A **primary** limit is a `403` or `429` with `x-ratelimit-remaining: 0` (wait for `x-ratelimit-reset`); a **secondary** limit is a `403`/`429` whose message names a secondary limit (wait `retry-after`, else at least a minute, then back off). The page does not say whether other 403 causes exist; it tells clients to read the message and the headers.
- **Anonymous request from this machine**: `x-ratelimit-limit: 60`, `x-ratelimit-resource: core`, `used: 20` (so even a quiet address had spent a third of its allowance), and `cache-control: public, max-age=60, s-maxage=60` with an ETag.
- **Does a conditional request save allowance?** For anonymous calls, **no**: the `304` answer lowered `x-ratelimit-remaining` from 39 to 38. So ETag logic would not relieve a shared address and was not added.
- **A syntactically valid but fake token** gets **`401 Bad credentials`**, not 403. A revoked or expired token will therefore show up as `github_unauthorized`, a different thing from a limit.

## Classification now in the collector (local)
| GitHub answer | Stored status | Meaning |
|---|---|---|
| 403/429, `x-ratelimit-remaining 0` (or 429, or "API rate limit exceeded") | `github_rate_limited` | primary limit of the address (anonymous) or the token |
| 403/429 whose message names a secondary limit | `github_secondary_limited` | burst heuristics; wait comes from `retry-after` (stored as `rate_reset_at`) |
| 401 | `github_unauthorized` | the token is invalid, expired or revoked (alert `github.token_rejected`) |
| 404 | `github_not_found` | repository missing, renamed or private |
| any other 403 | `github_forbidden` | e.g. blocked client; GitHub's own message is stored |
| 5xx / other | `github_error` | |

## What was done (local, not deployed)
- `7956d74`: every 403 is classified: `github_rate_limited` only if the status is 429, `x-ratelimit-remaining` is 0 or GitHub's message says so; any other 403 is `github_forbidden`. The message (GitHub's own text, with URLs, IPs and token-like strings redacted) and the rate headers are stored on **failure** too.
- `b635edd`: optional read-only token. `GITHUB_TOKEN` is used only if it is well-formed (`[A-Za-z0-9_-]{20,255}`), flagged in `gh_sync.authenticated` (migration `0002`) and shown on the Community dashboard; a malformed value is ignored and never sent; the value cannot appear in an error, a log row or the database even if GitHub echoes it (tested). A token raises the limit to 5,000/h **per token**, independent of the shared address. A fine-grained token with no repository permissions is enough for public data.
- Alert `github.collector_reliability` (success ratio over 24 h, needs ≥6 runs): the existing "three consecutive failures" rule would have fired only once in this data.
- An incident event to GuardOps is raised on the third consecutive failure, not on every blip.

## Impact on the numbers
GitHub's counters are **cumulative**, so a failed run delays an observation but loses no downloads: the next success records the full increase. What degrades is time resolution (the longest gap so far is 4 hours). Dashboards show coverage and the reliability ratio.

## To close it (owner)
1. Redeploy the branch (diagnostics, token support, migration `0002`). 2. Create a fine-grained GitHub token without permissions and set it with `pbpaste | node gateway/tools/set_worker_secret.mjs --name GITHUB_TOKEN` (add `--dry-run` first: it validates the shape and prints only a length; the value goes through a pipe to `wrangler secret put`, never into a command line, a history or this chat). 3. After a few cron runs, run `node gateway/tools/check_collector.mjs` (read-only): it prints `authenticated`, `rate_remaining`, the 24-hour success ratio and the failure causes, and says HEALTHY once authenticated with ≥ 95% of recent runs succeeding. If failures persist with a token, the stored message will say why.

## Authenticated collector: minimum privilege and handling (prepared 2026-10-24; the secret is not set)
- **Why a token at all:** the observed failures fit the anonymous per-IP allowance, but that is **not proven**. A token (a) removes the shared-address hypothesis from the problem and (b) makes the stored failure message decisive: if a 403 persists *with* a token, the redeployed collector records GitHub's own text and rate headers, so the true cause stops being a guess.
- **Token type:** a **fine-grained personal access token**, resource owner `MacGuard`, repository access **only** `macguard-yara-channel`, **no repository permissions** (the data is public; GitHub grants read of public metadata without any), expiry ≤ 90 days. No classic token, no `repo` scope, no write permission, no organisation permission. If a classic token is the only option, it must have **no scopes**.
- **Where it lives:** the Worker secret `GITHUB_TOKEN` only. It is set with `pbpaste | node gateway/tools/set_worker_secret.mjs --name GITHUB_TOKEN` (shape check, stdin only; `--dry-run` first). Never in the repo, a command line, chat, the Keychain item list of the other secrets, or a report. If it was ever pasted anywhere, rotate it.
- **Rotation:** create the new token, `set_worker_secret` again (the old one stops being used immediately), run `check_collector.mjs`, revoke the old token on GitHub. A token that expires or is revoked produces `github_unauthorized` and the alert `github.token_rejected`.
- **Success criterion (not met yet):** `check_collector.mjs` prints HEALTHY: authenticated, ≥ 95% of the last runs `ok`. Until observed, the cause of the 403s stays **UNKNOWN**.
