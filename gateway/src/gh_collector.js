// Incremental collector of GitHub release download counters (https://docs.github.com/en/rest/releases/releases).
// GitHub's `download_count` is a CUMULATIVE counter per asset. It says nothing about who downloaded, from where, or whether a download finished. This module therefore:
//   * stores a row only when a counter changes (plus the first sight), with the exact interval it closes: no daily history is ever made up;
//   * computes a difference ONLY between two observations of the SAME asset_id, and only if the counter did not fall; a fall is a discontinuity that counts nothing;
//   * treats a replaced asset (same name in the same release, new asset_id) as a NEW series;
//   * classifies assets, so the bundle's downloads are never summed with its manifest's or signature's as if they were independent;
//   * records every sync (and every failure) so coverage and staleness are measurable.
// A failure here is isolated: it is recorded, it never throws to the caller of sync(), and nothing in the Community channel depends on it.
import { HttpError, iso } from './util.js';

export const KINDS = ['bundle', 'manifest', 'signature', 'checkpoint', 'checksums', 'changelog', 'proof', 'metadata', 'documentation', 'other'];
export function kindOf(name) {
  const n = String(name).toLowerCase();
  if (/(\.sigstore\.json|\.sig|\.asc|\.pem|\.cert)$/.test(n)) return 'signature';
  if (/^checkpoint\.txt$/.test(n)) return 'checkpoint';
  if (/^manifest\.json$/.test(n)) return 'manifest';
  if (/(sha256sums?|checksums?)(\.txt)?$|\.sha256$/.test(n)) return 'checksums';
  if (/^changelog(\.md)?$/.test(n)) return 'changelog';
  if (/^(inclusion-proof|consistency)\.json$/.test(n)) return 'proof';
  if (/^(release|changes)\.json$/.test(n)) return 'metadata';
  if (/\.(md|txt|pdf)$/.test(n)) return 'documentation';
  if (/\.(tar\.gz|tgz|tar\.zst|zip)$/.test(n)) return 'bundle';
  return 'other';
}

// A GitHub token is a bare credential: letters, digits, '_' and '-' only (classic, fine-grained and app tokens). Anything else (spaces, newlines, quotes) is refused so it can never inject a header, and
// the value is never echoed into an error or a stored message.
export const validToken = (t) => typeof t === 'string' && /^[A-Za-z0-9_-]{20,255}$/.test(t);

export async function fetchReleases(fetchImpl, { repo, token = null, baseUrl = 'https://api.github.com', maxPages = 10 }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error('bad repository name');
  const releases = []; let rate = {};
  for (let page = 1; page <= maxPages; page++) {
    let r;
    try { r = await fetchImpl(`${baseUrl}/repos/${repo}/releases?per_page=100&page=${page}`, { headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'macguard-analytics', ...(token ? { authorization: `Bearer ${token}` } : {}) }, signal: AbortSignal.timeout(15000) }); }
    catch { throw new HttpError(502, 'github_unreachable', 'GitHub could not be reached.'); }
    rate = { remaining: Number(r.headers.get('x-ratelimit-remaining') ?? NaN), reset: Number(r.headers.get('x-ratelimit-reset') ?? NaN) };
    if (r.status === 401) throw Object.assign(new HttpError(502, 'github_unauthorized', token ? 'GitHub rejected the token (401): it is invalid, expired or revoked.' : 'GitHub answered 401.'), { rate });
    if (r.status === 404) throw Object.assign(new HttpError(502, 'github_not_found', 'GitHub answered 404: the repository is missing, renamed or private.'), { rate });
    if (r.status === 403 || r.status === 429) {
      // GitHub's documented signals: PRIMARY = 403/429 with x-ratelimit-remaining 0; SECONDARY = 403/429 whose message names a secondary limit (wait retry-after, else a minute); any other 403 is something else.
      let msg = ''; try { msg = String((await r.json())?.message ?? '').replace(/https?:\/\/\S+/g, '').replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<ip>').replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+/g, '<token>').split(token ?? '\0').join('<token>').slice(0, 120); } catch { /* no JSON body */ }
      const ra = Number(r.headers.get('retry-after')); if (Number.isFinite(ra) && ra > 0) rate.retryAfter = ra;
      const secondary = /secondary rate limit|abuse detection/i.test(msg), primary = !secondary && (r.status === 429 || rate.remaining === 0 || /api rate limit exceeded/i.test(msg));
      const code = secondary ? 'github_secondary_limited' : primary ? 'github_rate_limited' : 'github_forbidden';
      throw Object.assign(new HttpError(secondary || primary ? 429 : 502, code, `GitHub answered ${r.status}${msg ? ': ' + msg : ''} (remaining ${Number.isFinite(rate.remaining) ? rate.remaining : '?'}${rate.retryAfter ? ', retry-after ' + rate.retryAfter + 's' : ''}).`), { rate });
    }
    if (!r.ok) throw Object.assign(new HttpError(502, 'github_error', `GitHub answered ${r.status}.`), { rate });
    const batch = await r.json(); if (!Array.isArray(batch)) throw new HttpError(502, 'github_error', 'Unexpected GitHub response.');
    releases.push(...batch); if (batch.length < 100) return { releases, rate, complete: true };
  }
  return { releases, rate, complete: false };                     // more pages than we are willing to read: reported as incomplete, never treated as a full listing
}

// Applies one complete listing observed at `observedAt`. Idempotent for the same listing and instant.
export async function ingest(db, repo, listing, observedAt) {
  const stats = { releases: 0, assets: 0, baselines: 0, deltas: 0, discontinuities: 0, replaced: 0, removed: 0 };
  const seenReleases = new Set(), seenAssets = new Set();
  for (const rel of listing) {
    if (rel.draft) continue;                                       // drafts are not public: their counters mean nothing
    stats.releases++; seenReleases.add(rel.id);
    await db.prepare(`INSERT INTO gh_releases(release_id,repo,tag,name,draft,prerelease,created_at,published_at,first_observed_at,last_observed_at) VALUES (?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(release_id) DO UPDATE SET tag=excluded.tag, name=excluded.name, prerelease=excluded.prerelease, published_at=excluded.published_at, last_observed_at=excluded.last_observed_at, deleted_at=NULL`)
      .bind(rel.id, repo, rel.tag_name, rel.name ?? null, 0, rel.prerelease ? 1 : 0, rel.created_at ?? null, rel.published_at ?? null, observedAt, observedAt).run();
    for (const a of rel.assets || []) {
      stats.assets++; seenAssets.add(a.id);
      const cur = await db.prepare('SELECT * FROM gh_assets WHERE asset_id = ?').bind(a.id).first();
      if (!cur) {
        const prior = await db.prepare('SELECT asset_id FROM gh_assets WHERE release_id = ? AND name = ? AND asset_id != ? ORDER BY first_observed_at DESC LIMIT 1').bind(rel.id, a.name, a.id).first();
        if (prior) stats.replaced++;
        await db.batch([
          db.prepare('INSERT INTO gh_assets(asset_id,release_id,name,kind,size,content_type,first_observed_at,last_observed_at,last_count,supersedes_asset_id) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(a.id, rel.id, a.name, kindOf(a.name), a.size ?? 0, a.content_type ?? null, observedAt, observedAt, a.download_count ?? 0, prior?.asset_id ?? null),
          db.prepare("INSERT INTO gh_observations(asset_id,observed_at,download_count,kind) VALUES (?,?,?,'baseline')").bind(a.id, observedAt, a.download_count ?? 0)]);
        stats.baselines++; continue;
      }
      const c = a.download_count ?? 0;
      if (c === cur.last_count) { await db.prepare('UPDATE gh_assets SET last_observed_at = ?, deleted_at = NULL, size = ? WHERE asset_id = ?').bind(observedAt, a.size ?? cur.size, a.id).run(); continue; }
      const kind = c > cur.last_count ? 'delta' : 'discontinuity';
      // (asset_id, observed_at) is the key of an observation. Two syncs inside the same second would collide and the variation would be lost while the counter moved on, so an observation is
      // always stamped strictly after the previous one of the same asset (a one-second nudge in that rare case, never a lost delta).
      const at = cur.last_observed_at && observedAt <= cur.last_observed_at ? iso(new Date(Date.parse(cur.last_observed_at) + 1000)) : observedAt;
      await db.batch([
        db.prepare('INSERT INTO gh_observations(asset_id,observed_at,download_count,prev_observed_at,prev_count,kind) VALUES (?,?,?,?,?,?)').bind(a.id, at, c, cur.last_observed_at, cur.last_count, kind),
        db.prepare('UPDATE gh_assets SET last_observed_at = ?, last_count = ?, deleted_at = NULL, size = ? WHERE asset_id = ?').bind(at, c, a.size ?? cur.size, a.id)]);
      stats[kind === 'delta' ? 'deltas' : 'discontinuities']++;
    }
  }
  // Absent from a COMPLETE listing = removed (kept for the record, flagged, never counted as zero).
  for (const r of (await db.prepare('SELECT release_id FROM gh_releases WHERE repo = ? AND deleted_at IS NULL').bind(repo).all()).results) if (!seenReleases.has(r.release_id)) { await db.prepare('UPDATE gh_releases SET deleted_at = ? WHERE release_id = ?').bind(observedAt, r.release_id).run(); stats.removed++; }
  for (const a of (await db.prepare('SELECT a.asset_id FROM gh_assets a JOIN gh_releases r ON r.release_id = a.release_id WHERE r.repo = ? AND a.deleted_at IS NULL').bind(repo).all()).results) if (!seenAssets.has(a.asset_id)) await db.prepare('UPDATE gh_assets SET deleted_at = ? WHERE asset_id = ?').bind(observedAt, a.asset_id).run();
  return stats;
}

// One synchronisation. Never throws: the outcome is recorded in gh_sync / gh_sync_log and returned.
export async function sync(db, clock, fetchImpl, { repo, token = null, baseUrl } = {}) {
  const at = iso(clock());
  const authenticated = validToken(token); if (token && !authenticated) token = null;           // a malformed secret is ignored (and reported below), never sent
  await db.prepare('INSERT OR IGNORE INTO gh_sync(id) VALUES (1)').run();
  try {
    const { releases, rate, complete } = await fetchReleases(fetchImpl, { repo, token, baseUrl });
    const rateAt = Number.isFinite(rate.reset) ? iso(new Date(rate.reset * 1000)) : null;
    if (!complete) { await db.prepare("UPDATE gh_sync SET last_attempt_at=?, last_status='incomplete', last_error='more release pages than the collector reads', consecutive_failures=consecutive_failures+1, rate_remaining=?, rate_reset_at=? WHERE id=1").bind(at, Number.isFinite(rate.remaining) ? rate.remaining : null, rateAt).run(); return { ok: false, status: 'incomplete' }; }
    const stats = await ingest(db, repo, releases, at);
    await db.batch([
      db.prepare("UPDATE gh_sync SET authenticated="+(authenticated?1:0)+", last_attempt_at=?, last_success_at=?, last_status='ok', last_error=NULL, consecutive_failures=0, first_success_at=COALESCE(first_success_at, ?), rate_remaining=?, rate_reset_at=? WHERE id=1").bind(at, at, at, Number.isFinite(rate.remaining) ? rate.remaining : null, rateAt),
      db.prepare("INSERT OR IGNORE INTO gh_sync_log(observed_at,releases,assets,status) VALUES (?,?,?,'ok')").bind(at, stats.releases, stats.assets)]);
    return { ok: true, status: 'ok', stats, authenticated };
  } catch (e) {
    const status = e.code ?? 'error';
    await db.prepare("UPDATE gh_sync SET authenticated="+(authenticated?1:0)+", last_attempt_at=?, last_status=?, last_error=?, consecutive_failures=consecutive_failures+1, rate_remaining=COALESCE(?, rate_remaining), rate_reset_at=COALESCE(?, rate_reset_at) WHERE id=1").bind(at, status, String(e.message ?? e).slice(0, 200), Number.isFinite(e.rate?.remaining) ? e.rate.remaining : null, Number.isFinite(e.rate?.reset) ? iso(new Date(e.rate.reset * 1000)) : e.rate?.retryAfter ? iso(new Date(clock().getTime() + e.rate.retryAfter * 1000)) : null).run().catch(() => {});
    await db.prepare("INSERT OR IGNORE INTO gh_sync_log(observed_at,releases,assets,status) VALUES (?,0,0,?)").bind(at, status).run().catch(() => {});
    return { ok: false, status, authenticated };
  }
}

// ---- reading ---------------------------------------------------------------------------------------------------------------------
// Cumulative figure = GitHub's own counter at the last observation (exact, but includes every download before this collector existed). Observed figure = growth seen by the
// collector since it started, built only from continuous intervals. They are different numbers and are never added together.
export async function downloadSummary(db, clock, { windowDays = 30 } = {}) {
  const now = clock(), from = iso(new Date(now.getTime() - windowDays * 86400000));
  const sync = await db.prepare('SELECT * FROM gh_sync WHERE id = 1').first();
  const rels = (await db.prepare('SELECT * FROM gh_releases ORDER BY published_at DESC, release_id DESC').all()).results;
  const assets = (await db.prepare('SELECT * FROM gh_assets').all()).results;
  const obs = (await db.prepare("SELECT o.*, a.release_id, a.kind AS akind FROM gh_observations o JOIN gh_assets a ON a.asset_id = o.asset_id WHERE o.kind = 'delta'").all()).results;
  const disc = (await db.prepare("SELECT COUNT(*) n FROM gh_observations WHERE kind = 'discontinuity'").first()).n;
  const firstAt = sync?.first_success_at ?? null;
  const inWindow = (o) => o.observed_at > from;
  const perRelease = rels.map((r) => {
    const mine = assets.filter((a) => a.release_id === r.release_id), bundles = mine.filter((a) => a.kind === 'bundle' && !a.deleted_at);
    const growth = obs.filter((o) => o.release_id === r.release_id && o.akind === 'bundle');
    return { release_id: r.release_id, tag: r.tag, published_at: r.published_at, deleted: !!r.deleted_at, first_observed_at: r.first_observed_at,
      bundle_downloads_cumulative: bundles.reduce((n, a) => n + a.last_count, 0), bundle_downloads_observed: growth.reduce((n, o) => n + (o.download_count - o.prev_count), 0),
      bundle_downloads_observed_in_window: growth.filter(inWindow).reduce((n, o) => n + (o.download_count - o.prev_count), 0) };
  });
  const byKind = {}; for (const a of assets) { const k = (byKind[a.kind] ??= { assets: 0, downloads_cumulative: 0 }); k.assets++; k.downloads_cumulative += a.last_count; }
  const windowMs = windowDays * 86400000, covStart = firstAt ? Math.max(Date.parse(firstAt), now.getTime() - windowMs) : now.getTime();
  const coverage = firstAt ? Math.min(1, Math.max(0, (now.getTime() - covStart) / windowMs)) : 0;
  const gaps = (await db.prepare("SELECT observed_at FROM gh_sync_log WHERE status = 'ok' AND observed_at > ? ORDER BY observed_at").bind(from).all()).results.map((r) => Date.parse(r.observed_at));
  let longestGap = 0; for (let i = 1; i < gaps.length; i++) longestGap = Math.max(longestGap, gaps[i] - gaps[i - 1]);
  const lastOk = sync?.last_success_at ?? null;
  return { source: 'github_release_download_count', window_days: windowDays, as_of: iso(now), collector_first_success_at: firstAt, last_success_at: lastOk, last_status: sync?.last_status ?? 'never_run',
    consecutive_failures: sync?.consecutive_failures ?? 0, staleness_seconds: lastOk ? Math.round((now.getTime() - Date.parse(lastOk)) / 1000) : null,
    coverage_of_window: +coverage.toFixed(4), longest_sync_gap_seconds: Math.round(longestGap / 1000), discontinuities_total: disc,
    totals: { bundle_downloads_cumulative: perRelease.reduce((n, r) => n + (r.deleted ? 0 : r.bundle_downloads_cumulative), 0), bundle_downloads_observed: perRelease.reduce((n, r) => n + r.bundle_downloads_observed, 0),
      bundle_downloads_observed_in_window: perRelease.reduce((n, r) => n + r.bundle_downloads_observed_in_window, 0) },
    releases: perRelease, by_asset_kind: byKind,
    accuracy: { cumulative: 'EXACT', observed: coverage >= 1 && longestGap <= 2 * 3600000 * 6 ? 'RECONCILED' : 'PARTIAL' },
    limitations: ['download_count counts requests GitHub served, not people, devices, countries or completed transfers', 'history before the collector started is unknown and is not estimated', 'bundle, manifest, signature and other assets are separate counters and are not summed as bundle downloads'] };
}

// Observed growth of the BUNDLE counters over day / week / month / year windows, with the share of each window the collector really covers (an uncovered part is unknown, never zero), plus a per-day
// series for the last 30 days (null before the first observation). Manifests, signatures, checkpoints and proofs are never added to these figures.
export async function observedWindows(db, clock) {
  const now = clock(), first = (await db.prepare('SELECT first_success_at f, last_success_at l FROM gh_sync WHERE id = 1').first()) ?? {}, firstMs = first.f ? Date.parse(first.f) : null;
  const rows = (await db.prepare("SELECT substr(o.observed_at,1,10) d, SUM(o.download_count - o.prev_count) n FROM gh_observations o JOIN gh_assets a ON a.asset_id = o.asset_id WHERE o.kind = 'delta' AND a.kind = 'bundle' GROUP BY d").all()).results;
  const byDay = new Map(rows.map((r) => [r.d, r.n])), dayStr = (ms) => new Date(ms).toISOString().slice(0, 10), DAY = 86400000;
  const windows = {};
  for (const [name, days] of [['day', 1], ['week', 7], ['month', 30], ['year_observed', 365]]) {
    const startMs = now.getTime() - days * DAY; let sum = 0; for (const [d, n] of byDay) if (Date.parse(d) + DAY > startMs) sum += n;
    const covered = firstMs === null ? 0 : Math.min(1, Math.max(0, (now.getTime() - Math.max(firstMs, startMs)) / (days * DAY)));
    windows[name] = { days, observed: firstMs === null ? null : sum, coverage: +covered.toFixed(4), state: firstMs === null ? 'NO_DATA' : covered < 1 ? 'PARTIAL_COVERAGE' : 'REAL_VERIFIED' };
  }
  const series = []; for (let i = 29; i >= 0; i--) { const ms = now.getTime() - i * DAY, d = dayStr(ms); series.push({ day: d, observed: firstMs !== null && ms + DAY > firstMs ? (byDay.get(d) ?? 0) : null }); }
  return { first_observation_at: first.f ?? null, last_success_at: first.l ?? null, days_observed: firstMs === null ? 0 : +((now.getTime() - firstMs) / DAY).toFixed(2), windows, series };
}
