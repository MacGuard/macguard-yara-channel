// Pipeline activity for the panel, built only from real public records: GitHub Actions runs of daily.yml and publish.yml, GitHub releases, the public
// site's stats.json (last run of each day) and the repository's own run log. Nothing is estimated: a day with no run is NO_RUN, a source that cannot
// be read is reported as unavailable, and pipeline success is never confused with a published release.
//
// Day states (UTC days; the daily review is scheduled at 03:17 UTC):
//   OK            the day's primary run succeeded and nothing needs attention
//   WARNING       it succeeded but the run log reports previously published rules withheld, or the accounting invariant failed
//   FAIL          the primary run failed, timed out or never started (a manual re-run the same day is shown as `recovered`, not hidden)
//   CANCELLED     the primary run was cancelled
//   RUNNING       queued or in progress
//   NO_RUN        a past day with no daily run at all (absence is not zero rules and not a pass)
//   PENDING       today, before the schedule is overdue (GRACE_HOURS after the nominal time)
//   FUTURE        a day that has not happened; BEFORE: before the first recorded run
// The primary run is the scheduled one; a day with only manual runs uses the latest manual run and is flagged `manual_only`.

export const SCHEDULE_UTC = { hour: 3, minute: 17 };
export const GRACE_HOURS = 3;
export const CACHE_SECONDS = 300;
const DAY = 86400000;
const iso = (ms) => new Date(ms).toISOString();
const dayOf = (s) => String(s).slice(0, 10);
const secs = (a, b) => { const x = Date.parse(a), y = Date.parse(b); return Number.isFinite(x) && Number.isFinite(y) && y >= x ? Math.round((y - x) / 1000) : null; };
const runView = (r) => r && { id: r.id, event: r.event, status: r.status, conclusion: r.conclusion, created_at: r.created_at, started_at: r.run_started_at || r.created_at, updated_at: r.updated_at, duration_s: r.status === 'completed' ? secs(r.run_started_at || r.created_at, r.updated_at) : null, url: r.html_url, attempt: r.run_attempt || 1 };

function runState(r) {
  if (!r) return null;
  if (r.status !== 'completed') return 'RUNNING';
  switch (r.conclusion) { case 'success': return 'OK'; case 'cancelled': return 'CANCELLED'; case 'failure': case 'timed_out': case 'startup_failure': return 'FAIL'; default: return 'WARNING'; }   // neutral, skipped, stale, action_required: not a clean pass
}

/** inputs: {runs, publishRuns, releases, stats, log, sources, firstRunAt}; each may be null when its source could not be read. */
export function buildOverview(inputs, nowMs, days = 30) {
  const today = dayOf(iso(nowMs)), from = dayOf(iso(nowMs - (days - 1) * DAY));
  const byDay = new Map(), pubByDay = new Map(), relByDay = new Map(), statsByDay = new Map(), warnByDay = new Map();
  for (const r of inputs.runs || []) { const d = dayOf(r.created_at); (byDay.get(d) || byDay.set(d, []).get(d)).push(r); }
  for (const r of inputs.publishRuns || []) { const d = dayOf(r.created_at); (pubByDay.get(d) || pubByDay.set(d, []).get(d)).push(runView(r)); }
  for (const r of inputs.releases || []) { if (r.draft || !r.published_at) continue; const d = dayOf(r.published_at); (relByDay.get(d) || relByDay.set(d, []).get(d)).push({ tag: r.tag_name, published_at: r.published_at, url: r.html_url, prerelease: !!r.prerelease }); }
  for (const s of (inputs.stats && inputs.stats.days) || []) statsByDay.set(s.date, s);
  for (const e of inputs.log || []) { if (e.event === 'rules.withheld') { const d = dayOf(e.time || ''); const n = Number((/(\d+)/.exec(e.message || '') || [])[1]) || null; const w = warnByDay.get(d) || { withheld: 0 }; w.withheld = Math.max(w.withheld, n || 0); warnByDay.set(d, w); } }
  const first = inputs.firstRunAt ? dayOf(inputs.firstRunAt) : null, pendingUntil = Date.parse(`${today}T00:00:00Z`) + (SCHEDULE_UTC.hour + GRACE_HOURS) * 3600000;
  const out = [];
  for (let t = Date.parse(`${from}T00:00:00Z`); dayOf(iso(t)) <= today; t += DAY) {
    const date = dayOf(iso(t)), list = (byDay.get(date) || []).slice().sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));
    const sched = list.filter((r) => r.event === 'schedule'), manual = list.filter((r) => r.event !== 'schedule');
    const primary = sched.length ? sched[sched.length - 1] : manual.length ? manual[manual.length - 1] : null;
    const stats = statsByDay.get(date) || null, warn = warnByDay.get(date) || null, reasons = [];
    let state;
    if (primary) {
      state = runState(primary);
      if (state === 'OK') { if (warn && warn.withheld) reasons.push({ code: 'withheld', n: warn.withheld }); if (stats && stats.observed && stats.accounting_ok === false) reasons.push({ code: 'accounting' }); if (reasons.length) state = 'WARNING'; }
      else if (state === 'WARNING') reasons.push({ code: `conclusion_${primary.conclusion || 'unknown'}` });
    } else if (first && date < first) state = 'BEFORE';
    else if (date === today) state = nowMs < pendingUntil ? 'PENDING' : 'NO_RUN';
    else state = 'NO_RUN';
    const recovered = !!(sched.length && state === 'FAIL' && manual.some((r) => r.status === 'completed' && r.conclusion === 'success' && Date.parse(r.created_at) > Date.parse(primary.created_at)));
    out.push({ date, state, manual_only: !!primary && !sched.length, recovered, reasons, scheduled: runView(sched[sched.length - 1] || null), manual: manual.map(runView), runs: list.length,
      stats: stats && stats.observed ? { examined: stats.examined, accepted: stats.accepted, quarantined: stats.quarantined, rejected: stats.rejected, deprecated: stats.deprecated, accounting_ok: stats.accounting_ok, performance: stats.performance || null, new: stats.new, modified: stats.modified, removed: stats.removed } : null,
      releases: relByDay.get(date) || [], publish_runs: pubByDay.get(date) || [] });
  }
  // success rate of the scheduled runs of the window: unique days, success / (success + failure); cancelled, running and manual-only days are excluded
  const counted = out.filter((d) => d.scheduled && (d.scheduled.conclusion === 'success' || ['failure', 'timed_out', 'startup_failure'].includes(d.scheduled.conclusion)));
  const okN = counted.filter((d) => d.scheduled.conclusion === 'success').length;
  const dur = (arr) => arr.map((d) => (d.scheduled || d.manual.slice(-1)[0] || {}).duration_s).filter((x) => Number.isFinite(x));
  const last7 = dur(out.slice(-7)), prev7 = dur(out.slice(-14, -7)), avg = (a) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null);
  const summary = { ok: 0, warning: 0, fail: 0, cancelled: 0, running: 0, no_run: 0 };
  for (const d of out) { const k = d.state.toLowerCase(); if (k in summary) summary[k]++; }
  Object.assign(summary, { scheduled_counted: counted.length, scheduled_ok: okN, success_rate: counted.length ? Math.round((okN / counted.length) * 1000) / 10 : null,
    avg_duration_7d_s: avg(last7), avg_duration_prev_7d_s: avg(prev7), trend_valid: last7.length >= 3 && prev7.length >= 3 });
  const lastRun = (inputs.runs || []).slice().sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0] || null;
  const lastRel = (inputs.releases || []).filter((r) => !r.draft && r.published_at).sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at))[0] || null;
  const observed = out.filter((d) => d.stats).slice(-1)[0] || null;
  // upstream sources: the allow-list (config/sources.json) joined with the latest `sources.fetched` record of the run log
  const fetched = [...(inputs.log || [])].reverse().find((e) => e.event === 'sources.fetched');
  const pins = new Map(((fetched && fetched.details && fetched.details.sources) || []).map((s) => [s.repository, s.commit]));
  const sources = ((inputs.sources && inputs.sources.sources) || []).map((s) => ({ id: s.id, repo: s.repo, kind: s.kind, paths: s.paths || [], commit: pins.get(s.repo) || null, fetched_at: fetched ? fetched.time : null, run_id: fetched ? fetched.run_id : null }));
  return { window: { from, to: today, days }, days: out, summary,
    latest: { run: runView(lastRun), release: lastRel && { tag: lastRel.tag_name, published_at: lastRel.published_at, url: lastRel.html_url }, observed_day: observed && { date: observed.date, ...observed.stats } }, sources,
    definitions: { schedule_utc: `${String(SCHEDULE_UTC.hour).padStart(2, '0')}:${String(SCHEDULE_UTC.minute).padStart(2, '0')}`, pending_grace_hours: GRACE_HOURS } };
}

/** Reads every source once (in parallel). A source that fails is listed in `unavailable`; the rest is still returned. */
export async function loadOverview(env, deps, token, nowMs, days = 30) {
  const api = env.GITHUB_API || 'https://api.github.com', repo = env.REPO, site = env.PUBLIC_SITE || 'https://rules.mac-guard.com', raw = env.GITHUB_RAW || 'https://raw.githubusercontent.com';
  const gh = { Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  let rate = null; const unavailable = [];
  const getJson = async (name, url, headers, fallbackUrl) => {
    try { let r = await deps.fetch(url, { headers }); if (!r.ok && r.status === 404 && fallbackUrl) r = await deps.fetch(fallbackUrl, { headers }); if (r.headers && r.headers.get && r.headers.get('x-ratelimit-remaining') !== null) rate = { remaining: Number(r.headers.get('x-ratelimit-remaining')), limit: Number(r.headers.get('x-ratelimit-limit')) };
      if (!r.ok) { unavailable.push({ source: name, reason: r.status === 403 || r.status === 429 ? 'rate_limited' : `http_${r.status}` }); return null; } return r; }
    catch { unavailable.push({ source: name, reason: 'unreachable' }); return null; }
  };
  const since = dayOf(iso(nowMs - (days + 1) * DAY));
  const [runsR, pubR, relR, statsR, logR, srcR] = await Promise.all([
    getJson('runs', `${api}/repos/${repo}/actions/workflows/daily.yml/runs?per_page=100&exclude_pull_requests=true&created=%3E%3D${since}`, gh),
    getJson('publish_runs', `${api}/repos/${repo}/actions/workflows/publish.yml/runs?per_page=100&exclude_pull_requests=true&created=%3E%3D${since}`, gh),
    getJson('releases', `${api}/repos/${repo}/releases?per_page=100`, gh),
    getJson('stats', `${site}/stats.json`, { Accept: 'application/json' }),
    getJson('log', `${raw}/${repo}/logs/logs/log.jsonl`, { Accept: 'text/plain' }, `${raw}/${repo}/main/logs/log.jsonl`),   // the log lives on the `logs` branch; main keeps it frozen at the move
    getJson('sources', `${raw}/${repo}/main/config/sources.json`, { Accept: 'application/json' }),
  ]);
  const j = async (r, name) => { if (!r) return null; try { return await r.json(); } catch { unavailable.push({ source: name, reason: 'malformed' }); return null; } };
  const runs = await j(runsR, 'runs'), pub = await j(pubR, 'publish_runs'), rel = await j(relR, 'releases'), stats = await j(statsR, 'stats'), sources = await j(srcR, 'sources');
  let log = null;
  if (logR) { try { const text = await logR.text(); if (text.length > 3_000_000) unavailable.push({ source: 'log', reason: 'too_large' }); else log = text.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch { unavailable.push({ source: 'log', reason: 'malformed' }); } }
  const overview = buildOverview({ runs: runs && runs.workflow_runs, publishRuns: pub && pub.workflow_runs, releases: Array.isArray(rel) ? rel : null, stats, log, sources, firstRunAt: (log && log[0] && log[0].time) || ((stats && stats.days) || []).find((d) => d.observed)?.date || null }, nowMs, days);   // the run log starts with the first pipeline event
  return { ...overview, generated_at: iso(nowMs), rate, unavailable, limits: { cache_seconds: CACHE_SECONDS, github_anonymous_per_hour: 60, github_token_per_hour: 5000 } };
}
