// A realistic month of pipeline records, relative to "now", served through the faked GitHub: scheduled successes, a scheduled failure recovered by a manual run,
// a cancelled run, a day with no run, a manual-only day, a day with withheld rules, one run in progress today, two releases, public stats and the run log.
export function installOps(w, { down = [] } = {}) {
  const now = Date.now(), DAY = 86400000, utc = (n, h = 3, m = 20) => { const d = new Date(now - n * DAY); d.setUTCHours(h, m, 0, 0); return d.toISOString(); }, date = (n) => utc(n).slice(0, 10);
  let id = 1000; const mk = (n, event, conclusion, mins, h = 3, m = 20, status = 'completed') => { const c = utc(n, h, m); return { id: ++id, event, status, conclusion, created_at: c, run_started_at: c, updated_at: new Date(Date.parse(c) + mins * 60000).toISOString(), run_attempt: 1, html_url: `https://github.com/MacGuard/macguard-yara-channel/actions/runs/${id}` }; };
  const runs = [];
  for (let n = 19; n >= 1; n--) {
    if (n === 10) continue;                                              // no run at all
    if (n === 14) { runs.push(mk(n, 'schedule', 'failure', 2), mk(n, 'workflow_dispatch', 'success', 6, 12, 40)); continue; }
    if (n === 8) { runs.push(mk(n, 'schedule', 'cancelled', 1)); continue; }
    if (n === 6) { runs.push(mk(n, 'workflow_dispatch', 'success', 7, 15, 5)); continue; }
    runs.push(mk(n, 'schedule', 'success', 8 + (n % 4)));
  }
  runs.push(mk(0, 'schedule', null, 3, 0, 5, 'in_progress'));
  const publish = [mk(19, 'workflow_run', 'success', 1, 3, 40), mk(3, 'workflow_run', 'success', 1, 3, 40)];
  const releases = [{ tag_name: `rules-${date(3).replace(/-/g, '')}-1003`, published_at: utc(3, 3, 41), draft: false, html_url: 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/x3' }, { tag_name: `rules-${date(19).replace(/-/g, '')}-1001`, published_at: utc(19, 3, 41), draft: false, html_url: 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/x19' }];
  const sdays = []; for (let n = 19; n >= 1; n--) { if (n === 10 || n === 8) continue; sdays.push({ date: date(n), observed: true, examined: 1184, accepted: 1174, quarantined: 6, rejected: 4, deprecated: 0, accounting_ok: true, performance: { gate_seconds: 150 + n, classify_seconds: 11 }, new: null, modified: null, removed: null }); }
  const log = [{ event: 'run.started', level: 'INFO', time: utc(19, 3, 20), run_id: '1001', message: 'x' }, { event: 'sources.fetched', level: 'INFO', time: utc(1, 3, 21), run_id: '2001', message: 'Fetched 3 upstream sources at pinned commits.', details: { sources: [{ repository: 'Neo23x0/signature-base', commit: '3ce6640c26046da8e6d8094af3eaaee3ee84e648' }, { repository: 'Yara-Rules/rules', commit: '0f93570194a80d2f2032869055808b0ddcdfb360' }, { repository: 'VirusTotal/yara-x', commit: '20c794932b94698b048c6e5cce325c8a548cf9b5' }] } },
    { event: 'rules.withheld', level: 'WARNING', time: utc(3, 3, 30), run_id: '1003', message: '10 previously published rule files no longer pass the checks and are withheld until resolved.' }];
  const sources = { schema: 1, sources: [{ id: 'nextron', repo: 'Neo23x0/signature-base', kind: 'rules', paths: ['yara'] }, { id: 'community', repo: 'Yara-Rules/rules', kind: 'rules', paths: ['malware', 'packers', 'crypto'] }, { id: 'yara-x', repo: 'VirusTotal/yara-x', kind: 'engine', paths: [] }] };
  const hdr = { headers: { 'x-ratelimit-remaining': '4981', 'x-ratelimit-limit': '5000' } }, ok = (o) => new Response(JSON.stringify(o), hdr), bad = (k, f) => (down.includes(k) ? new Response('down', { status: 502 }) : f());
  w.route(/actions\/workflows\/daily\.yml\/runs/, () => bad('runs', () => ok({ workflow_runs: runs })));
  w.route(/actions\/workflows\/publish\.yml\/runs/, () => ok({ workflow_runs: publish }));
  w.route(/\/releases\?per_page/, () => ok(releases));
  w.route(/\/stats\.json$/, () => bad('stats', () => new Response(JSON.stringify({ schema: 1, days: sdays }))));
  w.route(/logs\/log\.jsonl$/, () => new Response(log.map((e) => JSON.stringify(e)).join('\n')));
  w.route(/config\/sources\.json$/, () => new Response(JSON.stringify(sources)));
  return { date, utc };
}
