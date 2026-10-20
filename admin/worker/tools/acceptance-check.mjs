// Read-only acceptance check of the pipeline -> quarantine panel integration. It never writes to GitHub, D1 or the panel.
//
//   node tools/acceptance-check.mjs pre  <baseline.json>
//   node tools/acceptance-check.mjs post <run_id> <baseline.json>
//
// `pre` records the state before an activation or a first review and checks the preconditions. `post` proves what a run did from records that do not depend
// on the workflow's green status, and tells apart the things a re-run mixes up: the RUN (run_id) from its ATTEMPTS (run_attempt), the FIRST receipt of
// candidates from IDEMPOTENT RETRIES, and any PUBLICATION. Needs `gh` (authenticated), `wrangler` with D1 read access, git, and the production wrangler config.
//
// The baseline holds the paths of the files the review is expected to send (private by policy: keep that file out of the repository).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GENESIS, chainHash } from '../src/core.js';

const WORKER = resolve(dirname(fileURLToPath(import.meta.url)), '..'), REPO_DIR = resolve(WORKER, '../..');
const REPO = process.env.REPO || 'MacGuard/macguard-yara-channel', PANEL = process.env.PANEL_URL || 'https://panel.mac-guard.com', SITE = process.env.SITE_URL || 'https://rules.mac-guard.com';
const D1 = process.env.D1_NAME || 'macguard-quarantine', WRANGLER_CONFIG = process.env.WRANGLER_CONFIG || 'wrangler.production.toml';
const sh = (cmd, args, cwd) => execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 256e6, cwd, stdio: ['ignore', 'pipe', 'ignore'] });
const gh = (path, jq) => sh('gh', ['api', path, ...(jq ? ['--jq', jq] : [])]).trim();
const d1 = (sql) => JSON.parse(sh('npx', ['wrangler', 'd1', 'execute', D1, '--remote', '--config', WRANGLER_CONFIG, '--json', '--command', sql], WORKER))[0].results;
const results = [];
const check = (name, ok, detail) => { results.push({ name, ok: !!ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`); };
const note = (text) => console.log(`NOTE  ${text}`);

async function chain() {
  const rows = d1('SELECT seq, at, actor, role, action, target, detail, prev_hash, hash FROM audit ORDER BY seq'); let prev = GENESIS;
  for (const r of rows) { const h = await chainHash(prev, { at: r.at, actor: r.actor, role: r.role, action: r.action, target: r.target, detail: r.detail }); if (r.prev_hash !== prev || r.hash !== h) return { ok: false, rows }; prev = r.hash; }
  return { ok: true, rows, head: prev, n: rows.length };
}
const latestRelease = () => JSON.parse(gh(`repos/${REPO}/releases/latest`, '{tag:.tag_name}')).tag;
const fetchManifest = async (tag) => (await fetch(`https://github.com/${REPO}/releases/download/${tag}/manifest.json`)).json();
const logEvents = () => { sh('git', ['fetch', '-q', 'origin'], REPO_DIR); return sh('git', ['show', 'origin/main:logs/log.jsonl'], REPO_DIR).trim().split('\n').map((l) => JSON.parse(l)); };
const finish = () => process.exit(results.every((r) => r.ok) ? 0 : 1);

const mode = process.argv[2];

if (mode === 'pre') {
  const snap = { at: new Date().toISOString() };
  snap.variables = gh(`repos/${REPO}/actions/variables`, '[.variables[].name]|join(",")');
  const busy = ['daily.yml', 'publish.yml'].flatMap((w) => ['in_progress', 'queued', 'waiting', 'pending', 'requested'].map((s) => Number(gh(`repos/${REPO}/actions/workflows/${w}/runs?status=${s}&per_page=1`, '.total_count')))).reduce((a, b) => a + b, 0);
  check('no daily.yml / publish.yml run in progress', busy === 0, `${busy} active`);
  const tag = latestRelease(), man = await fetchManifest(tag); snap.release = { tag, rules_root: man.rules_root, files: man.files.length };
  check('latest release recorded', tag && man.rules_root, `${tag} rules_root ${man.rules_root.slice(0, 16)}… (${man.files.length} files)`);
  const heads = { nextron: gh('repos/Neo23x0/signature-base/commits/HEAD', '.sha'), community: gh('repos/Yara-Rules/rules/commits/HEAD', '.sha') }; snap.upstream_heads = heads;
  const used = logEvents().filter((e) => e.event === 'sources.fetched').pop(), last = Object.fromEntries(used.details.sources.map((s) => [s.repository, s.commit]));
  check('rule sources upstream HEADs equal those of the last review (a review would reproduce the published set)', heads.nextron === last['Neo23x0/signature-base'] && heads.community === last['Yara-Rules/rules'], `signature-base ${heads.nextron.slice(0, 7)} / Yara-Rules ${heads.community.slice(0, 7)}`);
  const c = await chain(); snap.audit = { n: c.n, head: c.head }; check('D1 audit chain valid', c.ok, `${c.n} entries, head ${c.head && c.head.slice(0, 16)}…`);
  const visible = d1('SELECT COUNT(*) n FROM candidates WHERE archived_at IS NULL')[0].n, decisive = d1("SELECT COUNT(*) n FROM candidates WHERE archived_at IS NULL AND state IN ('APPROVED_PENDING_VALIDATION','REJECTED','RELEASED')")[0].n;
  snap.visible_candidates = visible; snap.decisive_candidates = decisive; snap.decisions = d1('SELECT COUNT(*) n FROM decisions')[0].n;
  note(`panel: ${visible} visible candidates, ${decisive} with an approval, rejection or release the pipeline would read`);
  const pr = await fetch(PANEL + '/'), pp = await fetch(PANEL + '/api/pipeline/decisions'); check('panel up; pipeline API closed to anonymous', pr.status === 200 && pp.status === 401, `/ ${pr.status}, pipeline ${pp.status}`);
  check('public site up', (await fetch(SITE + '/')).status === 200);
  const expected = process.env.EXPECTED_PATHS_FILE ? JSON.parse(readFileSync(process.env.EXPECTED_PATHS_FILE, 'utf8')) : null; if (expected) snap.expected_candidate_paths = expected;
  writeFileSync(process.argv[3] || 'baseline.json', JSON.stringify(snap, null, 1) + '\n'); console.log('baseline written'); finish();
}

if (mode === 'post') {
  const run = process.argv[3], base = JSON.parse(readFileSync(process.argv[4], 'utf8'));
  const info = JSON.parse(gh(`repos/${REPO}/actions/runs/${run}`, '{path,head_branch,event,run_attempt,created_at}')); const attempts = [];
  check('run is daily.yml on main', info.path === '.github/workflows/daily.yml' && info.head_branch === 'main', `${info.path} ${info.head_branch} ${info.event}; ${info.run_attempt} attempt(s)`);
  for (let k = 1; k <= info.run_attempt; k++) {
    const a = JSON.parse(gh(`repos/${REPO}/actions/runs/${run}/attempts/${k}`, '{by:.triggering_actor.login,created:.created_at,updated:.updated_at,conclusion}'));
    const jobs = JSON.parse(gh(`repos/${REPO}/actions/runs/${run}/attempts/${k}/jobs`, '[.jobs[]|{name,conclusion}]')); let log = '';
    try { log = sh('gh', ['run', 'view', run, '--repo', REPO, '--attempt', String(k), '--log']); } catch { /* an attempt with no jobs has no log */ }
    const m = log.match(/quarantine: (\d+) new, (\d+) already known/);
    attempts.push({ k, ...a, jobs, reviewRan: jobs.some((j) => j.name === 'review' && j.conclusion !== 'skipped'), logged: m ? { created: +m[1], known: +m[2] } : null, unavailable: /quarantine (decisions )?UNAVAILABLE/.test(log) });
    note(`attempt ${k}: ${a.by}, ${a.created.slice(11, 19)}–${a.updated.slice(11, 19)}Z, ${a.conclusion}; jobs ${jobs.map((j) => j.name + ':' + j.conclusion).join(' ')}; log ${m ? `${m[1]} new, ${m[2]} known` : 'no receipt line'}`);
  }
  check('no attempt reported the service as unavailable', attempts.every((a) => !a.unavailable));
  const c = await chain(); check('D1 audit chain valid', c.ok, `${c.n} entries`);
  // receipts of this RUN: by the run id the verified token carries (entries from before the Worker recorded it: by the run id in the target and the attempt's time window)
  const receipts = c.rows.filter((e) => e.seq > base.audit.n && e.action === 'pipeline.submit').map((e) => ({ seq: e.seq, at: e.at, actor: e.actor, role: e.role, target: e.target, ...JSON.parse(e.detail) }))
    .filter((e) => (e.token_run_id ? e.token_run_id === run : e.target === run)).map((e) => ({ ...e, attempt: e.run_attempt || attempts.find((a) => e.at >= a.created.replace('Z', '') && e.at <= a.updated.replace('Z', '.999'))?.k || null }));
  check('every audit entry added since the baseline is a pipeline.submit written by pipeline:daily.yml (OIDC validated: only then is the actor set)', c.rows.filter((e) => e.seq > base.audit.n).every((e) => e.action === 'pipeline.submit') && receipts.every((e) => e.actor === 'pipeline:daily.yml' && e.role === 'PIPELINE' && e.run_url.endsWith(`/actions/runs/${run}`)), `${receipts.length} receipt(s)`);
  const firsts = receipts.filter((e) => e.created > 0), retries = receipts.filter((e) => e.created === 0 && e.count > 0);
  for (const e of receipts) note(`receipt seq ${e.seq}: attempt ${e.attempt ?? '?'} ${e.receipt || (e.created > 0 ? 'first' : 'idempotent_retry')} — ${e.count} candidates, ${e.created} created${e.token_run_id ? ' (run and attempt from the verified token)' : ' (older entry: attempt placed by time window)'}`);
  check('exactly one first receipt created the candidates; every other receipt of the run is an idempotent retry that created nothing', firsts.length === 1 && firsts.length + retries.length === receipts.length, `${firsts.length} first, ${retries.length} retries`);
  check('the first receipt belongs to the first attempt that ran the review, and each receipt matches that attempt\'s own log line', firsts.length === 1 && attempts.filter((a) => a.reviewRan)[0]?.k === firsts[0].attempt && receipts.every((e) => { const a = attempts.find((x) => x.k === e.attempt); return a && a.logged && a.logged.created === e.created && a.logged.created + a.logged.known === e.count; }));
  const cands = d1('SELECT sha256, path, state, reasons, version FROM candidates WHERE archived_at IS NULL ORDER BY path');
  check('candidates really arrived in D1 (1 to 6), once each: the number equals what the first receipt created and no retry added or changed any', firsts.length === 1 && cands.length >= 1 && cands.length <= 6 && cands.length === firsts[0].created && cands.every((x) => x.version === 1), `D1 ${cands.length}, first receipt created ${firsts[0]?.created}`);
  const man = new Map((await fetchManifest(process.env.PREVIOUS_TAG || 'rules-20261018-39103534527')).files.map((f) => [f.path, f])), allowed = new Set(base.expected_candidate_paths || []);
  check('every candidate path is one of the expected withheld files', cands.length > 0 && cands.every((x) => allowed.has(x.path)), `${cands.filter((x) => !allowed.has(x.path)).length} outside`);
  check('every candidate hash equals the hash of that path in the previous SIGNED manifest (content unchanged; differences are reported, not hidden)', cands.length > 0 && cands.every((x) => man.has(x.path) && man.get(x.path).sha256 === x.sha256), `${cands.filter((x) => !man.has(x.path) || man.get(x.path).sha256 !== x.sha256).length} differ`);
  const HARD = new Set(['binary', 'no-rules', 'oversized', 'previously-rejected', 'too-many-rules']);
  check('no technically rejected file entered the panel; all candidates PENDING', cands.length > 0 && cands.every((x) => x.state === 'PENDING' && !JSON.parse(x.reasons).some((r) => HARD.has(r))));
  const decisive = d1("SELECT COUNT(*) n FROM candidates WHERE archived_at IS NULL AND state IN ('APPROVED_PENDING_VALIDATION','REJECTED','RELEASED')")[0].n, dec = d1('SELECT COUNT(*) n FROM decisions')[0].n;
  check('no approval or rejection exists or was added by the run', decisive === base.decisive_candidates && dec === base.decisions, `${decisive} decisive visible, ${dec} decision rows (baseline ${base.decisions})`);
  const ev = logEvents().filter((e) => e.run_id === run), acc = ev.find((e) => e.event === 'candidate.accepted'), changed = ev.some((e) => e.event === 'candidate.changes');
  check('PUBLICATION: the review reproduced the published set (same rules_root, no release requested)', acc && acc.details.rules_root === base.release.rules_root && !changed && ev.some((e) => e.event === 'candidate.unchanged'), acc ? `rules_root ${acc.details.rules_root.slice(0, 16)}…` : 'no accepted event');
  const pubs = gh(`repos/${REPO}/actions/workflows/publish.yml/runs?created=>=${info.created_at}&per_page=5`, '.total_count');
  check('PUBLICATION: no publish.yml run since the dispatch, and the latest release is unchanged', pubs === '0' && latestRelease() === base.release.tag, `${pubs} publish runs; latest ${latestRelease()}`);
  check('public site up', (await fetch(SITE + '/')).status === 200); finish();
}
console.error('usage: acceptance-check.mjs pre <baseline.json> | post <run_id> <baseline.json>'); process.exit(2);
