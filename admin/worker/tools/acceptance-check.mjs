// Read-only acceptance check of the pipeline -> quarantine panel integration. It never writes to GitHub, D1 or the panel.
//
//   node tools/acceptance-check.mjs pre  <baseline.json>
//   node tools/acceptance-check.mjs post <run_id> <baseline.json>
//
// `pre` records the state before an activation or a first review and checks the preconditions. `post` proves what a run did from records that do not
// depend on the workflow's green status, and tells apart the things a re-run mixes up: the RUN (run_id) from its ATTEMPTS (run_attempt), the FIRST receipt
// of candidates from IDEMPOTENT RETRIES, and any PUBLICATION. Needs `gh` (authenticated), `wrangler` with D1 read access, git, and the production wrangler config.
//
// Every check ends PASS, FAIL or INCOMPLETE (the evidence could not be obtained: network, missing log, expired artifact, run still going...). Exit code:
// 0 only if everything is PASS, 1 if any check FAILS, 3 if nothing fails but something is INCOMPLETE. A discrepancy is never turned into PASS by ignoring it and a
// missing piece of evidence is never a PASS. The kind of run is read from the signed log (candidate.unchanged / candidate.changes) and the jobs; if it
// cannot be told, the run-specific checks are INCOMPLETE.
//
// The logic lives in verify(mode, args, io): the CLI builds a real `io` (gh, wrangler, git, fetch); the tests inject a fake one. `io` is wrapped in a guard that
// refuses anything that is not a read.
//
// The baseline (private by policy: keep it out of the repository) holds the state before the run and what the run is expected to produce:
//   audit {n, head}, release {tag, rules_root, files}, release_tags [every tag, drafts as "tag:draft"], visible_candidates, decisive_candidates, decisions,
//   expected_candidate_paths, previous_tag (signed manifest the withheld candidates must match) and, for a changed=true run,
//   expected_added_paths / expected_modified_paths / expected_removed_paths and added_hashes_source_tag.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { GENESIS, chainHash } from '../src/core.js';

export const PASS = 'PASS', FAIL = 'FAIL', INCOMPLETE = 'INCOMPLETE';
export class Incomplete extends Error {}
export class ReadOnlyViolation extends Error {}

// ---- rules_root: RFC 6962 Merkle tree exactly as scripts/tlog.py::rules_root (leaf = sha256(0x00||"path\0sha256"), node = sha256(0x01||l||r), sorted by path)
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
function mth(leaves) {
  const n = leaves.length; if (n === 0) return sha(''); if (n === 1) return leaves[0];
  let k = 1; while (k * 2 < n) k *= 2;
  return sha([1], mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}
export const rulesRoot = (files) => mth([...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).map((f) => sha([0], `${f.path}\0${f.sha256}`))).toString('hex');

// ---- read-only guard
const GH_WRITE = [/(^|\s)(-X|--method)[\s=]*(POST|PUT|PATCH|DELETE)/i, /\bworkflow\s+(run|enable|disable)\b/, /\brun\s+(rerun|cancel|delete)\b/, /\brelease\s+(create|edit|delete|upload)\b/, /\b(variable|secret)\s+(set|delete|remove)\b/, /(^|\s)(-f|-F|--field|--raw-field|--input)(\s|=)/];
const SQL_WRITE = /\b(insert|update|delete|drop|alter|create|replace|pragma|attach|detach|vacuum|truncate)\b/i;
export function guardIo(io) {
  const bad = (what) => { throw new ReadOnlyViolation(`write refused by the read-only guard: ${what}`); };
  return {
    gh: (path, jq) => { if (GH_WRITE.some((r) => r.test(path))) bad(`gh api ${path}`); return io.gh(path, jq); },
    ghRun: (args) => { const s = args.join(' '); if (GH_WRITE.some((r) => r.test(s)) || !(args[0] === 'run' && ['view', 'download', 'list'].includes(args[1]))) bad(`gh ${s}`); return io.ghRun(args); },
    d1: (sql) => { if (!/^\s*select\s/i.test(sql) || SQL_WRITE.test(sql)) bad(`D1 ${sql.slice(0, 40)}`); return io.d1(sql); },
    git: (args) => { if (!['fetch', 'show', 'log', 'rev-parse'].includes(args[0])) bad(`git ${args.join(' ')}`); return io.git(args); },
    fetchJson: (u) => io.fetchJson(u), fetchStatus: (u) => io.fetchStatus(u), readFile: (p) => io.readFile(p), now: () => io.now(),
    artifact: (run, name) => io.artifact(run, name), writeFile: (p, t) => io.writeFile(p, t),
  };
}

const need = (v, msg) => { if (v === undefined || v === null || v === '') throw new Incomplete(msg); return v; };
const same = (a, b) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);
const diff = (a, b) => a.filter((x) => !b.includes(x));
const HARD = new Set(['binary', 'no-rules', 'oversized', 'previously-rejected', 'too-many-rules']);
const BUSY = ['in_progress', 'queued', 'waiting', 'pending', 'requested'];

export async function verify(mode, args, io0, opts = {}) {
  const io = guardIo(io0), skip = new Set(opts.skip || []), results = [], notes = [];
  const REPO = args.repo || 'MacGuard/macguard-yara-channel', SITE = args.site || 'https://rules.mac-guard.com', PANEL = args.panel || 'https://panel.mac-guard.com';
  const note = (t) => notes.push(t), cache = new Map();
  const memo = (k, fn) => { if (!cache.has(k)) cache.set(k, Promise.resolve().then(fn)); return cache.get(k); };
  const check = async (id, name, fn) => {
    if (skip.has(id)) return; let status, detail = '';
    try { const r = await fn(); status = r.ok ? PASS : FAIL; detail = r.detail || ''; } catch (e) {
      if (e instanceof ReadOnlyViolation) throw e;
      status = INCOMPLETE; detail = e instanceof Incomplete ? e.message : `evidence unavailable: ${String(e.message).split('\n')[0].slice(0, 160)}`;
    }
    results.push({ id, name, status, detail });
  };
  const ok = (cond, detail) => ({ ok: !!cond, detail });
  const ghJ = async (path, jq) => { const s = await io.gh(path, jq); try { return JSON.parse(s); } catch { throw new Incomplete(`unparseable response of ${path.split('?')[0]}`); } };
  const manifest = (tag) => memo('man:' + tag, async () => { const m = await io.fetchJson(`https://github.com/${REPO}/releases/download/${need(tag, 'a tag needed to fetch a manifest is missing from the baseline')}/manifest.json`); if (!m || !Array.isArray(m.files)) throw new Incomplete(`manifest of ${tag} unreadable`); return new Map(m.files.map((f) => [f.path, f])); });
  const done = () => { const exit = results.some((r) => r.status === FAIL) ? 1 : results.some((r) => r.status === INCOMPLETE) ? 3 : 0; return { mode, results, notes, exit }; };

  if (mode === 'pre') {
    const snap = { at: io.now() };
    await check('pre-variables', 'repository variables readable', async () => { snap.variables = (await ghJ(`repos/${REPO}/actions/variables`, '[.variables[].name]')).join(','); return ok(true, snap.variables); });
    await check('pre-idle', 'no daily.yml / publish.yml run in progress', async () => {
      let busy = 0; for (const w of ['daily.yml', 'publish.yml']) for (const s of BUSY) busy += Number(await ghJ(`repos/${REPO}/actions/workflows/${w}/runs?status=${s}&per_page=1`, '.total_count'));
      return ok(busy === 0, `${busy} active`);
    });
    await check('pre-release', 'latest release recorded', async () => {
      const tag = (await ghJ(`repos/${REPO}/releases/latest`, '{tag:.tag_name}')).tag, man = await io.fetchJson(`https://github.com/${REPO}/releases/download/${tag}/manifest.json`);
      snap.release = { tag, rules_root: man.rules_root, files: man.files.length };
      snap.release_tags = (await ghJ(`repos/${REPO}/releases?per_page=100`, '[.[]|{tag:.tag_name,draft}]')).map((r) => r.tag + (r.draft ? ':draft' : '')).sort();
      return ok(tag && man.rules_root, `${tag} rules_root ${String(man.rules_root).slice(0, 16)}… (${man.files.length} files), ${snap.release_tags.length} release(s)`);
    });
    await check('pre-upstream', 'rule sources upstream HEADs equal those of the last review', async () => {
      const heads = { nextron: await io.gh('repos/Neo23x0/signature-base/commits/HEAD', '.sha'), community: await io.gh('repos/Yara-Rules/rules/commits/HEAD', '.sha') }; snap.upstream_heads = heads;
      const used = (await events()).filter((e) => e.event === 'sources.fetched').pop(), last = Object.fromEntries(need(used, 'no sources.fetched event').details.sources.map((s) => [s.repository, s.commit]));
      return ok(heads.nextron === last['Neo23x0/signature-base'] && heads.community === last['Yara-Rules/rules'], `signature-base ${heads.nextron.slice(0, 7)} / Yara-Rules ${heads.community.slice(0, 7)}`);
    });
    await check('pre-chain', 'D1 audit chain valid', async () => { const c = await chain(); snap.audit = { n: c.n, head: c.head }; return ok(c.ok, `${c.n} entries, head ${String(c.head).slice(0, 16)}…`); });
    await check('pre-panel-state', 'candidate and decision counts recorded', async () => {
      snap.visible_candidates = (await io.d1('SELECT COUNT(*) n FROM candidates WHERE archived_at IS NULL'))[0].n;
      snap.decisive_candidates = (await io.d1("SELECT COUNT(*) n FROM candidates WHERE archived_at IS NULL AND state IN ('APPROVED_PENDING_VALIDATION','REJECTED','RELEASED')"))[0].n;
      snap.decisions = (await io.d1('SELECT COUNT(*) n FROM decisions'))[0].n; return ok(true, `${snap.visible_candidates} visible, ${snap.decisive_candidates} decisive, ${snap.decisions} decision rows`);
    });
    await check('pre-panel-up', 'panel up; pipeline API closed to anonymous', async () => { const a = await io.fetchStatus(PANEL + '/'), b = await io.fetchStatus(PANEL + '/api/pipeline/decisions'); return ok(a === 200 && b === 401, `/ ${a}, pipeline ${b}`); });
    await check('pre-site-up', 'public site up', async () => ok((await io.fetchStatus(SITE + '/')) === 200));
    if (args.expectedPathsFile) snap.expected_candidate_paths = JSON.parse(await io.readFile(args.expectedPathsFile));
    await io.writeFile(args.baseline || 'baseline.json', JSON.stringify(snap, null, 1) + '\n'); note('baseline written');
    return done();
  }
  if (mode !== 'post') throw new Error('usage: acceptance-check.mjs pre <baseline.json> | post <run_id> <baseline.json>');

  const run = String(args.run); let base;
  try { base = JSON.parse(await io.readFile(args.baseline)); } catch { results.push({ id: 'baseline', name: 'baseline readable', status: INCOMPLETE, detail: 'baseline file unreadable' }); return done(); }
  async function events() { return memo('events', async () => { await io.git(['fetch', '-q', 'origin']); let text; try { text = await io.git(['show', 'origin/logs:logs/log.jsonl']); } catch { text = await io.git(['show', 'origin/main:logs/log.jsonl']); } return text.trim().split('\n').map((l) => JSON.parse(l)); }); }
  async function chain() {
    const rows = await io.d1('SELECT seq, at, actor, role, action, target, detail, prev_hash, hash FROM audit ORDER BY seq'); let prev = GENESIS;
    for (const r of rows) { const h = await chainHash(prev, { at: r.at, actor: r.actor, role: r.role, action: r.action, target: r.target, detail: r.detail }); if (r.prev_hash !== prev || r.hash !== h) return { ok: false, rows, n: rows.length }; prev = r.hash; }
    return { ok: true, rows, head: prev, n: rows.length };
  }
  const latestTag = () => memo('latest', async () => (await ghJ(`repos/${REPO}/releases/latest`, '{tag:.tag_name}')).tag);

  // ---- the run
  let info;
  try { info = await ghJ(`repos/${REPO}/actions/runs/${run}`, '{path,head_branch,event,run_attempt,created_at,status,conclusion}'); } catch (e) { results.push({ id: 'run-info', name: 'run readable', status: INCOMPLETE, detail: String(e.message).split('\n')[0].slice(0, 160) }); return done(); }
  if (info.status !== 'completed') { results.push({ id: 'run-finished', name: 'the run has finished', status: INCOMPLETE, detail: `status ${info.status}: nothing is concluded about a run still going` }); return done(); }
  await check('run-identity', 'run is daily.yml on main, started by workflow_dispatch', async () => ok(info.path === '.github/workflows/daily.yml' && info.head_branch === 'main' && info.event === 'workflow_dispatch', `${info.path} ${info.head_branch} ${info.event}; ${info.run_attempt} attempt(s), conclusion ${info.conclusion}`));

  // ---- the attempts (one view per attempt, then the aggregate)
  const attempts = await memo('attempts', async () => {
    const out = [];
    for (let k = 1; k <= info.run_attempt; k++) {
      const a = { k }; try {
        Object.assign(a, await ghJ(`repos/${REPO}/actions/runs/${run}/attempts/${k}`, '{by:.triggering_actor.login,created:.created_at,updated:.updated_at,conclusion}'));
        a.jobs = await ghJ(`repos/${REPO}/actions/runs/${run}/attempts/${k}/jobs`, '[.jobs[]|{name,conclusion,started_at}]');
      } catch (e) { a.error = String(e.message).split('\n')[0].slice(0, 120); a.jobs = a.jobs || []; }
      // A job that started before its attempt was created is a job REUSED from an earlier attempt ("re-run failed jobs"): it did not run again and its log is a copy.
      const t0 = a.created ? Date.parse(a.created) - 3000 : NaN;
      a.reviewRan = a.jobs.some((j) => j.name === 'review' && j.conclusion !== 'skipped' && !(j.started_at && t0 && Date.parse(j.started_at) < t0));
      try { a.log = await io.ghRun(['run', 'view', run, '--repo', REPO, '--attempt', String(k), '--log']); } catch { a.log = null; }
      const m = (a.log || '').match(/quarantine: (\d+) new, (\d+) already known/);
      a.logged = m ? { created: +m[1], known: +m[2] } : null; a.unavailable = /quarantine (decisions )?UNAVAILABLE/.test(a.log || ''); out.push(a);
    }
    return out;
  });
  const lastJob = (name) => { for (const a of [...attempts].reverse()) { const j = a.jobs.find((x) => x.name === name); if (j) return j.conclusion; } return undefined; };
  await check('attempts-evidence', 'every attempt has its jobs concluded and, if it ran the review, its log', async () => {
    const bad = attempts.filter((a) => a.error || a.jobs.length === 0 || a.jobs.some((j) => !j.conclusion) || (a.reviewRan && a.log === null)).map((a) => a.k);
    if (bad.length) throw new Incomplete(`attempt(s) ${bad.join(',')}: jobs or log not available`);
    return ok(true, `${attempts.length} attempt(s)`);
  });
  await check('no-unavailable', 'no attempt reported the service as unavailable', async () => ok(attempts.every((a) => !a.unavailable)));

  // ---- audit chain and receipts
  const c = await memo('chain', chain).catch((e) => ({ err: e }));
  await check('audit-chain', 'D1 audit chain valid', async () => { if (c.err) throw c.err; return ok(c.ok, `${c.n} entries`); });
  let receipts = null;
  if (c.rows && c.ok) {
    try {
      const n = need(base.audit && base.audit.n, 'baseline has no audit.n');
      receipts = c.rows.filter((e) => e.seq > n && e.action === 'pipeline.submit').map((e) => ({ seq: e.seq, at: e.at, actor: e.actor, role: e.role, target: e.target, ...JSON.parse(e.detail) }))
        .filter((e) => (e.token_run_id ? e.token_run_id === run : e.target === run))
        .map((e) => ({ ...e, attempt: e.run_attempt || attempts.find((a) => a.created && e.at >= a.created.replace('Z', '') && e.at <= a.updated.replace('Z', '.999'))?.k || null, kind: e.receipt || (e.created > 0 ? 'first' : 'idempotent_retry') }));
    } catch { receipts = null; }
  }
  const R = () => { if (!receipts) throw new Incomplete('receipts unavailable (audit chain or baseline)'); return receipts; };
  await check('audit-prefix', 'the audit entries of the baseline are still the same ones (head of the baseline reached at seq n)', async () => {
    if (c.err) throw c.err; need(base.audit && base.audit.head, 'baseline has no audit.head'); const row = c.rows.find((e) => e.seq === base.audit.n); need(row, 'baseline entry not readable');
    return ok(row.hash === base.audit.head, `entry ${base.audit.n}`);
  });
  await check('audit-new-entries', 'every audit entry added since the baseline is a pipeline.submit written by pipeline:daily.yml (only OIDC-validated tokens set the actor)', async () => {
    if (c.err) throw c.err; const rs = R(); return ok(c.rows.filter((e) => e.seq > base.audit.n).every((e) => e.action === 'pipeline.submit') && rs.every((e) => e.actor === 'pipeline:daily.yml' && e.role === 'PIPELINE' && String(e.run_url).endsWith(`/actions/runs/${run}`)), `${rs.length} receipt(s) of this run`);
  });
  await check('receipt-coherence', 'each receipt is coherent: first iff it created candidates, created <= count, token run id is this run', async () => {
    const rs = R(); return ok(rs.every((e) => e.kind === (e.created > 0 ? 'first' : 'idempotent_retry') && e.created <= e.count && (!e.token_run_id || e.token_run_id === run)), rs.map((e) => `seq ${e.seq}: attempt ${e.attempt ?? '?'} ${e.kind} ${e.count}/${e.created}`).join('; '));
  });
  await check('one-first', 'at most one first receipt in the run (any other receipt is an idempotent retry that created nothing)', async () => {
    const rs = R(), f = rs.filter((e) => e.kind === 'first'); return ok(f.length <= 1 && rs.filter((e) => e.created === 0).length + f.length === rs.length, `${f.length} first, ${rs.length - f.length} retries`);
  });
  await check('attempt-receipts', 'each attempt matches its own receipt: a review without a receipt is a failure when QUARANTINE_URL is set; a reused attempt has none; the first receipt belongs to the first review', async () => {
    const rs = R(); if (attempts.some((a) => a.error || (a.reviewRan && a.log === null))) throw new Incomplete('attempt evidence incomplete');
    const vars = await ghJ(`repos/${REPO}/actions/variables`, '[.variables[].name]'), url = vars.includes('QUARANTINE_URL'), problems = [];
    for (const a of attempts) {
      const mine = rs.filter((e) => e.attempt === a.k);
      if (!a.reviewRan) { if (mine.length) problems.push(`attempt ${a.k} did not run the review but has a receipt`); continue; }
      if (url && !a.unavailable && mine.length !== 1) problems.push(`attempt ${a.k} ran the review and has ${mine.length} receipts`);
      for (const e of mine) if (!a.logged || a.logged.created !== e.created || a.logged.created + a.logged.known !== e.count) problems.push(`attempt ${a.k} log line differs from receipt ${e.seq}`);
    }
    const first = rs.find((e) => e.kind === 'first'); if (first && attempts.find((a) => a.reviewRan)?.k !== first.attempt) problems.push('first receipt is not from the first attempt that ran the review');
    if (rs.some((e) => e.attempt === null)) problems.push('a receipt could not be placed in an attempt');
    return ok(!problems.length, problems.join('; ') || `QUARANTINE_URL ${url ? 'set' : 'not set'}`);
  });
  for (const a of attempts) {
    const mine = (receipts || []).filter((e) => e.attempt === a.k);
    note(`attempt ${a.k}: ${a.by}, ${(a.created || '').slice(11, 19)}-${(a.updated || '').slice(11, 19)}Z, ${a.conclusion}; jobs ${a.jobs.map((j) => j.name + ':' + j.conclusion).join(' ') || 'none'}${a.reviewRan || !a.jobs.some((j) => j.name === 'review') ? '' : ' (review reused from an earlier attempt)'}; log ${a.log === null ? 'absent' : a.logged ? `${a.logged.created} new, ${a.logged.known} known` : 'no receipt line'}; receipt ${mine.map((e) => `seq ${e.seq} ${e.kind} ${e.count}/${e.created}`).join(', ') || 'none'}`);
  }
  note(`run ${run} (aggregate): ${attempts.length} attempt(s), ${(receipts || []).length} receipt(s) [${(receipts || []).filter((e) => e.kind === 'first').length} first, ${(receipts || []).filter((e) => e.kind !== 'first').length} retries], jobs now ${['review', 'macos', 'app-compat', 'request-publish'].map((n) => n + ':' + (lastJob(n) ?? 'absent')).join(' ')}`);

  // ---- candidates in the panel
  const cands = await memo('cands', () => io.d1('SELECT sha256, path, state, reasons, version FROM candidates WHERE archived_at IS NULL ORDER BY path')).catch(() => null);
  await check('d1-candidates', 'candidates in D1: the number equals the baseline plus what receipts created, no duplicate path, no changed version', async () => {
    const rs = R(); if (!cands) throw new Incomplete('candidates not readable'); const exp = need(base.visible_candidates, 'baseline has no visible_candidates') + rs.reduce((s, e) => s + e.created, 0);
    return ok(cands.length === exp && new Set(cands.map((x) => x.path)).size === cands.length && cands.every((x) => x.version === 1), `D1 ${cands.length}, expected ${exp}`);
  });
  await check('d1-paths', 'every candidate path is one of the expected withheld files', async () => {
    if (!cands) throw new Incomplete('candidates not readable'); const allowed = new Set(need(base.expected_candidate_paths, 'baseline has no expected_candidate_paths')); return ok(cands.every((x) => allowed.has(x.path)), `${cands.filter((x) => !allowed.has(x.path)).length} outside`);
  });
  await check('d1-hashes', 'every candidate hash equals that path in the previous SIGNED manifest (content unchanged)', async () => {
    if (!cands) throw new Incomplete('candidates not readable'); const man = await manifest(base.previous_tag); const badN = cands.filter((x) => !man.has(x.path) || man.get(x.path).sha256 !== x.sha256).length; return ok(badN === 0, `${badN} differ of ${cands.length}`);
  });
  await check('d1-states', 'no technically rejected file entered the panel; all candidates PENDING', async () => { if (!cands) throw new Incomplete('candidates not readable'); return ok(cands.every((x) => x.state === 'PENDING' && !JSON.parse(x.reasons).some((r) => HARD.has(r)))); });
  await check('no-decisions', 'no approval or rejection exists or was added by the run', async () => {
    const decisive = (await io.d1("SELECT COUNT(*) n FROM candidates WHERE archived_at IS NULL AND state IN ('APPROVED_PENDING_VALIDATION','REJECTED','RELEASED')"))[0].n, dec = (await io.d1('SELECT COUNT(*) n FROM decisions'))[0].n;
    return ok(decisive === need(base.decisive_candidates, 'baseline has no decisive_candidates') && dec === need(base.decisions, 'baseline has no decisions'), `${decisive} decisive, ${dec} decision rows (baseline ${base.decisive_candidates}/${base.decisions})`);
  });

  // ---- kind of run, from the signed log
  const ev = await events().then((all) => all.filter((e) => e.run_id === run), () => null);
  const acc = ev && ev.find((e) => e.event === 'candidate.accepted'), hasChanges = ev && ev.some((e) => e.event === 'candidate.changes'), hasUnchanged = ev && ev.some((e) => e.event === 'candidate.unchanged');
  let kind = null; await check('run-kind', 'the kind of run (changed or unchanged) is determined by the signed log', async () => {
    if (!ev) throw new Incomplete('transparency log not readable'); if (hasChanges && hasUnchanged) return ok(false, 'log holds both candidate.changes and candidate.unchanged for the run');
    if (!hasChanges && !hasUnchanged) throw new Incomplete('no candidate.changes / candidate.unchanged event for the run (log not committed yet, or the run stopped early)');
    kind = hasChanges ? 'changed' : 'unchanged'; return ok(true, kind);
  });

  // ---- no publication, release intact (both kinds)
  await check('no-publish-run', 'PUBLICATION: no publish.yml run created since the run started', async () => { const n = Number(await ghJ(`repos/${REPO}/actions/workflows/publish.yml/runs?created=>=${info.created_at}&per_page=5`, '.total_count')); return ok(n === 0, `${n} publish run(s)`); });
  await check('request-publish-not-run', 'PUBLICATION: request-publish never ran in any attempt', async () => {
    const seen = attempts.flatMap((a) => a.jobs.filter((j) => j.name === 'request-publish').map((j) => j.conclusion)); if (attempts.some((a) => a.error)) throw new Incomplete('attempt jobs unavailable'); return ok(seen.every((s) => s === 'skipped'), `request-publish: ${seen.join(',') || 'absent'}`);
  });
  await check('release-unchanged', 'PUBLICATION: the latest release is the baseline one and the list of releases (drafts included) is identical', async () => {
    const tag = await latestTag(); need(base.release && base.release.tag, 'baseline has no release.tag'); const tags = need(base.release_tags, 'baseline has no release_tags');
    const now = (await ghJ(`repos/${REPO}/releases?per_page=100`, '[.[]|{tag:.tag_name,draft}]')).map((r) => r.tag + (r.draft ? ':draft' : ''));
    return ok(tag === base.release.tag && same(now, tags), `latest ${tag}; ${now.length} release(s), new: ${diff(now, tags).length}, missing: ${diff(tags, now).length}`);
  });
  await check('site-up', 'public site up', async () => ok((await io.fetchStatus(SITE + '/')) === 200));

  if (kind === 'unchanged') {
    await check('unchanged-root', 'PUBLICATION: the review reproduced the published set (same rules_root, candidate.unchanged, no candidate.changes)', async () => {
      need(acc, 'no candidate.accepted event for the run'); return ok(acc.details.rules_root === need(base.release && base.release.rules_root, 'baseline has no release.rules_root') && !hasChanges && hasUnchanged, `rules_root ${String(acc.details.rules_root).slice(0, 16)}…`);
    });
  }
  if (kind === 'changed') await changedChecks();
  return done();

  // ---- changed=true (acceptance) run
  async function changedChecks() {
    await check('acceptance-deduced', 'acceptance=true is deduced from independent evidence (dispatch + candidate.changes + macos success + request-publish skipped)', async () => {
      // request-publish runs iff publishable && changed && macos success (non-acceptance). macos only runs when publishable=='true', and candidate.changes means changed=='true'.
      // So: macos success + candidate.changes + request-publish skipped can only be an acceptance run. Anything else is not enough evidence.
      const rp = attempts.flatMap((a) => a.jobs.filter((j) => j.name === 'request-publish').map((j) => j.conclusion)); need(rp.length ? rp : null, 'request-publish job not listed: cannot deduce acceptance'); if (attempts.some((a) => a.error)) throw new Incomplete('attempt jobs unavailable');
      if (lastJob('macos') !== 'success') throw new Incomplete(`macos is ${lastJob('macos')}: cannot deduce acceptance from a skipped request-publish`);
      return ok(info.event === 'workflow_dispatch' && hasChanges && rp.every((s) => s === 'skipped'), `event ${info.event}, request-publish ${rp.join(',')}`);
    });
    await check('jobs-state', 'jobs: review, macos and app-compat success; request-publish skipped', async () => {
      const got = ['review', 'macos', 'app-compat', 'request-publish'].map((n) => [n, lastJob(n)]); if (got.some(([, s]) => s === undefined)) throw new Incomplete(`job(s) not listed: ${got.filter(([, s]) => s === undefined).map(([n]) => n).join(',')}`);
      return ok(got.every(([n, s]) => s === (n === 'request-publish' ? 'skipped' : 'success')), got.map(([n, s]) => `${n}:${s}`).join(' '));
    });
    const art = (name) => memo('art:' + name, async () => {
      const list = need(await ghJ(`repos/${REPO}/actions/runs/${run}/artifacts`, '[.artifacts[]|{name,expired}]'), 'artifact list unavailable'), a = list.find((x) => x.name === name);
      if (!a) throw new Incomplete(`artifact ${name} not listed`); if (a.expired) throw new Incomplete(`artifact ${name} expired`); return io.artifact(run, name);
    });
    const json = async (name, file) => { const a = await art(name), b = a.read(file); if (b === null || b === undefined) throw new Incomplete(`${file} missing from ${name}`); try { return JSON.parse(Buffer.from(b).toString('utf8')); } catch { throw new Incomplete(`${file} unreadable`); } };
    const cand = () => memo('candjson', () => json('candidate-' + run, 'candidate.json')), files = async () => { const f = (await cand()).files; if (!Array.isArray(f) || !f.length) throw new Incomplete('candidate.json holds no files'); return f; };
    const derived = () => memo('derived', async () => {
      const cur = await manifest(need(base.release && base.release.tag, 'baseline has no release.tag')), set = new Map((await files()).map((f) => [f.path, f]));
      return { added: [...set.keys()].filter((p) => !cur.has(p)).sort(), modified: [...set.keys()].filter((p) => cur.has(p) && cur.get(p).sha256 !== set.get(p).sha256).sort(), removed: [...cur.keys()].filter((p) => !set.has(p)).sort(), set, cur };
    });
    await check('changes-exact', 'changes.json (counters and added/modified/removed) equals the expectation of the baseline and the independent diff against the current release', async () => {
      const exp = { added: need(base.expected_added_paths, 'baseline has no expected_added_paths'), modified: need(base.expected_modified_paths, 'baseline has no expected_modified_paths'), removed: need(base.expected_removed_paths, 'baseline has no expected_removed_paths') };
      const ch = await json('candidate-' + run, 'changes.json'), d = await derived(), n = d.set.size, cnt = ch.counts || {};
      const lists = ['added', 'modified', 'removed'].every((k) => Array.isArray(ch[k]) && same(ch[k], exp[k]) && same(d[k], exp[k]) && cnt[k] === exp[k].length);
      return ok(ch.changed === true && lists && cnt.total === n && cnt.unchanged === n - d.added.length - d.modified.length, `+${d.added.length} ~${d.modified.length} -${d.removed.length}, total ${n}, unchanged ${cnt.unchanged}`);
    });
    await check('unchanged-hashes', 'hashes of the unchanged files equal the manifest of the current release', async () => {
      const d = await derived(), bad = [...d.set.keys()].filter((p) => d.cur.has(p) && !d.modified.includes(p) && d.cur.get(p).sha256 !== d.set.get(p).sha256); return ok(bad.length === 0, `${bad.length} differ`);
    });
    await check('added-hashes', 'hashes of the added and modified files equal the signed manifest named in the baseline', async () => {
      const src = await manifest(need(base.added_hashes_source_tag, 'baseline has no added_hashes_source_tag')), d = await derived(), pick = [...d.added, ...d.modified]; return ok(pick.every((p) => src.has(p) && src.get(p).sha256 === d.set.get(p).sha256), `${pick.filter((p) => !src.has(p) || src.get(p).sha256 !== d.set.get(p).sha256).length} differ of ${pick.length}`);
    });
    await check('file-bytes', 'the rule files of the public candidate hash to the sha256 of candidate.json', async () => {
      const a = await art('candidate-' + run), d = await derived(); let bad = 0; for (const [p, f] of d.set) { const b = a.read(p); if (b === null || b === undefined) throw new Incomplete(`${p.split('/').slice(-1)[0]} missing from the artifact`); if (createHash('sha256').update(b).digest('hex') !== f.sha256) bad++; } return ok(bad === 0, `${bad} differ of ${d.set.size}`);
    });
    await check('deps-closure', 'dependency closure: every depends_on is inside the set', async () => {
      const fl = await files(), paths = new Set(fl.map((f) => f.path)), miss = fl.flatMap((f) => (f.depends_on || []).filter((p) => !paths.has(p))); return ok(miss.length === 0, `${miss.length} missing dependencies, ${fl.filter((f) => (f.depends_on || []).length).length} files with dependencies`);
    });
    await check('rules-root', 'rules_root recomputed (RFC 6962) equals candidate.json, the candidate.accepted event and dynamic.json set_root', async () => {
      const fl = await files(), mine = rulesRoot(fl), dyn = await json('candidate-' + run, 'dynamic.json'), c0 = await cand(); need(acc, 'no candidate.accepted event for the run');
      const others = { 'candidate.json': c0.rules_root, event: acc.details.rules_root, 'dynamic.json': dyn.set_root }; if (c0.rules_root === undefined) delete others['candidate.json'];
      return ok(Object.values(others).every((v) => v === mine) && acc.details.file_count === fl.length, `recomputed ${mine.slice(0, 16)}… over ${fl.length} files; compared with ${Object.keys(others).join(', ')}`);
    });
    await check('dynamic-ok', 'dynamic.json verdict ok and canaries detected == expected', async () => { const d = await json('candidate-' + run, 'dynamic.json'); return ok(d.verdict === 'ok' && d.canaries_expected > 0 && d.canaries_detected === d.canaries_expected, `verdict ${d.verdict}, canaries ${d.canaries_detected}/${d.canaries_expected}`); });
    await check('validation-ok', 'validation.json has no failures', async () => { const v = await json('candidate-' + run, 'validation.json'), n = (await files()).length; return ok(Array.isArray(v.failures) && v.failures.length === 0 && v.checked === n, `${(v.failures || []).length} failure(s), checked ${v.checked}/${n}`); });
    await check('macos-validation', 'macos-validation verdict ok on the same set root', async () => {
      const m = await json('macos-validation-' + run, 'dynamic-macos.json'); return ok(m.verdict === 'ok' && m.set_root === rulesRoot(await files()) && m.canaries_expected > 0 && m.canaries_detected === m.canaries_expected, `verdict ${m.verdict}, ${m.platform}, canaries ${m.canaries_detected}/${m.canaries_expected}`);
    });
  }
}

// ---- CLI
function realIo() {
  const WORKER = resolve(dirname(fileURLToPath(import.meta.url)), '..'), REPO_DIR = resolve(WORKER, '../..');
  const D1 = process.env.D1_NAME || 'macguard-quarantine', CONFIG = process.env.WRANGLER_CONFIG || 'wrangler.production.toml';
  const sh = (cmd, args, cwd) => execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 256e6, cwd, stdio: ['ignore', 'pipe', 'ignore'], timeout: 180000 });
  const tmo = () => AbortSignal.timeout(60000);
  return {
    gh: (path, jq) => sh('gh', ['api', path, ...(jq ? ['--jq', jq] : [])]).trim(),
    ghRun: (args) => sh('gh', args),
    d1: (sql) => JSON.parse(sh('npx', ['wrangler', 'd1', 'execute', D1, '--remote', '--config', CONFIG, '--json', '--command', sql], WORKER))[0].results,
    git: (args) => sh('git', args, REPO_DIR),
    fetchJson: async (u) => { const r = await fetch(u, { signal: tmo() }); if (!r.ok) throw new Error(`${r.status} ${u.split('/').slice(-3).join('/')}`); return r.json(); },
    fetchStatus: async (u) => (await fetch(u, { signal: tmo() })).status,
    readFile: (p) => readFileSync(p, 'utf8'), writeFile: (p, t) => writeFileSync(p, t), now: () => new Date().toISOString(),
    artifact: (run, name) => { const dir = mkdtempSync(join(tmpdir(), 'acc-art-')); sh('gh', ['run', 'download', run, '--repo', process.env.REPO || 'MacGuard/macguard-yara-channel', '-n', name, '-D', dir]); return { read: (rel) => { try { return readFileSync(join(dir, rel)); } catch { return null; } } }; },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [mode, a, b] = process.argv.slice(2);
  if (!['pre', 'post'].includes(mode) || !a || (mode === 'post' && !b)) { console.error('usage: acceptance-check.mjs pre <baseline.json> | post <run_id> <baseline.json>'); process.exit(2); }
  const args = mode === 'pre' ? { baseline: a, expectedPathsFile: process.env.EXPECTED_PATHS_FILE, repo: process.env.REPO, site: process.env.SITE_URL, panel: process.env.PANEL_URL } : { run: a, baseline: b, repo: process.env.REPO, site: process.env.SITE_URL };
  const r = await verify(mode, args, realIo());
  for (const n of r.notes) console.log(`NOTE  ${n}`);
  for (const x of r.results) console.log(`${x.status.padEnd(10)} ${x.name}${x.detail ? '  — ' + x.detail : ''}`);
  const c = (s) => r.results.filter((x) => x.status === s).length; console.log(`RESULT  ${c(PASS)} PASS, ${c(FAIL)} FAIL, ${c(INCOMPLETE)} INCOMPLETE  -> exit ${r.exit}`); process.exit(r.exit);
}
