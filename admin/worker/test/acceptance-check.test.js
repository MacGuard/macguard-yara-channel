// Tests of tools/acceptance-check.mjs with a FAKE io: no network, no gh, no D1. Synthetic data only (no real rule names or hashes).
// Positive worlds must give PASS / exit 0; each negative control breaks ONE thing and must give the expected state and exit code
// (FAIL -> 1, INCOMPLETE -> 3); a mutation test removes a critical check and proves the matching test would notice.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { GENESIS, chainHash } from '../src/core.js';
import { verify, guardIo, rulesRoot, ReadOnlyViolation } from '../tools/acceptance-check.mjs';

const RUN = '4000', REPO = 'MacGuard/macguard-yara-channel', SELF = fileURLToPath(new URL('../tools/acceptance-check.mjs', import.meta.url));
const hex = (s) => createHash('sha256').update(s).digest('hex');
const content = (p, v = '') => `content of ${p}${v}`;
const file = (p, extra = {}) => ({ path: p, sha256: hex(content(p)), bytes: content(p).length, source: 'synth', ...extra });
const A = ['f0', 'f1', 'f2', 'f3', 'f4'].map((n) => `rules/synth/${n}.yar`), ADD = ['a0', 'a1', 'a2'].map((n) => `rules/synth/${n}.yar`);

// ---- the world: everything the real tool would read, as plain data (mutated by each scenario before the io is built)
async function world(o = {}) {
  const kind = o.kind || 'changed', first = !!o.first, w = {
    info: { path: '.github/workflows/daily.yml', head_branch: 'main', event: 'workflow_dispatch', run_attempt: 1, created_at: '2026-10-20T22:00:00Z', status: 'completed', conclusion: 'success' },
    variables: ['AUTO_PUBLISH', 'QUARANTINE_URL'], publishRuns: 0, siteStatus: 200, latest: 'rules-A', releases: [{ tag: 'rules-A', draft: false }, { tag: 'rules-P', draft: false }], logAbsent: false,
  };
  const relA = A.map((p) => file(p)), relP = [...relA, ...ADD.map((p) => file(p))];
  const set = kind === 'changed' ? relP.map((f) => (f.path === ADD[2] ? { ...f, depends_on: [ADD[0]] } : { ...f })) : relA.map((f) => ({ ...f }));
  const created = first ? 2 : 0, known = 2 - created;
  w.attempts = [{ meta: { by: 'tester', created: '2026-10-20T22:00:01Z', updated: '2026-10-20T22:10:00Z', conclusion: 'success' },
    jobs: kind === 'changed' ? [['review', 'success'], ['macos', 'success'], ['app-compat', 'success'], ['request-publish', 'skipped']] : [['review', 'success'], ['macos', 'skipped'], ['app-compat', 'skipped'], ['request-publish', 'skipped']],
    log: `...\nquarantine: ${created} new, ${known} already known\n...` }];
  w.attempts[0].jobs = w.attempts[0].jobs.map(([name, conclusion]) => ({ name, conclusion, started_at: '2026-10-20T22:00:05Z' }));
  w.manifests = { 'rules-A': { files: relA }, 'rules-P': { files: relP } };
  const root = rulesRoot(set);
  w.events = [{ event: 'candidate.accepted', run_id: RUN, details: { rules_root: root, file_count: set.length } }, { event: kind === 'changed' ? 'candidate.changes' : 'candidate.unchanged', run_id: RUN, details: {} },
    { event: 'candidate.changes', run_id: '3999', details: {} }];
  w.artifacts = [{ name: `candidate-${RUN}`, expired: false }, { name: `macos-validation-${RUN}`, expired: false }];
  const byteMap = new Map(set.map((f) => [f.path, Buffer.from(content(f.path))]));
  w.art = {
    [`candidate-${RUN}`]: { 'candidate.json': { files: set, rules_root: root }, 'changes.json': { changed: true, counts: { added: 3, modified: 0, removed: 0, unchanged: 5, total: 8 }, added: [...ADD], modified: [], removed: [] },
      'dynamic.json': { verdict: 'ok', set_root: root, canaries_detected: 5, canaries_expected: 5 }, 'validation.json': { checked: set.length, failures: [] } },
    [`macos-validation-${RUN}`]: { 'dynamic-macos.json': { verdict: 'ok', platform: 'darwin', set_root: root, canaries_detected: 5, canaries_expected: 5 } },
  };
  w.bytes = byteMap;
  w.cands = (kind === 'changed' ? [ADD[1], ADD[2]] : [ADD[0], ADD[1]]).map((p) => ({ sha256: hex(content(p)), path: p, state: 'PENDING', reasons: '["matches-benign-corpus"]', version: 1 }));
  w.decisive = 0; w.decisions = 1;
  // audit: three earlier logins, then the receipts of this run (built last so the chain is valid unless a scenario breaks it)
  w.priorAudit = 3;
  w.receipts = [{ attempt: 1, created, count: 2, receipt: first ? 'first' : 'idempotent_retry' }];
  w.base = {
    audit: { n: 3 }, release: { tag: 'rules-A', rules_root: rulesRoot(relA), files: relA.length }, release_tags: ['rules-A', 'rules-P'], previous_tag: 'rules-P',
    visible_candidates: first ? 0 : 2, decisive_candidates: 0, decisions: 1, expected_candidate_paths: [ADD[0], ADD[1], ADD[2]],
    ...(kind === 'changed' ? { expected_added_paths: [...ADD], expected_modified_paths: [], expected_removed_paths: [], added_hashes_source_tag: 'rules-P' } : {}),
  };
  if (first) w.cands = w.cands.slice(0, 2);
  return w;
}

async function buildRows(w) {
  const rows = []; let prev = GENESIS;
  const push = async (e) => { const detail = typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail), at = e.at || `2026-10-20T22:0${rows.length}:00.000Z`; const h = await chainHash(prev, { at, actor: e.actor, role: e.role, action: e.action, target: e.target, detail }); rows.push({ seq: rows.length + 1, at, actor: e.actor, role: e.role, action: e.action, target: e.target, detail, prev_hash: prev, hash: h }); prev = h; };
  for (let i = 0; i < w.priorAudit; i++) await push({ actor: 'someone', role: 'ADMIN', action: 'session.login', target: 'session', detail: {}, at: `2026-10-19T10:0${i}:00.000Z` });
  w.base.audit = { n: w.priorAudit, head: prev };
  for (const r of w.receipts) await push({ actor: r.actor || 'pipeline:daily.yml', role: r.role || 'PIPELINE', action: 'pipeline.submit', target: RUN, at: '2026-10-20T22:05:00.000Z',
    detail: { count: r.count, created: r.created, run_url: `https://github.com/${REPO}/actions/runs/${RUN}`, token_run_id: RUN, run_attempt: r.attempt, receipt: r.receipt } });
  return rows;
}

const WRITE_RE = [/(-X|--method)[\s=]*(POST|PUT|PATCH|DELETE)/i, /workflow run/, /run (rerun|cancel)/, /release (create|edit)/, /variable set/, /\b(INSERT|UPDATE|DELETE|DROP|ALTER)\b/i];
async function makeIo(w) {
  const rows = w.rows || (await buildRows(w)), calls = [], rec = (s) => calls.push(s);
  const art = (name) => { const files = w.art[name]; if (!files) throw new Error('no such artifact'); return { read: (rel) => (rel in files ? Buffer.from(JSON.stringify(files[rel])) : w.bytes.has(rel) && name.startsWith('candidate') ? w.bytes.get(rel) : null) }; };
  const io = {
    gh: (path) => {
      rec(`gh ${path}`); let m;
      if (path === `repos/${REPO}/actions/runs/${RUN}`) return JSON.stringify(w.info);
      if ((m = path.match(/attempts\/(\d+)\/jobs$/))) { const a = w.attempts[m[1] - 1]; if (!a) throw new Error('404'); return JSON.stringify(a.jobs); }
      if ((m = path.match(/attempts\/(\d+)$/))) { const a = w.attempts[m[1] - 1]; if (!a) throw new Error('404'); return JSON.stringify(a.meta); }
      if (path.endsWith('/actions/variables')) return JSON.stringify(w.variables);
      if (path.endsWith(`/runs/${RUN}/artifacts`)) return JSON.stringify(w.artifacts);
      if (path.includes('workflows/publish.yml/runs')) return String(w.publishRuns);
      if (path.endsWith('releases/latest')) return JSON.stringify({ tag: w.latest });
      if (path.includes('/releases?')) return JSON.stringify(w.releases);
      throw new Error('unexpected gh ' + path);
    },
    ghRun: (args) => { rec('gh ' + args.join(' ')); const k = Number(args[args.indexOf('--attempt') + 1]), a = w.attempts[k - 1]; if (!a || a.log === null || w.logAbsent) throw new Error('log not found'); return a.log; },
    d1: (sql) => {
      rec('d1 ' + sql);
      if (/FROM audit/.test(sql)) return rows;
      if (/state IN/.test(sql)) return [{ n: w.decisive }];
      if (/FROM decisions/.test(sql)) return [{ n: w.decisions }];
      if (/FROM candidates/.test(sql)) return w.cands;
      throw new Error('unexpected sql');
    },
    git: (args) => { rec('git ' + args.join(' ')); return args[0] === 'show' ? w.events.map((e) => JSON.stringify(e)).join('\n') : ''; },
    fetchJson: (url) => { rec('fetch ' + url); const t = url.match(/download\/([^/]+)\/manifest/)?.[1]; if (!w.manifests[t]) throw new Error('404'); return w.manifests[t]; },
    fetchStatus: () => w.siteStatus, readFile: () => JSON.stringify(w.base), writeFile: () => { throw new Error('unexpected write'); }, now: () => '2026-10-21T00:00:00Z',
    artifact: (run, name) => { rec(`artifact ${name}`); return art(name); },
  };
  return { io, calls };
}
const run = async (w, opts) => { const { io, calls } = await makeIo(w); const r = await verify('post', { run: RUN, baseline: 'b.json', repo: REPO }, io, opts); return { ...r, calls }; };
const ids = (r, st) => r.results.filter((x) => x.status === st).map((x) => x.id);

// ---- positive
test('rulesRoot reproduces the RFC 6962 vectors of scripts/tlog.py::rules_root (synthetic)', () => {
  const mk = (n) => Array.from({ length: n }, (_, i) => ({ path: `rules/synth/r${String(i).padStart(2, '0')}.yar`, sha256: i.toString(16).padStart(2, '0').repeat(32) }));
  const vec = { 1: '72e0ba8c4a86e79268083d4bd5be7bb322d32bdf8b463c0379c982770448fb11', 2: '415e6d8add464d3eef070d613e3b78f34de55e6153320ed78d8e9eed609c45e3', 3: 'bae8050a4b2481c284ea863485545c1a0ea3b912e5e3289eb876d68de17f94be', 5: '0512f678a8ef55131bb7c41855825ed1572afc4b609160067b534d3b13346085', 8: '380263c2d4257225b1564af079807e8348cd49d3f4ecc7beba604e7fb586ec2d' };
  for (const [n, root] of Object.entries(vec)) assert.equal(rulesRoot(mk(+n)), root, `n=${n}`);
  assert.equal(rulesRoot(mk(5).reverse()), vec[5], 'order of the input does not matter: sorted by path');
});
test('changed=true acceptance run: all PASS, exit 0, kind detected from the log', async () => {
  const r = await run(await world());
  assert.deepEqual(ids(r, 'FAIL').concat(ids(r, 'INCOMPLETE')), []); assert.equal(r.exit, 0);
  for (const id of ['acceptance-deduced', 'changes-exact', 'rules-root', 'macos-validation', 'deps-closure', 'added-hashes', 'unchanged-hashes', 'file-bytes']) assert.ok(ids(r, 'PASS').includes(id), id);
  assert.match(r.notes.join('\n'), /attempt 1: tester/); assert.match(r.notes.join('\n'), /\(aggregate\)/);
});
test('changed=false run with a first receipt: all PASS, exit 0 (and no changed-only checks run)', async () => {
  const r = await run(await world({ kind: 'unchanged', first: true }));
  assert.deepEqual(ids(r, 'FAIL').concat(ids(r, 'INCOMPLETE')), []); assert.equal(r.exit, 0); assert.ok(ids(r, 'PASS').includes('unchanged-root')); assert.ok(!r.results.some((x) => x.id === 'changes-exact'));
});
test('a retry-only run of a changed set needs no new candidates; a re-run attempt that reused the review has no receipt', async () => {
  const w = await world(); w.info.run_attempt = 2;
  w.attempts.push({ meta: { by: 'tester', created: '2026-10-20T22:20:00Z', updated: '2026-10-20T22:20:05Z', conclusion: 'success' }, log: w.attempts[0].log,
    jobs: w.attempts[0].jobs.map((j) => ({ ...j, started_at: j.name === 'review' ? '2026-10-20T22:00:05Z' : '2026-10-20T22:20:01Z' })) });
  const r = await run(w); assert.equal(r.exit, 0, JSON.stringify(r.results.filter((x) => x.status !== 'PASS')));
  assert.match(r.notes.join('\n'), /review reused from an earlier attempt/);
});

// ---- negative controls: one broken thing each
const breakIt = {
  'unexpected new release': { id: 'release-unchanged', fn: (w) => { w.releases.unshift({ tag: 'rules-N', draft: false }); w.latest = 'rules-N'; } },
  'a new draft release': { id: 'release-unchanged', fn: (w) => { w.releases.push({ tag: 'rules-D', draft: true }); } },
  'publish.yml run after the dispatch': { id: 'no-publish-run', sole: true, fn: (w) => { w.publishRuns = 1; } },
  'request-publish success': { id: 'request-publish-not-run', fn: (w) => { w.attempts[0].jobs.find((j) => j.name === 'request-publish').conclusion = 'success'; } },
  'extra candidate in D1': { id: 'd1-candidates', fn: (w) => { w.cands.push({ ...w.cands[0], path: 'rules/synth/extra.yar' }); } },
  'candidate missing from D1': { id: 'd1-candidates', fn: (w) => { w.cands.pop(); } },
  'candidate hash altered in D1': { id: 'd1-hashes', fn: (w) => { w.cands[0].sha256 = hex('tampered'); } },
  'added file hash altered in candidate.json': { id: 'added-hashes', fn: (w) => { const f = w.art['candidate-' + RUN]['candidate.json'].files.find((x) => x.path === ADD[0]); f.sha256 = hex('tampered'); } },
  'unchanged file silently modified (hash altered in candidate.json)': { id: 'changes-exact', fn: (w) => { const f = w.art['candidate-' + RUN]['candidate.json'].files.find((x) => x.path === A[1]); f.sha256 = hex('tampered'); } },
  'rule bytes differ from candidate.json': { id: 'file-bytes', sole: true, fn: (w) => { w.bytes.set(ADD[1], Buffer.from('other bytes')); } },
  'rules_root of the log differs': { id: 'rules-root', fn: (w) => { w.events[0].details.rules_root = hex('other'); } },
  'dynamic.json set_root differs': { id: 'rules-root', fn: (w) => { w.art['candidate-' + RUN]['dynamic.json'].set_root = hex('other'); } },
  'dependency outside the set': { id: 'deps-closure', sole: true, fn: (w) => { w.art['candidate-' + RUN]['candidate.json'].files[7].depends_on = ['rules/synth/not-there.yar']; } },
  'changes.json lists one added path too many': { id: 'changes-exact', fn: (w) => { w.art['candidate-' + RUN]['changes.json'].added.push('rules/synth/extra.yar'); } },
  'baseline expects a different added path': { id: 'changes-exact', fn: (w) => { w.base.expected_added_paths = [ADD[0], ADD[1], 'rules/synth/other.yar']; } },
  'dynamic canary not detected': { id: 'dynamic-ok', sole: true, fn: (w) => { w.art['candidate-' + RUN]['dynamic.json'].canaries_detected = 4; } },
  'validation failure': { id: 'validation-ok', sole: true, fn: (w) => { w.art['candidate-' + RUN]['validation.json'].failures = [{ path: 'x' }]; } },
  'macos verdict not ok': { id: 'macos-validation', sole: true, fn: (w) => { w.art['macos-validation-' + RUN]['dynamic-macos.json'].verdict = 'regressed'; } },
  'two first receipts in the run': { id: 'one-first', fn: (w) => { w.receipts = [{ attempt: 1, created: 2, count: 2, receipt: 'first' }, { attempt: 1, created: 2, count: 2, receipt: 'first' }]; } },
  'receipt by another actor': { id: 'audit-new-entries', sole: true, fn: (w) => { w.receipts[0].actor = 'pipeline:publish.yml'; } },
  'receipt with another role': { id: 'audit-new-entries', sole: true, fn: (w) => { w.receipts[0].role = 'ADMIN'; } },
  'receipt says first but created nothing': { id: 'receipt-coherence', fn: (w) => { w.receipts[0].receipt = 'first'; } },
  'attempt ran the review and has no receipt': { id: 'attempt-receipts', fn: (w) => { w.receipts = []; } },
  'acceptance not deducible (run came from a schedule)': { id: 'run-identity', fn: (w) => { w.info.event = 'schedule'; } },
  'a decision appeared': { id: 'no-decisions', sole: true, fn: (w) => { w.decisive = 1; } },
  'site down': { id: 'site-up', sole: true, fn: (w) => { w.siteStatus = 503; } },
};
for (const [name, s] of Object.entries(breakIt)) {
  test(`negative control: ${name} -> FAIL (exit 1)`, async () => {
    const r = await run(await (async () => { const w = await world(); s.fn(w); return w; })());
    assert.ok(ids(r, 'FAIL').includes(s.id), `${s.id} should FAIL; got FAIL=${ids(r, 'FAIL')} INCOMPLETE=${ids(r, 'INCOMPLETE')}`); assert.equal(r.exit, 1);
  });
}
test('negative control: broken audit chain -> FAIL (exit 1)', async () => {
  const w = await world(); w.rows = await buildRows(w); w.rows[3].detail = w.rows[3].detail.replace('"created":0', '"created":9');
  const r = await run(w); assert.ok(ids(r, 'FAIL').includes('audit-chain')); assert.equal(r.exit, 1);
});
test('negative control: an audit entry removed from the middle -> FAIL', async () => {
  const w = await world(); w.rows = await buildRows(w); w.rows.splice(1, 1); const r = await run(w); assert.ok(ids(r, 'FAIL').includes('audit-chain')); assert.equal(r.exit, 1);
});
test('negative control: unchanged run but the set root differs from the release -> FAIL', async () => {
  const w = await world({ kind: 'unchanged', first: true }); w.events[0].details.rules_root = hex('x'); const r = await run(w); assert.ok(ids(r, 'FAIL').includes('unchanged-root')); assert.equal(r.exit, 1);
});

// ---- missing evidence is INCOMPLETE (exit 3), never PASS
const missing = {
  'public artifact expired': { id: 'changes-exact', fn: (w) => { w.artifacts[0].expired = true; } },
  'macos artifact expired': { id: 'macos-validation', fn: (w) => { w.artifacts[1].expired = true; } },
  'artifact not listed': { id: 'rules-root', fn: (w) => { w.artifacts.shift(); } },
  'attempt log absent': { id: 'attempts-evidence', fn: (w) => { w.logAbsent = true; } },
  'attempt without jobs': { id: 'attempts-evidence', fn: (w) => { w.attempts[0].jobs = []; } },
  'job still without conclusion': { id: 'attempts-evidence', fn: (w) => { w.attempts[0].jobs[0].conclusion = null; } },
  'baseline without expected_added_paths': { id: 'changes-exact', fn: (w) => { delete w.base.expected_added_paths; } },
  'baseline without the manifest source of the added files': { id: 'added-hashes', fn: (w) => { delete w.base.added_hashes_source_tag; } },
  'baseline without release list': { id: 'release-unchanged', fn: (w) => { delete w.base.release_tags; } },
  'signed log has no event for the run': { id: 'run-kind', fn: (w) => { w.events = []; } },
  'manifest of the release unreachable': { id: 'unchanged-hashes', fn: (w) => { delete w.manifests['rules-A']; } },
  'request-publish job not listed': { id: 'acceptance-deduced', fn: (w) => { w.attempts[0].jobs = w.attempts[0].jobs.filter((j) => j.name !== 'request-publish'); } },
  'macos did not succeed (acceptance cannot be deduced)': { id: 'acceptance-deduced', fn: (w) => { w.attempts[0].jobs.find((j) => j.name === 'macos').conclusion = 'skipped'; } },
};
for (const [name, s] of Object.entries(missing)) {
  test(`missing evidence: ${name} -> INCOMPLETE and never exit 0`, async () => {
    const w = await world(); s.fn(w); const r = await run(w);
    assert.ok(ids(r, 'INCOMPLETE').includes(s.id), `${s.id} should be INCOMPLETE; got INCOMPLETE=${ids(r, 'INCOMPLETE')} FAIL=${ids(r, 'FAIL')}`);
    assert.ok(!ids(r, 'PASS').includes(s.id)); assert.notEqual(r.exit, 0);
  });
}
test('the run still going is INCOMPLETE (exit 3) and concludes nothing else', async () => {
  const w = await world(); w.info.status = 'in_progress'; w.info.conclusion = null; const r = await run(w);
  assert.equal(r.exit, 3); assert.deepEqual(r.results.map((x) => x.status), ['INCOMPLETE']);
});
test('INCOMPLETE without any FAIL exits 3; a FAIL together with an INCOMPLETE exits 1', async () => {
  const w = await world(); delete w.base.expected_added_paths; assert.equal((await run(w)).exit, 3);
  const w2 = await world(); delete w2.base.expected_added_paths; w2.publishRuns = 2; assert.equal((await run(w2)).exit, 1);
});
test('a mismatch is never ignored: an acceptance run whose log shows no candidate.changes nor unchanged is INCOMPLETE, and with both is FAIL', async () => {
  const w = await world(); w.events.push({ event: 'candidate.unchanged', run_id: RUN, details: {} }); const r = await run(w); assert.ok(ids(r, 'FAIL').includes('run-kind')); assert.equal(r.exit, 1);
});

// ---- mutation: take a critical check away and the matching negative control stops failing, so the control really depends on it
test('mutation: with a critical check removed the negative control no longer fails (the controls are not vacuous)', async () => {
  let n = 0;
  for (const [name, s] of Object.entries(breakIt)) {
    const w = await world(); s.fn(w); const withCheck = await run(w);
    const w2 = await world(); s.fn(w2); const without = await run(w2, { skip: [s.id] });
    assert.ok(ids(withCheck, 'FAIL').includes(s.id), name); assert.ok(!without.results.some((x) => x.id === s.id), `${name}: check ${s.id} should be gone`);
    if (s.sole) { assert.equal(without.exit, 0, `${name}: ${s.id} is the only detector, the run would pass without it: ${JSON.stringify(without.results.filter((x) => x.status !== 'PASS'))}`); n++; }
  }
  assert.ok(n >= 10, `${n} sole-detector controls`);
});

// ---- read-only
test('read-only: no scenario ever issues a write (gh, workflow, release, variable, D1, git)', async () => {
  const all = [];
  for (const s of [() => world(), () => world({ kind: 'unchanged', first: true }), async () => { const w = await world(); w.publishRuns = 1; return w; }]) { const r = await run(await s()); all.push(...r.calls); }
  assert.ok(all.length > 30);
  for (const c of all) for (const re of WRITE_RE) assert.ok(!re.test(c), `write-looking call: ${c}`);
  for (const c of all) assert.match(c, /^(gh |d1 SELECT|git (fetch|show)|fetch https:\/\/github\.com\/.*manifest\.json|artifact )/);
});
test('read-only guard: refuses every write method before it reaches the real io', () => {
  const calls = [], io = guardIo({ gh: (p) => calls.push(p), ghRun: (a) => calls.push(a), d1: (s) => calls.push(s), git: (a) => calls.push(a), fetchJson() {}, fetchStatus() {}, readFile() {}, now() {}, artifact() {}, writeFile() {} });
  const bad = [() => io.gh(`repos/${REPO}/releases -X POST`), () => io.gh(`repos/${REPO}/actions/variables --method DELETE`), () => io.ghRun(['workflow', 'run', 'publish.yml']), () => io.ghRun(['run', 'rerun', '1']), () => io.ghRun(['run', 'cancel', '1']),
    () => io.ghRun(['release', 'create', 'x']), () => io.ghRun(['release', 'edit', 'x']), () => io.ghRun(['variable', 'set', 'X']), () => io.ghRun(['api', '-X', 'PATCH', 'repos/x']),
    () => io.d1('INSERT INTO audit VALUES (1)'), () => io.d1('UPDATE candidates SET state = 1'), () => io.d1('DELETE FROM decisions'), () => io.d1('DROP TABLE audit'), () => io.d1('ALTER TABLE audit ADD x'),
    () => io.d1('SELECT 1; DELETE FROM audit'), () => io.git(['push', 'origin', 'main']), () => io.git(['reset', '--hard'])];
  for (const f of bad) assert.throws(f, ReadOnlyViolation);
  assert.deepEqual(calls, [], 'nothing reached the underlying io');
  io.gh('repos/x/actions/runs/1'); io.d1('SELECT 1'); io.ghRun(['run', 'view', '1', '--log']); io.git(['show', 'origin/main:logs/log.jsonl']); assert.equal(calls.length, 4);
});
test('the CLI refuses a call without arguments with exit 2', () => { assert.equal(spawnSync(process.execPath, [SELF], { encoding: 'utf8' }).status, 2); });
