// Source proposals: URL and SSRF containment, verification, roles, idempotence, concurrency, audit, and the migration with its rollback. Everything runs on the node:sqlite D1 shim and a fake GitHub.
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { world, cand, rid, REPO } from './helpers.js';
import { newDb } from './d1shim.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';
import * as P from '../src/proposals.js';

const MIT = 'MIT License\n\nCopyright (c) 2024 Acme\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.\n';
const b64 = (s) => Buffer.from(s).toString('base64');
const J = (d, status = 200, h = {}) => new Response(JSON.stringify(d), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...h } });
const SOURCES = { schema: 1, sources: [{ id: 'nextron', repo: 'Neo23x0/signature-base', kind: 'rules', paths: ['yara'] }, { id: 'community', repo: 'Yara-Rules/rules', kind: 'rules', paths: ['malware'] }, { id: 'yara-x', repo: 'VirusTotal/yara-x', kind: 'engine', paths: [] }] };

/** A fake GitHub for owner `acme`, repository `yara-feed`. `answer.<name>` replaces one answer; `repo`/`license`/`commit`/`tree` patch the default bodies. */
function github(w, o = {}) {
  const seen = [], owner = o.owner || 'acme', name = o.name || 'yara-feed';
  const R = { id: 777, full_name: `${owner}/${name}`, private: false, fork: false, archived: false, disabled: false, size: 1200, default_branch: 'main', stargazers_count: 5, forks_count: 1, created_at: '2023-01-01T00:00:00Z', pushed_at: new Date(w.now() * 1000 - 30 * 86400e3).toISOString(), owner: { type: 'Organization' }, license: { spdx_id: 'MIT' }, html_url: 'http://169.254.169.254/latest', ...o.repo };
  const L = { license: { spdx_id: 'MIT' }, content: b64(o.licenseText ?? MIT), ...o.license };
  const C = { sha: 'a'.repeat(40), commit: { verification: { verified: true } }, ...o.commit };
  const T = { truncated: false, tree: [{ path: 'yara/a.yar', type: 'blob', size: 100 }, { path: 'yara/b.yara', type: 'blob', size: 200 }, { path: 'README.md', type: 'blob', size: 5 }], tarball_url: 'http://10.0.0.1/x', ...o.tree };
  const U = { created_at: '2015-01-01T00:00:00Z', type: 'Organization', ...o.user };
  const table = { repo: () => J(R), license: () => J(L), commit: () => J(C), tree: () => J(T), user: () => J(U), ...o.answer };
  w.route(new RegExp(`^https://api\\.github\\.com/(repos/${owner}/${name}|users/${owner}$)`, 'i'), (url, init) => {
    seen.push({ url, init }); const p = new URL(url).pathname;
    if (/\/license$/.test(p)) return table.license(url); if (/\/commits\/HEAD$/.test(p)) return table.commit(url); if (/\/git\/trees\//.test(p)) return table.tree(url); if (p.startsWith('/users/')) return table.user(url); return table.repo(url);
  });
  return { seen, R };
}
function rawSources(w, { status = 200, body = SOURCES } = {}) { w.route(/raw\.githubusercontent\.com\/.*\/config\/sources\.json$/, () => (status === 200 ? J(body) : new Response('x', { status }))); }
async function setup({ enabled = true } = {}) {
  const w = await world(); w.env.PIPELINE_WORKFLOWS = 'daily.yml,publish.yml,source-proposals.yml'; if (enabled) w.env.SOURCE_PROPOSALS_ENABLED = '1';
  w.admin = await w.login('ada', { admin: true }, { id: 3 }); w.rita = await w.login('rita', { push: true }, { id: 4 });
  w.account('vera', 7); w.vera = null; rawSources(w); return w;
}
const body = (over = {}) => ({ request_id: rid(), url: 'https://github.com/acme/yara-feed', source_id: 'acme-feed', paths: ['yara'], reason: 'community feed with a clear licence', ...over });
const propose = (w, user, over) => w.call('POST', '/api/source-proposals', { user, body: body(over) });
const act = (w, user, id, op, b = {}) => w.call('POST', `/api/source-proposals/${id}/${op}`, { user, body: { request_id: rid(), ...b } });
const get = async (w, id, user = w.admin) => (await w.call('GET', `/api/source-proposals/${id}`, { user })).data;
async function verified(w, over = {}, gh = {}) {
  github(w, gh); const p = (await propose(w, w.rita, over)).data.proposal; const v = await act(w, w.rita, p.id, 'verify', { expect_version: p.version }); return { p, v, cur: await get(w, p.id) };
}
const authorize = (w, cur, over = {}) => act(w, w.admin, cur.id, 'authorize', { expect_version: cur.version, acks: [], confirm_repo: cur.repo, reason: 'licence read and source reviewed', ...over });
const count = async (w, sql, ...a) => (await w.db.prepare(sql).bind(...a).first()).n;

// ---------- syntax and containment (T-S1, T-S5) ----------
test('T-S1: every hostile URL is refused before any request is made', async () => {
  const w = await setup(); const calls = []; const orig = w.deps.fetch; w.deps.fetch = async (...a) => { if (!String(a[0]).includes(REPO)) calls.push(String(a[0])); return orig(...a); };   // the role lookup of the signed-in person is not ours
  const bad = ['http://github.com/a/b', 'https://github.com.evil.com/a/b', 'https://evil.com/github.com/a/b', 'https://user:pw@github.com/a/b', 'https://github.com:444/a/b', 'https://github.com:443/a/b', 'https://127.0.0.1/a/b', 'https://[::1]/a/b', 'https://169.254.169.254/', 'https://2130706433/a/b',
    'file:///etc/passwd', 'gopher://github.com/a/b', 'ftp://github.com/a/b', 'https://github.com/a/b/tree/x', 'https://github.com/a/b?x=1', 'https://github.com/a/b#x', 'https://github.com/%2e%2e/b', 'https://github.com/a/%2e%2e', 'https://ｇithub.com/a/b', 'https://github.com/ａ/b',
    'https://xn--gthub-bsa.com/a/b', 'https://github.com/a/b%0d%0aX', 'https://github.com/a/b\nX', 'https://github.com/a/b ', ' https://github.com/a/b', 'HTTPS://GITHUB.COM/a/b', 'https://www.github.com/a/b', 'https://api.github.com/repos/a/b', 'https://github.com//a/b', 'https://github.com/a', 'https://github.com/a/b/c',
    'https://github.com/-a/b', 'https://github.com/a-/b', 'https://github.com/a--b/c', 'https://github.com/' + 'a'.repeat(40) + '/b', 'https://github.com/a/' + 'b'.repeat(106), 'https://github.com/a/..', 'https://github.com/a/.', 'https://github.com/a/b.git.git', 'https://github.com/a@evil.com/b', 'https://github.com\\@evil.com/a/b', 'https://github.com/a/b`id`', 'https://github.com/a/$(id)', 'https://github.com/a/b;rm', 'https://github.com/a/b‮', 12, null, {}, ['https://github.com/a/b']];
  for (const url of bad) { const r = await propose(w, w.rita, { url }); assert.equal(r.status, 400, `accepted: ${JSON.stringify(url)}`); }
  assert.deepEqual(calls, [], 'no request at all');
  assert.equal(await count(w, 'SELECT COUNT(*) AS n FROM source_proposals'), 0);
  for (const [url, full] of [['https://github.com/Acme/Yara-Feed', 'Acme/Yara-Feed'], ['https://github.com/acme/yara-feed.git', 'acme/yara-feed'], ['https://github.com/acme/yara-feed/', 'acme/yara-feed'], ['https://github.com/a/b.c_d', 'a/b.c_d']]) assert.equal(P.parseRepoUrl(url).full, full);
});

test('T-S5: assertAllowedUrl accepts only the five request shapes on api.github.com', () => {
  const ok = ['https://api.github.com/repos/acme/yara-feed', 'https://api.github.com/repos/acme/yara-feed/license', 'https://api.github.com/repos/acme/yara-feed/commits/HEAD', `https://api.github.com/repos/acme/yara-feed/git/trees/${'a'.repeat(40)}?recursive=1`, 'https://api.github.com/users/acme'];
  for (const u of ok) assert.equal(P.assertAllowedUrl(u).ok, true, u);
  const no = ['http://api.github.com/repos/a/b', 'https://api.github.com:8443/repos/a/b', 'https://api.github.com:443/repos/a/b', 'https://user@api.github.com/repos/a/b', 'https://user:pw@api.github.com/repos/a/b', 'https://api.github.com@evil.com/repos/a/b', 'https://api.github.com.evil.com/repos/a/b', 'https://evil.com/api.github.com/repos/a/b',
    'https://API.github.com.evil.com/repos/a/b', 'https://api.github.com/repos/a/b#x', 'https://api.github.com/repos/a/b?x=1', 'https://api.github.com/repos/a/b?recursive=1&x=1', 'https://api.github.com/repos/a/%2e%2e/b', 'https://api.github.com/repos/a/../../orgs/x', 'https://api.github.com/repos//a/b',
    'https://api.github.com/orgs/acme', 'https://api.github.com/user', 'https://api.github.com/', 'https://api.github.com\\@evil.com/repos/a/b', 'https://api.github.com/repos/a/b c', 'https://api.github.com/repos/a/b\n', 'https://127.0.0.1/repos/a/b', 'https://[::1]/repos/a/b', 'https://169.254.169.254/repos/a/b', 'https://raw.githubusercontent.com/a/b/main/x', 'https://github.com/a/b', 'file:///etc/passwd', '', null, undefined, 5];
  for (const u of no) assert.equal(P.assertAllowedUrl(u).ok, false, String(u));
});

test('crafted source ids, paths and reasons cannot reach a pull request', async () => {
  const w = await setup();
  for (const source_id of ['', 'a', 'A-Upper', 'has space', 'new\nline', '`id`', '$(id)', '../x', 'a/b', 'x'.repeat(33), '-lead', 'trail-', 'synthetic-test', 'ünï', 'a‮b', 12, null]) assert.equal((await propose(w, w.rita, { source_id })).status, 400, `id ${JSON.stringify(source_id)}`);
  const longPaths = Array.from({ length: 21 }, (_, i) => `p${i}`);
  for (const paths of [[], 'yara', ['..'], ['../x'], ['a/../b'], ['/abs'], ['a//b'], ['a/'], ['.'], ['./a'], ['a/./b'], ['a\nb'], ['a`b'], ['$(x)'], ['a b'], ['a;b'], ['a‮b'], ['x'.repeat(101)], ['a', 'a'], longPaths, [5], [null], ['%2e%2e']]) assert.equal((await propose(w, w.rita, { paths })).status, 400, `paths ${JSON.stringify(paths)}`);
  for (const reason of ['', 'abc', '   ​  ', 'x'.repeat(2001), 5]) assert.equal((await propose(w, w.rita, { reason })).status, 400, `reason ${JSON.stringify(reason)}`);
  assert.equal((await propose(w, w.rita, { request_id: 'short' })).status, 400); assert.equal((await propose(w, w.rita, { request_id: 'has space in it!' })).status, 400);
  assert.equal(await count(w, 'SELECT COUNT(*) AS n FROM source_proposals'), 0);
  const ok = await propose(w, w.rita, { paths: ['yara', 'rules/sub-dir_1.v2'] }); assert.equal(ok.status, 200);
});

// ---------- verification ----------
test('verification: five GETs to api.github.com, redirects never followed, the token only goes to GitHub, nothing inside a response is requested (T-S2)', async () => {
  const w = await setup(); const { v, cur } = await verified(w);
  assert.equal(v.status, 200); assert.equal(cur.state, 'verified');
  assert.ok(cur.verification.requests.length === 5, cur.verification.requests.join('\n'));
  for (const u of cur.verification.requests) assert.equal(P.assertAllowedUrl(u).ok, true, u);
  assert.equal(cur.license_spdx, 'MIT'); assert.equal(cur.license_sha256, createHash('sha256').update(MIT).digest('hex')); assert.equal(cur.verified_commit, 'a'.repeat(40));
  assert.deepEqual(cur.findings, []); assert.equal(cur.verification.rule_files, 2);
  assert.ok(!JSON.stringify(cur).includes('169.254') && !JSON.stringify(cur).includes('10.0.0.1'), 'no URL taken from a response is stored');
});
test('T-S2/T-S3: only the five URLs are ever requested, every request is a GET with redirect:manual, and a Location is never followed', async () => {
  const w = await setup(); const g = github(w); const outbound = []; const orig = w.deps.fetch; w.deps.fetch = async (u, init = {}) => { outbound.push({ u: String(u), init }); return orig(u, init); };
  const p = (await propose(w, w.rita)).data.proposal; assert.equal((await act(w, w.rita, p.id, 'verify')).status, 200);
  const gh = outbound.filter((o) => o.u.includes('api.github.com') && /acme/.test(o.u));
  assert.equal(gh.length, 5); for (const o of gh) { assert.equal(o.init.method, 'GET'); assert.equal(o.init.redirect, 'manual'); assert.match(o.init.headers.Authorization, /^Bearer tok-rita$/); }
  assert.ok(outbound.every((o) => /^https:\/\/(api\.github\.com|raw\.githubusercontent\.com)\//.test(o.u)), outbound.map((o) => o.u).join('\n'));
  assert.ok(!outbound.some((o) => /169\.254|10\.0\.0\.1/.test(o.u)));
  assert.ok(outbound.filter((o) => o.init.method && o.init.method !== 'GET').length === 0);
  void g;
});
test('T-S3: redirects are refused or recorded, never followed, and nobody is sent the token elsewhere', async () => {
  for (const [status, location, code] of [[301, 'https://evil.com/', 'REDIRECT_REFUSED'], [301, 'https://api.github.com/repositories/12345', 'RENAMED'], [302, 'https://api.github.com/repositories/12345', 'REDIRECT_REFUSED'], [307, 'http://169.254.169.254/latest/meta-data', 'REDIRECT_REFUSED'], [302, 'https://127.0.0.1/', 'REDIRECT_REFUSED'], [301, 'https://api.github.com/repositories/1/../../x', 'REDIRECT_REFUSED'], [308, '', 'REDIRECT_REFUSED']]) {
    const w = await setup(); const g = github(w, { answer: { repo: () => new Response(null, { status, headers: { Location: location } }) } });
    const { cur } = await verified(w, {}, { answer: { repo: () => new Response(null, { status, headers: { Location: location } }) } });
    assert.equal(cur.state, 'rejected', `${status} ${location}`); assert.equal(cur.state_reason, code); void g;
  }
  const w = await setup(); const g = github(w, { answer: { license: () => new Response(null, { status: 302, headers: { Location: 'https://evil.com/x' } }) } });
  const p = (await propose(w, w.rita)).data.proposal; await act(w, w.rita, p.id, 'verify'); assert.equal((await get(w, p.id)).state_reason, 'REDIRECT_REFUSED');
  assert.ok(!g.seen.some((s) => /evil/.test(s.url)), 'the Location was not requested');
});
test('T-S4: oversized, wrong type, malformed and slow answers are never stored as verified', async () => {
  const mk = (cl) => () => J({ id: 1 }, 200, { 'content-length': String(cl) });
  const stream = () => { const big = new Uint8Array(300_000).fill(120); return new Response(new ReadableStream({ start(c) { c.enqueue(big.subarray(0, 150_000)); c.enqueue(big.subarray(150_000)); c.close(); } }), { status: 200, headers: { 'content-type': 'application/json' } }); };
  const cases = [['declared too large', { repo: mk(999_999) }, 'RESPONSE_TOO_LARGE'], ['streamed too large without content-length', { repo: stream }, 'RESPONSE_TOO_LARGE'], ['html', { repo: () => new Response('<html>', { status: 200, headers: { 'content-type': 'text/html' } }) }, 'UNEXPECTED_CONTENT'],
    ['no content type', { repo: () => new Response('{}', { status: 200 }) }, 'UNEXPECTED_CONTENT'], ['invalid json', { repo: () => new Response('{nope', { status: 200, headers: { 'content-type': 'application/json' } }) }, 'UNEXPECTED_CONTENT'], ['wrong shape', { repo: () => J({ id: 'x', full_name: 5 }) }, 'UNEXPECTED_CONTENT'],
    ['tree too large', { tree: mk(5_000_001) }, 'RESPONSE_TOO_LARGE'], ['license text is a number', { license: () => J({ license: { spdx_id: 'MIT' }, content: 7 }) }, 'UNEXPECTED_CONTENT']];
  for (const [label, answer, code] of cases) { const w = await setup(); const { cur } = await verified(w, {}, { answer }); assert.equal(cur.state, 'rejected', label); assert.equal(cur.state_reason, code, label); }
  for (const [label, answer] of [['rate limited', () => new Response('{}', { status: 403 })], ['429', () => new Response('{}', { status: 429 })], ['5xx', () => new Response('x', { status: 502 })], ['network error', () => { throw new Error('boom'); }], ['timeout', () => { throw new DOMException('timed out', 'TimeoutError'); }]]) {
    const w = await setup(); const { v, cur } = await verified(w, {}, { answer: { repo: answer } }); assert.equal(v.status, 200, label); assert.equal(cur.state, 'proposed', `${label}: neither a pass nor a rejection`); assert.equal(cur.verified_at, null);
    assert.equal(cur.events.at(-1).event, 'verify.unavailable');
  }
});
test('T-V1: private, fork, archived, disabled, missing, too big, truncated and empty repositories are rejected with exact codes', async () => {
  const cases = [['private', { repo: { private: true } }, 'PRIVATE'], ['fork', { repo: { fork: true } }, 'FORK'], ['archived', { repo: { archived: true } }, 'ARCHIVED'], ['disabled', { repo: { disabled: true } }, 'DISABLED'], ['too big', { repo: { size: 90_001 } }, 'TOO_BIG'], ['404', { answer: { repo: () => J({}, 404) } }, 'NOT_FOUND_OR_PRIVATE'],
    ['renamed', { repo: { full_name: 'other/name' } }, 'RENAMED'], ['truncated', { tree: { truncated: true } }, 'TREE_TRUNCATED'], ['too many entries', { tree: { tree: Array.from({ length: 25_001 }, (_, i) => ({ path: `yara/f${i}.yar`, type: 'blob', size: 1 })) } }, 'TREE_TRUNCATED'],
    ['no rule files', { tree: { tree: [{ path: 'yara/readme.md', type: 'blob', size: 1 }, { path: 'other/a.yar', type: 'blob', size: 1 }, { path: 'yara/dir.yar', type: 'tree' }] } }, 'NO_RULE_FILES']];
  for (const [label, gh, code] of cases) { const w = await setup(); const { cur } = await verified(w, {}, gh); assert.equal(cur.state, 'rejected', label); assert.equal(cur.state_reason, code, label); assert.ok(cur.findings.some((f) => f.code === code && f.severity === 'block'), label); }
  const w = await setup(); const r = await verified(w, { paths: ['yara'] }, { tree: { tree: [{ path: 'yara/big.yar', type: 'blob', size: 2_000_000 }, { path: 'yara/ok.yar', type: 'blob', size: 5 }, { path: 'yara/LICENSE.txt', type: 'blob', size: 5 }] } });
  assert.equal(r.cur.state, 'verified'); assert.equal(r.cur.verification.oversize_skipped, 1); assert.deepEqual(r.cur.findings.map((f) => f.code), ['EXTRA_LICENSE_FILES']);
});
test('T-V1: trust signals are warnings that must be acknowledged', async () => {
  const w = await setup(); const young = new Date(w.now() * 1000 - 10 * 86400e3).toISOString(), old = new Date(w.now() * 1000 - 900 * 86400e3).toISOString();
  const { cur } = await verified(w, {}, { repo: { created_at: young, pushed_at: old }, user: { created_at: young } });
  assert.equal(cur.state, 'verified'); assert.deepEqual(cur.findings.map((f) => f.code).sort(), ['STALE', 'YOUNG_ACCOUNT', 'YOUNG_REPO']);
  assert.equal((await authorize(w, cur)).status, 409, 'unacknowledged warnings'); assert.equal((await authorize(w, cur, { acks: ['YOUNG_REPO', 'STALE', 'YOUNG_ACCOUNT'] })).status, 200);
});
test('T-V2: licence spoofing, mismatch, missing and unknown licences', async () => {
  const GPL = 'GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007\n';
  const cases = [['claims MIT, text is GPL', { licenseText: GPL }, 'rejected', 'LIC_TEXT_MISMATCH'], ['repository says MIT, licence endpoint says Apache', { license: { license: { spdx_id: 'Apache-2.0' } } }, 'rejected', 'LIC_MISMATCH'], ['no licence file', { answer: { license: () => J({}, 404) } }, 'rejected', 'LIC_MISSING'],
    ['empty text', { licenseText: '' }, 'rejected', 'LIC_MISSING'], ['text is not base64', { license: { content: '%%%not base64%%%' } }, 'rejected', 'UNEXPECTED_CONTENT']];
  for (const [label, gh, state, code] of cases) { const w = await setup(); const { cur } = await verified(w, {}, gh); assert.equal(cur.state, state, label); assert.equal(cur.state_reason, code, label); }
  const w = await setup(); const odd = await verified(w, {}, { repo: { license: { spdx_id: 'NOASSERTION' } }, license: { license: { spdx_id: 'NOASSERTION' } }, licenseText: 'Detection Rule License 1.1' });
  assert.equal(odd.cur.state, 'verified'); assert.deepEqual(odd.cur.findings, [{ code: 'LIC_NEEDS_LEGAL', severity: 'warn' }]);
  assert.equal((await authorize(w, odd.cur)).status, 409); assert.equal((await authorize(w, odd.cur, { acks: ['LIC_NEEDS_LEGAL'] })).status, 200);
});
test('T-V3: lookalikes of existing sources need an acknowledgement and exact duplicates are blocked', async () => {
  for (const [owner, name, want] of [['Neo23x0', 'signature-bas3', 'LOOKALIKE'], ['Neo23x1', 'signature-base', 'LOOKALIKE'], ['Yara-Rule', 'rules', 'LOOKALIKE'], ['evil', 'signature-base', 'LOOKALIKE'], ['neo-23x0', 'signature_base', 'LOOKALIKE'], ['neo23x0', 'signature-base', 'DUPLICATE'], ['NEO23X0', 'Signature-Base', 'DUPLICATE'], ['virustotal', 'yara-x', 'DUPLICATE']]) {
    const w = await setup(); github(w, { owner, name }); const p = (await propose(w, w.rita, { url: `https://github.com/${owner}/${name}`, source_id: 'fresh-id' })).data.proposal; await act(w, w.rita, p.id, 'verify');
    const cur = await get(w, p.id); assert.ok(cur.findings.some((f) => f.code === want), `${owner}/${name}: ${JSON.stringify(cur.findings)}`); assert.equal(cur.state, want === 'DUPLICATE' ? 'rejected' : 'verified');
  }
  for (const [id, want] of [['nextron', 'DUPLICATE_ID'], ['nextr0n', 'LOOKALIKE'], ['next-ron', 'LOOKALIKE'], ['communit', 'LOOKALIKE']]) {
    const w = await setup(); const { cur } = await verified(w, { source_id: id }); assert.ok(cur.findings.some((f) => f.code === want), `${id}: ${JSON.stringify(cur.findings)}`);
  }
  const w = await setup(); const a = await verified(w); await authorize(w, a.cur); const mine = await get(w, a.p.id);
  assert.equal(mine.state, 'approved');
  assert.deepEqual(P.lookalikes({ full: 'acme/yara-feed', source_id: 'zz', repo_id: 777 }, [{ id: 'other', repo: 'someone/else', repo_id: 777 }]).map((f) => f.code), ['DUPLICATE'], 'same immutable repo id after a rename');
});
test('verification needs the list of existing sources: when it cannot be read the result is unavailable, never verified', async () => {
  const w = await setup(); rawSources(w, { status: 502 }); github(w); const p = (await propose(w, w.rita)).data.proposal; await act(w, w.rita, p.id, 'verify');
  assert.equal((await get(w, p.id)).state, 'proposed');
});
test('T-V5: the eleventh verification within an hour is refused', async () => {
  const w = await setup(); github(w, { answer: { repo: () => new Response('x', { status: 502 }) } }); const p = (await propose(w, w.rita)).data.proposal;
  for (let i = 0; i < 10; i++) assert.equal((await act(w, w.rita, p.id, 'verify')).status, 200);
  assert.equal((await act(w, w.rita, p.id, 'verify')).status, 429); w.tick(3700); assert.equal((await act(w, w.rita, p.id, 'verify')).status, 200);
});
test('an SSRF guard failure is a finding and an audit event without the raw URL', async () => {
  const w = await setup(); const g = github(w); const p = (await propose(w, w.rita)).data.proposal;
  const res = await P.verifyRepo(w.deps, { owner: 'a/../../orgs', repo: 'x', full: 'a/x', source_id: 'zz', paths: ['y'] }, [], { token: 't', nowMs: Date.now() });
  assert.equal(res.outcome, 'rejected'); assert.equal(res.findings[0].code, 'SSRF_GUARD'); assert.equal(res.evidence.requests.length, 0); void g; void p;
  const res2 = await P.verifyRepo(w.deps, { owner: 'evil.com#', repo: 'x', full: 'a/x', source_id: 'zz', paths: ['y'] }, [], { token: 't', nowMs: Date.now() }); assert.equal(res2.findings[0].code, 'SSRF_GUARD');
});

// ---------- roles ----------
test('roles: a VIEWER and a stranger cannot propose; REVIEWER and ADMIN propose and verify; only an ADMIN authorizes, rejects or retires; everybody signed in reads', async () => {
  const w = await setup(); w.account('vera', 7); assert.equal((await w.grant(w.admin, 'vera', 'VIEWER')).status, 200); const vera = await w.login('vera', { pull: true }, { id: 7 }); const stranger = await w.login('sam', { pull: true }, { id: 9 });
  assert.equal((await w.call('POST', '/api/source-proposals', { body: body() })).status, 401);
  assert.equal((await propose(w, vera)).status, 403); assert.equal((await propose(w, stranger)).status, 403);
  github(w); const p = (await propose(w, w.rita)).data.proposal;
  for (const u of [vera, stranger]) assert.equal((await act(w, u, p.id, 'verify')).status, 403);
  assert.equal((await act(w, w.rita, p.id, 'verify', { expect_version: 1 })).status, 200);
  const cur = await get(w, p.id);
  for (const [name, op, b] of [['authorize', 'authorize', { expect_version: cur.version, acks: [], confirm_repo: cur.repo, reason: 'looks fine to me' }], ['reject', 'reject', { expect_version: cur.version, reason: 'not wanted' }], ['retire', 'retire', { expect_version: cur.version, reason: 'not wanted' }]]) {
    for (const u of [w.rita, vera, stranger]) assert.equal((await act(w, u, p.id, op, b)).status, 403, `${name} by ${u.cookie}`);
  }
  assert.equal((await get(w, p.id)).state, 'verified');
  assert.equal((await w.call('GET', '/api/source-proposals', { user: vera })).status, 200); assert.equal((await w.call('GET', `/api/source-proposals/${p.id}`, { user: vera })).status, 200);
  assert.equal((await w.call('GET', '/api/source-proposals', { user: stranger })).status, 403); assert.equal((await w.call('GET', '/api/source-proposals')).status, 401);
  const list = (await w.call('GET', '/api/source-proposals', { user: vera })).data; assert.equal(list.can_propose, false); assert.equal(list.can_authorize, false);
  const adminPropose = await propose(w, w.admin, { url: 'https://github.com/acme/other', source_id: 'other-one' }); assert.equal(adminPropose.status, 200);
});
test('unsafe requests need the CSRF token and the same origin, and the feature answers 404 until it is switched on', async () => {
  const w = await setup(); assert.equal((await w.call('POST', '/api/source-proposals', { user: w.rita, body: body(), csrf: false })).status, 403); assert.equal((await w.call('POST', '/api/source-proposals', { user: w.rita, body: body(), origin: false })).status, 403);
  const off = await setup({ enabled: false }); assert.equal((await off.call('GET', '/api/source-proposals', { user: off.rita })).status, 404); assert.equal((await propose(off, off.rita)).status, 404);
  assert.equal((await off.call('GET', '/api/pipeline/source-proposals', { bearer: await off.pipelineToken('source-proposals.yml') })).status, 404);
  assert.equal(await count(off, 'SELECT COUNT(*) AS n FROM source_proposals'), 0);
});
test('a request body above the cap is refused', async () => {
  const w = await setup(); assert.equal((await propose(w, w.rita, { reason: 'x'.repeat(25_000) })).status, 413);
});

// ---------- authorization, payload and the pipeline endpoint ----------
test('authorize: stale verification, wrong version, wrong confirmation and wrong state are refused; success freezes a canonical payload', async () => {
  const w = await setup(); const { p, cur } = await verified(w);
  assert.equal((await authorize(w, cur, { confirm_repo: 'acme/other' })).status, 400); assert.equal((await authorize(w, cur, { confirm_repo: 'ACME/YARA-FEED' })).status, 400, 'exact canonical case');
  assert.equal((await authorize(w, cur, { expect_version: cur.version + 5 })).status, 409); assert.equal((await authorize(w, cur, { reason: 'no' })).status, 400); assert.equal((await act(w, w.admin, p.id, 'authorize', { confirm_repo: cur.repo, acks: [], reason: 'reviewed it fine' })).status, 400, 'expect_version required');
  await w.db.prepare('UPDATE source_proposals SET verified_at = ? WHERE id = ?').bind(new Date((w.now() - 86_401) * 1000).toISOString(), p.id).run(); const stale = await authorize(w, cur); assert.equal(stale.status, 409); assert.equal(stale.data.code, 'stale_verification');
  assert.equal((await act(w, w.rita, p.id, 'verify')).status, 200); const fresh = await get(w, p.id);
  const ok = await authorize(w, fresh); assert.equal(ok.status, 200); const a = await get(w, p.id);
  assert.equal(a.state, 'approved'); assert.equal(a.approved_by, 'ada');
  const expected = { admission: 'probation', id: 'acme-feed', kind: 'rules', license: { sha256: createHash('sha256').update(MIT).digest('hex'), spdx: 'MIT' }, paths: ['yara'], repo: 'acme/yara-feed', verified_commit: 'a'.repeat(40) };
  assert.deepEqual(a.payload, expected); assert.equal(a.payload_sha256, createHash('sha256').update(JSON.stringify(expected)).digest('hex'));
  assert.ok(!JSON.stringify(a.payload).includes('community feed'), 'the proposer text never reaches the payload');
  assert.equal((await authorize(w, a)).status, 409, 'already approved'); assert.equal((await act(w, w.admin, p.id, 'verify')).status, 409);
});
test('GET /api/pipeline/source-proposals returns only approved proposals, only to the dedicated workflow on main', async () => {
  const w = await setup(); const a = await verified(w); await authorize(w, a.cur);
  github(w, { owner: 'beta', name: 'feed' }); const b = (await propose(w, w.rita, { url: 'https://github.com/beta/feed', source_id: 'beta-feed' })).data.proposal; await act(w, w.rita, b.id, 'verify');
  github(w, { owner: 'gamma', name: 'feed' }); const c = (await propose(w, w.rita, { url: 'https://github.com/gamma/feed', source_id: 'gamma-feed' })).data.proposal;
  const ok = await w.call('GET', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken('source-proposals.yml') }); assert.equal(ok.status, 200);
  assert.deepEqual(ok.data.proposals.map((x) => x.id), [a.p.id]); assert.equal(ok.data.proposals[0].payload.admission, 'probation'); assert.match(ok.data.proposals[0].payload_sha256, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(ok.data).includes('community feed') && !JSON.stringify(ok.data).includes('rita'), 'no reason, no names'); void b; void c;
  for (const wf of ['daily.yml', 'publish.yml']) assert.equal((await w.call('GET', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken(wf) })).status, 403, wf);
  assert.equal((await w.call('GET', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken('source-proposals.yml', { ref: 'refs/heads/feature' }) })).status, 401);
  assert.equal((await w.call('GET', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken('source-proposals.yml', { repository: 'evil/fork' }) })).status, 401);
  assert.equal((await w.call('GET', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken('source-proposals.yml', { aud: 'https://evil.test' }) })).status, 401);
  assert.equal((await w.call('GET', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken('source-proposals.yml', { exp: 1 }) })).status, 401);
  assert.equal((await w.call('GET', '/api/pipeline/source-proposals')).status, 401);
  assert.equal((await w.call('GET', '/api/pipeline/source-proposals', { user: w.admin })).status, 401, 'a signed-in person is not the pipeline');
  assert.equal((await w.call('POST', '/api/pipeline/source-proposals', { bearer: await w.pipelineToken('source-proposals.yml'), body: {} })).status, 404, 'no write endpoint for the pipeline in phase 1');
});
test('reject and retire: allowed moves only, terminal states stay terminal, the unique open index frees the repository', async () => {
  const w = await setup(); const a = await verified(w);
  assert.equal((await act(w, w.admin, a.p.id, 'retire', { expect_version: a.cur.version, reason: 'nothing to retire' })).status, 409, 'cannot retire a verified proposal');
  assert.equal((await act(w, w.admin, a.p.id, 'reject', { expect_version: a.cur.version, reason: 'not interested now' })).status, 200);
  for (const op of ['verify', 'authorize', 'reject', 'retire']) assert.equal((await act(w, w.admin, a.p.id, op, { expect_version: a.cur.version + 1, reason: 'again please', acks: [], confirm_repo: 'acme/yara-feed' })).status, 409, op);
  github(w); assert.equal((await propose(w, w.rita)).status, 200, 'the same repository can be proposed again after a rejection');
  const w2 = await setup(); const b = await verified(w2); await authorize(w2, b.cur); const ap = await get(w2, b.p.id);
  assert.equal((await act(w2, w2.admin, b.p.id, 'retire', { expect_version: ap.version, reason: 'withdrawn by owner' })).status, 200); assert.equal((await get(w2, b.p.id)).state, 'retired');
  assert.equal((await w2.call('GET', '/api/pipeline/source-proposals', { bearer: await w2.pipelineToken('source-proposals.yml') })).data.proposals.length, 0, 'a retired proposal is no longer handed to the pipeline');
});

// ---------- idempotence, concurrency, per-row guards (T-A4, T-D3) ----------
test('idempotence: the same request id applies once; reusing it for another proposal or action is refused', async () => {
  const w = await setup(); const b = body(); const r1 = await w.call('POST', '/api/source-proposals', { user: w.rita, body: b }), r2 = await w.call('POST', '/api/source-proposals', { user: w.rita, body: b });
  assert.equal(r1.status, 200); assert.equal(r2.status, 200); assert.equal(r2.data.replay, true); assert.equal(r2.data.proposal.id, r1.data.proposal.id); assert.equal(await count(w, 'SELECT COUNT(*) AS n FROM source_proposals'), 1);
  assert.equal((await w.call('POST', '/api/source-proposals', { user: w.rita, body: { ...b, url: 'https://github.com/acme/else', source_id: 'else-id' } })).status, 409);
  assert.equal((await w.call('POST', '/api/source-proposals', { user: w.admin, body: b })).status, 409, 'another person cannot replay it');
  github(w); const id = r1.data.proposal.id, v = { request_id: rid() };
  assert.equal((await w.call('POST', `/api/source-proposals/${id}/verify`, { user: w.rita, body: v })).status, 200); const again = await w.call('POST', `/api/source-proposals/${id}/verify`, { user: w.rita, body: v });
  assert.equal(again.status, 200); assert.equal(again.data.replay, true); assert.equal(await count(w, "SELECT COUNT(*) AS n FROM source_proposal_events WHERE event LIKE 'verify.%'"), 1);
  const cur = await get(w, id); const rq = rid(); const first = await authorize(w, cur, { request_id: rq }); assert.equal(first.status, 200);
  const rep = await authorize(w, cur, { request_id: rq }); assert.equal(rep.status, 200); assert.equal(rep.data.replay, true); assert.equal(await count(w, "SELECT COUNT(*) AS n FROM audit WHERE action = 'source.approved'"), 1);
  assert.equal((await act(w, w.admin, id, 'reject', { request_id: rq, expect_version: 99, reason: 'reuse of an id' })).status, 409, 'same id, different action');
});
test('concurrency: two administrators authorize at once, one wins, one audit entry, the chain verifies', async () => {
  const w = await setup(); const { cur } = await verified(w); const boss = await w.login('boss', { admin: true }, { id: 11 });
  const mk = (u) => w.call('POST', `/api/source-proposals/${cur.id}/authorize`, { user: u, body: { request_id: rid(), expect_version: cur.version, acks: [], confirm_repo: cur.repo, reason: 'reviewed it carefully' } });
  const [a, b] = await Promise.all([mk(w.admin), mk(boss)]); assert.deepEqual([a.status, b.status].sort(), [200, 409]);
  assert.equal(await count(w, "SELECT COUNT(*) AS n FROM source_proposal_events WHERE event = 'approved'"), 1); assert.equal(await count(w, "SELECT COUNT(*) AS n FROM audit WHERE action = 'source.approved'"), 1);
  assert.equal((await verifyChain(await auditRows(w.db))).ok, true);
});
test('concurrency: reject racing authorize leaves exactly one outcome', async () => {
  const w = await setup(); const { cur } = await verified(w);
  const [a, r] = await Promise.all([authorize(w, cur), act(w, w.admin, cur.id, 'reject', { expect_version: cur.version, reason: 'changed my mind' })]);
  assert.deepEqual([a.status, r.status].sort(), [200, 409]); const end = await get(w, cur.id); assert.ok(['approved', 'rejected'].includes(end.state));
  assert.equal(await count(w, "SELECT COUNT(*) AS n FROM source_proposal_events WHERE proposal_id = ? AND version = ?", cur.id, cur.version + 1), 1);
});
test('concurrent identical creates make one proposal; a second open proposal for the same repository or id is a 409', async () => {
  const w = await setup(); const b = body(); const [x, y] = await Promise.all([w.call('POST', '/api/source-proposals', { user: w.rita, body: b }), w.call('POST', '/api/source-proposals', { user: w.rita, body: b })]);
  assert.deepEqual([x.status, y.status], [200, 200]); assert.equal(await count(w, 'SELECT COUNT(*) AS n FROM source_proposals'), 1);
  assert.equal((await propose(w, w.rita, { source_id: 'other-id' })).status, 409, 'same repository'); assert.equal((await propose(w, w.rita, { url: 'https://github.com/zed/other', source_id: 'acme-feed' })).status, 409, 'same id');
  assert.equal((await propose(w, w.rita, { url: 'https://github.com/ACME/YARA-FEED', source_id: 'third-id' })).status, 409, 'same repository, other case');
});
test('a statement whose guard fails rolls the whole batch back: no row change, no event, no audit entry', async () => {
  const w = await setup(); const { cur } = await verified(w); const n = async () => ({ ev: await count(w, 'SELECT COUNT(*) AS n FROM source_proposal_events'), au: await count(w, 'SELECT COUNT(*) AS n FROM audit') });
  const before = await n(); let hit = false; const realBatch = w.db.batch.bind(w.db);
  w.db.batch = async (list) => { if (!hit) { hit = true; await w.db.prepare('UPDATE source_proposals SET version = version + 1 WHERE id = ?').bind(cur.id).run(); } return realBatch(list); };   // someone else moves it between the read and the write
  const lost = await P.transition(w.db, cur.id, { from: ['verified'], to: 'rejected', event: 'rejected', action: 'source.rejected', request_id: rid() }, { login: 'x', id: 1, role: 'ADMIN' }, new Date().toISOString());
  assert.equal(lost.status, 409); assert.equal(lost.retry, true);
  const raw = await P.getRaw(w.db, cur.id); assert.equal(raw.state, 'verified'); assert.equal(raw.version, cur.version + 1, 'only the other writer changed the row');
  assert.deepEqual(await n(), before);
});

// ---------- audit and tables (T-D1, T-D2) ----------
test('audit: every step is in the hash chain and in the append-only event table; the chain verifies and detects tampering', async () => {
  const w = await setup(); const { cur } = await verified(w); await authorize(w, cur); const a = await get(w, cur.id); await act(w, w.admin, cur.id, 'retire', { expect_version: a.version, reason: 'retired after review' });
  const actions = (await auditRows(w.db, 100)).map((r) => r.action).filter((x) => x.startsWith('source.')); assert.deepEqual(actions, ['source.proposed', 'source.verify', 'source.approved', 'source.retired']);
  const end = await get(w, cur.id); assert.deepEqual(end.events.map((e) => e.event), ['proposed', 'verify.ok', 'approved', 'retired']); assert.deepEqual(end.events.map((e) => e.version), [1, 2, 3, 4]);
  assert.deepEqual(end.events.map((e) => e.role), ['REVIEWER', 'REVIEWER', 'ADMIN', 'ADMIN']);
  const rows = await auditRows(w.db, 100); assert.equal((await verifyChain(rows)).ok, true);
  const hashes = new Set(rows.map((r) => r.hash)); for (const e of (await w.db.prepare('SELECT audit_hash FROM source_proposal_events').all()).results) assert.ok(hashes.has(e.audit_hash), 'each event points at its audit entry');
  const detail = JSON.parse(rows.find((r) => r.action === 'source.proposed').detail); assert.equal(detail.reason_len, 'community feed with a clear licence'.length); assert.ok(!('reason' in detail), 'the reason text is not copied to the audit');
  const bad = rows.map((r) => ({ ...r })); bad[1].detail = '{}'; assert.equal((await verifyChain(bad)).ok, false);
  await assert.rejects(() => w.db.prepare("UPDATE source_proposal_events SET actor = 'x'").run(), /append-only/); await assert.rejects(() => w.db.prepare('DELETE FROM source_proposal_events').run(), /append-only/);
});
test('table constraints refuse malformed rows even when the application is bypassed', async () => {
  const w = await setup(); const ins = (over) => { const r = { id: 'x1', source_id: 'ok-id', repo: 'a/b', repo_lc: 'a/b', kind: 'rules', paths: '["p"]', state: 'proposed', reason: 'long enough', proposer: 'p', proposer_id: 1, request_id: 'r1', created_at: 't', updated_at: 't', ...over }; return w.db.prepare(`INSERT INTO source_proposals (${Object.keys(r).join(',')}) VALUES (${Object.keys(r).map(() => '?').join(',')})`).bind(...Object.values(r)).run(); };
  for (const over of [{ source_id: 'Bad' }, { source_id: 'a b' }, { source_id: 'a\n' }, { kind: 'engine' }, { state: 'merged' }, { paths: '[]' }, { paths: '{}' }, { paths: 'x' }, { repo_lc: 'A/B' }, { reason: 'abc' }, { verified_commit: 'xyz' }, { payload_sha256: 'abc' }, { repo: 'nosep' }]) await assert.rejects(() => ins(over), /constraint/i, JSON.stringify(over));
  await ins({}); await assert.rejects(() => ins({ id: 'x2', request_id: 'r2' }), /UNIQUE/);
});
test('the Worker keeps no GitHub write path: proposals.js only issues GET and never dispatches', () => {
  const src = readFileSync(new URL('../src/proposals.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /dispatches|\/actions\/|workflow_dispatch|repository_dispatch|method:\s*'(POST|PUT|PATCH|DELETE)'/); assert.match(src, /redirect: 'manual'/); assert.doesNotMatch(src, /redirect: '(follow|error)'/);
  assert.deepEqual([...new Set([...src.matchAll(/https:\/\/[a-z.]+/g)].map((m) => m[0]))].sort(), ['https://api.github.com', 'https://github.com', 'https://raw.githubusercontent.com']);
});

// ---------- the new-source hold, panel side ----------
test('a new-source candidate is cleared by an ADMIN only; a REVIEWER can still reject or hold it and nothing is written on refusal', async () => {
  const w = await setup(); const r = await w.submit([cand('ns', 'rules/acme/ns.yar', { source: 'acme', reasons: ['new-source'] })]); assert.equal(r.status, 200); const id = r.data.results[0].id;
  const c = (await w.call('GET', `/api/candidates/${id}`, { user: w.rita })).data; assert.equal(c.approvable, true);
  const dec = (u, action, extra = {}) => w.call('POST', '/api/decisions', { user: u, body: { action, ids: [id], reason: 'reviewed by hand', request_id: rid(), expect: { [id]: c.version }, ...extra } });
  const before = await count(w, 'SELECT COUNT(*) AS n FROM audit'); const no = await dec(w.rita, 'approve'); assert.equal(no.status, 403); assert.match(no.data.error, /admin role required/);
  assert.equal(await count(w, 'SELECT COUNT(*) AS n FROM audit'), before); assert.equal(await count(w, 'SELECT COUNT(*) AS n FROM decisions'), 0); assert.equal((await w.call('GET', `/api/candidates/${id}`, { user: w.rita })).data.state, 'PENDING');
  assert.equal((await dec(w.rita, 'hold')).status, 200);
  const c2 = (await w.call('GET', `/api/candidates/${id}`, { user: w.rita })).data; const ok = await w.call('POST', '/api/decisions', { user: w.admin, body: { action: 'approve', ids: [id], reason: 'source reviewed', request_id: rid(), expect: { [id]: c2.version } } }); assert.equal(ok.status, 200);
  const w2 = await setup(); const r2 = await w2.submit([cand('ns2', 'rules/acme/ns2.yar', { source: 'acme', reasons: ['new-source', 'license-changed'] })]); const id2 = r2.data.results[0].id;
  assert.equal((await w2.call('GET', `/api/candidates/${id2}`, { user: w2.admin })).data.approvable, false, 'a changed licence stays unapprovable even for an ADMIN');
});

// ---------- migration 0005 and its rollback ----------
test('migration 0005: schema.sql mirrors it exactly, it upgrades an older database, and the rollback removes only what it created and can be undone', () => {
  const dir = new URL('../', import.meta.url), up = readFileSync(new URL('migrations/0005_source_proposals.sql', dir), 'utf8'), down = readFileSync(new URL('migrations/0005_rollback.sql', dir), 'utf8'), schema = readFileSync(new URL('schema.sql', dir), 'utf8');
  const marker = schema.match(/-- >>> 0005[^\n]*\n([\s\S]*?)-- <<< 0005/); assert.ok(marker, 'delimited mirror'); assert.equal(marker[1], up, 'schema.sql carries the migration verbatim');
  const objects = (db) => db.prepare("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all().map((r) => `${r.type}:${r.name}:${r.sql}`);
  const old = new DatabaseSync(':memory:'); old.exec(schema.replace(marker[0], '')); const base = objects(old);   // the database as it is before 0005: every other migration (0003, 0004) already applied, whatever their order in schema.sql
  old.exec("INSERT INTO audit (at, actor, role, action, target, detail, prev_hash, hash) VALUES ('t','a','ADMIN','x','y','{}','" + '0'.repeat(64) + "','" + '1'.repeat(64) + "')");
  old.exec(up); const upgraded = objects(old); assert.ok(upgraded.length > base.length); assert.deepEqual(upgraded, objects(newDb().raw), 'an upgraded database equals a fresh one');
  old.exec(up); assert.deepEqual(objects(old), upgraded, 'idempotent (IF NOT EXISTS)');
  old.exec("INSERT INTO source_proposals (id, source_id, repo, repo_lc, kind, paths, state, reason, proposer, proposer_id, request_id, created_at, updated_at) VALUES ('i','abc','a/b','a/b','rules','[\"p\"]','proposed','long enough','p',1,'r','t','t')");
  old.exec(down); assert.deepEqual(objects(old), base, 'back to the previous schema, object for object'); assert.equal(old.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 1, 'audit untouched');
  old.exec(down); old.exec(up); assert.deepEqual(objects(old), upgraded, 'up again after a rollback');
});

// ---------- phase 2: the pull workflow reports back (pr, sync) ----------
const VECTOR_DIGEST = '44cd18e84160d7f1ee456a1fa8c9f48dd3ae61f17f7564da088cb336469ee6d5';   // tests/test_source_proposal.py computes the same value in Python
const pipe = async (w, wf = 'source-proposals.yml', claims = {}) => ({ bearer: await w.pipelineToken(wf, { run_id: 4242, run_attempt: 1, ...claims }) });
async function approved(w) {
  const { cur } = await verified(w); assert.equal((await authorize(w, cur)).status, 200); const a = await get(w, cur.id);
  const branch = `proposal/${a.source_id}-${a.payload_sha256.slice(0, 8)}`;
  return { a, branch, pr: (n = 7, over = {}) => ({ pr_number: n, pr_url: `https://github.com/${REPO}/pull/${n}`, branch, head_sha: 'b'.repeat(40), payload_sha256: a.payload_sha256, ...over }) };
}
const postPr = async (w, id, body, wf, claims) => w.call('POST', `/api/pipeline/source-proposals/${id}/pr`, { ...(await pipe(w, wf, claims)), body });
const sync = async (w, body, wf) => w.call('POST', '/api/pipeline/source-proposals/sync', { ...(await pipe(w, wf)), body });

test('pipeline /pr: records the pull request once, only for the dedicated workflow, only for the exact branch and payload', async () => {
  const w = await setup(); const { a, pr, branch } = await approved(w);
  for (const wf of ['daily.yml', 'publish.yml']) assert.equal((await postPr(w, a.id, pr(), wf)).status, 403, wf);
  assert.equal((await w.call('POST', `/api/pipeline/source-proposals/${a.id}/pr`, { body: pr() })).status, 401);
  assert.equal((await w.call('POST', `/api/pipeline/source-proposals/${a.id}/pr`, { user: w.admin, body: pr() })).status, 401, 'a signed-in person is not the pipeline');
  for (const over of [{ branch: 'proposal/evil-12345678' }, { branch: 'main' }, { pr_url: 'https://github.com/evil/x/pull/7' }, { pr_url: `https://github.com/${REPO}/pull/8` }, { head_sha: 'xyz' }, { pr_number: 0 }, { pr_number: '7' }, { pr_number: 1e9 }]) assert.equal((await postPr(w, a.id, pr(7, over))).status, 400, JSON.stringify(over));
  assert.equal((await postPr(w, a.id, pr(7, { payload_sha256: 'f'.repeat(64) }))).status, 409);
  assert.equal((await get(w, a.id)).state, 'approved', 'nothing changed yet');
  const ok = await postPr(w, a.id, pr()); assert.equal(ok.status, 200); const now = await get(w, a.id); assert.equal(now.state, 'pr_open'); assert.equal(now.pr_branch, branch); assert.equal(now.pr_number, 7);
  const again = await postPr(w, a.id, pr()); assert.equal(again.status, 200); assert.equal(again.data.replay, true); assert.equal(await count(w, "SELECT COUNT(*) AS n FROM source_proposal_events WHERE event = 'pr.opened'"), 1);
  assert.equal((await postPr(w, a.id, pr(9))).status, 409, 'a second pull request for the same proposal');
  const ev = now.events.at(-1); assert.equal(ev.role, 'PIPELINE'); assert.equal(ev.detail.token_run_id, '4242'); assert.equal(ev.detail.head_sha, 'b'.repeat(40));
  assert.deepEqual((await w.call('GET', '/api/pipeline/source-proposals', await pipe(w))).data.proposals, [], 'a proposal with a pull request is no longer handed out');
  assert.equal((await verifyChain(await auditRows(w.db))).ok, true);
  const w2 = await setup(); const { cur } = await verified(w2); assert.equal((await postPr(w2, cur.id, { pr_number: 1, pr_url: `https://github.com/${REPO}/pull/1`, branch: 'proposal/x-12345678', head_sha: 'b'.repeat(40), payload_sha256: 'a'.repeat(64) })).status, 400);
});
test('pipeline /sync: merged is believed only when main itself contains the entry exactly as authorized', async () => {
  const w = await setup(); const { a, pr, branch } = await approved(w); await postPr(w, a.id, pr());
  const entry = { id: 'acme-feed', repo: 'acme/yara-feed', kind: 'rules', paths: ['yara'], admission: 'probation' };
  const main = (over) => rawSources(w, { body: { sources: [...SOURCES.sources, ...(over === null ? [] : [{ ...entry, ...over }])] } });
  for (const over of [null, { repo: 'evil/yara-feed' }, { paths: ['yara', 'extra'] }, { admission: undefined }, { kind: 'engine' }, { id: 'other' }]) { main(over); const r = await sync(w, { branch, outcome: 'merged' }); assert.equal(r.status, 409, JSON.stringify(over)); assert.equal((await get(w, a.id)).state, 'pr_open'); }
  rawSources(w, { status: 502 }); assert.equal((await sync(w, { branch, outcome: 'merged' })).status, 502); assert.equal((await get(w, a.id)).state, 'pr_open');
  assert.equal((await sync(w, { branch, outcome: 'merged' }, 'daily.yml')).status, 403);
  for (const body of [{ branch: 'main', outcome: 'merged' }, { branch, outcome: 'whatever' }, { outcome: 'merged' }]) assert.equal((await sync(w, body)).status, 400);
  assert.equal((await sync(w, { branch: 'proposal/unknown-12345678', outcome: 'merged' })).status, 404);
  main({}); const ok = await sync(w, { branch, outcome: 'merged' }); assert.equal(ok.status, 200); const end = await get(w, a.id); assert.equal(end.state, 'active');
  assert.equal(end.events.at(-1).detail.equal, true); assert.match(end.events.at(-1).detail.main_entry_sha256, /^[0-9a-f]{64}$/);
  assert.equal((await sync(w, { branch, outcome: 'merged' })).status, 404, 'no longer open: the second call finds nothing to do');
  assert.equal((await act(w, w.admin, a.id, 'retire', { expect_version: end.version, reason: 'removed again' })).status, 200);
});
test('pipeline /sync: a pull request closed without merging returns the proposal to approved and a new one can be recorded', async () => {
  const w = await setup(); const { a, pr, branch } = await approved(w); await postPr(w, a.id, pr(7));
  assert.equal((await sync(w, { branch, outcome: 'closed_unmerged' })).status, 200); const back = await get(w, a.id); assert.equal(back.state, 'approved'); assert.equal(back.pr_number, null); assert.equal(back.pr_branch, null);
  assert.equal((await postPr(w, a.id, pr(8))).status, 200); assert.equal((await get(w, a.id)).pr_number, 8);
  assert.equal((await verifyChain(await auditRows(w.db))).ok, true);
});
test('canonical payload digest: key order does not matter and the vector is shared with scripts/source_proposal.py', async () => {
  const p = { admission: 'probation', id: 'acme-feed', kind: 'rules', license: { sha256: 'a'.repeat(64), spdx: 'MIT' }, paths: ['yara', 'rules/x'], repo: 'acme/yara-feed', verified_commit: 'b'.repeat(40) };
  assert.equal(await P.payloadDigest({ verified_commit: p.verified_commit, repo: p.repo, paths: p.paths, license: { spdx: 'MIT', sha256: 'a'.repeat(64) }, kind: 'rules', id: p.id, admission: 'probation' }), await P.payloadDigest(p));
  assert.equal(await P.payloadDigest(p), createHash('sha256').update(JSON.stringify(p)).digest('hex'), 'keys already sorted: the digest is the SHA-256 of the compact JSON');
  assert.equal(await P.payloadDigest(p), VECTOR_DIGEST);
});
