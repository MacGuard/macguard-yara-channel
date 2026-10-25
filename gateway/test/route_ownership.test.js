// Route ownership audit: which Worker owns which paths, checked from the SOURCE of both Workers (no remote call). It is the machine-checkable half of the "audit routes before any domain migration" rule:
// the gateway (Intelligence REST/MCP, billing, admin, analytics) and Quarantine (panel API, GitHub sign-in, pipeline) must never claim the same path, so moving a hostname can never silently move a function.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { routes } from '../tools/route_inventory.mjs';

const QSRC = readFileSync(new URL('../../admin/worker/src/index.js', import.meta.url), 'utf8') + readFileSync(new URL('../../admin/worker/src/proposals.js', import.meta.url), 'utf8');
const GATEWAY_PREFIXES = ['/v1/', '/admin/v1/', '/mcp', '/stripe/', '/x402/'];
// Paths the Quarantine Worker routes on, read from its code: literal comparisons and startsWith prefixes.
const qExact = new Set([...QSRC.matchAll(/path === '(\/[^']*)'/g)].map((m) => m[1])), qPrefix = new Set([...QSRC.matchAll(/path\.startsWith\('(\/[^']*)'\)/g)].map((m) => m[1]));
const gwPath = (p) => p.replace(/\{[^}]+\}/g, 'x');

test('the audit reads a meaningful route set from both Workers (a parser that finds nothing would pass vacuously)', () => {
  assert.ok(qExact.size >= 15, `Quarantine exact routes found: ${qExact.size}`); assert.ok(qPrefix.has('/api/') && qPrefix.has('/auth/'), [...qPrefix].join(' '));
  assert.ok(routes().length >= 40);
});

test('no gateway route is a Quarantine route, and no Quarantine route sits under a gateway prefix', () => {
  for (const r of routes()) {
    const p = gwPath(r.path);
    assert.ok(![...qExact].includes(p), `${r.method} ${r.path} is also a Quarantine path`); assert.ok(![...qPrefix].some((q) => p.startsWith(q)), `${r.method} ${r.path} is under a Quarantine prefix`);
    assert.ok(GATEWAY_PREFIXES.some((g) => p === g || p.startsWith(g) || p === g.replace(/\/$/, '')), `${r.path} is outside the gateway's own prefixes: the ownership rule needs a decision`);
  }
  for (const q of [...qExact, ...qPrefix]) assert.ok(!GATEWAY_PREFIXES.some((g) => q.startsWith(g)), `Quarantine path ${q} sits under a gateway prefix`);
});

test('the gateway answers 404 for every Quarantine path, so attaching the wrong hostname to it cannot serve Quarantine functions', async () => {
  const { apiWorld } = await import('./apiworld.js'); const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40) } });
  for (const p of ['/api/me', '/api/candidates', '/api/decisions', '/api/pipeline/submit', '/api/policies', '/auth/login', '/auth/callback', '/public/stats']) {
    const res = await w.call(p); assert.equal(res.status, 404, `${p} -> ${res.status}`); assert.equal(res.res.headers.get('set-cookie'), null);
  }
});

test('the gateway has no function the Quarantine decision flow owns (approve / publish / withdraw a rule) and no route named like one', () => {
  for (const r of routes()) assert.ok(!/(candidates|decisions|withdraw|quarantine|pipeline\/submit)/i.test(r.path), r.path);
});
