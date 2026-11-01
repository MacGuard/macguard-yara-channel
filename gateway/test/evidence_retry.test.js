import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sh = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const SCRIPT = new URL('../tools/evidence_retry.sh', import.meta.url).pathname;

function world(n) {
  const root = mkdtempSync(join(tmpdir(), 'mg-evid-')), origin = join(root, 'origin.git'); sh(root, 'init', '-q', '--bare', '-b', 'main', origin);
  const seed = join(root, 'seed'); sh(root, 'clone', '-q', origin, seed); sh(seed, 'config', 'user.email', 'a@b'); sh(seed, 'config', 'user.name', 'a');
  mkdirSync(join(seed, 'evidence'), { recursive: true }); writeFileSync(join(seed, 'evidence/backups.jsonl'), '{"n":0}\n'); mkdirSync(join(seed, 'gateway/tools'), { recursive: true });
  for (const f of ['commit_evidence.sh', 'evidence_retry.sh']) writeFileSync(join(seed, 'gateway/tools', f), readFileSync(new URL(`../tools/${f}`, import.meta.url)));
  sh(seed, 'add', '-A'); sh(seed, 'commit', '-q', '-m', 'seed'); sh(seed, 'push', '-q', 'origin', 'main');
  const clones = Array.from({ length: n }, (_, i) => { const c = join(root, 'c' + i); sh(root, 'clone', '-q', origin, c); return c; });
  return { root, origin, clones, done: () => rmSync(root, { recursive: true, force: true }) };
}
const run = (cwd, i) => new Promise((ok) => { const p = spawn('sh', [join(cwd, 'gateway/tools/evidence_retry.sh'), `record ${i}`, '--', 'sh', '-c', `echo '{"n":${i}}' >> evidence/backups.jsonl`], { cwd, stdio: 'pipe' }); let e = ''; p.stderr.on('data', (d) => (e += d)); p.on('close', (code) => ok({ code, e })); });

test('three concurrent writers all land their evidence: none is lost, none conflicts, the log stays append-only', async () => {
  const w = world(3);
  try {
    const out = await Promise.all(w.clones.map((c, i) => run(c, i + 1)));
    assert.deepEqual(out.map((r) => r.code), [0, 0, 0], JSON.stringify(out.map((r) => r.e)));
    const check = join(w.root, 'check'); sh(w.root, 'clone', '-q', w.origin, check);
    const lines = readFileSync(join(check, 'evidence/backups.jsonl'), 'utf8').trim().split('\n');
    assert.equal(lines[0], '{"n":0}', 'the existing history is untouched'); assert.deepEqual(lines.slice(1).sort(), ['{"n":1}', '{"n":2}', '{"n":3}']);
  } finally { w.done(); }
});

test('a writer that can never push fails loudly after bounded attempts instead of looping or losing the record silently', async () => {
  const w = world(1);
  try {
    writeFileSync(join(w.origin, 'hooks/pre-receive'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const r = await run(w.clones[0], 1); assert.equal(r.code, 1); assert.match(r.e, /after 6 attempts/);
  } finally { w.done(); }
});
