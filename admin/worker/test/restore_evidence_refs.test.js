// Where the panel reads the evidence log from: `main` by default (today), or several refs united without duplicates during the move to the evidence branch. Synthetic data, injected fetch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadRecoveryStatus } from '../src/restore.js';

const NOW = Date.parse('2026-10-28T12:00:00Z');
const BACKUP = { schema: 'macguard.backup-evidence/1', kind: 'backup', resource: 'gateway', at: '2026-10-28T03:00:00Z', run_id: 7, stamp: '20261028T030000Z', sequence: 3, providers: {} };
const RESTORE = { schema: 'macguard.backup-evidence/1', kind: 'restore', resource: 'gateway', at: '2026-10-28T09:00:00Z', run_id: 7, stamp: '20261028T030000Z', provider: 'b2', ok: true, mode: 'drill', plaintext_sha256: 'ab'.repeat(32), duration_s: 12 };
const text = (...r) => r.map((x) => JSON.stringify(x)).join('\n') + '\n';

function deps(files) {   // files: { ref: text | status number }
  const urls = [];
  const fetch = async (url) => {
    urls.push(url);
    const m = /\/(?:MacGuard\/macguard-yara-channel)\/([^/]+)\/evidence\/backups\.jsonl$/.exec(url);
    if (m) { const f = files[m[1]]; if (typeof f === 'number') return new Response('', { status: f }); if (f === undefined) return new Response('', { status: 404 }); return new Response(f, { status: 200 }); }
    if (/actions\/workflows\/backup\.yml\/runs/.test(url)) return Response.json({ workflow_runs: [] });
    if (/backup-trust\.json$/.test(url)) return Response.json({ age_recipient: 'age1abc', ed25519: { fingerprint: 'SHA256:x', max_sequence: 1, namespaces: ['macguard-backup/1'] }, sigstore: null });
    return new Response('', { status: 200 });
  };
  return { fetch, urls };
}
const lastRestore = (st) => st.indicators.find((i) => i.id === 'last_restore');
const env = (extra = {}) => ({ REPO: 'MacGuard/macguard-yara-channel', ...extra });

test('default: only main is read (today\'s behaviour, unchanged)', async () => {
  const d = deps({ main: text(BACKUP, RESTORE), evidence: text(BACKUP) }); const st = await loadRecoveryStatus(env(), d, null, NOW);
  assert.deepEqual(d.urls.filter((u) => u.endsWith('evidence/backups.jsonl')), ['https://raw.githubusercontent.com/MacGuard/macguard-yara-channel/main/evidence/backups.jsonl']);
  assert.notEqual(lastRestore(st).state, 'NOT_RUN'); assert.deepEqual(st.unavailable, []);
});

test('EVIDENCE_REFS=evidence,main: a record present in only ONE copy is still seen, in either direction', async () => {
  for (const [a, b] of [[text(BACKUP), text(BACKUP, RESTORE)], [text(BACKUP, RESTORE), text(BACKUP)]]) {
    const st = await loadRecoveryStatus(env({ EVIDENCE_REFS: 'evidence,main' }), deps({ evidence: a, main: b }), null, NOW);
    assert.equal(lastRestore(st).state === 'NOT_RUN', false, 'the restore is visible whichever copy holds it');
  }
});

test('united without duplicates: the same record in both copies counts once', async () => {
  const st1 = await loadRecoveryStatus(env({ EVIDENCE_REFS: 'evidence,main' }), deps({ evidence: text(BACKUP, RESTORE), main: text(BACKUP, RESTORE) }), null, NOW);
  const st2 = await loadRecoveryStatus(env(), deps({ main: text(BACKUP, RESTORE) }), null, NOW);
  assert.deepEqual(st1.indicators, st2.indicators, 'identical to reading one copy');
});

test('one copy unreadable: the other is still used and the failure is reported by name; both missing (404) is simply "no evidence", not an error', async () => {
  const st = await loadRecoveryStatus(env({ EVIDENCE_REFS: 'evidence,main' }), deps({ evidence: 500, main: text(BACKUP, RESTORE) }), null, NOW);
  assert.notEqual(lastRestore(st).state, 'NOT_RUN'); assert.deepEqual(st.unavailable, [{ source: 'evidence:evidence', reason: 'http_500' }]);
  const none = await loadRecoveryStatus(env({ EVIDENCE_REFS: 'evidence,main' }), deps({}), null, NOW); assert.deepEqual(none.unavailable, []); assert.equal(lastRestore(none).state, 'NOT_RUN');
});

test('the refs setting is validated: odd values cannot build a different URL, more than three are ignored, an empty or invalid list falls back to main', async () => {
  const d = deps({ main: text(BACKUP) });
  await loadRecoveryStatus(env({ EVIDENCE_REFS: '../etc/passwd, a/b, ?x=1, ' }), d, null, NOW);
  assert.deepEqual(d.urls.filter((u) => u.endsWith('evidence/backups.jsonl')), ['https://raw.githubusercontent.com/MacGuard/macguard-yara-channel/main/evidence/backups.jsonl']);
  const d2 = deps({}); await loadRecoveryStatus(env({ EVIDENCE_REFS: 'a,b,c,d,e' }), d2, null, NOW); assert.equal(d2.urls.filter((u) => u.endsWith('evidence/backups.jsonl')).length, 3);
});
