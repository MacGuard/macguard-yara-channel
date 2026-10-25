// Backup records served through the faked GitHub for the Restauración screens: one good backup run 2 hours ago (all three providers written and read back), one earlier run that failed at the export, one selftest, a
// trust policy and the verifier files. Synthetic. MG_RESTORE_DOWN=runs makes the runs source answer 403 (the screen must then say UNKNOWN, never FAILED).
export const TRUST = { age_recipient: 'age1synthetic0000000000000000000000000000000000000000000000000', ed25519: { fingerprint: 'SHA256:O+m9SDdUH6cLko7//d4uktHJOSKxDjp5mdyBQH7hw9o', max_sequence: 1, namespaces: ['macguard-backup/1', 'macguard-backup-checkpoint/1'] }, sigstore: { identity: 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main', repository: 'MacGuard/macguard-yara-channel', issuer: 'https://token.actions.githubusercontent.com' } };
export function installRestore(w, { down = [], latestFails = false } = {}) {
  const now = Date.now(), at = (h) => new Date(now - h * 3600000).toISOString(), P = ['b2', 'scaleway', 'r2'];
  const run = (id, h, conclusion, event = 'workflow_dispatch') => ({ id, html_url: `https://github.com/MacGuard/macguard-yara-channel/actions/runs/${id}`, event, status: 'completed', conclusion, created_at: at(h + 0.1), updated_at: at(h) });
  const SIGN = { name: 'Sign ANCHOR.json and CHECKPOINT.json with Sigstore keyless (nothing is kept unless it verifies for the pinned identity)', conclusion: 'success' };
  const j = (name, conclusion, h = 1, steps = []) => ({ name, status: 'completed', conclusion, completed_at: at(h), steps });
  const good = [j('export', 'success', 2.2, [SIGN]), ...P.flatMap((p) => [j(`fetch (${p})`, 'success', 3), j(`write (${p})`, 'success', 2), j(`read (${p})`, 'success', 1.5)]), j('redundancy', 'success', 1.4), j('selftest', 'skipped')];
  const failed = [j('export', 'failure', 30, []), ...P.flatMap((p) => [j(`fetch (${p})`, 'success', 31), j(`write (${p})`, 'skipped', 30), j(`read (${p})`, 'skipped', 30)])];
  const selftest = [j('selftest', 'success', 50), j('export', 'skipped', 50)];
  const bad = [{ id: 777, ...j('export', 'failure', 1, [{ name: 'Export D1', conclusion: 'failure' }]) }, ...P.flatMap((p) => [j(`fetch (${p})`, 'success', 1.5), j(`write (${p})`, 'skipped', 1), j(`read (${p})`, 'skipped', 1)])];
  const runs = [...(latestFails ? [run(5002, 1, 'failure')] : []), run(5001, 2, 'success'), run(5000, 30, 'failure'), run(4999, 50, 'success')], jobs = { 5002: bad, 5001: good, 5000: failed, 4999: selftest };
  const ok = (o, extra = {}) => new Response(JSON.stringify(o), { headers: { 'x-ratelimit-remaining': '4990', 'x-ratelimit-limit': '5000', ...extra } });
  w.route(/actions\/workflows\/backup\.yml\/runs/, () => (down.includes('runs') ? new Response('{}', { status: 403 }) : ok({ workflow_runs: runs })));
  w.route(/actions\/runs\/(\d+)\/jobs/, (u) => ok({ jobs: jobs[u.match(/runs\/(\d+)\/jobs/)[1]] || [] }));
  w.route(/check-runs\/777\/annotations/, () => ok([{ message: 'macguard-backup: resource=gateway phase=export kind=cloudflare_auth code=10000' }, { message: 'macguard-backup: kind=evil <x>' }]));
  w.route(/backup-trust\.json$/, () => new Response(JSON.stringify(TRUST))); w.route(/evidence\/backups\.jsonl$/, () => new Response('not found', { status: 404 }));
  w.route(/\/gateway\/tools\/[a-z_.]+$/, () => new Response('#!/bin/sh'));
}
