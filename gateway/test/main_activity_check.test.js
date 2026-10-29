// scripts/main_activity_check.sh with a `gh` shim: events are reported (exit 1), a clean window is exit 0, and anything that stops the question being answered is exit 2, never "no events". It is read-only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SH = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'main_activity_check.sh');
function shim(events, { fail = false } = {}) {   // events: [{timestamp, activity_type, ref, actor}] served through the real --jq filter by a tiny node implementation
  const d = mkdtempSync(join(tmpdir(), 'mg-gh-')), calls = join(d, 'calls.log');
  writeFileSync(join(d, 'gh'), `#!${process.execPath}
const a = process.argv.slice(2), fs = require('node:fs'); fs.appendFileSync(${JSON.stringify(calls)}, a.join(' ') + '\\n');
if (${fail}) { console.error('HTTP 403: Resource not accessible'); process.exit(1); }
const url = new URL('https://x/' + a[1]), ref = url.searchParams.get('ref'), type = url.searchParams.get('activity_type');
const since = /timestamp >= "([^"]+)"/.exec(a[a.indexOf('--jq') + 1])[1];
for (const e of ${JSON.stringify(events)}) if (e.ref === ref && e.activity_type === type && e.timestamp >= since) console.log(e.timestamp + ' ' + type + ' ' + e.ref + ' by ' + e.actor);
`); chmodSync(join(d, 'gh'), 0o755); return { d, calls, done: () => rmSync(d, { recursive: true, force: true }) };
}
const run = (s, args) => spawnSync('sh', [SH, ...args], { encoding: 'utf8', env: { ...process.env, PATH: [s.d, '/usr/bin', '/bin', dirname(process.execPath)].join(delimiter) } });
const EV = [
  { timestamp: '2026-10-18T04:33:29Z', activity_type: 'force_push', ref: 'refs/heads/main', actor: 'MacGuard' },
  { timestamp: '2026-10-28T12:00:00Z', activity_type: 'branch_deletion', ref: 'refs/heads/main', actor: 'someone' },
  { timestamp: '2026-10-28T13:00:00Z', activity_type: 'force_push', ref: 'refs/heads/feature', actor: 'dependabot[bot]' },
];

test('events inside the window are reported with time, kind, ref and actor, exit 1; events outside it, or on other refs, are not', () => {
  const s = shim(EV); try {
    const r = run(s, ['--since', '2026-10-28T00:00:00Z']); assert.equal(r.status, 1); assert.match(r.stdout, /2026-10-28T12:00:00Z branch_deletion refs\/heads\/main by someone/); assert.doesNotMatch(r.stdout, /2026-10-18|feature/);
    const all = run(s, ['--since', '2026-10-01T00:00:00Z']); assert.equal(all.status, 1); assert.match(all.stdout, /2026-10-18T04:33:29Z force_push refs\/heads\/main by MacGuard/);
  } finally { s.done(); }
});

test('a clean window is exit 0 and says which refs it covered; several refs can be asked at once', () => {
  const s = shim(EV); try {
    const r = run(s, ['--since', '2026-10-29T00:00:00Z']); assert.equal(r.status, 0); assert.match(r.stdout, /no force-push or deletion on: refs\/heads\/main since 2026-10-29T00:00:00Z/);
    const two = run(s, ['--since', '2026-10-28T00:00:00Z', '--ref', 'refs/heads/main', '--ref', 'refs/heads/feature']); assert.equal(two.status, 1); assert.match(two.stdout, /feature by dependabot/);
  } finally { s.done(); }
});

test('if the question cannot be answered the exit is 2 and the message says so: an API failure is never reported as "no events"', () => {
  const s = shim(EV, { fail: true }); try {
    const r = run(s, ['--since', '2026-10-29T00:00:00Z']); assert.equal(r.status, 2); assert.match(r.stderr, /could not query the activity/); assert.doesNotMatch(r.stdout, /no force-push/);
  } finally { s.done(); }
});

test('bad input is refused before any request (malformed date, refs that could smuggle query parameters or shell), and the script only ever issues GET reads', () => {
  const s = shim(EV); try {
    for (const args of [['--since', 'yesterday'], ['--since', '2026-10-28'], ['--ref', 'main'], ['--ref', 'refs/heads/main&per_page=1'], ['--ref', 'refs/heads/x;rm -rf /'], ['--bogus']]) { const r = run(s, args); assert.equal(r.status, 2, args.join(' ')); }
    let calls = ''; try { calls = readFileSync(s.calls, 'utf8'); } catch { /* no calls at all */ }
    assert.equal(calls, '', 'nothing was sent for refused input');
    run(s, ['--since', '2026-10-28T00:00:00Z']); const sent = readFileSync(s.calls, 'utf8').trim().split('\n');
    assert.ok(sent.every((l) => l.startsWith('api repos/MacGuard/macguard-yara-channel/activity?') && !/ -X |--method|--input|-f |-F /.test(l)), 'only `gh api <GET url> --jq`: no method override, no body'); assert.equal(sent.length, 2, 'one query per activity type');
  } finally { s.done(); }
});
