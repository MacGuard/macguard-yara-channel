// scripts/monitoring_setup.sh configures the monitor without any secret value in arguments or output, never turns the monitor on, and refuses to send a test message while a secret is missing.
// `gh` and `curl` are replaced by shims that record every argument they receive; nothing leaves this machine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const SCRIPT = new URL('../../../scripts/monitoring_setup.sh', import.meta.url).pathname, NAMES = ['CLOUDFLARE_ANALYTICS_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID'];
const FAKE_TOKEN = '123456789:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK';

function world({ have = [], variable = '' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'mg-setup-')), bin = join(root, 'bin'), state = join(root, 'secrets'), calls = join(root, 'calls.log'), curlStdin = join(root, 'curl.stdin'); mkdirSync(bin);
  writeFileSync(state, have.join('\n') + (have.length ? '\n' : '')); writeFileSync(calls, '');
  const shim = (name, body) => { writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`); chmodSync(join(bin, name), 0o755); };
  shim('gh', `echo "gh $*" >> "${calls}"
case "$1 $2" in
  "secret list") sed 's/$/\\tUpdated/' "${state}" ;;
  "secret set") echo "$3" >> "${state}" ;;
  "variable list") [ -n "${variable}" ] && printf 'USAGE_MONITOR_ENABLED\\t${variable}\\t2026-10-28\\n' ; true ;;
  "workflow run") : ;;
esac`);
  shim('curl', `echo "curl $*" >> "${calls}"; cat > "${curlStdin}"; echo '{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":424242,"type":"private"}}}]}'`);
  const run = (args, input = '') => spawnSync('sh', [SCRIPT, ...args], { env: { PATH: `${bin}:${process.env.PATH}`, MG_REPO: 'o/r', HOME: root }, input, encoding: 'utf8', timeout: 20000 });
  return { root, calls: () => readFileSync(calls, 'utf8'), curlStdin: () => (existsSync(curlStdin) ? readFileSync(curlStdin, 'utf8') : ''), state: () => readFileSync(state, 'utf8').split('\n').filter(Boolean), run, done: () => rmSync(root, { recursive: true, force: true }) };
}

test('status lists secret NAMES and the enable variable, says what is next, and only reads', () => {
  const w = world({ have: ['TELEGRAM_CHAT_ID'] }); try {
    const r = w.run(['status']); assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /MISSING\s+CLOUDFLARE_ANALYTICS_TOKEN/); assert.match(r.stdout, /present\s+TELEGRAM_CHAT_ID/); assert.match(r.stdout, /not set: the scheduled jobs stay skipped, state NOT_CONFIGURED/); assert.match(r.stdout, /next: sh scripts\/monitoring_setup.sh secrets/);
    assert.ok(w.calls().split('\n').filter(Boolean).every((l) => /^gh (secret|variable) list/.test(l)), 'status only lists');
  } finally { w.done(); }
  const w2 = world({ have: NAMES, variable: 'true' }); try { const r = w2.run(['status']); assert.match(r.stdout, /USAGE_MONITOR_ENABLED: true/); assert.match(r.stdout, /next: sh scripts\/monitoring_setup.sh test/); } finally { w2.done(); }
});

test('secrets asks gh for ONLY the missing ones, never with a value on the command line, and never touches the enable variable', () => {
  const w = world({ have: ['CLOUDFLARE_ACCOUNT_ID', 'TELEGRAM_CHAT_ID'] }); try {
    const r = w.run(['secrets']); assert.equal(r.status, 0, r.stderr);
    const sets = w.calls().split('\n').filter((l) => l.startsWith('gh secret set'));
    assert.deepEqual(sets, ['gh secret set CLOUDFLARE_ANALYTICS_TOKEN --env macguard-monitoring --repo o/r', 'gh secret set TELEGRAM_BOT_TOKEN --env macguard-monitoring --repo o/r'], 'exactly the missing two; no --body / -b / value argument');
    assert.deepEqual(w.state().sort(), [...NAMES].sort()); assert.match(r.stdout, /0 still missing/); assert.doesNotMatch(w.calls(), /variable set/);
  } finally { w.done(); }
});

test('telegram-chat reads the token silently, hands it to curl on STDIN (never in an argument or in the output) and prints only chat ids and types', () => {
  const w = world(); try {
    const r = w.run(['telegram-chat'], FAKE_TOKEN + '\n'); assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(w.calls(), /FAKEFAKE/, 'the token is in no argument of any command'); assert.match(w.calls(), /curl -sS -K -/);
    assert.match(w.curlStdin(), /api\.telegram\.org\/bot123456789:FAKE.*\/getUpdates/, 'the token travels on stdin'); assert.doesNotMatch(r.stdout + r.stderr, /FAKEFAKE/, 'and is never printed');
    assert.match(r.stdout, /424242/); assert.match(r.stdout, /private/);
  } finally { w.done(); }
  const w2 = world(); try { const r = w2.run(['telegram-chat'], '\n'); assert.equal(r.status, 1); assert.match(r.stdout + r.stderr, /no token given/); assert.equal(w2.calls().includes('curl'), false, 'no request without a token'); } finally { w2.done(); }
});

test('test refuses while any secret is missing (nothing is dispatched) and, with all four, dispatches ONE manual test_message run and never enables the monitor', () => {
  const w = world({ have: ['CLOUDFLARE_ANALYTICS_TOKEN', 'TELEGRAM_BOT_TOKEN'] }); try {
    const r = w.run(['test']); assert.equal(r.status, 1); assert.match(r.stdout + r.stderr, /refused: missing CLOUDFLARE_ACCOUNT_ID TELEGRAM_CHAT_ID/); assert.doesNotMatch(w.calls(), /workflow run/);
  } finally { w.done(); }
  const w2 = world({ have: NAMES }); try {
    const r = w2.run(['test']); assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(w2.calls().split('\n').filter((l) => l.startsWith('gh workflow run')), ['gh workflow run usage-monitor.yml --repo o/r --ref main -f test_message=true']);
    assert.doesNotMatch(w2.calls(), /variable set|USAGE_MONITOR_ENABLED=/, 'turning the monitor on stays a manual decision'); assert.match(r.stdout, /Check your phone/);
  } finally { w2.done(); }
});

test('no subcommand can set the enable variable or take a value from its arguments; an unknown subcommand exits 2', () => {
  const src = readFileSync(SCRIPT, 'utf8');
  assert.doesNotMatch(src.replace(/^#.*$/gm, ''), /variable set|--body|\s-b\s/, 'the script has no code path that sets the variable or passes a value'); assert.match(src, /It never sets USAGE_MONITOR_ENABLED/);
  const w = world(); try { const r = w.run(['status', '--value', 'SECRET']); assert.equal(r.status, 0); assert.doesNotMatch(r.stdout + w.calls(), /SECRET/, 'extra arguments are ignored, not used'); assert.equal(w.run(['bogus']).status, 2); } finally { w.done(); }
});
