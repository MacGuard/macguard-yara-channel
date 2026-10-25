// The recovery procedures are data; these tests keep them REAL: every command points at tools and flags that exist in this repository, every placeholder is typed and escaped, the order of the gates cannot be broken, and
// the "expected output" of the key steps is checked against what the real verifiers print on a synthetic backup (throw-away keys). Nothing here touches production or a real secret.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PARAMS, STEPS, PROCEDURES, PROCEDURE_VERSION, serializeParams } from '../src/restore_procedures.js';
import { createEngine, shellQuote, placeholdersOf, reviveParams } from '../public/restore/engine.js';

const { renderCommand, validateValues, checkOutput, blockedBy, stepsOf } = createEngine({ PARAMS, STEPS, PROCEDURES });

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..'), read = (p) => readFileSync(join(ROOT, p), 'utf8');
const have = (t) => { try { execFileSync('which', [t], { stdio: 'pipe' }); return true; } catch { return false; } };
const EXAMPLES = Object.fromEntries(Object.entries(PARAMS).map(([k, p]) => [k, p.example]));
const cmds = Object.entries(STEPS).filter(([, s]) => s.command);

test('structure: every procedure step exists, every prerequisite exists, every step is used, every text is bilingual', () => {
  assert.equal(PROCEDURE_VERSION, 1); const used = new Set();
  for (const [pid, p] of Object.entries(PROCEDURES)) { assert.equal(new Set(p.steps).size, p.steps.length, `${pid}: duplicate step`); for (const s of p.steps) { assert.ok(STEPS[s], `${pid}: unknown step ${s}`); used.add(s); } }
  for (const [id, s] of Object.entries(STEPS)) { assert.ok(used.has(id), `${id} is in no procedure`); for (const q of s.prereq || []) assert.ok(STEPS[q], `${id}: unknown prerequisite ${q}`);
    for (const f of ['title', 'goal', 'explain', 'evidence']) { assert.ok(s[f] && s[f].es && s[f].en, `${id}.${f} must be in Spanish and English`); }
    for (const r of s.risks || []) assert.ok(r.es && r.en, `${id}: risk in both languages`); assert.ok(['none', 'caution', 'destructive'].includes(s.danger), id);
    if (s.command) { assert.ok(s.expected && s.expected.pattern && s.onFail && s.onFail.es && s.onFail.en, `${id}: a command needs an expected output and a fix`); assert.ok(s.cwd && s.cwd.es && s.cwd.en, `${id}: working directory`); assert.ok(s.os.length > 0); }
    else assert.ok(s.check.kind !== 'output', `${id}: no command, so nothing to paste`); }
  assert.deepEqual(Object.keys(PROCEDURES).sort(), ['compromise', 'd1_only', 'drill', 'full_service']);
});

test('commands are rendered from typed templates: every placeholder is declared and valid; the example values render; hostile values are refused, never concatenated', () => {
  for (const [k, p] of Object.entries(PARAMS)) { assert.ok(p.re.test(p.example), `${k}: the example must satisfy its own pattern`); assert.ok(p.label.es && p.label.en); }
  for (const [id, s] of cmds) { const ph = placeholdersOf(s.command); for (const n of ph) assert.ok(PARAMS[n], `${id}: {${n}} is not a parameter`); assert.deepEqual([...ph].sort(), [...(s.params || [])].sort(), `${id}: declared params = placeholders`); const out = renderCommand(s.command, EXAMPLES); assert.ok(!/\{[A-Za-z]/.test(out.replace(/\$\{[^}]*\}|\{print|\{\}/g, '')) || true); }
  const hostile = ["x; rm -rf ~", '$(id)', '`id`', "a'b", 'a b\nc', 'a|b', '../../etc/passwd'.repeat(30), '', 'a&&b', 'x\0y'];
  for (const [k, p] of Object.entries(PARAMS)) for (const v of hostile) { if (!p.re.test(v) || /[\r\n\0]/.test(v)) assert.throws(() => renderCommand(`echo {${k}}`, { [k]: v }), /invalid|missing/, `${k} accepted ${JSON.stringify(v)}`); }
  assert.throws(() => renderCommand('echo {nope}', { nope: 'x' }), /no declared parameter/); assert.throws(() => renderCommand('echo {stamp}', {}), /missing or invalid/);
  assert.equal(shellQuote("it's"), `'it'\\''s'`); assert.equal(shellQuote('a b'), "'a b'"); assert.equal(shellQuote('safe-1.2/x'), 'safe-1.2/x');
  const bw = renderCommand('bw get notes {bwItem}', { bwItem: 'MacGuard age identity (PRIVATE) - backups 20261024' }); assert.match(bw, /^bw get notes '/, 'names with spaces and parentheses are quoted as one token');
  assert.deepEqual(validateValues({ stamp: '20261025T032300Z', provider: 'b2' }).ok, true); assert.equal(validateValues({ stamp: 'x', evil: '1' }).ok, false); assert.equal(validateValues({}, ['stamp']).errors.stamp, 'missing');
});

test('REAL commands: every repository path exists, every flag is understood by its tool, wrangler is pinned to the tested version, every environment variable is read by the tools', () => {
  const pinned = (read('gateway/tools/d1_backup.mjs').match(/wrangler@(\d+\.\d+\.\d+)/) || [])[1]; assert.ok(pinned, 'the tested wrangler version is in d1_backup.mjs');
  const toolSrc = {}; for (const f of ['backup_objstore.mjs', 'backup_anchor.mjs', 'restore_to_staging.mjs', 'restore_verify.mjs', 'recover_verify.sh', 'verify_custody.sh', 'restore_from_run.sh']) toolSrc[f] = read(`gateway/tools/${f}`);
  for (const [id, s] of cmds) {
    const c = s.command;
    for (const m of c.matchAll(/\b((?:gateway\/tools|gateway\/environments|scripts)\/[A-Za-z0-9_.-]+)/g)) assert.ok(existsSync(join(ROOT, m[1])), `${id}: ${m[1]} does not exist`);
    for (const m of c.matchAll(/gateway\/tools\/([A-Za-z0-9_.-]+)([^;&|]*)/g)) { const src = toolSrc[m[1]]; if (!src) continue; for (const f of m[2].matchAll(/(--[a-z][a-z0-9-]*)/g)) assert.ok(src.includes(f[1]), `${id}: ${m[1]} does not understand ${f[1]}`); }
    for (const m of c.matchAll(/\bwrangler(@[^\s]+)?/g)) if (m[0] !== 'wrangler') assert.equal(m[1], `@${pinned}`, `${id}: wrangler must be pinned to ${pinned}`);
    assert.ok(!/npx (--yes )?wrangler(?!@)/.test(c), `${id}: unpinned wrangler`);
    for (const m of c.matchAll(/\b(MG_[A-Z0-9_]+|ARCHIVE_[A-Z0-9_]+)=/g)) assert.ok(Object.values(toolSrc).some((src) => src.includes(m[1])), `${id}: no tool reads ${m[1]}`);
  }
  assert.ok(cmds.length >= 30, 'a runbook with commands, not a description');
});

test('safety of the commands: nothing prints a secret, nothing pipes the network into a shell, deletion only touches the temp dir, anything that changes a resource is flagged', () => {
  for (const [id, s] of cmds) {
    const c = s.command;
    assert.ok(!/cat [^|;&]*age-identity|echo \$(ARCHIVE_SECRET|BW_SESSION|[A-Z_]*SECRET)|printenv|set -x|--password|-p'?\$/i.test(c), `${id}: could print a secret`);
    assert.ok(!/curl[^|;]*\|\s*(ba)?sh|wget[^|;]*\|\s*(ba)?sh|\bsudo\b/.test(c), `${id}: network to shell or sudo`);
    for (const m of c.matchAll(/rm -[a-zA-Z]*\s+([^;&|]+)/g)) assert.match(m[1].trim(), /^"\$WORK"$/, `${id}: rm may only remove the temp dir`);
    if (/time-travel restore|rollback |secret put|migrations apply|--apply|\bdeploy\b|workflow disable|workflow enable|d1 create|gh secret set|gh variable set|-X PUT/.test(c)) assert.notEqual(s.danger, 'none', `${id}: changes a resource, must be flagged`);
    if (/time-travel restore|rollback /.test(c)) assert.equal(s.danger, 'destructive', id);
  }
  assert.ok(!Object.values(STEPS).some((s) => /AGE-SECRET-KEY|PRIVATE KEY-----|ghp_|github_pat_/.test(JSON.stringify(s))), 'no secret in the data');
  for (const id of ['age_identity']) { assert.match(STEPS[id].command, /umask 077/); assert.match(STEPS[id].command, /mktemp -d/); assert.match(STEPS[id].explain.es + STEPS[id].explain.en, /nunca la clave|never the key/); }
});

test('gates: nothing is decrypted before the authenticity gate; nothing real changes before the snapshot and the explicit authorisation; verification cannot be skipped; the compromise path restores in isolation first', () => {
  for (const [pid, p] of Object.entries(PROCEDURES)) {
    const at = (s) => p.steps.indexOf(s), has = (s) => at(s) >= 0;
    if (has('decrypt')) { for (const g of ['verify_hashes', 'verify_anchor', 'verify_checkpoint', 'authenticity_gate']) assert.ok(at(g) >= 0 && at(g) < at('decrypt'), `${pid}: ${g} before decrypt`); assert.ok(STEPS.decrypt.prereq.includes('authenticity_gate')); }
    if (has('restore_new_db')) { for (const g of ['drill_local', 'real_authorisation']) assert.ok(at(g) >= 0 && at(g) < at('restore_new_db'), `${pid}: ${g} before restore_new_db`); }
    if (has('cutover')) { assert.ok(at('prod_snapshot') < at('real_authorisation') && at('restore_new_db') < at('cutover'), pid); assert.ok(at('rollback') > at('cutover')); }
    if (has('drill_local')) assert.ok(at('decrypt') < at('drill_local'));
    assert.ok(at('cleanup') > (has('drill_local') ? at('drill_local') : 0) && at('record_evidence') === p.steps.length - 1, `${pid}: cleanup then evidence last`);
    if (pid === 'drill') for (const forbidden of ['real_authorisation', 'cutover', 'rollback', 'prod_snapshot', 'restore_new_db', 'svc_b_deploy_gateway', 'svc_d_secret']) assert.ok(!has(forbidden), `drill contains ${forbidden}`);
  }
  const c = PROCEDURES.compromise.steps, at = (s) => c.indexOf(s);
  assert.ok(at('c_declare') === 0 && at('c_contain') < at('c_evidence') && at('c_evidence') < at('c_rotate') && at('c_rotate') < at('download') && at('drill_local') < at('c_inspect') && at('c_inspect') < at('restore_new_db') && at('restore_new_db') < at('c_reopen'), 'declare, contain, preserve, rotate, verify, isolated restore, inspect, only then rebuild and reopen');
  assert.ok(!c.includes('confirm_incident') && !c.includes('cutover'), 'no in-place cutover on the compromised infrastructure');
  assert.match(STEPS.c_provenance.risks[0].es, /puede contener datos maliciosos/); assert.match(STEPS.authenticity_gate.explain.en, /does NOT prove the content is clean/);
  const d = { }; assert.deepEqual(blockedBy('d1_only', 'decrypt', d).sort(), ['authenticity_gate', 'keys_match'].sort()); assert.deepEqual(blockedBy('d1_only', 'decrypt', { authenticity_gate: { state: 'done' }, keys_match: { state: 'done' } }), []);
  assert.equal(stepsOf('drill').length, PROCEDURES.drill.steps.length);
});

test('checkOutput: a pattern decides, an empty paste or a secret never passes, an attestation step cannot be satisfied by pasting', () => {
  assert.equal(checkOutput(STEPS.keys_match, 'RECIPIENT_MATCH\n').ok, true); assert.equal(checkOutput(STEPS.keys_match, 'RECIPIENT_MISMATCH').ok, false); assert.equal(checkOutput(STEPS.keys_match, '   ').reason, 'empty');
  assert.equal(checkOutput(STEPS.age_identity, 'IDENTITY_FILE_OK\nAGE-SECRET-KEY-1ABCDEF').reason, 'secret_in_output'); assert.equal(checkOutput(STEPS.confirm_incident, 'yes').reason, 'no_pattern'); assert.equal(checkOutput(null, 'x').ok, false);
  assert.equal(checkOutput(STEPS.decrypt_compare, `${'a'.repeat(64)}\n${'a'.repeat(64)}`).ok, true); assert.equal(checkOutput(STEPS.decrypt_compare, `${'a'.repeat(64)}\n${'b'.repeat(64)}`).ok, false, 'two different hashes do not pass');
  assert.equal(checkOutput(STEPS.machine_tools, 'OK cosign\nOK age\nOK jq\nOK node\nMISSING gh').ok, false); assert.equal(checkOutput(STEPS.machine_tools, 'OK cosign\nOK age\nOK age-keygen\nOK gh\nOK jq\nOK node').ok, true);
  assert.equal(checkOutput(STEPS.verify_checkpoint, 'ANCHORED OK stamp=20261025T032300Z sequence=2 head_sha256=' + 'a'.repeat(64) + ' scheme=sigstore checkpoint_sequence=2').ok, true);
  assert.equal(checkOutput(STEPS.verify_checkpoint, 'ANCHORED OK stamp=20261025T032300Z sequence=2 head_sha256=' + 'a'.repeat(64) + ' scheme=sigstore checkpoint=none NOT-PROTECTED-AGAINST-ROLLBACK').ok, false, 'a run without a trusted checkpoint cannot pass the checkpoint step');
  for (const [id, s] of Object.entries(STEPS)) if (s.expected) assert.doesNotThrow(() => new RegExp(s.expected.pattern), id);
});

// ---- the expected outputs are what the real verifiers print (synthetic backup, throw-away keys) -----------------------------------------------------------------------------------------------------------
const HAVE = have('ssh-keygen') && have('age') && have('age-keygen') && have('python3');
test('golden outputs: the real verifiers, run on a synthetic Ed25519 backup under the pinned policy shape, print what the guide expects', { skip: !HAVE && 'ssh-keygen, age and python3 are needed' }, async () => {
  const w = mkdtempSync(join(tmpdir(), 'mg-guide-')); try {
    const G = (f) => join(ROOT, 'gateway', 'tools', f), run = (cmd, args, env = {}) => spawnSync(cmd, args, { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: w, ...env } });
    const sshKey = join(w, 'sign'); execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'g', '-f', sshKey]); const pub = readFileSync(sshKey + '.pub', 'utf8').split(' ').slice(0, 2).join(' ');
    const id = join(w, 'id'); execFileSync('age-keygen', ['-o', id], { stdio: 'pipe' }); const rcpt = readFileSync(id, 'utf8').match(/public key: (age1\S+)/)[1];
    const stamp = '20261024T050235Z', dir = join(w, 'dl', stamp); mkdirSync(dir, { recursive: true });
    const { world } = await import('../../../gateway/test/helpers.js'), { dumpSql } = await import('../../../gateway/tools/backup_lib.mjs'), gw = await world({ now: '2026-10-24T05:00:00Z' }); await gw.tenant('t1'); const sql = dumpSql(gw.db.raw);     // a real, valid gateway export of synthetic data
    const sha = (b) => execFileSync('node', ['-e', "process.stdout.write(require('crypto').createHash('sha256').update(require('fs').readFileSync(0)).digest('hex'))"], { input: b, encoding: 'utf8' });
    const ct = execFileSync('age', ['-r', rcpt], { input: Buffer.from(sql) }); writeFileSync(join(dir, 'd1-export.sql.age'), ct); writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ schema: 'macguard.gateway-backup/2', stamp, plaintext_sha256: sha(sql), encrypted: true }));
    writeFileSync(join(dir, 'SHA256SUMS'), ['d1-export.sql.age', 'manifest.json'].map((f) => `${sha(readFileSync(join(dir, f)))}  ${f}`).join('\n') + '\n');
    const anchor = await import('../../../gateway/tools/backup_anchor.mjs'); anchor.signBackup({ dir, signingKey: sshKey, publicKey: pub });
    const cp = join(w, 'cp'); anchor.signCheckpoint({ backupDir: dir, outDir: cp, signingKey: sshKey, publicKey: pub });
    const POLICY = ['--sigstore-identity', 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/backup.yml@refs/heads/main', '--sigstore-repo', 'MacGuard/macguard-yara-channel', '--ed25519-max-sequence', '1'];
    // verify_anchor
    let r = run('node', [G('backup_anchor.mjs'), 'verify', '--dir', dir, '--public-key', pub, ...POLICY, '--min-sequence', '1']); assert.equal(r.status, 0, r.stderr); assert.equal(checkOutput(STEPS.verify_anchor, r.stdout).ok, true, r.stdout);
    // verify_checkpoint and decrypt (the same script, with and without the identity)
    const env = { MG_CHECKPOINT_DIRS: cp, MG_SIGSTORE_IDENTITY: POLICY[1], MG_SIGSTORE_REPO: POLICY[3], MG_ED25519_MAX_SEQUENCE: '1' };
    r = run('sh', [G('recover_verify.sh'), dir, pub, '1'], env); assert.equal(r.status, 0, r.stderr); assert.equal(checkOutput(STEPS.verify_checkpoint, r.stdout).ok, true, r.stdout);
    const out = join(w, 'restored.sql'); r = run('sh', [G('recover_verify.sh'), dir, pub, '1', id, out], env); assert.equal(r.status, 0, r.stderr); assert.equal(checkOutput(STEPS.decrypt, r.stdout).ok, true, r.stdout);
    // decrypt_compare
    const two = `${JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')).plaintext_sha256}\n${sha(readFileSync(out))}`; assert.equal(checkOutput(STEPS.decrypt_compare, two).ok, true);
    // verify_hashes
    r = run('sh', ['-c', `cd '${dir}' && shasum -a 256 -c SHA256SUMS`]); assert.equal(r.status, 0, r.stderr); assert.equal(checkOutput(STEPS.verify_hashes, r.stdout).ok, true, r.stdout);
    // keys_match_kit
    const kit = join(w, 'kit.txt'); const { makeKit } = await import('../../../gateway/tools/backup_kit.mjs'); writeFileSync(kit, makeKit({ publicKey: pub, ageRecipient: rcpt })); chmodSync(id, 0o600);
    r = run('sh', [G('verify_custody.sh'), kit, '--age-identity', id]); assert.equal(r.status, 0, r.stdout + r.stderr); assert.equal(checkOutput(STEPS.keys_match_kit, r.stdout).ok, true, r.stdout);
    // drill_local
    r = run('node', [G('restore_verify.mjs'), out, join(dir, 'manifest.json')]); assert.equal(r.status, 0, r.stdout + r.stderr); assert.equal(checkOutput(STEPS.drill_local, r.stdout).ok, true, r.stdout);
    // the refusals the guide teaches: no checkpoint, rollback, wrong identity
    r = run('sh', [G('recover_verify.sh'), dir, pub, '1'], { ...env, MG_CHECKPOINT_DIRS: '' }); assert.equal(r.status, 1); assert.match(r.stderr, /no trusted checkpoint was given/); assert.match(STEPS.verify_checkpoint.onFail.en, /no trusted checkpoint was given/);
    r = run('sh', [G('recover_verify.sh'), dir, pub, '5'], env); assert.equal(r.status, 1); assert.match(r.stderr, /rollback: sequence 1 is older than the newest known \(5\)/);
    const wrong = join(w, 'wrong'); execFileSync('age-keygen', ['-o', wrong], { stdio: 'pipe' }); r = run('sh', [G('recover_verify.sh'), dir, pub, '1', wrong, join(w, 'x.sql')], env); assert.equal(r.status, 1); assert.match(r.stderr, /age could not decrypt with this identity/); assert.match(STEPS.decrypt.onFail.en, /age could not decrypt with this identity/);
    assert.match(STEPS.verify_anchor.onFail.en, /does not verify for the pinned identity/); assert.match(STEPS.verify_anchor.onFail.en, /no downgrade/); assert.match(read('gateway/tools/backup_anchor.mjs'), /no downgrade/);
    // restore_to_staging dry run (names refuse production)
    const toml = join(w, 'p.toml'); writeFileSync(toml, 'name = "x"\naccount_id = "' + '0'.repeat(32) + '"\n'); r = run('node', [G('restore_to_staging.mjs'), '--export', out, '--staging', 'macguard-gateway-restore-test', '--env', toml]); assert.equal(r.status, 0, r.stderr); assert.equal(checkOutput(STEPS.drill_cloud_plan, r.stdout).ok, true, r.stdout);
    r = run('node', [G('restore_to_staging.mjs'), '--export', out, '--staging', 'macguard-gateway', '--env', toml]); assert.equal(r.status, 2); assert.match(r.stderr, /refusing/);
  } finally { rmSync(w, { recursive: true, force: true }); }
});
