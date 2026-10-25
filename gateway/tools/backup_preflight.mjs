// Go / no-go for the first real copy and restore. READ-ONLY and OFFLINE by default: it reads the local backup directory, the public kit and (optionally) a file of key capabilities, and it never uploads, deletes or decrypts anything.
// It checks what can be checked BEFORE a first write: the ciphertext and manifest are intact, the age header addresses one recipient, the signed anchor and its chain verify with the trusted key, the recipient is the one in the kit
// (and, if you give the identity FILE, that the identity matches it), each destination is fully described, the keys' capabilities do what is needed and no more, and what the first sync will cost. The things only a person can supply
// are listed as NOT_RUN: write permission can only be proven by the first PUT; a restore needs the identity.
//   node tools/backup_preflight.mjs --root DIR [--stamp S] [--trust-key PUBKEY_OR_FILE] [--kit FILE] [--identity FILE] [--capabilities FILE] [--checkpoint-dir D1,D2]
// Exit: 0 GO (no FAIL; every NOT_RUN is a stated human step), 1 NO_GO, 2 usage.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DEFAULT_CONFIG, PROVIDERS, loadCheckpoint } from './backup_objstore.mjs';
import { anchorFiles, verifyAnchor, verifyChain } from './backup_anchor.mjs';

const STAMP = /^\d{8}T\d{6}Z$/, sha = (b) => createHash('sha256').update(b).digest('hex'), LIMITS = JSON.parse(readFileSync(new URL('../environments/provider-limits.json', import.meta.url), 'utf8'));
const FILES = ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS'];

export function ageStanzas(buf) {
  const head = buf.subarray(0, 4096).toString('latin1').split('\n'); if (head[0] !== 'age-encryption.org/v1') return null;
  const out = []; for (const l of head.slice(1)) { if (l.startsWith('---')) return out; if (l.startsWith('-> ')) out.push(l.slice(3).split(' ')[0]); }
  return null;
}
const publicKeyOf = (v) => (v && existsSync(v) ? readFileSync(v, 'utf8').trim().split('\n')[0] : v);
const kitField = (kit, head) => { const L = kit.split('\n'), i = L.findIndex((l) => l.startsWith(head)); return i >= 0 ? (L[i + 1] ?? '').trim() : null; };

export function preflight({ root, stamp = null, trustKey = null, sigstore = null, ed25519MaxSequence = null, kit = null, identity = null, capabilities = null, checkpointDirs = [], config = DEFAULT_CONFIG, env = process.env, ageKeygen = 'age-keygen' }) {
  root = resolve(root); const checks = [], add = (id, state, detail, extra = {}) => checks.push({ id, state, detail, ...extra });
  const stamps = existsSync(root) ? readdirSync(root).filter((n) => STAMP.test(n)).sort() : [], encrypted = stamps.filter((s) => existsSync(join(root, s, 'd1-export.sql.age'))), skipped = stamps.filter((s) => !encrypted.includes(s));
  const chosen = stamp ?? encrypted.at(-1); if (!chosen || !encrypted.includes(chosen)) { add('candidate', 'FAIL', 'no encrypted backup to send'); return finish(checks); }
  const dir = join(root, chosen), files = Object.fromEntries(FILES.filter((f) => existsSync(join(dir, f))).map((f) => [f, readFileSync(join(dir, f))]));
  add('candidate', 'PASS', `stamp ${chosen}; plaintext stamps that will never be sent: ${skipped.length ? skipped.join(', ') : 'none'}`);
  // integrity of the three files against each other
  const miss = FILES.filter((f) => !files[f]); if (miss.length) add('integrity', 'FAIL', 'missing ' + miss.join(', '));
  else {
    const sums = Object.fromEntries(files['SHA256SUMS'].toString().trim().split('\n').map((l) => { const [h, n] = l.split(/\s+/); return [n, h]; })), bad = ['d1-export.sql.age', 'manifest.json'].filter((f) => sums[f] !== sha(files[f]));
    let m; try { m = JSON.parse(files['manifest.json'].toString()); } catch { m = null; }
    if (bad.length) add('integrity', 'FAIL', 'SHA256SUMS does not match: ' + bad.join(', '));
    else if (!m || m.encrypted !== true) add('integrity', 'FAIL', 'the manifest does not say the export is encrypted');
    else if (m.stored_sha256 && m.stored_sha256 !== sha(files['d1-export.sql.age'])) add('integrity', 'FAIL', 'the manifest names a different ciphertext hash');
    else add('integrity', 'PASS', `ciphertext ${files['d1-export.sql.age'].length} bytes, manifest and checksums agree; created ${m.created_at ?? 'unknown'}`);
  }
  // who can decrypt: the number and kind of recipient stanzas in the age header (it cannot name the recipient without the identity)
  const st = files['d1-export.sql.age'] ? ageStanzas(files['d1-export.sql.age']) : null;
  if (!st) add('age_header', 'FAIL', 'the file is not an age file');
  else { const real = st.filter((t) => !/grease/i.test(t)); add('age_header', real.length === 1 && real[0] === 'X25519' ? 'PASS' : 'FAIL', `recipient stanzas: ${real.join(', ') || 'none'}${real.length === 1 && real[0] === 'X25519' ? ' (one X25519 recipient; no passphrase or SSH-key stanza that would let someone else decrypt)' : ''}`); }
  // recipient identity
  const recFile = join(root, 'recipient.txt'), rec = existsSync(recFile) ? readFileSync(recFile, 'utf8').trim() : null, kitText = kit && existsSync(kit) ? readFileSync(kit, 'utf8') : null, kitRec = kitText ? kitField(kitText, 'AGE RECIPIENT') : null;
  if (kitRec && rec) add('recipient_vs_kit', kitRec === rec ? 'PASS' : 'FAIL', kitRec === rec ? 'recipient.txt equals the recipient in the kit' : 'recipient.txt is NOT the recipient in the kit: the backups may be encrypted to a key the kit does not describe'); else add('recipient_vs_kit', 'NOT_RUN', 'needs recipient.txt and --kit');
  if (identity && (rec || kitRec)) { let y = null; try { y = execFileSync(ageKeygen, ['-y', identity], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { /* reported below */ } add('identity_matches_recipient', y && y === (rec ?? kitRec) ? 'PASS' : 'FAIL', y ? (y === (rec ?? kitRec) ? 'the identity file corresponds to the recipient (nothing was decrypted or printed)' : 'the identity file does NOT correspond to the recipient') : 'could not derive a public key from that file'); }
  else add('identity_matches_recipient', 'NOT_RUN', 'give --identity (a file path) to check that the key you hold matches the recipient; a real restore is a separate step');
  // signed anchor, chain and (optionally) the external checkpoint
  const pk = publicKeyOf(trustKey);
  if (!pk) { add('anchor', 'NOT_RUN', 'no trusted public key given: authenticity is not checked'); }
  else if (!anchorFiles((f) => existsSync(join(dir, f))).every((f) => existsSync(join(dir, f)))) add('anchor', 'FAIL', 'this backup has no signed anchor; sign it first');
  else {
    const all = Object.fromEntries([...FILES, ...anchorFiles((f) => existsSync(join(dir, f)))].map((f) => [f, readFileSync(join(dir, f))])), v = verifyAnchor({ files: all, publicKey: pk, expectedStamp: chosen, sigstore, ed25519MaxSequence });
    add('anchor', v.ok ? 'PASS' : 'FAIL', v.ok ? `signed by the trusted ${v.scheme === 'sigstore' ? 'Sigstore workflow identity' : 'key'}; sequence ${v.anchor.sequence}` : v.reason);
    const anchored = encrypted.filter((s) => anchorFiles((f) => existsSync(join(root, s, f))).every((f) => existsSync(join(root, s, f)))), chain = verifyChain(anchored.map((s) => readFileSync(join(root, s, 'ANCHOR.json'))));
    add('anchor_chain', chain.ok ? 'PASS' : 'FAIL', chain.ok ? `${anchored.length} anchored backups form an unbroken chain` : chain.reason);
    if (checkpointDirs.length) { const cp = loadCheckpoint(checkpointDirs, pk, { sigstore, ed25519MaxSequence }); add('checkpoint', !cp.ok ? 'FAIL' : v.ok && v.anchor.sequence < cp.checkpoint.sequence ? 'FAIL' : 'PASS', !cp.ok ? cp.reason : `external checkpoint: sequence ${cp.checkpoint.sequence}${cp.stale ? ' (stale)' : ''}`); }
    else add('checkpoint', 'NOT_RUN', 'no external checkpoint given: REQUIRED, because a rollback of every provider could not be excluded without it');
  }
  // destinations: described, and which credential variables exist (names only, never values)
  for (const n of PROVIDERS) { const d = config.destinations[n]; if (!d?.bucket || !/^https:\/\//.test(d.endpoint ?? '')) { add(`destination_${n}`, 'FAIL', 'bucket or https endpoint missing'); continue; } add(`destination_${n}`, 'PASS', `bucket ${d.bucket}; credentials in the environment: ${env[d.key_id_env] && env[d.secret_env] ? 'present' : 'absent'} (names ${d.key_id_env}/${d.secret_env}; values never read here)`); }
  // key capabilities: least privilege for the key that will write
  if (capabilities && existsSync(capabilities)) {
    const caps = JSON.parse(readFileSync(capabilities, 'utf8'));
    for (const n of PROVIDERS) { const keys = caps[n]; if (!Array.isArray(keys)) { add(`permissions_${n}`, 'NOT_RUN', 'no capability data for this provider: write permission is proven only by the first PUT'); continue; }
      const writers = keys.filter((k) => k.capabilities.includes('writeFiles') || k.capabilities.includes('Object Read & Write') || k.capabilities.includes('write'));
      const wide = writers.filter((k) => k.capabilities.some((c) => /deleteFiles|bypassGovernance|deleteKeys|writeKeys|delete/.test(c)) || !k.bucket_scoped);
      add(`permissions_${n}`, !writers.length ? 'FAIL' : wide.length === writers.length ? 'WARN' : 'PASS', !writers.length ? 'no key can write to the bucket' : `${writers.length} key(s) can write: ${writers.map((k) => k.name + (k.bucket_scoped ? '' : ' [NOT bucket-scoped]') + (k.capabilities.some((c) => /delete|bypassGovernance/.test(c)) ? ' [can delete/bypass retention]' : '')).join('; ')}${wide.length ? ' - use a key limited to this bucket without delete or retention-bypass for the sync' : ''}`); }
  } else for (const n of PROVIDERS) add(`permissions_${n}`, 'NOT_RUN', 'no capability data given: write permission is proven only by the first PUT');
  // cost of the first sync and a month of keeping it
  const bytes = FILES.reduce((s, f) => s + (files[f]?.length ?? 0), 0) + anchorFiles((f) => existsSync(join(dir, f))).reduce((s, f) => s + (existsSync(join(dir, f)) ? readFileSync(join(dir, f)).length : 0), 0), objects = FILES.length + (anchorFiles((f) => existsSync(join(dir, f))).every((f) => existsSync(join(dir, f))) ? 2 : 0), gb = bytes / 1e9;
  const cost = { b2: Math.max(0, gb - LIMITS.providers.b2.free_storage_gb) * LIMITS.providers.b2.storage_usd_per_gb_month, r2: Math.max(0, gb - LIMITS.providers.r2.free_storage_gb) * LIMITS.providers.r2.storage_usd_per_gb_month, scaleway: Math.max(1, gb) * LIMITS.providers.scaleway.storage_eur_per_gb_month };
  add('cost', 'INFO', `${objects} objects, ${bytes} bytes per destination. One month of storage: B2 ${cost.b2.toFixed(4)} USD (inside the free 10 GB), R2 ${cost.r2.toFixed(4)} USD (inside the free 10 GB), Scaleway about ${cost.scaleway.toFixed(3)} EUR (billed per started GB-hour; no free storage). Requests: ${objects} writes and about ${objects * 3} reads per destination for sync, verify and a drill, inside every free allowance read on ${LIMITS.read_on}.`, { prices_read_on: LIMITS.read_on });
  add('write_permission', 'NOT_RUN', 'cannot be proven without writing: the first sync is the proof; keys are write-once and nothing is deleted');
  add('real_restore', 'NOT_RUN', 'needs the age identity file from the owner; run `drill --identity FILE --trust-key …` after the sync');
  return finish(checks);
}
// GO needs these to PASS, not merely to be absent: a copy whose authenticity, integrity or recipient was not checked is not ready to be sent.
const REQUIRED = ['candidate', 'integrity', 'age_header', 'anchor', 'anchor_chain', 'checkpoint', 'recipient_vs_kit', 'destination_b2', 'destination_scaleway', 'destination_r2'];
function finish(checks) {
  const fail = checks.filter((c) => c.state === 'FAIL'), warn = checks.filter((c) => c.state === 'WARN'), by = Object.fromEntries(checks.map((c) => [c.id, c.state])), unmet = REQUIRED.filter((id) => by[id] !== 'PASS');
  return { verdict: fail.length || unmet.length ? 'NO_GO' : 'GO', failures: fail.map((c) => c.id), required_not_passed: unmet, warnings: warn.map((c) => c.id), human_steps: checks.filter((c) => c.state === 'NOT_RUN' && !REQUIRED.includes(c.id)).map((c) => c.id), checks };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
  if (!arg('--root')) { console.error('usage: backup_preflight.mjs --root DIR [--stamp S] [--trust-key …] [--kit FILE] [--identity FILE] [--capabilities FILE] [--checkpoint-dir D1,D2]'); process.exit(2); }
  const r = preflight({ root: arg('--root'), stamp: arg('--stamp'), trustKey: arg('--trust-key'), kit: arg('--kit'), identity: arg('--identity'), capabilities: arg('--capabilities'), checkpointDirs: (arg('--checkpoint-dir') ?? '').split(',').filter(Boolean), sigstore: arg('--sigstore-identity') ? { identity: arg('--sigstore-identity'), repository: arg('--sigstore-repo'), trustedRoot: arg('--trusted-root') } : null, ed25519MaxSequence: arg('--ed25519-max-sequence') != null ? +arg('--ed25519-max-sequence') : null });
  console.log(JSON.stringify(r, null, 1)); process.exit(r.verdict === 'GO' ? 0 : 1);
}
