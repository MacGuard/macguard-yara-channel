// Independent cryptographic anchor for backups. The checksums, the manifest and the ciphertext of a backup all live in the same bucket, and age encrypts to a PUBLIC key, so none of them can tell a genuine backup from a
// different one that someone with write access to a bucket made self-consistent. What can: a signature, by a key that is not in any bucket and not only on the Mac, over a small statement (ANCHOR.json) that pins the hash of
// every file of the backup, its sequence number and the hash of the previous statement.
//
//   signer      an ed25519 SSH key (ssh-keygen -Y sign, namespace "macguard-backup/1"): no new dependency, the verifier needs only the PUBLIC key line, the statement and the signature.
//   trust       the public key line (and the last sequence number you know) are kept OUTSIDE the buckets and OUTSIDE the Mac: in the recovery kit (docs/analytics/BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md), a password-manager note, a printout.
//   rollback    the sequence number grows by one per backup and each statement names the hash of the previous one, so an older genuine backup is refused when a newer one is known, a provider that serves an older head is
//               reported stale, two different statements with the same sequence are reported as equivocation, and a missing link in the chain is visible.
// This module never reads a private key into memory: ssh-keygen is given the key FILE. It prints nothing secret.
//   node tools/backup_anchor.mjs sign   --dir BACKUP_DIR --signing-key KEYFILE [--previous PREV_BACKUP_DIR] [--sequence N]
//   node tools/backup_anchor.mjs checkpoint --dir BACKUP_DIR --signing-key KEYFILE --out CHECKPOINT_DIR     the external statement "sequence N is the newest I confirmed"
//   node tools/backup_anchor.mjs verify-checkpoint --dir CHECKPOINT_DIR --public-key "ssh-ed25519 AAAA..." [--max-age-days N]
//   node tools/backup_anchor.mjs verify --dir BACKUP_DIR --public-key "ssh-ed25519 AAAA..." [--min-sequence N] [--principal NAME]
//   Sigstore keyless (every sequence after the Ed25519 freeze; add to verify / verify-checkpoint too):
//     --sigstore-identity https://github.com/OWNER/REPO/.github/workflows/backup.yml@refs/heads/main --sigstore-repo OWNER/REPO --ed25519-max-sequence N [--trusted-root FILE]
//   node tools/backup_anchor.mjs sign-sigstore --dir BACKUP_DIR --previous PREV_DIR --public-key "ssh-ed25519 ..." <sigstore flags>      (runs in GitHub Actions with id-token: write)
//   node tools/backup_anchor.mjs checkpoint-sigstore --dir BACKUP_DIR --out CHECKPOINT_DIR <sigstore flags>
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export const CHECKPOINT_NAMESPACE = 'macguard-backup-checkpoint/1', CHECKPOINT_SCHEMA = 'macguard.backup-checkpoint/1', CHECKPOINT_FILES = ['CHECKPOINT.json', 'CHECKPOINT.json.sig'];
export const NAMESPACE = 'macguard-backup/1', SCHEMA = 'macguard.backup-anchor/1', ANCHOR_FILES = ['ANCHOR.json', 'ANCHOR.json.sig'], PRINCIPAL = 'macguard-backup';
const BACKED = ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS'];
const sha = (b) => createHash('sha256').update(b).digest('hex'), iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

// ---- Sigstore keyless (the signer of every backup after the Ed25519 freeze) ----------------------------------------------------------------------------------------------------------
// A statement is signed by the GitHub Actions workflow itself: cosign asks Fulcio for a ~10 minute certificate whose identity is the workflow (repository, file and ref), signs, and records the signature in Rekor; the
// bundle (certificate + signature + inclusion proof) is the only artifact. Nothing permanent has to be protected. The verifier pins the EXACT identity (never a regexp), the issuer and the repository, and runs offline
// against the bundle (cosign needs the Sigstore trusted root, from its TUF cache or from `trustedRoot`). Policy: Ed25519 signs only sequences <= ed25519MaxSequence (the frozen, historical ones); every later sequence
// MUST carry a Sigstore bundle and an Ed25519 signature on it is refused, so a leaked old key cannot be used to downgrade.
export const SIGSTORE_ISSUER = 'https://token.actions.githubusercontent.com', ANCHOR_BUNDLE = 'ANCHOR.json.sigstore.json', CHECKPOINT_BUNDLE = 'CHECKPOINT.json.sigstore.json';
const IDENTITY = /^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml@refs\/heads\/[A-Za-z0-9._\/-]+$/, REPO = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
// Which two files form the signed anchor / checkpoint of a directory or bucket listing: the Sigstore pair when its bundle is there, else the Ed25519 pair.
export const anchorFiles = (has) => ['ANCHOR.json', has(ANCHOR_BUNDLE) ? ANCHOR_BUNDLE : 'ANCHOR.json.sig'];
export const checkpointFiles = (has) => ['CHECKPOINT.json', has(CHECKPOINT_BUNDLE) ? CHECKPOINT_BUNDLE : 'CHECKPOINT.json.sig'];
export function sigstorePolicyError(policy, ed25519MaxSequence) {
  if (!policy || typeof policy !== 'object') return 'no Sigstore policy';
  if (!Number.isInteger(ed25519MaxSequence) || ed25519MaxSequence < 0) return 'a Sigstore policy needs ed25519MaxSequence (the last sequence signed with Ed25519): without it nothing prevents a downgrade';
  if (!IDENTITY.test(String(policy.identity ?? ''))) return 'the Sigstore identity must be one exact GitHub workflow identity (https://github.com/OWNER/REPO/.github/workflows/FILE@refs/heads/BRANCH); a pattern is never accepted';
  if (!REPO.test(String(policy.repository ?? '')) || !policy.identity.startsWith(`https://github.com/${policy.repository}/`)) return 'the Sigstore repository must be OWNER/REPO and match the identity';
  if ((policy.issuer ?? SIGSTORE_ISSUER) !== SIGSTORE_ISSUER) return 'the Sigstore issuer must be the GitHub Actions OIDC issuer';
  return null;
}
export function verifySigstoreBlob({ body, bundle, policy, ed25519MaxSequence, cosign = 'cosign' }) {
  const perr = sigstorePolicyError(policy, ed25519MaxSequence); if (perr) return { ok: false, reason: perr };
  if (!Buffer.isBuffer(bundle) || bundle.length < 64 || bundle.length > 1 << 20) return { ok: false, reason: 'the Sigstore bundle is missing, truncated or oversized' };
  try { JSON.parse(bundle.toString('utf8')); } catch { return { ok: false, reason: 'the Sigstore bundle is not valid JSON' }; }
  const tmp = mkdtempSync(join(tmpdir(), 'mg-sigstore-'));
  try {
    writeFileSync(join(tmp, 'body'), body, { mode: 0o600 }); writeFileSync(join(tmp, 'bundle.json'), bundle, { mode: 0o600 });
    const args = ['verify-blob', '--bundle', join(tmp, 'bundle.json'), '--certificate-identity', policy.identity, '--certificate-oidc-issuer', SIGSTORE_ISSUER, '--certificate-github-workflow-repository', policy.repository, ...(policy.trustedRoot ? ['--trusted-root', policy.trustedRoot] : []), join(tmp, 'body')];
    try { execFileSync(policy.cosign ?? cosign, args, { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 }); return { ok: true }; }
    catch (e) { return { ok: false, reason: 'the Sigstore bundle does not verify for the pinned identity: ' + String(e.stderr ?? e.message).split('\n').filter(Boolean).pop()?.slice(0, 120) }; }
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
const PUBKEY = /^ssh-ed25519 [A-Za-z0-9+/]{43,}={0,2}(?: [^\r\n]*)?$/;      // one line, one key: no option, no second entry, no newline can be smuggled into allowed_signers

// The statement is canonical (sorted keys, one trailing newline) so that its hash is the identity of the head.
const canonical = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k] && typeof o[k] === 'object' && !Array.isArray(o[k]) ? Object.fromEntries(Object.keys(o[k]).sort().map((j) => [j, o[k][j]])) : o[k]]))) + '\n';
export const headSha = (anchorBytes) => sha(anchorBytes);

export function buildAnchor({ stamp, files, sequence, previousHeadSha256 = null, createdAt }) {
  if (!Number.isInteger(sequence) || sequence < 1) throw new Error('sequence must be an integer >= 1');
  if ((sequence === 1) !== (previousHeadSha256 === null)) throw new Error('the first statement has no predecessor and every other one must name its predecessor');
  for (const f of BACKED) if (!Buffer.isBuffer(files[f])) throw new Error(`${f} is required`);
  return canonical({ schema: SCHEMA, stamp, created_at: createdAt, sequence, previous_head_sha256: previousHeadSha256, files: Object.fromEntries(BACKED.map((f) => [f, sha(files[f])])) });
}

// Signs `body` as `name` with `namespace` inside a private temporary directory, checks the result with `verify(bodyBytes, sigBytes)`, and only then publishes the PAIR into `dir`: the signature first, the statement last
// (the statement is the commit point), each by hard link so an existing file is never replaced. A failure or an interruption at any earlier point leaves `dir` exactly as it was. With `agent` the key is served by
// ssh-agent: `signingKey` is then the PUBLIC key file and the private key never touches a file this code can read.
function signAtomic({ dir, name, body, signingKey, namespace, sshKeygen, agent = false, verify = null, sigName = name + '.sig', signFn = null }) {
  const tmp = mkdtempSync(join(dir, '.sign-'));
  try {
    writeFileSync(join(tmp, name), body, { mode: 0o600 });
    try { if (signFn) signFn(join(tmp, name), join(tmp, sigName)); else execFileSync(sshKeygen, ['-Y', 'sign', ...(agent ? ['-U'] : []), '-f', signingKey, '-n', namespace, join(tmp, name)], { stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { throw new Error('signing failed: ' + String(e.stderr ?? e.message).split('\n')[0].slice(0, 120)); }
    if (!existsSync(join(tmp, sigName)) || statSync(join(tmp, sigName)).size < 64) throw new Error('signing produced no usable signature, nothing was kept');
    chmodSync(join(tmp, sigName), 0o600);
    if (verify) { const v = verify(readFileSync(join(tmp, name)), readFileSync(join(tmp, sigName))); if (!v.ok) throw new Error('the new signature does not verify with the trusted key, nothing was kept: ' + v.reason); }
    linkSync(join(tmp, sigName), join(dir, sigName));
    try { linkSync(join(tmp, name), join(dir, name)); } catch (e) { rmSync(join(dir, sigName), { force: true }); throw new Error('could not publish the statement, nothing was kept: ' + e.code); }
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
const sweepStale = (dir) => { for (const f of readdirSync(dir)) if (f.startsWith('.sign-')) rmSync(join(dir, f), { recursive: true, force: true }); };      // leftovers of an interrupted run of THIS tool only

// Signs the statement of the backup in `dir` with the key FILE `signingKey` and writes ANCHOR.json and ANCHOR.json.sig beside the other files. Never overwrites an existing statement.
// With `publicKey` the statement is verified independently right after signing (the CLI always passes it); on any failure BOTH files are removed, so a backup is never left looking signed.
// The statement every scheme signs: same canonical bytes, same chain rule.
function prepareAnchor({ dir, previousDir, sequence, clock }) {
  const stamp = dir.split('/').pop(); let prev = null, seq = sequence ?? 1;
  if (previousDir) { const pa = join(resolve(previousDir), 'ANCHOR.json'); if (!existsSync(pa)) throw new Error('the previous backup has no anchor'); const pb = readFileSync(pa); prev = headSha(pb); seq = sequence ?? JSON.parse(pb.toString()).sequence + 1; }
  const files = Object.fromEntries(BACKED.map((f) => [f, readFileSync(join(dir, f))]));
  return { stamp, seq, prev, files, anchor: buildAnchor({ stamp, files, sequence: seq, previousHeadSha256: prev, createdAt: iso(clock()) }) };
}
export function signBackup({ dir, signingKey, publicKey = null, previousDir = null, sequence = null, agent = false, clock = () => new Date(), sshKeygen = 'ssh-keygen' }) {
  dir = resolve(dir);
  if (existsSync(join(dir, 'ANCHOR.json'))) throw new Error('this backup already has an anchor: it is never overwritten');
  if (!signingKey || !existsSync(signingKey)) throw new Error('the signing key file is missing');
  if (!agent && statSync(signingKey).size < 64) throw new Error('the signing key file is empty or truncated: restore it from the password manager (no statement was written)');
  const { stamp, seq, prev, files, anchor } = prepareAnchor({ dir, previousDir, sequence, clock });
  sweepStale(dir); rmSync(join(dir, 'ANCHOR.json.sig'), { force: true });                                  // a signature without its statement authenticates nothing: it is the trace of an interrupted publication
  const verify = publicKey ? (a, sig) => verifyAnchor({ files: { ...files, 'ANCHOR.json': a, 'ANCHOR.json.sig': sig }, publicKey, expectedStamp: stamp, minSequence: seq, sshKeygen }) : null;
  signAtomic({ dir, name: 'ANCHOR.json', body: anchor, signingKey, namespace: NAMESPACE, sshKeygen, agent, verify });
  return { stamp, sequence: seq, head_sha256: headSha(Buffer.from(anchor)), previous_head_sha256: prev, scheme: 'ed25519' };
}

// Keyless: runs inside GitHub Actions (id-token: write). The result is verified against the PINNED policy before anything is published, so a run from the wrong workflow, branch or repository publishes nothing.
const cosignSigner = (cosign) => (file, sigFile) => { try { execFileSync(cosign, ['sign-blob', '--yes', '--bundle', sigFile, file], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 180000 }); } catch (e) { throw new Error(String(e.stderr ?? e.message).split('\n').filter(Boolean).pop() ?? 'cosign failed'); } };
export function signBackupSigstore({ dir, sigstore, ed25519MaxSequence, previousDir = null, sequence = null, clock = () => new Date(), cosign = 'cosign' }) {
  dir = resolve(dir); const perr = sigstorePolicyError(sigstore, ed25519MaxSequence); if (perr) throw new Error(perr);
  if (existsSync(join(dir, 'ANCHOR.json'))) throw new Error('this backup already has an anchor: it is never overwritten');
  const { stamp, seq, prev, files, anchor } = prepareAnchor({ dir, previousDir, sequence, clock });
  if (seq <= ed25519MaxSequence) throw new Error(`sequence ${seq} belongs to the frozen Ed25519 range (<= ${ed25519MaxSequence}): a Sigstore signature would not be accepted for it`);
  sweepStale(dir); rmSync(join(dir, ANCHOR_BUNDLE), { force: true });
  const verify = (a, bundle) => verifyAnchor({ files: { ...files, 'ANCHOR.json': a, [ANCHOR_BUNDLE]: bundle }, sigstore, ed25519MaxSequence, expectedStamp: stamp, minSequence: seq });
  signAtomic({ dir, name: 'ANCHOR.json', body: anchor, sigName: ANCHOR_BUNDLE, signFn: cosignSigner(sigstore.cosign ?? cosign), verify });
  return { stamp, sequence: seq, head_sha256: headSha(Buffer.from(anchor)), previous_head_sha256: prev, scheme: 'sigstore' };
}

// `files`: Map or object name -> Buffer as fetched from ONE place (a bucket or a directory). Returns { ok, reason, anchor, head_sha256 }.
export function verifyAnchor({ files, publicKey = null, principal = PRINCIPAL, minSequence = 0, expectedStamp = null, sigstore = null, ed25519MaxSequence = null, sshKeygen = 'ssh-keygen' }) {
  const get = (n) => (files instanceof Map ? files.get(n) : files[n]), fail = (reason) => ({ ok: false, reason });
  const a = get('ANCHOR.json'); if (!Buffer.isBuffer(a)) return fail('the backup carries no signed anchor');
  let scheme = 'ed25519', seq = null;
  if (sigstore) {
    const perr = sigstorePolicyError(sigstore, ed25519MaxSequence); if (perr) return fail(perr);
    try { seq = JSON.parse(a.toString('utf8')).sequence; } catch { return fail('the signed statement is not valid JSON'); }
    if (!Number.isInteger(seq)) return fail('the signed statement has no sequence');
    scheme = seq > ed25519MaxSequence ? 'sigstore' : 'ed25519';                                      // only SELECTS the verifier; the verifier then has to accept the exact bytes
  }
  if (scheme === 'sigstore') {
    const bundle = get(ANCHOR_BUNDLE); if (!Buffer.isBuffer(bundle)) return fail(`sequence ${seq} must be signed with Sigstore keyless (Ed25519 is frozen at sequence ${ed25519MaxSequence}): no downgrade`);
    const v = verifySigstoreBlob({ body: a, bundle, policy: sigstore, ed25519MaxSequence }); if (!v.ok) return fail(v.reason);
  } else {
    if (typeof publicKey !== 'string' || !PUBKEY.test(publicKey.trim())) return fail('the trusted public key is not a single ssh-ed25519 line');
    if (!/^[A-Za-z0-9._-]{1,40}$/.test(principal)) return fail('invalid principal');
    const sig = get('ANCHOR.json.sig'); if (!Buffer.isBuffer(sig)) return fail('the backup carries no signed anchor');
    const tmp = mkdtempSync(join(tmpdir(), 'mg-anchor-'));
    try {
      const key = publicKey.trim().split(/\s+/).slice(0, 2).join(' '); writeFileSync(join(tmp, 'allowed'), `${principal} namespaces="${NAMESPACE}" ${key}\n`, { mode: 0o600 }); writeFileSync(join(tmp, 'a.sig'), sig, { mode: 0o600 });
      try { execFileSync(sshKeygen, ['-Y', 'verify', '-f', join(tmp, 'allowed'), '-I', principal, '-n', NAMESPACE, '-s', join(tmp, 'a.sig')], { input: a, stdio: ['pipe', 'pipe', 'pipe'] }); }
      catch (e) { return fail('the signature does not verify with the trusted key: ' + String(e.stderr ?? e.stdout ?? 'rejected').split('\n')[0].slice(0, 100)); }
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  }
  let anchor; try { anchor = JSON.parse(a.toString('utf8')); } catch { return fail('the signed statement is not valid JSON'); }
  if (a.toString('utf8') !== canonical(anchor)) return fail('the signed statement is not in canonical form');
  if (anchor.schema !== SCHEMA) return fail('unknown statement schema');
  if (expectedStamp && anchor.stamp !== expectedStamp) return fail(`the signed statement is for ${anchor.stamp}, not for ${expectedStamp}`);
  for (const f of BACKED) { const b = get(f); if (!Buffer.isBuffer(b)) return fail(`${f} is missing`); if (anchor.files?.[f] !== sha(b)) return fail(`${f} does not match the signed statement`); }
  if (!Number.isInteger(anchor.sequence) || anchor.sequence < minSequence) return fail(`rollback: sequence ${anchor.sequence} is older than the newest known (${minSequence})`);
  return { ok: true, anchor, head_sha256: headSha(a), scheme };
}

// ---- external checkpoint -------------------------------------------------------------------------------------------------------------------------------------------------------
// All three providers can serve an OLD but coherent, genuinely signed backup (a rollback of every copy at once, or the loss of the newest ones). Nothing inside the buckets can show it: only a statement of "the newest
// backup I confirmed is sequence N with this head" that lives OUTSIDE them can. The checkpoint is signed by the same key with its OWN namespace, so a backup signature can never pass for a checkpoint or the reverse.
// It is small and public (a sequence, a stamp and a hash): keep several copies where an attacker of the buckets cannot reach (the repository, a password-manager note, a printout) and refresh it after each confirmed backup.
export function signCheckpoint({ backupDir, outDir, signingKey, publicKey = null, agent = false, confirmedAt = null, clock = () => new Date(), sshKeygen = 'ssh-keygen' }) {
  backupDir = resolve(backupDir); outDir = resolve(outDir);
  if (!existsSync(join(backupDir, 'ANCHOR.json'))) throw new Error('that backup has no anchor: sign the backup first');
  if (!signingKey || !existsSync(signingKey)) throw new Error('the signing key file is missing');
  if (!agent && statSync(signingKey).size < 64) throw new Error('the signing key file is empty or truncated: restore it from the password manager (no statement was written)');
  if (existsSync(join(outDir, 'CHECKPOINT.json'))) throw new Error('a checkpoint already exists in that directory: write the new one elsewhere (checkpoints are never overwritten)');
  const raw = readFileSync(join(backupDir, 'ANCHOR.json')), a = JSON.parse(raw.toString()), body = canonical({ schema: CHECKPOINT_SCHEMA, sequence: a.sequence, stamp: a.stamp, head_sha256: headSha(raw), confirmed_at: confirmedAt ?? iso(clock()) });
  mkdirSync(outDir, { recursive: true }); sweepStale(outDir); rmSync(join(outDir, 'CHECKPOINT.json.sig'), { force: true });
  const verify = publicKey ? (c, sig) => verifyCheckpoint({ files: { 'CHECKPOINT.json': c, 'CHECKPOINT.json.sig': sig }, publicKey, sshKeygen }) : null;
  signAtomic({ dir: outDir, name: 'CHECKPOINT.json', body, signingKey, namespace: CHECKPOINT_NAMESPACE, sshKeygen, agent, verify });
  return { sequence: a.sequence, stamp: a.stamp, head_sha256: headSha(raw), checkpoint_sha256: sha(Buffer.from(body)) };
}

export function signCheckpointSigstore({ backupDir, outDir, sigstore, ed25519MaxSequence, confirmedAt = null, clock = () => new Date(), cosign = 'cosign' }) {
  backupDir = resolve(backupDir); outDir = resolve(outDir); const perr = sigstorePolicyError(sigstore, ed25519MaxSequence); if (perr) throw new Error(perr);
  if (!existsSync(join(backupDir, 'ANCHOR.json'))) throw new Error('that backup has no anchor: sign the backup first');
  if (existsSync(join(outDir, 'CHECKPOINT.json'))) throw new Error('a checkpoint already exists in that directory: write the new one elsewhere (checkpoints are never overwritten)');
  const raw = readFileSync(join(backupDir, 'ANCHOR.json')), a = JSON.parse(raw.toString());
  if (a.sequence <= ed25519MaxSequence) throw new Error(`sequence ${a.sequence} belongs to the frozen Ed25519 range: its checkpoint is signed with the Ed25519 key`);
  const body = canonical({ schema: CHECKPOINT_SCHEMA, sequence: a.sequence, stamp: a.stamp, head_sha256: headSha(raw), confirmed_at: confirmedAt ?? iso(clock()) });
  mkdirSync(outDir, { recursive: true }); sweepStale(outDir); rmSync(join(outDir, CHECKPOINT_BUNDLE), { force: true });
  const verify = (c, bundle) => verifyCheckpoint({ files: { 'CHECKPOINT.json': c, [CHECKPOINT_BUNDLE]: bundle }, sigstore, ed25519MaxSequence });
  signAtomic({ dir: outDir, name: 'CHECKPOINT.json', body, sigName: CHECKPOINT_BUNDLE, signFn: cosignSigner(sigstore.cosign ?? cosign), verify });
  return { sequence: a.sequence, stamp: a.stamp, head_sha256: headSha(raw), checkpoint_sha256: sha(Buffer.from(body)), scheme: 'sigstore' };
}

// `files`: { 'CHECKPOINT.json': Buffer, 'CHECKPOINT.json.sig': Buffer } from ONE external copy. maxAgeDays (optional) turns an old checkpoint into `stale: true`: it is still authentic, but it can no longer exclude a recent rollback.
export function verifyCheckpoint({ files, publicKey = null, principal = PRINCIPAL, maxAgeDays = null, now = () => new Date(), sigstore = null, ed25519MaxSequence = null, sshKeygen = 'ssh-keygen' }) {
  const fail = (reason) => ({ ok: false, reason }), get = (n) => (files instanceof Map ? files.get(n) : files[n]), c = get('CHECKPOINT.json');
  if (!Buffer.isBuffer(c)) return fail('the checkpoint copy is incomplete');
  let scheme = 'ed25519', seq = null;
  if (sigstore) {
    const perr = sigstorePolicyError(sigstore, ed25519MaxSequence); if (perr) return fail(perr);
    try { seq = JSON.parse(c.toString('utf8')).sequence; } catch { return fail('the checkpoint is not valid JSON'); }
    if (!Number.isInteger(seq)) return fail('the checkpoint has no sequence');
    scheme = seq > ed25519MaxSequence ? 'sigstore' : 'ed25519';
  }
  if (scheme === 'sigstore') {
    const bundle = get(CHECKPOINT_BUNDLE); if (!Buffer.isBuffer(bundle)) return fail(`a checkpoint for sequence ${seq} must be signed with Sigstore keyless (Ed25519 is frozen at sequence ${ed25519MaxSequence}): no downgrade`);
    const v = verifySigstoreBlob({ body: c, bundle, policy: sigstore, ed25519MaxSequence }); if (!v.ok) return fail(v.reason.replace('the Sigstore bundle', 'the checkpoint bundle'));
  } else {
    const sig = get('CHECKPOINT.json.sig');
    if (typeof publicKey !== 'string' || !PUBKEY.test(publicKey.trim())) return fail('the trusted public key is not a single ssh-ed25519 line');
    if (!/^[A-Za-z0-9._-]{1,40}$/.test(principal)) return fail('invalid principal');
    if (!Buffer.isBuffer(sig)) return fail('the checkpoint copy is incomplete');
    const tmp = mkdtempSync(join(tmpdir(), 'mg-ckpt-'));
    try {
      writeFileSync(join(tmp, 'allowed'), `${principal} namespaces="${CHECKPOINT_NAMESPACE}" ${publicKey.trim().split(/\s+/).slice(0, 2).join(' ')}\n`, { mode: 0o600 }); writeFileSync(join(tmp, 'c.sig'), sig, { mode: 0o600 });
      try { execFileSync(sshKeygen, ['-Y', 'verify', '-f', join(tmp, 'allowed'), '-I', principal, '-n', CHECKPOINT_NAMESPACE, '-s', join(tmp, 'c.sig')], { input: c, stdio: ['pipe', 'pipe', 'pipe'] }); }
      catch (e) { return fail('the checkpoint signature does not verify with the trusted key: ' + String(e.stderr ?? e.stdout ?? 'rejected').split('\n')[0].slice(0, 100)); }
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  }
  let cp; try { cp = JSON.parse(c.toString('utf8')); } catch { return fail('the checkpoint is not valid JSON'); }
  if (c.toString('utf8') !== canonical(cp) || cp.schema !== CHECKPOINT_SCHEMA || !Number.isInteger(cp.sequence) || cp.sequence < 1 || !/^[0-9a-f]{64}$/.test(cp.head_sha256 ?? '')) return fail('the checkpoint is not in canonical form');
  const ageDays = (now().getTime() - Date.parse(cp.confirmed_at)) / 86400000;
  return { ok: true, scheme, checkpoint: cp, stale: maxAgeDays != null && !(ageDays <= maxAgeDays), age_days: Math.round(ageDays * 10) / 10, checkpoint_sha256: sha(c) };
}

// Several external copies (repository, password manager, printout…): each verified on its own; the NEWEST authentic one counts, and two authentic copies that disagree at the same sequence are equivocation.
export function bestCheckpoint(results) {
  const ok = results.filter((r) => r?.ok), bad = results.filter((r) => !r?.ok).map((r) => r?.reason ?? 'missing');
  if (!ok.length) return { ok: false, reason: 'no authentic checkpoint is available' + (bad.length ? ': ' + bad[0] : ''), rejected: bad };
  const top = Math.max(...ok.map((r) => r.checkpoint.sequence)), tops = ok.filter((r) => r.checkpoint.sequence === top);
  if (new Set(tops.map((r) => r.checkpoint.head_sha256)).size > 1) return { ok: false, reason: `two authentic checkpoints name different heads for sequence ${top} (equivocation)`, rejected: bad };
  return { ok: true, checkpoint: tops[0].checkpoint, stale: tops.every((r) => r.stale), copies: ok.length, rejected: bad };
}

// A provider's verified head against the checkpoint: older than the checkpoint is a rollback or a loss; the same sequence with another head is a fork; newer is fine (the checkpoint is simply behind).
export function checkAgainstCheckpoint(verified, checkpoint) {
  if (!verified?.ok) return { ok: false, reason: verified?.reason ?? 'not verified' };
  const a = verified.anchor;
  if (a.sequence < checkpoint.sequence) return { ok: false, reason: `rollback or loss: this copy is sequence ${a.sequence} but sequence ${checkpoint.sequence} was confirmed` };
  if (a.sequence === checkpoint.sequence && verified.head_sha256 !== checkpoint.head_sha256) return { ok: false, reason: `fork: sequence ${a.sequence} is signed but its head differs from the confirmed one` };
  return { ok: true, ahead_of_checkpoint: a.sequence > checkpoint.sequence };
}

// Several places hold a copy: who is current, who is behind, who disagrees. `results`: { name: verifyAnchor(...) result or null when the place is gone }.
export function compareHeads(results) {
  const ok = Object.entries(results).filter(([, r]) => r?.ok), out = { newest: null, current: [], stale: [], conflicts: [], failed: [], gone: [] };
  for (const [n, r] of Object.entries(results)) { if (!r) out.gone.push(n); else if (!r.ok) out.failed.push({ name: n, reason: r.reason }); }
  if (!ok.length) return out;
  const top = Math.max(...ok.map(([, r]) => r.anchor.sequence)); out.newest = top;
  const heads = new Set(ok.filter(([, r]) => r.anchor.sequence === top).map(([, r]) => r.head_sha256));
  if (heads.size > 1) out.conflicts.push({ sequence: top, reason: 'two different signed statements carry the same sequence number (equivocation)', heads: [...heads] });
  for (const [n, r] of ok) (r.anchor.sequence === top ? out.current : out.stale).push(n);
  return out;
}

// A list of verified statements, oldest first: every one must name the hash of the one before it and the sequence must be consecutive.
export function verifyChain(anchorBuffers) {
  let prev = null, seq = 0;
  for (const b of anchorBuffers) {
    const a = JSON.parse(b.toString()); if (a.sequence !== seq + 1) return { ok: false, reason: `a statement is missing before sequence ${a.sequence}` };
    if (a.previous_head_sha256 !== prev) return { ok: false, reason: `sequence ${a.sequence} does not name the statement that precedes it` };
    prev = headSha(b); seq = a.sequence;
  }
  return { ok: true, head_sha256: prev, sequence: seq };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd] = process.argv.slice(2), arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; }, has = (n) => process.argv.includes(n);
  const policy = () => arg('--sigstore-identity') ? { identity: arg('--sigstore-identity'), repository: arg('--sigstore-repo'), trustedRoot: arg('--trusted-root') } : null, frozen = () => arg('--ed25519-max-sequence') != null ? +arg('--ed25519-max-sequence') : null;
  const need = (flag, why) => { if (!arg(flag)) { console.error(`${cmd} requires ${flag}: ${why}`); process.exit(2); } };
  const load = (d, names) => Object.fromEntries(names.filter((f) => existsSync(join(d, f))).map((f) => [f, readFileSync(join(d, f))]));
  const out = (o) => console.log(JSON.stringify(o, null, 1));
  try {
    if (cmd === 'sign') { need('--public-key', 'a backup is never declared signed without an independent verification'); out(signBackup({ dir: arg('--dir'), signingKey: arg('--signing-key'), publicKey: arg('--public-key'), agent: has('--agent'), previousDir: arg('--previous'), sequence: arg('--sequence') ? +arg('--sequence') : null })); }
    else if (cmd === 'checkpoint') { need('--public-key', 'it is never declared signed without an independent verification'); out(signCheckpoint({ backupDir: arg('--dir'), outDir: arg('--out'), signingKey: arg('--signing-key'), publicKey: arg('--public-key'), agent: has('--agent') })); }
    else if (cmd === 'sign-sigstore' || cmd === 'checkpoint-sigstore') {
      need('--sigstore-identity', 'the exact workflow identity that is allowed to sign'); need('--sigstore-repo', 'OWNER/REPO'); need('--ed25519-max-sequence', 'the frozen Ed25519 range, so that no downgrade is possible');
      if (cmd === 'sign-sigstore') {
        if (arg('--previous')) { need('--public-key', 'the previous statement is verified before it is extended'); const pd = resolve(arg('--previous')), pv = verifyAnchor({ files: load(pd, [...BACKED, 'ANCHOR.json', 'ANCHOR.json.sig', ANCHOR_BUNDLE]), publicKey: arg('--public-key'), sigstore: policy(), ed25519MaxSequence: frozen() }); if (!pv.ok) throw new Error('the previous statement does not verify, nothing was signed: ' + pv.reason); }
        out(signBackupSigstore({ dir: arg('--dir'), sigstore: policy(), ed25519MaxSequence: frozen(), previousDir: arg('--previous'), sequence: arg('--sequence') ? +arg('--sequence') : null }));
      } else out(signCheckpointSigstore({ backupDir: arg('--dir'), outDir: arg('--out'), sigstore: policy(), ed25519MaxSequence: frozen() }));
    }
    else if (cmd === 'verify-checkpoint') { const d = resolve(arg('--dir')), r = verifyCheckpoint({ files: load(d, ['CHECKPOINT.json', 'CHECKPOINT.json.sig', CHECKPOINT_BUNDLE]), publicKey: arg('--public-key'), sigstore: policy(), ed25519MaxSequence: frozen(), maxAgeDays: arg('--max-age-days') ? +arg('--max-age-days') : null }); out({ ok: r.ok, reason: r.reason ?? null, scheme: r.scheme ?? null, sequence: r.checkpoint?.sequence ?? null, head_sha256: r.checkpoint?.head_sha256 ?? null, stale: r.stale ?? null, age_days: r.age_days ?? null }); process.exit(r.ok ? 0 : 1); }
    else if (cmd === 'verify') { const dir = resolve(arg('--dir')), r = verifyAnchor({ files: load(dir, [...BACKED, 'ANCHOR.json', 'ANCHOR.json.sig', ANCHOR_BUNDLE]), publicKey: arg('--public-key'), sigstore: policy(), ed25519MaxSequence: frozen(), principal: arg('--principal', PRINCIPAL), minSequence: +arg('--min-sequence', 0) }); out({ ok: r.ok, reason: r.reason ?? null, scheme: r.scheme ?? null, sequence: r.anchor?.sequence ?? null, head_sha256: r.head_sha256 ?? null }); process.exit(r.ok ? 0 : 1); }
    else { console.error('usage: backup_anchor.mjs sign|checkpoint|sign-sigstore|checkpoint-sigstore|verify|verify-checkpoint (see the header of this file)'); process.exit(2); }
  } catch (e) { console.error(String(e.message).split('\n')[0]); process.exit(2); }
}
