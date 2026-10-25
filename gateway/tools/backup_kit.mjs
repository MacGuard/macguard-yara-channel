// Builds the text of the RECOVERY KIT: the public facts needed to authenticate and restore a backup after the Mac is gone, in a form fit for a password-manager secure note and for paper.
// It holds ONLY public material: the signing PUBLIC key, the age RECIPIENT (public), the newest known head, the destinations (bucket names, endpoints; no credentials) and the commands. It refuses any input that looks
// private, and it prints nothing it was not given. The private halves (the age identity and the signing key) are never read by this tool: where they are kept is the owner's decision (docs/analytics/BACKUP-AUTHENTICATION-AND-RECOVERY-2026-10-25.md).
//   node tools/backup_kit.mjs --public-key "ssh-ed25519 AAAA..." --age-recipient age1... [--head-dir BACKUP_DIR] > kit.txt
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DEFAULT_CONFIG } from './backup_objstore.mjs';
import { anchorFiles, sigstorePolicyError, SIGSTORE_ISSUER } from './backup_anchor.mjs';

const PRIVATE = /PRIVATE KEY|AGE-SECRET-KEY|AGE-PLUGIN|SECRET_ACCESS|aws_secret|password\s*[:=]/i, PUB = /^ssh-ed25519 [A-Za-z0-9+/]{43,}={0,2}(?: [^\r\n]*)?$/, RECIPIENT = /^age1[a-z0-9]{50,}$/;
export function makeKit({ publicKey, ageRecipient, headDir = null, checkpointDir = null, sigstore = null, ed25519MaxSequence = null, config = DEFAULT_CONFIG, now = () => new Date() }) {
  for (const [n, v] of Object.entries({ publicKey, ageRecipient })) if (PRIVATE.test(String(v ?? ''))) throw new Error(`${n} looks like private material: nothing was written`);
  if (!PUB.test(String(publicKey ?? '').trim())) throw new Error('the signing public key must be one ssh-ed25519 line');
  if (!RECIPIENT.test(String(ageRecipient ?? '').trim())) throw new Error('the age recipient must be an age1... public key');
  let head = 'none recorded yet: sign the first backup and record its sequence and head here';
  if (headDir) { const a = join(resolve(headDir), 'ANCHOR.json'); if (!existsSync(a)) throw new Error('that backup has no ANCHOR.json'); const b = readFileSync(a), j = JSON.parse(b.toString()); head = `sequence ${j.sequence}, stamp ${j.stamp}, head SHA-256 ${createHash('sha256').update(b).digest('hex')}`; }
  const sha = (b) => createHash('sha256').update(b).digest('hex'), blob = Buffer.from(publicKey.trim().split(/\s+/)[1], 'base64'), fingerprint = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  if (sigstore) { const e = sigstorePolicyError(sigstore, ed25519MaxSequence); if (e) throw new Error(e); }
  let artifacts = 'none recorded yet', checkpoint = 'none recorded yet: sign the first checkpoint and record it here';
  if (headDir) artifacts = ['d1-export.sql.age', 'manifest.json', 'SHA256SUMS', ...anchorFiles((f) => existsSync(join(resolve(headDir), f)))].map((f) => { const x = join(resolve(headDir), f); if (!existsSync(x)) throw new Error(`that backup lacks ${f}`); return `  ${sha(readFileSync(x))}  ${f}`; }).join('\n');
  if (checkpointDir) { const f = join(resolve(checkpointDir), 'CHECKPOINT.json'); if (!existsSync(f) || !existsSync(f + '.sig')) throw new Error('that checkpoint directory lacks CHECKPOINT.json or its signature'); const b = readFileSync(f), j = JSON.parse(b.toString()); checkpoint = `sequence ${j.sequence}, stamp ${j.stamp}, head SHA-256 ${j.head_sha256}, confirmed ${j.confirmed_at}\n  CHECKPOINT.json SHA-256 ${sha(b)}, signature SHA-256 ${sha(readFileSync(f + '.sig'))}`; }
  const dests = Object.entries(config.destinations).map(([n, d]) => `  ${n}: bucket ${d.bucket}, endpoint ${d.endpoint}, prefix ${config.prefix}/<stamp>/`).join('\n');
  const text = `MACGUARD BACKUP RECOVERY KIT (public facts only: contains no secret)
Made ${now().toISOString().replace(/\.\d{3}Z$/, 'Z')}

TRUSTED SIGNING PUBLIC KEY (authenticates every backup; keep it somewhere that is neither a bucket nor only this Mac):
${publicKey.trim()}
Principal: macguard-backup    Namespace: macguard-backup/1    Checkpoint namespace: macguard-backup-checkpoint/1
Fingerprint: ${fingerprint}
Schemas: macguard.gateway-backup/2, macguard.backup-anchor/1, macguard.backup-checkpoint/1

SIGNING POLICY (which signature is valid for which sequence; anything else is refused, there is no downgrade):
${sigstore ? `  sequence 1..${ed25519MaxSequence}: Ed25519 key above (historical, frozen)
  sequence ${ed25519MaxSequence + 1} and later: Sigstore keyless, ONLY this workflow identity:
    identity   ${sigstore.identity}
    issuer     ${SIGSTORE_ISSUER}
    repository ${sigstore.repository}
  files: ANCHOR.json.sigstore.json and CHECKPOINT.json.sigstore.json (cosign bundles with the Rekor proof). Verifying needs \`cosign\`.` : '  Ed25519 only (no Sigstore policy recorded yet).'}

AGE RECIPIENT (public; the matching identity is the PRIVATE key that decrypts):
${ageRecipient.trim()}

NEWEST KNOWN HEAD (refuse anything older than this sequence):
${head}

ARTIFACTS OF THAT HEAD (SHA-256; the anchor signs the first three, the head above is the hash of ANCHOR.json):
${artifacts}

TRUSTED CHECKPOINT ANCHOR (an independent signed statement of the newest confirmed head; keep a copy outside the buckets and outside this Mac):
  ${checkpoint}
  Verify a copy with:  MG_CHECKPOINT_DIRS=/dir/with/CHECKPOINT.json sh recover_verify.sh ...   (the restore is REFUSED if no authentic copy is given, or if the backup is older than it)

DESTINATIONS (credentials are NOT in this kit):
${dests}

PRIVATE MATERIAL (not here, never to be pasted into this note, chat or a log):
  - the age IDENTITY file: decrypts the backups. Keep two independent copies (for example the password manager as an attachment and an offline copy).
  - the SIGNING private key: signs new backups. Needed to make new ones, NOT to restore.
  - the bucket credentials: create new ones if the old ones are lost.

TO RESTORE ON A CLEAN MACHINE
  1. Download the five files of the newest stamp from ANY destination: d1-export.sql.age manifest.json SHA256SUMS ANCHOR.json and its signature (ANCHOR.json.sigstore.json for Sigstore backups, ANCHOR.json.sig for the historical Ed25519 ones)
  2. MG_CHECKPOINT_DIRS=/dir/with/CHECKPOINT.json${sigstore ? ` MG_SIGSTORE_IDENTITY='${sigstore.identity}' MG_SIGSTORE_REPO='${sigstore.repository}' MG_ED25519_MAX_SEQUENCE=${ed25519MaxSequence}` : ''} sh recover_verify.sh DIR "<the signing public key above>" <the sequence above> /path/to/age-identity restored.sql
  3. Only if it prints ANCHORED OK and DECRYPTED OK is the file authentic and intact. If two destinations disagree, trust the higher sequence that verifies.
  4. Load restored.sql into a NEW staging database first; never over production.
`;
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----|AGE-SECRET-KEY-|AGE-PLUGIN-/.test(text)) throw new Error('the kit would contain private material: nothing was written');
  return text;
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const arg = (n) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : null; };
  try { process.stdout.write(makeKit({ publicKey: arg('--public-key'), ageRecipient: arg('--age-recipient'), headDir: arg('--head-dir'), checkpointDir: arg('--checkpoint-dir'), sigstore: arg('--sigstore-identity') ? { identity: arg('--sigstore-identity'), repository: arg('--sigstore-repo') } : null, ed25519MaxSequence: arg('--ed25519-max-sequence') != null ? +arg('--ed25519-max-sequence') : null })); } catch (e) { console.error(String(e.message).split('\n')[0]); process.exit(1); }
}
