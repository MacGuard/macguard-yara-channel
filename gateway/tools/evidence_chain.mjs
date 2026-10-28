// Tamper-EVIDENCE for evidence/backups.jsonl. A git branch is not WORM storage: anyone with write access can rewrite it. What this adds is that a rewrite cannot go unnoticed:
//   - evidence/backups.chain holds one line per record: "<n> <chain_sha256>", chain_n = SHA-256( chain_(n-1) + "\n" + SHA-256(record line n) ), chain_0 = SHA-256("macguard.evidence-chain/1").
//     Editing, deleting or reordering any record changes every chain value from there on, so the sidecar and the log can no longer agree.
//   - a CHECKPOINT {count, head} is the chain value after `count` records. It is signed and logged OUTSIDE the repository (Sigstore + Rekor, see .github/workflows/evidence-checkpoint.yml): verifying the
//     log against a checkpoint proves that the first `count` records are exactly the ones that existed when it was signed, whatever happened to the branch since. Appending afterwards stays valid.
// What it does NOT do: stop a deletion or a rewrite (that is the job of branch rules), or vouch for records written after the last checkpoint.
//   node evidence_chain.mjs update     [--dir evidence]                  append the missing chain lines (idempotent); refuses when the existing ones do not match the log
//   node evidence_chain.mjs verify     [--dir evidence] [--checkpoint F --bundle B [--identity ID] [--issuer URL]]
//                                      exit 0 only when the sidecar matches the log AND (with --checkpoint) the checkpoint's Sigstore signature verifies for the authorised workflow identity AND the checkpoint is a prefix
//                                      of the log. A checkpoint without --bundle is refused unless --allow-unsigned (local tests): an unsigned file proves nothing.
//   node evidence_chain.mjs checkpoint [--dir evidence]                  print the checkpoint statement for the current head
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const isMain = () => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } };   // argv[1] may go through a symlink (/var -> /private/var): comparing raw strings would silently do nothing

export const CHECKPOINT_IDENTITY = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/evidence-checkpoint.yml@refs/heads/main';
export const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
/** cosign verify-blob for the authorised workflow identity (the Rekor inclusion proof travels in the bundle). `cosign` is resolved through PATH, like the other tools. */
export function verifyCheckpointSignature({ checkpointFile, bundleFile, identity = CHECKPOINT_IDENTITY, issuer = OIDC_ISSUER }) {
  const r = spawnSync('cosign', ['verify-blob', '--bundle', bundleFile, '--certificate-identity', identity, '--certificate-oidc-issuer', issuer, checkpointFile], { encoding: 'utf8' });
  if (r.error) return { ok: false, problem: 'cosign is not available, so the checkpoint signature cannot be verified' };
  return r.status === 0 ? { ok: true } : { ok: false, problem: 'the checkpoint signature does not verify for the authorised identity' };
}
const sha = (s) => createHash('sha256').update(s).digest('hex');
export const GENESIS = sha('macguard.evidence-chain/1');
const lines = (text) => String(text || '').split('\n').filter((l) => l.length > 0);

/** The chain values of a list of record lines (index i is the value after i+1 records). */
export function chainOf(recordLines) { const out = []; let prev = GENESIS; for (const l of recordLines) { prev = sha(prev + '\n' + sha(l)); out.push(prev); } return out; }

/** Compare the sidecar with the log. `problems` is empty only when every sidecar line is the right value for its record; `missing` is how many records have no chain line yet. */
export function check(jsonlText, chainText) {
  const recs = lines(jsonlText), want = chainOf(recs), have = lines(chainText), problems = [];
  have.forEach((l, i) => {
    const m = /^(\d+) ([0-9a-f]{64})$/.exec(l);
    if (!m || Number(m[1]) !== i + 1) problems.push(`chain line ${i + 1} is malformed or out of order`);
    else if (i >= want.length) problems.push(`chain line ${i + 1} has no record: records were removed`);
    else if (m[2] !== want[i]) problems.push(`chain line ${i + 1} does not match record ${i + 1}: the log was altered from that record on`);
  });
  return { ok: problems.length === 0, problems, count: recs.length, chained: have.length, missing: Math.max(0, recs.length - have.length), head: want.length ? want[want.length - 1] : GENESIS };
}

/** The chain text with the missing lines appended. Throws when the existing lines do not match the log (it never repairs a divergence by overwriting it). */
export function extend(jsonlText, chainText) {
  const c = check(jsonlText, chainText); if (!c.ok) throw new Error('the chain does not match the log: ' + c.problems[0]);
  const want = chainOf(lines(jsonlText)), have = lines(chainText).length;
  return (have ? String(chainText).replace(/\n*$/, '\n') : '') + want.slice(have).map((h, i) => `${have + i + 1} ${h}`).join('\n') + (want.length > have ? '\n' : '');
}

export const checkpointOf = (jsonlText, at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')) => { const c = check(jsonlText, ''); return { schema: 'macguard.evidence-checkpoint/1', count: c.count, head: c.head, at }; };

/** Is the log consistent with a checkpoint? The record count may only have grown, and the chain value at `count` must be the signed one. */
export function verifyAgainstCheckpoint(jsonlText, cp) {
  if (!cp || cp.schema !== 'macguard.evidence-checkpoint/1' || !Number.isInteger(cp.count) || cp.count < 0 || !/^[0-9a-f]{64}$/.test(cp.head || '')) return { ok: false, problem: 'not a valid checkpoint' };
  const want = chainOf(lines(jsonlText));
  if (want.length < cp.count) return { ok: false, problem: `the log has ${want.length} records, fewer than the ${cp.count} the checkpoint covers: records were removed` };
  const at = cp.count === 0 ? GENESIS : want[cp.count - 1];
  return at === cp.head ? { ok: true } : { ok: false, problem: 'the first ' + cp.count + ' records are not the ones the checkpoint covers: the log was altered' };
}

if (isMain()) {
  const [cmd] = process.argv.slice(2), arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
  const dir = arg('--dir', 'evidence'), log = join(dir, 'backups.jsonl'), side = join(dir, 'backups.chain');
  const read = (f) => (existsSync(f) ? readFileSync(f, 'utf8') : '');
  try {
    if (cmd === 'update') { const next = extend(read(log), read(side)); if (next !== read(side)) writeFileSync(side, next, { mode: 0o644 }); console.log(`chain: ${check(read(log), next).count} records`); }
    else if (cmd === 'verify') {
      const c = check(read(log), read(side)); let bad = c.problems.slice();
      if (c.missing) bad.push(`${c.missing} record(s) have no chain line yet (run update)`);
      const cpFile = arg('--checkpoint'), bundle = arg('--bundle');
      if (cpFile && !bundle && !process.argv.includes('--allow-unsigned')) bad.push('the checkpoint has no signature bundle (--bundle): an unsigned checkpoint is not accepted');
      if (cpFile && bundle) { const sg = verifyCheckpointSignature({ checkpointFile: cpFile, bundleFile: bundle, identity: arg('--identity', CHECKPOINT_IDENTITY), issuer: arg('--issuer', OIDC_ISSUER) }); if (!sg.ok) bad.push(sg.problem); }
      if (cpFile) { const v = verifyAgainstCheckpoint(read(log), JSON.parse(readFileSync(cpFile, 'utf8'))); if (!v.ok) bad.push(v.problem); }
      if (bad.length) { for (const b of bad) console.error('FAIL: ' + b); process.exit(1); } console.log(`OK: ${c.count} records, head ${c.head}`);
    } else if (cmd === 'checkpoint') console.log(JSON.stringify(checkpointOf(read(log))));
    else { console.error('usage: evidence_chain.mjs update|verify|checkpoint [--dir evidence] [--checkpoint FILE]'); process.exit(2); }
  } catch (e) { console.error('refused: ' + String(e.message).split('\n')[0]); process.exit(1); }
}
