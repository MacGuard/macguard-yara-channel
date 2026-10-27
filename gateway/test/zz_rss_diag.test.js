// DIAGNOSTIC ONLY (throwaway branch, never merged): where does the memory of decrypt + hash + load go on Linux, and does it scale with the export size?
import test from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { createWriteStream, mkdtempSync, rmSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { ageEncryptFile } from '../tools/stream_io.mjs';
const MIB = 1048576;
async function makeExport(file, mib) {
  await new Promise((ok, ko) => { const w = createWriteStream(file, { mode: 0o600 }); w.on('error', ko).on('finish', ok);
    w.write("CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b TEXT);\nCREATE TABLE log(n INTEGER);\nCREATE TRIGGER trg AFTER INSERT ON t BEGIN INSERT INTO log VALUES (new.id); END;\n");
    let bytes = 0, id = 0; const pad = 'x'.repeat(700);
    (function pump() { let go = true; while (bytes < mib * MIB && go) { id++; const row = `INSERT INTO t VALUES(${id},'it''s; a "row"\nline2 -- not a comment ${id}','${pad}${id}');\n`; bytes += row.length; go = w.write(row); } if (bytes < mib * MIB) w.once('drain', pump); else w.end(); }()); });
}
const CHILD = `
import { ageDecryptFile, loadExport, shaFile } from ${JSON.stringify(new URL('../tools/stream_io.mjs', import.meta.url).href)};
import { open } from 'node:fs/promises'; import { createHash } from 'node:crypto';
const shaFileBuf = async (file) => { const h = createHash('sha256'), fh = await open(file, 'r'), buf = Buffer.allocUnsafe(1 << 20); try { for (;;) { const { bytesRead } = await fh.read(buf, 0, buf.length, null); if (!bytesRead) break; h.update(buf.subarray(0, bytesRead)); } } finally { await fh.close(); } return h.digest('hex'); };
const [enc, id, plain, variant] = process.argv.slice(1), mu = () => { const m = process.memoryUsage(); return { rss: Math.round(m.rss / 1048576), heap: Math.round(m.heapUsed / 1048576), ext: Math.round(m.external / 1048576), ab: Math.round(m.arrayBuffers / 1048576), peak: Math.round(process.resourceUsage().maxRSS / 1024) }; };
const out = { start: mu() };
await ageDecryptFile({ identity: id, src: enc, dst: plain }); out.afterDecrypt = mu();
const sha = variant === 'buf' ? await shaFileBuf(plain) : await shaFile(plain); out.sha = sha.slice(0, 10); out.afterSha = mu();
const L = await loadExport({ file: plain }); out.afterLoad = mu();
L.db.prepare('SELECT COUNT(*) n FROM t').get(); out.afterCount = mu(); L.close(); out.end = mu();
console.log(JSON.stringify(out));
`;
test('DIAG: RSS by stage and by export size', { timeout: 600000 }, async () => {
  const d = mkdtempSync(join(homedir(), '.mg-diag-')); try {
    const key = join(d, 'k'); execFileSync('age-keygen', ['-o', key], { stdio: 'ignore' }); const pub = execFileSync('age-keygen', ['-y', key], { encoding: 'utf8' }).trim();
    console.log('NODE', process.version, 'platform', process.platform);
    for (const mib of [2, 25, 100]) {
      const src = join(d, `e${mib}.sql`), enc = join(d, `e${mib}.age`); await makeExport(src, mib); await ageEncryptFile({ recipient: pub, src, dst: enc }); rmSync(src);
      for (const variant of ['stream', 'buf']) {
        const r = spawnSync(process.execPath, ['--input-type=module', '-e', CHILD, enc, key, join(d, `p${mib}.sql`), variant], { encoding: 'utf8', timeout: 300000 });
        const j = r.status === 0 ? JSON.parse(r.stdout.trim().split('\n').pop()) : null;
        console.log(`DIAG size=${mib}MiB hash=${variant} status=${r.status} ` + (j ? `sha=${j.sha} peakAfterSha=${j.afterSha.peak} rssAfterSha=${j.afterSha.rss} extAfterSha=${j.afterSha.ext} afterLoad=${j.afterLoad.rss} peakEnd=${j.end.peak}` : r.stderr.slice(0, 300)));
        rmSync(join(d, `p${mib}.sql`), { force: true });
      }
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});
