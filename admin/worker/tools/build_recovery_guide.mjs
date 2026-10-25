// Builds the OFFLINE recovery package from the same data the panel serves: one self-contained HTML guide (no network, no backend, inline script and style pinned by hash in a CSP), a README with how to verify its origin,
// the public trust policy, the hashes of the verifier tools at this commit, and SHA256SUMS (the file that is signed with Sigstore by .github/workflows/recovery-guide.yml). It contains no secret and reads none.
//   node tools/build_recovery_guide.mjs OUT_DIR [--commit SHA] [--built ISO_DATE]
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PARAMS, STEPS, PROCEDURES, PROCEDURE_VERSION, serializeParams } from '../src/restore_procedures.js';

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = resolve(HERE, '..', '..', '..'), sha = (b) => createHash('sha256').update(b).digest('hex'), b64 = (b) => createHash('sha256').update(b).digest('base64');
const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const CSS = `:root{color-scheme:light dark;--bg:#fff;--fg:#0c1829;--mut:#44556d;--line:#c9d2de;--acc:#0b5cad;--ok:#116329;--bad:#b3261e;--warn:#7a4a00;--code:#f3f5f9}@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--fg:#e8eef7;--mut:#a9b8cc;--line:#2c3a52;--acc:#7db8ff;--ok:#7ee2a0;--bad:#ff9a92;--warn:#ffd28a;--code:#111b2e}}
body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}main{max-width:980px;margin:0 auto;padding:16px}h1{font-size:1.5rem}.note,small{color:var(--mut)}.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}button,select,input,textarea{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;min-height:44px}button{cursor:pointer;background:var(--acc);color:#fff;border-color:var(--acc)}@media (prefers-color-scheme:dark){button{color:#0b1220}}button.ghost{background:transparent;color:var(--acc)}textarea{width:100%;box-sizing:border-box;font-family:ui-monospace,monospace}
fieldset{border:1px solid var(--line);border-radius:8px;margin:12px 0}.param{display:grid;gap:4px;margin:8px 0}.param input{width:100%;box-sizing:border-box}.step{border:1px solid var(--line);border-radius:8px;margin:10px 0;padding:0 12px}.step>summary{cursor:pointer;display:flex;gap:10px;align-items:center;min-height:48px;font-weight:600}.n{min-width:2em;text-align:center;color:var(--mut)}.tag{margin-left:auto;font-size:.8rem;color:var(--acc)}.is-done>summary .tag{color:var(--ok)}.is-blocked>summary{color:var(--mut)}select{max-width:100%}summary{overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}.warn{color:var(--warn)}.bad{color:var(--bad)}.ok{color:var(--ok)}.risk{border-left:4px solid var(--warn);padding:4px 10px;background:var(--code)}.chk{display:flex;gap:10px;align-items:flex-start;min-height:44px}:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
@media print{.bar button,.bar select{display:none}.step{break-inside:avoid}.step>*{display:block!important}details:not([open])>*{display:block}}`;
export function buildGuide({ commit = 'unknown', built = new Date().toISOString() } = {}) {
  const engineSrc = readFileSync(join(ROOT, 'admin/worker/public/restore/engine.js'), 'utf8').replace(/^export /gm, ''), clientSrc = readFileSync(join(HERE, 'recovery_guide_client.js'), 'utf8');
  const js = `${engineSrc}\n${clientSrc}`;
  const SEP = [String.fromCharCode(0x2028), String.fromCharCode(0x2029)];
  let data = JSON.stringify({ version: PROCEDURE_VERSION, params: serializeParams(PARAMS), steps: STEPS, procedures: PROCEDURES }).replace(/</g, '\\u003c'); for (const c of SEP) data = data.split(c).join('');
  const csp = `default-src 'none'; style-src 'sha256-${b64(CSS)}'; script-src 'sha256-${b64(js)}'; base-uri 'none'; form-action 'none'`;
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${csp}"><title>MacGuard — Guía de recuperación offline / Offline recovery guide</title><style>${CSS}</style></head>
<body><main><h1>MacGuard — Guía de recuperación offline / Offline recovery guide</h1>
<p class="note" id="build">commit ${commit} · ${built} · procedures v${PROCEDURE_VERSION}</p>
<noscript><p>Esta guía necesita JavaScript (sin red). Los procedimientos completos están también en RUNBOOK.md. / This guide needs JavaScript (no network). The full procedures are also in RUNBOOK.md.</p></noscript>
<div id="app" aria-live="polite"></div>
<p class="note" id="foot">Guía offline: no ejecuta nada, no recibe claves y funciona sin red. / Offline guide: it executes nothing, receives no keys and works without a network.</p>
<script type="application/json" id="data">${data}</script>
<script>${js}</script></main></body></html>`;
}
export function runbookMarkdown() {
  const out = ['# MacGuard recovery runbook (generated)', '', 'Generated from the same data as the panel and the offline guide. Commands are POSIX shell, run from the repository root unless stated. No secret appears here: private keys are recovered locally from Bitwarden.', ''];
  for (const p of Object.values(PROCEDURES)) { out.push(`## ${p.title.en} / ${p.title.es}`, '', p.summary.en, '');
    p.steps.forEach((id, i) => { const s = STEPS[id]; out.push(`### ${i + 1}. ${s.title.en} (${id})`, '', `- Goal: ${s.goal.en}`, `- Danger: ${s.danger}${s.gate ? ' · mandatory gate' : ''}`, `- ${s.explain.en}`);
      if (s.command) out.push('', '```sh', s.command, '```', '', `Expected: \`${s.expected.text.replace(/\n/g, ' ⏎ ')}\``, '', `If it fails: ${s.onFail.en}`); out.push(''); }); }
  return out.join('\n') + '\n';
}
function listTools() { const d = join(ROOT, 'gateway/tools'); return readdirSync(d).filter((f) => /\.(mjs|sh)$/.test(f)).sort().map((f) => `${sha(readFileSync(join(d, f)))}  gateway/tools/${f}`); }
if (import.meta.url === `file://${process.argv[1]}`) {
  const out = resolve(process.argv[2] || ''); if (!process.argv[2]) { console.error('usage: build_recovery_guide.mjs OUT_DIR [--commit SHA] [--built ISO_DATE]'); process.exit(2); }
  mkdirSync(join(out, 'trust'), { recursive: true });
  const files = { 'recovery-guide.html': buildGuide({ commit: arg('--commit', 'unknown'), built: arg('--built', new Date().toISOString()) }), 'RUNBOOK.md': runbookMarkdown(), 'trust/backup-trust.json': readFileSync(join(ROOT, 'gateway/environments/backup-trust.json'), 'utf8'), 'trust/verifier-tools.sha256': listTools().join('\n') + '\n' };
  files['README.md'] = `# MacGuard recovery package

Open \`recovery-guide.html\` in any browser, offline. Print it (or "save as PDF") for a paper copy. \`RUNBOOK.md\` is the same content as text.

## Verify where this package came from (do this before trusting it)
1. \`shasum -a 256 -c SHA256SUMS\` must print OK for every file.
2. SHA256SUMS is signed with Sigstore keyless by the workflow \`recovery-guide.yml\` on \`main\`:
   \`cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity https://github.com/MacGuard/macguard-yara-channel/.github/workflows/recovery-guide.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-github-workflow-repository MacGuard/macguard-yara-channel SHA256SUMS\` must print "Verified OK".
3. \`trust/backup-trust.json\` must equal the policy printed in your recovery kit (age recipient, Ed25519 fingerprint, Sigstore identity). \`trust/verifier-tools.sha256\` lists the hashes of the verifier tools of this commit: compare them with the clone you use.

Keep at least two copies outside the Mac and outside the three backup buckets (for example an attachment in the password manager and a printout in another place). Re-verify them when you refresh the package. No secret is in this package, and none must ever be added.
`;
  for (const [f, c] of Object.entries(files)) writeFileSync(join(out, f), c);
  writeFileSync(join(out, 'SHA256SUMS'), Object.keys(files).sort().map((f) => `${sha(readFileSync(join(out, f)))}  ${f}`).join('\n') + '\n');
  console.log(JSON.stringify({ out, files: Object.keys(files).length + 1, guide_sha256: sha(files['recovery-guide.html']) }));
}
