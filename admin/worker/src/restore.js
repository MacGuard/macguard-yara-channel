import { PROCEDURES, STEPS, PARAMS, PROCEDURE_VERSION, serializeParams } from './restore_procedures.js';

// Recovery status for the panel, built only from real public records: the GitHub Actions runs and jobs of backup.yml, the public trust policy (gateway/environments/backup-trust.json), the presence of the verifier
// tools in the repository and, when it exists, the append-only evidence file evidence/backups.jsonl. Nothing is estimated and nothing is assumed:
//   VERIFIED  a real record proves it, with its date and source      FAILED   a real record proves it did not work
//   STALE     it worked once but the record is older than STALE_HOURS  NOT_RUN  the operation has never been executed (or was skipped)
//   UNKNOWN   no record can answer from here (e.g. the owner's machine, the providers' consoles): the panel never fills the gap
// A copy that exists in a bucket is never "recoverable" by itself: `recoverable` is PROVEN only by a restore record, AUTHENTICATED when CI read it back from the provider and verified it, otherwise NOT_VERIFIED.

export const STATES = ['VERIFIED', 'FAILED', 'STALE', 'UNKNOWN', 'NOT_RUN'];
export const PROVIDERS = ['b2', 'scaleway', 'r2'];
export const STALE_HOURS = 36;            // the workflow runs daily (03:23 UTC); a day and a half without a good run is stale
export const CACHE_SECONDS = 120;
const HOUR = 3600000;
const iso = (ms) => new Date(ms).toISOString();
const ms = (s) => { const x = Date.parse(s); return Number.isFinite(x) ? x : null; };
const secs = (a, b) => { const x = ms(a), y = ms(b); return x !== null && y !== null && y >= x ? Math.round((y - x) / 1000) : null; };

const jobsOf = (jobs) => {
  const by = {}; for (const j of jobs || []) by[j.name] = j;
  const prov = (kind, p) => by[`${kind} (${p})`] || null;
  const export_ = by.export || null, signStep = export_ && (export_.steps || []).find((s) => /^Sign ANCHOR\.json/.test(s.name));
  return { by, export: export_, sign: signStep || null, redundancy: by.redundancy || null, selftest: by.selftest || null, fetch: (p) => prov('fetch', p), write: (p) => prov('write', p), read: (p) => prov('read', p) };
};

/** One run, classified. `jobs` may be null when GitHub could not be asked (the run is then only a bare record). */
export function classifyRun(run, jobs) {
  const j = jobs ? jobsOf(jobs) : null;
  const kind = !j ? 'unknown' : j.selftest && j.selftest.conclusion === 'success' && (!j.export || j.export.conclusion === 'skipped') ? 'selftest' : j.export && j.export.conclusion !== 'skipped' ? 'backup' : 'skipped';
  const done = run.status === 'completed';
  const jr = (job) => (!job ? null : job.status !== 'completed' ? 'running' : job.conclusion);
  const out = { id: run.id, url: run.html_url, event: run.event, created_at: run.created_at, finished_at: done ? run.updated_at : null, status: run.status, conclusion: run.conclusion, kind,
    export: j ? jr(j.export) : null, signed: j && j.sign ? (j.sign.conclusion === 'success') : null, redundancy: j ? jr(j.redundancy) : null, providers: {} };
  for (const p of PROVIDERS) out.providers[p] = { fetch: j ? jr(j.fetch(p)) : null, write: j ? jr(j.write(p)) : null, read: j ? jr(j.read(p)) : null, read_at: j && j.read(p) && j.read(p).completed_at || null, write_at: j && j.write(p) && j.write(p).completed_at || null };
  return out;
}

const ind = (id, state, value, observed_at, source, note = '') => ({ id, state, value, observed_at: observed_at || null, source, note });

/** inputs: {runs, jobs (run id -> jobs array), evidence (parsed records) or null, trust or null, tools [{path, present}] or null}. Any may be null when its source could not be read. */
export function buildRecoveryStatus(inputs, nowMs) {
  const runs = (inputs.runs || []).slice().sort((a, b) => ms(b.created_at) - ms(a.created_at)).map((r) => classifyRun(r, inputs.jobs && inputs.jobs[r.id] ? inputs.jobs[r.id] : null));
  const backups = runs.filter((r) => r.kind === 'backup'), evidence = inputs.evidence || [], trust = inputs.trust || null;
  const last = backups[0] || null, lastExportOk = backups.find((r) => r.export === 'success') || null, lastSigned = backups.find((r) => r.signed === true) || null;
  const fresh = (at) => at && nowMs - ms(at) <= STALE_HOURS * HOUR;
  const verifiedState = (r) => (!r ? null : fresh(r.finished_at || r.created_at) ? 'VERIFIED' : 'STALE');
  const src = (r) => (r ? `GitHub Actions run ${r.id}` : 'GitHub Actions: backup.yml');

  const indicators = [];
  // 1-2. last backup created / last signed
  if (!backups.length) { indicators.push(ind('last_backup', 'NOT_RUN', null, null, 'GitHub Actions: backup.yml', 'no real backup run exists yet')); indicators.push(ind('last_signed', 'NOT_RUN', null, null, 'GitHub Actions: backup.yml', 'no backup has been signed yet')); }
  else {
    indicators.push(lastExportOk ? ind('last_backup', verifiedState(lastExportOk), lastExportOk.id, lastExportOk.finished_at, src(lastExportOk), last.id !== lastExportOk.id ? `the latest attempt (run ${last.id}) ended ${last.conclusion || last.status}` : '') : ind('last_backup', 'FAILED', null, last.finished_at || last.created_at, src(last), `every backup attempt failed; the latest ended ${last.conclusion || last.status} at job export`));
    indicators.push(lastSigned ? ind('last_signed', verifiedState(lastSigned), lastSigned.id, lastSigned.finished_at, src(lastSigned), 'the Sigstore signature and its verification are one workflow step: nothing is published unless it verified') : ind('last_signed', lastExportOk ? 'FAILED' : 'NOT_RUN', null, null, src(last), 'no backup run reached the signing step'));
  }
  // 3. checkpoint: produced in CI vs confirmed outside
  indicators.push(lastSigned ? ind('checkpoint_produced', verifiedState(lastSigned), lastSigned.id, lastSigned.finished_at, src(lastSigned), 'signed and verified in the same step; kept one day as an artifact') : ind('checkpoint_produced', 'NOT_RUN', null, null, 'GitHub Actions: backup.yml', ''));
  const cpExt = evidence.filter((e) => e.kind === 'checkpoint_confirmed').sort((a, b) => ms(b.at) - ms(a.at))[0] || null;
  indicators.push(cpExt ? ind('checkpoint_external', fresh(cpExt.at) ? 'VERIFIED' : 'STALE', cpExt.sequence, cpExt.at, 'evidence/backups.jsonl', `confirmed copy: ${cpExt.where || 'unspecified'}`) : ind('checkpoint_external', 'UNKNOWN', null, null, '', 'the durable external copy (Bitwarden note, paper, second person) is held by the owner; no confirmation has been recorded'));
  // 4. last successful restore and RTO
  const restores = evidence.filter((e) => e.kind === 'restore').sort((a, b) => ms(b.at) - ms(a.at)), okRestore = restores.find((e) => e.ok === true) || null;
  indicators.push(okRestore ? ind('last_restore', fresh(okRestore.at) || nowMs - ms(okRestore.at) <= 35 * 24 * HOUR ? 'VERIFIED' : 'STALE', okRestore.stamp || null, okRestore.at, 'evidence/backups.jsonl', `${okRestore.mode === 'real' ? 'real restore' : 'isolated drill'} from ${okRestore.provider || 'unspecified provider'}`) : restores.length ? ind('last_restore', 'FAILED', null, restores[0].at, 'evidence/backups.jsonl', 'only failed restores are recorded') : ind('last_restore', 'NOT_RUN', null, null, '', 'restores need the age identity and run on the owner\'s machine; none is recorded'));
  // 5. RPO / RTO
  indicators.push(lastExportOk ? ind('rpo_observed', fresh(lastExportOk.finished_at) ? 'VERIFIED' : 'STALE', Math.round((nowMs - ms(lastExportOk.finished_at)) / 1000), lastExportOk.finished_at, src(lastExportOk), 'seconds since the newest good backup: the data that a failure right now would lose at most') : ind('rpo_observed', 'UNKNOWN', null, null, '', 'no good backup, so no recovery point exists'));
  const drills = restores.filter((e) => e.ok === true && Number.isFinite(e.duration_s));
  indicators.push(drills.length ? ind('rto_observed', 'VERIFIED', drills[0].duration_s, drills[0].at, 'evidence/backups.jsonl', 'seconds of the latest recorded drill, not a promise') : ind('rto_observed', 'NOT_RUN', null, null, '', 'no timed drill is recorded'));
  // 6. providers
  const providers = {}; let verifiedCopies = 0;
  for (const p of PROVIDERS) {
    const r = backups.find((x) => x.providers[p].write !== null) || null, pr = r && r.providers[p];
    if (!r) providers[p] = { state: 'NOT_RUN', write: null, read: null, observed_at: null, run_id: null, note: 'no backup run has reached the providers yet' };
    else if (pr.write === 'success' && pr.read === 'success') { const st = verifiedState({ finished_at: pr.read_at || r.finished_at, created_at: r.created_at }); providers[p] = { state: st, write: 'success', read: 'success', observed_at: pr.read_at || r.finished_at, run_id: r.id, note: 'written, read back with the provider\'s own READ credential and verified' }; if (st === 'VERIFIED') verifiedCopies++; }
    else providers[p] = { state: pr.write === 'skipped' || pr.write === null ? 'NOT_RUN' : 'FAILED', write: pr.write, read: pr.read, observed_at: pr.read_at || pr.write_at || r.finished_at, run_id: r.id, note: `write ${pr.write || 'not run'}, read ${pr.read || 'not run'}` };
    indicators.push(ind(`provider_${p}`, providers[p].state, null, providers[p].observed_at, providers[p].run_id ? `GitHub Actions run ${providers[p].run_id}` : 'GitHub Actions: backup.yml', providers[p].note));
  }
  indicators.push(ind('copies_verified', verifiedCopies === 3 ? 'VERIFIED' : verifiedCopies === 0 ? (backups.length ? 'FAILED' : 'NOT_RUN') : 'FAILED', verifiedCopies, last ? (last.finished_at || last.created_at) : null, 'GitHub Actions: backup.yml', verifiedCopies === 3 ? 'three independent copies written and read back' : `${verifiedCopies} of 3: never reported as three copies unless all three verified`));
  // 7. signature chain, verifiers, secrets, next test
  indicators.push(lastSigned ? ind('signature_chain', verifiedState(lastSigned), null, lastSigned.finished_at, src(lastSigned), 'the predecessor was chosen among signed statements, sequence and previous-head hash checked in CI; the full chain is re-verified by the verifier on a clean machine') : ind('signature_chain', 'UNKNOWN', null, null, '', 'no Sigstore-signed backup yet; the historical Ed25519 range is frozen at the sequence in the trust policy'));
  const tools = inputs.tools || null;
  indicators.push(tools ? ind('verifiers', tools.every((t) => t.present) ? 'VERIFIED' : 'FAILED', tools.filter((t) => t.present).length, null, 'repository main', tools.every((t) => t.present) ? 'verifier tools are present on main (their tests run in CI; they are not executed here)' : `missing on main: ${tools.filter((t) => !t.present).map((t) => t.path).join(', ')}`) : ind('verifiers', 'UNKNOWN', null, null, 'repository main', 'could not read the repository'));
  indicators.push(ind('secrets', 'UNKNOWN', null, null, '', 'names of environment secrets need repository-admin rights and are never read by the panel; run `sh gateway/tools/set_backup_secrets.sh --report` (values are never shown)'));
  indicators.push(ind('next_backup', 'VERIFIED', null, null, 'backup.yml schedule', 'daily at 03:23 UTC (the workflow cron)'));
  indicators.push(ind('next_drill', 'UNKNOWN', null, null, '', 'no drill schedule exists: run procedure 4 (simulacro) and record it'));

  // inventory: one row per (backup run, provider); the fields only an evidence record can give stay UNKNOWN
  const evByRun = new Map(evidence.filter((e) => e.kind === 'backup').map((e) => [String(e.run_id), e]));
  const inventory = [];
  for (const r of backups.slice(0, 10)) for (const p of PROVIDERS) {
    const pr = r.providers[p], ev = evByRun.get(String(r.id)) || null, rest = restores.find((e) => e.ok === true && e.provider === p && ev && e.stamp === ev.stamp) || null;
    const authenticated = pr.write === 'success' && pr.read === 'success' && r.signed === true;
    inventory.push({ run_id: r.id, run_url: r.url, at: r.finished_at || r.created_at, provider: p, id: ev ? ev.stamp : null, stamp: ev ? ev.stamp : null, sequence: ev ? ev.sequence : null, bytes: ev ? ev.files && ev.files['d1-export.sql.age'] && ev.files['d1-export.sql.age'].bytes : null, sha256: ev ? ev.files && ev.files['d1-export.sql.age'] && ev.files['d1-export.sql.age'].sha256 : null,
      signature_type: r.signed === true ? 'sigstore' : r.signed === false ? 'failed' : null, signer_identity: r.signed === true ? (ev && ev.signer && ev.signer.identity) || (trust && trust.sigstore && trust.sigstore.identity) || null : null,
      sigstore_state: r.signed === true ? 'VERIFIED' : r.signed === false ? 'FAILED' : 'NOT_RUN', transparency_log: ev && ev.signer && ev.signer.tlog_index != null ? { state: 'VERIFIED', index: ev.signer.tlog_index } : { state: 'UNKNOWN', index: null },
      checkpoint_state: r.signed === true ? 'VERIFIED' : 'NOT_RUN', last_download: pr.read === 'success' ? pr.read_at : null, last_restore: rest ? rest.at : null, last_drill: rest ? { ok: true, at: rest.at, duration_s: rest.duration_s ?? null } : null,
      schema_version: ev ? ev.schema_version || null : null, provider_state: pr.write === 'success' && pr.read === 'success' ? 'VERIFIED' : pr.write === 'success' ? 'FAILED' : pr.write === null || pr.write === 'skipped' ? 'NOT_RUN' : 'FAILED',
      recoverable: rest ? 'PROVEN' : authenticated ? 'AUTHENTICATED' : pr.write === 'failure' || pr.read === 'failure' ? 'FAILED' : 'NOT_VERIFIED' });
  }
  if (inputs.runs === null || inputs.runs === undefined) {                                   // GitHub could not be read: absence of evidence is UNKNOWN, never NOT_RUN or FAILED
    const derived = new Set(['last_backup', 'last_signed', 'checkpoint_produced', 'rpo_observed', 'copies_verified', 'signature_chain', ...PROVIDERS.map((p) => `provider_${p}`)]);
    for (const i of indicators) if (derived.has(i.id)) Object.assign(i, { state: 'UNKNOWN', value: null, observed_at: null, note: 'GitHub Actions could not be read just now' });
    for (const p of PROVIDERS) providers[p] = { state: 'UNKNOWN', write: null, read: null, observed_at: null, run_id: null, note: 'GitHub Actions could not be read just now' };
  }
  const policy = trust ? { ed25519: { fingerprint: trust.ed25519 && trust.ed25519.fingerprint, frozen_at_sequence: trust.ed25519 && trust.ed25519.max_sequence, namespaces: trust.ed25519 && trust.ed25519.namespaces }, sigstore: trust.sigstore || null, age_recipient: trust.age_recipient || null } : null;
  return { indicators, providers, inventory, recent_runs: runs.slice(0, 12).map((r) => ({ id: r.id, url: r.url, event: r.event, kind: r.kind, created_at: r.created_at, conclusion: r.conclusion, status: r.status })), policy, tools: tools || [], definitions: { states: STATES, stale_hours: STALE_HOURS, providers: PROVIDERS } };
}

const RECORD_KINDS = new Set(['backup', 'restore', 'checkpoint_confirmed']);
/** evidence/backups.jsonl: one JSON object per line; unknown kinds and malformed lines are skipped, never guessed. */
export function parseEvidence(text) {
  const out = []; for (const line of String(text || '').split('\n')) { if (!line.trim()) continue; try { const o = JSON.parse(line); if (o && typeof o === 'object' && RECORD_KINDS.has(o.kind)) out.push(o); } catch { /* a corrupt line is not evidence */ } } return out;
}

export const VERIFIER_TOOLS = ['gateway/tools/recover_verify.sh', 'gateway/tools/restore_from_run.sh', 'gateway/tools/restore_verify.mjs', 'gateway/tools/backup_anchor.mjs', 'gateway/tools/backup_objstore.mjs', 'gateway/tools/verify_custody.sh'];

/** Reads every source once, in parallel. A source that fails is listed in `unavailable`; the rest is still returned. */
export async function loadRecoveryStatus(env, deps, token, nowMs) {
  const api = env.GITHUB_API || 'https://api.github.com', repo = env.REPO, raw = env.GITHUB_RAW || 'https://raw.githubusercontent.com';
  const gh = { Accept: 'application/vnd.github+json', 'User-Agent': 'macguard-admin', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const unavailable = []; let rate = null;
  const get = async (name, url, headers, { method = 'GET', optional = false } = {}) => {
    try { const r = await deps.fetch(url, { method, headers }); if (r.headers && r.headers.get && r.headers.get('x-ratelimit-remaining') !== null) rate = { remaining: Number(r.headers.get('x-ratelimit-remaining')), limit: Number(r.headers.get('x-ratelimit-limit')) };
      if (!r.ok) { if (!(optional && r.status === 404)) unavailable.push({ source: name, reason: r.status === 403 || r.status === 429 ? 'rate_limited' : `http_${r.status}` }); return null; } return r; }
    catch { unavailable.push({ source: name, reason: 'unreachable' }); return null; }
  };
  const [runsR, trustR, evR, ...toolR] = await Promise.all([
    get('backup_runs', `${api}/repos/${repo}/actions/workflows/backup.yml/runs?per_page=20&exclude_pull_requests=true`, gh),
    get('trust_policy', `${raw}/${repo}/main/gateway/environments/backup-trust.json`, { Accept: 'application/json' }),
    get('evidence', `${raw}/${repo}/main/evidence/backups.jsonl`, { Accept: 'text/plain' }, { optional: true }),
    ...VERIFIER_TOOLS.map((p) => get(`tool:${p}`, `${raw}/${repo}/main/${p}`, { Accept: 'text/plain' }, { method: 'HEAD', optional: true })),
  ]);
  const jsonOf = async (r, name) => { if (!r) return null; try { return await r.json(); } catch { unavailable.push({ source: name, reason: 'malformed' }); return null; } };
  const runsBody = await jsonOf(runsR, 'backup_runs'), trust = await jsonOf(trustR, 'trust_policy');
  let evidence = null; if (evR) { const text = await evR.text(); evidence = text.length > 2_000_000 ? (unavailable.push({ source: 'evidence', reason: 'too_large' }), null) : parseEvidence(text); }
  const runs = (runsBody && runsBody.workflow_runs) || null, jobs = {};
  await Promise.all((runs || []).slice(0, 8).filter((r) => r.status === 'completed' || r.status === 'in_progress').map(async (r) => { const jr = await get(`jobs:${r.id}`, `${api}/repos/${repo}/actions/runs/${r.id}/jobs?per_page=100`, gh); const b = await jsonOf(jr, `jobs:${r.id}`); if (b && Array.isArray(b.jobs)) jobs[r.id] = b.jobs; }));
  const tools = VERIFIER_TOOLS.map((path, i) => ({ path, present: !!toolR[i] }));
  const toolsKnown = !unavailable.some((u) => u.source.startsWith('tool:'));
  const status = buildRecoveryStatus({ runs, jobs, evidence, trust, tools: toolsKnown ? tools : null }, nowMs);
  return { ...status, generated_at: iso(nowMs), rate, unavailable, cache_seconds: CACHE_SECONDS };
}

// ---- audited progress events: the ONLY write the panel offers for recovery, and it records, it does not execute ---------------------------------------------------------------------------------------------
// Typed, allow-listed, bounded. It stores identifiers (procedure, step, a random run id) and the way a step was confirmed: never output text, never a command, never a secret. Executing a recovery is done by the
// operator on their own machine; there is no endpoint that runs anything.
export const EVENTS = ['procedure_started', 'step_done', 'step_failed', 'procedure_completed', 'procedure_abandoned'];
export const VIA = ['output', 'attest', 'none'];
export function validateEvent(body, role) {
  const bad = (m, status = 400) => ({ ok: false, status, error: m });
  if (!body || typeof body !== 'object' || Array.isArray(body)) return bad('a JSON object is required');
  const allowed = new Set(['event', 'procedure', 'step', 'run', 'via']); for (const k of Object.keys(body)) if (!allowed.has(k)) return bad(`unknown field ${k}`);
  if (!EVENTS.includes(body.event)) return bad('unknown event');
  const proc = PROCEDURES[body.procedure]; if (!proc) return bad('unknown procedure');
  if (!/^[A-Za-z0-9-]{8,64}$/.test(String(body.run || ''))) return bad('invalid run id');
  const rank = { VIEWER: 1, REVIEWER: 2, ADMIN: 3 }[role] || 0;
  if (rank < (proc.protected ? 3 : 2)) return bad(proc.protected ? 'a protected recovery procedure needs the ADMIN role' : 'reviewer role required', 403);
  const needsStep = body.event === 'step_done' || body.event === 'step_failed';
  if (needsStep) { if (!proc.steps.includes(body.step) || !STEPS[body.step]) return bad('unknown step for this procedure'); } else if (body.step !== undefined) return bad('this event takes no step');
  if (body.event === 'step_done') {
    const kind = STEPS[body.step].check.kind; if (kind === 'none' ? body.via !== 'none' : body.via !== kind) return bad(`this step is confirmed by "${kind}", not by "${body.via}"`);
  } else if (body.via !== undefined) return bad('this event takes no confirmation method');
  const detail = { run: body.run, ...(needsStep ? { step: body.step } : {}), ...(body.event === 'step_done' ? { via: body.via } : {}), procedure_version: 1 };
  return { ok: true, action: `restore.${body.event}`, target: body.procedure, detail };
}

/** The runbook as JSON for signed-in REVIEWER/ADMIN users (it is not a public asset). Regular expressions travel as {source, flags}. */
export const procedureBundle = () => ({ version: PROCEDURE_VERSION, params: serializeParams(PARAMS), steps: STEPS, procedures: PROCEDURES });
