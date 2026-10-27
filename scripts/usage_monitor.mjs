#!/usr/bin/env node
// Independent usage and cost monitor. Runs in GitHub Actions (usage-monitor.yml), NOT in Cloudflare and NOT through D1, so it keeps working when D1 is exhausted. It uses a READ-ONLY Cloudflare
// analytics token (never D1 Write or Workers Admin), compares real consumption with config/usage-limits.json, predicts exhaustion from what was observed, de-duplicates alerts and sends them to Telegram;
// when no channel is configured or delivery fails the job fails, which makes GitHub e-mail the repository administrators (the e-mail fallback needs no secret).
// Usage: node scripts/usage_monitor.mjs [--simulate scenario.json] [--state FILE] [--out FILE]
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

export const LEVELS = ['ok', 'notice', 'warning', 'critical', 'limit'];
const rank = (l) => LEVELS.indexOf(l);
export function levelOf(fraction, th) { return fraction >= th.limit ? 'limit' : fraction >= th.critical ? 'critical' : fraction >= th.warning ? 'warning' : fraction >= th.notice ? 'notice' : 'ok'; }

/** metrics: { id: { used, period } | { unavailable: reason } }. Returns one finding per configured metric, in the configured order. now: Date. */
export function evaluate(metrics, cfg, now = new Date()) {
  const elapsed = (now.getUTCHours() * 3600 + now.getUTCMinutes() * 60 + now.getUTCSeconds()) / 86400, out = [];
  for (const [id, def] of Object.entries(cfg.metrics)) {
    const m = metrics[id]; if (!m || m.unavailable !== undefined || typeof m.used !== 'number') { out.push({ id, label: def.label, level: 'unknown', reason: (m && m.unavailable) || 'not collected' }); continue; }
    const fraction = m.used / def.limit, f = { id, label: def.label, period: def.period, used: m.used, limit: def.limit, fraction, level: levelOf(fraction, cfg.thresholds) };
    if (def.period === 'day' && elapsed >= cfg.predictive.min_elapsed_fraction && fraction < 1) { const projected = m.used / elapsed; f.projected = Math.round(projected); if (projected >= def.limit * cfg.predictive.warn_at_projection && rank(f.level) < rank('warning')) { f.level = 'warning'; f.predictive = true; } }
    out.push(f);
  }
  return out;
}
/** Costs by currency. Confirmed (an invoice), estimated (a quantity times an owner-supplied rate) and pending consolidation are kept apart and never mixed across currencies. */
export function evaluateCosts(lines, cfg) {
  const by = {}; for (const l of lines || []) { const c = (by[l.currency] ||= { confirmed: 0, estimated: 0, pending: 0, lines: 0 }); c[l.kind] = (c[l.kind] || 0) + l.amount; c.lines += 1; }
  const out = [];
  for (const [currency, c] of Object.entries(by)) {
    const th = cfg.costs.currency_thresholds[currency]; const known = c.confirmed + c.estimated, worst = known + c.pending;
    const lv = !th ? 'unknown' : known >= th.containment ? 'containment' : known >= th.critical ? 'critical' : known >= th.warning ? 'warning' : known >= th.notice ? 'notice' : 'ok';
    out.push({ currency, confirmed: round(c.confirmed), estimated: round(c.estimated), pending: round(c.pending), worst_case: round(worst), level: lv, thresholds: th || null, reason: th ? undefined : `no threshold is defined for ${currency}: it is reported, not judged` });
  }
  return out;
}
const round = (x) => Math.round(x * 100) / 100;
const CSEV = { unknown: -1, ok: 0, notice: 1, warning: 2, critical: 3, containment: 4 };

/** Alerts worth sending: a metric/cost is alerted only when its level is HIGHER than the last one alerted for the same period (state: { key: level }). Improving never alerts; the state resets with the day/month key. */
export function dedupe(findings, costs, state, now = new Date()) {
  const day = now.toISOString().slice(0, 10), month = day.slice(0, 7), next = { ...state }, alerts = [];
  for (const f of findings) { if (f.level === 'ok' || f.level === 'unknown') continue; const key = `${f.id}:${f.period === 'month' ? month : day}${f.predictive ? ':predictive' : ''}`; if (rank(f.level) > rank(state[key] || 'ok')) { alerts.push({ kind: 'usage', key, ...f }); next[key] = f.level; } }
  for (const c of costs) { if (c.level === 'ok' || c.level === 'unknown') continue; const key = `cost:${c.currency}:${month}`, prev = state[key]; if (CSEV[c.level] > (prev ? CSEV[prev] : 0)) { alerts.push({ kind: 'cost', key, ...c }); next[key] = c.level; } }
  return { alerts, state: next };
}
const pct = (f) => `${Math.round(f.fraction * 100)} %`;
export function formatAlert(a) {
  const tag = { notice: 'AVISO', warning: 'ALERTA', critical: 'CRÍTICO', limit: 'LÍMITE', containment: 'CONTENCIÓN' }[a.level] || a.level.toUpperCase();
  if (a.kind === 'cost') return `MacGuard ${tag}: gasto en ${a.currency} — confirmado ${a.confirmed}, estimado ${a.estimated}, pendiente de consolidar ${a.pending} (peor caso ${a.worst_case}). Umbrales ${a.currency}: ${JSON.stringify(a.thresholds)}.${a.level === 'containment' ? ' Se contienen operaciones de gasto variable NO esenciales; no se apaga ningún servicio crítico ni se frena la distribución de reglas ya firmadas. Esto no es un límite de facturación.' : ''}`;
  return `MacGuard ${tag}${a.predictive ? ' (predicción)' : ''}: ${a.label} ${a.used.toLocaleString('es-ES')} de ${a.limit.toLocaleString('es-ES')} (${pct(a)})${a.projected ? `; al ritmo actual llegaría a ${a.projected.toLocaleString('es-ES')} a fin de día UTC` : ''}.${a.id.startsWith('d1_') ? ' No ejecutes importaciones ni pruebas masivas contra D1 hasta el reinicio de cuota (00:00 UTC).' : ''}`;
}

// ---- collection (Cloudflare GraphQL Analytics + REST, read-only) ---------------------------------------------------------------------------------------------------------------------------
const GQL = 'https://api.cloudflare.com/client/v4/graphql';
async function gql(fetchImpl, token, query, variables) {
  const r = await fetchImpl(GQL, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ query, variables }) });
  if (!r.ok) throw new Error(`analytics HTTP ${r.status}`); const j = await r.json(); if (j.errors && j.errors.length) throw new Error(String(j.errors[0].message).slice(0, 160)); return j.data.viewer.accounts[0];
}
export async function collect({ fetchImpl = fetch, token, account, now = new Date() }) {
  const day = now.toISOString().slice(0, 10), month = day.slice(0, 7), from = `${day}T00:00:00Z`, to = now.toISOString(), mfrom = `${month}-01T00:00:00Z`, m = {};
  const tryit = async (ids, fn) => { try { Object.assign(m, await fn()); } catch (e) { for (const id of ids) m[id] = { unavailable: String(e.message).slice(0, 120) }; } };
  await tryit(['d1_rows_read', 'd1_rows_written'], async () => { const a = await gql(fetchImpl, token, 'query($acc:String!,$d:Date!){viewer{accounts(filter:{accountTag:$acc}){d1AnalyticsAdaptiveGroups(limit:200,filter:{date_geq:$d,date_leq:$d}){sum{rowsRead rowsWritten}}}}}', { acc: account, d: day }); const g = a.d1AnalyticsAdaptiveGroups; return { d1_rows_read: { used: g.reduce((s, x) => s + x.sum.rowsRead, 0) }, d1_rows_written: { used: g.reduce((s, x) => s + x.sum.rowsWritten, 0) } }; });
  await tryit(['workers_requests'], async () => { const a = await gql(fetchImpl, token, 'query($acc:String!,$f:Time!,$t:Time!){viewer{accounts(filter:{accountTag:$acc}){workersInvocationsAdaptive(limit:100,filter:{datetime_geq:$f,datetime_leq:$t}){sum{requests}}}}}', { acc: account, f: from, t: to }); return { workers_requests: { used: a.workersInvocationsAdaptive.reduce((s, x) => s + x.sum.requests, 0) } }; });
  await tryit(['r2_storage_bytes'], async () => { const a = await gql(fetchImpl, token, 'query($acc:String!,$f:Time!,$t:Time!){viewer{accounts(filter:{accountTag:$acc}){r2StorageAdaptiveGroups(limit:100,filter:{datetime_geq:$f,datetime_leq:$t},orderBy:[datetime_DESC]){max{payloadSize}}}}}', { acc: account, f: from, t: to }); const g = a.r2StorageAdaptiveGroups; return { r2_storage_bytes: { used: g.reduce((s, x) => s + x.max.payloadSize, 0) } }; });
  await tryit(['r2_class_a_ops', 'r2_class_b_ops'], async () => { const a = await gql(fetchImpl, token, 'query($acc:String!,$f:Time!,$t:Time!){viewer{accounts(filter:{accountTag:$acc}){r2OperationsAdaptiveGroups(limit:200,filter:{datetime_geq:$f,datetime_leq:$t}){dimensions{actionType} sum{requests}}}}}', { acc: account, f: mfrom, t: to }); const A = new Set(['ListBuckets', 'PutBucket', 'ListObjects', 'PutObject', 'CopyObject', 'CompleteMultipartUpload', 'CreateMultipartUpload', 'ListMultipartUploads', 'UploadPart', 'UploadPartCopy', 'ListParts', 'PutBucketEncryption', 'PutBucketCors', 'PutBucketLifecycleConfiguration']); let ca = 0, cb = 0; for (const g of a.r2OperationsAdaptiveGroups) { if (/^(Delete|Abort)/.test(g.dimensions.actionType)) continue; (A.has(g.dimensions.actionType) ? (ca += g.sum.requests) : (cb += g.sum.requests)); } return { r2_class_a_ops: { used: ca }, r2_class_b_ops: { used: cb } }; });
  await tryit(['d1_storage_bytes'], async () => { const r = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database?per_page=50`, { headers: { Authorization: `Bearer ${token}` } }); if (!r.ok) throw new Error(`D1 list HTTP ${r.status} (D1 Read is needed for storage)`); const j = await r.json(); return { d1_storage_bytes: { used: j.result.reduce((s, d) => s + (d.file_size || 0), 0) } }; });
  return m;
}

// ---- delivery ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
export async function sendTelegram(fetchImpl, { token, chat }, text) {
  const r = await fetchImpl(`https://api.telegram.org/bot${token}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: chat, text: text.slice(0, 3900), disable_web_page_preview: true }) });
  if (!r.ok) throw new Error(`Telegram HTTP ${r.status}`); return true;
}
/** Runs once. Returns { findings, costs, alerts, delivered, failures, exit }. exit 2 = something critical or a delivery problem: the job fails and GitHub e-mails the administrators. */
export async function run({ cfg, metrics, costLines = [], state = {}, now = new Date(), deliver }) {
  const findings = evaluate(metrics, cfg, now), costs = evaluateCosts(costLines, cfg), d = dedupe(findings, costs, state, now), failures = [], delivered = [];
  for (const a of d.alerts) { const text = formatAlert(a); if (!deliver) { failures.push(`${a.key}: no notification channel configured`); continue; } try { await deliver(text); delivered.push(a.key); } catch (e) { failures.push(`${a.key}: ${String(e.message).slice(0, 80)}`); } }
  const nextState = { ...state }; for (const k of delivered) nextState[k] = d.state[k];   // an alert that could not be delivered is retried next time
  const worst = [...findings.map((f) => rank(f.level)), ...costs.map((c) => (c.level === 'containment' ? 4 : CSEV[c.level]))].reduce((a, b) => Math.max(a, b), 0);
  const exit = failures.length || worst >= rank('critical') ? 2 : 0;
  return { findings, costs, alerts: d.alerts, delivered, failures, state: nextState, containment: costs.some((c) => c.level === 'containment'), exit };
}

async function main(argv) {
  const arg = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  const cfg = JSON.parse(readFileSync(new URL('../config/usage-limits.json', import.meta.url), 'utf8')), statePath = arg('--state'), outPath = arg('--out') || 'usage-report.json', sim = arg('--simulate');
  const state = statePath && existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {};
  let metrics, costLines = [], now = new Date(), deliver = null;
  if (sim) { const s = JSON.parse(readFileSync(sim, 'utf8')); metrics = s.metrics; costLines = s.costs || []; if (s.now) now = new Date(s.now); deliver = async (t) => console.log(`[SIMULATED SEND] ${t}`); }
  else {
    const token = process.env.CLOUDFLARE_ANALYTICS_TOKEN, account = process.env.CLOUDFLARE_ACCOUNT_ID; if (!token || !account) { console.error('CLOUDFLARE_ANALYTICS_TOKEN and CLOUDFLARE_ACCOUNT_ID are required'); return 3; }
    metrics = await collect({ token, account, now }); const tg = { token: process.env.TELEGRAM_BOT_TOKEN, chat: process.env.TELEGRAM_CHAT_ID }; if (tg.token && tg.chat) deliver = (t) => sendTelegram(fetch, tg, t);
  }
  const r = await run({ cfg, metrics, costLines, state, now, deliver });
  writeFileSync(outPath, JSON.stringify({ at: now.toISOString(), findings: r.findings, costs: r.costs, alerts: r.alerts.map((a) => a.key), delivered: r.delivered, failures: r.failures, containment: r.containment }, null, 1)); if (statePath) writeFileSync(statePath, JSON.stringify(r.state));
  for (const f of r.findings) console.log(`${f.level.padEnd(8)} ${f.label}: ${f.level === 'unknown' ? f.reason : `${f.used} / ${f.limit} (${Math.round(f.fraction * 100)} %)${f.projected ? ` projected ${f.projected}` : ''}`}`);
  for (const c of r.costs) console.log(`${c.level.padEnd(8)} cost ${c.currency}: confirmed ${c.confirmed}, estimated ${c.estimated}, pending ${c.pending}`);
  if (r.failures.length) console.error(`DELIVERY PROBLEM: ${r.failures.join('; ')}`); return r.exit;
}
if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(String(e.message || e)); process.exit(1); });
