// Every source, whatever its family, in one table with one format: YARA repositories and the sources of every other family. Opening a row shows its metadata, its own chart, its downloads,
// quarantine and publication counts, its errors and its recent events. Adding or retiring a source is a request that an administrator decides (the Worker never fetches a typed address); a
// retirement or any sensitive action asks for a reason and a confirmation. Nothing here is invented: a column with no data says so.
import { t, has } from '../i18n.js';
import { h, icon, put, fmtDateTime, copyButton, modal, reasonField, toast, bytes, pillGroup, can } from '../ui.js';
import { api, failure } from '../api.js';
import { loadOps, freshness, ago } from './ops.js';
import { proposalsSection } from './proposals.js';
import { chart } from './charts.js';

const FAMILIES = ['yara', 'suricata', 'sigma', 'ioc', 'hash', 'cve', 'epss', 'kev', 'attack', 'advisory'], FORMATS = ['json', 'csv', 'xml', 'rss', 'text', 'api', 'git', 'other'], AUTHS = ['none', 'api_key', 'unknown'];
const rid = () => `ui_${crypto.randomUUID().replace(/-/g, '')}`;
const famName = (f) => (has(`ix_f_${f}`) ? t(`ix_f_${f}`) : f);
const num = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'es-ES'));
const okUrl = (u) => typeof u === 'string' && /^https?:\/\/[^\s]+$/.test(u);
const link = (u, text) => (okUrl(u) ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer' }, text || u, icon('external')) : h('span', { text: u || '—' }));
const kv = (rows) => h('dl', { class: 'kv kv-tight' }, ...rows.filter(Boolean).flatMap(([k, v]) => [h('dt', { text: k }), h('dd', {}, v)]));
const RUN_CHIP = { COMPLETE: 'chip chip-ok', PARTIAL: 'chip chip-warn', FAILED: 'chip chip-bad', SYNCED: 'chip chip-ok', STALE: 'chip chip-warn' };
const runLabel = (st) => (st === 'SYNCED' ? t('sr_synced') : st === 'STALE' ? t('sr_stale') : has(`ix_run_${st}`) ? t(`ix_run_${st}`) : st);
const INT_CHIP = { CONNECTED: 'chip chip-ok', BLOCKED: 'chip chip-bad', NOT_INTEGRATED: 'chip' };

/** One row model for both kinds of source, so that the table, the sheet and the filters do not care where a source comes from. */
export function unify({ yara, intel, queue }) {
  const rows = [];
  for (const s of yara || []) { const fresh = s.fetched_at && Date.now() - Date.parse(s.fetched_at) < 72 * 3600 * 1000; rows.push({ key: `yara:${s.id}`, id: s.id, name: s.id, org: s.repo, family: 'yara', origin: 'yara', integration: 'CONNECTED', kind: s.kind, lastAt: s.fetched_at || null, runState: s.commit ? (fresh ? 'SYNCED' : 'STALE') : null, records: null, quarantined: (queue || {})[s.id] ?? null, url: `https://github.com/${s.repo}`, raw: s }); }
  for (const s of intel || []) { const r = s.latest_run; rows.push({ key: `intel:${s.id}`, id: s.id, name: s.name, org: s.organization, family: s.family, origin: 'intel', integration: s.integration, lastAt: r ? r.retrieved_at : null, runState: r ? r.state : null, records: s.records, quarantined: r ? r.retained : null, url: s.url, raw: s }); }
  return rows.sort((a, b) => (a.family === 'yara' ? -1 : b.family === 'yara' ? 1 : a.family.localeCompare(b.family)) || a.name.localeCompare(b.name));
}

function requestDialog(ctx, preset) {
  const f = (id, label, node, hint) => h('div', { class: 'field' }, h('label', { for: id, text: label }), node, hint ? h('p', { class: 'note', text: hint }) : null);
  const sel = (id, opts, val, lab) => { const s = h('select', { class: 'input', id }, ...opts.map((o) => h('option', { value: o, text: lab(o) }))); s.value = val; return s; };
  const retire = !!preset && preset.kind === 'RETIRE';
  const name = h('input', { class: 'input', id: 'sq-name', maxlength: '80', autocomplete: 'off', value: preset ? preset.name : '' }), url = h('input', { class: 'input', id: 'sq-url', type: 'url', autocomplete: 'off', spellcheck: 'false', placeholder: 'https://', value: preset && preset.url && okUrl(preset.url) ? preset.url : '' });
  const fam = sel('sq-fam', FAMILIES, preset ? preset.family : 'ioc', famName), fmt = sel('sq-fmt', FORMATS, 'json', (x) => t(`sq_fmt_${x}`)), auth = sel('sq-auth', AUTHS, 'none', (x) => t(`ix_auth_${x}`));
  const lic = h('input', { class: 'input', id: 'sq-lic', maxlength: '500', autocomplete: 'off' }), reason = reasonField();
  const body = h('div', { class: 'grid-12' }, h('p', { class: 'alert alert-info' }, icon('info'), t(retire ? 'sq_retire_note' : 'sq_note')), f('sq-name', t('sq_name'), name), f('sq-url', t('sq_url'), url, t('sq_url_hint')), f('sq-fam', t('ix_d_family'), fam), retire ? null : f('sq-fmt', t('sq_format'), fmt), retire ? null : f('sq-auth', t('ix_h_auth'), auth), retire ? null : f('sq-lic', t('sq_license'), lic), reason.node);
  modal({ title: t(retire ? 'sq_retire_h' : 'sq_add_h', { name: preset ? preset.name : '' }), body, confirmLabel: t(retire ? 'sq_retire' : 'sq_add'), variant: retire ? 'bad' : 'primary',
    validate: () => (name.value.trim().length < 2 ? t('sq_name_short') : !/^https:\/\//.test(url.value.trim()) ? t('sq_url_bad') : reason.value.length < 5 ? t('reason_short') : null),
    async submit() {
      const b = { request_id: rid(), kind: retire ? 'RETIRE' : 'ADD', ...(retire ? { target_source: preset.id } : {}), family: fam.value, name: name.value.trim(), url: url.value.trim(), format: retire ? 'other' : fmt.value, auth: retire ? 'unknown' : auth.value, ...(lic.value.trim() ? { license_note: lic.value.trim() } : {}), reason: reason.value };
      const r = await api('POST', '/api/source-requests', b); if (r.status === 200) { toast(t('sq_done')); ctx.rerender(); return null; } return t('failed', { msg: failure(r, t('err_generic')) });
    } });
}

function requestsSection(ctx, items, canDecide) {
  const done = (r, ok) => { if (r.status === 200) { toast(ok); ctx.rerender(); return null; } return t('failed', { msg: failure(r, t('err_generic')) }); };
  const decideDialog = (q, op) => { const reason = reasonField(); modal({ title: t(`sq_${op}_h`, { name: q.name }), body: h('div', { class: 'grid-12' }, h('p', { class: 'note', text: t(`sq_${op}_p`) }), reason.node), confirmLabel: t(`sq_${op}`), variant: op === 'accept' ? 'ok' : 'bad', validate: () => (reason.value.length < 5 ? t('reason_short') : null),
    async submit() { return done(await api('POST', `/api/source-requests/${q.id}/${op}`, { reason: reason.value, expect_version: q.version }), t(`sq_${op}_done`)); } }); };
  const rows = items.map((q) => h('tr', {}, h('td', {}, h('strong', { text: q.name }), h('div', { class: 'faint', text: q.kind === 'RETIRE' ? `${t('sq_kind_RETIRE')} · ${q.target_source}` : t('sq_kind_ADD') })), h('td', { text: famName(q.family) }), h('td', { class: 'clip', title: q.url }, link(q.url, q.url.replace(/^https:\/\//, ''))),
    h('td', {}, h('span', { class: q.state === 'REQUESTED' ? 'chip chip-warn' : q.state === 'ACCEPTED' ? 'chip chip-ok' : 'chip', text: t(`sq_state_${q.state}`) })), h('td', { class: 'nowrap', text: `${q.requested_by} · ${fmtDateTime(q.requested_at)}` }), h('td', { class: 'clip', title: q.reason, text: q.decision_reason || q.reason }),
    h('td', {}, q.state === 'REQUESTED' ? h('div', { class: 'flex-8' }, canDecide ? h('button', { type: 'button', class: 'btn btn-sm btn-ok', onclick: () => decideDialog(q, 'accept') }, t('sq_accept')) : null, canDecide ? h('button', { type: 'button', class: 'btn btn-sm', onclick: () => decideDialog(q, 'reject') }, t('sq_reject')) : null, h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onclick: () => decideDialog(q, 'cancel') }, t('sq_cancel'))) : null)));
  return h('section', { class: 'card minw0', 'aria-labelledby': 'h-sq' }, h('h2', { id: 'h-sq', text: t('sq_h') }), h('p', { class: 'note', text: t('sq_lead') }),
    items.length ? h('div', { class: 'dt-wrap', role: 'region', tabindex: '0', 'aria-label': t('sq_h') }, h('table', { class: 'dt' }, h('caption', { class: 'sr', text: t('sq_h') }), h('thead', {}, h('tr', {}, ...['sq_c_source', 'ix_d_family', 'sq_c_url', 'ix_c_state', 'sq_c_by', 'sq_c_reason', ''].map((k) => h('th', { scope: 'col', text: k ? t(k) : '' })))), h('tbody', {}, ...rows))) : h('p', { class: 'nodata', text: t('sq_none') }));
}

export async function renderSources(ctx) {
  const { root, me } = ctx, canAsk = can(me, 'sources.propose'), isAdmin = can(me, 'sources.review');
  const head = (extra) => h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('sr_title_all') }), h('p', { text: t('sr_lead_all') })), h('div', { class: 'actions' }, extra, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh'))));
  put(root, head(null), h('div', { class: 'skeleton sk-block', 'aria-hidden': 'true' }));
  const [ops, stats, isrc, reqs] = await Promise.all([loadOps(), api('GET', '/api/stats'), can(me, 'intel.sources.read') ? api('GET', '/api/intel/sources') : Promise.resolve(null), can(me, 'sources.requests.read') ? api('GET', '/api/source-requests') : Promise.resolve(null)]);
  const inq = (stats.status === 200 && stats.data.sources) || {};
  if (!ops.ok) { put(root, head(null), h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), `${t('db_ops_fail')} ${ops.error}`)); return; }
  const o = ops.data, rows = unify({ yara: o.sources, intel: isrc && isrc.status === 200 ? isrc.data.sources : [], queue: inq });
  const add = canAsk ? h('button', { type: 'button', class: 'btn btn-primary btn-sm', onclick: () => requestDialog(ctx, null) }, icon('plus'), t('sq_new')) : null;
  const f = { family: '' }, tbody = h('tbody', {}), sheet = h('aside', { class: 'sheet-side', 'aria-label': t('sr_sheet'), hidden: true }); let selected = null;
  const famCounts = {}; for (const r of rows) famCounts[r.family] = (famCounts[r.family] || 0) + 1;
  const fam = pillGroup(t('ix_d_family'), [['', t('all'), rows.length], ...Object.keys(famCounts).map((x) => [x, famName(x), famCounts[x]])], f.family, (v) => { f.family = v; fam.redraw(v); drawRows(); });

  const open = async (r, tr) => {
    if (selected) selected.setAttribute('aria-selected', 'false'); selected = tr; tr.setAttribute('aria-selected', 'true'); sheet.hidden = false; put(sheet, h('div', { class: 'skeleton sk-block' }));
    const close = h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-label': t('close') }, icon('x')); close.addEventListener('click', () => { sheet.hidden = true; tr.setAttribute('aria-selected', 'false'); tr.focus(); });
    const s = r.raw, od = o.latest.observed_day, out = [h('div', { class: 'flex-between' }, h('h2', { id: 'sr-sheet-title', text: r.name }), close)];
    if (r.origin === 'intel') {
      const runs = await api('GET', `/api/intel/runs?source=${encodeURIComponent(s.id)}&limit=50`), list = runs.status === 200 ? runs.data.items.slice().reverse() : [];
      const latest = s.latest_run, failed = list.filter((x) => x.state === 'FAILED').length, partial = list.filter((x) => x.state === 'PARTIAL').length;
      out.push(kv([[t('ix_d_family'), famName(s.family)], [t('ix_h_integration'), h('span', { class: INT_CHIP[s.integration] || 'chip', text: has(`ix_int_${s.integration}`) ? t(`ix_int_${s.integration}`) : s.integration })], s.status_reason ? [t('sr_why'), has(`ix_why_${s.status_reason}`) ? t(`ix_why_${s.status_reason}`) : s.status_reason] : null,
        [t('ix_h_auth'), has(`ix_auth_${s.auth}`) ? t(`ix_auth_${s.auth}`) : s.auth], [t('ix_d_url'), link(s.url)], [t('sr_license'), s.license_id || '—'], [t('ix_d_redistribution'), s.redistribution || '—'], [t('sr_adapter'), s.adapter ? `${s.adapter} ${s.adapter_version || ''}` : t('sr_noadapter')]]));
      out.push(h('h3', { text: t('sr_numbers') }), kv([[t('sr_runs'), `${num(list.length)} (${t('sr_failed_n', { n: failed })}, ${t('sr_partial_n', { n: partial })})`], [t('ix_h_records'), num(s.records)], [t('sr_last'), latest ? `${fmtDateTime(latest.retrieved_at)} · ${latest.http_status ?? '—'} · ${latest.bytes === null ? '—' : bytes(latest.bytes)}` : t('ix_never')],
        [t('sr_acc_rej'), latest ? `${num(latest.accepted)} / ${num(latest.rejected)} / ${num(latest.duplicates)}` : '—'], [t('sr_ret_app_pub'), latest ? `${num(latest.retained)} / ${num(latest.approved)} / ${num(latest.published)}` : '—']]));
      const pts = list.filter((x) => x.retrieved_at);
      out.push(pts.length ? chart({ title: t('sr_chart'), labels: pts.map((x) => x.retrieved_at.slice(0, 10)), series: [{ name: t('rl_accepted'), cls: 'c-info', values: pts.map((x) => x.accepted) }, { name: t('rl_rejected'), cls: 'c-bad', values: pts.map((x) => x.rejected) }] }) : h('p', { class: 'nodata', text: t('sr_nochart') }));
      if (latest && latest.blocking.length) out.push(h('h3', { text: t('sr_errors') }), h('ul', { class: 'in-causes' }, ...latest.blocking.map((b) => h('li', { text: b }))));
      out.push(h('div', { class: 'actions' }, h('a', { class: 'btn btn-sm', href: `#/quarantine?fam=other&source=${encodeURIComponent(s.id)}` }, t('sr_see_records')), h('a', { class: 'btn btn-sm', href: `#/logs?source_id=${encodeURIComponent(s.id)}` }, t('sr_see_logs'))));
    } else {
      out.push(kv([[t('ix_d_family'), famName('yara')], [t('sr_repo'), link(`https://github.com/${s.repo}`, s.repo)], [t('sr_commit'), s.commit ? h('span', { class: 'sha' }, h('a', { class: 'mono', href: `https://github.com/${s.repo}/commit/${s.commit}`, target: '_blank', rel: 'noopener noreferrer', text: s.commit.slice(0, 10) }), copyButton(s.commit, t('copy'))) : t('nodata')],
        [t('sr_fetched'), s.fetched_at ? `${fmtDateTime(s.fetched_at)} · ${ago(s.fetched_at)}` : t('nodata')], [t('sr_paths'), s.paths.length ? h('span', { class: 'reasons' }, ...s.paths.map((p) => h('span', { class: 'chip mono', text: p }))) : t('sr_nopaths')], s.kind === 'rules' ? [t('sr_inq'), String(inq[s.id] || 0)] : null]),
      od ? kv([[t('kpi_observed'), od.date], [t('rl_examined'), String(od.examined)], [t('rl_accepted'), String(od.accepted)], [t('rl_quarantined'), String(od.quarantined ?? '—')], [t('rl_rejected'), String(od.rejected)]]) : null,
      h('p', { class: 'note', text: t('sr_yara_numbers') }), h('div', { class: 'actions' }, h('a', { class: 'btn btn-sm', href: `#/quarantine?source=${encodeURIComponent(s.id)}` }, t('sr_see_records')), h('a', { class: 'btn btn-sm', href: '#/activity' }, t('sr_see_activity'))));
    }
    if (canAsk) out.push(h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm btn-bad', onclick: () => requestDialog(ctx, { kind: 'RETIRE', id: s.id, name: r.name, family: r.family, url: r.url }) }, icon('x'), t('sq_retire'))), h('p', { class: 'note', text: t('sq_retire_note') }));
    put(sheet, ...out); sheet.setAttribute('aria-labelledby', 'sr-sheet-title');
  };
  const cols = ['sr_c_source', 'ix_d_family', 'ix_h_integration', 'sr_c_last', 'ix_c_state', 'ix_h_records', 'sr_c_quarantined'];
  const drawRows = () => {
    put(tbody, ...rows.filter((r) => !f.family || r.family === f.family).map((r) => {
      const tr = h('tr', { tabindex: '0', 'aria-selected': 'false', 'data-source': r.key }, h('th', { scope: 'row' }, h('strong', { text: r.name }), h('div', { class: 'faint', text: r.org || '' })), h('td', { text: famName(r.family) }),
        h('td', {}, r.origin === 'yara' ? h('span', { class: 'chip', text: has(`sk_${r.kind}`) ? t(`sk_${r.kind}`) : r.kind }) : h('span', { class: INT_CHIP[r.integration] || 'chip', text: has(`ix_int_${r.integration}`) ? t(`ix_int_${r.integration}`) : r.integration })), h('td', { class: 'nowrap', text: r.lastAt ? `${fmtDateTime(r.lastAt)} · ${ago(r.lastAt)}` : t('ix_never') }),
        h('td', {}, r.runState ? h('span', { class: RUN_CHIP[r.runState] || 'chip', text: runLabel(r.runState) }) : h('span', { class: 'nodata', text: t('nodata') })), h('td', { class: 'num', text: num(r.records) }), h('td', { class: 'num', text: num(r.quarantined) }));
      const go = () => open(r, tr); tr.addEventListener('click', go); tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } }); return tr;
    }));
  };
  drawRows();
  const table = h('div', { class: 'dt-wrap', role: 'region', 'aria-label': t('sr_title_all'), tabindex: '0' }, h('table', { class: 'dt dt-sel' }, h('caption', { class: 'sr', text: t('sr_title_all') }), h('thead', {}, h('tr', {}, ...cols.map((k) => h('th', { scope: 'col', class: ['ix_h_records', 'sr_c_quarantined'].includes(k) ? 'num' : '', text: t(k) })))), tbody));
  const proposals = await proposalsSection(ctx);   // GitHub rule repositories, when that feature is on
  put(root, head(add), freshness(o), h('div', { class: 'filter-row' }, h('span', { class: 'fl', text: t('ix_d_family') }), fam), h('div', { class: 'master-detail' }, h('div', { class: 'minw0' }, table, h('p', { class: 'note', text: t('sr_legend_all') })), sheet), reqs && reqs.status === 200 ? requestsSection(ctx, reqs.data.items, isAdmin) : null, proposals, h('p', { class: 'alert alert-info' }, icon('info'), t('sr_split_note')));
  root.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !sheet.hidden) { sheet.hidden = true; if (selected) { selected.setAttribute('aria-selected', 'false'); selected.focus(); } } });
}
