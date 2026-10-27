// Intelligence: the real inventory of sources (with the latest run each one actually has), and the real records of every family in dense tables with a side sheet. Nothing here is a
// declaration: rows come from /api/intel/*, which reads the promoted, hash-verified data. A source without a run, a family without records and a database that is not bound each say so.
import { t, has } from '../i18n.js';
import { h, icon, put, pillGroup, fmtDateTime, bytes, copyButton } from '../ui.js';
import { api, failure } from '../api.js';
import { recordsBrowser } from './records.js';

export const GROUPS = ['sources', 'detections', 'indicators', 'vulnerabilities', 'context'];
export const FAMILIES = { detections: ['suricata', 'sigma'], indicators: ['ioc', 'hash'], vulnerabilities: ['cve', 'kev', 'advisory'], context: ['attack', 'epss'] };
export const COLS = {
  detections: [['key', 'ix_c_id'], ['title', 'ix_c_name'], ['source_id', 'ix_c_source'], ['severity', 'ix_c_class'], ['validated', 'ix_c_validated'], ['functional', 'ix_c_functional'], ['performance', 'ix_c_perf'], ['state', 'ix_c_state']],
  indicators: [['title', 'ix_c_value'], ['source_id', 'ix_c_source'], ['first_seen', 'ix_c_first'], ['last_seen', 'ix_c_last'], ['state', 'ix_c_state']],
  vulnerabilities: [['key', 'ix_c_id'], ['title', 'ix_c_name'], ['source_id', 'ix_c_source'], ['score', 'ix_c_cvss'], ['first_seen', 'ix_c_published'], ['updated_at', 'ix_c_updated'], ['state', 'ix_c_state']],
  context: [['key', 'ix_c_id'], ['title', 'ix_c_name'], ['severity', 'ix_c_type'], ['score', 'ix_c_score'], ['updated_at', 'ix_c_updated'], ['state', 'ix_c_state']],
};
export const label = (prefix, k) => (has(`${prefix}${k}`) ? t(`${prefix}${k}`) : k);
export const num = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'es-ES'));
const okUrl = (u) => typeof u === 'string' && /^https?:\/\/[^\s]+$/.test(u);
const verdict = (v) => (v === null || v === undefined ? h('span', { class: 'faint', text: '—' }) : h('span', { class: `vd vd-${String(v).toLowerCase().replace(/[^a-z]/g, '')}`, text: v }));
export const stateChip = (s, held) => h('span', { class: s === 'EXPIRED' ? 'chip' : held ? 'chip chip-warn' : 'chip chip-ok', text: s ? label('ix_st_', s) : '—' });

export function cell(r, col) {
  const v = r[col];
  if (col === 'validated' || col === 'functional' || col === 'performance') return h('td', {}, verdict(v));
  if (col === 'state') return h('td', {}, stateChip(v, r.held_back));
  if (col === 'score') return h('td', { class: 'num', text: v === null ? '—' : String(v) });
  if (col === 'first_seen' || col === 'last_seen' || col === 'updated_at') return h('td', { class: 'nowrap', text: v || '—' });
  if (col === 'key') return h('td', { class: 'mono nowrap', text: v });
  return h('td', { class: col === 'title' ? 'clip' : '', title: col === 'title' ? v || '' : null, text: v || '—' });
}

// ---- the side sheet ----
const kv = (rows) => h('dl', { class: 'kv kv-tight' }, ...rows.filter(Boolean).flatMap(([k, v]) => [h('dt', { text: k }), h('dd', {}, v)]));
const sha = (s) => (s ? h('span', { class: 'sha mono' }, String(s).slice(0, 16), copyButton(s, `${t('copy')} SHA-256`)) : '—');
const link = (u, text) => (okUrl(u) ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: text || u }) : h('span', { text: u || '—' }));

export function detailBody(d) {
  const { record: r, run, source } = d, doc = r.doc || {}, fam = r.family, out = [];
  out.push(kv([[t('ix_d_key'), h('span', { class: 'mono', text: r.key })], [t('ix_d_family'), label('ix_f_', fam)], [t('ix_c_state'), stateChip(r.state, r.held_back)], [t('ix_d_updated'), r.updated_at || '—']]));
  if (fam === 'suricata' || fam === 'sigma') {
    const m = doc.matrix_row;
    out.push(h('h3', { text: t('ix_d_quality') }), m ? kv([[t('ix_c_validated'), verdict(m.validated)], [t('ix_c_functional'), verdict(m.functional)], [t('ix_c_perf'), verdict(m.performance)], [t('ix_d_held'), m.held_back === 'True' ? t('yes') : t('no')], [t('ix_d_qstate'), m.quarantine_state || '—'], [t('ix_d_reason'), m.reason || '—']]) : h('p', { class: 'muted', text: t('ix_d_noquality') }));
    if (fam === 'sigma') out.push(kv([[t('ix_c_class'), doc.level || '—'], [t('ix_d_status'), doc.status || '—'], ['ATT&CK', (doc.attack || []).join(', ') || '—'], [t('ix_d_logsource'), JSON.stringify(doc.logsource || {})]]));
    if (fam === 'suricata') out.push(kv([['SID', String(doc.sid ?? '—')], ['rev', String(doc.rev ?? '—')], [t('ix_c_class'), doc.classtype || '—'], [t('ix_d_proto'), `${doc.action || '—'} ${doc.proto || ''}`]]));
    out.push(h('h3', { text: t('ix_d_rule') }), h('pre', { class: 'code', tabindex: '0', 'aria-label': t('ix_d_rule'), text: r.body || t('ix_d_nobody') }));
  } else if (fam === 'ioc') {
    out.push(kv([[t('ix_c_value'), h('span', { class: 'mono', text: doc.value || r.key })], [t('ix_d_type'), doc.type || '—'], [t('ix_d_malware'), doc.malware || '—'], [t('ix_d_status'), doc.status || '—'], [t('ix_c_first'), doc.first_seen || '—'], [t('ix_c_last'), doc.last_online || '—'], [t('ix_d_country'), doc.country || '—'], ['AS', doc.as_name || '—']]));
  } else if (fam === 'attack') {
    out.push(kv([[t('ix_c_name'), doc.name], [t('ix_d_type'), doc.kind], [t('ix_d_tactics'), (doc.tactics || [doc.shortname]).filter(Boolean).join(', ') || '—'], ['STIX', doc.stix_id], [t('ix_d_version'), doc.version || '—'], [t('ix_d_url'), link(doc.url)]]));
  } else if (fam === 'epss') {
    out.push(kv([['EPSS', doc.epss], [t('ix_d_percentile'), doc.percentile], [t('ix_d_model'), doc.model_version], [t('ix_d_date'), doc.score_date]]));
  } else {
    const sev = doc.severity || {}, ids = doc.ids || {}, ex = doc.exploitation || {};
    out.push(h('p', { text: doc.summary || r.title || '' }),
      kv([['CVE', (ids.cve || []).join(', ') || '—'], ['EUVD', (ids.euvd || []).join(', ') || '—'], ['GHSA', (ids.ghsa || []).join(', ') || '—'], [t('ix_c_cvss'), sev.score ? `${sev.score} (CVSS ${sev.version || '?'}, ${sev.rated_by || '?'})` : '—'], [t('ix_d_vector'), sev.vector || '—'], ['EPSS', doc.epss || '—'],
        ['KEV', doc.kev ? `${t('ix_d_kev_due')} ${doc.kev.due_date || '—'} · ${t('ix_d_ransomware')}: ${doc.kev.ransomware_use || '—'}` : '—'], [t('ix_d_exploited'), ex.asserted ? `${t('yes')} — ${ex.basis || ''}` : `${t('no')} — ${ex.basis || ''}`],
        [t('ix_c_published'), (doc.dates || {}).published || (doc.dates || {}).listed || '—'], [t('ix_c_updated'), (doc.dates || {}).updated || '—'], [t('ix_d_assigner'), doc.assigner || '—']]));
    const aff = doc.affected || [];
    if (aff.length) out.push(h('h3', { text: `${t('ix_d_affected')} (${num(doc.affected_total || aff.length)})` }), h('ul', { class: 'in-counts' }, ...aff.slice(0, 15).map((a) => h('li', { text: `${a.vendor || ''} ${a.product || ''} ${a.version && a.version.raw ? '· ' + a.version.raw : ''}`.trim() })), aff.length > 15 ? h('li', { class: 'faint', text: t('ix_d_more', { n: num((doc.affected_total || aff.length) - 15) }) }) : null));
    const refs = (doc.references || []).filter(okUrl);
    if (refs.length) out.push(h('h3', { text: t('ix_d_refs') }), h('ul', { class: 'in-counts' }, ...refs.slice(0, 12).map((u) => h('li', {}, link(u)))));
    if (doc.evidence) out.push(h('h3', { text: t('ix_d_evidence') }), kv([[t('ix_d_file'), doc.evidence.file], ['SHA-256 file', sha(doc.evidence.file_sha256)], ['SHA-256 item', sha(doc.evidence.item_sha256)], [t('ix_d_locator'), doc.evidence.locator], [t('ix_d_retrieved'), doc.evidence.retrieved_at]]));
  }
  out.push(h('h3', { text: t('ix_d_source') }), kv([[t('ix_c_source'), source ? `${source.name} · ${source.organization || ''}` : r.source_id], [t('ix_d_url'), source ? link(source.url) : '—'], [t('ix_d_redistribution'), source && source.redistribution ? source.redistribution : '—']]));
  if (run) out.push(h('h3', { text: t('ix_d_run') }), kv([[t('ix_d_retrieved'), run.retrieved_at || '—'], ['HTTP', run.http_status === null ? '—' : String(run.http_status)], [t('ix_d_bytes'), run.bytes === null ? '—' : bytes(run.bytes)], [t('ix_d_runstate'), run.state], ['SHA-256', sha(run.content_sha256)], [t('ix_d_promoted'), `${run.promoted_by} · ${run.promoted_at}`], [t('ix_d_promo_sha'), sha(run.promotion_sha256)]]),
    run.blocking.length ? h('ul', { class: 'in-causes' }, ...run.blocking.map((b) => h('li', { text: b }))) : null);
  out.push(h('p', { class: 'note', text: `doc SHA-256: ${r.doc_sha256.slice(0, 16)}…` }), h('p', { class: 'note', text: t('ix_d_scope') }));
  return out;
}

export async function renderIntel(ctx) {
  const { root, query, go } = ctx, group = GROUPS.includes(query.get('group')) ? query.get('group') : 'sources';
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('ix_title') }), h('p', { text: t('ix_lead') }))), h('div', { class: 'skeleton sk-block' }));
  const [src, stats, fam] = await Promise.all([api('GET', '/api/intel/sources'), api('GET', '/api/intel/stats'), api('GET', '/api/intel/families')]);
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('ix_title') }), h('p', { text: t('ix_lead') })));
  if (src.status === 503 || (src.status !== 200 && src.data && src.data.code === 'intel_store_unavailable')) { put(root, head, h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('ix_unbound'))); return; }
  if (src.status !== 200) { put(root, head, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(src, t('err_generic')))); return; }
  const sources = src.data.sources, st = stats.status === 200 ? stats.data : null;
  const counts = (g) => (g === 'sources' ? sources.length : sources.filter((s) => s.grp === g).reduce((a, s) => a + s.records, 0));
  const tabs = pillGroup(t('ix_group'), GROUPS.map((g) => [g, t(`ix_g_${g}`), counts(g)]), group, (v) => go(`#/intel?group=${v}`, true));
  const scope = h('p', { class: 'note' }, st && st.runs.last_run ? t('ix_scope', { n: st.runs.n, first: (st.runs.first_run || '').slice(0, 10), last: (st.runs.last_run || '').slice(0, 10) }) : t('ix_scope_none'), ' ', t('ix_scope_note'));
  const body = h('div', { class: 'minw0' });
  put(root, head, h('div', { class: 'field' }, tabs), scope, body);
  document.title = `${t('ix_title')} · MacGuard Quarantine`;
  if (group === 'sources') { put(body, sourcesTable(sources, fam.status === 200 ? fam.data : null)); return; }
  await recordsBrowser(body, { ctx, scope: null, families: FAMILIES[group], cols: COLS[group], query, urlFor: (f) => { const p = new URLSearchParams({ group }); for (const k of ['source', 'state', 'q', 'family']) if (f[k]) p.set(k, f[k]); return `#/intel?${p}`; } });
}

export function sourcesTable(sources, fam) {
  void fam;
  const row = (s) => {
    const r = s.latest_run;
    return h('tr', {}, h('th', { scope: 'row' }, h('strong', { text: s.name }), h('div', { class: 'faint', text: s.organization || '' })),
      h('td', { text: label('ix_f_', s.family) }), h('td', {}, h('span', { class: s.integration === 'CONNECTED' ? 'chip chip-ok' : s.integration === 'BLOCKED' ? 'chip chip-bad' : 'chip', text: label('ix_int_', s.integration) }), s.status_reason ? h('div', { class: 'faint', text: label('ix_why_', s.status_reason) }) : null),
      h('td', { text: label('ix_auth_', s.auth) }),
      h('td', { class: 'nowrap', text: r ? (r.retrieved_at || '—').replace('T', ' ').replace('Z', '') : t('ix_never') }),
      h('td', { class: 'num', text: r ? (r.http_status === null ? '—' : String(r.http_status)) : '—' }), h('td', { class: 'num', text: r && r.bytes !== null ? bytes(r.bytes) : '—' }),
      h('td', { class: 'num', text: r ? `${num(r.accepted)} / ${num(r.rejected)} / ${num(r.duplicates)}` : '—' }),
      h('td', { class: 'num', text: r ? `${num(r.retained)} / ${num(r.approved)} / ${num(r.published)}` : '—' }),
      h('td', {}, r ? h('span', { class: r.state === 'COMPLETE' ? 'chip chip-ok' : 'chip chip-warn', text: label('ix_run_', r.state) }) : '—', r && r.blocking.length ? h('details', { class: 'tight' }, h('summary', { text: t('ix_blocking', { n: r.blocking.length }) }), h('ul', { class: 'in-causes' }, ...r.blocking.map((b) => h('li', { text: b })))) : null),
      h('td', { class: 'num', text: num(s.records) }), h('td', {}, link(s.url, t('ix_official'))), h('td', { class: 'faint', text: t('ix_notscheduled') }));
  };
  const heads = ['ix_h_source', 'ix_d_family', 'ix_h_integration', 'ix_h_auth', 'ix_h_last', 'ix_h_http', 'ix_d_bytes', 'ix_h_arD', 'ix_h_rap', 'ix_h_state', 'ix_h_records', 'ix_d_url', 'ix_h_next'];
  return h('div', {}, h('div', { class: 'dt-wrap', role: 'region', 'aria-label': t('ix_g_sources'), tabindex: '0' }, h('table', { class: 'dt in-wide' }, h('caption', { class: 'sr', text: t('ix_g_sources') }),
    h('thead', {}, h('tr', {}, ...heads.map((k) => h('th', { scope: 'col', text: t(k) })))), h('tbody', {}, ...sources.map(row)))), h('p', { class: 'note', text: t('ix_legend') }));
}
