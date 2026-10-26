// Charts and summaries over the REAL promoted intelligence (from /api/intel/stats). Every chart says its period, unit, source, last update, scope and coverage; a series is drawn only
// from stored facts (a point per real run), never extrapolated from a current count.
import { t, has } from '../i18n.js';
import { h, icon, fmtDateTime, can } from '../ui.js';
import { api } from '../api.js';
import { chart } from './charts.js';

const num = (n) => Number(n).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'es-ES');
const fam = (f) => (has(`ix_f_${f}`) ? t(`ix_f_${f}`) : f);
export const loadIntelStats = async (me) => { if (!can(me, 'intel.sources.read')) return null; const r = await api('GET', '/api/intel/stats'); return r.status === 200 ? r.data : { error: r.status === 503 ? 'unbound' : 'unreadable' }; };

function caption(st, unit, coverage) {
  const from = (st.runs.first_run || '').slice(0, 10), to = (st.runs.last_run || '').slice(0, 10);
  return h('p', { class: 'chart-meta note' }, `${t('cm_period')}: ${from} → ${to} · ${t('cm_unit')}: ${unit} · ${t('cm_source')}: D1 macguard-intel · ${t('cm_updated')}: ${fmtDateTime(st.generated_at)} · ${t('cm_scope')}: ${t('cm_scope_v')} · ${t('cm_coverage')}: ${coverage}`);
}

/** Three charts: records per family, validation verdicts of the rules, and what each real download yielded. */
export function intelCharts(st) {
  if (!st || st.error) return h('section', { class: 'card' }, h('h2', { text: t('ic_title') }), h('p', { class: st && st.error === 'unbound' ? 'alert alert-warn' : 'alert alert-bad', role: 'status' }, icon('alert'), t(st && st.error === 'unbound' ? 'ix_unbound' : 'ic_unreadable')));
  if (!st.runs.n) return h('section', { class: 'card' }, h('h2', { text: t('ic_title') }), h('p', { class: 'nodata', text: t('ix_scope_none') }));
  const fams = st.by_family.map((x) => x.family), cov = t('cm_cov_v', { n: st.runs.n });
  const rules = st.verdicts.filter((v) => ['suricata', 'sigma'].includes(v.family)), rf = ['suricata', 'sigma'];
  const sum = (f, key, val) => rules.filter((v) => v.family === f && v[key] === val).reduce((a, v) => a + v.n, 0);
  const notRun = rf.reduce((a, f) => a + sum(f, 'functional', 'NOT_RUN'), 0), verified = rf.reduce((a, f) => a + rules.filter((v) => v.family === f && v.functional === 'PASS').reduce((x, v) => x + v.n, 0), 0);
  const runs = st.runs.items.filter((r) => r.retrieved_at || r.accepted), runLabels = runs.map((r) => `${r.source_id.replace(/^(abusech|first|cert|emerging|enisa)-?/, '').slice(0, 9)} ${(r.retrieved_at || '').slice(5, 10)}`.trim());
  return h('section', { class: 'card', 'aria-labelledby': 'h-ic' }, h('h2', { id: 'h-ic', text: t('ic_title') }),
    h('div', { class: 'charts' },
      h('div', {}, chart({ title: t('ic_by_family'), labels: fams, series: [{ name: t('ic_records'), cls: 'c-ok', values: st.by_family.map((x) => x.records) }], unit: '', labelFn: fam }), caption(st, t('ic_unit_rec'), cov)),
      h('div', {}, chart({ title: t('ic_verdicts'), labels: rf, series: [{ name: 'VALIDATED', cls: 'c-ok', values: rf.map((f) => sum(f, 'validated', 'VALIDATED')) }, { name: 'FAILED', cls: 'c-bad', values: rf.map((f) => sum(f, 'validated', 'FAILED')) }], unit: '', labelFn: fam }), caption(st, t('ic_unit_rules'), cov),
        h('p', { class: 'note' }, t('ic_functional', { verified: num(verified), notrun: num(notRun) }))),
      h('div', {}, chart({ title: t('ic_runs'), labels: runLabels, series: [{ name: t('rl_accepted'), cls: 'c-ok', values: runs.map((r) => r.accepted) }, { name: t('rl_rejected'), cls: 'c-bad', values: runs.map((r) => r.rejected) }], unit: '', labelFn: (lb) => lb }), caption(st, t('ic_unit_rec'), cov))));
}

/** Held / published per family, for Quarantine and Published: what is retained by policy and what is truly distributed (nothing, today). */
export function retainedTable(st, published) {
  if (!st || st.error) return null;
  const rows = st.by_family.map((x) => h('tr', {}, h('th', { scope: 'row', text: fam(x.family) }), h('td', { class: 'num', text: num(x.records) }), h('td', { class: 'num', text: num(x.held_back || 0) }), h('td', { class: 'num', text: '0' }), h('td', {}, h('a', { href: `#/intel?group=${groupOf(x.family)}&family=${x.family}`, text: t('ix_title') }))));
  return h('section', { class: 'card', 'aria-labelledby': 'h-ret' }, h('h2', { id: 'h-ret', text: t(published ? 'rt_published_h' : 'rt_quarantine_h') }), h('p', { class: 'note', text: t(published ? 'rt_published_p' : 'rt_quarantine_p') }),
    h('div', { class: 'dt-wrap', role: 'region', tabindex: '0', 'aria-label': t('rt_quarantine_h') }, h('table', { class: 'dt' }, h('caption', { class: 'sr', text: t('rt_quarantine_h') }), h('thead', {}, h('tr', {}, ...['ix_d_family', 'ix_h_records', 'rt_held', 'rt_pub', 'ix_d_url'].map((k) => h('th', { scope: 'col', text: k === 'ix_d_url' ? '' : t(k) })))), h('tbody', {}, ...rows))));
}
const groupOf = (f) => ({ suricata: 'detections', sigma: 'detections', ioc: 'indicators', hash: 'indicators', cve: 'vulnerabilities', kev: 'vulnerabilities', advisory: 'vulnerabilities', attack: 'context', epss: 'context' }[f] || 'sources');

/** The real ingestion runs, newest first, for Activity. */
export function runsTable(st) {
  if (!st || st.error || !st.runs.items.length) return null;
  const rows = st.runs.items.slice().reverse().map((r) => h('tr', {}, h('td', { class: 'mono nowrap', text: (r.retrieved_at || '—').replace('T', ' ').replace('Z', '') }), h('td', { text: r.source_id }), h('td', {}, h('span', { class: r.state === 'COMPLETE' ? 'chip chip-ok' : 'chip chip-warn', text: has(`ix_run_${r.state}`) ? t(`ix_run_${r.state}`) : r.state })),
    h('td', { class: 'num', text: num(r.accepted) }), h('td', { class: 'num', text: num(r.rejected) }), h('td', {}, h('a', { href: `#/logs?run_id=${encodeURIComponent(r.id)}`, text: t('lg_title') }))));
  return h('section', { class: 'card', 'aria-labelledby': 'h-runs' }, h('h2', { id: 'h-runs', text: t('ar_title') }), h('p', { class: 'note', text: t('ar_note') }),
    h('div', { class: 'dt-wrap', role: 'region', tabindex: '0', 'aria-label': t('ar_title') }, h('table', { class: 'dt' }, h('caption', { class: 'sr', text: t('ar_title') }), h('thead', {}, h('tr', {}, ...['lg_h_ts', 'ix_c_source', 'ix_h_state', 'rl_accepted', 'rl_rejected', 'lg_title'].map((k) => h('th', { scope: 'col', text: t(k) })))), h('tbody', {}, ...rows))));
}
