// Main panel: the few numbers that say whether the channel is healthy, each from a real record, with its freshness. No figure is estimated.
import { t, has } from '../i18n.js';
import { mergeDays, matrix } from './families_agg.js';
import { h, icon, put, fmtDate, fmtDateTime, stateBadge } from '../ui.js';
import { api } from '../api.js';
import { chart } from './charts.js';
import { loadBackupAlerts } from './backup_alerts.js';
import { intelCharts, loadIntelStats } from './intel_summary.js';
import { loadOps, freshness, dayBadge, ago, mmss, eventLabel, STATE_CLASS, STATE_ICON, stateLabel } from './ops.js';

const runState = (r) => (!r ? null : r.status !== 'completed' ? 'RUNNING' : r.conclusion === 'success' ? 'OK' : r.conclusion === 'cancelled' ? 'CANCELLED' : ['failure', 'timed_out', 'startup_failure'].includes(r.conclusion) ? 'FAIL' : 'WARNING');
function kpi({ label, value, sub, href, external, tone, id }) {
  const body = [h('span', { class: 'kpi-label', id, text: label }), h('strong', { class: `kpi-value ${tone ? `tone-${tone}` : ''}`, 'aria-labelledby': id }, value), sub ? h('span', { class: 'kpi-sub' }, sub) : null];
  return h('li', { class: 'kpi' }, href ? h('a', { class: 'kpi-link', href, target: external ? '_blank' : null, rel: external ? 'noopener noreferrer' : null }, body, external ? icon('external') : null) : h('div', { class: 'kpi-link' }, body));
}
const nodata = (why) => h('span', { class: 'nodata', title: why || '' }, t('nodata'));

export async function renderDashboard(ctx) {
  const { root } = ctx;
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('db_title') }), h('p', { text: t('db_lead') })), h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh')))), h('div', { class: 'skeleton sk-block', 'aria-hidden': 'true' }));
  const [ops, stats, alerts, istats] = await Promise.all([loadOps(), api('GET', '/api/stats'), loadBackupAlerts(ctx.me), loadIntelStats(ctx.me)]);
  const c = (stats.status === 200 && stats.data.counts) || {}, waiting = (c.PENDING || 0) + (c.UNDER_REVIEW || 0);
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('db_title') }), h('p', { text: t('db_lead') })), h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh'))));
  const cards = [kpi({ id: 'k1', label: t('kpi_quarantine'), value: stats.status === 200 ? String(waiting) : nodata(), sub: stats.status === 200 ? t('kpi_quarantine_sub', { n: c.APPROVED_PENDING_VALIDATION || 0 }) : null, href: '#/quarantine', tone: waiting ? 'warn' : 'ok' })];
  if (!ops.ok) { put(root, head, alerts, h('div', { class: 'card' }, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), `${t('db_ops_fail')} ${ops.error}`)), h('ul', { class: 'kpis' }, cards)); return; }
  const o = ops.data, sum = o.summary, lr = o.latest.run, st = runState(lr), od = o.latest.observed_day;
  cards.push(
    kpi({ id: 'k2', label: t('kpi_lastrun'), value: lr ? dayBadge(st) : nodata(t('why_norun')), sub: lr ? `${eventLabel(lr.event)} · ${ago(lr.created_at)}` : null, href: lr && lr.url, external: true }),
    kpi({ id: 'k3', label: t('kpi_release'), value: o.latest.release ? o.latest.release.tag.replace(/^rules-/, '') : nodata(), sub: o.latest.release ? `${fmtDate(o.latest.release.published_at)} · ${t('kpi_release_note')}` : t('kpi_release_none'), href: o.latest.release && o.latest.release.url, external: true }),
    kpi({ id: 'k4', label: t('kpi_observed'), value: od ? `${od.examined}` : nodata(t('why_nostats')), sub: od ? t('kpi_observed_sub', { date: fmtDate(od.date), a: od.accepted, q: od.quarantined ?? '—', r: od.rejected }) : null }),
    kpi({ id: 'k5', label: t('kpi_success'), value: sum.success_rate === null ? nodata(t('why_norate')) : `${sum.success_rate}%`, sub: sum.success_rate === null ? null : t('kpi_success_sub', { ok: sum.scheduled_ok, n: sum.scheduled_counted }), tone: sum.success_rate === null ? null : sum.success_rate >= 95 ? 'ok' : sum.success_rate >= 80 ? 'warn' : 'bad' }),
    kpi({ id: 'k6', label: t('kpi_duration'), value: sum.avg_duration_7d_s === null ? nodata() : mmss(sum.avg_duration_7d_s), sub: sum.trend_valid ? (() => { const d = Math.round(((sum.avg_duration_7d_s - sum.avg_duration_prev_7d_s) / sum.avg_duration_prev_7d_s) * 100); return t(d > 0 ? 'trend_up' : d < 0 ? 'trend_down' : 'trend_flat', { n: Math.abs(d) }); })() : t('trend_none') }));
  const intelOk = !!(istats && !istats.error), merged = mergeDays(o.days, intelOk ? istats.runs.items : [], 14, intelOk), famName = (f) => (has(`ix_f_${f}`) ? t(`ix_f_${f}`) : f);
  const strip = h('ul', { class: 'strip', 'aria-label': t('db_strip') }, ...merged.map((d) => { const why = d.attention.map((a) => `${famName(a.family)}: ${stateLabel(a.state)}`).join(', ');
    return h('li', {}, h('a', { class: `cal-cell cal-${STATE_CLASS[d.state]}`, href: `#/activity?day=${d.date}`, title: why || `${t('mf_observed', { n: d.families_observed })}`, 'aria-label': `${fmtDate(d.date)}: ${stateLabel(d.state)}${why ? ` (${why})` : ''}` }, h('span', { class: 'cal-n', text: String(+d.date.slice(8)) }), STATE_ICON[d.state] ? icon(STATE_ICON[d.state]) : null)); }));
  const last7 = merged.slice(-7), labels = last7.map((d) => d.date), mq = matrix(last7, 'retained'), mr = matrix(last7, 'rejected'), cell = (v) => (v === null ? h('span', { class: 'nodata', title: t('mf_not_observed') }, '·') : String(v));
  const table = h('table', { class: 'dt mf-matrix' }, h('caption', { class: 'sr', text: t('ch_qr7') }),
    h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: t('mf_family') }), ...labels.map((l) => h('th', { scope: 'col', class: 'num', text: l.slice(5) })))),
    h('tbody', {}, ...mq.rows.map((r, ri) => h('tr', {}, h('th', { scope: 'row', text: famName(r.family) }), ...r.values.map((q, i) => h('td', { class: 'num' }, q === null && mr.rows[ri].values[i] === null ? cell(null) : h('span', {}, h('span', { class: 'tone-warn', text: String(q ?? '·') }), ' / ', h('span', { class: 'tone-bad', text: String(mr.rows[ri].values[i] ?? '·') })))))),
      h('tr', { class: 'mf-total' }, h('th', { scope: 'row', text: t('mf_total') }), ...mq.totals.map((q, i) => h('td', { class: 'num' }, q === null && mr.totals[i] === null ? cell(null) : h('span', {}, h('span', { class: 'tone-warn', text: String(q ?? '·') }), ' / ', h('span', { class: 'tone-bad', text: String(mr.totals[i] ?? '·') })))))));
  put(root, head, alerts, freshness(o), h('ul', { class: 'kpis' }, cards), istats ? intelCharts(istats) : null,
    h('section', { class: 'card', 'aria-labelledby': 'h-strip' }, h('div', { class: 'flex-between' }, h('h2', { id: 'h-strip', text: t('db_strip') }), h('a', { class: 'btn btn-sm', href: '#/activity' }, icon('calendar'), t('db_open_activity'))), strip, h('p', { class: 'note', text: intelOk ? t('db_strip_note') : t('mf_yara_only') })),
    h('section', { class: 'card', 'aria-labelledby': 'h-mf' }, h('h2', { id: 'h-mf', text: t('ch_qr7') }), h('div', { class: 'dt-wrap', role: 'region', tabindex: '0', 'aria-label': t('ch_qr7') }, table), h('p', { class: 'note', text: t('mf_matrix_note') }),
      chart({ title: t('mf_total_chart'), labels, series: [{ name: t('rl_quarantined'), cls: 'c-warn', values: mq.totals }, { name: t('rl_rejected'), cls: 'c-bad', values: mr.totals }] })));
}
export { stateBadge, fmtDateTime };
