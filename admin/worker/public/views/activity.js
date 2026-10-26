// Daily calendar, 7/30-day charts and history of the daily review, from GitHub Actions and the pipeline's own records.
import { t, has, getLang } from '../i18n.js';
import { mergeDays } from './families_agg.js';
import { h, icon, put, fmtDate, fmtDateTime, fmtTime, pillGroup } from '../ui.js';
import { chart } from './charts.js';
import { loadIntelStats, runsTable } from './intel_summary.js';
import { loadOps, freshness, dayBadge, mmss, eventLabel, conclusionLabel, STATE_CLASS, STATE_ICON, stateLabel } from './ops.js';

const WEEKDAYS = { es: ['L', 'M', 'X', 'J', 'V', 'S', 'D'], en: ['M', 'T', 'W', 'T', 'F', 'S', 'S'] };
const WEEKDAYS_LONG = { es: ['lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado', 'domingo'], en: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'] };
const monthShort = (date) => new Intl.DateTimeFormat(getLang() === 'en' ? 'en-GB' : 'es-ES', { month: 'short', timeZone: 'UTC' }).format(new Date(`${date}T00:00:00Z`));
const dow = (date) => (new Date(`${date}T00:00:00Z`).getUTCDay() + 6) % 7;   // Monday = 0
const label = (d) => `${fmtDate(d.date)}: ${stateLabel(d.state)}${d.manual_only ? ` (${t('ev_run_manual').toLowerCase()})` : ''}${d.recovered ? `. ${t('recovered')}` : ''}`;

function runLine(r, kind) {
  return h('li', { class: 'runline' }, h('strong', { text: kind }), h('span', { text: ` · ${conclusionLabel(r)} · ${fmtTime(r.started_at)} UTC · ${t('r_duration')}: ${mmss(r.duration_s)} · ` }), h('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer' }, t('open_run'), icon('external')));
}
const famName = (f) => (has(`ix_f_${f}`) ? t(`ix_f_${f}`) : f);
function dayDetail(d) {
  if (!d) return h('p', { class: 'muted', text: t('cal_pick') });
  const parts = [h('div', { class: 'flex-between' }, h('h3', { text: fmtDate(d.date) }), dayBadge(d.state))];
  if (d.state === 'NO_RUN') parts.push(h('p', { class: 'note', text: t('cal_norun_note') }));
  else if (d.state === 'PENDING') parts.push(h('p', { class: 'note', text: t('cal_pending_note') }));
  else if (d.state === 'BEFORE') parts.push(h('p', { class: 'note', text: t('cal_before_note') }));
  if (d.recovered) parts.push(h('p', { class: 'alert alert-info' }, icon('info'), t('recovered_note')));
  if (d.manual_only) parts.push(h('p', { class: 'note', text: t('manual_only_note') }));
  const runs = []; if (d.scheduled) runs.push(runLine(d.scheduled, t('ev_run_schedule'))); for (const r of d.manual) runs.push(runLine(r, t('ev_run_manual'))); if (runs.length) parts.push(h('ul', { class: 'runs' }, runs));
  if (d.reasons.length) parts.push(h('ul', { class: 'reasons-list' }, ...d.reasons.map((r) => h('li', { text: t(`rs_${r.code}`) === `rs_${r.code}` ? r.code : t(`rs_${r.code}`, { n: r.n }) }))));
  if (d.stats) parts.push(h('dl', { class: 'kv' }, h('dt', { text: t('rl_examined') }), h('dd', { text: String(d.stats.examined) }), h('dt', { text: t('rl_accepted') }), h('dd', { text: String(d.stats.accepted) }), h('dt', { text: t('rl_quarantined') }), h('dd', { text: String(d.stats.quarantined ?? '—') }), h('dt', { text: t('rl_rejected') }), h('dd', { text: String(d.stats.rejected) })));
  else if (d.runs) parts.push(h('p', { class: 'nodata', text: t('cal_nostats') }));
  const fc = (d.cells || []).filter((c) => c.family !== 'yara' || c.state || c.accepted !== null);
  if (fc.length) parts.push(h('div', { class: 'dt-wrap', role: 'region', tabindex: '0', 'aria-label': t('ac_fam_title') }, h('table', { class: 'dt' }, h('caption', { class: 'sr', text: t('ac_fam_title') }),
    h('thead', {}, h('tr', {}, ...['mf_family', 'ac_state', 'mf_runs', 'rl_accepted', 'mf_retained', 'rl_rejected'].map((k, i) => h('th', { scope: 'col', class: i > 1 ? 'num' : '', text: t(k) })))),
    h('tbody', {}, ...fc.map((c) => h('tr', {}, h('th', { scope: 'row', text: famName(c.family) }), h('td', {}, c.state ? dayBadge(c.state) : h('span', { class: 'nodata', text: t('mf_not_observed') })), h('td', { class: 'num', text: String(c.runs) }), h('td', { class: 'num', text: c.accepted === null ? '·' : String(c.accepted) }), h('td', { class: 'num', text: c.retained === null ? '·' : String(c.retained) }), h('td', { class: 'num', text: c.rejected === null ? '·' : String(c.rejected) })))))));
  parts.push(d.releases.length ? h('p', { class: 'alert alert-ok' }, icon('check'), t('cal_release', { tags: d.releases.map((x) => x.tag).join(', ') })) : h('p', { class: 'note', text: t('cal_norelease') }));
  parts.push(h('p', { class: 'note', text: t('cal_release_vs_run') }));
  return h('div', { class: 'grid-10' }, parts);
}

export async function renderActivity(ctx) {
  const { root, query, me } = ctx; const intelBox = h('div', { class: 'minw0' }); let fam = 'all', days = query.get('days') === '7' ? 7 : 30, selected = /^\d{4}-\d{2}-\d{2}$/.test(query.get('day') || '') ? query.get('day') : null;
  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('ac_title' ) }), h('p', { text: t('ac_lead') }))), h('div', { class: 'skeleton sk-block', 'aria-hidden': 'true' }));
  const [ops, ist] = await Promise.all([loadOps(), loadIntelStats(me)]); const intelOk = !!(ist && !ist.error); { const n = runsTable(ist); if (n) put(intelBox, n); }
  const head = h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('ac_title') }), h('p', { text: t('ac_lead') })), h('div', { class: 'actions' }, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => ctx.rerender() }, icon('refresh'), t('refresh'))));
  if (!ops.ok) { put(root, head, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), `${t('db_ops_fail')} ${ops.error}`)); return; }
  const o0 = ops.data, mdays = mergeDays(o0.days, intelOk ? ist.runs.items : [], o0.days.length, intelOk), o = { ...o0, days: o0.days.map((d, i) => ({ ...d, state: mdays[i].state, ops_state: d.state, cells: mdays[i].cells, attention: mdays[i].attention })) }, byDate = new Map(o.days.map((d) => [d.date, d]));
  const families = [...new Set(mdays.flatMap((d) => d.cells.filter((c) => c.runs > 0 || c.state).map((c) => c.family)))].sort((a, b) => (a === 'yara' ? -1 : b === 'yara' ? 1 : a.localeCompare(b)));
  const detail = h('div', { class: 'card', 'aria-live': 'polite', id: 'cal-detail' }), calBox = h('div'), charts = h('div', { class: 'grid-14' }), history = h('div');
  if (!selected) { const last = [...o.days].reverse().find((d) => d.runs); selected = last ? last.date : o.days[o.days.length - 1].date; }

  const drawCal = () => {
    const first = o.days[0].date, lastD = o.days[o.days.length - 1].date, pad = dow(first), weeks = []; let cells = Array(pad).fill(null).concat(o.days);
    while (cells.length % 7) cells.push(null); for (let i = 0; i < cells.length; i += 7) weeks.push(cells.slice(i, i + 7));
    const tbl = h('table', { class: 'cal', 'aria-label': t('cal_label', { from: fmtDate(first), to: fmtDate(lastD) }) }, h('thead', {}, h('tr', {}, ...WEEKDAYS[getLang()].map((w, i) => h('th', { scope: 'col', abbr: WEEKDAYS_LONG[getLang()][i], text: w })))),
      h('tbody', {}, ...weeks.map((wk) => h('tr', {}, ...wk.map((d) => d ? h('td', {}, h('button', { type: 'button', class: `cal-cell cal-${STATE_CLASS[d.state]} ${d.manual_only ? 'cal-manual' : ''}`, 'aria-pressed': String(d.date === selected), 'aria-label': label(d), onclick: () => { selected = d.date; drawCal(); put(detail, dayDetail(byDate.get(selected))); } },
        (d.date.endsWith('-01') || d.date === o.days[0].date) ? h('span', { class: 'cal-mon', 'aria-hidden': 'true', text: monthShort(d.date) }) : null, h('span', { class: 'cal-n', text: String(+d.date.slice(8)) }), STATE_ICON[d.state] ? icon(STATE_ICON[d.state]) : null, d.manual_only ? h('span', { class: 'cal-tag', 'aria-hidden': 'true', text: 'M' }) : null, d.releases.length ? h('span', { class: 'cal-rel', 'aria-hidden': 'true', title: t('cal_has_release') }, icon('check')) : null)) : h('td', {}, h('span', { class: 'cal-cell cal-empty', 'aria-hidden': 'true' })))))));
    const legend = h('ul', { class: 'legend wide' }, ...['OK', 'WARNING', 'FAIL', 'CANCELLED', 'RUNNING', 'NO_RUN', 'PENDING'].map((s) => h('li', {}, h('i', { class: `swatch sw-${STATE_CLASS[s]}` }, STATE_ICON[s] ? icon(STATE_ICON[s]) : null), h('span', {}, h('strong', { text: stateLabel(s) }), ' — ', t(`dsd_${s}`)))), h('li', {}, h('i', { class: 'swatch cal-tag-sw', text: 'M' }), t('lg_manual')), h('li', {}, h('i', { class: 'swatch cal-tag-sw' }, icon('check')), t('lg_release')));
    put(calBox, tbl, h('details', { class: 'chart-data' }, h('summary', { text: t('cal_legend') }), legend));
  };
  const drawCharts = () => {
    const sel = o.days.slice(-days), labels = sel.map((d) => d.date), pick = (d, key) => { const cs = d.cells.filter((c) => (fam === 'all' || c.family === fam) && (c.runs > 0 || c.family === 'yara') && c[key] !== null && c[key] !== undefined); return cs.length ? cs.reduce((a, c) => a + c[key], 0) : null; };
    const dur = sel.map((d) => { const r = d.scheduled || d.manual[d.manual.length - 1]; return r && r.duration_s !== null && r.duration_s !== undefined ? Math.round((r.duration_s / 60) * 10) / 10 : null; });
    put(charts, chart({ title: t('ac_ch_accepted', { n: days }), labels, series: [{ name: t('rl_accepted'), cls: 'c-info', values: sel.map((d) => pick(d, 'accepted')) }] }),
      chart({ title: t('ch_qr', { n: days }), labels, series: [{ name: t('mf_retained'), cls: 'c-warn', values: sel.map((d) => pick(d, 'retained')) }, { name: t('rl_rejected'), cls: 'c-bad', values: sel.map((d) => pick(d, 'rejected')) }] }),
      chart({ title: t('ch_duration', { n: days }), labels, kind: 'line', unit: ' min', series: [{ name: t('r_duration'), cls: 'c-info', values: dur }] }));
    const rows = sel.filter((d) => d.runs || d.state === 'NO_RUN').reverse();
    put(history, h('ul', { class: 'events' }, ...rows.map((d) => h('li', { class: 'event hist' }, h('div', { class: `badge-ic k-${STATE_CLASS[d.state]}` }, icon(STATE_ICON[d.state] || 'minus')), h('div', {}, h('p', {}, h('strong', { text: fmtDate(d.date) }), ' ', dayBadge(d.state), d.recovered ? ` ${t('recovered')}` : ''), h('div', { class: 'sub' }, d.scheduled ? h('span', { text: `${t('ev_run_schedule')} ${mmss(d.scheduled.duration_s)}` }) : null, d.manual.length ? h('span', { text: `${t('ev_run_manual')} ×${d.manual.length}` }) : null, d.stats ? h('span', { text: `${t('rl_examined')} ${d.stats.examined} · ${t('rl_quarantined')} ${d.stats.quarantined ?? '—'} · ${t('rl_rejected')} ${d.stats.rejected}` }) : null, d.releases.length ? h('span', { text: `${t('cal_release', { tags: d.releases.map((x) => x.tag.replace(/^rules-/, '')).join(', ') })}` }) : null))))));
  };
  const range = pillGroup(t('ac_range'), [[7, t('ac_7')], [30, t('ac_30')]], days, (val) => { days = val; range.redraw(val); drawCharts(); });
  const famPills = pillGroup(t('ac_family'), [['all', t('ac_fam_all')], ...families.map((f) => [f, famName(f)])], fam, (val) => { fam = val; famPills.redraw(val); drawCharts(); });
  drawCal(); put(detail, dayDetail(byDate.get(selected))); drawCharts();
  put(root, head, freshness(o), h('section', { class: 'card', 'aria-labelledby': 'h-cal' }, h('h2', { id: 'h-cal', text: t('cal_title') }), h('p', { class: 'note', text: t('cal_utc', { at: o.definitions.schedule_utc }) }), calBox),
    detail, h('section', { class: 'grid-14', 'aria-labelledby': 'h-ch' }, h('div', { class: 'flex-between' }, h('h2', { id: 'h-ch', text: t('ch_title') }), range), intelOk ? famPills : h('p', { class: 'note', text: t('mf_yara_only') }), charts),
    h('section', { class: 'grid-14', 'aria-labelledby': 'h-hist' }, h('h2', { id: 'h-hist', text: t('hist_title') }), history),
    intelBox);
}
export { fmtDateTime };
