// Shared pieces for the screens that show pipeline activity: loading, freshness banner, day-state vocabulary.
import { t, getLang } from '../i18n.js';
import { h, icon, fmtDateTime } from '../ui.js';
import { api, failure } from '../api.js';

export const STATE_ICON = { OK: 'check', WARNING: 'alert', FAIL: 'x', CANCELLED: 'pause', RUNNING: 'refresh', NO_RUN: 'minus', PENDING: 'clock', BEFORE: null };
export const STATE_CLASS = { OK: 'ok', WARNING: 'warn', FAIL: 'bad', CANCELLED: 'neutral', RUNNING: 'info', NO_RUN: 'none', PENDING: 'none', BEFORE: 'none' };
export const stateLabel = (s) => t(`ds_${s}`);
export function dayBadge(state) { return h('span', { class: `badge badge-day-${STATE_CLASS[state]}` }, STATE_ICON[state] ? icon(STATE_ICON[state]) : null, stateLabel(state)); }

export async function loadOps() { const r = await api('GET', '/api/ops/overview'); return r.status === 200 ? { ok: true, data: r.data } : { ok: false, error: failure(r, t('err_generic')), status: r.status }; }

export function ago(iso, now = Date.now()) {
  const ms = now - Date.parse(iso); if (!Number.isFinite(ms)) return '—'; const m = Math.round(ms / 60000);
  const rtf = new Intl.RelativeTimeFormat(getLang() === 'en' ? 'en' : 'es', { numeric: 'auto' });
  return m < 60 ? rtf.format(-Math.max(m, 0), 'minute') : m < 2880 ? rtf.format(-Math.round(m / 60), 'hour') : rtf.format(-Math.round(m / 1440), 'day');
}
export const mmss = (s) => (s === null || s === undefined ? '—' : s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min` : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`);
export const eventLabel = (e) => (e === 'schedule' ? t('ev_run_schedule') : e === 'workflow_dispatch' ? t('ev_run_manual') : e);
export function conclusionLabel(r) { return !r ? '—' : r.status !== 'completed' ? t('ds_RUNNING') : t(`cc_${r.conclusion}`) === `cc_${r.conclusion}` ? String(r.conclusion) : t(`cc_${r.conclusion}`); }

/** Where the numbers come from, how fresh they are, and which source could not be read. */
export function freshness(o) {
  const parts = [t('fr_source'), t('fr_updated', { when: ago(o.generated_at) }), o.cache && o.cache.hit ? t('fr_cached', { s: o.cache.age_s }) : t('fr_live')];
  if (o.rate) parts.push(t('fr_rate', { n: o.rate.remaining, max: o.rate.limit }));
  const box = h('p', { class: 'freshness note', text: parts.join(' · ') }); box.append(h('span', { class: 'sr', text: ` ${fmtDateTime(o.generated_at)}` }));
  const missing = (o.unavailable || []).map((u) => `${t(`src_${u.source}`)} (${t(`why_src_${u.reason}`) === `why_src_${u.reason}` ? u.reason : t(`why_src_${u.reason}`)})`);
  return h('div', { class: 'grid-10' }, box, missing.length ? h('p', { class: 'alert alert-warn', role: 'status' }, icon('alert'), t('fr_partial', { list: missing.join(', ') })) : null);
}
