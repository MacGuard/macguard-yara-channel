// "What is wrong with the backups, why, since when, what is at risk, what can I do and how do I know it worked": one card per failed resource, built only from the recovery status the Worker read
// (GitHub Actions jobs and the annotation the failing job wrote). Used by the dashboard and by the recovery screen.
import { t, has } from '../i18n.js';
import { h, icon, fmtDateTime, can } from '../ui.js';
import { api } from '../api.js';

const PROBE = 'https://github.com/MacGuard/macguard-yara-channel/actions/workflows/d1-token-probe.yml';
const BACKUP = 'https://github.com/MacGuard/macguard-yara-channel/actions/workflows/backup.yml';
const link = (href, text, ext = true) => h('a', { class: 'btn btn-sm', href, target: ext ? '_blank' : null, rel: ext ? 'noopener noreferrer' : null }, text, ext ? icon('external') : null);

/** What the person must understand about this failure, in their language. */
function cause(f) {
  const d = f.diagnosis, job = f.failed_jobs[0] ? f.failed_jobs[0].name : '?';
  if (d && has(`ba_kind_${d.kind}`)) return { text: t(`ba_kind_${d.kind}`, { code: d.code || '—', http: d.http || '—' }), fix: has(`ba_fix_${d.kind}`) ? t(`ba_fix_${d.kind}`) : null, known: true };
  return { text: t('ba_unknown_cause', { job }), fix: t('ba_unknown_fix'), known: false };
}
const lastGood = (st, service) => (st.inventory || []).filter((r) => r.service === service && (r.recoverable === 'PROVEN' || r.recoverable === 'AUTHENTICATED')).sort((a, b) => String(b.at).localeCompare(String(a.at)))[0] || null;

export function backupAlertCard(f, st) {
  const c = cause(f), good = lastGood(st, f.resource), phase = f.failed_jobs.length ? f.failed_jobs.map((j) => j.name).join(', ') : '—';
  const sev = good ? 'warn' : 'bad';
  return h('section', { class: `card alert-card sev-${sev}`, 'aria-labelledby': `ba-${f.run_id}` },
    h('div', { class: 'flex-between' }, h('h2', { id: `ba-${f.run_id}`, text: t('ba_title', { service: t(`ba_svc_${f.resource}`) }) }), h('span', { class: sev === 'bad' ? 'chip chip-bad' : 'chip chip-warn', text: t(`ba_sev_${sev}`) })),
    h('p', { class: 'ba-what' }, h('strong', { text: `${t('ba_what')}: ` }), c.text, ' ', t('ba_skipped', { n: f.not_run_jobs.length })),
    h('dl', { class: 'kv kv-tight' },
      h('dt', { text: t('ba_service') }), h('dd', { text: t(`ba_svc_${f.resource}`) }), h('dt', { text: t('ba_since') }), h('dd', {}, h('time', { datetime: f.at, text: fmtDateTime(f.at) }), ` · ${t('ba_run', { id: f.run_id })}`),
      h('dt', { text: t('ba_phase') }), h('dd', { class: 'mono', text: phase }),
      h('dt', { text: t('ba_risk') }), h('dd', { text: good ? t('ba_risk_some', { when: fmtDateTime(good.at) }) : t('ba_risk_all') }),
      h('dt', { text: t('ba_lastgood') }), h('dd', { text: good ? `${fmtDateTime(good.at)} · ${good.provider} · ${t(`rs_rec_${good.recoverable}`)}` : t('ba_lastgood_none') })),
    c.fix ? h('p', { class: 'ba-fix' }, h('strong', { text: `${t('ba_do')}: ` }), c.fix) : null,
    h('p', { class: 'note', text: t('ba_safe') }), h('p', { class: 'note', text: t('ba_verify') }),
    h('div', { class: 'actions' }, link(f.run_url, t('ba_a_run')), link(PROBE, t('ba_a_probe')), link(BACKUP, t('ba_a_rerun')), link('#/restore?tab=assistant&proc=drill', t('ba_a_guide'), false), good ? link('#/restore?tab=inventory', t('ba_a_last'), false) : null));
}

/** The cards for every failed resource; null when the person may not read the recovery status or nothing is failing; an UNKNOWN line when the status cannot be read. */
export async function loadBackupAlerts(me) {
  if (!can(me, 'backups.read')) return null;
  const r = await api('GET', '/api/restore/status'); if (r.status !== 200) return h('p', { class: 'note', role: 'status', text: t('ba_unreadable') });
  const st = r.data; if (!st.failures || !st.failures.length) return null;
  return h('div', { class: 'stack', 'aria-label': t('ba_h') }, ...st.failures.map((f) => backupAlertCard(f, st)));
}
