// Audit timeline: who accessed what, reviewed what and decided what, grouped by day, filterable, with cryptographic verification for administrators.
import { t } from '../i18n.js';
import { h, icon, fmtDate, fmtTime, shortSha, rulesText, put, pillGroup, can } from '../ui.js';
import { api, failure } from '../api.js';

const FAMILIES = ['', 'decision', 'access', 'session', 'member', 'pipeline', 'retest'];
const IC = { decision: 'check', access: 'file', session: 'key', member: 'users', pipeline: 'refresh', retest: 'refresh' };

function describe(e) {
  const d = e.detail || {}, fam = e.action.split('.')[0], key = `ev_${e.action.replace('.', '_')}`;
  const vars = { actor: e.actor, path: d.path || e.target, rules: rulesText(d.count ?? d.changed ?? ((d.applied || []).length || 1)), n: d.count ?? d.changed ?? (d.applied || []).length, login: d.login || e.target, from: d.from_role ? t(`role_${d.from_role}`) : t('role_NONE'), to: d.to_role ? t(`role_${d.to_role}`) : t('role_NONE'), action: e.action };
  const text = t(key, vars);
  return { fam, text: text === key ? t('ev_other', vars) : text };
}
const ruleTarget = (e) => (/^(decision|access|retest)\./.test(e.action) && /^[0-9a-f-]{8,64}$/.test(e.target) ? e.target : (e.detail?.applied || []).length === 1 ? e.detail.applied[0].id : null);

export async function renderAudit(ctx) {
  const { root, me } = ctx, isAdmin = can(me, 'audit.verify');
  const f = { family: '', actor: '' }; let before = null;
  const fam = pillGroup(t('a_family'), FAMILIES.map((x) => [x, t(`f_${x || 'all'}`)]), f.family, (v) => { f.family = v; fam.redraw(v); load(true); });
  const actor = h('input', { class: 'input', id: 'a-actor', type: 'search', autocomplete: 'off', placeholder: t('a_actor_ph') });
  const list = h('div', { class: 'events', 'aria-live': 'polite' }), more = h('div'), verifyOut = h('div', { role: 'status' });
  const verify = isAdmin ? h('section', { class: 'card', 'aria-labelledby': 'h-ver' }, h('h2', { id: 'h-ver', text: t('a_verify_h') }), h('p', { class: 'note mt-6 mb-12', text: t('a_verify_p') }), h('button', { type: 'button', class: 'btn', onclick: async (ev) => {
    const b = ev.currentTarget; b.disabled = true; verifyOut.replaceChildren(h('p', { class: 'muted', text: t('a_verifying') })); const r = await api('GET', '/api/audit/verify'); b.disabled = false;
    verifyOut.replaceChildren(r.status !== 200 ? h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(r, t('err_generic'))) : r.data.ok ? h('p', { class: 'alert alert-ok' }, icon('check'), t('a_ok', { n: r.data.entries, head: shortSha(r.data.head || '') })) : h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), t('a_bad', { at: r.data.at ?? '?', msg: r.data.error || '' })));
  } }, icon('lock'), t('a_verify')), verifyOut) : null;

  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('a_title') }), h('p', { text: t('a_lead') }))), verify,
    h('div', { class: 'field' }, h('span', { text: t('a_family') }), fam), h('div', { class: 'field' }, h('label', { for: 'a-actor', text: t('a_actor') }), actor), list, more);

  let lastDay = '';
  async function load(reset) {
    if (reset) { before = null; lastDay = ''; put(list, ); }
    const q = new URLSearchParams({ limit: '40' }); if (before) q.set('before', before); if (f.family) q.set('family', f.family); if (f.actor) q.set('actor', f.actor);
    const r = await api('GET', `/api/audit?${q}`);
    if (r.status !== 200) { list.append(h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(r, t('err_generic')))); return; }
    if (reset && !r.data.entries.length) { put(list, h('div', { class: 'card empty' }, icon('audit'), h('h2', { text: t('a_none_h') }), h('p', { text: t('a_none_p') }))); more.replaceChildren(); return; }
    for (const e of r.data.entries) {
      const day = e.at.slice(0, 10); if (day !== lastDay) { lastDay = day; list.append(h('h2', { class: 'day', text: fmtDate(e.at) })); }
      const { fam, text } = describe(e), rule = ruleTarget(e), d = e.detail || {};
      list.append(h('article', { class: 'event' }, h('div', { class: `badge-ic k-${fam}` }, icon(IC[fam] || 'info')), h('div', {},
        h('p', {}, rule ? h('a', { href: `#/rules/${rule}`, text: text }) : text),
        d.reason ? h('div', { class: 'quote' }, h('strong', { text: `${t('a_reason')}: ` }), d.reason) : null,
        h('div', { class: 'sub' }, h('time', { datetime: e.at, text: `${fmtTime(e.at)}` }), h('span', { text: `#${e.seq}` }), h('span', { text: e.role })))));
    }
    before = r.data.next_before; more.replaceChildren(r.data.has_more ? h('button', { type: 'button', class: 'btn', onclick: () => load(false) }, t('a_more')) : '');
  }
  let timer; actor.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { f.actor = actor.value.trim(); load(true); }, 350); });
  await load(true);
}
