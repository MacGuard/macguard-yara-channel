// Members and permissions: who is authorized, who signed in without authorization, whose grant was revoked; audited changes by immutable GitHub id.
import { t, has } from '../i18n.js';
import { h, icon, avatar, roleBadge, fmtDate, fmtDateTime, modal, toast, put, radioGroup, pillGroup } from '../ui.js';
import { api, failure } from '../api.js';

const STATUSES = ['', 'authorized', 'unauthorized', 'revoked', 'unbound'];
const SIZE = 12;
const ROLE_LIST = ['VIEWER', 'REVIEWER', 'PUBLISHER', 'SECURITY_ADMIN', 'ADMIN'];
const roles = () => ROLE_LIST.map((r) => [r, t(`role_${r}`), t(`rh_${r}`)]);

export async function renderMembers(ctx) {
  const { root, me, query, go } = ctx; const f = { q: '', status: '', page: 1 }, tab = query.get('tab') === 'matrix' ? 'matrix' : 'users';
  const tabs = pillGroup(t('adm_tabs'), [['users', t('adm_tab_users')], ['matrix', t('adm_tab_matrix')]], tab, (v) => go(`#/admin?tab=${v}`, true));
  if (tab === 'matrix') { put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('adm_title') }), h('p', { text: t('adm_lead') }))), h('div', { class: 'field' }, tabs), await matrixSection()); document.title = `${t('adm_title')} · MacGuard Quarantine`; return; }
  const list = h('div', { 'aria-live': 'polite' }), counts = h('p', { class: 'muted' });
  const search = h('input', { class: 'input', id: 'm-search', type: 'search', autocomplete: 'off', placeholder: t('m_search') });
  const pills = h('div', { class: 'pills', role: 'group', 'aria-label': t('m_status') });
  const add = h('button', { type: 'button', class: 'btn btn-primary', onclick: () => openEditor(null) }, icon('plus'), t('m_add'));

  put(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', { id: 'page-title', tabindex: '-1', text: t('adm_title') }), h('p', { text: t('m_lead') })), h('div', { class: 'actions' }, add)),
    h('div', { class: 'field' }, tabs), counts, pills, h('div', { class: 'field' }, h('label', { for: 'm-search', text: t('m_search') }), search), list);

  let timer; search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); f.page = 1; load(); }, 300); });
  const drawPills = (c) => pills.replaceChildren(...STATUSES.map((s) => { const n = s === '' ? Object.values(c).reduce((a, b) => a + b, 0) : c[s] || 0; const b = h('button', { type: 'button', class: 'pill', 'aria-pressed': String(f.status === s) }, t(`ms_${s || 'all'}`), h('b', { text: String(n) })); b.addEventListener('click', () => { f.status = s; f.page = 1; load(); }); return b; }));

  async function load() {
    const q = new URLSearchParams({ page: f.page, pageSize: SIZE }); if (f.q) q.set('q', f.q); if (f.status) q.set('status', f.status);
    list.setAttribute('aria-busy', 'true'); const r = await api('GET', `/api/members?${q}`); list.removeAttribute('aria-busy');
    if (r.status !== 200) { put(list, h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(r, t('err_generic')))); return; }
    const d = r.data; drawPills(d.counts); counts.textContent = t('m_counts', { a: d.counts.authorized + (d.counts.unbound || 0), u: d.counts.unauthorized, r: d.counts.revoked });
    if (!d.items.length) { put(list, h('div', { class: 'card empty' }, icon('users'), h('h2', { text: t('m_none_h') }), h('p', { text: t('m_none_p') }))); return; }
    const pages = Math.max(1, Math.ceil(d.total / SIZE));
    const pager = h('div', { class: 'pager mt-14' }, h('span', { text: `${d.page} / ${pages}` }), h('div', { class: 'flex-8' },
      h('button', { type: 'button', class: 'btn btn-sm', disabled: d.page <= 1, onclick: () => { f.page--; load(); } }, icon('back'), t('q_prev')), h('button', { type: 'button', class: 'btn btn-sm', disabled: d.page >= pages, onclick: () => { f.page++; load(); } }, t('q_next'), icon('chevron'))));
    put(list, ...[h('ul', { class: 'people' }, d.items.map(card)), pages > 1 ? pager : null].filter(Boolean));
  }

  function card(p) {
    const self = p.user_id === me.user_id, hist = h('div', { class: 'history', hidden: true });
    const origin = p.state === 'unauthorized' || p.state === 'revoked' ? 'none' : p.origin;
    const kv = h('dl', { class: 'kv' },
      h('dt', { text: t('m_origin') }), h('dd', { text: t(`org_${origin}`) }),
      h('dt', { text: t('m_repo') }), h('dd', { text: p.repo_role ? t(`role_${p.repo_role}`) : p.repo_checked_at ? t('role_NONE') : t('m_unknown') }),
      h('dt', { text: t('m_manual') }), h('dd', { text: p.manual_role ? t(`role_${p.manual_role}`) : t('none') }),
      p.created_at ? [h('dt', { text: t('m_created') }), h('dd', { text: fmtDate(p.created_at) })] : null, p.updated_at && p.updated_at !== p.created_at ? [h('dt', { text: t('m_updated') }), h('dd', { text: fmtDateTime(p.updated_at) })] : null,
      h('dt', { text: t('m_last') }), h('dd', { text: p.last_login ? fmtDateTime(p.last_login) : t('m_never') }), p.granted_by ? [h('dt', { text: t('m_by', { who: '' }).replace(/\s*$/, '') }), h('dd', { text: p.granted_by })] : null);
    const canEdit = !self && p.user_id !== null, acts = [];
    if (canEdit) acts.push(h('button', { type: 'button', class: 'btn btn-sm', onclick: () => openEditor(p) }, icon('edit'), t('m_change')));
    if (canEdit && p.manual_role) acts.push(h('button', { type: 'button', class: 'btn btn-sm btn-bad', onclick: () => openRevoke(p) }, icon('trash'), t('m_revoke')));
    acts.push(h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-expanded': 'false', onclick: async (ev) => {
      const b = ev.currentTarget; const open = hist.hidden; hist.hidden = !open; b.setAttribute('aria-expanded', String(open)); if (!open || hist.dataset.loaded) return;
      const r = await api('GET', `/api/members/${p.user_id ?? 0}/history?login=${encodeURIComponent(p.login)}`); hist.dataset.loaded = '1';
      const rows = (r.data.history || []); hist.replaceChildren(...(rows.length ? rows.map((x) => h('div', {}, h('strong', { text: `${x.from_role ? t(`role_${x.from_role}`) : t('role_NONE')} → ${x.to_role ? t(`role_${x.to_role}`) : t('role_NONE')}` }), h('div', { class: 'note', text: `${fmtDateTime(x.at)} · ${x.actor}` }), x.reason ? h('div', { class: 'quote', text: x.reason }) : null)) : [h('p', { class: 'muted', text: t('m_history_none') })]));
    } }, icon('history'), t('m_history')));
    return h('li', { class: 'person' },
      h('div', { class: 'person-head' }, avatar(p.user_id, p.login, 44), h('div', {}, h('strong', { text: p.login }), h('span', { class: 'faint mono', text: p.user_id !== null ? `${t('m_id')} ${p.user_id}` : `${t('m_id')}: —` }))),
      h('div', { class: 'person-badges' }, roleBadge(p.effective_role), h('span', { class: 'badge badge-neutral', text: t(`ms_state_${p.state}`) })),
      kv, self ? h('p', { class: 'note', text: t('m_self') }) : p.origin === 'repo' && !p.manual_role ? h('p', { class: 'note', text: t('m_repo_only') }) : null,
      h('div', { class: 'person-actions' }, acts), hist);
  }

  function openRevoke(p) {
    const reason = reasonInput();
    modal({ title: t('md_revoke_h', { login: p.login }), intro: t('md_revoke_p'), body: reason.node, confirmLabel: t('m_revoke'), variant: 'bad', validate: () => (reason.value.length < 5 ? t('reason_short') : null),
      async submit() { const r = await api('POST', '/api/members', { user_id: p.user_id, role: null, reason: reason.value }); if (r.status === 200) { toast(t('md_saved')); load(); return null; } return t('failed', { msg: failure(r, t('err_generic')) }); } });
  }

  function openEditor(p) {
    let found = p ? { account: { id: p.user_id, login: p.login }, current_role: p.manual_role, legacy_unbound: !p.bound } : null;
    const login = h('input', { class: 'input', id: 'md-login', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', maxlength: '39', value: p ? p.login : '', readonly: !!p });
    const status = h('div', { 'aria-live': 'polite' }), form = h('div', { class: 'grid-12' });
    let role = radioGroup(t('md_new'), 'md-role', roles(), found && found.current_role || 'VIEWER'); const roleBox = h('div');
    const reason = reasonInput();
    const find = h('button', { type: 'button', class: 'btn', onclick: lookup }, icon('search'), t('md_find'));
    function show() {
      const a = found.account; role = radioGroup(t('md_new'), 'md-role', roles(), found.current_role || 'VIEWER'); put(roleBox, role.node);
      status.replaceChildren(h('div', { class: 'lookup' }, h('div', { class: 'person-head' }, avatar(a.id, a.login, 52), h('div', {}, h('strong', { text: a.login }), h('span', { class: 'faint mono', text: `${t('m_id')} ${a.id}` }))),
        h('p', { class: 'note', text: t('md_confirm_acc') }), found.is_self ? h('p', { class: 'alert alert-warn' }, icon('lock'), t('md_self')) : null, found.login_held_by_other_id ? h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), t('md_held', { login: a.login, id: found.login_held_by_other_id })) : null,
        found.legacy_unbound ? h('p', { class: 'alert alert-info' }, icon('info'), t('md_legacy')) : null,
        h('div', {}, `${t('md_current')}: `, found.current_role ? roleBadge(found.current_role) : h('span', { text: t('none') }))));
      form.hidden = found.is_self || !!found.login_held_by_other_id;
    }
    async function lookup() {
      const v = login.value.trim().replace(/^@/, ''); if (!/^[A-Za-z0-9-]{1,39}$/.test(v)) { status.replaceChildren(h('p', { class: 'alert alert-bad', role: 'alert', text: t('md_notfound') })); return; }
      find.disabled = true; const r = await api('GET', `/api/members/lookup?login=${encodeURIComponent(v)}`); find.disabled = false;
      if (r.status !== 200) { found = null; form.hidden = true; status.replaceChildren(h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), r.status === 404 ? t('md_notfound') : r.status === 400 ? t('md_only_user') : failure(r, t('err_generic')))); return; }
      found = r.data; show();
    }
    login.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); lookup(); } });
    form.append(roleBox, reason.node); form.hidden = true; if (found) put(roleBox, role.node);
    const body = h('div', { class: 'grid-12' }, h('div', { class: 'field' }, h('label', { for: 'md-login', text: t('md_login') }), h('div', { class: 'flex-8' }, login, p ? null : find)), status, form);
    modal({ title: p ? t('m_change') : t('md_add_h'), body, confirmLabel: t('save'), validate: () => (!found ? t('md_notfound') : reason.value.length < 5 ? t('reason_short') : null),
      async submit() { const r = await api('POST', '/api/members', { user_id: found.account.id, role: role.value, reason: reason.value }); if (r.status === 200) { toast(t('md_saved')); load(); return null; } return t('failed', { msg: failure(r, t('err_generic')) }); } });
    if (p) show();
  }
  await load();
}

function reasonInput() {
  const ta = h('textarea', { class: 'textarea', rows: '3', maxlength: '2000', id: `mr-${Math.random().toString(36).slice(2)}`, placeholder: t('md_reason_ph') });
  return { node: h('div', { class: 'field' }, h('label', { for: ta.id, text: t('reason') }), ta, h('p', { class: 'note', text: t('reason_hint') })), get value() { return ta.value.trim(); } };
}
/** The permission matrix as the server enforces it (GET /api/permissions): explicit permissions per module, nothing inherited. */
async function matrixSection() {
  const r = await api('GET', '/api/permissions'); if (r.status !== 200) return h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), failure(r, t('err_generic')));
  const m = r.data, label = (p) => { const k = `pm_${p.replace(/\./g, '_')}`; return has(k) ? t(k) : m.permissions[p].desc; };
  const sections = Object.entries(m.modules).map(([mod, perms]) => h('section', { class: 'card minw0', 'aria-labelledby': `mx-${mod}` }, h('h2', { id: `mx-${mod}`, text: has(`pmod_${mod}`) ? t(`pmod_${mod}`) : mod }),
    h('div', { class: 'dt-wrap', role: 'region', tabindex: '0', 'aria-label': mod }, h('table', { class: 'dt' }, h('caption', { class: 'sr', text: mod }),
      h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: t('mx_cap') }), ...m.roles.map((ro) => h('th', { scope: 'col', class: 'num', text: t(`role_${ro}`) })), h('th', { scope: 'col', text: t('mx_flags') }))),
      h('tbody', {}, ...perms.map((p) => { const d = m.permissions[p]; return h('tr', {}, h('th', { scope: 'row' }, label(p), h('div', { class: 'faint mono', text: p })), ...m.roles.map((ro) => h('td', { class: 'num' }, d.roles.includes(ro) ? h('span', {}, h('span', { 'aria-hidden': 'true', text: '✓' }), h('span', { class: 'sr', text: t('yes') })) : h('span', {}, h('span', { 'aria-hidden': 'true', class: 'faint', text: '—' }), h('span', { class: 'sr', text: t('no') })))),
        h('td', { class: 'faint' }, [d.critical ? t('mx_critical') : null, d.dual ? t('mx_dual') : null, d.planned ? t('mx_planned') : null].filter(Boolean).join(' · '))); }))))));
  const mine = h('p', { class: 'note' }, t('adm_you', { roles: m.you.roles.map((x) => t(`role_${x}`)).join(', '), n: m.you.permissions.length }));
  return h('div', { class: 'stack' }, h('p', { class: 'note', text: t('adm_rules') }), mine, ...sections);
}
