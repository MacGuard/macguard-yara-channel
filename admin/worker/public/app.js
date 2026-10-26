// Application shell: boot, sign-in states, navigation (sidebar on desktop, drawer on small screens), hash routing.
import { t, getLang } from './i18n.js';
import { h, icon, avatar, roleBadge, put, can } from './ui.js';
import { api, setCsrf } from './api.js';
import { renderLogin } from './views/login.js';
import { renderQuarantine } from './views/quarantine.js';
import { renderPublished } from './views/published.js';
import { renderPublishedRule } from './views/published_rule.js';
import { renderIntel } from './views/intel.js';
import { renderLogs } from './views/logs.js';
import { renderDashboard } from './views/dashboard.js';
import { renderActivity } from './views/activity.js';
import { renderSources } from './views/sources.js';
import { renderRule } from './views/rule.js';
import { renderAudit } from './views/audit.js';
import { renderMembers } from './views/members.js';
import { tools } from './views/tools.js';
import { renderRestore } from './views/restore.js';

const root = document.getElementById('root');
const NAV = [{ id: 'dashboard', icon: 'grid', label: 'nav_dashboard', perm: 'dashboard.read' }, { id: 'quarantine', icon: 'quarantine', label: 'nav_quarantine', perm: 'quarantine.read' }, { id: 'published', icon: 'check', label: 'nav_published', perm: 'publication.read' },
  { id: 'intel', icon: 'globe', label: 'nav_intel', perm: 'intel.sources.read' }, { id: 'activity', icon: 'calendar', label: 'nav_activity', perm: 'dashboard.read' }, { id: 'logs', icon: 'file', label: 'nav_logs', perm: 'logs.read' }, { id: 'sources', icon: 'source', label: 'nav_sources', perm: 'sources.read' },
  { id: 'restore', icon: 'history', label: 'nav_restore', perm: 'backups.read' }, { id: 'audit', icon: 'audit', label: 'nav_audit', perm: 'audit.read' }, { id: 'admin', icon: 'users', label: 'nav_admin', perm: 'admin.members.read' }];
let me = null, content = null, links = [];
const wasIn = { get: () => { try { return localStorage.getItem('mg_was_in') === '1'; } catch { return false; } }, set: (v) => { try { if (v) localStorage.setItem('mg_was_in', '1'); else localStorage.removeItem('mg_was_in'); } catch { /* ignore */ } } };

const parse = () => { const raw = location.hash.replace(/^#/, '') || '/dashboard'; const [path, qs] = raw.split('?'); return { path, query: new URLSearchParams(qs || '') }; };
function go(hash, replace) { if (replace) { history.replaceState(null, '', hash); route(); } else location.hash = hash; }

async function logout(thenSignIn) { await api('POST', '/api/logout'); wasIn.set(false); location.replace(thenSignIn ? '/auth/login' : '/'); }

function navList(close) {
  links = NAV.filter((n) => can(me, n.perm)).map((n) => { const a = h('a', { href: `#/${n.id}`, 'data-nav': n.id }, icon(n.icon), h('span', { text: t(n.label) })); a.addEventListener('click', () => close && close()); return a; });
  return h('nav', { class: 'nav', 'aria-label': t('main_nav') }, ...links);
}
function userBlock() {
  return h('div', { class: 'side-foot' }, tools(), h('div', { class: 'usercard' }, avatar(me.user_id, me.login, 36), h('div', {}, h('strong', { text: me.login }), roleBadge(me.role))),
    h('button', { type: 'button', class: 'btn btn-sm', onclick: () => logout(false) }, icon('logout'), t('signout')));
}
const brand = () => h('a', { class: 'brand', href: '#/dashboard', 'aria-label': `${t('app')}` }, icon('logo'), h('div', {}, h('div', { class: 'brand-name', text: 'MacGuard' }), h('div', { class: 'brand-sub', text: 'Quarantine' })));

function shell() {
  const drawer = h('dialog', { class: 'drawer', 'aria-label': t('menu') });
  const fill = () => drawer.replaceChildren(h('div', { class: 'flex-between' }, brand(), h('button', { type: 'button', class: 'btn btn-ghost btn-icon', 'aria-label': t('close'), onclick: () => drawer.close() }, icon('x'))), navList(() => drawer.close()), userBlock());
  const menu = h('button', { type: 'button', class: 'btn btn-icon', 'aria-label': t('menu'), onclick: () => { fill(); highlight(); drawer.showModal(); } }, icon('menu'));
  const top = h('header', { class: 'topbar' }, brand(), h('div', { class: 'grow' }), menu);
  const side = h('aside', { class: 'sidebar' }, brand(), navList(), userBlock());
  content = h('main', { class: 'content', id: 'main', tabindex: '-1' });
  put(root, h('a', { class: 'skip', href: '#main', onclick: (e) => { e.preventDefault(); content.focus(); }, text: t('skip') }), h('div', { class: 'app' }, side, h('div', { class: 'minw0' }, top, content)), drawer);
  drawer.addEventListener('click', (e) => { if (e.target === drawer) drawer.close(); });
}
function highlight() { const { path } = parse(); const cur = path.startsWith('/rules') ? 'quarantine' : path.split('/')[1]; document.querySelectorAll('[data-nav]').forEach((a) => { if (a.dataset.nav === cur) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); }

let seq = 0, firstRoute = true;
async function route() {
  if (!me) return; const mine = ++seq, { path, query } = parse(); highlight();
  const view = content.cloneNode(false); const ctx = { root: view, me, query, go, rerender: () => route() };
  const rm = path.match(/^\/rules\/([0-9a-f-]{8,64})$/), seg = path.split('/')[1];
  try {
    if (rm) await renderRule(ctx, rm[1]);
    else if (seg === 'restore' && can(me, 'backups.read')) await renderRestore(ctx);
    else if (seg === 'intel' && can(me, 'intel.sources.read')) await renderIntel(ctx);
    else if (seg === 'logs' && can(me, 'logs.read')) await renderLogs(ctx);
    else if (seg === 'audit' && can(me, 'audit.read')) await renderAudit(ctx);
    else if ((seg === 'admin' || seg === 'members') && can(me, 'admin.members.read')) await renderMembers(ctx);
    else if (seg === 'quarantine') await renderQuarantine(ctx);
    else if (path === '/published/rule') await renderPublishedRule(ctx);
    else if (seg === 'published') await renderPublished(ctx);
    else if (seg === 'activity') await renderActivity(ctx);
    else if (seg === 'sources') await renderSources(ctx);
    else if (seg === 'dashboard' || !seg) await renderDashboard(ctx);
    else { go('#/dashboard', true); return; }
  } catch (e) {
    console.error('view failed', e);
    view.replaceChildren(h('p', { class: 'alert alert-bad', role: 'alert' }, icon('alert'), t('err_generic')));
  }
  if (mine !== seq) return;   // a newer navigation already took over
  content.replaceWith(view); content = view; content.id = 'main'; content.setAttribute('tabindex', '-1');
  const title = content.querySelector('#page-title'); if (title) document.title = `${title.textContent} · MacGuard Quarantine`;
  if (!firstRoute) { window.scrollTo(0, 0); (title || content).focus({ preventScroll: true }); }   // on later navigations focus moves to the new page heading for screen readers; the first load keeps the natural tab order (skip link first)
  firstRoute = false;
}

function showLogin(variant, extra) { me = null; renderLogin(root, { variant, ...extra, onLogout: logout }); }
window.addEventListener('hashchange', route);
window.addEventListener('mg:rerender', () => { if (me) { shell(); route(); } else boot(); });
window.addEventListener('mg:unauth', (e) => { if (me) { wasIn.set(false); showLogin(e.detail === 'reauth' ? 'reauth' : 'expired'); } });

async function boot() {
  const q = new URLSearchParams(location.search), e = q.get('e');
  if (e) { history.replaceState(null, '', '/'); if (['state', 'cancelled', 'oauth', 'unavailable'].includes(e)) { showLogin(e); return; } }
  const r = await api('GET', '/api/me');
  if (r.status === 200) { me = r.data; setCsrf(me.csrf); wasIn.set(true); document.documentElement.lang = getLang(); shell(); await route(); return; }
  if (r.status === 401) { showLogin(r.data.code === 'reauth' ? 'reauth' : wasIn.get() ? 'expired' : 'signin'); return; }
  if (r.status === 403 && r.data.code === 'no_access') { setCsrf(r.data.csrf); showLogin('denied', { login: r.data.login }); return; }
  showLogin('unavailable');
}
boot();
