// Sign-in screen and its states. Nothing about the quarantine is requested or shown here: it is rendered before anyone is authenticated or authorized.
import { t } from '../i18n.js';
import { h, icon, put } from '../ui.js';
import { tools } from './tools.js';

const NOTICE = {   // variant -> [alert kind, title key, text key]
  expired: ['info', 'in_expired', 'in_expired_p'], reauth: ['info', 'in_reauth', 'in_reauth_p'], cancelled: ['info', 'in_cancelled', 'in_cancelled_p'],
  state: ['bad', 'in_state', 'in_state_p'], oauth: ['bad', 'in_oauth', 'in_oauth_p'], unavailable: ['warn', 'in_down', 'in_down_p'],
};

export function renderLogin(root, { variant = 'signin', login = '', onLogout } = {}) {
  const denied = variant === 'denied', notice = NOTICE[variant];
  const brand = h('a', { class: 'brand', href: '/', 'aria-label': `${t('app')} — ${t('app_sub')}` }, icon('logo'), h('div', {}, h('div', { class: 'brand-name', text: 'MacGuard' }), h('div', { class: 'brand-sub', text: 'Quarantine' })));
  const points = h('ul', { class: 'auth-points' }, ...[['lock', 'in_p1'], ['key', 'in_p2'], ['audit', 'in_p3']].map(([ic, k]) => h('li', {}, icon(ic), h('span', { text: t(k) }))));
  const left = h('section', { class: 'auth-brand', 'aria-label': t('app') }, h('div', {}, brand, h('div', { class: 'mt-48' }, h('h2', { text: t('in_h') }), points)), h('p', { class: 'muted', text: '© MacGuard' }));

  const btn = h('a', { class: 'btn btn-github', href: '/auth/login' }, icon('github'), h('span', { text: t('in_btn') }));
  btn.addEventListener('click', () => {   // navigation proceeds; this only gives immediate, accessible feedback while the redirect happens
    btn.setAttribute('aria-busy', 'true'); btn.replaceChildren(h('span', { class: 'spinner', 'aria-hidden': 'true' }), h('span', { text: t('in_btn_going') }));
  });
  const msg = h('div', { role: denied || variant === 'state' || variant === 'oauth' || variant === 'unavailable' ? 'alert' : 'status' });
  if (denied) msg.append(h('div', { class: 'alert alert-warn' }, icon('lock'), h('div', {}, h('strong', { text: t('in_denied') }), h('p', { text: t('in_denied_p', { login }) }))));
  else if (notice) msg.append(h('div', { class: `alert alert-${notice[0]}` }, icon(notice[0] === 'bad' || notice[0] === 'warn' ? 'alert' : 'info'), h('div', {}, h('strong', { text: t(notice[1]) }), h('p', { text: t(notice[2]) }))));

  let actions;
  if (denied) {
    const out = h('button', { type: 'button', class: 'btn btn-primary', text: t('signout') }); out.addEventListener('click', () => onLogout && onLogout(false));
    const other = h('button', { type: 'button', class: 'btn', text: t('in_other') }); other.addEventListener('click', () => onLogout && onLogout(true));
    actions = h('div', { class: 'grid-10' }, out, other);
  } else if (variant === 'unavailable') {
    const retry = h('button', { type: 'button', class: 'btn btn-primary', text: t('retry') }); retry.addEventListener('click', () => location.replace('/'));
    actions = h('div', { class: 'grid-10' }, retry);
  } else actions = btn;

  const card = h('div', { class: 'auth-card' },
    h('div', {}, h('h1', { id: 'auth-title', tabindex: '-1', text: denied ? t('in_denied') : t('in_title') }), denied ? null : h('p', { class: 'muted mt-8', text: t('in_lead') })),
    denied ? null : msg, denied ? msg : null, actions, denied || variant === 'unavailable' ? null : h('p', { class: 'note', text: t('in_note') }));
  const right = h('main', { class: 'auth-main', id: 'main' }, h('div', { class: 'auth-tools' }, tools()), card);
  put(root, h('a', { class: 'skip', href: '#main', text: t('skip') }), h('div', { class: 'auth' }, left, right));
  document.title = `${denied ? t('in_denied') : t('in_title')} · MacGuard Quarantine`;
  if (notice || denied) document.getElementById('auth-title').focus();
}
