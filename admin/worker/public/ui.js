// Small DOM toolkit shared by every screen: element builder (text only, never innerHTML), inline icons, dialogs, toasts, formatting.
import { t, getLang, has } from './i18n.js';

const NS = 'http://www.w3.org/2000/svg';
const P = {   // 24x24 stroke icons
  quarantine: 'M4 13l2-8h12l2 8v6H4v-6zM4 13h4l1 2h6l1-2h4', audit: 'M12 7v5l3 2M21 12a9 9 0 11-3-6.7M21 4v5h-5', users: 'M16 20v-1.5a3.5 3.5 0 00-3.5-3.5h-5A3.5 3.5 0 004 18.5V20M10 11.5a3.2 3.2 0 100-6.4 3.2 3.2 0 000 6.4zM20 20v-1.4a3.5 3.5 0 00-2.5-3.3M15.5 5.3a3.2 3.2 0 010 5.8',
  check: 'M5 12.5l4.5 4.5L19 7.5', x: 'M6 6l12 12M18 6L6 18', copy: 'M9 9h10v11H9zM5 15V4h10', menu: 'M4 7h16M4 12h16M4 17h16', search: 'M11 17a6 6 0 100-12 6 6 0 000 12zM16 16l4 4', plus: 'M12 5v14M5 12h14',
  sun: 'M12 16a4 4 0 100-8 4 4 0 000 8zM12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6L7 7M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4', moon: 'M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z', auto: 'M4 5h16v11H4zM9 20h6M12 16v4',
  globe: 'M12 21a9 9 0 100-18 9 9 0 000 18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18', logout: 'M10 4H5v16h5M15 8l4 4-4 4M19 12H9', alert: 'M12 4l9 16H3L12 4zM12 10v4M12 17v.01',
  refresh: 'M20 11a8 8 0 10-2.3 5.7M20 5v6h-6', chevron: 'M9 6l6 6-6 6', back: 'M15 6l-6 6 6 6', lock: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 017 0v3', key: 'M14 10a4 4 0 11-3.5-4M12 12l8 8M17 17l2-2', file: 'M7 3h7l4 4v14H7zM14 3v4h4', info: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 11v5M12 8v.01',
  edit: 'M4 20h4L19 9l-4-4L4 16v4z', trash: 'M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13', pause: 'M8 5v14M16 5v14', history: 'M3 12a9 9 0 109-9 9 9 0 00-6.4 2.6L3 8M3 3v5h5M12 8v4l3 2',
};
const GITHUB = 'M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z';

export function icon(name, cls = '') {
  const s = document.createElementNS(NS, 'svg'); s.setAttribute('aria-hidden', 'true'); s.setAttribute('focusable', 'false');
  if (name === 'github') { s.setAttribute('viewBox', '0 0 16 16'); s.setAttribute('class', `ic fill ${cls}`.trim()); const p = document.createElementNS(NS, 'path'); p.setAttribute('d', GITHUB); s.appendChild(p); return s; }
  if (name === 'logo') {   // MacGuard mark: shield with a check
    s.setAttribute('viewBox', '0 0 32 32'); s.setAttribute('class', `ic ${cls}`.trim());
    const a = document.createElementNS(NS, 'path'); a.setAttribute('d', 'M16 2.5l11 4v8.6c0 7.1-4.7 12.1-11 14.4C9.7 27.2 5 22.2 5 15.1V6.5l11-4z'); a.setAttribute('fill', 'currentColor'); a.setAttribute('stroke', 'none');
    const b = document.createElementNS(NS, 'path'); b.setAttribute('d', 'M10.8 16.2l3.9 3.9 6.6-7.4'); b.setAttribute('fill', 'none'); b.setAttribute('stroke', '#fff'); b.setAttribute('stroke-width', '2.6'); s.append(a, b); return s;
  }
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', `ic ${cls}`.trim());
  for (const d of (P[name] || '').split(/(?=M)/).filter(Boolean)) { const p = document.createElementNS(NS, 'path'); p.setAttribute('d', d); s.appendChild(p); }
  return s;
}

/** Element builder. Children are text nodes or elements; there is deliberately no way to inject markup. */
export function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
    else if (k === 'style') throw new Error('inline styles are forbidden by the CSP (style-src self): use a class');
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of kids.flat(Infinity)) { if (c === null || c === undefined || c === false) continue; e.append(c instanceof Node ? c : document.createTextNode(String(c))); }
  return e;
}
/** Replace a node's children, ignoring null/false entries (replaceChildren would print them as text). */
export const put = (parent, ...kids) => { parent.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)); return parent; };
export const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

// ---- theme ----
export const getTheme = () => { try { const v = localStorage.getItem('mg_theme'); return v === 'light' || v === 'dark' ? v : 'auto'; } catch { return 'auto'; } };
export function setTheme(v) { try { if (v === 'auto') localStorage.removeItem('mg_theme'); else localStorage.setItem('mg_theme', v); } catch { /* ignore */ } if (v === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', v); }

// ---- formatting ----
const loc = () => (getLang() === 'en' ? 'en-GB' : 'es-ES');
export function fmtDate(iso) { const d = new Date(iso); return isNaN(d) ? '—' : new Intl.DateTimeFormat(loc(), { day: 'numeric', month: 'short', year: 'numeric' }).format(d); }
export function fmtTime(iso) { const d = new Date(iso); return isNaN(d) ? '—' : new Intl.DateTimeFormat(loc(), { hour: '2-digit', minute: '2-digit' }).format(d); }
export function fmtDateTime(iso) { const d = new Date(iso); return isNaN(d) ? '—' : new Intl.DateTimeFormat(loc(), { dateStyle: 'medium', timeStyle: 'short' }).format(d); }
export const shortSha = (s) => (s && s.length > 16 ? `${s.slice(0, 8)}…${s.slice(-6)}` : s || '');
export function bytes(n) { return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`; }
export function reasonLabel(code) { const k = `why_${String(code).replace(/[^a-z0-9]+/gi, '_')}`; return has(k) ? t(k) : String(code).replace(/[-_]+/g, ' '); }
export function rulesText(n) { return n === 1 ? t('rules_one') : t('rules_n', { n }); }

// ---- badges ----
const STATE_CLASS = { PENDING: 'pending', UNDER_REVIEW: 'review', APPROVED_PENDING_VALIDATION: 'approved', REJECTED: 'rejected', RELEASED: 'released' };
export const stateBadge = (s) => h('span', { class: `badge badge-${STATE_CLASS[s] || 'neutral'}`, text: t(`st_${s}`) });
export const roleBadge = (r) => h('span', { class: `badge ${r === 'ADMIN' ? 'badge-admin' : r === 'NONE' ? 'badge-neutral badge-none' : r === 'REVIEWER' ? 'badge-review' : 'badge-neutral'}`, text: t(`role_${r}`) });

export function avatar(userId, login, size = 36) {
  const fallback = () => h('div', { class: `avatar avatar-fallback ${size > 40 ? 'avatar-lg' : ''}`, 'aria-hidden': 'true', text: (login || '?').slice(0, 1).toUpperCase() });
  if (!Number.isInteger(userId)) return fallback();
  const img = h('img', { class: `avatar ${size > 40 ? 'avatar-lg' : ''}`, src: `https://avatars.githubusercontent.com/u/${userId}?s=${size * 2}`, alt: '', width: size, height: size, loading: 'lazy', referrerpolicy: 'no-referrer' });
  img.addEventListener('error', () => img.replaceWith(fallback()), { once: true }); return img;
}

// ---- toasts and clipboard ----
let toasts;
export function toast(msg, bad = false) {
  if (!toasts) { toasts = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.append(toasts); }
  const n = h('div', { class: `toast ${bad ? 'bad' : ''}`, text: msg }); toasts.append(n); setTimeout(() => n.remove(), bad ? 8000 : 4000);
}
export async function copyText(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch { const ta = h('textarea', { 'aria-hidden': 'true', class: 'sr' }); ta.value = text; document.body.append(ta); ta.select(); try { document.execCommand('copy'); } catch { /* ignore */ } ta.remove(); }
  toast(t('copied'));
  if (btn) { const old = btn.getAttribute('aria-label'); btn.setAttribute('aria-label', t('copied')); setTimeout(() => btn.setAttribute('aria-label', old), 1500); }
}
export function copyButton(text, label) {
  const b = h('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-icon', 'aria-label': label || t('copy'), title: label || t('copy') }, icon('copy'));
  b.addEventListener('click', () => copyText(text, b)); return b;
}
export function shaFull(sha) { return h('code', { class: 'shafull' }, sha.slice(0, 32), h('br'), sha.slice(32)); }

// ---- dialogs ----
/** Modal form. `build()` returns the body nodes; `submit()` returns null on success or an error string (the dialog stays open). */
export function modal({ title, intro, body, confirmLabel, variant = 'primary', submit, validate }) {
  const err = h('p', { class: 'alert alert-bad', role: 'alert', hidden: true });
  const go = h('button', { type: 'submit', class: `btn ${variant === 'bad' ? 'btn-bad' : variant === 'ok' ? 'btn-ok' : 'btn-primary'}`, text: confirmLabel || t('confirm') });
  const cancel = h('button', { type: 'button', class: 'btn', text: t('cancel') });
  const hid = `dlg-${Math.random().toString(36).slice(2)}`;
  const form = h('form', { method: 'dialog', novalidate: true }, h('h2', { id: hid, text: title }), intro ? h('p', { class: 'muted', text: intro }) : null, body, err, h('div', { class: 'row' }, cancel, go));
  const d = h('dialog', { class: 'modal', 'aria-labelledby': hid }, form);
  const opener = document.activeElement;
  const show = (m) => { err.textContent = m; err.hidden = !m; };
  cancel.addEventListener('click', () => d.close());
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault(); show(''); const bad = validate ? validate() : null; if (bad) { show(bad); return; }
    go.disabled = true; go.setAttribute('aria-busy', 'true'); const e = await submit(); go.disabled = false; go.removeAttribute('aria-busy');
    if (e) show(e); else d.close('ok');
  });
  d.addEventListener('close', () => { d.remove(); if (opener && opener.isConnected) opener.focus(); });
  document.body.append(d); d.showModal(); const first = d.querySelector('input,textarea,select'); (first || go).focus(); return d;
}
export function reasonField() {
  const ta = h('textarea', { class: 'textarea', rows: '3', maxlength: '2000', id: `r-${Math.random().toString(36).slice(2)}`, 'aria-describedby': 'reason-hint' });
  return { node: h('div', { class: 'field' }, h('label', { for: ta.id, text: t('reason') }), ta, h('p', { id: 'reason-hint', class: 'note', text: t('reason_hint') })), get value() { return ta.value.trim(); }, el: ta };
}

/** Single-choice filter as a group of toggle buttons (no native <select>: WebKit's select internals violate a strict CSP, and this reads better on a phone). */
export function pillGroup(label, options, current, pick) {
  const box = h('div', { class: 'pills compact', role: 'group', 'aria-label': label });
  const draw = (cur) => put(box, ...options.map(([value, text, n]) => { const b = h('button', { type: 'button', class: 'pill', 'aria-pressed': String(cur === value) }, text, n === undefined ? null : h('b', { text: String(n) })); b.addEventListener('click', () => pick(value)); return b; }));
  draw(current); box.redraw = draw; return box;
}
/** Single-choice radio group with a visible legend and a description per option. */
export function radioGroup(legend, name, options, value) {
  const fs = h('fieldset', { class: 'radios' }, h('legend', { text: legend }));
  for (const [val, text, hint] of options) { const id = `${name}-${val}`; fs.append(h('label', { class: 'radio', for: id }, h('input', { type: 'radio', name, id, value: val, checked: val === value }), h('span', {}, h('strong', { text }), hint ? h('small', { text: hint }) : null))); }
  return { node: fs, get value() { const c = fs.querySelector('input:checked'); return c ? c.value : ''; } };
}
