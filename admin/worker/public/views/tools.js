// Language and theme controls, shared by the sign-in screen and the application shell.
import { t, getLang, setLang } from '../i18n.js';
import { h, icon, getTheme, setTheme } from '../ui.js';

export function tools() {
  const rerender = () => window.dispatchEvent(new CustomEvent('mg:rerender'));
  const seg = (label, items, current, pick, cls = '') => {
    const box = h('div', { class: `seg ${cls}`, role: 'group', 'aria-label': label });
    const draw = () => { box.replaceChildren(...items.map(([val, text, ic, lang]) => { const b = h('button', { type: 'button', 'aria-pressed': String(current() === val), 'aria-label': ic ? text : null, title: ic ? text : null, lang }, ic ? icon(ic) : text); b.addEventListener('click', () => { pick(val); draw(); }); return b; })); };
    draw(); return box;
  };
  return h('div', { class: 'tools' },
    seg(t('lang'), [['es', 'ES', null, 'es'], ['en', 'EN', null, 'en']], getLang, (v) => { setLang(v); rerender(); }),
    seg(t('theme'), [['auto', t('theme_auto'), 'auto'], ['light', t('theme_light'), 'sun'], ['dark', t('theme_dark'), 'moon']], getTheme, (v) => setTheme(v)));
}
