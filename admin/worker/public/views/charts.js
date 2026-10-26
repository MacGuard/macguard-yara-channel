// Small accessible SVG charts. Colours come from CSS classes (the CSP forbids inline styles); every chart has a text summary and a data table.
import { t } from '../i18n.js';
import { h, put } from '../ui.js';

const NS = 'http://www.w3.org/2000/svg';
const s = (tag, attrs, ...kids) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, String(v)); for (const c of kids) if (c) e.append(typeof c === 'string' ? document.createTextNode(c) : c); return e; };
const nice = (max) => { if (max <= 0) return 1; const p = 10 ** Math.floor(Math.log10(max)), n = max / p; return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p; };
const fmt = (v) => (Math.abs(v) >= 1000 ? `${Math.round(v / 100) / 10}k` : String(Math.round(v * 10) / 10));

/** series: [{name, cls, values:[number|null per label]}]; null = no observation (drawn as an empty slot, never as zero). */
export function chart({ title, labels, series, kind = 'bars', unit = '', width = 640, height = 220, labelFn = (lb) => lb.slice(5) }) {
  const m = { l: 44, r: 10, t: 10, b: 30 }, iw = width - m.l - m.r, ih = height - m.t - m.b, n = labels.length;
  const all = series.flatMap((x) => x.values).filter((v) => v !== null && v !== undefined);
  const wrap = h('figure', { class: 'chart' }); const caption = h('figcaption', { class: 'chart-title', text: title }); wrap.append(caption);
  if (!all.length) { wrap.append(h('p', { class: 'nodata', text: t('nodata_chart') })); return wrap; }
  const top = nice(Math.max(...all) * 1.05), y = (v) => m.t + ih - (v / top) * ih, slot = iw / n, x = (i) => m.l + slot * i + slot / 2;
  const svg = s('svg', { viewBox: `0 0 ${width} ${height}`, class: 'chart-svg', role: 'img', 'aria-label': `${title}. ${t('chart_summary', { n: all.length, min: fmt(Math.min(...all)), max: fmt(Math.max(...all)), unit })}` });
  for (let i = 0; i <= 4; i++) { const v = (top / 4) * i, yy = y(v); svg.append(s('line', { x1: m.l, x2: width - m.r, y1: yy, y2: yy, class: 'grid' }), s('text', { x: m.l - 6, y: yy + 4, class: 'tick', 'text-anchor': 'end' }, fmt(v))); }
  const step = Math.max(1, Math.ceil(n / 8));
  labels.forEach((lb, i) => { if (i % step === 0 || i === n - 1) svg.append(s('text', { x: x(i), y: height - 8, class: 'tick', 'text-anchor': 'middle' }, labelFn(lb))); });
  if (kind === 'bars') {
    const g = series.length, bw = Math.max(3, Math.min(28, (slot * 0.7) / g));
    series.forEach((ser, si) => ser.values.forEach((v, i) => { if (v === null || v === undefined) { svg.append(s('text', { x: x(i), y: m.t + ih - 4, class: 'tick', 'text-anchor': 'middle' }, '·')); return; } const bx = x(i) - (bw * g) / 2 + si * bw, bh = Math.max(1, ih - (y(v) - m.t)); svg.append(s('rect', { x: bx, y: m.t + ih - bh, width: bw - 1, height: bh, class: ser.cls, rx: 1.5 })); }));
  } else {
    series.forEach((ser) => { let d = ''; ser.values.forEach((v, i) => { if (v === null || v === undefined) return; d += `${d && ser.values[i - 1] !== null && ser.values[i - 1] !== undefined ? 'L' : 'M'}${x(i)},${y(v)}`; }); svg.append(s('path', { d, class: `line ${ser.cls}`, fill: 'none' }));
      ser.values.forEach((v, i) => { if (v !== null && v !== undefined) svg.append(s('circle', { cx: x(i), cy: y(v), r: 3.2, class: ser.cls })); }); });
  }
  wrap.append(svg, h('ul', { class: 'legend' }, ...series.map((ser) => h('li', {}, h('i', { class: `swatch ${ser.cls}` }), ser.name))));
  const rows = labels.map((lb, i) => h('tr', {}, h('th', { scope: 'row', text: lb }), ...series.map((ser) => h('td', { text: ser.values[i] === null || ser.values[i] === undefined ? t('nodata_short') : `${ser.values[i]}${unit}` }))));
  wrap.append(h('details', { class: 'chart-data' }, h('summary', { text: t('chart_table') }), h('div', { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': `${title} — ${t('chart_table')}` }, h('table', { class: 'matrix' }, h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: t('chart_day') }), ...series.map((ser) => h('th', { scope: 'col', text: ser.name })))), h('tbody', {}, rows)))));
  return wrap;
}
export { put };
