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
/** Horizontal bars: the labels are read in full on the left, in a readable size; rows: [{label, values:[per series], cls?}] (a row class gives that row's bars its own colour, e.g. one per family).
 *  A null value is an empty slot with a dot, never a zero. Every chart also has its summary and a data table. */
export function hbars({ title, rows, series, unit = '', valueFmt = fmt, width = 420 }) {
  const wrap = h('figure', { class: 'chart chart-h' }); wrap.append(h('figcaption', { class: 'chart-title', text: title }));
  const all = rows.flatMap((r) => r.values).filter((v) => v !== null && v !== undefined);
  if (!all.length) { wrap.append(h('p', { class: 'nodata', text: t('nodata_chart') })); return wrap; }
  const longest = Math.max(...rows.map((r) => r.label.length)), labelW = Math.max(70, Math.min(Math.round(width * 0.45), Math.round(longest * 6.2) + 12)), barH = Math.max(7, Math.min(14, 22 / series.length)), rowH = series.length * barH + 10;
  const valueW = 44, iw = width - labelW - valueW - 8, top = nice(Math.max(...all) * 1.02), height = rows.length * rowH + 24;
  const svg = s('svg', { viewBox: `0 0 ${width} ${height}`, class: 'chart-svg', role: 'img', 'aria-label': `${title}. ${t('chart_summary', { n: all.length, min: valueFmt(Math.min(...all)), max: valueFmt(Math.max(...all)), unit })}` });
  for (let i = 0; i <= 4; i++) { const xx = labelW + (iw / 4) * i; svg.append(s('line', { x1: xx, x2: xx, y1: 0, y2: height - 20, class: 'grid' }), s('text', { x: xx, y: height - 6, class: 'tick', 'text-anchor': i === 0 ? 'start' : i === 4 ? 'end' : 'middle' }, valueFmt((top / 4) * i))); }
  rows.forEach((r, ri) => {
    const y0 = ri * rowH + 4; svg.append(s('text', { x: labelW - 8, y: y0 + (series.length * barH) / 2 + 4, class: 'tick tick-label', 'text-anchor': 'end' }, r.label));
    series.forEach((ser, si) => { const v = r.values[si]; const yy = y0 + si * barH;
      if (v === null || v === undefined) { svg.append(s('text', { x: labelW + 4, y: yy + barH - 1, class: 'tick' }, '·')); return; }
      const w = Math.max(v > 0 ? 2 : 0, (v / top) * iw); svg.append(s('rect', { x: labelW, y: yy, width: w, height: barH - 2, class: r.cls || ser.cls, rx: 1.5 }), s('text', { x: labelW + w + 5, y: yy + barH - 3, class: 'tick' }, valueFmt(v))); });
  });
  wrap.append(svg, h('ul', { class: 'legend' }, ...series.map((ser) => h('li', {}, h('i', { class: `swatch ${ser.cls}` }), ser.name))));
  wrap.append(h('details', { class: 'chart-data' }, h('summary', { text: t('chart_table') }), h('div', { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': `${title} — ${t('chart_table')}` }, h('table', { class: 'matrix' }, h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: '' }), ...series.map((ser) => h('th', { scope: 'col', text: ser.name })))),
    h('tbody', {}, ...rows.map((r) => h('tr', {}, h('th', { scope: 'row', text: r.label }), ...series.map((_, si) => h('td', { text: r.values[si] === null || r.values[si] === undefined ? t('nodata_short') : `${r.values[si]}${unit}` }))))))))
  );
  return wrap;
}
export { put };
