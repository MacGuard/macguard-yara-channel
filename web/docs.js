/* Documentation pages: theme, code copy, and Mermaid diagrams with zoom, full screen, copy and SVG download.
   The diagram sources are text placed in the page at build time from this repository; Mermaid runs with securityLevel "strict". */
(function () {
'use strict';
var ui = {}; try { ui = JSON.parse(document.getElementById('main').getAttribute('data-ui')); } catch (e) {}
var $ = function (i) { return document.getElementById(i); };
try { if (localStorage.getItem('theme') === 'dark') document.body.classList.add('dark'); } catch (e) {}
var th = $('theme'); if (th) th.addEventListener('click', function () { document.body.classList.toggle('dark'); try { localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light'); } catch (e) {} renderAll(); });
var sw = $('lang-switch'); if (sw) sw.addEventListener('click', function () { try { localStorage.setItem('lang', sw.getAttribute('hreflang')); } catch (e) {} });

function btn(label, text, fn) { var b = document.createElement('button'); b.type = 'button'; b.textContent = text; b.setAttribute('aria-label', label); b.title = label; b.addEventListener('click', fn); return b; }
document.querySelectorAll('.codeblock').forEach(function (cb) {
  var b = btn(ui.copy_code || 'Copy', ui.copy_code || 'Copy', function () { copy(cb.querySelector('code').textContent, b, ui.copy_code); }); b.className = 'copy'; cb.appendChild(b);
});
function copy(text, button, original) {
  function done() { var o = button.textContent; button.textContent = ui.copied || 'Copied'; setTimeout(function () { button.textContent = original || o; }, 1500); }
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
  function fallback() { var t = document.createElement('textarea'); t.value = text; t.setAttribute('readonly', ''); t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); done(); } catch (e) {} t.remove(); }
}

var state = window.__docsDiagrams = { total: 0, rendered: 0, errors: [], done: false };
var counter = 0;
function themeName() { return document.body.classList.contains('dark') ? 'dark' : 'default'; }
function natural(svg) { var vb = (svg.getAttribute('viewBox') || '').split(/[\s,]+/).map(Number); return vb.length === 4 ? { w: vb[2], h: vb[3] } : { w: svg.getBoundingClientRect().width, h: svg.getBoundingClientRect().height }; }
function setScale(fig, s) { var svg = fig.querySelector('.dg-stage svg'); if (!svg) return; var n = fig._nat; s = Math.max(0.3, Math.min(3, s)); fig._scale = s; svg.setAttribute('width', Math.round(n.w * s)); svg.setAttribute('height', Math.round(n.h * s)); svg.style.width = Math.round(n.w * s) + 'px'; svg.style.height = Math.round(n.h * s) + 'px'; }
function minFont(svg) { var m = 1e9; svg.querySelectorAll('text,tspan,.nodeLabel,foreignObject').forEach(function (t) { var f = parseFloat(getComputedStyle(t).fontSize) || 0; if (f > 0) m = Math.min(m, f); }); return m < 1e9 ? m : 14; }
/* fit to the width, but never so small that the text is unreadable (about 9 px): a wide diagram then scrolls inside its own stage */
function fit(fig) { var stage = fig.querySelector('.dg-stage'), avail = stage.clientWidth - 20, s = Math.min(1, avail / fig._nat.w), floor = Math.min(1, 9 / (fig._minFont || 14)); setScale(fig, Math.max(s, floor)); }
function build(fig) {
  var stage = fig.querySelector('.dg-stage'), name = fig.getAttribute('data-diagram'), src = fig.querySelector('.mermaid-src').textContent;
  var old = fig.querySelector('.dg-bar'); if (old) old.remove();
  var bar = document.createElement('div'); bar.className = 'dg-bar'; bar.setAttribute('role', 'toolbar'); bar.setAttribute('aria-label', fig.querySelector('figcaption').textContent);
  bar.appendChild(btn(ui.zoom_out || 'Zoom out', '−', function () { setScale(fig, fig._scale / 1.25); }));
  bar.appendChild(btn(ui.zoom_in || 'Zoom in', '+', function () { setScale(fig, fig._scale * 1.25); }));
  bar.appendChild(btn(ui.fit || 'Fit', '⤢', function () { fit(fig); }));
  bar.appendChild(btn(ui.reset || '100%', '1:1', function () { setScale(fig, 1); }));
  bar.appendChild(btn(ui.full || 'Full screen', '⛶', function () { toggleFull(fig); }));
  var cp = btn(ui.copy || 'Copy', '⧉', function () { copy(src, cp, '⧉'); }); bar.appendChild(cp);
  bar.appendChild(btn(ui.svg || 'SVG', '⬇ SVG', function () { var svg = stage.querySelector('svg'); if (!svg) return; var blob = new Blob(['<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(svg)], { type: 'image/svg+xml' }); var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name + '.svg'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(a.href); }, 500); }));
  fig.insertBefore(bar, stage);
  stage.addEventListener('keydown', function (e) { if (e.key === '+' || e.key === '=') { setScale(fig, fig._scale * 1.25); e.preventDefault(); } else if (e.key === '-') { setScale(fig, fig._scale / 1.25); e.preventDefault(); } else if (e.key === '0') { fit(fig); e.preventDefault(); } });
}
function toggleFull(fig) {
  var on = document.fullscreenElement === fig || fig.classList.contains('dg-full');
  if (on) { if (document.fullscreenElement) document.exitFullscreen(); fig.classList.remove('dg-full'); }
  else if (fig.requestFullscreen) fig.requestFullscreen().catch(function () { fig.classList.add('dg-full'); });
  else fig.classList.add('dg-full');
  setTimeout(function () { fit(fig); }, 150);
}
document.addEventListener('keydown', function (e) { if (e.key === 'Escape') document.querySelectorAll('.diagram.dg-full').forEach(function (f) { f.classList.remove('dg-full'); fit(f); }); });

function renderFigure(fig) {
  var stage = fig.querySelector('.dg-stage'), src = fig.querySelector('.mermaid-src').textContent, id = 'dg' + (++counter);
  return window.mermaid.render(id, src).then(function (r) {
    stage.querySelector('.dg-loading') && stage.querySelector('.dg-loading').remove();
    var prev = stage.querySelector('svg'); if (prev) prev.remove();
    var holder = document.createElement('div'); holder.innerHTML = r.svg; var svg = holder.firstElementChild; stage.appendChild(svg);
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', fig.querySelector('figcaption').textContent); svg.removeAttribute('style');
    fig._nat = natural(svg); fig._minFont = minFont(svg); build(fig); fit(fig); state.rendered++;
  }).catch(function (e) { state.errors.push({ diagram: fig.getAttribute('data-diagram'), error: String(e && e.message || e).slice(0, 200) }); stage.innerHTML = '<p class="badmsg">The diagram could not be drawn. Its source is below.</p>'; fig.querySelector('.dg-code').open = true; });
}
function renderAll() {
  var figs = document.querySelectorAll('figure.diagram'); state.total = figs.length; state.rendered = 0; state.errors = []; state.done = false;
  if (!figs.length) { state.done = true; return; }
  if (!window.mermaid) { state.errors.push({ error: 'mermaid is not loaded' }); state.done = true; document.querySelectorAll('.dg-code').forEach(function (d) { d.open = true; }); return; }
  window.mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', theme: themeName(), fontFamily: '-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif', flowchart: { useMaxWidth: false, htmlLabels: false, curve: 'basis' }, sequence: { useMaxWidth: false, wrap: true, width: 150 }, state: { useMaxWidth: false }, themeVariables: {} });
  var chain = Promise.resolve(); figs.forEach(function (f) { chain = chain.then(function () { return renderFigure(f); }); });
  chain.then(function () { state.done = true; });
}
window.addEventListener('resize', function () { document.querySelectorAll('figure.diagram').forEach(function (f) { if (f._nat && !document.fullscreenElement) fit(f); }); });
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', renderAll); else renderAll();
})();
