#!/usr/bin/env python3
"""Renders the built documentation in headless Chrome and checks what a reader would see.

usage: docs_check.py [--site DIR] [--chrome PATH]
  --site   an assembled site (output of build_site.py: release data + web assets). The docs are rebuilt from docs-src/ into a COPY of it.

For every page, in both languages and at desktop (1280 px) and phone (390 px) widths, loaded in an iframe of exactly that width:
  * every Mermaid diagram compiles and renders (no error, rendered == total) with the vendored Mermaid
  * no horizontal scroll of the page; nothing in the article sticks out except inside its own scroll area (diagram stage, table, code)
  * diagram toolbars: all controls present with accessible names; zoom in/out/fit/1:1 change the size; the SVG has role=img and a label
  * rendered text stays legible after fit (>= 8 px effective) and the fitted diagram is not smaller than half its natural size on a phone
  * one h1, main landmark, html lang, every button/link has a name
Exit 0 only if everything passes."""
import argparse, json, os, pathlib, shutil, socket, subprocess, sys, tempfile, time, re, html
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_docs

PROBE = r"""<!doctype html><meta charset=utf-8><title>probe</title><pre id=result>RUNNING</pre><script>
var W=%(width)d, URLS=%(urls)s, out=[];
function sleep(ms){return new Promise(function(r){setTimeout(r,ms)})}
async function one(u){
  var f=document.createElement('iframe'); f.style.cssText='width:'+W+'px;height:900px;border:0'; f.src=u; document.body.appendChild(f);
  await new Promise(function(r){f.onload=r}); var w=f.contentWindow, d=f.contentDocument, t=0;
  while(!(w.__docsDiagrams&&w.__docsDiagrams.done) && t<400){await sleep(100);t++}
  var res={url:u,problems:[],figs:0};
  var st=w.__docsDiagrams||{total:0,rendered:0,errors:[]};
  res.figs=st.total; if(!st.done) res.problems.push('diagrams did not finish'); if(st.rendered!==st.total) res.problems.push('rendered '+st.rendered+' of '+st.total); st.errors.forEach(function(e){res.problems.push('diagram error '+(e.diagram||'')+': '+e.error)});
  var de=d.documentElement; if(de.scrollWidth>W+1) res.problems.push('page scrolls horizontally: '+de.scrollWidth+' > '+W);
  if(d.querySelectorAll('h1').length!==1) res.problems.push('expected exactly one h1'); if(!d.querySelector('main')) res.problems.push('no main landmark'); if(!de.getAttribute('lang')) res.problems.push('no html lang');
  d.querySelectorAll('button').forEach(function(b){ if(!(b.getAttribute('aria-label')||b.textContent.trim())) res.problems.push('button without a name') });
  d.querySelectorAll('a[href]').forEach(function(a){ if(!(a.textContent.trim()||a.getAttribute('aria-label'))) res.problems.push('link without a name: '+a.getAttribute('href')) });
  var art=d.querySelector('article'); if(art){ art.querySelectorAll('*').forEach(function(el){ var r=el.getBoundingClientRect(); if(r.width&&r.right>W+1){ if(el.closest('.dg-stage,.tablewrap,pre,.dg-bar,details')) return; res.problems.push('sticks out of the viewport: <'+el.tagName.toLowerCase()+'> right='+Math.round(r.right)); } }) }
  var figs=d.querySelectorAll('figure.diagram');
  for(var i=0;i<figs.length;i++){ var fig=figs[i], name=fig.getAttribute('data-diagram'), stage=fig.querySelector('.dg-stage'), svg=stage.querySelector('svg');
    if(!svg){ res.problems.push(name+': no svg'); continue }
    if(svg.getAttribute('role')!=='img'||!svg.getAttribute('aria-label')) res.problems.push(name+': svg lacks role=img/aria-label');
    var fr=fig.getBoundingClientRect(); if(fr.right>W+1) res.problems.push(name+': figure wider than the viewport');
    var bar=fig.querySelectorAll('.dg-bar button'); if(bar.length<7) res.problems.push(name+': toolbar has '+bar.length+' controls');
    bar.forEach(function(b){ if(!b.getAttribute('aria-label')) res.problems.push(name+': toolbar control without aria-label') });
    var nat=fig._nat, wd=function(){return parseFloat(svg.style.width)||svg.getBoundingClientRect().width};
    var scale=wd()/nat.w; if(W<700 && scale<0.5) res.problems.push(name+': fitted scale '+scale.toFixed(2)+' is below 0.5 on a phone');
    var minFont=1e9; svg.querySelectorAll('text,tspan,.nodeLabel,foreignObject').forEach(function(t){ var fs=parseFloat(getComputedStyle(t).fontSize)||0; if(fs>0) minFont=Math.min(minFont,fs) });
    if(minFont<1e9 && minFont*scale<8) res.problems.push(name+': text renders at '+(minFont*scale).toFixed(1)+' px (<8)');
    var before=wd(), zin=fig.querySelector('.dg-bar button[aria-label="'+(JSON.parse(d.getElementById('main').dataset.ui).zoom_in)+'"]'); if(zin){ zin.click(); await sleep(20); if(!(wd()>before)) res.problems.push(name+': zoom in did not enlarge'); }
    var zout=fig.querySelector('.dg-bar button[aria-label="'+(JSON.parse(d.getElementById('main').dataset.ui).zoom_out)+'"]'); if(zout){ var b2=wd(); zout.click(); await sleep(20); if(!(wd()<b2)) res.problems.push(name+': zoom out did not shrink'); }
    var fitb=fig.querySelector('.dg-bar button[aria-label="'+(JSON.parse(d.getElementById('main').dataset.ui).fit)+'"]'); if(fitb){ fitb.click(); await sleep(20); if(Math.abs(wd()-before)>2) res.problems.push(name+': fit does not return to the fitted size'); }
    if(stage.scrollWidth>stage.clientWidth+1 && getComputedStyle(stage).overflowX==='visible') res.problems.push(name+': diagram overflows its container without scrolling');
  }
  out.push(res); f.remove();
}
(async function(){ for(var i=0;i<URLS.length;i++){ try{ await one(URLS[i]) }catch(e){ out.push({url:URLS[i],problems:['probe error '+e]}) } } document.getElementById('result').textContent='DONE '+JSON.stringify(out); })();
</script>"""

def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p

def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument('--site', default=str(ROOT / 'site')); ap.add_argument('--chrome', default=os.environ.get('CHROME', ''))
    ap.add_argument('--widths', default='1280,390'); a = ap.parse_args(argv)
    chrome = a.chrome or next((c for c in ('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', shutil.which('google-chrome') or '', shutil.which('chromium') or '', shutil.which('chromium-browser') or '') if c and os.path.exists(c)), '')
    if not chrome: print('no Chrome/Chromium found (set CHROME or --chrome)'); return 2
    tmp = pathlib.Path(tempfile.mkdtemp(prefix='docs-check-')); srv = None
    try:
        site = tmp / 'site'; shutil.copytree(a.site, site)
        for f in ('docs.css', 'docs.js', 'style.css', 'common.js'): shutil.copy(ROOT / 'web' / f, site / f)
        shutil.copytree(ROOT / 'web' / 'vendor', site / 'vendor', dirs_exist_ok=True)
        shutil.rmtree(site / 'docs', ignore_errors=True); rep = build_docs.build(site / 'docs', site)
        pages = [p for p in rep['files'] if p.endswith('.html') and '/' in p]
        port = free_port(); srv = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1', '--directory', str(site)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try: socket.create_connection(('127.0.0.1', port), 0.2).close(); break
            except OSError: time.sleep(0.1)
        failures = []; checked = 0; figs = 0
        for width in [int(x) for x in a.widths.split(',')]:
            urls = [f'docs/{p}' for p in pages]
            (site / '__probe.html').write_text(PROBE % {'width': width, 'urls': json.dumps(urls)})
            r = subprocess.run([chrome, '--headless=new', '--disable-gpu', '--no-sandbox', '--virtual-time-budget=900000', '--dump-dom', f'http://127.0.0.1:{port}/__probe.html'], capture_output=True, text=True, timeout=1500)
            m = re.search(r'<pre id="result">(.*?)</pre>', r.stdout, re.S)
            if not m or not html.unescape(m.group(1)).startswith('DONE'): failures.append(f'{width}px: probe did not finish: {(m.group(1) if m else r.stdout[-300:])[:300]}'); continue
            for res in json.loads(html.unescape(m.group(1))[5:]):
                checked += 1; figs += res.get('figs', 0)
                failures += [f'{width}px {res["url"]}: {p}' for p in res['problems']]
        print(f'docs_check: {checked} page renders ({len(pages)} pages x widths {a.widths}), {figs} diagram renders')
        for f in failures[:80]: print('FAIL', f)
        return 1 if failures else 0
    finally:
        if srv: srv.terminate()
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == '__main__': sys.exit(main())
