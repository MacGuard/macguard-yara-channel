#!/usr/bin/env python3
"""Screenshots of every diagram variant the wiki pages use, to LOOK at them (wiki-owned tool; optional, not run by CI, nothing is published).

For each diagram a page uses, in Spanish and English, it renders the variant with the vendored Mermaid in headless Chrome at a phone width (390 px) and a
desktop width (1280 px), on a light (#ffffff, Mermaid theme 'default') and a dark (#0d1117, GitHub dark, Mermaid theme 'dark') background. The diagram sources
and their classDefs are used unchanged. Diagrams are packed into PNG sheets; each diagram has a caption with its name, language, theme, width and the
smallest effective text size (computed font size x rendered scale, measured in the browser by scripts/wiki_measure.py, the same measurement wiki_check.py --render uses; below 10 px at 390 px is reported as a PROBLEM).

  python3 scripts/wiki_screens.py [--out DIR] [--only SUBSTRING ...] [--lang es en] [--widths 390 1280] [--themes light dark] [--cols N] [--max-height PX]

--out defaults to a new temporary directory (printed at the end); it is refused inside the repository. One Chrome at a time, under a hard time limit, in its own
process group (docs_check.run_chrome). Exit 0 when every sheet was written."""
import argparse, html, json, os, pathlib, re, shutil, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import wiki_build  # noqa: E402
import wiki_measure  # noqa: E402   (the measurement shared with wiki_check.py --render)

COLORS = {'light': {'bg': '#ffffff', 'fg': '#1f2328', 'theme': 'default'}, 'dark': {'bg': '#0d1117', 'fg': '#e6edf3', 'theme': 'dark'}}

PAGE = ('<!doctype html><meta charset=utf-8><meta name="color-scheme" content="%(scheme)s"><style>'
        ':root{color-scheme:%(scheme)s}html,body{margin:0;background:%(bg)s;color:%(fg)s}'
        '#wrap{display:flex;align-items:flex-start;gap:%(gap)spx}'
        '.col{width:%(w)spx;flex:none}.item{margin:0 0 10px;padding:0 0 6px}.cap{font:11px/1.3 Menlo,monospace;padding:3px 4px;background:%(capbg)s;color:%(fg)s}'
        '.box{width:100%%;overflow:visible}.box svg{display:block;margin:0 auto;max-width:100%%;height:auto}</style>'
        '<div id=wrap></div><pre id=result style="display:none">RUNNING</pre><script src="mermaid.js"></script><script>%(measure)s'
        'var ITEMS=%(items)s, COLS=%(cols)s, THEME=%(theme)s, W=%(w)s, out=[];'
        'mermaid.initialize({startOnLoad:false,securityLevel:"strict",theme:THEME});'
        '(async function(){var cols=[];for(var c=0;c<COLS.length;c++){var col=document.createElement("div");col.className="col";document.getElementById("wrap").appendChild(col);cols.push(col)}'
        'for(var c=0;c<COLS.length;c++){for(var k=0;k<COLS[c].length;k++){var it=ITEMS[COLS[c][k]];var f=document.createElement("div");f.className="item";f.id="item_"+COLS[c][k];'
        'var cap=document.createElement("div");cap.className="cap";var box=document.createElement("div");box.className="box";f.appendChild(cap);f.appendChild(box);cols[c].appendChild(f);'
        'try{var r=await mermaid.render("d_"+COLS[c][k],it.src,box);box.innerHTML=r.svg;var mm=wikiMeasure(box);var vw=mm.vw,eff=mm.eff;'
        'cap.textContent=it.key+" | "+it.lang+" | "+%(themename)s+" | "+W+"px | smallest text ~"+eff.toFixed(1)+"px (font "+mm.font+"px, svg "+Math.round(vw)+"px wide)";'
        'out.push({i:COLS[c][k],ok:true,h:f.offsetHeight,vw:vw,eff:eff})}catch(e){cap.textContent=it.key+" DOES NOT COMPILE: "+String(e&&e.message||e).slice(0,120);out.push({i:COLS[c][k],ok:false,h:f.offsetHeight})}}}'
        'document.getElementById("result").textContent="DONE "+JSON.stringify(out)})();</script>')


def used_diagrams():
    """Names of the diagrams the pages use, in page order, without duplicates."""
    names = []
    for p in json.loads((wiki_build.WIKI / 'pages.json').read_text())['pages']:
        for lang in wiki_build.LANGS:
            for n in re.findall(r'\{\{diagram:([^}]+)\}\}', (wiki_build.WIKI / lang / f'{p["id"]}.md').read_text()):
                if n not in names: names.append(n)
    return names


def build_items(names, langs, only=()):
    items = []
    for n in names:
        if only and not any(o in n for o in only): continue
        for lang in langs:
            mmd = wiki_build.diagram_source(n, lang)[0]
            items.append({'key': n, 'lang': lang, 'src': mmd.read_text()})
    return items


def pack(heights, cols, max_height, gap=10):
    """Greedy sequential packing of item indexes into sheets of `cols` columns, each column at most max_height tall (a taller item gets a column of its own)."""
    sheets, cur, col, used = [], [], [], 0
    for i, h in enumerate(heights):
        h += gap
        if col and used + h > max_height:
            cur.append(col); col, used = [], 0
            if len(cur) == cols: sheets.append(cur); cur = []
        col.append(i); used += h
    if col: cur.append(col)
    if cur: sheets.append(cur)
    return sheets


def sheet_height(sheet, heights, gap=10): return max(sum(heights[i] + gap for i in col) for col in sheet) + 8


def page_html(items, sheet, theme, width, cols):
    c = COLORS[theme]
    return PAGE % {'scheme': theme, 'bg': c['bg'], 'fg': c['fg'], 'capbg': '#21262d' if theme == 'dark' else '#eaeef2', 'w': width, 'gap': 12 if cols > 1 else 0,
                   'items': json.dumps(items), 'cols': json.dumps(sheet), 'theme': json.dumps(c['theme']), 'themename': json.dumps(theme), 'measure': wiki_measure.JS.replace('%', '%%')}


def run_page(chrome, d, name, html_text, extra, limit):
    import docs_check
    (d / f'{name}.html').write_text(html_text)
    return docs_check.run_chrome([chrome, '--headless=new', '--disable-gpu', '--no-sandbox', '--hide-scrollbars', '--force-device-scale-factor=1', '--allow-file-access-from-files',
                                  '--virtual-time-budget=60000'] + extra + [(d / f'{name}.html').as_uri()], limit)


def find_chrome(given):
    return given or next((c for c in ('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', shutil.which('google-chrome') or '', shutil.which('chromium') or '', shutil.which('chromium-browser') or '') if c and os.path.exists(c)), '')


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or '').split('\n')[0])
    ap.add_argument('--out', default=''); ap.add_argument('--chrome', default=os.environ.get('CHROME', '')); ap.add_argument('--only', nargs='*', default=[], help='keep only the diagrams whose name contains one of these')
    ap.add_argument('--lang', nargs='+', default=list(wiki_build.LANGS), choices=wiki_build.LANGS); ap.add_argument('--widths', nargs='+', type=int, default=[390, 1280])
    ap.add_argument('--themes', nargs='+', default=['light', 'dark'], choices=sorted(COLORS)); ap.add_argument('--cols', type=int, default=1, help='columns per sheet (side by side) for widths under 700 px')
    ap.add_argument('--max-height', type=int, default=3000, help='tallest column of a sheet, px'); ap.add_argument('--limit', type=int, default=240, help='hard time limit per Chrome run, seconds')
    a = ap.parse_args(argv)
    chrome = find_chrome(a.chrome)
    if not chrome: print('wiki_screens: needs Chrome/Chromium (set CHROME or --chrome)', file=sys.stderr); return 2
    out = pathlib.Path(a.out).resolve() if a.out else pathlib.Path(tempfile.mkdtemp(prefix='wiki-screens-'))
    if ROOT in (out, *out.parents): print(f'wiki_screens: --out must be outside the repository ({ROOT})', file=sys.stderr); return 2
    out.mkdir(parents=True, exist_ok=True)
    items = build_items(used_diagrams(), a.lang, a.only)
    if not items: print('wiki_screens: no diagram matches', file=sys.stderr); return 2
    written, problems = [], []
    work = pathlib.Path(tempfile.mkdtemp(prefix='wiki-screens-work-')); (work / 'mermaid.js').write_bytes((ROOT / 'web' / 'vendor' / 'mermaid-12.2.0.min.js').read_bytes())
    try:
        for width in a.widths:
            cols = a.cols if width < 700 else 1
            # pass 1: the height of every item at this width (the layout does not depend on the theme)
            o, to = run_page(chrome, work, f'measure-{width}', page_html(items, [list(range(len(items)))], a.themes[0], width, 1), [f'--window-size={width},2000', '--dump-dom'], a.limit)
            m = re.search(r'<pre id="result"[^>]*>DONE (.*?)</pre>', o, re.S)
            if to or not m: problems.append(f'{width}px: the measuring run did not finish (timeout={to})'); continue
            res = {r['i']: r for r in json.loads(html.unescape(m.group(1)))}
            problems += [f'{items[i]["key"]} ({items[i]["lang"]}) does not compile' for i, r in sorted(res.items()) if not r['ok']]
            heights = [res[i]['h'] if i in res else 400 for i in range(len(items))]
            sheets = pack(heights, cols, a.max_height)
            for theme in a.themes:
                for n, sheet in enumerate(sheets, 1):
                    h = sheet_height(sheet, heights); png = out / f'{width}-{theme}-{n:02d}.png'
                    for _attempt in range(2):   # a screenshot run now and then hits the time limit: one retry
                        _, to = run_page(chrome, work, f'sheet-{width}-{theme}-{n}', page_html(items, sheet, theme, width, cols), [f'--window-size={width * cols + 12 * (cols - 1)},{h}', f'--screenshot={png}'], a.limit)
                        if png.exists(): break
                    if to or not png.exists(): problems.append(f'{png.name}: Chrome did not write the screenshot (timeout={to})')
                    else: written.append(png.name)
            for i, r in sorted(res.items()):
                if r['ok'] and width < 700 and wiki_measure.too_small(r['eff']): problems.append(f'{items[i]["key"]} ({items[i]["lang"]}) text ~{r["eff"]:.1f}px at {width}px')
    finally:
        shutil.rmtree(work, ignore_errors=True)
    (out / 'index.json').write_text(json.dumps({'items': [{'key': i['key'], 'lang': i['lang']} for i in items], 'sheets': written}, indent=1))
    for p in problems: print('PROBLEM', p)
    print(f'wiki_screens: {len(items)} diagram variants, {len(written)} sheets in {out}')
    return 1 if problems else 0


if __name__ == '__main__': sys.exit(main())
