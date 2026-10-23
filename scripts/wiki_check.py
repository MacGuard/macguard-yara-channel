#!/usr/bin/env python3
"""Static checks of the wiki sources (docs/wiki/) and of what wiki_build.py would publish. No network, no secrets, no publishing.

  1. every page in pages.json exists in es/ and en/ with parity: same number of headings, same {{diagram:}} and {{ev:}} references, same number of tables
  2. internal links resolve (to a page of the build output or to an anchor-less known file) and never leave the wiki by an absolute path
  3. every {{ev:ID}} exists in provenance.json; provenance entries are complete, use the allowed states, are not CONFIDENCIAL, and the ones that point at this repository
     (repo = self) name a file that exists and a commit that exists
  4. every diagram has a .mmd and a .json with title and alt in both languages; the diagram type is a known Mermaid type; the page text has no raw ```mermaid block
     (diagrams live in files so both languages share one source)
  5. no secret-like string, no absolute local path, no absolute claims ("100% safe", "unbreakable"...) in any source
  6. accessibility basics of the Markdown: one H1, headings do not skip levels, images have alt text, link text is not "here"
  --render also compiles every diagram with the vendored Mermaid in headless Chrome (needs Chrome); GitHub renders with its own Mermaid version, so the real check is the first publication.
Exit 0 only if everything passes."""
import argparse, json, os, pathlib, re, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIKI = ROOT / 'docs' / 'wiki'
sys.path.insert(0, str(ROOT / 'scripts'))
import wiki_build  # noqa: E402

STATES = {'concept', 'documented design', 'prototype', 'development', 'validation', 'release candidate', 'published', 'maintained', 'blocked', 'operational', 'implemented-not-deployed', 'planned'}
CLASSES = {'PUBLICABLE', 'REQUIERE REVISION'}
DIAGRAM_TYPES = ('flowchart', 'graph', 'sequenceDiagram', 'stateDiagram-v2', 'stateDiagram', 'gantt', 'mindmap', 'timeline', 'classDiagram', 'erDiagram', 'journey', 'quadrantChart', 'gitGraph', 'pie', 'block-beta')
SECRETS = [r'AGE-SECRET-KEY-1[A-Z0-9]{20,}', r'-----BEGIN [A-Z ]*PRIVATE KEY', r'\bSCW[A-Z0-9]{17}\b', r'\b003[0-9a-f]{22}\b', r'\bgh[pousr]_[A-Za-z0-9]{30,}', r'\bAKIA[0-9A-Z]{16}\b',
           r'(?i)(secret|token|password|passwd|api[_-]?key)\s*[:=]\s*[\'"]?[A-Za-z0-9/+_\-]{16,}', r'/Users/[A-Za-z0-9._-]+/', r'\b[a-f0-9]{32}\.r2\.cloudflarestorage\.com']
ABSOLUTE = [r'(?i)100 ?% (safe|seguro|secure)', r'(?i)\bunbreakable\b', r'(?i)\binquebrantable\b', r'(?i)garantiza(mos)? (la )?seguridad total', r'(?i)\bcompletely (safe|secure)\b', r'(?i)protege de todo']
HEAD = re.compile(r'^(#{1,6})\s+(.+?)\s*$', re.M)


def jload(p): return json.loads(pathlib.Path(p).read_text())


def strip_code(text): return re.sub(r'```.*?```', '', text, flags=re.S)


def git_has(sha):
    return subprocess.run(['git', '-C', str(ROOT), 'cat-file', '-e', f'{sha}^{{commit}}'], capture_output=True).returncode == 0


def check(wiki=WIKI):
    err = []
    pages = jload(wiki / 'pages.json')['pages']; prov = jload(wiki / 'provenance.json')['entries']
    ids = [p['id'] for p in pages]
    if len(ids) != len(set(ids)): err.append('pages.json: duplicate page ids')
    known = {wiki_build.wiki_name(i, l) for i in ids for l in wiki_build.LANGS} | {wiki_build.wiki_name('Evidence', l) for l in wiki_build.LANGS}
    # provenance
    pids = set()
    for e in prov:
        i = e.get('id', '?')
        for f in ('id', 'claim', 'source', 'date', 'confidence', 'validation', 'state', 'class'):
            if f not in e: err.append(f'provenance {i}: missing {f}')
        if i in pids: err.append(f'provenance {i}: duplicate id')
        pids.add(i)
        if e.get('state') not in STATES: err.append(f'provenance {i}: state {e.get("state")!r} is not one of the allowed states')
        if e.get('class') not in CLASSES: err.append(f'provenance {i}: class {e.get("class")!r} must be PUBLICABLE or REQUIERE REVISION (CONFIDENCIAL never enters the repository)')
        if not isinstance(e.get('claim'), dict) or set(e['claim']) != {'es', 'en'}: err.append(f'provenance {i}: claim needs es and en')
        if e.get('repo') == 'self':
            if e.get('path') and not (ROOT / e['path']).exists(): err.append(f'provenance {i}: path {e["path"]} does not exist (obsolete reference)')
            if e.get('ref') and re.fullmatch(r'[0-9a-f]{7,40}', e['ref']) and not git_has(e['ref']): err.append(f'provenance {i}: commit {e["ref"]} does not exist')
    # pages
    for p in pages:
        texts = {}
        for lang in wiki_build.LANGS:
            f = wiki / lang / f'{p["id"]}.md'
            if not f.exists(): err.append(f'missing {lang}/{p["id"]}.md'); continue
            texts[lang] = f.read_text()
        if len(texts) != 2: continue
        s = {l: strip_code(t) for l, t in texts.items()}
        hs = {l: [(len(m.group(1))) for m in HEAD.finditer(s[l])] for l in s}
        if hs['es'] != hs['en']: err.append(f'{p["id"]}: ES and EN have different heading structure ({len(hs["es"])} vs {len(hs["en"])})')
        for l in s:
            lv = hs[l]
            if lv.count(1) != 1: err.append(f'{p["id"]}/{l}: expected exactly one H1, found {lv.count(1)}')
            for a, b in zip(lv, lv[1:]):
                if b > a + 1: err.append(f'{p["id"]}/{l}: heading level jumps from H{a} to H{b}'); break
        refs = {l: sorted(re.findall(r'\{\{(?:diagram|ev):[^}]+\}\}', texts[l])) for l in texts}
        if refs['es'] != refs['en']: err.append(f'{p["id"]}: ES and EN reference different diagrams or evidence')
        tabs = {l: len(re.findall(r'^\|[-: |]+\|\s*$', texts[l], re.M)) for l in texts}
        if tabs['es'] != tabs['en']: err.append(f'{p["id"]}: ES and EN have different numbers of tables')
        for l, t in texts.items():
            if '```mermaid' in t: err.append(f'{p["id"]}/{l}: raw mermaid block; use {{{{diagram:name}}}} so both languages share one source')
            for m in re.finditer(r'\{\{ev:([^}]+)\}\}', t):
                if m.group(1) not in pids: err.append(f'{p["id"]}/{l}: evidence {m.group(1)} is not in provenance.json')
            for m in re.finditer(r'\{\{diagram:([^}]+)\}\}', t):
                try: wiki_build.diagram_block(m.group(1), l)
                except wiki_build.BuildError as e: err.append(f'{p["id"]}/{l}: {e}')
            for m in re.finditer(r'(?<!\!)\[([^\]]*)\]\(([^)\s]+)\)', strip_code(t)):
                txt, tgt = m.group(1), m.group(2)
                if re.match(r'(?i)^(here|aquí|aqui|click here|link)$', txt.strip()): err.append(f'{p["id"]}/{l}: link text {txt!r} says nothing')
                if tgt.startswith(('http://', 'https://', 'mailto:', '#')): continue
                base = tgt.split('#')[0]
                if tgt.startswith('/') or '..' in tgt: err.append(f'{p["id"]}/{l}: link {tgt} leaves the wiki')
                elif base and base not in known: err.append(f'{p["id"]}/{l}: link {tgt} does not resolve to a wiki page')
                if base.startswith(('ES-', 'EN-')) and base[:2].lower() != l: err.append(f'{p["id"]}/{l}: link {tgt} points to the other language')
            for m in re.finditer(r'!\[([^\]]*)\]\(', t):
                if not m.group(1).strip(): err.append(f'{p["id"]}/{l}: image without alt text')
            for pat in SECRETS:
                if re.search(pat, t): err.append(f'{p["id"]}/{l}: matches a secret-like or private-path pattern ({pat[:30]}...)')
            for pat in ABSOLUTE:
                if re.search(pat, t): err.append(f'{p["id"]}/{l}: absolute security claim ({pat[:30]}...)')
    # diagrams in use or present
    for base in (wiki / 'diagrams',):
        if not base.exists(): continue
        for mmd in sorted(base.glob('*.mmd')):
            meta = mmd.with_suffix('.json')
            if not meta.exists(): err.append(f'diagram {mmd.name} has no .json'); continue
            m = jload(meta)
            for k in ('title', 'alt'):
                if not isinstance(m.get(k), dict) or set(m[k]) != {'es', 'en'} or not all(m[k].values()): err.append(f'diagram {mmd.stem}: {k} needs es and en')
            first = next((l.strip() for l in mmd.read_text().splitlines() if l.strip() and not l.strip().startswith('%%')), '')
            if not first.startswith(DIAGRAM_TYPES): err.append(f'diagram {mmd.stem}: unknown Mermaid type {first[:30]!r}')
            if mmd.read_text().count('\t'): err.append(f'diagram {mmd.stem}: tabs in Mermaid source')
    return err


def render_diagrams(chrome, limit=120):
    """Compile every diagram used by the wiki with the vendored Mermaid in one headless Chrome."""
    import docs_check
    names = set()
    for p in jload(WIKI / 'pages.json')['pages']:
        for lang in wiki_build.LANGS:
            names |= set(re.findall(r'\{\{diagram:([^}]+)\}\}', (WIKI / lang / f'{p["id"]}.md').read_text()))
    srcs = {}
    for n in sorted(names):
        for base in (WIKI / 'diagrams', ROOT / 'docs-src' / 'diagrams'):
            if (base / f'{n}.mmd').exists(): srcs[n] = (base / f'{n}.mmd').read_text(); break
    page = ('<!doctype html><meta charset=utf-8><pre id=result>RUNNING</pre><script src="mermaid.js"></script><script>'
            'var S=%s, out=[]; mermaid.initialize({startOnLoad:false,securityLevel:"strict"});'
            '(async function(){for(var k in S){try{await mermaid.parse(S[k]);await mermaid.render("d_"+k.replace(/[^a-z0-9]/gi,"_"),S[k]);out.push({n:k,ok:true})}catch(e){out.push({n:k,ok:false,e:String(e&&e.message||e).slice(0,200)})}}'
            'document.getElementById("result").textContent="DONE "+JSON.stringify(out)})();</script>') % json.dumps(srcs)
    with tempfile.TemporaryDirectory(prefix='wiki-render-') as d:
        d = pathlib.Path(d); (d / 'index.html').write_text(page); (d / 'mermaid.js').write_bytes((ROOT / 'web' / 'vendor' / 'mermaid-12.2.0.min.js').read_bytes())
        out, timed_out = docs_check.run_chrome([chrome, '--headless=new', '--disable-gpu', '--no-sandbox', '--allow-file-access-from-files', '--virtual-time-budget=60000', '--dump-dom', (d / 'index.html').as_uri()], limit)
    m = re.search(r'<pre id="result">DONE (.*?)</pre>', out, re.S)
    if timed_out or not m: return [f'the browser did not finish (timeout={timed_out})'], len(srcs)
    import html
    res = json.loads(html.unescape(m.group(1)))
    return [f'diagram {r["n"]} does not compile: {r["e"]}' for r in res if not r['ok']], len(res)


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or '').split('\n')[0]); ap.add_argument('--render', action='store_true', help='also compile diagrams in headless Chrome'); ap.add_argument('--chrome', default=os.environ.get('CHROME', ''))
    a = ap.parse_args(argv)
    err = check()
    if a.render:
        import docs_check, shutil  # noqa: F401
        chrome = a.chrome or next((c for c in ('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', shutil.which('google-chrome') or '', shutil.which('chromium') or '') if c and os.path.exists(c)), '')
        if not chrome: err.append('--render needs Chrome/Chromium (set CHROME)')
        else:
            e, n = render_diagrams(chrome); err += e; print(f'wiki_check: {n} diagrams compiled with the vendored Mermaid')
    for e in err[:100]: print('FAIL', e)
    print(f'wiki_check: {"OK" if not err else str(len(err)) + " problem(s)"}')
    return 1 if err else 0


if __name__ == '__main__': sys.exit(main())
