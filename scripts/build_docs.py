#!/usr/bin/env python3
"""Builds the public documentation (HTML) from Markdown sources, in Spanish and English.

docs-src/pages.json            ordered list of pages with a title per language
docs-src/<lang>/<slug>.md      the text; front matter `title:` / `summary:`; {{placeholders}}; {{diagram:name}}
docs-src/diagrams/<name>.mmd   Mermaid source, written ONCE and shared by both languages
docs-src/diagrams/<name>.json  {"title": {"es","en"}, "alt": {"es","en"}} accessible name and text description
docs-src/events.json           the log events, described per language (checked against the code by tests/test_docs.py)

Safety: the Markdown subset is rendered with every character escaped; raw HTML in a source is shown as text, never interpreted. Only
http(s), mailto, relative and #anchor links are produced. Mermaid sources come from this repository, are placed in the page as text
and rendered by the vendored Mermaid with securityLevel "strict"; nothing from outside is ever rendered as a diagram.
Placeholders are filled from real data (the released manifest, latest.json, releases.json, the code); an unresolved placeholder is a
build error, so a page cannot show a number that is not backed by something real."""
import hashlib, base64, html, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MERMAID_VERSION = '12.2.0'
MERMAID_FILE = f'vendor/mermaid-{MERMAID_VERSION}.min.js'
LANGS = ('es', 'en')
SITE_BASE = 'https://macguard.github.io/macguard-yara-channel/'
UI = {
    'es': {'docs': 'Documentación', 'home': 'Inicio', 'on_page': 'En esta página', 'other_lang': 'English', 'skip': 'Saltar al contenido', 'prev': 'Anterior', 'next': 'Siguiente', 'lang_label': 'Idioma', 'theme': 'Claro / oscuro',
           'zoom_in': 'Acercar', 'zoom_out': 'Alejar', 'fit': 'Ajustar al ancho', 'reset': 'Tamaño real', 'full': 'Pantalla completa', 'copy': 'Copiar código Mermaid', 'svg': 'Descargar SVG', 'copied': 'Copiado',
           'desc': 'Descripción del diagrama', 'source': 'Código Mermaid', 'diagram': 'Diagrama', 'copy_code': 'Copiar', 'pager': 'Paginación', 'draw_error': 'No se pudo dibujar el diagrama. Su código está debajo.', 'nojs': 'Sin JavaScript no se dibuja el diagrama: aquí tiene su descripción y su código fuente.', 'rendering': 'Dibujando el diagrama…',
           'footer': 'Generada desde docs-src/ con scripts/build_docs.py. Proyecto independiente, sin afiliación con las fuentes.', 'sidebar': 'Documentación', 'status_actual': 'ACTUAL', 'status_proposal': 'PROPUESTA'},
    'en': {'docs': 'Documentation', 'home': 'Home', 'on_page': 'On this page', 'other_lang': 'Español', 'skip': 'Skip to content', 'prev': 'Previous', 'next': 'Next', 'lang_label': 'Language', 'theme': 'Light / dark',
           'zoom_in': 'Zoom in', 'zoom_out': 'Zoom out', 'fit': 'Fit to width', 'reset': 'Actual size', 'full': 'Full screen', 'copy': 'Copy Mermaid code', 'svg': 'Download SVG', 'copied': 'Copied',
           'desc': 'Diagram description', 'source': 'Mermaid code', 'diagram': 'Diagram', 'copy_code': 'Copy', 'pager': 'Pages', 'draw_error': 'The diagram could not be drawn. Its source is below.', 'nojs': 'Without JavaScript the diagram is not drawn: its description and source code are here.', 'rendering': 'Drawing the diagram…',
           'footer': 'Generated from docs-src/ with scripts/build_docs.py. Independent project, not affiliated with the sources.', 'sidebar': 'Documentation', 'status_actual': 'CURRENT', 'status_proposal': 'PROPOSED'},
}

class BuildError(Exception): pass

# ---- context from real data ----------------------------------------------------------------------------------
def tool_versions() -> dict:
    sh = (ROOT / 'DMGTrustAuditor/DMGTrustAuditor/Scripts/build-yara-engine.sh').read_text()
    yara = re.search(r'^YARA_VERSION=(\S+)', sh, re.M).group(1); openssl = re.search(r'^OPENSSL_VERSION=(\S+)', sh, re.M).group(1)
    cos = re.search(r'cosign (v[\d.]+) darwin', (ROOT / 'DMGTrustAuditor/DMGTrustAuditor/Core/SigstoreVerifier.swift').read_text()).group(1)
    return {'yara': yara, 'openssl': openssl, 'cosign': cos, 'mermaid': MERMAID_VERSION}

def release_context(site: pathlib.Path) -> dict:
    """Facts about the latest release, read from the files the site publishes (they were verified before this runs)."""
    ctx = {}
    latest = json.loads((site / 'latest.json').read_text()) if (site / 'latest.json').exists() else None
    manifest = json.loads((site / 'manifest.json').read_text()) if (site / 'manifest.json').exists() else None
    rels = json.loads((site / 'releases.json').read_text())['releases'] if (site / 'releases.json').exists() else []
    if not (latest and manifest and rels): return ctx
    last, prev = rels[-1], (rels[-2] if len(rels) > 1 else None)
    st = latest.get('stats', {})
    ctx.update({'release.tag': last['tag'], 'release.url': last['url'], 'release.date': last['published_at'][:10], 'release.files': str(last['total']), 'release.yara_rules': str(st.get('yara_rules', '')),
                'release.package_bytes': str(last.get('package_bytes') or st.get('package_bytes', '')), 'release.package_sha256': latest['package_sha256'], 'release.manifest_sha256': latest['manifest_sha256'],
                'release.rules_root': manifest['rules_root'], 'release.log_size': str(manifest['log']['size']), 'release.log_root': manifest['log']['root'],
                'release.download': last['url'].replace('/tag/', '/download/'), 'release.count': str(len(rels)),
                'prev.tag': prev['tag'] if prev else '', 'prev.url': prev['url'] if prev else '', 'prev.download': prev['url'].replace('/tag/', '/download/') if prev else ''})
    f0 = manifest['files'][0]
    ex = {k: manifest[k] for k in ('schema', 'created_at') if k in manifest}
    ex['sources'] = manifest.get('sources', [])
    ex['files'] = [dict(f0), '... %d more entries ...' % (len(manifest['files']) - 1)]
    ex['rules_root'] = manifest['rules_root']; ex['log'] = manifest['log']
    for k in ('stats', 'validation', 'status'):
        if k in manifest: ex[k] = manifest[k]
    ctx['manifest_example'] = json.dumps(ex, indent=2, ensure_ascii=False)
    ctx['manifest_keys'] = ', '.join(sorted(manifest.keys()))
    return ctx

def build_context(site: pathlib.Path) -> dict:
    ctx = {f'tool.{k}': v for k, v in tool_versions().items()}
    ctx.update(release_context(site)); ctx['site.base'] = SITE_BASE
    ctx['repo'] = 'MacGuard/macguard-yara-channel'; ctx['identity'] = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main'; ctx['issuer'] = 'https://token.actions.githubusercontent.com'
    return ctx

# ---- Markdown subset -------------------------------------------------------------------------------------------
def esc(s): return html.escape(s, quote=True)
def slugify(s):
    s = re.sub(r'[^\w\s-]', '', s.lower(), flags=re.UNICODE).strip(); return re.sub(r'[\s_]+', '-', s) or 'section'

def safe_url(u: str) -> str:
    u = u.strip()
    if re.match(r'^(https?://|mailto:|#|\.{0,2}/|[A-Za-z0-9_./-]+\.html|[A-Za-z0-9_./-]+/?$)', u): return u
    raise BuildError(f'disallowed link target: {u!r}')

def inline(text, page_links):
    out, i = [], 0
    pattern = re.compile(r'`([^`]+)`|\*\*([^*]+)\*\*|\*([^*\s][^*]*)\*|\[([^\]]+)\]\(([^)\s]+)\)')
    for m in pattern.finditer(text):
        out.append(esc(text[i:m.start()])); i = m.end()
        if m.group(1) is not None: out.append(f'<code>{esc(m.group(1))}</code>')
        elif m.group(2) is not None: out.append(f'<strong>{inline(m.group(2), page_links)}</strong>')
        elif m.group(3) is not None: out.append(f'<em>{inline(m.group(3), page_links)}</em>')
        else:
            label, url = m.group(4), m.group(5)
            if url.startswith('page:'):
                slug = url[5:].split('#')[0]; frag = ('#' + url.split('#', 1)[1]) if '#' in url else ''
                if slug not in page_links: raise BuildError(f'link to unknown page {slug!r}')
                url = page_links[slug] + frag
            ext = url.startswith('http')
            out.append(f'<a href="{esc(safe_url(url))}"' + (' rel="noopener noreferrer"' if ext else '') + f'>{inline(label, page_links)}</a>')
    out.append(esc(text[i:])); return ''.join(out)

def parse_front(src):
    m = re.match(r'^---\n(.*?)\n---\n', src, re.S)
    if not m: raise BuildError('missing front matter')
    meta = dict(l.split(': ', 1) for l in m.group(1).split('\n') if ': ' in l)
    return meta, src[m.end():]

TABLE_LABEL = {'es': 'Tabla (desplazable)', 'en': 'Table (scrollable)'}
def tablewrap(lang): return f'<div class="tablewrap" role="region" tabindex="0" aria-label="{TABLE_LABEL[lang]}">'

def render_events(lang):
    ev = json.loads((ROOT / 'docs-src/events.json').read_text())
    head = {'es': ('Código', 'Nivel', 'Cuándo se registra', 'Origen'), 'en': ('Code', 'Level', 'When it is recorded', 'Source')}[lang]
    rows = ''.join(f"<tr><td><code>{esc(e['code'])}</code></td><td>{esc(e['level'])}</td><td>{esc(e[lang])}</td><td><code>{esc(e['source'])}</code></td></tr>" for e in ev)
    return f'{tablewrap(lang)}<table><thead><tr>{"".join(f"<th scope=col>{h}</th>" for h in head)}</tr></thead><tbody>{rows}</tbody></table></div>'

def diagram_figure(name, lang, ui):
    mmd = ROOT / 'docs-src/diagrams' / f'{name}.mmd'; meta = ROOT / 'docs-src/diagrams' / f'{name}.json'
    if not mmd.exists() or not meta.exists(): raise BuildError(f'diagram {name!r} is missing its .mmd or .json')
    m = json.loads(meta.read_text()); src = mmd.read_text().rstrip('\n')
    title, alt = m['title'][lang], m['alt'][lang]
    return (f'<figure class="diagram" id="fig-{esc(name)}" data-diagram="{esc(name)}" aria-labelledby="cap-{esc(name)}"><figcaption id="cap-{esc(name)}">{esc(ui["diagram"])}: {esc(title)}</figcaption>'
            f'<div class="dg-stage" tabindex="0" role="group" aria-label="{esc(title)}"><p class="dg-loading" aria-live="polite">{esc(ui["rendering"])}</p><pre class="mermaid-src" hidden>{esc(src)}</pre></div>'
            f'<details class="dg-desc"><summary>{esc(ui["desc"])}</summary><p>{esc(alt)}</p></details>'
            f'<details class="dg-code"><summary>{esc(ui["source"])}</summary><pre><code>{esc(src)}</code></pre></details>'
            f'<noscript><p>{esc(ui["nojs"])}</p></noscript></figure>')

def render_md(body, lang, ctx, page_links, used_diagrams):
    ui = UI[lang]
    def fill(s):
        def sub(m):
            k = m.group(1).strip()
            if k.startswith('diagram:') or k == 'events_table': return m.group(0)
            if k not in ctx: raise BuildError(f'unresolved placeholder {{{{{k}}}}}')
            return ctx[k]
        return re.sub(r'\{\{([^}]+)\}\}', sub, s)
    lines = body.split('\n'); out, toc = [], []; i = 0
    def flush_list(buf, ordered):
        tag = 'ol' if ordered else 'ul'
        return f'<{tag}>' + ''.join(f'<li>{inline(fill(x), page_links)}</li>' for x in buf) + f'</{tag}>'
    while i < len(lines):
        ln = lines[i]
        if not ln.strip(): i += 1; continue
        if ln.startswith('```'):
            lang_ = ln[3:].strip(); i += 1; buf = []
            while i < len(lines) and not lines[i].startswith('```'): buf.append(lines[i]); i += 1
            i += 1; code = fill('\n'.join(buf))
            out.append(f'<div class="codeblock"><pre><code' + (f' class="language-{esc(lang_)}"' if lang_ else '') + f'>{esc(code)}</code></pre></div>'); continue
        m = re.match(r'^\{\{diagram:([\w-]+)\}\}\s*$', ln.strip())
        if m: used_diagrams.append(m.group(1)); out.append(diagram_figure(m.group(1), lang, ui)); i += 1; continue
        if ln.strip() == '{{events_table}}': out.append(render_events(lang)); i += 1; continue
        m = re.match(r'^(#{2,4})\s+(.*)$', ln)
        if m:
            level, text = len(m.group(1)), fill(m.group(2)); sid = slugify(text)
            if level == 2: toc.append((sid, text))
            out.append(f'<h{level} id="{sid}">{inline(text, page_links)}</h{level}>'); i += 1; continue
        if ln.startswith('|') and i + 1 < len(lines) and re.match(r'^\|[\s:|-]+\|\s*$', lines[i + 1]):
            head = [c.strip() for c in ln.strip().strip('|').split('|')]; i += 2; rows = []
            while i < len(lines) and lines[i].startswith('|'): rows.append([c.strip() for c in lines[i].strip().strip('|').split('|')]); i += 1
            out.append(tablewrap(lang) + '<table><thead><tr>' + ''.join(f'<th scope="col">{inline(fill(h), page_links)}</th>' for h in head) + '</tr></thead><tbody>'
                       + ''.join('<tr>' + ''.join(f'<td>{inline(fill(c), page_links)}</td>' for c in r) + '</tr>' for r in rows) + '</tbody></table></div>'); continue
        if re.match(r'^[-*]\s+', ln) or re.match(r'^\d+\.\s+', ln):
            ordered = bool(re.match(r'^\d+\.', ln)); buf = []
            while i < len(lines) and (re.match(r'^[-*]\s+', lines[i]) if not ordered else re.match(r'^\d+\.\s+', lines[i])):
                buf.append(re.sub(r'^([-*]|\d+\.)\s+', '', lines[i])); i += 1
            out.append(flush_list(buf, ordered)); continue
        if ln.startswith('>'):
            buf = []
            while i < len(lines) and lines[i].startswith('>'): buf.append(lines[i].lstrip('> ').rstrip()); i += 1
            label = ''
            first = buf[0]
            m2 = re.match(r'^\*\*(ACTUAL|CURRENT|PROPUESTA|PROPOSED|NOTA|NOTE|LÍMITE|LIMIT)\*\*\s*(.*)$', first)
            cls = 'note'
            if m2:
                cls = {'ACTUAL': 'actual', 'CURRENT': 'actual', 'PROPUESTA': 'proposal', 'PROPOSED': 'proposal', 'LÍMITE': 'limit', 'LIMIT': 'limit'}.get(m2.group(1), 'note')
            out.append(f'<blockquote class="callout {cls}">' + inline(fill(' '.join(buf)), page_links) + '</blockquote>'); continue
        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(r'^(#{2,4}\s|```|\||>|[-*]\s|\d+\.\s|\{\{diagram:|\{\{events_table)', lines[i]): buf.append(lines[i]); i += 1
        if not buf: buf = [lines[i]]; i += 1
        out.append(f'<p>{inline(fill(" ".join(buf)), page_links)}</p>')
    return '\n'.join(out), toc

# ---- pages ----------------------------------------------------------------------------------------------------
def page_html(lang, slug, meta, content, toc, pages, ctx, prev_next):
    ui = UI[lang]; other = 'en' if lang == 'es' else 'es'
    nav = ''.join(f'<li><a href="{p["slug"]}.html"' + (' aria-current="page"' if p['slug'] == slug else '') + f'>{esc(p["title"][lang])}</a></li>' for p in pages)
    toc_html = ''.join(f'<li><a href="#{sid}">{esc(t.replace(chr(96), ""))}</a></li>' for sid, t in toc)
    pn = ''.join(f'<a rel="{rel}" href="{p["slug"]}.html">{esc(lab)}: {esc(p["title"][lang])}</a>' for rel, lab, p in prev_next if p)
    needs_mermaid = 'class="diagram"' in content
    scripts = (f'<script src="../../{MERMAID_FILE}" integrity="sha256-{sri()}" crossorigin="anonymous"></script>' if needs_mermaid else '') + '<script src="../../docs.js"></script>'
    ui_json = esc(json.dumps({k: ui[k] for k in ('zoom_in', 'zoom_out', 'fit', 'reset', 'full', 'copy', 'svg', 'copied', 'copy_code', 'draw_error')}))
    return f'''<!doctype html><html lang="{lang}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(meta["title"])} · {esc(ui["docs"])} · MacGuard YARA Channel</title>
<meta name="description" content="{esc(meta.get("summary", ""))}"><link rel="stylesheet" href="../../style.css"><link rel="stylesheet" href="../../docs.css">
<link rel="alternate" hreflang="{other}" href="../{other}/{slug}.html">
<a class="skip" href="#main">{esc(ui["skip"])}</a>
<aside class="docs-side"><h2>🛡 MacGuard</h2><small>YARA Rules Channel</small><nav aria-label="{esc(ui["sidebar"])}"><a class="home" href="../../index.html">{esc(ui["home"])}</a><ol class="docs-nav">{nav}</ol></nav></aside>
<main id="main" class="docs-main" data-ui="{ui_json}"><header class="docs-top"><div><small>MACGUARD · {esc(ui["docs"]).upper()}</small></div><div><label class="sr" for="lang">{esc(ui["lang_label"])}</label><a id="lang-switch" class="btn" lang="{other}" hreflang="{other}" href="../{other}/{slug}.html">{esc(ui["other_lang"])}</a>
<button id="theme" type="button" aria-label="{esc(ui["theme"])}">◐</button></div></header>
<article><h1>{esc(meta["title"])}</h1><p class="lead">{esc(meta.get("summary", ""))}</p>
<nav class="toc" aria-label="{esc(ui["on_page"])}"><strong>{esc(ui["on_page"])}</strong><ul>{toc_html}</ul></nav>
{content}</article><nav class="pager" aria-label="{esc(ui["pager"])}">{pn}</nav><footer>{esc(ui["footer"])}</footer></main>{scripts}</html>'''

def sri():
    return base64.b64encode(hashlib.sha256((ROOT / 'web' / MERMAID_FILE).read_bytes()).digest()).decode()

def build(out: pathlib.Path, site_for_context: pathlib.Path = None, strict=True) -> dict:
    pages = json.loads((ROOT / 'docs-src/pages.json').read_text())
    ctx = build_context(site_for_context or out.parent)
    page_links = {p['slug']: f'{p["slug"]}.html' for p in pages}
    report = {'pages': 0, 'diagrams': {}, 'files': []}
    for lang in LANGS:
        (out / lang).mkdir(parents=True, exist_ok=True)
        for idx, p in enumerate(pages):
            src_file = ROOT / 'docs-src' / lang / f'{p["slug"]}.md'
            if not src_file.exists(): raise BuildError(f'missing {lang}/{p["slug"]}.md')
            meta, body = parse_front(src_file.read_text(encoding='utf-8'))
            try:
                used = []; content, toc = render_md(body, lang, ctx, page_links, used)
            except BuildError as e: raise BuildError(f'{lang}/{p["slug"]}.md: {e}')
            prev_next = [('prev', UI[lang]['prev'], pages[idx - 1] if idx else None), ('next', UI[lang]['next'], pages[idx + 1] if idx + 1 < len(pages) else None)]
            target = out / lang / f'{p["slug"]}.html'
            target.write_text(page_html(lang, p['slug'], meta, content, toc, pages, ctx, prev_next), encoding='utf-8'); report['pages'] += 1; report['files'].append(str(target.relative_to(out)))
            for d in used: report['diagrams'].setdefault(lang, []).append(d)
    first = pages[0]['slug']
    if first != 'overview': raise BuildError(f"the first documentation page must be 'overview' (web/docs-redirect.js sends readers there), got {first!r}")
    # WCAG 2.2.1 (F41): no timed redirect. The 0 s fallback is inside <noscript>: with JavaScript, only docs-redirect.js navigates (it picks the
    # language), so an immediate refresh can never race it and send a Spanish reader to en/; without JavaScript the fallback redirects at once.
    # WCAG 3.1.2: the Spanish parts of this English page carry lang="es".
    (out / 'index.html').write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Documentation · MacGuard YARA Channel</title><link rel="stylesheet" href="../style.css">
<noscript><meta http-equiv="refresh" content="0;url=en/{first}.html"></noscript><main style="max-width:640px;margin:60px auto;padding:0 16px"><h1><span lang="es">Documentación</span> · Documentation</h1><p><a href="es/{first}.html" lang="es" hreflang="es">Leer en español</a> · <a href="en/{first}.html" hreflang="en">Read in English</a></p>
<script src="../docs-redirect.js"></script></main></html>''', encoding='utf-8')
    report['files'].append('index.html')
    return report

if __name__ == '__main__':
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'site/docs'
    try: r = build(out, out.parent)
    except BuildError as e: sys.exit(f'docs build failed: {e}')
    print(f"documentation built: {r['pages']} pages, diagrams per language {{ {', '.join(f'{k}: {len(v)}' for k, v in r['diagrams'].items())} }}")
