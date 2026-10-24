#!/usr/bin/env python3
"""Builds the flat GitHub Wiki files from the editable sources in docs/wiki/ (nothing is published by this script).

docs/wiki/pages.json              ordered pages: id, section, title {es,en}, summary {es,en}
docs/wiki/es/<id>.md, en/<id>.md  the text (same id in both languages); {{diagram:name}}, {{ev:EV-ID}}
docs/wiki/diagrams/<name>.mmd|json  wiki-only diagrams; otherwise docs-src/diagrams/ (the diagrams of the public docs site are reused, never copied)
docs/wiki/provenance.json         the evidence matrix; every {{ev:ID}} must exist there

Output (a directory you choose): ES-<Name>.md / EN-<Name>.md, _Sidebar.md, _Footer.md, ES-Evidence.md / EN-Evidence.md (rendered from provenance.json).
GitHub Wiki links are page names without extension, so the builder writes `[text](EN-Home)`."""
import argparse, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIKI = ROOT / 'docs' / 'wiki'
LANGS = ('es', 'en')
PREFIX = {'es': 'ES', 'en': 'EN'}
LABEL = {'es': {'switch': 'Idioma', 'diagram': 'Diagrama', 'alt': 'Descripción textual', 'ev': 'Evidencia', 'home': 'Inicio', 'footer': 'MacGuard: documentación pública. Cada afirmación de estado enlaza con su evidencia; lo que no está probado se dice.'},
         'en': {'switch': 'Language', 'diagram': 'Diagram', 'alt': 'Text description', 'ev': 'Evidence', 'home': 'Home', 'footer': 'MacGuard public documentation. Every status claim links to its evidence; what is not proven is said so.'}}
EV_HEAD = {'es': ('ID', 'Afirmación', 'Fuente', 'Fecha', 'Versión/SHA', 'Confianza', 'Validación', 'Estado'), 'en': ('ID', 'Claim', 'Source', 'Date', 'Version/SHA', 'Confidence', 'Validation', 'State')}


class BuildError(Exception): pass


def load(name): return json.loads((WIKI / name).read_text())


def wiki_name(pid, lang): return f'{PREFIX[lang]}-{pid}'


def diagram_block(name, lang):
    for base in (WIKI / 'diagrams', ROOT / 'docs-src' / 'diagrams'):
        mmd, meta = base / f'{name}.mmd', base / f'{name}.json'
        if mmd.exists() and meta.exists():
            m = json.loads(meta.read_text())
            if not all(isinstance(m.get(k), dict) and m[k].get(lang) for k in ('title', 'alt')): raise BuildError(f'diagram {name!r} needs title and alt in {lang}')
            return (f'**{LABEL[lang]["diagram"]}: {m["title"][lang]}**\n\n```mermaid\n{mmd.read_text().rstrip()}\n```\n\n'
                    f'<details><summary>{LABEL[lang]["alt"]}</summary>\n\n{m["alt"][lang]}\n\n</details>\n')
    raise BuildError(f'diagram {name!r} has no .mmd and .json in docs/wiki/diagrams or docs-src/diagrams')


def render(text, lang, prov_ids):
    def sub(m):
        kind, arg = m.group(1), m.group(2)
        if kind == 'diagram': return diagram_block(arg, lang)
        if arg not in prov_ids: raise BuildError(f'evidence {arg!r} is not in provenance.json')
        return f'[{LABEL[lang]["ev"]} {arg}]({wiki_name("Evidence", lang)}#{arg.lower()})'
    return re.sub(r'\{\{(diagram|ev):([A-Za-z0-9._-]+)\}\}', sub, text)


def evidence_page(lang, prov):
    h = EV_HEAD[lang]
    rows = [f'| {" | ".join(h)} |', f'|{"---|" * len(h)}']
    for e in prov['entries']:
        rows.append(f'| <a id="{e["id"].lower()}"></a>{e["id"]} | {e["claim"][lang]} | {e["source"]} | {e["date"]} | {e.get("ref", "")} | {e["confidence"]} | {e["validation"]} | {e["state"]} |')
    intro = {'es': 'Matriz de evidencias. Estados: concept, documented design, prototype, development, validation, release candidate, published, maintained, blocked. Esta tabla se genera desde `docs/wiki/provenance.json`.',
             'en': 'Evidence matrix. States: concept, documented design, prototype, development, validation, release candidate, published, maintained, blocked. This table is generated from `docs/wiki/provenance.json`.'}[lang]
    return f'# {"Matriz de evidencias" if lang == "es" else "Evidence matrix"}\n\n{intro}\n\n' + '\n'.join(rows) + '\n'


def sidebar(pages):
    out = ['**ES**']
    for lang in LANGS:
        if lang == 'en': out += ['', '**EN**']
        section = None
        for p in pages:
            if p['section'][lang] != section: section = p['section'][lang]; out.append(f'\n*{section}*')
            out.append(f'- [{p["title"][lang]}]({wiki_name(p["id"], lang)})')
        out.append(f'- [{"Evidencias" if lang == "es" else "Evidence"}]({wiki_name("Evidence", lang)})')
    return '\n'.join(out) + '\n'


def build(out_dir):
    out = pathlib.Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    pages, prov = load('pages.json')['pages'], load('provenance.json')
    ids = {e['id'] for e in prov['entries']}
    for p in pages:
        for lang in LANGS:
            src = WIKI / lang / f'{p["id"]}.md'
            if not src.exists(): raise BuildError(f'missing {src.relative_to(ROOT)}')
            other = LANGS[1 - LANGS.index(lang)]
            switch = f'**{PREFIX[lang]}** | [{PREFIX[other]}]({wiki_name(p["id"], other)})\n\n'
            (out / f'{wiki_name(p["id"], lang)}.md').write_text(switch + render(src.read_text(), lang, ids))
    for lang in LANGS:
        other = LANGS[1 - LANGS.index(lang)]
        (out / f'{wiki_name("Evidence", lang)}.md').write_text(f'**{PREFIX[lang]}** | [{PREFIX[other]}]({wiki_name("Evidence", other)})\n\n' + evidence_page(lang, prov))
    (out / '_Sidebar.md').write_text(sidebar(pages))
    (out / '_Footer.md').write_text(' · '.join(LABEL[l]['footer'] for l in LANGS) + '\n')
    return sorted(p.name for p in out.iterdir())


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or '').split('\n')[0]); ap.add_argument('--out', required=True); a = ap.parse_args(argv)
    try: files = build(a.out)
    except BuildError as e: print(f'wiki_build: {e}', file=sys.stderr); return 1
    print(f'wiki_build: {len(files)} files in {a.out}'); return 0


if __name__ == '__main__': sys.exit(main())
