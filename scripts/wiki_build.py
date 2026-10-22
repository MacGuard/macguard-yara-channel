#!/usr/bin/env python3
"""Builds the flat GitHub Wiki files from the editable sources in docs/wiki/ (nothing is published by this script).

docs/wiki/pages.json              ordered pages: id, section, title {es,en}, summary {es,en}
docs/wiki/es/<id>.md, en/<id>.md  the text (same id in both languages); {{diagram:name}}, {{ev:EV-ID}}
docs/wiki/diagrams/<name>.mmd|json  wiki-only diagrams (+ <name>.es.mmd, the Spanish labels of the same diagram, also for the ones reused from docs-src/diagrams/, whose English source is never copied)
docs/wiki/provenance.json         the evidence matrix; every {{ev:ID}} must exist there

Output (a directory you choose): ES-<Name>.md / EN-<Name>.md, _Sidebar.md, _Footer.md, ES-Evidence.md / EN-Evidence.md (rendered from provenance.json).
GitHub Wiki links are page names without extension, so the builder writes `[text](EN-Home)`."""
import argparse, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIKI = ROOT / 'docs' / 'wiki'
LANGS = ('es', 'en')
PREFIX = {'es': 'ES', 'en': 'EN'}
LABEL = {'es': {'switch': 'Idioma', 'diagram': 'Diagrama', 'legend': 'Leyenda', 'alt': 'Descripción textual', 'ev': 'Evidencia', 'home': 'Inicio', 'labels': ' (Las etiquetas dentro del diagrama están en inglés.)', 'footer': 'MacGuard: documentación pública. Cada afirmación de estado enlaza con su evidencia; lo que no está probado se dice.'},
         'en': {'switch': 'Language', 'diagram': 'Diagram', 'legend': 'Legend', 'alt': 'Text description', 'ev': 'Evidence', 'home': 'Home', 'labels': '', 'footer': 'MacGuard public documentation. Every status claim links to its evidence; what is not proven is said so.'}}
EV_HEAD = {'es': ('ID', 'Afirmación', 'Fuente', 'Fecha', 'Versión/SHA', 'Confianza', 'Validación', 'Estado'), 'en': ('ID', 'Claim', 'Source', 'Date', 'Version/SHA', 'Confidence', 'Validation', 'State')}


class BuildError(Exception): pass


def load(name): return json.loads((WIKI / name).read_text())


def wiki_name(pid, lang): return f'{PREFIX[lang]}-{pid}'


def diagram_source(name, lang):
    """(mmd path, localized?, json path) for a diagram. <name>.<lang>.mmd in docs/wiki/diagrams is the localized variant of a wiki-owned diagram or of one reused from docs-src (the English source and the .json stay where they are)."""
    for base in (WIKI / 'diagrams', ROOT / 'docs-src' / 'diagrams'):
        mmd, meta = base / f'{name}.mmd', base / f'{name}.json'
        if mmd.exists() and meta.exists():
            loc = WIKI / 'diagrams' / f'{name}.{lang}.mmd'
            return (loc, True, meta) if lang != 'en' and loc.exists() else (mmd, False, meta)
    raise BuildError(f'diagram {name!r} has no .mmd and .json in docs/wiki/diagrams or docs-src/diagrams')


def diagram_block(name, lang):
    mmd, localized, meta = diagram_source(name, lang)
    m = json.loads(meta.read_text())
    if not all(isinstance(m.get(k), dict) and m[k].get(lang) for k in ('title', 'alt')): raise BuildError(f'diagram {name!r} needs title and alt in {lang}')
    note = '' if localized else LABEL[lang]['labels']
    legend = f'\n*{LABEL[lang]["legend"]}: {m["legend"][lang]}*\n' if isinstance(m.get('legend'), dict) and m['legend'].get(lang) else ''
    return (f'**{LABEL[lang]["diagram"]}: {m["title"][lang]}**\n\n```mermaid\n{mmd.read_text().rstrip()}\n```\n{legend}\n'
            f'<details><summary>{LABEL[lang]["alt"]}</summary>\n\n{m["alt"][lang]}{note}\n\n</details>\n')


RM_HEAD = {'es': ('Hito', 'Abiertos', 'Cerrados'), 'en': ('Milestone', 'Open', 'Closed')}
RM_TEXT = {'es': ('Datos medidos de GitHub el {date}', 'Releases más recientes', 'PR abiertos', 'PR fusionados en los 30 días anteriores'),
           'en': ('GitHub data measured on {date}', 'Latest releases', 'Open PRs', 'PRs merged in the previous 30 days')}


def roadmap_table(lang):
    f = WIKI / 'roadmap-data.json'
    if not f.exists(): raise BuildError('{{roadmap:table}} needs docs/wiki/roadmap-data.json (python3 scripts/wiki_roadmap.py)')
    d = json.loads(f.read_text()); h = RM_HEAD[lang]; tx = RM_TEXT[lang]
    rows = [f'| {" | ".join(h)} |', f'|{"---|" * len(h)}'] + [f'| [{m["title"]}]({m["url"]}) | {m["open"]} | {m["closed"]} |' for m in d['milestones']]
    rel = ', '.join(f'[{r["tag"]}]({r["url"]})' for r in d['releases'])
    return f'*{tx[0].format(date=d["measured_on"])}*\n\n' + '\n'.join(rows) + f'\n\n- {tx[1]}: {rel}\n- {tx[2]}: {d["open_prs"]}\n- {tx[3]}: {d["merged_last_30_days"]}\n'


def render(text, lang, prov_ids):
    def sub(m):
        kind, arg = m.group(1), m.group(2)
        if kind == 'diagram': return diagram_block(arg, lang)
        if kind == 'roadmap': return roadmap_table(lang)
        if arg not in prov_ids: raise BuildError(f'evidence {arg!r} is not in provenance.json')
        return f'[{LABEL[lang]["ev"]} {arg}]({wiki_name("Evidence", lang)}#{arg.lower()})'
    return re.sub(r'\{\{(diagram|ev|roadmap):([A-Za-z0-9._-]+)\}\}', sub, text)


EV_LABEL = {'es': {'claim': 'Afirmación', 'source': 'Fuente', 'date': 'Fecha', 'ref': 'Versión/SHA', 'confidence': 'Confianza', 'validation': 'Validación', 'state': 'Estado', 'class': 'Clasificación'},
            'en': {'claim': 'Claim', 'source': 'Source', 'date': 'Date', 'ref': 'Version/SHA', 'confidence': 'Confidence', 'validation': 'Validation', 'state': 'State', 'class': 'Classification'}}
EV_WORDS = {'es': {'high': 'alta', 'medium': 'media', 'low': 'baja', 'concept': 'concepto', 'documented design': 'diseño documentado', 'prototype': 'prototipo', 'development': 'en desarrollo', 'validation': 'en validación',
                   'release candidate': 'candidato a release', 'published': 'publicado', 'maintained': 'mantenido', 'blocked': 'bloqueado', 'operational': 'operativo', 'implemented-not-deployed': 'implementado, no desplegado', 'planned': 'planificado',
                   'PUBLICABLE': 'publicable', 'REQUIERE REVISION': 'requiere revisión del propietario'},
            'en': {'concept': 'concept', 'documented design': 'documented design', 'prototype': 'prototype', 'development': 'development', 'validation': 'validation', 'release candidate': 'release candidate', 'published': 'published', 'maintained': 'maintained',
                   'blocked': 'blocked', 'operational': 'operational', 'implemented-not-deployed': 'implemented, not deployed', 'planned': 'planned', 'PUBLICABLE': 'publishable', 'REQUIERE REVISION': 'needs owner review'}}


def evidence_page(lang, prov):
    L, W = EV_LABEL[lang], EV_WORDS[lang]
    intro = {'es': 'Matriz de evidencias: cada afirmación de estado enlaza aquí con su fuente. Estados posibles: concepto, diseño documentado, prototipo, en desarrollo, en validación, candidato a release, publicado, mantenido, bloqueado, operativo, implementado (no desplegado) y planificado. Se genera desde el archivo provenance.json del repositorio.',
             'en': 'Evidence matrix: every status claim links here to its source. Possible states: concept, documented design, prototype, development, validation, release candidate, published, maintained, blocked, operational, implemented (not deployed) and planned. It is generated from provenance.json in the repository.'}[lang]
    out = [f'# {"Matriz de evidencias" if lang == "es" else "Evidence matrix"}', '', intro, '']
    for e in prov['entries']:
        ref = e.get('ref', '')
        out += [f'<a id="{e["id"].lower()}"></a>', f'#### {e["id"]}', '', f'- **{L["claim"]}:** {e["claim"][lang]}', f'- **{L["source"]}:** {e["source"]}', f'- **{L["date"]}:** {e["date"]}']
        if ref: out.append(f'- **{L["ref"]}:** {ref}')
        out += [f'- **{L["confidence"]}:** {W.get(e["confidence"], e["confidence"])}', f'- **{L["validation"]}:** {e["validation"]}', f'- **{L["state"]}:** {W.get(e["state"], e["state"])}', f'- **{L["class"]}:** {W.get(e["class"], e["class"])}', '']
    return '\n'.join(out)


def sidebar(pages):
    out = []
    for lang in LANGS:
        out += [f'**{PREFIX[lang]}**']
        sections = []
        for p in pages:
            if p['section'][lang] not in sections: sections.append(p['section'][lang])
        for s in sections:
            out.append(f'\n*{s}*')
            out += [f'- [{p["title"][lang]}]({wiki_name(p["id"], lang)})' for p in pages if p['section'][lang] == s]
        out += ['', f'- [{"Evidencias" if lang == "es" else "Evidence"}]({wiki_name("Evidence", lang)})', '']
    return '\n'.join(out)


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
