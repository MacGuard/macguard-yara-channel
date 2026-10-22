"""Help text generated from the command tree, in English or Spanish. Plain text only: never an escape sequence."""
from __future__ import annotations
from typing import List, Tuple

from . import CONTRACT, VERSION
from .tree import BY_PATH, COMMANDS, EXIT_CODES, GLOBAL_OPTS, children

DOCS = "docs/cli/mgctl.md"
STATUS_LABEL = {
    "implemented": {"en": "implemented", "es": "implementado"},
    "experimental": {"en": "experimental", "es": "experimental"},
    "planned": {"en": "PLANNED (not available)", "es": "PLANIFICADO (no disponible)"},
}
H = {
    "usage": {"en": "USAGE", "es": "USO"}, "args": {"en": "ARGUMENTS", "es": "ARGUMENTOS"}, "opts": {"en": "OPTIONS", "es": "OPCIONES"},
    "glob": {"en": "GLOBAL OPTIONS (same meaning in every command)", "es": "OPCIONES GLOBALES (mismo significado en todos los comandos)"},
    "ex": {"en": "EXAMPLES", "es": "EJEMPLOS"}, "rel": {"en": "RELATED COMMANDS", "es": "COMANDOS RELACIONADOS"},
    "exit": {"en": "EXIT CODES", "es": "CÓDIGOS DE SALIDA"}, "docs": {"en": "DOCUMENTATION", "es": "DOCUMENTACIÓN"},
    "needs": {"en": "REQUIRES", "es": "REQUIERE"}, "sub": {"en": "COMMANDS", "es": "COMANDOS"}, "status": {"en": "STATUS", "es": "ESTADO"},
}


def _opt_line(o, lang) -> str:
    flags = ", ".join(o.flags) + (f" {o.metavar}" if o.metavar else "")
    return f"  {flags:<28} {o.help[lang]}"


def _exit_block(lang) -> List[str]:
    return [f"  {c:<4} {d[lang]}" for c, d in EXIT_CODES]


def render(path: Tuple[str, ...], lang: str) -> str:
    L: List[str] = []
    if not path:
        L += [f"mgctl {VERSION} (contract {CONTRACT}) - MacGuard" if lang == "en" else f"mgctl {VERSION} (contrato {CONTRACT}) - MacGuard", ""]
        L += ["The canonical command of the MacGuard suite. It delegates to the existing engines; it never simulates a check.",
              "'mg' is only an optional alias you enable yourself (mgctl alias enable)."] if lang == "en" else \
             ["El comando canónico de la suite MacGuard. Delega en los motores existentes; nunca simula una comprobación.",
              "'mg' es solo un alias opcional que activas tú (mgctl alias enable)."]
        L += ["", H["usage"][lang] + ":", ("  mgctl [GLOBAL OPTIONS] <command> [<subcommand>] [ARGUMENTS] [OPTIONS]" if lang == "en" else "  mgctl [OPCIONES GLOBALES] <comando> [<subcomando>] [ARGUMENTOS] [OPCIONES]"), "", H["sub"][lang] + ":"]
        for c in COMMANDS:
            if len(c.path) == 1:
                mark = {"implemented": " ", "experimental": "~", "planned": "x"}[c.status]
                L.append(f"  {mark} {c.path[0]:<13} {c.summary[lang]}")
        L += ["", ("Legend: (blank) implemented   ~ experimental   x planned, not available yet" if lang == "en" else "Leyenda: (vacío) implementado   ~ experimental   x planificado, aún no disponible"),
              "", H["glob"][lang] + ":"] + [_opt_line(o, lang) for o in GLOBAL_OPTS]
        L += ["", H["exit"][lang] + ":"] + _exit_block(lang)
        L += ["", H["docs"][lang] + ": " + DOCS, ("More: mgctl help <command>   e.g. mgctl help audit file" if lang == "en" else "Más: mgctl help <comando>   p. ej. mgctl help audit file")]
        return "\n".join(L)
    cmd = BY_PATH.get(path)
    if cmd is None:
        raise KeyError(path)
    full = "mgctl " + " ".join(path)
    L += [f"{full} - {cmd.summary[lang]}", "", f"{H['status'][lang]}: {STATUS_LABEL[cmd.status][lang]}"]
    if cmd.detail:
        L += ["", cmd.detail[lang]]
    subs = children(path)
    usage = full + (" <subcommand>" if subs else "") + "".join(f" <{n}>" if req else f" [{n}]" for n, req, _ in cmd.positionals) + (" [OPTIONS]" if cmd.options else "")
    L += ["", H["usage"][lang] + ":", "  " + usage]
    if subs:
        L += ["", H["sub"][lang] + ":"] + [f"  {c.path[-1]:<14} {c.summary[lang]}" + (" [planned]" if c.status == "planned" and lang == "en" else " [planificado]" if c.status == "planned" else "") for c in subs]
    if cmd.positionals:
        L += ["", H["args"][lang] + ":"] + [f"  {n:<14} {h[lang]} ({'required' if r else 'optional'})" if lang == "en" else f"  {n:<14} {h[lang]} ({'obligatorio' if r else 'opcional'})" for n, r, h in cmd.positionals]
    if cmd.options:
        L += ["", H["opts"][lang] + ":"] + [_opt_line(o, lang) for o in cmd.options]
    if cmd.needs:
        L += ["", H["needs"][lang] + ": " + cmd.needs[lang]]
    if cmd.examples:
        L += ["", H["ex"][lang] + ":"]
        for ex, note in cmd.examples:
            L += [f"  {ex}", f"      {note[lang]}"]
    if cmd.related:
        L += ["", H["rel"][lang] + ": " + ", ".join("mgctl " + r for r in cmd.related)]
    L += ["", H["glob"][lang] + ": mgctl --help", "", H["exit"][lang] + ":"] + _exit_block(lang)
    L += ["", H["docs"][lang] + ": " + DOCS]
    return "\n".join(L)
