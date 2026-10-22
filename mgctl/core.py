"""Shared plumbing: exit codes, language, terminal detection and the output context used by every command (CLI and TUI hand-off alike)."""
from __future__ import annotations
import json
import os
import sys
from typing import Any, Optional

OK, FAILED, USAGE, UNAVAILABLE, CANCELLED = 0, 2, 3, 4, 130
MAX_TIMEOUT, MAX_WORKERS = 3600, 8


class UsageError(Exception):
    """Bad arguments or path: exit code 3."""


def detect_lang(explicit: Optional[str] = None) -> str:
    for v in (explicit, os.environ.get("MGCTL_LANG"), os.environ.get("LC_ALL"), os.environ.get("LC_MESSAGES"), os.environ.get("LANG")):
        if v and v.strip():
            return "es" if v.strip().lower().startswith("es") else "en"
    return "en"


def is_tty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class Ctx:
    """Options common to every command, with consistent meaning everywhere."""

    def __init__(self, opts: dict, stdout=None, stderr=None, stdin=None):
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
        self.stdin = stdin or sys.stdin
        self.json = bool(opts.get("json"))
        self.quiet = bool(opts.get("quiet"))
        self.verbose = bool(opts.get("verbose"))
        self.offline = bool(opts.get("offline"))
        self.non_interactive = bool(opts.get("non_interactive"))
        self.output = opts.get("output")
        self.lang = detect_lang(opts.get("lang"))
        self.timeout = self._int(opts.get("timeout"), 300, 1, MAX_TIMEOUT, "--timeout")
        self.max_workers = self._int(opts.get("max_workers"), 2, 1, MAX_WORKERS, "--max-workers")
        self.color = (not opts.get("no_color")) and ("NO_COLOR" not in os.environ) and is_tty(self.stdout) and os.environ.get("TERM", "") != "dumb"
        self.interactive = is_tty(self.stdin) and is_tty(self.stdout) and not self.non_interactive

    @staticmethod
    def _int(raw, default, lo, hi, name):
        if raw is None:
            return default
        try:
            n = int(raw)
        except (TypeError, ValueError):
            raise UsageError(f"{name} must be a whole number between {lo} and {hi}")
        if not lo <= n <= hi:
            raise UsageError(f"{name} must be between {lo} and {hi}")
        return n

    def t(self, en: str, es: str) -> str:
        return es if self.lang == "es" else en

    def out(self, text: str = "") -> None:
        """Result text. In --json mode it is suppressed (the JSON document is the result); with --quiet it is still printed."""
        if not self.json:
            self.stdout.write(text + "\n")

    def info(self, text: str) -> None:
        if not self.quiet:
            self.stderr.write(text + "\n")

    def debug(self, text: str) -> None:
        if self.verbose:
            self.stderr.write("[mgctl] " + text + "\n")

    def err(self, text: str) -> None:
        self.stderr.write(text + "\n")

    def emit_json(self, doc: Any) -> None:
        self.stdout.write(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text


_ES = [
    (r"^the path is empty$", "la ruta está vacía"),
    (r"^the path contains a NUL byte$", "la ruta contiene un byte NUL"),
    (r"^the path is too long$", "la ruta es demasiado larga"),
    (r"^path not found$", "ruta no encontrada"),
    (r"^permission denied reading the path$", "permiso denegado al leer la ruta"),
    (r"^cannot read the path \((.*)\)$", r"no se puede leer la ruta (\1)"),
    (r"^the path is a symbolic link; pass --follow-symlinks to audit its target$", "la ruta es un enlace simbólico; usa --follow-symlinks para auditar su destino"),
    (r"^the link target cannot be read \((.*)\)$", r"no se puede leer el destino del enlace (\1)"),
    (r"^only regular files are accepted( \(or bundles/folders\))?$", lambda m: "solo se aceptan archivos normales" + (" (o paquetes/carpetas)" if m.group(1) else "")),
    (r"^the output path contains a NUL byte$", "la ruta de salida contiene un byte NUL"),
    (r"^the output directory is a symbolic link$", "el directorio de salida es un enlace simbólico"),
    (r"^the output path exists and is not a directory$", "la ruta de salida existe y no es un directorio"),
    (r"^cannot create the output directory \((.*)\)$", r"no se puede crear el directorio de salida (\1)"),
    (r"^the output directory is not writable$", "el directorio de salida no es escribible"),
    (r"^--lang must be en or es$", "--lang debe ser en o es"),
    (r"^unknown command '(.*?)'\.(.*)Try: mgctl --help$", lambda m: f"comando desconocido '{m.group(1)}'." + m.group(2).replace("Did you mean", "¿Quisiste decir").replace("?", "?") + "Prueba: mgctl --help"),
    (r"^unknown option '(.*?)'\. Try: mgctl --help$", r"opción desconocida '\1'. Prueba: mgctl --help"),
    (r"^unknown subcommand '(.*?)' for '(.*?)'\.(.*)Try: (.*)$", lambda m: f"subcomando desconocido '{m.group(1)}' para '{m.group(2)}'." + m.group(3).replace("Did you mean", "¿Quisiste decir") + "Prueba: " + m.group(4)),
    (r"^unknown command for help: (.*)$", r"comando desconocido para la ayuda: \1"),
    (r"^--format must be text or json$", "--format debe ser text o json"),
    (r"^choose exactly one of --latest, --tag TAG or --directory DIR$", "elige exactamente una de --latest, --tag TAG o --directory DIR"),
    (r"^refusing to download without consent: pass --yes in scripts and pipelines$", "no se descarga sin consentimiento: usa --yes en scripts y pipelines"),
    (r"^the target directory is a symbolic link$", "el directorio de destino es un enlace simbólico"),
    (r"^the target directory does not exist: create it first \((.*)\)$", r"el directorio de destino no existe: créalo antes (\1)"),
    (r"^the target directory is not writable by you \(mgctl never asks for root\)$", "el directorio de destino no es escribible por ti (mgctl nunca pide root)"),
    (r"^unknown check\(s\): (.*); valid: (.*)$", r"comprobación(es) desconocida(s): \1; válidas: \2"),
    (r"^(.*) already exists in the output directory; nothing was overwritten$", r"\1 ya existe en el directorio de salida; no se sobrescribió nada"),
    (r"^(.*) already exists in the output directory; choose another directory$", r"\1 ya existe en el directorio de salida; elige otro directorio"),
    (r"^(--[a-z-]+) must be a whole number between (\d+) and (\d+)$", r"\1 debe ser un número entero entre \2 y \3"),
    (r"^(--[a-z-]+) must be between (\d+) and (\d+)$", r"\1 debe estar entre \2 y \3"),
]


def message(exc: Exception, lang: str) -> str:
    """The text of a UsageError in the requested language (English when there is no translation; the exit code never changes)."""
    import re
    text = str(exc)
    if lang != "es":
        return text
    for pat, rep in _ES:
        m = re.match(pat, text)
        if m:
            return rep(m) if callable(rep) else m.expand(rep)
    return text
