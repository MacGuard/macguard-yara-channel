"""Argument parsing and dispatch. No security logic lives here."""
from __future__ import annotations
import argparse
import difflib
import sys
from typing import List, Optional, Tuple

from . import commands
from .core import CANCELLED, OK, USAGE, Ctx, UsageError, detect_lang, message
from .help import render
from .tree import BY_PATH, COMMANDS, GLOBAL_OPTS, Cmd, children


class _Parser(argparse.ArgumentParser):
    def error(self, message):                      # argparse would print and exit(2); mgctl uses exit code 3 for usage errors
        raise UsageError(message)


def _dest(flag: str) -> str:
    return flag.lstrip("-").replace("-", "_")


def _add(p: argparse.ArgumentParser, o) -> None:
    kw = {"dest": _dest(o.flags[-1] if o.flags[-1].startswith("--") else o.flags[0]), "default": argparse.SUPPRESS}
    if o.metavar is None:
        p.add_argument(*o.flags, action="store_true", **kw)
    else:
        p.add_argument(*o.flags, **kw)


def _global_parser() -> argparse.ArgumentParser:
    p = _Parser(add_help=False, allow_abbrev=False, prog="mgctl")
    for o in GLOBAL_OPTS:
        _add(p, o)
    return p


def _leaf_parser(cmd: Cmd) -> argparse.ArgumentParser:
    p = _Parser(add_help=False, allow_abbrev=False, prog="mgctl " + " ".join(cmd.path))
    for name, required, _ in cmd.positionals:
        if cmd.path == ("help",):
            p.add_argument(name, nargs="*", default=[])
        else:
            p.add_argument(name, nargs=None if required else "?", default=None)
    for o in cmd.options:
        _add(p, o)
    return p


def _split_dashdash(argv: List[str]) -> Tuple[List[str], List[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def _resolve(tokens: List[str]) -> Tuple[Tuple[str, ...], List[str]]:
    path: Tuple[str, ...] = ()
    i = 0
    while i < len(tokens):
        names = {c.path[-1]: c for c in children(path)}
        if tokens[i] in names:
            path = names[tokens[i]].path
            i += 1
        else:
            break
    return path, tokens[i:]


def _suggest(word: str, path: Tuple[str, ...]) -> str:
    names = [c.path[-1] for c in children(path)]
    m = difflib.get_close_matches(word, names, n=1)
    return f" Did you mean '{m[0]}'?" if m else ""


def main(argv: Optional[List[str]] = None, stdout=None, stderr=None, stdin=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    pre_lang = detect_lang()
    try:
        before, literal = _split_dashdash(argv)
        gns, rest = _global_parser().parse_known_args(before)
        opts = vars(gns)
        opts["lang"] = opts.get("lang") if opts.get("lang") in ("en", "es") else (None if opts.get("lang") is None else "bad")
        if opts["lang"] == "bad":
            raise UsageError("--lang must be en or es")
        ctx = Ctx(opts, stdout, stderr, stdin)
    except UsageError as e:
        stderr.write(f"mgctl: error: {message(e, pre_lang)}\n")
        return USAGE

    want_help = any(t in ("-h", "--help") for t in rest)
    rest = [t for t in rest if t not in ("-h", "--help")]
    if "--version" in rest:
        rest = ["version"] + [t for t in rest if t != "--version"]
    try:
        path, remaining = _resolve(rest)
        if not path:
            if remaining and not remaining[0].startswith("-"):
                raise UsageError(f"unknown command '{remaining[0]}'." + _suggest(remaining[0], ()) + " Try: mgctl --help")
            if remaining and remaining[0].startswith("-"):
                raise UsageError(f"unknown option '{remaining[0]}'. Try: mgctl --help")
            ctx.out(render((), ctx.lang))
            return OK if want_help else USAGE
        cmd = BY_PATH[path]
        if want_help:
            ctx.out(render(path, ctx.lang))
            return OK
        if children(path):
            if remaining and not remaining[0].startswith("-"):
                raise UsageError(f"unknown subcommand '{remaining[0]}' for 'mgctl {' '.join(path)}'." + _suggest(remaining[0], path) + f" Try: mgctl {' '.join(path)} --help")
            if cmd.handler == "group":
                ctx.out(render(path, ctx.lang))
                return USAGE
        ns = _leaf_parser(cmd).parse_args(remaining + (["--"] + literal if literal else []))
        args = vars(ns)
        handler = getattr(commands, cmd.handler or "group")
        return int(handler(ctx, cmd, args))
    except UsageError as e:
        if ctx.json:
            ctx.emit_json({"schemaVersion": 1, "ok": False, "error": str(e), "exitCode": USAGE})
        else:
            stderr.write(f"mgctl: error: {message(e, ctx.lang)}\n")
        return USAGE
    except KeyboardInterrupt:
        stderr.write("\n" + ctx.t("mgctl: cancelled; nothing was reported as complete.", "mgctl: cancelado; nada se informó como completo.") + "\n")
        return CANCELLED
    except BrokenPipeError:
        return OK
