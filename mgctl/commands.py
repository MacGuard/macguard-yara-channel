"""Command handlers: thin. Each one validates input, calls an engine through mgctl.backends or a service, and maps the result to the shared exit codes."""
from __future__ import annotations
import json
import os
import platform
import shutil
import sys
from typing import Any, Dict, List

from . import CONTRACT, VERSION, backends
from .core import FAILED, OK, UNAVAILABLE, USAGE, Ctx, UsageError
from .help import render
from .paths import validate_path
from .services import aliasing, auditfile
from .tree import BY_PATH, Cmd


# ---- helpers ---------------------------------------------------------------------------------------------------
def _engine_unavailable(ctx: Ctx, command: str, reason: str) -> int:
    if ctx.json:
        ctx.emit_json({"schemaVersion": 1, "command": command, "ok": False, "status": "unavailable", "message": reason, "exitCode": UNAVAILABLE})
    else:
        ctx.err(f"mgctl: {reason}")
    return UNAVAILABLE


def _need_audit(ctx: Ctx, command: str):
    if not backends.is_macos():
        return None, _engine_unavailable(ctx, command, ctx.t("this command needs the Installer Auditor engine, which only exists for macOS.", "este comando necesita el motor del Installer Auditor, que solo existe para macOS."))
    exe = backends.audit_bin()
    if not exe:
        return None, _engine_unavailable(ctx, command, ctx.t("macguard-audit not found: set MGCTL_AUDIT_BIN or put it on PATH (see docs/cli/mgctl.md).", "macguard-audit no encontrado: define MGCTL_AUDIT_BIN o ponlo en el PATH (ver docs/cli/mgctl.md)."))
    return exe, 0


def _delegate(ctx: Ctx, exe: str, argv: List[str], pass_stdin: bool = False) -> int:
    """Runs the engine, prints its output verbatim and maps its exit code (0 ok, 2 failed, 3 usage, 4 unavailable)."""
    full = [exe] + argv
    ctx.debug("engine call: " + " ".join(full))
    rc, out, err, timed_out = backends.run(full, ctx.timeout, stdin_null=not pass_stdin)
    if timed_out:
        ctx.err(ctx.t(f"mgctl: the engine did not finish within {ctx.timeout} s and was stopped.", f"mgctl: el motor no terminó en {ctx.timeout} s y se detuvo."))
        return UNAVAILABLE
    if rc == 127 or rc == 126:
        return _engine_unavailable(ctx, " ".join(argv[:1]), "cannot execute the engine")
    if out:
        ctx.stdout.write(out if out.endswith("\n") else out + "\n")
    if err and not ctx.quiet:
        ctx.stderr.write(err if err.endswith("\n") else err + "\n")
    return rc if rc in (0, 2, 3, 4) else FAILED


# ---- handlers --------------------------------------------------------------------------------------------------
def group(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    ctx.out(render(cmd.path, ctx.lang))
    return USAGE


def planned(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    name = " ".join(cmd.path)
    msg = ctx.t(f"'mgctl {name}' is planned: no engine exists for it yet, so nothing was run and nothing is reported as passed.",
                f"'mgctl {name}' está planificado: todavía no existe un motor para él, así que no se ejecutó nada ni se informa de nada como superado.")
    if ctx.json:
        ctx.emit_json({"schemaVersion": 1, "command": name, "ok": False, "status": "planned", "message": msg, "exitCode": UNAVAILABLE})
    else:
        ctx.err("mgctl: " + msg)
    return UNAVAILABLE


def version(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    exe = backends.audit_bin()
    audit_v = None
    if exe:
        rc, out, _e, _t = backends.run([exe, "version"], 15)
        audit_v = out.strip() if rc == 0 else None
    ver = backends.verifier_script()
    doc = {"schemaVersion": 1, "tool": "mgctl", "version": VERSION, "contract": CONTRACT, "python": platform.python_version(), "platform": platform.system(),
           "engines": {"macguard-audit": {"path": exe, "version": audit_v}, "verify_public_release": {"path": ver}}}
    if ctx.json:
        ctx.emit_json(doc)
    else:
        ctx.out(f"mgctl {VERSION} (contract {CONTRACT})")
        if not ctx.quiet:
            ctx.out("macguard-audit: " + (f"{audit_v or 'found'} ({exe})" if exe else ctx.t("not found", "no encontrado")))
    return OK


def help_(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    words = tuple(args.get("command") or ())
    if words and words not in BY_PATH:
        raise UsageError("unknown command for help: " + " ".join(words))
    ctx.out(render(words, ctx.lang))
    return OK


globals()["help"] = help_          # tree handler name is "help"


def doctor(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    checks: List[Dict[str, Any]] = []

    def add(name, status, detail):
        checks.append({"check": name, "status": status, "detail": detail})

    add("python", "ok" if sys.version_info >= (3, 9) else "fail", platform.python_version())
    add("platform", "info", f"{platform.system()} {platform.machine()}")
    add("terminal", "info", "interactive" if ctx.interactive else "not interactive (no TUI will be opened)")
    exe = backends.audit_bin()
    if backends.is_macos():
        add("macguard-audit", "ok" if exe else "missing", exe or "not found: scan, audit file (integrity, yara) and intelligence need it")
        if exe:
            rc, out, _e, _t = backends.run([exe, "engine-status", "--format", "json"], min(ctx.timeout, 60))
            try:
                es = json.loads(out)
                add("yara-engine", "ok" if es.get("ready") else "missing", f"YARA {es.get('version')} ({es.get('architectures')})" if es.get("ready") else str(es.get("detail")))
            except Exception:
                add("yara-engine", "missing", f"engine-status returned no readable answer (exit code {rc})")
    else:
        add("macguard-audit", "info", "the Installer Auditor engine only exists for macOS; audit file runs the hash check only here")
    ver = backends.verifier_script()
    add("release-verifier", "ok" if ver else "missing", ver or "scripts/verify_public_release.py not found (evidence verify unavailable)")
    add("cosign", "ok" if shutil.which("cosign") else "missing", shutil.which("cosign") or "not on PATH (evidence verify needs it)")
    st = aliasing.status()
    add("alias-mg", "info", ("'mg' on PATH: " + ", ".join(f["path"] + (" (ours)" if f["ours"] else " (NOT ours)") for f in st["found"])) if st["found"] else "no 'mg' on PATH")
    add("telemetry", "ok", "none: mgctl never sends data")
    bad = any(c["status"] == "fail" for c in checks) or (backends.is_macos() and not exe)
    if ctx.json:
        ctx.emit_json({"schemaVersion": 1, "tool": "mgctl", "version": VERSION, "checks": checks, "ok": not bad})
    else:
        for c in checks:
            ctx.out(f"  {c['check']:<17} {c['status']:<8} {c['detail']}")
    return UNAVAILABLE if bad else OK


def scan(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    exe, rc = _need_audit(ctx, "scan")
    if not exe:
        return rc
    fmt = "json" if ctx.json else (args.get("format") or "text")
    if fmt not in ("text", "json"):
        raise UsageError("--format must be text or json")
    _given, resolved, _st = validate_path(args["path"], follow_symlinks=bool(args.get("follow_symlinks")), allow_dir=True)
    argv = ["scan", resolved, "--format", fmt] + (["--recursive"] if args.get("recursive") else [])
    return _delegate(ctx, exe, argv)


def audit_group(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    if not args.get("tui"):
        return group(ctx, cmd, args)
    if not ctx.interactive:
        return _engine_unavailable(ctx, "audit --tui", ctx.t("the interactive explorer needs a terminal; it never opens in pipelines, cron or systemd. Use 'mgctl scan' or 'mgctl audit file'.",
                                                         "el explorador interactivo necesita un terminal; nunca se abre en pipelines, cron o systemd. Usa 'mgctl scan' o 'mgctl audit file'."))
    exe, rc = _need_audit(ctx, "audit --tui")
    if not exe:
        return rc
    ctx.debug("engine call: " + exe + " tui")
    code = backends.run([exe, "tui"], 24 * 3600, stdin_null=False, capture=False)[0]     # inherits the terminal; the same engine as 'macguard-audit tui'
    return code if code in (0, 2, 3, 4) else FAILED


def audit_file(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    return auditfile.run(ctx, args)


def evidence_verify(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    chosen = [k for k in ("latest", "tag", "directory") if args.get(k)]
    if len(chosen) != 1:
        raise UsageError("choose exactly one of --latest, --tag TAG or --directory DIR")
    if ctx.offline and chosen[0] != "directory":
        return _engine_unavailable(ctx, "evidence verify", ctx.t("--offline: only --directory can be verified without the network.", "--offline: sin red solo se puede verificar con --directory."))
    script = backends.verifier_script()
    if not script:
        return _engine_unavailable(ctx, "evidence verify", ctx.t("scripts/verify_public_release.py not found: run from a checkout or set MGCTL_VERIFIER.", "scripts/verify_public_release.py no encontrado: ejecuta desde un checkout o define MGCTL_VERIFIER."))
    if chosen[0] == "directory":
        validate_path(args["directory"], allow_dir=True)
    argv = [sys.executable, script] + (["--latest"] if args.get("latest") else ["--tag", args["tag"]] if args.get("tag") else ["--directory", os.path.abspath(args["directory"])])
    argv += ["--json"] if ctx.json else ["--color", "never"]
    ctx.debug("verifier call: " + " ".join(argv))
    rc, out, err, timed_out = backends.run(argv, ctx.timeout)
    if timed_out:
        return _engine_unavailable(ctx, "evidence verify", f"the verifier did not finish within {ctx.timeout} s")
    mapped = {0: OK, 1: FAILED, 2: FAILED, 3: FAILED, 4: UNAVAILABLE, 5: UNAVAILABLE, 6: UNAVAILABLE}.get(rc, FAILED)
    if ctx.json:
        try:
            verifier = json.loads(out)
        except Exception:
            verifier = None
        ctx.emit_json({"schemaVersion": 1, "command": "evidence verify", "ok": rc == 0, "verifierExitCode": rc, "exitCode": mapped, "verifier": verifier,
                       "note": "A pass proves the publisher identity and the integrity of the files, not who wrote the third-party rules."})
    else:
        if out:
            ctx.stdout.write(out)
        if err and not ctx.quiet:
            ctx.stderr.write(err)
        ctx.info(f"mgctl: verifier exit code {rc} -> mgctl exit code {mapped}")
    return mapped


def intelligence_status(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    exe, rc = _need_audit(ctx, "intelligence status")
    return _delegate(ctx, exe, ["rules-status"] + (["--format", "json"] if ctx.json else [])) if exe else rc


def intelligence_verify(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    exe, rc = _need_audit(ctx, "intelligence verify")
    return _delegate(ctx, exe, ["verify-rules"] + (["--format", "json"] if ctx.json else [])) if exe else rc


def intelligence_update(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    if ctx.offline:
        return _engine_unavailable(ctx, "intelligence update", ctx.t("--offline: updating rules needs the network.", "--offline: actualizar las reglas necesita la red."))
    yes = bool(args.get("yes"))
    if not yes and not ctx.interactive:
        raise UsageError("refusing to download without consent: pass --yes in scripts and pipelines")
    exe, rc = _need_audit(ctx, "intelligence update")
    if not exe:
        return rc
    argv = ["update-rules"] + (["--yes"] if yes else []) + (["--format", "json"] if ctx.json else [])
    return _delegate(ctx, exe, argv, pass_stdin=not yes)


def _alias_result(ctx: Ctx, name: str, res: Dict[str, Any]) -> int:
    if ctx.json:
        ctx.emit_json({"schemaVersion": 1, "command": name, **{k: v for k, v in res.items() if k != "code"}, "exitCode": res.get("code", OK)})
    else:
        (ctx.out if res.get("ok") else ctx.err)(("" if res.get("ok") else "mgctl: ") + res["message"])
    return int(res.get("code", OK))


def alias_status(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    st = aliasing.status()
    if ctx.json:
        ctx.emit_json({"schemaVersion": 1, "command": "alias status", **st})
    elif st["found"]:
        for f in st["found"]:
            ctx.out(f"{f['path']}  " + ("-> mgctl (ours)" if f["ours"] else ctx.t("NOT ours: mgctl will not touch it", "NO es nuestro: mgctl no lo tocará")))
    else:
        ctx.out(ctx.t("no 'mg' on PATH. Enable the alias with: mgctl alias enable", "no hay 'mg' en el PATH. Actívalo con: mgctl alias enable"))
    return OK


def alias_enable(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    return _alias_result(ctx, "alias enable", aliasing.enable(args.get("dir"), bool(args.get("force_conflict"))))


def alias_disable(ctx: Ctx, cmd: Cmd, args: Dict[str, Any]) -> int:
    return _alias_result(ctx, "alias disable", aliasing.disable(args.get("dir")))
