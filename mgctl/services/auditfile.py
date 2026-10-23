"""Deep audit of one file. Orchestrates; the checks themselves come from existing engines:

  hash        SHA-256 + SHA-512 (mgctl.services.hashing)
  integrity   findings of the macguard-audit scan that are not YARA findings (signature, structure, Gatekeeper, ...)
  yara        YARA findings of the same macguard-audit scan (the engine bundled today is classic YARA, not YARA-X)
  provenance  NO ENGINE YET -> not_implemented
  vulns       NO ENGINE YET -> not_implemented
"""
from __future__ import annotations
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from .. import CONTRACT, VERSION, backends
from ..core import CANCELLED, FAILED, OK, UNAVAILABLE, Ctx, UsageError
from ..paths import prepare_output_dir, validate_path
from . import hashing

CHECKS = ("hash", "integrity", "yara", "provenance", "vulns")
SCHEMA = "mgctl.audit-file/1"
DONE = ("passed", "failed", "warning", "unknown")      # statuses that mean "the check really ran"


def parse_checks(raw: Optional[str]) -> List[str]:
    if raw is None:
        return list(CHECKS)
    names = [x.strip().lower() for x in raw.split(",") if x.strip()]
    bad = [n for n in names if n not in CHECKS]
    if bad or not names:
        raise UsageError(f"unknown check(s): {', '.join(bad) or '(none)'}; valid: {', '.join(CHECKS)}")
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _snapshot(path: str):
    st = os.stat(path)
    return (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)


def _roll_up(findings: List[Dict[str, Any]]) -> str:
    states = [f.get("state") for f in findings]
    if "failed" in states:
        return "failed"
    if "warning" in states:
        return "warning"
    if "passed" in states:
        return "passed"
    return "unknown"


def _engine_scan(path: str, ctx: Ctx) -> Dict[str, Any]:
    """One macguard-audit scan, returned as {'ok','reason','report','engine'}."""
    if not backends.is_macos():
        return {"ok": False, "reason": "the Installer Auditor engine only exists for macOS"}
    exe = backends.audit_bin()
    if not exe:
        return {"ok": False, "reason": "macguard-audit not found (set MGCTL_AUDIT_BIN or put it on PATH)"}
    argv = [exe, "scan", path, "--format", "json"]
    ctx.debug("engine call: " + " ".join(argv))
    rc, out, err, timed_out = backends.run(argv, ctx.timeout)
    if timed_out:
        return {"ok": False, "reason": f"the engine did not finish within {ctx.timeout} s"}
    try:
        doc = json.loads(out)
        report = doc["results"][0]
    except Exception:
        return {"ok": False, "reason": f"the engine returned no readable report (exit code {rc})"}
    engine: Dict[str, Any] = {"name": "unknown"}
    rc2, out2, _e2, _t2 = backends.run([exe, "engine-status", "--format", "json"], min(ctx.timeout, 60))
    try:
        es = json.loads(out2)
        engine = {"name": "YARA", "version": es.get("version"), "architectures": es.get("architectures"), "ready": es.get("ready"), "note": "classic YARA, not YARA-X"}
    except Exception:
        engine = {"name": "YARA", "ready": None, "note": "engine status unavailable"}
    return {"ok": True, "report": report, "engine": engine, "engineVersion": doc.get("version")}


def _text(doc: Dict[str, Any], ctx: Ctx) -> str:
    L = [f"{doc['file']['resolved']}  [{doc['status']}]  complete={str(doc['complete']).lower()}"]
    for c in doc["checks"]:
        L.append(f"  {c['id']:<11} {c['status']:<15} {c.get('detail', '')}")
    if doc.get("missing"):
        L.append("  not checked: " + ", ".join(doc["missing"]))
    L.append("  " + ctx.t("This is not a safety verdict: 'passed' means the check found nothing confirmed.", "Esto no es un veredicto de seguridad: 'passed' significa que la comprobación no confirmó nada."))
    return "\n".join(L)


def _write(out_dir: str, name: str, content: str) -> str:
    final = os.path.join(out_dir, name)
    if os.path.lexists(final):
        raise UsageError(f"{name} already exists in the output directory; nothing was overwritten")
    tmp = final + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.rename(tmp, final)
    return final


def run(ctx: Ctx, args: Dict[str, Any]) -> int:
    checks = parse_checks(args.get("checks"))
    fmt = "json" if ctx.json else (args.get("format") or "text")
    if fmt not in ("text", "json"):
        raise UsageError("--format must be text or json")
    given, resolved, st0 = validate_path(args["path"], follow_symlinks=bool(args.get("follow_symlinks")), allow_dir=True)
    out_dir = prepare_output_dir(ctx.output) if ctx.output else None
    if out_dir:
        for n in ("report.json", "report.txt"):
            if os.path.lexists(os.path.join(out_dir, n)):
                raise UsageError(f"{n} already exists in the output directory; choose another directory")
    is_file = os.path.isfile(resolved)
    doc: Dict[str, Any] = {
        "schemaVersion": 1, "schema": SCHEMA, "tool": "mgctl", "version": VERSION, "contract": CONTRACT, "startedAt": _now(),
        "file": {"given": given, "resolved": resolved, "symlink": given != resolved, "kind": "file" if is_file else "bundle-or-folder", "sizeBytes": st0.st_size if is_file else None},
        "requestedChecks": checks, "checks": [], "complete": False, "partial": True, "status": "running", "missing": [],
    }
    results: Dict[str, Dict[str, Any]] = {}
    scan: Dict[str, Any] = {}
    snap0 = _snapshot(resolved)
    cancel = threading.Event()
    try:
        with ThreadPoolExecutor(max_workers=ctx.max_workers) as ex:
            try:
                f_hash = ex.submit(hashing.digests, resolved, cancel) if ("hash" in checks and is_file) else None
                f_scan = ex.submit(_engine_scan, resolved, ctx) if ("integrity" in checks or "yara" in checks) else None
                if f_hash:
                    try:
                        d = f_hash.result()
                        results["hash"] = {"id": "hash", "status": "passed", "detail": "sha256 and sha512 computed", "sha256": d["sha256"], "sha512": d["sha512"]}
                    except OSError as e:
                        results["hash"] = {"id": "hash", "status": "unavailable", "detail": f"cannot read the file ({e.strerror})"}
                elif "hash" in checks:
                    results["hash"] = {"id": "hash", "status": "not_applicable", "detail": "digests are computed for regular files only"}
                if f_scan:
                    scan = f_scan.result()
            except KeyboardInterrupt:
                cancel.set()
                backends.terminate_all()
                raise
        changed = _snapshot(resolved) != snap0
    except KeyboardInterrupt:
        doc.update({"status": "cancelled", "complete": False, "partial": True, "finishedAt": _now(), "checks": list(results.values())})
        _persist(doc, out_dir, ctx)
        raise
    # engine-derived checks
    if scan:
        if scan.get("ok"):
            findings = scan["report"].get("findings", [])
            yara_f = [f for f in findings if str(f.get("title", "")).startswith("YARA")]
            other_f = [f for f in findings if f not in yara_f]
            if "integrity" in checks:
                results["integrity"] = {"id": "integrity", "status": _roll_up(other_f), "detail": f"{len(other_f)} finding(s) from the Installer Auditor engine", "findings": other_f, "coverage": scan["report"].get("coverage")}
            if "yara" in checks:
                if scan["engine"].get("ready") is True:
                    results["yara"] = {"id": "yara", "status": _roll_up(yara_f), "detail": f"{len(yara_f)} YARA finding(s)", "findings": yara_f, "engine": scan["engine"]}
                else:      # the engine did not scan: this is "unavailable", never "no findings"
                    results["yara"] = {"id": "yara", "status": "unavailable", "detail": "the YARA engine is not ready (see 'mgctl doctor'); nothing was scanned", "findings": yara_f, "engine": scan["engine"]}
            eng_sha = scan["report"].get("sha256")
            if eng_sha and "hash" in results and results["hash"].get("sha256") and eng_sha != results["hash"]["sha256"]:
                changed = True
                results["hash"]["detail"] += "; DIFFERS from the engine's SHA-256 (the file changed during analysis)"
        else:
            for c in ("integrity", "yara"):
                if c in checks:
                    results[c] = {"id": c, "status": "unavailable", "detail": scan.get("reason", "engine unavailable")}
    for c in ("provenance", "vulns"):
        if c in checks:
            results[c] = {"id": c, "status": "not_implemented", "detail": "no engine exists for this check yet; it is not reported as passed"}
    ordered = [results[c] for c in checks if c in results]
    doc["checks"] = ordered
    doc["missing"] = [c["id"] for c in ordered if c["status"] not in DONE and c["status"] != "not_applicable"]
    doc["changedDuringAnalysis"] = bool(changed)
    complete = (not doc["missing"]) and not changed
    doc.update({"complete": complete, "partial": not complete, "finishedAt": _now(), "status": "failed" if any(c["status"] == "failed" for c in ordered) else ("complete" if complete else "partial")})
    if changed:
        doc["status"] = "failed" if doc["status"] == "failed" else "partial"
    _persist(doc, out_dir, ctx)
    if fmt == "json":
        ctx.emit_json(doc)
    else:
        ctx.out(_text(doc, ctx))
    if any(c["status"] == "failed" for c in ordered):
        return FAILED
    return OK if complete else UNAVAILABLE


def _persist(doc: Dict[str, Any], out_dir: Optional[str], ctx: Ctx) -> None:
    if not out_dir:
        return
    try:
        _write(out_dir, "report.json", json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        _write(out_dir, "report.txt", _text(doc, ctx) + "\n")
    except (UsageError, OSError) as e:
        ctx.err(f"mgctl: could not write the report files: {e}")
