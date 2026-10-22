"""Homebrew formulae and casks, read from the manager's own metadata files (INSTALL_RECEIPT.json, Caskroom). The brew command is never run
(it may self-update or load user config); receipts are parsed as data and nothing in them is executed.

A path under Cellar/ is only PATH_LOCATION evidence. Ownership needs the keg's receipt. Homebrew keeps no per-file hash and relocates
Mach-O and text files at install, so a formula file has no integrity reference of its own; code signature evidence (ad hoc after relocation)
is added by the codesign collector."""
from __future__ import annotations
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..context import Ctx, is_real_dir, read_small, safe_token, url_parts
from ..model import Finding, claim

CELLAR_RE = re.compile(r"^(?P<prefix>/.+?)/Cellar/(?P<name>[^/]+)/(?P<ver>[^/]+)(?P<rest>/.*)?$")
OFFICIAL_TAPS = ("homebrew/core", "homebrew/cask")


def _iso(epoch: Any) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def load_json(path: str):
    data = read_small(path)
    if data is None:
        return None
    try:
        v = json.loads(data.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    return v if isinstance(v, dict) else None


def _origin_for_tap(tap: Optional[str], built_from_source: bool) -> str:
    if built_from_source:
        return "LOCAL_BUILD"
    return "REGISTERED_REPOSITORY" if tap in OFFICIAL_TAPS else "THIRD_PARTY_REPOSITORY"


def collect_formula(ctx: Ctx) -> Finding:
    f = Finding("brew-formula")
    m = CELLAR_RE.match(ctx.path)
    if not m:
        f.applicable = False
        return f
    prefix, name, ver = m.group("prefix"), m.group("name"), m.group("ver")
    keg = f"{prefix}/Cellar/{name}/{ver}"
    if not (is_real_dir(f"{prefix}/Cellar") and is_real_dir(f"{prefix}/Cellar/{name}") and is_real_dir(keg)):
        f.applicable = False
        return f
    f.coverage_state = "IMPLEMENTED"
    ctx.book.add("path-cellar", "PATH_LOCATION", "COMPUTED", "path prefix check", "HEURISTIC", "path",
                 summary="The path is inside a Homebrew Cellar. Recorded for the audit trail only: a path is not evidence of ownership.")
    rel = (m.group("rest") or "").lstrip("/")
    rec_path = keg + "/INSTALL_RECEIPT.json"
    rec = load_json(rec_path)
    pkg_name, pkg_ver = safe_token(name) or "?", safe_token(ver) or "?"
    if rec is None:
        eid = ctx.book.add("brew-receipt", "MANAGER_INSTALL_RECEIPT", "MANAGER_METADATA", "read <keg>/INSTALL_RECEIPT.json (JSON parse, no execution)", "MANAGER_DECLARED", "brew-cellar",
                           present=False, summary="No readable INSTALL_RECEIPT.json in the keg. A Cellar path alone does not show that Homebrew installed this file.")
        f.ownership_inconclusive.append("The file is inside a Cellar directory but the keg has no readable INSTALL_RECEIPT.json; a Cellar path alone is not proof of ownership.")
        f.miss("package_ownership", "INSTALL_RECEIPT.json")
        return f
    src = rec.get("source") if isinstance(rec.get("source"), dict) else {}
    tap = safe_token(src.get("tap"))
    built_from_source = rec.get("poured_from_bottle") is False and rec.get("built_as_bottle") is False
    origin_value = _origin_for_tap(tap, built_from_source) if tap or built_from_source else None
    claims = [claim("package_ownership", "OWNED_BY_PACKAGE", "MODERATE"), claim("installation_method", "THIRD_PARTY_PACKAGE_MANAGER", "MODERATE")]
    if origin_value:
        claims.append(claim("content_origin", origin_value, "MODERATE"))
    hv = safe_token(rec.get("homebrew_version"))
    when = _iso(rec.get("time"))
    eid = ctx.book.add("brew-receipt", "MANAGER_INSTALL_RECEIPT", "MANAGER_METADATA", "read <keg>/INSTALL_RECEIPT.json (JSON parse, no execution)", "MANAGER_DECLARED", "brew-cellar",
                       supports=claims, summary=(f"tap={tap or '?'}, poured_from_bottle={rec.get('poured_from_bottle')}, installed_on_request={rec.get('installed_on_request')}, "
                                                 f"loaded_from_api={rec.get('loaded_from_api')}, tap_git_head={'set' if src.get('tap_git_head') else 'null'}. "
                                                 "Written by Homebrew but editable by the account that owns the Cellar."))
    f.queried.append("brew")
    f.owners.append({"manager": "brew", "name": pkg_name, "version": pkg_ver, "arch": rec.get("arch") if isinstance(rec.get("arch"), str) else None, "evidence_id": eid, "repository": tap})
    f.installs.append({"value": "THIRD_PARTY_PACKAGE_MANAGER", "manager": "brew", "installer_version": hv, "installed_at": when, "installed_at_basis": "MANAGER_RECORD" if when else None, "evidence_id": eid})
    if origin_value:
        osrc = {"recorded_by": "brew INSTALL_RECEIPT.json"}
        if tap:
            osrc["repository_id"] = tap
        f.origins.append({"value": origin_value, "basis": "DECLARED_BY_MANAGER", "evidence_id": eid, "source": osrc})
    if when:
        f.history.append({"at": when, "at_precision": "EXACT", "change": "PACKAGE_INSTALLED", "known_via": "MANAGER_HISTORY_DB", "reliability": "MEDIUM", "evidence_ids": [eid],
                          "detail": "receipt time field; editable by the account"})
    # receipt version vs the directory it sits in
    stable = None
    if isinstance(src.get("versions"), dict):
        stable = safe_token(src["versions"].get("stable"))
    if stable:
        ok = ver == stable or ver.startswith(stable + "_")
        ctx.book.add("brew-version", "PACKAGE_DB_METADATA_MATCH" if ok else "PACKAGE_DB_METADATA_MISMATCH", "MANAGER_METADATA", "compare receipt source.versions.stable with the keg directory name",
                     "MANAGER_DECLARED", "brew-cellar", contradicts=None if ok else [claim("package_ownership", "OWNED_BY_PACKAGE", "MODERATE")],
                     summary=f"receipt says {stable}, keg directory is {ver}" + ("" if ok else ": they disagree"))
    # honest limits about integrity
    changed = rec.get("changed_files") if isinstance(rec.get("changed_files"), list) else []
    if rel and rel in changed:
        f.why("integrity_status", "The receipt lists this file in changed_files: Homebrew itself modified it after pouring the bottle.")
    f.miss("integrity_status", "Homebrew stores no per-file hash; the bottle sha256 covers the archive, not the installed files")
    f.miss("integrity_status", "installed Mach-O and text files are relocated at pour time, so they cannot be compared byte for byte with the bottle")
    f.miss("content_origin", "bottle build attestation not checked (the online comparison is not part of this offline run)")
    f.why("integrity_status", "Homebrew relocates installed files and keeps no per-file hash, so there is nothing local to compare the bytes with; the online bottle comparison is not implemented in this version.")
    f.attestations.append({"kind": "GITHUB_ATTESTATION", "availability": "NOT_CHECKED", "verifier": "gh attestation verify"})
    f.limits += ["Receipt and Cellar are writable by the installing account", "No per-file hash exists locally; formula files have no integrity reference unless a code signature gives one",
                 "The source link of the chain is not verified: the bottle is Homebrew's build of an upstream tarball"]
    f.historical = "PARTIAL"
    return f


def collect_cask(ctx: Ctx) -> Finding:
    f = Finding("brew-cask")
    if not ctx.bundle:
        f.applicable = False
        return f
    bundle_real = os.path.realpath(ctx.bundle)
    app_name = os.path.basename(bundle_real)
    hit = None
    for prefix in ctx.brew_prefixes:
        room = os.path.join(prefix, "Caskroom")
        if not is_real_dir(room):
            continue
        try:
            tokens = sorted(os.listdir(room))[:4000]
        except OSError:
            continue
        for tok in tokens:
            tdir = os.path.join(room, tok)
            if tok.startswith(".") or not safe_token(tok) or not is_real_dir(tdir):
                continue
            try:
                vers = [v for v in os.listdir(tdir) if not v.startswith(".")][:50]
            except OSError:
                continue
            for v in vers:
                link = os.path.join(tdir, v, app_name)
                try:
                    if os.path.islink(link) and os.path.realpath(link) == bundle_real:
                        hit = (prefix, tok, v)
                        break
                except OSError:
                    continue
            if hit:
                break
        if hit:
            break
    if not hit:
        if not any(is_real_dir(os.path.join(p, "Caskroom")) for p in ctx.brew_prefixes):
            f.applicable = False
            return f
        eid = ctx.book.add("cask-none", "MANAGER_INSTALL_RECEIPT", "MANAGER_METADATA", "scan <prefix>/Caskroom/*/<version>/<App>.app links", "MANAGER_DECLARED", "brew-caskroom", present=False,
                           summary="No Caskroom entry links to this bundle. A cask with the same name in today's catalog would be a name collision and is not consulted.")
        f.miss("package_ownership", "no Caskroom link for this bundle")
        f.queried.append("brew-cask")
        f.no_owner_ev.append(eid)
        return f
    prefix, tok, v = hit
    meta = os.path.join(prefix, "Caskroom", tok, ".metadata")
    rec = load_json(os.path.join(meta, "INSTALL_RECEIPT.json"))
    ctx.book.add("path-caskroom", "PATH_LOCATION", "COMPUTED", "Caskroom link target check", "HEURISTIC", "path",
                 summary="A symlink inside Caskroom points at this bundle. The link is the manager's bookkeeping; it is not proof by itself (a receipt is required).")
    if rec is None:
        ctx.book.add("cask-receipt", "MANAGER_INSTALL_RECEIPT", "MANAGER_METADATA", "read Caskroom/<cask>/.metadata/INSTALL_RECEIPT.json", "MANAGER_DECLARED", "brew-caskroom", present=False,
                     summary="Caskroom links to the bundle but the cask has no readable receipt; ownership is not concluded.")
        f.ownership_inconclusive.append("A Caskroom entry links to this bundle but the cask receipt is missing or unreadable.")
        return f
    src = rec.get("source") if isinstance(rec.get("source"), dict) else {}
    tap = safe_token(src.get("tap"))
    arts = rec.get("uninstall_artifacts") if isinstance(rec.get("uninstall_artifacts"), list) else []
    declared_apps = [a for x in arts if isinstance(x, dict) for a in (x.get("app") or []) if isinstance(a, str)]
    app_listed = app_name in declared_apps
    when = _iso(rec.get("time"))
    claims = [claim("package_ownership", "OWNED_BY_PACKAGE", "MODERATE" if app_listed else "WEAK"), claim("installation_method", "THIRD_PARTY_PACKAGE_MANAGER", "MODERATE")]
    if tap:
        claims.append(claim("content_origin", _origin_for_tap(tap, False), "WEAK"))
    eid = ctx.book.add("cask-receipt", "MANAGER_INSTALL_RECEIPT", "MANAGER_METADATA", "read Caskroom/<cask>/.metadata/INSTALL_RECEIPT.json (JSON parse, no execution)", "MANAGER_DECLARED", "brew-caskroom",
                       supports=claims if app_listed else None, summary=(f"cask {tok} version {safe_token(src.get('version')) or v}, tap={tap or '?'}, tap_git_head={'set' if src.get('tap_git_head') else 'null'}; "
                                                                                    f"receipt uninstall_artifacts {'lists' if app_listed else 'does NOT list'} {app_name}. Editable by the installing account."))
    if not app_listed:
        f.ownership_inconclusive.append("The cask receipt does not list this application among its app artifacts, so the Caskroom link is not accepted as ownership.")
        return f
    f.queried.append("brew-cask")
    f.owners.append({"manager": "brew-cask", "name": tok, "version": safe_token(src.get("version")) or v, "evidence_id": eid, "repository": tap})
    f.installs.append({"value": "THIRD_PARTY_PACKAGE_MANAGER", "manager": "brew-cask", "installer_version": safe_token(rec.get("homebrew_version")), "installed_at": when,
                       "installed_at_basis": "MANAGER_RECORD" if when else None, "evidence_id": eid})
    if tap:
        f.origins.append({"value": _origin_for_tap(tap, False), "basis": "DECLARED_BY_MANAGER", "evidence_id": eid, "source": {"repository_id": tap, "recorded_by": "brew cask INSTALL_RECEIPT.json"}})
    if when:
        f.history.append({"at": when, "at_precision": "EXACT", "change": "PACKAGE_INSTALLED", "known_via": "MANAGER_HISTORY_DB", "reliability": "MEDIUM", "evidence_ids": [eid],
                          "detail": "cask receipt time field; editable by the account"})
    rv = safe_token(src.get("version"))
    if rv:
        ok = rv == v
        ctx.book.add("cask-version", "PACKAGE_DB_METADATA_MATCH" if ok else "PACKAGE_DB_METADATA_MISMATCH", "MANAGER_METADATA", "compare receipt source.version with the Caskroom version directory",
                     "MANAGER_DECLARED", "brew-caskroom", contradicts=None if ok else [claim("package_ownership", "OWNED_BY_PACKAGE", "MODERATE")],
                     summary=f"receipt says {rv}, Caskroom directory is {v}" + ("" if ok else ": they disagree"))
    # definition snapshot taken at install time (archive sha256 is not the installed bundle's hash)
    snap_root = os.path.join(meta, v)
    snap = None
    try:
        for ts in sorted(os.listdir(snap_root))[:20]:
            c = load_json(os.path.join(snap_root, ts, "Casks", tok + ".json"))
            if c is not None:
                snap = c
                break
    except OSError:
        pass
    if snap:
        up = url_parts(snap["url"]) if isinstance(snap.get("url"), str) else {}
        sha = snap.get("sha256") if isinstance(snap.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", snap.get("sha256", "")) else None
        ctx.book.add("cask-snapshot", "INSTALL_MANIFEST", "MANAGER_METADATA", "read Caskroom/<cask>/.metadata/<ver>/<ts>/Casks/<cask>.json", "MANAGER_DECLARED", "brew-caskroom",
                     summary=("cask definition at install time" + (f", declared archive sha256 {sha[:12]}..." if sha else "") + ". The archive hash does not cover the installed bundle."),
                     sensitive=("download host " + up["host"]) if up.get("host") else None)
        if snap.get("auto_updates") is True:
            f.limits.append("This cask is marked auto_updates: the app may have updated itself away from the version in the receipt")
    f.limits += ["Cask receipts are editable by the installing account", "The cask sha256 covers the downloaded archive, not the installed bundle; the bundle's code signature is the integrity reference",
                 "Today's catalog entry for the same cask is never used as origin (it may be a different version)"]
    f.miss("integrity_status", "the cask archive sha256 is not a reference for the installed bundle")
    f.historical = "PARTIAL"
    return f
