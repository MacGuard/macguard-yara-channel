"""Assembles one provenance document for one subject: validate the path, hash it safely, run the collectors that apply to this OS, combine.

The engine writes nothing on the host. It never executes the subject, never follows a symlink unless asked, and never uses the network."""
from __future__ import annotations
import hashlib
import os
import plistlib
import platform
import re
from typing import Any, Callable, Dict, List, Optional

from . import ENGINE_NAME, POLICY_VERSION, SCHEMA_VERSION, VERSION
from .collectors import brew, dpkg, macos, pip
from .combiner import combine
from .context import Ctx, is_real_dir, read_small
from .fileid import PathError, identify, iso, validate
from .model import EvidenceBook, Finding
from .render import finalize
from .runner import Result


class Unavailable(Exception):
    """The OS family is not supported (exit code 4)."""


MACOS_COLLECTORS = (macos.collect_pkgutil, macos.collect_xattrs, macos.collect_codesign, brew.collect_formula, brew.collect_cask, pip.collect_pip)
LINUX_COLLECTORS = (dpkg.collect_dpkg, pip.collect_pip)
MANAGER_COVERAGE = {"brew": "brew-formula", "brew-cask": "brew-cask", "pkgutil": "pkg-installer", "pip": "pip", "dpkg": "apt-dpkg"}


def _enclosing_bundle(path: str) -> Optional[str]:
    cur = os.path.dirname(path)
    for _ in range(12):
        if cur.endswith(".app") and is_real_dir(cur):
            return cur
        nxt = os.path.dirname(cur)
        if nxt == cur:
            return None
        cur = nxt
    return None


def _plist(bundle: str) -> Dict[str, Any]:
    raw = read_small(os.path.join(bundle, "Contents", "Info.plist"), 2 * 1024 * 1024)
    if raw is None:
        return {}
    try:
        v = plistlib.loads(raw)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def _main_exe(bundle: str, info: Dict[str, Any]) -> Optional[str]:
    name = info.get("CFBundleExecutable")
    if isinstance(name, str) and name and "/" not in name and name not in (".", ".."):
        p = os.path.join(bundle, "Contents", "MacOS", name)
        try:
            if os.path.isfile(p) and not os.path.islink(p):
                return p
        except OSError:
            return None
    return None


def _host(os_family: str, root: str, distro: Optional[str], nonce: str) -> Dict[str, Any]:
    h: Dict[str, Any] = {"os_family": os_family, "arch": platform.machine(), "host_ref": "run-" + nonce[:8]}
    if os_family == "macos":
        h["os_version"] = platform.mac_ver()[0] or "unknown"
    elif os_family == "linux":
        raw = read_small(os.path.join(root, "etc/os-release"), 65536)
        if raw:
            kv = {m[0]: m[2] for m in re.findall(r'^([A-Z_]+)=("?)([^"\n]*)\2$', raw.decode("utf-8", "replace"), re.M)}
            h["os_version"] = kv.get("VERSION_ID", "unknown")
            h["distro_id"] = distro or kv.get("ID", "unknown")
        elif distro:
            h["distro_id"] = distro
    return h


def _chain(file_name: str, assessment: Dict[str, Any], findings: List[Finding]) -> List[Dict[str, Any]]:
    owners = [o for f in findings if f.applicable for o in f.owners]
    own, org = assessment["package_ownership"], assessment["content_origin"]
    chain: List[Dict[str, Any]] = [{"level": "file", "resolution": "RESOLVED", "id": file_name}]
    if len(owners) == 1:
        o = owners[0]
        link = {"level": "package", "resolution": "RESOLVED", "name": o["name"], "evidence_ids": [o["evidence_id"]]}
        if o.get("version"):
            link["version"] = o["version"]
        if o.get("arch"):
            link["arch"] = o["arch"]
        chain.append(link)
        chain.append({"level": "manager", "resolution": "RESOLVED", "name": o["manager"], "evidence_ids": [o["evidence_id"]]})
    elif len(owners) > 1:
        chain.append({"level": "package", "resolution": "CONFLICT", "note": "several packages claim the path: " + ", ".join(sorted({o["name"] for o in owners})[:6]),
                      "evidence_ids": sorted({o["evidence_id"] for o in owners})})
        chain.append({"level": "manager", "resolution": "CONFLICT", "name": ",".join(sorted({o["manager"] for o in owners}))})
    else:
        res = "NOT_QUERYABLE" if own["value"] == "OWNERSHIP_NOT_QUERYABLE" else "UNRESOLVED"
        chain.append({"level": "package", "resolution": res, "note": "no package claims this path" if own["value"] == "NOT_OWNED" else "ownership could not be established"})
        chain.append({"level": "manager", "resolution": res})
    repo = (org.get("source") or {}).get("repository_id")
    chain.append({"level": "repository", "resolution": "RESOLVED" if repo else "UNRESOLVED", **({"id": repo} if repo else {}),
                  **({} if repo else {"note": "no repository recorded for these bytes"})})
    team = (org.get("source") or {}).get("team_id")
    if org.get("claim_basis") == "VERIFIED_BINDING" and team:
        chain.append({"level": "source", "resolution": "RESOLVED", "id": "team:" + team, "evidence_ids": org.get("basis", [])[:3]})
    else:
        chain.append({"level": "source", "resolution": "UNRESOLVED", "note": "the upstream source of the bytes was not verified"})
    return chain


def assess(raw_path: str, *, follow_symlinks: bool = False, runner: Optional[Callable[[List[str]], Result]] = None, os_family: Optional[str] = None, root: str = "/",
           brew_prefixes: Optional[List[str]] = None, now: Optional[str] = None, nonce: Optional[str] = None, distro_id: Optional[str] = None, timeout: int = 20,
           redact: bool = False) -> Dict[str, Any]:
    """Returns the finished, schema-conformant document (sensitive details folded into summaries, or dropped with redact=True; home written as ~)."""
    family = os_family or {"Darwin": "macos", "Linux": "linux"}.get(platform.system(), "other")
    if family not in ("macos", "linux"):
        raise Unavailable(f"provenance is implemented for macOS and Linux; this OS is '{platform.system()}'")
    sub = validate(raw_path, follow_symlinks=follow_symlinks, allow_bundle=(family == "macos"))
    nonce = nonce or os.urandom(8).hex()
    bundle, info, is_main = None, {}, False
    hash_path = sub.resolved
    if sub.is_bundle:
        bundle, info = sub.resolved, _plist(sub.resolved)
        hash_path = _main_exe(bundle, info)
        if not hash_path:
            raise PathError("the .app bundle has no readable main executable (Contents/Info.plist CFBundleExecutable)")
        is_main = True
    elif family == "macos":
        bundle = _enclosing_bundle(sub.resolved)
        if bundle:
            info = _plist(bundle)
            me = _main_exe(bundle, info)
            is_main = bool(me) and os.path.samefile(me, sub.resolved)
    ident = identify(hash_path, was_symlink=sub.was_symlink, given_path=sub.given, want_md5=(family == "linux"))
    if sub.is_bundle:
        ident["path_was_symlink"] = sub.was_symlink
        ident["path"] = sub.given
        ident["resolved_path"] = hash_path
    stable = bool(ident["hashes"]["stable_during_read"])
    book = EvidenceBook(now)
    hid = book.add("hash", "HASH_ONLY", "COMPUTED", "SHA-256 and SHA-512 over one descriptor opened with O_NOFOLLOW", "HEURISTIC", "computed", raw_digest=ident["hashes"]["sha256"],
                   summary="SHA-256 and SHA-512 computed" + ("" if stable else "; the file CHANGED while it was being read (stable_during_read=false)")
                           + ". A hash identifies the bytes (useful for change detection and lookups); it is not integrity: that needs a reference to compare with.")
    ctx = Ctx(ident, hash_path, book, runner=runner, os_family=family, root=root, brew_prefixes=brew_prefixes, bundle=bundle, given_path=sub.given, distro_id=distro_id, timeout=timeout)
    ctx.is_main_exe = is_main
    findings: List[Finding] = []
    for fn in (MACOS_COLLECTORS if family == "macos" else LINUX_COLLECTORS):
        try:
            findings.append(fn(ctx))
        except Exception as e:                                  # a collector bug must never turn into a silent pass
            nm = fn.__name__.replace("collect_", "")
            book.add("collector-error-" + nm, "OTHER", "OS_API", nm, "HEURISTIC", "engine", present=False, summary=f"collector {nm} failed ({type(e).__name__}); its facts are missing, not negative")
            fd = Finding(nm)
            fd.unqueryable.append(nm)
            fd.integrity_failed.append(f"collector {nm} failed")
            findings.append(fd)
    # the code-signature summary belongs to the file identity
    for f in findings:
        if f.applicable and f.signature_summary:
            ident["code_signature_summary"] = f.signature_summary
    assessment = combine(findings, book.items, stable=stable, hash_evidence_id=hid)
    org = assessment["content_origin"]
    if org["value"] == "UNKNOWN" and not org.get("missing"):
        org["missing"] = ["no manager record, signature or origin attribute names a source"]
    live = [f for f in findings if f.applicable]
    owner_f = next((f for f in live if f.owners), None)
    cov_name = MANAGER_COVERAGE.get(owner_f.owners[0]["manager"], "manual-unowned") if owner_f else ("dmg-app-manual" if bundle else "manual-unowned")
    limits = list(dict.fromkeys(l for f in live for l in f.limits))
    limits += ["Offline run: no registry, bottle, attestation or signature-transparency lookup was made (the online comparison is not implemented in this version)",
               "The file is read once through a single descriptor; tools that take a path (codesign, spctl, xattr, pkgutil) re-resolve it, so a swap between steps is possible but would surface as an inconsistent result",
               "History before this first observation is unknowable; only the records listed in history exist"]
    hist = sorted((h for f in live for h in f.history), key=lambda h: h["at"])
    atts, seen = [], set()
    for f in live:
        for a in f.attestations:
            if a["kind"] not in seen:
                seen.add(a["kind"])
                atts.append(a)
    now_s = book.now
    doc: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "document_id": "prov-" + hashlib.sha256((ident["hashes"]["sha256"] + now_s + nonce).encode()).hexdigest()[:24],
        "generated_at": now_s,
        "engine": {"name": ENGINE_NAME, "version": VERSION, "policy_version": POLICY_VERSION, "network_used": False, "privileges": "ROOT" if hasattr(os, "geteuid") and os.geteuid() == 0 else "USER"},
        "host": _host(family, root, distro_id, nonce),
        "subject": {"kind": "file", "file": {k: v for k, v in ident.items() if not k.startswith("_")}},
        "assessment": assessment,
        "ownership_chain": _chain(os.path.basename(hash_path), assessment, findings),
        "evidence": book.items,
        "history": hist,
        "attestations": atts,
        "links": {"detections": [], "vulnerabilities": []},
        "coverage": {"manager_or_method": cov_name, "state": owner_f.coverage_state if owner_f else "IMPLEMENTED",
                     "historical_reconstruction": "PARTIAL" if hist else "NONE", "limits": limits},
    }
    if sub.is_bundle:
        bid, ver = info.get("CFBundleIdentifier"), info.get("CFBundleShortVersionString")
        sig = ident.get("code_signature_summary") or {}
        app: Dict[str, Any] = {"root_path_class": "/Applications" if sub.resolved.startswith("/Applications/") else "user-Applications" if "/Applications/" in sub.resolved else "other"}
        if isinstance(bid, str) and len(bid) < 200:
            app["bundle_id"] = bid
        if isinstance(ver, str) and len(ver) < 64:
            app["version"] = ver
        if sig.get("team_id"):
            app["team_id"] = sig["team_id"]
        doc["subject"]["kind"] = "application"
        doc["subject"]["application"] = app
    return finalize(doc, redact=redact)
