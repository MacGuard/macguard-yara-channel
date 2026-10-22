"""macOS evidence: pkgutil receipts, quarantine / WhereFroms / provenance extended attributes (read directly, never through mdls), code signature,
notarization and Gatekeeper. Everything is read-only; nothing here writes an attribute or runs the subject."""
from __future__ import annotations
import os
import plistlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..context import Ctx, safe_token, url_parts
from ..model import Finding, claim

SEALED_PREFIXES = ("/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/", "/Library/Apple/", "/private/etc/")
TEAM_RE = re.compile(r"^[A-Z0-9]{10}$")
QUARANTINE_RE = re.compile(r"^([0-9a-fA-F]{1,4});([0-9a-fA-F]{1,16});([^;]{0,64});?(.*)$")


def _epoch_iso(v: Any) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(v), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _is_sealed(path: str) -> bool:
    return any(path.startswith(p) for p in SEALED_PREFIXES) and not path.startswith("/usr/local/")


# ---- pkgutil -----------------------------------------------------------------------------------------------------------
def parse_file_info(text: str) -> List[Dict[str, str]]:
    """Blocks of 'key: value' lines separated by a blank line. The first block is volume/path; later blocks (pkgid, pkg-version, install-time, uid, gid, mode) are owners."""
    blocks, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if ": " in line:
            k, v = line.split(": ", 1)
            cur[k.strip()] = v.strip()
    if cur:
        blocks.append(cur)
    return [b for b in blocks if "pkgid" in b]


def collect_pkgutil(ctx: Ctx) -> Finding:
    f = Finding("pkgutil")
    if ctx.os_family != "macos":
        f.applicable = False
        return f
    path = ctx.path
    cmd = "pkgutil --file-info <path>"
    r = ctx.run(["/usr/sbin/pkgutil", "--file-info", path])
    if r.missing or r.timed_out or r.rc != 0:
        why = "pkgutil is not available" if r.missing else "pkgutil timed out" if r.timed_out else f"pkgutil exited {r.rc}"
        f.unqueryable.append("pkgutil")
        ctx.book.add("pkgutil-unreadable", "PKG_RECEIPT_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "pkgdb", present=False, exit_status=r.rc,
                     summary=why + "; ownership by installer packages could not be queried (not the same as 'no owner').")
        f.miss("package_ownership", "pkgutil receipts could not be read")
        return f
    owners = parse_file_info(r.out)
    sealed = _is_sealed(path)
    if not owners:
        if sealed:
            eid = ctx.book.add("pkgutil-no-owner", "PKG_RECEIPT_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "pkgdb", present=False, exit_status=r.rc,
                               summary="No installer receipt names this path. For files on the sealed system volume that is normal and says nothing: macOS system files are not recorded in pkgutil receipts.")
            f.ownership_inconclusive.append("pkgutil has no receipt for this system-volume path, and macOS does not record system files in receipts, so 'no owner' cannot be read as NOT_OWNED.")
            f.miss("package_ownership", "system files are not in pkgutil receipts; the OS image is not a package database this engine can query")
        else:
            eid = ctx.book.add("pkgutil-no-owner", "PKG_RECEIPT_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "pkgdb", present=False, exit_status=r.rc,
                               summary="pkgutil read its receipts successfully and none names this path.")
            f.queried.append("pkgutil")
            f.no_owner_ev.append(eid)
        return f
    f.queried.append("pkgutil")
    mode_now = ctx.ident.get("mode", "")
    for b in owners[:8]:
        pkgid = safe_token(b.get("pkgid"))
        if not pkgid:
            continue
        ver = b.get("pkg-version", "")
        when = _epoch_iso(b.get("install-time"))
        eid = ctx.book.add("pkgutil-" + pkgid, "PKG_RECEIPT_OWNER", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "pkgdb",
                           supports=[claim("package_ownership", "OWNED_BY_PACKAGE", "STRONG"), claim("installation_method", "PKG_INSTALLER", "MODERATE")],
                           summary=f"receipt {pkgid} version {ver or '?'} claims this path" + (f", installed {when}" if when else "") + ". The receipt holds no strong per-file digest.", exit_status=r.rc)
        f.owners.append({"manager": "pkgutil", "name": pkgid, "version": ver, "evidence_id": eid})
        f.installs.append({"value": "PKG_INSTALLER", "manager": "pkgutil", "installed_at": when, "installed_at_basis": "MANAGER_RECORD", "evidence_id": eid})
        if when:
            f.history.append({"at": when, "at_precision": "EXACT", "change": "PACKAGE_INSTALLED", "known_via": "MANAGER_HISTORY_DB", "reliability": "MEDIUM", "evidence_ids": [eid],
                              "detail": f"pkgutil install-time of receipt {pkgid}"})
        rec_mode = b.get("mode", "")[-3:] if b.get("mode") else ""
        if rec_mode and mode_now:
            same = rec_mode.lstrip("0") == mode_now.lstrip("0") or rec_mode == mode_now[-3:]
            uid_ok = (b.get("uid") != "0") or ctx.ident.get("uid_class") == "root"
            ok = same and uid_ok
            mid = ctx.book.add("pkgutil-meta-" + pkgid, "PACKAGE_DB_METADATA_MATCH" if ok else "PACKAGE_DB_METADATA_MISMATCH", "PACKAGE_DB", cmd, "SYSTEM_AUTHORITATIVE", "pkgdb",
                               contradicts=None if ok else [claim("integrity_status", "VERIFIED_INTACT", "WEAK")],
                               summary=f"receipt mode {rec_mode}, uid {b.get('uid', '?')}; file mode {mode_now}, owner class {ctx.ident.get('uid_class')}. Metadata only: it does not cover content.")
            f.integrity.append({"kind": "PACKAGE_DB_METADATA_ONLY", "authority": "pkgutil receipt " + pkgid, "strength": "METADATA_ONLY", "scope": "METADATA_ONLY",
                                "writable": False, "outcome": "MATCH" if ok else "MISMATCH", "evidence_id": mid})
        info = ctx.run(["/usr/sbin/pkgutil", "--pkg-info", pkgid])
        if not info.missing and info.rc == 0:
            loc = re.search(r"^location: (.*)$", info.out, re.M)
            if loc:
                f.why("package_ownership", f"Receipt {pkgid} installs relative to '{loc.group(1)}'.")
    f.miss("integrity_status", "installer receipts hold metadata, not a strong per-file digest")
    return f


# ---- extended attributes -----------------------------------------------------------------------------------------------
def _xattr_names(ctx: Ctx, path: str):
    r = ctx.run(["/usr/bin/xattr", "-s", path])          # -s: do not follow a symlink
    if r.missing or r.timed_out or r.rc != 0:
        return None, r
    return [ln.strip() for ln in r.out.splitlines() if ln.strip()], r


def _xattr_bytes(ctx: Ctx, path: str, name: str) -> Optional[bytes]:
    r = ctx.run(["/usr/bin/xattr", "-s", "-px", name, path])
    if r.missing or r.timed_out or r.rc != 0:
        return None
    try:
        return bytes.fromhex("".join(r.out.split()))
    except ValueError:
        return None


def parse_quarantine(raw: bytes) -> Optional[Dict[str, Any]]:
    m = QUARANTINE_RE.match(raw.decode("utf-8", "replace").strip())
    if not m:
        return None
    flags, ts, agent, rest = m.groups()
    agent = re.sub(r"[^A-Za-z0-9 ._()-]", "", agent)[:64]
    return {"flags": flags.zfill(4), "time": _epoch_iso(int(ts, 16)), "agent": agent, "event_id_present": bool(rest.strip())}


def parse_wherefroms(raw: bytes) -> List[str]:
    try:
        v = plistlib.loads(raw)
    except Exception:
        return []
    return [u for u in v[:8] if isinstance(u, str) and len(u) <= 2048] if isinstance(v, list) else []


def collect_xattrs(ctx: Ctx) -> Finding:
    f = Finding("xattr")
    if ctx.os_family != "macos":
        f.applicable = False
        return f
    targets = [("file", ctx.path)] + ([("bundle", ctx.bundle)] if ctx.bundle and ctx.bundle != ctx.path else [])
    quarantined = False
    any_read = False
    for label, tgt in targets:
        names, r = _xattr_names(ctx, tgt)
        cmd = f"xattr -s <{label}>; xattr -s -px <name> <{label}>"
        if names is None:
            ctx.book.add(f"xattr-unreadable-{label}", "QUARANTINE_XATTR", "XATTR", cmd, "WRITABLE_METADATA", "xattr-writer", present=False, exit_status=r.rc,
                         summary="extended attributes could not be read: not obtainable, which is different from absent")
            f.miss("content_origin", f"extended attributes of the {label} could not be read")
            continue
        any_read = True
        q_raw = _xattr_bytes(ctx, tgt, "com.apple.quarantine") if "com.apple.quarantine" in names else None
        if q_raw is not None:
            q = parse_quarantine(q_raw)
            quarantined = True
            if q:
                summ = (f"quarantine flags={q['flags']}"
                        + (", event id present (not recorded; it would key the quarantine events database, which is not read)" if q["event_id_present"] else "")
                        + ". Any process of the user can write or delete this attribute.")
            else:
                summ = "quarantine attribute present but not in the expected format. Any process of the user can write or delete it."
            eid = ctx.book.add(f"quarantine-{label}", "QUARANTINE_XATTR", "XATTR", cmd, "WRITABLE_METADATA", "xattr-writer",
                               supports=[claim("content_origin", "USER_DOWNLOAD_RECORDED", "MODERATE")], summary=summ,
                               sensitive=(f"agent={q['agent'] or '?'}, time={q['time'] or '?'}" if q else None))
            f.origins.append({"value": "USER_DOWNLOAD_RECORDED", "basis": "DECLARED_BY_WRITABLE_METADATA", "evidence_id": eid, "source": {"recorded_by": "com.apple.quarantine"}})
            f.installs.append({"value": "APP_BUNDLE_COPY" if label == "bundle" or ctx.bundle else "MANUAL_COPY", "evidence_id": eid})
            f.why("installation_method", "A quarantine mark is consistent with a copy placed by hand after a download; it does not exclude other ways the bytes arrived.")
        else:
            ctx.book.add(f"quarantine-{label}", "QUARANTINE_XATTR", "XATTR", cmd, "WRITABLE_METADATA", "xattr-writer", present=False,
                         summary="no quarantine attribute. Absence proves nothing: cask installs, curl, cp and archive tools may not set or may drop it, and users can remove it.")
            f.miss("content_origin", f"no com.apple.quarantine on the {label}")
        w_raw = _xattr_bytes(ctx, tgt, "com.apple.metadata:kMDItemWhereFroms") if "com.apple.metadata:kMDItemWhereFroms" in names else None
        if w_raw is not None:
            urls = [url_parts(u) for u in parse_wherefroms(w_raw)]
            urls = [u for u in urls if u.get("host")]
            host = urls[0]["host"] if urls else None
            eid = ctx.book.add(f"wherefroms-{label}", "WHERE_FROMS_XATTR", "XATTR", cmd, "WRITABLE_METADATA", "xattr-writer",
                               supports=[claim("content_origin", "USER_DOWNLOAD_RECORDED", "WEAK")],
                               summary=f"{len(urls)} download URL(s) recorded in kMDItemWhereFroms (read from the attribute itself; mdls is not used). Editable by any process of the user.",
                               sensitive="; ".join(u["clean"] for u in urls if u.get("clean")))
            if host:
                f.origins.append({"value": "USER_DOWNLOAD_RECORDED", "basis": "DECLARED_BY_WRITABLE_METADATA", "evidence_id": eid, "source": {"url_host": host, "recorded_by": "kMDItemWhereFroms"}})
        elif "com.apple.metadata:kMDItemWhereFroms" in names:
            ctx.book.add(f"wherefroms-{label}", "WHERE_FROMS_XATTR", "XATTR", cmd, "WRITABLE_METADATA", "xattr-writer", present=False, summary="WhereFroms attribute present but unreadable or malformed")
        prov = [n for n in names if n in ("com.apple.provenance", "com.apple.macl")]
        if prov:
            ctx.book.add(f"provenance-{label}", "PROVENANCE_XATTR", "XATTR", cmd, "WRITABLE_METADATA", "xattr-writer",
                         summary="present: " + ", ".join(prov) + ". Seen on almost every file on recent macOS; recorded for the audit trail, it says nothing about origin or publisher.")
    if not any_read:
        f.integrity_failed.append("extended attributes unreadable")
    f.limits.append("Quarantine and WhereFroms are writable by any process of the user: they are recorded as declarations, never as proof. The LaunchServices quarantine events database (personal data) is not read, so the download URL of a quarantined file may be unknown.")
    return f


# ---- code signature, notarization, Gatekeeper --------------------------------------------------------------------------
def parse_codesign_d(text: str) -> Dict[str, Any]:
    d: Dict[str, Any] = {"authorities": []}
    for line in text.splitlines():
        if line.startswith("Authority="):
            d["authorities"].append(line.split("=", 1)[1].strip())
        elif line.startswith("TeamIdentifier="):
            v = line.split("=", 1)[1].strip()
            d["team_id"] = v if TEAM_RE.match(v) else None
        elif line.startswith("Identifier="):
            d["identifier"] = line.split("=", 1)[1].strip()[:160]
        elif line.startswith("Signature=adhoc") or "flags=0x2(adhoc)" in line or "(adhoc)" in line:
            d["adhoc"] = True
        elif line.startswith("Notarization Ticket="):
            d["ticket"] = line.split("=", 1)[1].strip()
        elif line.startswith("Format="):
            d["format"] = line.split("=", 1)[1].strip()
        elif line.startswith("Platform identifier="):
            d["platform"] = True
    return d


def classify_signature(d: Dict[str, Any]) -> str:
    auth = d.get("authorities", [])
    if any(a.startswith("Developer ID Application") for a in auth):
        return "DEVELOPER_ID"
    if any(a.startswith("Apple Mac OS Application Signing") or a.startswith("Apple Distribution") or a.startswith("3rd Party Mac Developer") for a in auth):
        return "MAC_APP_STORE"
    if d.get("adhoc") and not auth:
        return "ADHOC"
    if "Software Signing" in auth or (d.get("platform") and "Apple Root CA" in auth):
        return "APPLE_PLATFORM"
    if not auth and not d.get("adhoc"):
        return "APPLE_PLATFORM" if d.get("platform") else "THIRD_PARTY_OTHER"
    return "THIRD_PARTY_OTHER"


def _publisher(auth: List[str]) -> Optional[str]:
    for a in auth:
        m = re.match(r"Developer ID Application: (.+) \([A-Z0-9]{10}\)$", a)
        if m:
            return re.sub(r"[^\w .,&'-]", "", m.group(1))[:96]
    return None


def collect_codesign(ctx: Ctx) -> Finding:
    f = Finding("codesign")
    if ctx.os_family != "macos":
        f.applicable = False
        return f
    ftype = ctx.ident.get("file_type")
    target = ctx.bundle or (ctx.path if ftype in ("macho", "macho_fat") else None)
    if not target:
        f.applicable = False
        return f
    bundle = bool(ctx.bundle)
    cs = "/usr/bin/codesign"
    d_run = ctx.run([cs, "-dv", "--verbose=4", target])
    if d_run.missing or d_run.timed_out:
        f.integrity_failed.append("codesign " + ("not available" if d_run.missing else "timed out"))
        ctx.book.add("codesign-unavailable", "CODE_SIGNATURE_VALID", "CODE_SIGNATURE", "codesign -dv --verbose=4", "CRYPTOGRAPHIC", "codesign", present=False,
                     summary="codesign could not run; signature state unknown (not the same as unsigned)")
        return f
    text = d_run.err + "\n" + d_run.out
    unsigned = "not signed at all" in text
    v_args = [cs, "--verify", "--strict"] + (["--deep"] if bundle else []) + [target]
    v = ctx.run(v_args)
    cmd = "codesign --verify --strict" + (" --deep" if bundle else "")
    if unsigned:
        ctx.book.add("codesign-none", "CODE_SIGNATURE_VALID", "CODE_SIGNATURE", cmd, "CRYPTOGRAPHIC", "codesign", present=False, exit_status=v.rc,
                     summary="the code is not signed at all: there is no signature to compare with and nothing is claimed about the signer")
        f.signature_summary = {"present": False, "kind": "NONE"}
        f.miss("integrity_status", "no code signature")
        f.miss("content_origin", "no code signature naming a publisher")
        return f
    d = parse_codesign_d(text)
    kind = classify_signature(d)
    team, ident_s = d.get("team_id"), d.get("identifier")
    f.signature_summary = {"present": True, "kind": kind}
    if team:
        f.signature_summary["team_id"] = team
    if ident_s:
        f.signature_summary["identifier"] = ident_s
    valid = v.rc == 0 and not v.timed_out
    if v.timed_out or v.missing:
        f.integrity_failed.append("codesign --verify timed out")
        return f
    standalone_or_main = (not bundle) or bool(getattr(ctx, "is_main_exe", False)) or ctx.path == ctx.bundle
    scope = "WHOLE_FILE_CONTENT" if standalone_or_main else "CODE_PAGES_ONLY"
    signed_kind = kind in ("DEVELOPER_ID", "APPLE_PLATFORM", "MAC_APP_STORE")
    if not valid:
        eid = ctx.book.add("codesign-invalid", "CODE_SIGNATURE_INVALID", "CODE_SIGNATURE", cmd, "CRYPTOGRAPHIC" if signed_kind else "WRITABLE_METADATA", "codesign",
                           exit_status=v.rc, supports=[claim("integrity_status", "MODIFIED", "STRONG")], contradicts=[claim("integrity_status", "VERIFIED_INTACT", "STRONG")],
                           summary="codesign --verify failed: " + (v.err.strip().splitlines()[-1][:160].replace(target, "<target>") if v.err.strip() else "no message")
                           + ". The signature seals the contents; something differs from what was signed (or the signature is damaged).")
        f.integrity.append({"kind": "CODE_SIGNATURE", "authority": kind, "strength": "CRYPTOGRAPHIC_SIGNED" if signed_kind else "CRYPTOGRAPHIC_UNSIGNED",
                            "scope": scope, "writable": not signed_kind, "outcome": "MISMATCH", "evidence_id": eid})
        return f
    # valid signature: is it anchored to Apple, and to whom?
    chain_ok, bound_value, authority = False, None, kind
    if kind == "APPLE_PLATFORM":
        rr = ctx.run([cs, "--verify", "--strict", "-R=anchor apple", target])
        chain_ok, bound_value, authority = rr.rc == 0, "OS_VENDOR", "Apple platform signature"
    elif kind == "DEVELOPER_ID" and team:
        req = ('-R=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
               f'and certificate leaf[subject.OU] = "{team}"')
        rr = ctx.run([cs, "--verify", "--strict", req, target])
        chain_ok, bound_value, authority = rr.rc == 0, "VENDOR_DIRECT", f"Developer ID team {team}"
    elif kind == "MAC_APP_STORE":
        rr = ctx.run([cs, "--verify", "--strict", "-R=anchor apple generic", target])
        chain_ok, bound_value, authority = rr.rc == 0, "REGISTERED_REPOSITORY", "Apple (Mac App Store signing chain)"
    if kind == "ADHOC":
        eid = ctx.book.add("codesign-adhoc", "CODE_SIGNATURE_ADHOC", "CODE_SIGNATURE", cmd, "WRITABLE_METADATA", "codesign", exit_status=v.rc,
                           summary="ad hoc signature, valid: the contents match the hashes sealed when it was ad hoc signed. Anyone can ad hoc sign any bytes, so it names no signer.")
        f.integrity.append({"kind": "CODE_SIGNATURE", "authority": "ad hoc (no signer)", "strength": "CRYPTOGRAPHIC_UNSIGNED", "scope": scope, "writable": True, "outcome": "MATCH", "evidence_id": eid,
                            "note": "An ad hoc signature can be recomputed by whoever changes the file."})
        return f
    if chain_ok and bound_value:
        eid = ctx.book.add("codesign-valid", "CODE_SIGNATURE_VALID", "CODE_SIGNATURE", cmd + "; codesign --verify -R=<anchor and team requirement>", "CRYPTOGRAPHIC", "codesign", exit_status=v.rc,
                           supports=[claim("content_origin", bound_value, "STRONG"), claim("integrity_status", "VERIFIED_INTACT", "STRONG")],
                           summary=f"signature valid and anchored to Apple's roots; signer: {authority}" + (f", identifier {ident_s}" if ident_s else "") + ".")
        src = {}
        if team:
            src["team_id"] = team
        pub = _publisher(d.get("authorities", []))
        if pub:
            src["publisher"] = pub
        f.origins.append({"value": bound_value, "basis": "VERIFIED_BINDING", "evidence_id": eid, "source": src})
        f.integrity.append({"kind": "CODE_SIGNATURE", "authority": authority, "strength": "CRYPTOGRAPHIC_SIGNED", "scope": scope, "writable": False, "outcome": "MATCH", "evidence_id": eid,
                            "note": "" if standalone_or_main else "This file is inside a signed bundle; the bundle seal may or may not list this exact file."})
    else:
        eid = ctx.book.add("codesign-valid", "CODE_SIGNATURE_VALID", "CODE_SIGNATURE", cmd, "WRITABLE_METADATA", "codesign", exit_status=v.rc,
                           summary=f"signature valid, but not anchored to the Apple requirement for kind {kind}: the signer is not shown to be who it claims; anyone with their own certificate can sign.")
        f.integrity.append({"kind": "CODE_SIGNATURE", "authority": "signature not anchored to Apple (" + kind + ")", "strength": "CRYPTOGRAPHIC_UNSIGNED", "scope": scope, "writable": True,
                            "outcome": "MATCH", "evidence_id": eid})
        return f
    # Gatekeeper / notarization: only for bundles (spctl rejects bare tools with an unrelated message)
    if bundle:
        sp = ctx.run(["/usr/sbin/spctl", "--assess", "--type", "execute", "-vv", ctx.bundle])
        out = (sp.err + "\n" + sp.out)
        src_m = re.search(r"source=([^\n]+)", out)
        source = src_m.group(1).strip() if src_m else None
        if sp.missing or sp.timed_out:
            f.attestations.append({"kind": "NOTARIZATION_TICKET", "availability": "NOT_CHECKED", "verifier": "spctl"})
        elif sp.rc == 0 and source:
            kind_ev = "NOTARIZATION_ACCEPTED" if "Notarized" in source else "OTHER"
            claims = []
            if "Notarized Developer ID" in source:
                claims = [claim("content_origin", "VENDOR_DIRECT", "STRONG")]
            elif source == "Apple System":
                claims = [claim("content_origin", "OS_VENDOR", "STRONG")]
            elif source == "Mac App Store":
                claims = [claim("content_origin", "REGISTERED_REPOSITORY", "STRONG")]
            elif source == "Developer ID":
                claims = [claim("content_origin", "VENDOR_DIRECT", "MODERATE")]
            gk = ctx.book.add("gatekeeper", kind_ev, "OS_API", "spctl --assess --type execute -vv", "SYSTEM_AUTHORITATIVE", "codesign", exit_status=sp.rc, supports=claims,
                         summary=f"Gatekeeper accepted the bundle, source={source}. This is the OS's own assessment (it may consult Apple services about notarization; the engine makes no network call itself).")
            f.attestations.append({"kind": "NOTARIZATION_TICKET", "availability": "AVAILABLE_VERIFIED" if "Notarized" in source else "NOT_FOUND", "verifier": "spctl",
                                   "subject_matches_file": True, "evidence_id": gk})
            if source == "Mac App Store":
                rc_path = os.path.join(ctx.bundle, "Contents", "_MASReceipt", "receipt")
                if os.path.isfile(rc_path) and not os.path.islink(rc_path):
                    rid = ctx.book.add("mas-receipt", "APP_STORE_RECEIPT", "OS_API", "stat Contents/_MASReceipt/receipt (presence only)", "MANAGER_DECLARED", "mas-receipt",
                                       supports=[claim("installation_method", "SYSTEM_PACKAGE_MANAGER", "MODERATE")], summary="Mac App Store receipt file present (presence only; validated by the app and the OS, not by this engine)")
                    f.installs.append({"value": "SYSTEM_PACKAGE_MANAGER", "manager": "app-store", "evidence_id": rid})
        else:
            rej = ctx.book.add("gatekeeper-rejected", "GATEKEEPER_REJECTED", "OS_API", "spctl --assess --type execute -vv", "SYSTEM_AUTHORITATIVE", "codesign", exit_status=sp.rc,
                               contradicts=[claim("provenance_confidence", "HIGH", "STRONG")],
                               summary="Gatekeeper rejected the bundle although its signature verifies: " + ((re.sub(r"\s+", " ", out.strip().replace(ctx.bundle, "<bundle>"))[:140]) or "no message"))
            f.attestations.append({"kind": "NOTARIZATION_TICKET", "availability": "VERIFICATION_FAILED", "verifier": "spctl", "evidence_id": rej})
    return f
