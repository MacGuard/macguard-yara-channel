"""Python packages: <site-packages>/<dist>.dist-info/{RECORD,INSTALLER,direct_url.json,METADATA}, parsed as data.

RECORD is written by the installer. Its hash is a reference stored beside the file it protects, with no signature: a match is PARTIALLY_VERIFIED
at best and a mismatch is a contradiction to explain (vendor builds, patched installs and edited files all produce one), never a verdict.
The dist-info does not record which index the package came from, so a plain pip install has no content origin."""
from __future__ import annotations
import base64
import csv
import hashlib
import io
import json
import os
import re
from email.parser import BytesHeaderParser
from typing import Any, Dict, List, Optional, Tuple

from ..context import Ctx, is_real_dir, read_small, safe_token, url_parts
from ..model import Finding, claim

MAX_DISTS = 800
MAX_RECORD = 16 * 1024 * 1024
MAX_TOTAL = 96 * 1024 * 1024
SITE_NAMES = ("site-packages", "dist-packages")


def find_site_packages(path: str) -> Optional[str]:
    parts = path.split(os.sep)
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] in SITE_NAMES:
            return os.sep.join(parts[: i + 1])
    d = os.path.dirname(path)
    if os.path.basename(d) == "bin":                          # console scripts: RECORD lists them as ../../../bin/x relative to site-packages
        lib = os.path.join(os.path.dirname(d), "lib")
        try:
            for e in sorted(os.listdir(lib))[:20]:
                c = os.path.join(lib, e, "site-packages")
                if e.startswith("python") and is_real_dir(c):
                    return c
        except OSError:
            return None
    return None


def parse_record(data: bytes) -> List[Tuple[str, str, str]]:
    rows = []
    try:
        text = data.decode("utf-8", "replace")
        for row in csv.reader(io.StringIO(text)):
            if row and len(row[0]) <= 4096:
                rows.append((row[0], row[1] if len(row) > 1 else "", row[2] if len(row) > 2 else ""))
    except csv.Error:
        pass
    return rows


def record_digest_matches(spec: str, sha256_hex: str, sha512_hex: Optional[str]) -> Optional[bool]:
    """spec is 'sha256=<urlsafe base64 without padding>'. None when the algorithm is one we did not compute."""
    if "=" not in spec:
        return None
    algo, b64 = spec.split("=", 1)
    have = {"sha256": sha256_hex, "sha512": sha512_hex}.get(algo.lower())
    if not have:
        return None
    try:
        want = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).hex()
    except Exception:
        return False
    return want == have


def _metadata(dist_dir: str) -> Dict[str, str]:
    raw = read_small(os.path.join(dist_dir, "METADATA"), 1 << 20)
    out: Dict[str, str] = {}
    if raw:
        try:
            msg = BytesHeaderParser().parsebytes(raw[:65536])
            for k in ("Name", "Version"):
                v = safe_token(str(msg.get(k, "")).strip())
                if v:
                    out[k.lower()] = v
        except Exception:
            pass
    if "name" not in out:
        m = re.match(r"^(.+?)-([0-9][^-]*)\.dist-info$", os.path.basename(dist_dir))
        if m:
            out["name"], out["version"] = safe_token(m.group(1)) or "?", safe_token(m.group(2)) or "?"
    return out


def collect_pip(ctx: Ctx) -> Finding:
    f = Finding("pip")
    site = find_site_packages(ctx.path)
    if not site or not is_real_dir(site):
        f.applicable = False
        return f
    norm_target = os.path.normpath(ctx.path)
    cmd = "read <site-packages>/*.dist-info/RECORD (CSV parse, no execution)"
    try:
        entries = sorted(e.name for e in os.scandir(site) if e.name.endswith(".dist-info") and e.is_dir(follow_symlinks=False))
    except OSError:
        entries = None
    if entries is None:
        f.unqueryable.append("pip")
        ctx.book.add("pip-unreadable", "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "MANAGER_DECLARED", "pip-dist-info", present=False, summary="the site-packages directory could not be listed")
        return f
    total, scanned, hits, truncated = 0, 0, [], False
    for name in entries:
        if scanned >= MAX_DISTS or total >= MAX_TOTAL:
            truncated = True
            break
        ddir = os.path.join(site, name)
        data = read_small(os.path.join(ddir, "RECORD"), MAX_RECORD)
        scanned += 1
        if data is None:
            continue
        total += len(data)
        for rp, h, sz in parse_record(data):
            if os.path.normpath(os.path.join(site, rp)) == norm_target:
                hits.append((ddir, rp, h, sz))
                break
    if not hits:
        if truncated:
            f.unqueryable.append("pip")
            ctx.book.add("pip-limit", "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "MANAGER_DECLARED", "pip-dist-info", present=False,
                         summary=f"scan limit reached after {scanned} distributions: 'no owner' cannot be concluded")
            f.miss("package_ownership", "RECORD scan limit reached")
        else:
            eid = ctx.book.add("pip-no-owner", "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "MANAGER_DECLARED", "pip-dist-info", present=False,
                               summary=f"none of {scanned} dist-info RECORD files in this site-packages lists the path (generated files such as .pyc and files dropped by hand are not in RECORD)")
            f.queried.append("pip")
            f.no_owner_ev.append(eid)
        return f
    f.queried.append("pip")
    for ddir, rp, h, sz in hits[:4]:
        meta = _metadata(ddir)
        pname, pver = meta.get("name", "?"), meta.get("version", "?")
        inst_raw = read_small(os.path.join(ddir, "INSTALLER"), 256)
        installer = safe_token(inst_raw.decode("utf-8", "replace").strip()) if inst_raw else None
        base = f"{pname}-{pver}"
        verdict = record_digest_matches(h, ctx.sha256, ctx.sha512) if h else None
        sup = [claim("package_ownership", "OWNED_BY_PACKAGE", "MODERATE"), claim("installation_method", "LANGUAGE_PACKAGE_MANAGER", "MODERATE")]
        if h and verdict is True:
            eid = ctx.book.add("pip-record-" + base, "RECORD_HASH_MATCH", "PACKAGE_DB", cmd, "MANAGER_DECLARED", "pip-dist-info", supports=sup,
                               summary=f"RECORD of {base} lists the file with a {h.split('=')[0]} hash that equals the file's hash. RECORD is written by the installer and stored beside the file: no signature.")
            f.integrity.append({"kind": "RECORD_FILE_HASH", "authority": f"installer RECORD of {base}", "strength": "CRYPTOGRAPHIC_UNSIGNED", "scope": "WHOLE_FILE_CONTENT", "writable": True,
                                "outcome": "MATCH", "evidence_id": eid})
        elif h and verdict is False:
            eid = ctx.book.add("pip-record-" + base, "RECORD_HASH_MISMATCH", "PACKAGE_DB", cmd, "MANAGER_DECLARED", "pip-dist-info", supports=[sup[0], sup[1]],
                               contradicts=[claim("integrity_status", "VERIFIED_INTACT", "MODERATE")],
                               summary=f"RECORD of {base} lists this file with a different hash than the file has now. RECORD is installer-written, not an authority: vendor builds and patched installs "
                                       "also show mismatches. A contradiction to explain, not proof of tampering.")
            f.integrity.append({"kind": "RECORD_FILE_HASH", "authority": f"installer RECORD of {base}", "strength": "CRYPTOGRAPHIC_UNSIGNED", "scope": "WHOLE_FILE_CONTENT", "writable": True,
                                "outcome": "MISMATCH", "evidence_id": eid, "note": "RECORD is written by the installer and sits beside the file; a mismatch is a contradiction to explain, not proof of tampering."})
        else:
            why = "RECORD lists the file without a hash" if not h else "RECORD uses a hash algorithm this engine did not compute"
            eid = ctx.book.add("pip-record-" + base, "PACKAGE_DB_OWNER", "PACKAGE_DB", cmd, "MANAGER_DECLARED", "pip-dist-info", supports=sup, summary=f"RECORD of {base} lists the path. {why}.")
            f.miss("integrity_status", why)
        f.owners.append({"manager": "pip", "name": pname, "version": pver, "evidence_id": eid})
        f.installs.append({"value": "LANGUAGE_PACKAGE_MANAGER", "manager": installer or "unknown-installer", "evidence_id": eid})
        if inst_raw is None:
            f.miss("installation_method", "INSTALLER file missing: the tool that wrote RECORD is unknown")
        du = read_small(os.path.join(ddir, "direct_url.json"), 65536)
        if du:
            try:
                dj = json.loads(du.decode("utf-8", "replace"))
            except (ValueError, RecursionError):
                dj = None
            if isinstance(dj, dict) and isinstance(dj.get("url"), str):
                up = url_parts(dj["url"])
                scheme = dj["url"].split(":", 1)[0].lower()
                if isinstance(dj.get("dir_info"), dict):
                    val = "LOCAL_BUILD"
                elif isinstance(dj.get("vcs_info"), dict) or scheme in ("http", "https"):
                    val = "THIRD_PARTY_REPOSITORY"
                else:
                    val = None
                did = ctx.book.add("pip-direct-url-" + base, "DIRECT_URL_RECORD", "PACKAGE_DB", "read dist-info/direct_url.json", "WRITABLE_METADATA", "pip-dist-info",
                                   supports=[claim("content_origin", val, "WEAK")] if val else None,
                                   summary=f"direct_url.json: install from a {'VCS checkout' if 'vcs_info' in dj else 'local directory' if 'dir_info' in dj else 'URL or archive'}. Written by the installer, editable.",
                                   sensitive=(up.get("clean") or None) if scheme != "file" else None)
                if val:
                    osrc = {"recorded_by": "direct_url.json"}
                    if up.get("host") and scheme != "file":
                        osrc["url_host"] = up["host"]
                    f.origins.append({"value": val, "basis": "DECLARED_BY_WRITABLE_METADATA", "evidence_id": did, "source": osrc})
        else:
            f.miss("content_origin", "the dist-info records no index or URL (a plain pip install does not store where the wheel came from)")
    if len(hits) > 1:
        f.why("package_ownership", "More than one dist-info lists this path.")
    f.limits += ["INSTALLER and RECORD are written by the installer (or shipped by a vendor) and are editable; they are declarations, not an authority",
                 "A plain index install records no origin; PEP 740 attestations (network) are not checked in this offline run"]
    f.attestations.append({"kind": "PEP740", "availability": "NOT_CHECKED"})
    return f
