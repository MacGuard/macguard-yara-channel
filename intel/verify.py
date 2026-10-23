"""Independent verification of a catalog and the channels it pins. Standard library; `cosign` only for the signature check.

Layout it expects:  <root>/<channel-id>/<version>/manifest.json  +  the artifacts next to it (paths in the manifest are relative to that folder).
The legacy YARA channel is found at <root>/yara/<release-tag>/manifest.json and its artifacts are verified by `mgctl evidence verify`, not here.

Exit codes   0 verified (signature checked and valid)   1 integrity   2 signature   3 policy (revoked, draft, rollback)   4 missing file or bad format
             5 consistent, but the signature was NOT checked (never reported as 'verified')
Several failures: all are listed; the code is the first by precedence 4, 1, 2, 3, then 5."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from . import SCHEMA_CATALOG, SCHEMA_CHANNEL
from .canonical import canonical_bytes, doc_sha256, file_sha256, sha256_hex
from .merkle import artifacts_root

PRECEDENCE = [4, 1, 2, 3, 5]


class Report:
    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []
        self.codes: List[int] = []

    def add(self, name: str, ok: Optional[bool], detail: str, code: int = 0) -> None:
        status = "pass" if ok else ("n/a" if ok is None else "FAIL")
        self.checks.append({"check": name, "status": status, "detail": detail})
        if ok is False:
            self.codes.append(code)

    def result(self, signature_checked: bool) -> Dict[str, Any]:
        codes = list(self.codes)
        if not codes and not signature_checked:
            codes.append(5)
        exit_code = 0
        for c in PRECEDENCE:
            if c in codes:
                exit_code = c
                break
        label = {0: "VERIFIED", 1: "INTEGRITY FAILURE", 2: "SIGNATURE FAILURE", 3: "POLICY REFUSAL", 4: "INCOMPLETE OR INVALID", 5: "CONSISTENT, SIGNATURE NOT CHECKED"}[exit_code]
        return {"result": label, "exit_code": exit_code, "checks": self.checks}


def _load(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    return json.loads(raw), raw


def verify_signature(file: str, bundle: Optional[str] = None, key: Optional[str] = None, signature: Optional[str] = None, identity: Optional[str] = None,
                     issuer: Optional[str] = None, cosign: str = "cosign", timeout: int = 120):
    """Returns (ok, detail). Identity mode (Sigstore bundle + expected workflow identity) is the production mode; key mode pins a public key for
    offline or test deployments. cosign's text output is never trusted: only its return code."""
    exe = shutil.which(cosign) if os.sep not in cosign else (cosign if os.path.isfile(cosign) else None)
    if not exe:
        return False, "cosign is not installed"
    if bundle and identity and issuer:
        argv = [exe, "verify-blob", "--bundle", bundle, "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, file]
    elif key and (signature or bundle):
        argv = [exe, "verify-blob", "--key", key, "--insecure-ignore-tlog=true"] + (["--signature", signature] if signature else ["--bundle", bundle]) + [file]
    else:
        return False, "give --bundle with --identity and --issuer, or --key with --signature"
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False, "cosign did not finish in time"
    return p.returncode == 0, "cosign verify-blob returned " + str(p.returncode)


def verify_channel_dir(ref: Dict[str, Any], root: str, rep: Report, allow_draft: bool) -> None:
    cid, ver = ref["id"], ref["version"]
    d = os.path.join(root, cid, str(ver))
    mpath = os.path.join(d, "manifest.json")
    name = f"{cid}@{ver}"
    if not os.path.isfile(mpath):
        rep.add(f"{name}: manifest present", False, f"missing: {cid}/{ver}/manifest.json", 4)
        return
    try:
        m, raw = _load(mpath)
    except ValueError:
        rep.add(f"{name}: manifest parses", False, "not valid JSON", 4)
        return
    if ref.get("legacy"):
        rep.add(f"{name}: legacy manifest hash", sha256_hex(raw) == ref["manifest"]["sha256"], "equals the hash pinned in the catalog (artifacts: use 'mgctl evidence verify')", 1)
        return
    rep.add(f"{name}: schema", m.get("schema") == SCHEMA_CHANNEL, m.get("schema", "missing"), 4)
    rep.add(f"{name}: manifest hash", doc_sha256(m) == ref["manifest"]["sha256"], "canonical SHA-256 equals the catalog's", 1)
    rep.add(f"{name}: manifest size", len(raw) == ref["manifest"]["bytes"], f"{len(raw)} bytes", 1)
    rep.add(f"{name}: identity", (m["channel"]["id"], m["channel"]["version"]) == (cid, ver), "channel id and version equal the catalog's", 1)
    bad, listed = [], set()
    for a in m["artifacts"]:
        rel = a["path"]
        listed.add(rel)
        if rel.startswith("/") or ".." in rel.split("/"):
            bad.append(f"{rel}: unsafe path")
            continue
        p = os.path.join(d, rel)
        if os.path.islink(p) or not os.path.isfile(p):
            bad.append(f"{rel}: missing")
        elif os.path.getsize(p) != a["bytes"] or file_sha256(p) != a["sha256"]:
            bad.append(f"{rel}: size or SHA-256 differs")
    rep.add(f"{name}: artifacts", not bad, f"{len(m['artifacts'])} artifacts match their SHA-256" if not bad else "; ".join(bad[:5]), 1)
    extra = []
    for base, _dirs, files in os.walk(d):
        for fn in files:
            rel = os.path.relpath(os.path.join(base, fn), d).replace(os.sep, "/")
            if rel != "manifest.json" and not rel.endswith(".sigstore.json") and rel not in listed:
                extra.append(rel)
    rep.add(f"{name}: no unlisted files", not extra, "none" if not extra else ", ".join(sorted(extra)[:5]), 1)
    root_ok = artifacts_root([{"path": a["path"], "sha256": a["sha256"]} for a in m["artifacts"]]) == m["artifacts_root"] == ref["artifacts_root"]
    rep.add(f"{name}: artifacts root", root_ok, "recomputed Merkle root equals the manifest's and the catalog's", 1)
    st = m["approval"]["state"]
    rep.add(f"{name}: approval state", st == ref["state"], f"manifest says '{st}', catalog says '{ref['state']}'", 1)
    if st == "revoked":
        rep.add(f"{name}: not revoked", False, "this version is revoked", 3)
    elif st != "approved" and not allow_draft:
        rep.add(f"{name}: approved", False, f"state is '{st}': not approved for use", 3)
    elif st == "approved":
        rep.add(f"{name}: licences cleared", bool(m["approval"].get("publishable")), "every source is cleared in the registry", 3)


def verify_catalog(catalog_path: str, root: str, *, signature_bundle: Optional[str] = None, key: Optional[str] = None, signature: Optional[str] = None,
                   identity: Optional[str] = None, issuer: Optional[str] = None, previous_catalog: Optional[str] = None, min_catalog_version: Optional[int] = None,
                   allow_draft: bool = False, cosign: str = "cosign") -> Dict[str, Any]:
    rep = Report()
    try:
        cat, raw = _load(catalog_path)
    except (OSError, ValueError) as e:
        rep.add("catalog readable", False, f"cannot read or parse the catalog ({type(e).__name__})", 4)
        return rep.result(False)
    rep.add("catalog schema", cat.get("schema") == SCHEMA_CATALOG, cat.get("schema", "missing"), 4)
    if cat.get("schema") != SCHEMA_CATALOG:
        return rep.result(False)
    rep.add("catalog canonical form", raw.rstrip(b"\n") == canonical_bytes(cat), "the file is exactly its canonical JSON", 1)
    sig_checked = False
    if signature_bundle or signature:
        ok, detail = verify_signature(catalog_path, signature_bundle, key, signature, identity, issuer, cosign)
        rep.add("catalog signature", ok, detail, 2)
        sig_checked = True
    else:
        rep.add("catalog signature", None, "NOT CHECKED: no signature was supplied")
    version = int(cat["catalog"]["version"])
    if min_catalog_version is not None:
        rep.add("rollback protection", version >= min_catalog_version, f"catalog version {version}, newest trusted {min_catalog_version}", 3)
    if previous_catalog:
        try:
            prev, _ = _load(previous_catalog)
            rep.add("previous catalog link", cat["previous"]["catalog_sha256"] == doc_sha256(prev) and version > int(prev["catalog"]["version"]),
                    "links to the previous catalog and the version increased", 1)
        except (OSError, ValueError):
            rep.add("previous catalog link", False, "cannot read the previous catalog", 4)
    revoked = {(r["channel"], str(r["version"])) for r in cat.get("revocations", [])}
    for ref in cat["channels"]:
        if (ref["id"], str(ref["version"])) in revoked:
            rep.add(f"{ref['id']}@{ref['version']}: not revoked", False, "listed in the catalog's revocations", 3)
        verify_channel_dir(ref, root, rep, allow_draft)
    for combo in cat.get("combinations", []):
        pinned = {c["id"]: c["version"] for c in cat["channels"]}
        ok = all(pinned.get(cid) == v for cid, v in combo["channels"].items())
        rep.add(f"combination {combo['id']}", ok, "every channel version equals the one pinned in the catalog", 1)
    return rep.result(sig_checked)
