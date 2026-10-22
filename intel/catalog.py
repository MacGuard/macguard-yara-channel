"""The global catalog: one signed document that pins the exact version and manifest hash of every channel, and lists the approved COMBINATIONS.
A client that verifies the catalog's signature and then each manifest hash holds a combination that someone approved together.

The legacy YARA channel is referenced as it is (release tag, manifest hash, rules root, signature bundle hash): its files, signature and
workflow are not touched and not re-signed."""
from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Optional

from . import SCHEMA_CATALOG
from .canonical import canonical_bytes, doc_sha256, file_sha256, sha256_hex


class CatalogError(Exception):
    pass


def channel_ref(manifest_path: str) -> Dict[str, Any]:
    with open(manifest_path, "rb") as f:
        raw = f.read()
    m = json.loads(raw)
    c = m["channel"]
    return {"id": c["id"], "family": c["family"], "version": c["version"], "state": m["approval"]["state"], "publishable": m["approval"]["publishable"],
            "manifest": {"path": None, "sha256": doc_sha256(m), "bytes": len(raw)}, "artifacts_root": m["artifacts_root"]}


def legacy_yara_ref(manifest_json: str, release_json: str, signature_bundle: Optional[str] = None) -> Dict[str, Any]:
    """References an existing legacy release from its published files (downloaded by the caller). Nothing about it is modified."""
    with open(manifest_json, "rb") as f:
        mraw = f.read()
    with open(release_json, "rb") as f:
        rel = json.loads(f.read())
    m = json.loads(mraw)
    ref = {"id": "yara", "family": "yara", "legacy": True, "version": rel["tag"], "state": "approved" if m.get("status") == "PUBLISHED" else "draft",
           "publishable": m.get("status") == "PUBLISHED", "manifest": {"path": "manifest.json", "sha256": sha256_hex(mraw), "bytes": len(mraw)},
           "artifacts_root": m["rules_root"], "validation_engine": m.get("validation", {}).get("engine"), "package_sha256": rel.get("package_sha256")}
    if signature_bundle:
        ref["signature_bundle_sha256"] = file_sha256(signature_bundle)
    return ref


def build_catalog(version: int, created_at: str, channels: List[Dict[str, Any]], combinations: Optional[List[Dict[str, Any]]] = None,
                  previous: Optional[Dict[str, Any]] = None, revocations: Optional[List[Dict[str, Any]]] = None, include_draft: bool = False) -> Dict[str, Any]:
    if not isinstance(version, int) or version < 1:
        raise CatalogError("catalog version must be an integer >= 1")
    chosen = []
    for c in channels:
        if not (c.get("publishable") and c.get("state") == "approved") and not include_draft:
            continue
        chosen.append(c)
    ids = [c["id"] for c in chosen]
    if len(ids) != len(set(ids)):
        raise CatalogError("a channel appears twice in the catalog")
    combos = combinations or []
    for combo in combos:
        for cid, ver in combo["channels"].items():
            ref = next((c for c in chosen if c["id"] == cid), None)
            if ref is None:
                raise CatalogError(f"combination '{combo['id']}' names channel '{cid}' which is not in the catalog")
            if ref["version"] != ver:
                raise CatalogError(f"combination '{combo['id']}' names {cid} version {ver}, the catalog holds {ref['version']}")
            if combo.get("state") == "approved" and ref["state"] != "approved":
                raise CatalogError(f"combination '{combo['id']}' cannot be approved: channel '{cid}' is '{ref['state']}'")
    doc: Dict[str, Any] = {
        "schema": SCHEMA_CATALOG, "catalog": {"version": version, "created_at": created_at},
        "channels": sorted(chosen, key=lambda c: c["id"]), "combinations": combos, "revocations": revocations or [],
        "previous": {"version": None, "catalog_sha256": None},
        "note": "States describe approval, not safety. Verify the signature of this file, then every manifest hash.",
    }
    if previous is not None:
        if int(previous["catalog"]["version"]) >= version:
            raise CatalogError("the catalog version must increase")
        doc["previous"] = {"version": int(previous["catalog"]["version"]), "catalog_sha256": doc_sha256(previous)}
    return doc


def write_catalog(doc: Dict[str, Any], out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    p = os.path.join(out_dir, "catalog.json")
    if os.path.lexists(p):
        raise CatalogError("catalog.json already exists: a published catalog is never overwritten")
    with open(p, "wb") as f:
        f.write(canonical_bytes(doc) + b"\n")
    return p
