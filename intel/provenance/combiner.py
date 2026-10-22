"""Evidence combination policy 1.0.0 (design section 5). Pure functions: the same evidence and findings always give the same assessment,
whatever the order they arrive in. Nothing here touches the disk, the network or a subprocess.

Never-upgrade rules enforced here regardless of what a collector emits:
  R1/R2/R3  HASH_ONLY, PATH_LOCATION, NAME_COLLISION_NOTE, TIMESTAMP_CORRELATION, PROVENANCE_XATTR evidence supports nothing.
  C1        evidence in one independence group counts once.
  C2        any contradiction lowers confidence by one level per independent contradicting group, and HIGH/VERY_HIGH are impossible.
  C3        MODIFIED integrity caps confidence at LOW.
  C4        writable metadata and heuristics never lift confidence above LOW; a computed hash is never integrity.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .model import NO_SUPPORT_KINDS, ORIGIN_BASIS_RANK, TRUST_RANK, Finding

LEVELS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
CONF_FIELDS = ("content_origin", "package_ownership", "integrity_status", "provenance_confidence")
OWNED = ("OWNED_BY_PACKAGE", "OWNED_BY_MULTIPLE_PACKAGES", "GENERATED_BY_PACKAGE_SCRIPT")
INSTALL_PRIORITY = ["SYSTEM_PACKAGE_MANAGER", "THIRD_PARTY_PACKAGE_MANAGER", "LANGUAGE_PACKAGE_MANAGER", "PKG_INSTALLER", "SELF_CONTAINED_BUNDLE", "SOURCE_INSTALL",
                    "CONTAINER_RUNTIME", "APP_BUNDLE_COPY", "MANUAL_COPY", "SCRIPT_OR_PIPE_UNRECORDED"]
CAP_RULE = {"PACKAGE_DB_CHECKSUM_MISMATCH": "CAP-INTEGRITY-MODIFIED", "CODE_SIGNATURE_INVALID": "CAP-INTEGRITY-MODIFIED", "RECORD_HASH_MISMATCH": "CAP-RECORD-HASH-MISMATCH",
            "LOCKFILE_INTEGRITY_MISMATCH": "CAP-LOCKFILE-MISMATCH", "GATEKEEPER_REJECTED": "CAP-GATEKEEPER-REJECTED", "PACKAGE_DB_METADATA_MISMATCH": "CAP-OWNER-VERSION-MISMATCH",
            "PACKAGE_SIGNATURE_INVALID": "CAP-PACKAGE-SIGNATURE-INVALID"}


def _uniq(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _ids(xs):
    return sorted(set(xs))


def ref_rank(ref: Dict[str, Any]) -> int:
    """Design step 2 ordering: signed reference > crypto package-db > other unsigned crypto (RECORD, ad hoc) > weak hash > metadata."""
    s, k = ref.get("strength", "NONE"), ref.get("kind", "NONE")
    if s == "CRYPTOGRAPHIC_SIGNED":
        return 6
    if s == "CRYPTOGRAPHIC_UNSIGNED":
        return 5 if k == "PACKAGE_DB_CHECKSUM" else 4
    return {"WEAK_HASH": 3, "METADATA_ONLY": 2}.get(s, 1)


# ---- package_ownership -------------------------------------------------------------------------------------------------
def ownership(findings: Sequence[Finding]) -> Dict[str, Any]:
    owners, seen = [], set()
    for f in findings:
        for o in f.owners:
            k = (o.get("manager"), o.get("name"), o.get("version"))
            if k not in seen:
                seen.add(k)
                owners.append(o)
    queried = sorted({m for f in findings for m in f.queried})
    unq = sorted({m for f in findings for m in f.unqueryable} - set())
    reasons = [r for f in findings for r in f.reasons.get("package_ownership", [])]
    out: Dict[str, Any] = {"queried_managers": queried, "unqueryable_managers": unq}
    if owners:
        out["value"] = "OWNED_BY_MULTIPLE_PACKAGES" if len({(o["manager"], o["name"]) for o in owners}) > 1 else "OWNED_BY_PACKAGE"
        out["basis"] = _ids([o["evidence_id"] for o in owners if o.get("evidence_id")])
        reasons.append("A manager database names the package; this is a claim about the path, not about the bytes (a replaced file keeps its owner).")
        if unq:
            reasons.append("Not every applicable manager could be read: " + ", ".join(unq))
    else:
        inc = _uniq([r for f in findings for r in f.ownership_inconclusive])
        if inc:
            out["value"] = "UNKNOWN"
            reasons += inc
        elif unq:
            out["value"] = "OWNERSHIP_NOT_QUERYABLE"
            reasons.append("An applicable package database could not be read, so 'no owner' cannot be concluded: " + ", ".join(unq))
        elif queried:
            out["value"] = "NOT_OWNED"
            out["basis"] = _ids([e for f in findings for e in f.no_owner_ev])
            reasons.append("Every database consulted (" + ", ".join(queried) + ") was read successfully and none names this path. Other managers that were not consulted may still know it.")
        else:
            out["value"] = "UNKNOWN"
            reasons.append("No package manager applicable to this path was identified.")
    miss = [m for f in findings for m in f.missing.get("package_ownership", [])]
    if miss:
        out["missing"] = _uniq(miss)
    out["reasons"] = _uniq(reasons)
    if not out.get("basis"):
        out.pop("basis", None)
    return out


# ---- content_origin ----------------------------------------------------------------------------------------------------
def origin(findings: Sequence[Finding], stable: bool) -> Tuple[Dict[str, Any], bool]:
    """Returns (assessment, conflict). A conflict between two claims of the same top basis is UNKNOWN and counts as a contradiction."""
    claims = [dict(o) for f in findings for o in f.origins]
    reasons = [r for f in findings for r in f.reasons.get("content_origin", [])]
    if not stable:
        dropped = [c for c in claims if c["basis"] == "VERIFIED_BINDING"]
        if dropped:
            reasons.append("The file changed while it was being read, so no signature or reference was accepted as binding these bytes.")
        claims = [c for c in claims if c["basis"] != "VERIFIED_BINDING"]
    claims = [c for c in claims if c["basis"] in ORIGIN_BASIS_RANK]
    miss = _uniq([m for f in findings for m in f.missing.get("content_origin", [])])
    out: Dict[str, Any] = {}
    if not claims:
        out.update({"value": "UNKNOWN", "claim_basis": "NONE"})
        reasons.append("Nothing recorded says where these bytes came from; the path is not evidence.")
        return _finish(out, miss, reasons), False
    top = max(ORIGIN_BASIS_RANK[c["basis"]] for c in claims)
    tops = [c for c in claims if ORIGIN_BASIS_RANK[c["basis"]] == top]
    values = sorted({c["value"] for c in tops})
    if len(values) > 1:
        out.update({"value": "UNKNOWN", "claim_basis": "NONE"})
        reasons.append("Claims of equal strength disagree (" + ", ".join(values) + "); the engine does not pick one.")
        out["basis"] = _ids([c["evidence_id"] for c in tops if c.get("evidence_id")])
        return _finish(out, miss, reasons), True
    out["value"], out["claim_basis"] = values[0], tops[0]["basis"]
    src: Dict[str, Any] = {}
    for c in tops + [c for c in claims if c not in tops and c["value"] == values[0]]:
        for k, v in (c.get("source") or {}).items():
            src.setdefault(k, v)
    if src:
        out["source"] = src
    out["basis"] = _ids([c["evidence_id"] for c in claims if c["value"] == values[0] and c.get("evidence_id")])
    lower = sorted({c["value"] for c in claims if c["value"] != values[0]})
    if lower:
        reasons.append("Weaker claims also recorded: " + ", ".join(lower) + " (not used).")
    if out["claim_basis"] == "DECLARED_BY_WRITABLE_METADATA":
        reasons.append("The claim comes from metadata that any process of the user can write or delete; it is recorded, not trusted.")
    elif out["claim_basis"] == "DECLARED_BY_MANAGER":
        reasons.append("The manager wrote this down and the same account can edit it; nothing ties these exact bytes to the source.")
    return _finish(out, miss, reasons), False


def _finish(out, miss, reasons):
    if miss:
        out["missing"] = miss
    if reasons:
        out["reasons"] = _uniq(reasons)
    if not out.get("basis"):
        out.pop("basis", None)
    return out


# ---- installation_method -----------------------------------------------------------------------------------------------
def installation(findings: Sequence[Finding]) -> Dict[str, Any]:
    claims = [c for f in findings for c in f.installs if c.get("value") in INSTALL_PRIORITY]
    reasons = [r for f in findings for r in f.reasons.get("installation_method", [])]
    miss = _uniq([m for f in findings for m in f.missing.get("installation_method", [])])
    if not claims:
        out = {"value": "UNKNOWN"}
        reasons.append("No manager record or installer evidence was found. curl|sh, a manual copy and make install leave nothing this engine can read.")
        return _finish(out, miss, reasons)
    claims.sort(key=lambda c: INSTALL_PRIORITY.index(c["value"]))
    best = claims[0]
    out = {"value": best["value"]}
    same = [c for c in claims if c["value"] == best["value"]]
    for k in ("manager", "installer_version", "installed_at", "installed_at_basis"):
        v = next((c[k] for c in same if c.get(k)), None)
        if v:
            out[k] = v
    out["basis"] = _ids([c["evidence_id"] for c in claims if c["value"] == best["value"] and c.get("evidence_id")])
    others = sorted({c["value"] for c in claims if c["value"] != best["value"]})
    if others:
        reasons.append("Other installation records also exist: " + ", ".join(others))
    return _finish(out, miss, reasons)


# ---- integrity_status --------------------------------------------------------------------------------------------------
def integrity(findings: Sequence[Finding], stable: bool, hash_ev: Optional[str] = None) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Returns (assessment, top_reference_or_None)."""
    none_ref = {"kind": "NONE", "strength": "NONE"}
    reasons = [r for f in findings for r in f.reasons.get("integrity_status", [])]
    miss = _uniq([m for f in findings for m in f.missing.get("integrity_status", [])])
    if not stable:
        reasons.append("The file changed (device, inode, size or mtime) while it was being read, even after one retry: no integrity claim is made.")
        return _finish({"value": "UNKNOWN", "reference": none_ref}, miss, reasons), None
    refs = [r for f in findings for r in f.integrity if r.get("outcome") in ("MATCH", "MISMATCH")]
    if not refs:
        failed = _uniq([x for f in findings for x in f.integrity_failed])
        if failed:
            reasons.append("A probe that could have given a reference failed: " + "; ".join(failed))
            return _finish({"value": "UNKNOWN", "reference": none_ref}, miss, reasons), None
        reasons.append("A SHA-256 was computed, but there is no package checksum, signature, manifest or attestation to compare it with: it identifies the bytes, it does not show them intact.")
        return _finish({"value": "NO_REFERENCE", "reference": none_ref, "basis": [hash_ev] if hash_ev else []}, miss, reasons), None
    refs.sort(key=lambda r: (-ref_rank(r), r["kind"], r.get("evidence_id") or ""))
    top = refs[0]
    weaker_mismatch = [r for r in refs[1:] if r["outcome"] == "MISMATCH"]
    if top["outcome"] == "MISMATCH":
        value = "MODIFIED" if top.get("scope") != "METADATA_ONLY" else "PARTIALLY_VERIFIED"
        if value == "PARTIALLY_VERIFIED":
            reasons.append("Only metadata (mode, owner) differs from the package record; that does not show the content changed.")
    else:
        full = ref_rank(top) >= 5 and top.get("scope") == "WHOLE_FILE_CONTENT" and (not top.get("writable") or top.get("strength") == "CRYPTOGRAPHIC_SIGNED")
        value = "VERIFIED_INTACT" if full and not weaker_mismatch else "PARTIALLY_VERIFIED"
        if value == "PARTIALLY_VERIFIED":
            if weaker_mismatch:
                reasons.append("A weaker reference disagrees; listed as a contradiction.")
            if top.get("writable"):
                reasons.append("The reference sits where whoever could change the file could also change the reference, or it is only an unsigned hash.")
            if top.get("scope") != "WHOLE_FILE_CONTENT":
                reasons.append("The reference covers only part of what a file is (" + str(top.get("scope")) + ").")
    if top.get("note"):
        reasons.append(top["note"])
    ref = {"kind": top["kind"], "strength": top["strength"], "scope": top["scope"], "reference_location_writable_by_attacker": bool(top.get("writable"))}
    if top.get("authority"):
        ref["authority"] = top["authority"]
    out = {"value": value, "reference": ref, "basis": _ids([r["evidence_id"] for r in refs if r.get("evidence_id")])}
    return _finish(out, miss, reasons), top


# ---- provenance_confidence ---------------------------------------------------------------------------------------------
def confidence(evidence: Sequence[Dict[str, Any]], org: Dict[str, Any], own: Dict[str, Any], integ: Dict[str, Any], top_ref: Optional[Dict[str, Any]],
               stable: bool, extra_conflict: bool) -> Dict[str, Any]:
    owned = own["value"] in OWNED
    sup: Dict[str, Tuple[int, List[str]]] = {}
    for ev in evidence:
        if not ev.get("present") or ev["kind"] in NO_SUPPORT_KINDS:
            continue
        rank = TRUST_RANK.get(ev["trust"], 0)
        if rank < 1:
            continue
        counted = False
        for c in ev.get("supports", []):
            if c["field"] == "content_origin" and org["value"] != "UNKNOWN" and c["value"] == org["value"]:
                counted = True
            elif c["field"] == "package_ownership" and owned and c["value"] in OWNED:
                counted = True
        if counted:
            g = ev.get("independence_group") or ev["id"]
            prev = sup.get(g, (0, []))
            sup[g] = (max(prev[0], rank), prev[1] + [ev["id"]])
    con: Dict[str, List[str]] = {}
    rules: List[str] = []
    for ev in evidence:
        if ev.get("present") and any(c["field"] in CONF_FIELDS for c in ev.get("contradicts", [])):
            con.setdefault(ev.get("independence_group") or ev["id"], []).append(ev["id"])
            rules.append(CAP_RULE.get(ev["kind"], "CAP-CONTRADICTION"))
    n_con = len(con) + (1 if extra_conflict else 0)
    if extra_conflict:
        rules.append("CAP-ORIGIN-CLAIMS-CONFLICT")
    out: Dict[str, Any] = {"contradicted": n_con > 0}
    if not sup:
        lvl, base = 0, 0
    else:
        ranks = [r for r, _ in sup.values()]
        strong = [r for r in ranks if r >= 2]
        lvl = 1
        if any(r >= 3 for r in ranks) or len(strong) >= 2:
            lvl = 2
        integ_strong = bool(top_ref) and top_ref["outcome"] == "MATCH" and ref_rank(top_ref) >= 5 and (not top_ref.get("writable") or top_ref.get("strength") == "CRYPTOGRAPHIC_SIGNED")
        if strong and integ_strong:
            lvl = 3
        binding = org.get("claim_basis") == "VERIFIED_BINDING" and bool(top_ref) and top_ref["outcome"] == "MATCH" and top_ref.get("strength") == "CRYPTOGRAPHIC_SIGNED"
        crypto_groups = {g for g, (r, _) in sup.items() if r == 4}
        local = [g for g, (r, _) in sup.items() if r in (2, 3) and g not in crypto_groups]
        if binding and crypto_groups and local:
            lvl = 4
        elif binding and crypto_groups:
            lvl = max(lvl, 3)
        base = lvl
    if not stable:
        lvl = min(lvl, 1)
        rules.append("CAP-UNSTABLE-READ")
    if n_con:
        lvl = max(lvl - n_con, 1 if sup else 0)
        lvl = min(lvl, 2)
    if integ["value"] == "MODIFIED":
        lvl = min(lvl, 1 if sup else 0)
        rules.append("CAP-INTEGRITY-MODIFIED")
    out["value"] = LEVELS[lvl]
    if lvl < base and base >= 1:
        out["capped_from"] = LEVELS[base]
    if rules:
        out["cap_rule_ids"] = _uniq(rules)
    out["independent_sources"] = len(sup)
    basis = _ids([i for _, ids in sup.values() for i in ids])
    if basis:
        out["basis"] = basis
    if con or extra_conflict:
        cb = _ids([i for ids in con.values() for i in ids])
        if not cb:
            cb = [i for i in org.get("basis", [])][:1]
        out["contradicted_by"] = cb
        if not cb:
            out["contradicted"] = bool(con)
    reasons = []
    if not sup:
        reasons.append("No supporting evidence for origin or ownership: the engine cannot say. Unknown is not safe and not suspicious by itself.")
    else:
        reasons.append(f"{len(sup)} independent evidence group(s) support the origin/ownership claims; evidence from one database or one writer counts once.")
    if n_con:
        reasons.append("Contradicting evidence lowers the level and rules out HIGH and VERY_HIGH; it is listed in contradicted_by, to be explained, not a verdict.")
    if integ["value"] == "MODIFIED":
        reasons.append("Integrity is MODIFIED against its reference: confidence is capped at LOW and the declared origin is not trusted.")
    if not stable:
        reasons.append("Unstable read: confidence capped at LOW.")
    if lvl <= 1 and sup and all(r <= 1 for r, _ in sup.values()):
        reasons.append("Only writable metadata or a single declarative source supports the claim.")
    out["reasons"] = reasons
    if out["value"] in ("MEDIUM", "HIGH", "VERY_HIGH") and not out.get("basis"):
        out["value"] = "LOW"          # defensive: the schema requires a basis from MEDIUM up
    return out


# ---- the whole assessment ----------------------------------------------------------------------------------------------
def combine(findings: Sequence[Finding], evidence: Sequence[Dict[str, Any]], stable: bool = True, hash_evidence_id: Optional[str] = None) -> Dict[str, Any]:
    fs = [f for f in findings if f.applicable]
    own = ownership(fs)
    org, conflict = origin(fs, stable)
    inst = installation(fs)
    integ, top = integrity(fs, stable, hash_evidence_id)
    conf = confidence(evidence, org, own, integ, top, stable, conflict)
    return {"content_origin": org, "installation_method": inst, "package_ownership": own, "integrity_status": integ, "provenance_confidence": conf,
            "detection_status": {"value": "NOT_SCANNED", "reasons": ["This engine does not scan. No YARA/AV/IOC result is attached; absence of a scan is not a clean result."]}}
