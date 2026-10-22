"""Output: final redaction pass and the human-readable text. Redaction is applied to a copy, after the assessment is computed, so it can never change a verdict.

Sensitive details (download URLs, quarantine agent and time, apt command lines) travel in a private '_sensitive' key on evidence while the
engine works. By default they are written into the evidence summary with URL query strings, fragments and credentials already removed.
With redact=True they are dropped and the structured url_host is removed too. The home directory is always written as ~."""
from __future__ import annotations
import copy
import os
from typing import Any, Dict, List

SENSITIVE_NOTE = " [sensitive details removed by --redact]"


def _home_variants() -> List[str]:
    h = os.path.expanduser("~")
    out = []
    for v in (h, os.path.realpath(h)):
        if v and v != "/" and v not in out:
            out.append(v)
    return out


def _walk(o: Any, homes: List[str]) -> Any:
    if isinstance(o, str):
        for h in homes:
            if o == h or o.startswith(h + "/"):
                o = "~" + o[len(h):]
            elif h in o:
                o = o.replace(h + "/", "~/").replace(h, "~")
        return o
    if isinstance(o, list):
        return [_walk(x, homes) for x in o]
    if isinstance(o, dict):
        return {k: _walk(v, homes) for k, v in o.items()}
    return o


def finalize(doc: Dict[str, Any], redact: bool = False, homes: List[str] = None) -> Dict[str, Any]:
    d = copy.deepcopy(doc)
    for ev in d.get("evidence", []):
        sens = ev.pop("_sensitive", None)
        if sens:
            ev["summary"] = (ev.get("summary", "") + (SENSITIVE_NOTE if redact else " | sensitive: " + sens)).strip()
    if redact:
        src = d.get("assessment", {}).get("content_origin", {}).get("source")
        if isinstance(src, dict):
            src.pop("url_host", None)
            if not src:
                d["assessment"]["content_origin"].pop("source")
    return _walk(d, homes if homes is not None else _home_variants())


def render_text(doc: Dict[str, Any]) -> str:
    a, f = doc["assessment"], doc["subject"].get("file", {})
    L = [f"Provenance of {f.get('path', '?')}", f"  SHA-256 {f.get('hashes', {}).get('sha256', '?')}  size {f.get('size')}  type {f.get('file_type')}"
         + ("" if f.get("hashes", {}).get("stable_during_read", True) else "  (CHANGED WHILE READING)"), ""]
    L.append("Six separate facts (UNKNOWN means the engine cannot say; it is never 'safe'):")
    o = a["content_origin"]
    L.append(f"  CONTENT_ORIGIN         {o['value']}  [{o['claim_basis']}]")
    L.append(f"  INSTALLATION_METHOD    {a['installation_method']['value']}" + (f"  via {a['installation_method']['manager']}" if a["installation_method"].get("manager") else ""))
    p = a["package_ownership"]
    L.append(f"  PACKAGE_OWNERSHIP      {p['value']}  (queried: {', '.join(p.get('queried_managers') or []) or 'none'}"
             + (f"; not readable: {', '.join(p['unqueryable_managers'])}" if p.get("unqueryable_managers") else "") + ")")
    i = a["integrity_status"]
    L.append(f"  INTEGRITY_STATUS       {i['value']}  reference: {i['reference']['kind']}" + (f" / {i['reference'].get('strength')}" if i["reference"]["kind"] != "NONE" else ""))
    c = a["provenance_confidence"]
    L.append(f"  PROVENANCE_CONFIDENCE  {c['value']}" + ("  CONTRADICTED" if c.get("contradicted") else "") + f"  ({c.get('independent_sources', 0)} independent source(s))")
    L.append(f"  DETECTION_STATUS       {a['detection_status']['value']}  (this engine does not scan)")
    for name in ("content_origin", "installation_method", "package_ownership", "integrity_status", "provenance_confidence"):
        for r in a[name].get("reasons", []):
            L.append(f"    - {name}: {r}")
    gaps = [(n, m) for n in ("content_origin", "installation_method", "package_ownership", "integrity_status") for m in a[n].get("missing", [])]
    if gaps:
        L += ["", "Looked for and absent / not obtainable:"] + [f"  - {n}: {m}" for n, m in gaps]
    cons = [e for e in doc["evidence"] if e.get("contradicts") and e.get("present")]
    if cons:
        L += ["", "Contradictions (to be explained, not verdicts):"] + [f"  - {e['id']}: {e.get('summary', '')}" for e in cons]
    L += ["", f"Evidence ({len(doc['evidence'])}):"] + [f"  {'+' if e['present'] else '-'} {e['id']} [{e['kind']}, {e['trust']}] {e.get('summary', '')}" for e in doc["evidence"]]
    L += ["", "Limits:"] + [f"  - {l}" for l in doc["coverage"].get("limits", [])]
    return "\n".join(L)
