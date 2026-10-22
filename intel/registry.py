"""The source registry: one record per upstream source with its licence, redistribution status and access method.

A channel may only be marked publishable when EVERY source it used is cleared here. 'Cleared' is a human decision recorded in the registry
(redistribution_status 'allowed' or 'allowed-with-conditions'); this code never decides a licence question and never upgrades a status."""
from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Tuple

CLEARED = ("allowed", "allowed-with-conditions")
STATUSES = ("allowed", "allowed-with-conditions", "pending-legal", "blocked", "not-evaluated")
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "intel", "sources.registry.json")


class RegistryError(Exception):
    pass


def load(path: str = DEFAULT_PATH) -> Dict[str, Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise RegistryError(f"registry not found: {path}")
    except ValueError as e:
        raise RegistryError(f"registry is not valid JSON: {e}")
    if doc.get("schema") != "macguard.source-registry/1":
        raise RegistryError("registry schema must be macguard.source-registry/1")
    out: Dict[str, Dict[str, Any]] = {}
    for s in doc.get("sources", []):
        sid = s.get("id")
        if not sid or sid in out:
            raise RegistryError(f"duplicate or missing source id: {sid!r}")
        if s.get("redistribution_status") not in STATUSES:
            raise RegistryError(f"{sid}: redistribution_status must be one of {STATUSES}")
        trust = s.get("trust", 50)
        if not isinstance(trust, int) or not 0 <= trust <= 100:
            raise RegistryError(f"{sid}: trust must be an integer 0..100")
        out[sid] = s
    return out


def clearance(registry: Dict[str, Dict[str, Any]], source_ids: List[str]) -> Tuple[bool, List[str]]:
    """(publishable, reasons). Unknown sources are not cleared."""
    reasons = []
    for sid in sorted(set(source_ids)):
        s = registry.get(sid)
        if s is None:
            reasons.append(f"{sid}: not in the source registry")
        elif s["redistribution_status"] not in CLEARED:
            reasons.append(f"{sid}: redistribution status is '{s['redistribution_status']}'")
        elif s.get("owner_confirmed") is not True:
            reasons.append(f"{sid}: the owner has not confirmed the redistribution decision (owner_confirmed is not true)")
        elif s.get("access", {}).get("credential_required") and not s.get("access", {}).get("credential_terms_allow_redistribution", False):
            reasons.append(f"{sid}: access needs a credential and the registry does not record that its terms allow redistribution")
    return (not reasons), reasons


def public_view(s: Dict[str, Any]) -> Dict[str, Any]:
    """The part of a registry record that goes into a published manifest (no internal notes)."""
    keep = ("id", "name", "upstream_url", "license", "redistribution_status", "owner_confirmed", "attribution", "original_signature")
    return {k: s[k] for k in keep if k in s}
