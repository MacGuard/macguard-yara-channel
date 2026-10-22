"""The honest status of every channel family. One place, used by `mgctl intelligence channels`, the documentation and (later) the web:
a page may only call a channel 'operational' if this table says so.

operational  = the pipeline publishes it today, signed, and an independent verifier exists
experimental = code and tests exist, but nothing is published from live sources (licence, access or approval is missing)
planned      = a design only
"""
from __future__ import annotations

CHANNELS = [
    {"id": "yara", "family": "yara", "status": "operational", "engine": "classic YARA (yarac), not YARA-X",
     "detail": "Daily validated release, Sigstore-signed, transparency log. This is the legacy channel; the catalog references it unchanged.",
     "evidence": "scripts/verify_public_release.py; mgctl evidence verify"},
    {"id": "yara-x", "family": "yara-x", "status": "planned", "engine": "YARA-X",
     "detail": "No YARA-X gate exists: yara-x is only an engine entry in config/sources.json and the manifests say validation.engine = yara. A YARA-X compatibility gate is designed as an additional check, not a replacement.",
     "evidence": "config/sources.json; docs/intelligence/VALIDATION-PLAN.md"},
    {"id": "sigma", "family": "sigma", "status": "planned", "detail": "Design only.", "evidence": "docs/intelligence/VALIDATION-PLAN.md"},
    {"id": "ioc", "family": "ioc", "status": "experimental",
     "detail": "One real source is wired (abuse.ch Feodo Tracker IP list: download, validation, TTL, manifest). On 2026-10-22 its five records were all older than the 30-day TTL, so 0 were publishable. ThreatFox, URLhaus and MalwareBazaar are blocked (credential and terms). Nothing is published: the owner has not confirmed the licence decision and no signing workflow exists.",
     "evidence": "intel/live.py; tests/test_intel_live.py; config/intel/sources.registry.json"},
    {"id": "vulns", "family": "vulns", "status": "experimental",
     "detail": "CISA Known Exploited Vulnerabilities is wired: the original file is kept byte for byte and 1754 of 1754 records validated on 2026-10-22 into a CVE index. Nothing is published (owner confirmation and signing workflow missing).",
     "evidence": "intel/live.py; tests/test_intel_live.py"},
    {"id": "clamav", "family": "clamav", "status": "planned", "detail": "Blocked until the redistribution terms of the signature databases are reviewed.", "evidence": "docs/intelligence/LICENSE-MATRIX.md"},
    {"id": "heuristics", "family": "heuristics", "status": "planned", "detail": "Design only.", "evidence": "docs/intelligence/VALIDATION-PLAN.md"},
    {"id": "behavior", "family": "behavior", "status": "planned", "detail": "Design only.", "evidence": "docs/intelligence/VALIDATION-PLAN.md"},
    {"id": "ml", "family": "ml", "status": "planned", "detail": "Needs infrastructure and independent test sets that do not exist.", "evidence": "docs/intelligence/VALIDATION-PLAN.md"},
    {"id": "sandbox", "family": "sandbox", "status": "planned", "detail": "Needs isolated infrastructure; real malware is never run on shared CI.", "evidence": "docs/intelligence/VALIDATION-PLAN.md"},
]
