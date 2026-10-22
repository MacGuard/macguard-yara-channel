"""Shared fixtures for the alerts tests. Everything here is SYNTHETIC test data, built in the test: it is never shown as real intelligence."""
import copy
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from intel import registry as reg  # noqa: E402
from intel.vulns import merge as vmerge, records  # noqa: E402
from alerts import engine, identity, model, store, tenancy, authz, subs  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
NOWT = store.utc(NOW)
SHA = "a" * 64
SPEC_ALL = {"schema": "macguard.subscription-filter/1", "version": 1, "expr": {"all": []}}


def spec(expr):
    return {"schema": "macguard.subscription-filter/1", "version": 1, "expr": expr}


def leaf(field, op, value, **kw):
    d = {"field": field, "op": op, "value": value}
    d.update(kw)
    return d


def test_registry():
    """The real registry, with four sources cleared as a TEST double (the real registry clears none of them)."""
    r = reg.load()
    for sid in ("cisa-kev", "enisa-euvd", "enisa-euvd-exploited", "cert-eu-advisories"):
        r[sid] = dict(r[sid], redistribution_status="allowed", owner_confirmed=True)
    return r


def vrec(source, rid, cve=(), euvd=(), ghsa=(), asserted=False, since=None, score=None, vector=None, affected=None, fixes=None, summary="", published="2026-10-01", updated=None, title=None, refs=None):
    r = {"schema": records.SCHEMA_VULN, "source": source, "source_record_id": rid, "ids": {"cve": list(cve), "euvd": list(euvd), "ghsa": list(ghsa)}, "mentions": [], "summary": summary,
         "assigner": None, "dates": {"published": published, "updated": updated}, "severity": ({"scheme": "cvss", "version": "3.1", "score": score, "vector": vector, "rated_by": source, "note": "n"} if score else None),
         "epss": None, "exploitation": {"asserted": asserted, "since": since, "basis": "test basis" if asserted else "none"}, "affected": affected or [], "fixes": fixes or [], "references": refs or [],
         "evidence": {"file": "f.json", "file_sha256": SHA, "locator": "items[0]", "item_sha256": SHA, "retrieved_at": "2026-10-22T11:00:00Z"}}
    if title:
        r["title"] = title
    return r


def aff(vendor, product, version="1.0 <2.0"):
    from intel.vulns import versions
    return {"vendor": vendor, "product": product, "version": versions.parse_affected(version)}


def contents_from(recs, registry, snaps=None):
    merged = vmerge.merge(recs, snaps, NOW, registry)
    return [model.from_merged_entry(e, registry) for e in merged["entries"]]


class DbCase(unittest.TestCase):
    """A fresh database per test, a cleared registry, fast scrypt."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="alerts-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.db = store.connect(os.path.join(self.dir, "a.db"))
        self.addCleanup(self.db.close)
        self.reg = test_registry()
        self.n = 0

    def user(self, email=None, password="correct horse battery staple"):
        self.n += 1
        return identity.register(self.db, email or f"user{self.n}@example.org", password, NOWT, params=identity.SCRYPT_TEST)

    def principal(self, uid):
        return authz.load_principal(self.db, uid)

    def ingest(self, recs):
        return engine.ingest(self.db, contents_from(recs, self.reg), NOWT)
