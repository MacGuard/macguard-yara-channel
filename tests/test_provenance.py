"""Tests for intel.provenance, the per-file provenance engine.

Layers: (a) the combiner as a pure function (never-upgrade rules, contradictions, UNKNOWN, property tests); (b) collectors against fixtures and an injected
command runner (these run anywhere); (c) negative tests (symlink, FIFO, path tricks, TOCTOU, hostile metadata, no network, no writes);
(d) REAL tests on this Mac, guarded by skipUnless(Darwin and the tool is present), against a real Homebrew formula, cask, pip install, an Apple system binary,
a file with a quarantine attribute set by the test, and a plain file; (e) the CLI and the mgctl command.
The Linux real-host test is PENDING and is reported as a skip with that reason: no Linux host was available."""
import base64
import hashlib
import json
import os
import plistlib
import random
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from intel.provenance import combiner, engine, fileid, render                      # noqa: E402
from intel.provenance.collectors import dpkg as dpkg_mod, macos as macos_mod, pip as pip_mod   # noqa: E402
from intel.provenance.model import Finding, claim                                  # noqa: E402
from intel.provenance.runner import Result                                         # noqa: E402
from provenance_schema_check import validate as schema_validate                    # noqa: E402

SCHEMA = json.load(open(os.path.join(ROOT, "docs", "intelligence", "schemas", "file-provenance.schema.json")))
FIXTURES = os.path.join(ROOT, "docs", "intelligence", "fixtures", "provenance")
DARWIN = sys.platform == "darwin"
NOW = "2026-10-22T14:00:00Z"
LEVELS = combiner.LEVELS


def have(path):
    return os.path.exists(path)


def slurp(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


class Fake:
    """Injectable command runner. Later rules win; an unknown command behaves like a missing executable. Every call is recorded."""

    def __init__(self):
        self.rules, self.calls = [], []

    def on(self, *prefix, rc=0, out="", err="", timed_out=False):
        self.rules.append((prefix, Result(rc, out, err, timed_out, False)))
        return self

    def __call__(self, argv):
        self.calls.append(list(argv))
        for prefix, res in reversed(self.rules):
            if tuple(argv[:len(prefix)]) == prefix:
                return res
        return Result(127, "", "not faked", False, True)


def mac_base():
    """pkgutil knows nothing and the file has no extended attributes."""
    return Fake().on("/usr/sbin/pkgutil", "--file-info", out="volume: /\npath: x\n").on("/usr/bin/xattr", "-s", out="")


def hexdump(b):
    return " ".join("%02X" % c for c in b) + "\n"


def run_assess(path, runner=None, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("nonce", "0123456789abcdef")
    return engine.assess(path, runner=runner, **kw)


def A(doc, name):
    return doc["assessment"][name]


def ev_by_kind(doc, kind):
    return [e for e in doc["evidence"] if e["kind"] == kind]


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="prov-test-"))
        self.addCleanup(shutil.rmtree, self.d, True)

    def mk(self, rel, data=b"hello provenance\n", mode=None):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        if mode:
            os.chmod(p, mode)
        return p

    def check_schema(self, doc):
        self.assertEqual(schema_validate(doc, SCHEMA), [], "document does not conform to the schema")
        s = json.dumps(doc)
        for bad in ('"SAFE"', '"TRUSTED"', '"CLEAN"'):
            self.assertNotIn(bad, s)


# ======================================================================================================================
# (a) the combiner
# ======================================================================================================================
def ev(i, kind="MANAGER_INSTALL_RECEIPT", trust="MANAGER_DECLARED", group="g1", present=True, supports=(), contradicts=()):
    e = {"id": "ev-" + i, "kind": kind, "present": present, "source": {"type": "PACKAGE_DB"}, "observed_at": NOW, "trust": trust, "independence_group": group}
    if supports:
        e["supports"] = [claim(*s) if isinstance(s, tuple) else s for s in supports]
    if contradicts:
        e["contradicts"] = [claim(*c) if isinstance(c, tuple) else c for c in contradicts]
    return e


def owned_finding(evid, origin_value="REGISTERED_REPOSITORY", basis="DECLARED_BY_MANAGER"):
    f = Finding("t")
    f.queried.append("mgr")
    f.owners.append({"manager": "mgr", "name": "pkg", "version": "1", "evidence_id": evid})
    if origin_value:
        f.origins.append({"value": origin_value, "basis": basis, "evidence_id": evid})
    return f


def ref(kind="CODE_SIGNATURE", strength="CRYPTOGRAPHIC_SIGNED", outcome="MATCH", scope="WHOLE_FILE_CONTENT", writable=False, eid="ev-ref"):
    return {"kind": kind, "authority": "t", "strength": strength, "scope": scope, "writable": writable, "outcome": outcome, "evidence_id": eid}


def level(a):
    return LEVELS.index(a["provenance_confidence"]["value"])


class CombinerTests(unittest.TestCase):
    def test_a_hash_alone_is_no_reference_and_unknown_never_intact(self):
        a = combiner.combine([Finding("t")], [ev("hash", "HASH_ONLY", "HEURISTIC", "computed")], True, "ev-hash")
        self.assertEqual(a["integrity_status"]["value"], "NO_REFERENCE")
        self.assertEqual(a["integrity_status"]["reference"]["kind"], "NONE")
        self.assertEqual(a["provenance_confidence"]["value"], "UNKNOWN")
        self.assertEqual(a["content_origin"], {"value": "UNKNOWN", "claim_basis": "NONE", "reasons": a["content_origin"]["reasons"]})
        self.assertEqual(a["package_ownership"]["value"], "UNKNOWN")
        self.assertEqual(a["detection_status"]["value"], "NOT_SCANNED")

    def test_path_name_collision_hash_and_provenance_xattr_never_support_anything(self):
        base_f = Finding("t")
        for kind in ("PATH_LOCATION", "NAME_COLLISION_NOTE", "HASH_ONLY", "TIMESTAMP_CORRELATION", "PROVENANCE_XATTR"):
            sup = [("content_origin", "REGISTERED_REPOSITORY"), ("package_ownership", "OWNED_BY_PACKAGE")]
            with_ev = combiner.combine([owned_finding("ev-x")], [ev("x", kind, "SYSTEM_AUTHORITATIVE", "gx", supports=sup)], True)
            self.assertEqual(with_ev["provenance_confidence"]["value"], "UNKNOWN", kind)
        a = combiner.combine([base_f], [ev("p", "PATH_LOCATION", "HEURISTIC", "path", supports=[("content_origin", "OS_VENDOR")])], True)
        self.assertEqual(a["content_origin"]["value"], "UNKNOWN")

    def test_absent_evidence_supports_nothing(self):
        a = combiner.combine([owned_finding("ev-r")], [ev("r", present=False, supports=[("package_ownership", "OWNED_BY_PACKAGE")])], True)
        self.assertEqual(a["provenance_confidence"]["value"], "UNKNOWN")

    def test_one_declared_group_is_low_two_independent_groups_medium_system_record_medium(self):
        sup = [("package_ownership", "OWNED_BY_PACKAGE"), ("content_origin", "REGISTERED_REPOSITORY")]
        one = combiner.combine([owned_finding("ev-a")], [ev("a", supports=sup)], True)
        self.assertEqual(one["provenance_confidence"]["value"], "LOW")
        two = combiner.combine([owned_finding("ev-a")], [ev("a", supports=sup), ev("b", group="g2", supports=sup)], True)
        self.assertEqual(two["provenance_confidence"]["value"], "MEDIUM")
        sysrec = combiner.combine([owned_finding("ev-a")], [ev("a", trust="SYSTEM_AUTHORITATIVE", supports=sup)], True)
        self.assertEqual(sysrec["provenance_confidence"]["value"], "MEDIUM")

    def test_same_independence_group_counts_once(self):
        sup = [("package_ownership", "OWNED_BY_PACKAGE"), ("content_origin", "REGISTERED_REPOSITORY")]
        a = combiner.combine([owned_finding("ev-a")], [ev("a", supports=sup), ev("b", supports=sup), ev("c", supports=sup)], True)
        self.assertEqual(a["provenance_confidence"]["independent_sources"], 1)
        self.assertEqual(a["provenance_confidence"]["value"], "LOW")

    def test_writable_metadata_alone_stays_low_even_when_repeated(self):
        f = Finding("t")
        f.origins.append({"value": "USER_DOWNLOAD_RECORDED", "basis": "DECLARED_BY_WRITABLE_METADATA", "evidence_id": "ev-q"})
        e = [ev("q", "QUARANTINE_XATTR", "WRITABLE_METADATA", "xattr", supports=[("content_origin", "USER_DOWNLOAD_RECORDED")]),
             ev("w", "WHERE_FROMS_XATTR", "WRITABLE_METADATA", "xattr", supports=[("content_origin", "USER_DOWNLOAD_RECORDED")])]
        a = combiner.combine([f], e, True)
        self.assertEqual(a["provenance_confidence"]["value"], "LOW")
        self.assertEqual(a["content_origin"]["claim_basis"], "DECLARED_BY_WRITABLE_METADATA")

    def test_high_needs_a_record_and_a_strong_reference_very_high_needs_a_binding_plus_a_local_record(self):
        sup = [("package_ownership", "OWNED_BY_PACKAGE")]
        f = owned_finding("ev-db", origin_value=None)
        f.integrity.append(ref("PACKAGE_DB_CHECKSUM", "CRYPTOGRAPHIC_UNSIGNED", eid="ev-sum"))
        a = combiner.combine([f], [ev("db", trust="SYSTEM_AUTHORITATIVE", group="db", supports=sup)], True)
        self.assertEqual(a["provenance_confidence"]["value"], "HIGH")
        weak = owned_finding("ev-db", origin_value=None)
        weak.integrity.append(ref("PACKAGE_DB_CHECKSUM", "WEAK_HASH", writable=True, eid="ev-sum"))
        w = combiner.combine([weak], [ev("db", trust="SYSTEM_AUTHORITATIVE", group="db", supports=sup)], True)
        self.assertEqual(w["provenance_confidence"]["value"], "MEDIUM")
        self.assertEqual(w["integrity_status"]["value"], "PARTIALLY_VERIFIED")
        bind = owned_finding("ev-db", origin_value="VENDOR_DIRECT", basis="VERIFIED_BINDING")
        bind.integrity.append(ref(eid="ev-sig"))
        e = [ev("db", trust="SYSTEM_AUTHORITATIVE", group="db", supports=sup),
             ev("sig", "CODE_SIGNATURE_VALID", "CRYPTOGRAPHIC", "codesign", supports=[("content_origin", "VENDOR_DIRECT")])]
        self.assertEqual(combiner.combine([bind], e, True)["provenance_confidence"]["value"], "VERY_HIGH")
        only_sig = Finding("t")
        only_sig.origins.append({"value": "VENDOR_DIRECT", "basis": "VERIFIED_BINDING", "evidence_id": "ev-sig"})
        only_sig.integrity.append(ref(eid="ev-sig"))
        self.assertEqual(combiner.combine([only_sig], [e[1]], True)["provenance_confidence"]["value"], "HIGH")

    def test_modified_integrity_caps_confidence_at_low_and_is_listed_as_contradiction(self):
        f = owned_finding("ev-r")
        f.integrity.append(ref("CODE_SIGNATURE", "CRYPTOGRAPHIC_SIGNED", "MISMATCH", eid="ev-bad"))
        e = [ev("r", trust="SYSTEM_AUTHORITATIVE", group="db", supports=[("package_ownership", "OWNED_BY_PACKAGE"), ("content_origin", "REGISTERED_REPOSITORY")]),
             ev("bad", "CODE_SIGNATURE_INVALID", "CRYPTOGRAPHIC", "codesign", contradicts=[("integrity_status", "VERIFIED_INTACT")])]
        a = combiner.combine([f], e, True)
        self.assertEqual(a["integrity_status"]["value"], "MODIFIED")
        c = a["provenance_confidence"]
        self.assertEqual(c["value"], "LOW")
        self.assertTrue(c["contradicted"])
        self.assertIn("ev-bad", c["contradicted_by"])
        self.assertIn("CAP-INTEGRITY-MODIFIED", c["cap_rule_ids"])
        self.assertEqual(c["capped_from"], "MEDIUM")

    def test_weaker_mismatch_next_to_a_strong_match_is_partial_not_intact(self):
        f = Finding("t")
        f.integrity += [ref(eid="ev-sig"), ref("RECORD_FILE_HASH", "CRYPTOGRAPHIC_UNSIGNED", "MISMATCH", writable=True, eid="ev-rec")]
        a = combiner.combine([f], [], True)
        self.assertEqual(a["integrity_status"]["value"], "PARTIALLY_VERIFIED")

    def test_metadata_only_mismatch_does_not_say_modified(self):
        f = Finding("t")
        f.integrity.append(ref("PACKAGE_DB_METADATA_ONLY", "METADATA_ONLY", "MISMATCH", "METADATA_ONLY", eid="ev-m"))
        self.assertEqual(combiner.combine([f], [], True)["integrity_status"]["value"], "PARTIALLY_VERIFIED")

    def test_a_signature_on_a_bundle_resource_is_partial_because_the_scope_is_narrower(self):
        f = Finding("t")
        f.integrity.append(ref(scope="CODE_PAGES_ONLY"))
        self.assertEqual(combiner.combine([f], [], True)["integrity_status"]["value"], "PARTIALLY_VERIFIED")

    def test_unstable_read_gives_unknown_integrity_drops_bindings_and_caps_confidence(self):
        f = owned_finding("ev-s", origin_value="VENDOR_DIRECT", basis="VERIFIED_BINDING")
        f.integrity.append(ref(eid="ev-s"))
        e = [ev("s", "CODE_SIGNATURE_VALID", "CRYPTOGRAPHIC", "codesign", supports=[("content_origin", "VENDOR_DIRECT"), ("package_ownership", "OWNED_BY_PACKAGE")])]
        a = combiner.combine([f], e, False)
        self.assertEqual(a["integrity_status"]["value"], "UNKNOWN")
        self.assertEqual(a["content_origin"]["value"], "UNKNOWN")
        self.assertLessEqual(level(a), 1)
        self.assertIn("CAP-UNSTABLE-READ", a["provenance_confidence"].get("cap_rule_ids", []))

    def test_ownership_states(self):
        unreadable = Finding("t")
        unreadable.unqueryable.append("dpkg")
        self.assertEqual(combiner.combine([unreadable], [], True)["package_ownership"]["value"], "OWNERSHIP_NOT_QUERYABLE")
        mixed = Finding("t")
        mixed.queried.append("pkgutil")
        mixed.unqueryable.append("brew")
        self.assertEqual(combiner.combine([mixed], [], True)["package_ownership"]["value"], "OWNERSHIP_NOT_QUERYABLE")       # never NOT_OWNED while a database is unreadable
        ok = Finding("t")
        ok.queried.append("dpkg")
        self.assertEqual(combiner.combine([ok], [], True)["package_ownership"]["value"], "NOT_OWNED")
        inconclusive = Finding("t")
        inconclusive.queried.append("pkgutil")
        inconclusive.ownership_inconclusive.append("system volume")
        self.assertEqual(combiner.combine([inconclusive], [], True)["package_ownership"]["value"], "UNKNOWN")
        self.assertEqual(combiner.combine([], [], True)["package_ownership"]["value"], "UNKNOWN")
        two = Finding("t")
        two.owners = [{"manager": "a", "name": "x", "version": "1", "evidence_id": "ev-1"}, {"manager": "b", "name": "y", "version": "1", "evidence_id": "ev-2"}]
        self.assertEqual(combiner.combine([two], [], True)["package_ownership"]["value"], "OWNED_BY_MULTIPLE_PACKAGES")
        owner_wins = Finding("t")
        owner_wins.owners = [{"manager": "a", "name": "x", "version": "1", "evidence_id": "ev-1"}]
        owner_wins.unqueryable.append("b")
        got = combiner.combine([owner_wins], [], True)["package_ownership"]
        self.assertEqual((got["value"], got["unqueryable_managers"]), ("OWNED_BY_PACKAGE", ["b"]))

    def test_conflicting_origin_claims_of_equal_strength_are_unknown_and_contradicted(self):
        f = Finding("t")
        f.origins += [{"value": "OS_VENDOR", "basis": "DECLARED_BY_MANAGER", "evidence_id": "ev-a"}, {"value": "VENDOR_DIRECT", "basis": "DECLARED_BY_MANAGER", "evidence_id": "ev-b"}]
        a = combiner.combine([f], [ev("a", supports=[("content_origin", "OS_VENDOR")]), ev("b", group="g2", supports=[("content_origin", "VENDOR_DIRECT")])], True)
        self.assertEqual(a["content_origin"]["value"], "UNKNOWN")
        self.assertTrue(a["provenance_confidence"]["contradicted"])

    def test_verified_binding_beats_a_declaration_and_inferred_never_counts(self):
        f = Finding("t")
        f.origins += [{"value": "REGISTERED_REPOSITORY", "basis": "DECLARED_BY_MANAGER", "evidence_id": "ev-a"}, {"value": "VENDOR_DIRECT", "basis": "VERIFIED_BINDING", "evidence_id": "ev-b"}]
        a = combiner.combine([f], [], True)
        self.assertEqual((a["content_origin"]["value"], a["content_origin"]["claim_basis"]), ("VENDOR_DIRECT", "VERIFIED_BINDING"))
        g = Finding("t")
        g.origins.append({"value": "LOCAL_BUILD", "basis": "INFERRED", "evidence_id": "ev-h"})
        a2 = combiner.combine([g], [ev("h", "OTHER", "HEURISTIC", "engine", supports=[("content_origin", "LOCAL_BUILD")])], True)
        self.assertEqual(a2["provenance_confidence"]["value"], "UNKNOWN")

    def test_installation_priority_and_missing_records(self):
        f = Finding("t")
        f.installs += [{"value": "MANUAL_COPY", "evidence_id": "ev-q"}, {"value": "THIRD_PARTY_PACKAGE_MANAGER", "manager": "brew", "installed_at": "2026-01-01T00:00:00Z",
                                                                          "installed_at_basis": "MANAGER_RECORD", "evidence_id": "ev-r"}]
        got = combiner.combine([f], [], True)["installation_method"]
        self.assertEqual((got["value"], got["manager"], got["installed_at"]), ("THIRD_PARTY_PACKAGE_MANAGER", "brew", "2026-01-01T00:00:00Z"))
        self.assertEqual(combiner.combine([Finding("t")], [], True)["installation_method"]["value"], "UNKNOWN")

    def test_failed_probe_is_unknown_not_no_reference(self):
        f = Finding("t")
        f.integrity_failed.append("codesign timed out")
        self.assertEqual(combiner.combine([f], [], True)["integrity_status"]["value"], "UNKNOWN")


class CombinerPropertyTests(unittest.TestCase):
    """Seeded random scenarios. Properties from the design, section 10.3."""
    GROUPS = ("db", "w", "mgr", "sig")
    TRUST = {"db": "SYSTEM_AUTHORITATIVE", "w": "WRITABLE_METADATA", "mgr": "MANAGER_DECLARED", "sig": "CRYPTOGRAPHIC"}
    KINDS = {"db": "PACKAGE_DB_OWNER", "w": "QUARANTINE_XATTR", "mgr": "MANAGER_INSTALL_RECEIPT", "sig": "CODE_SIGNATURE_VALID"}

    def scenario(self, rnd):
        groups = rnd.sample(self.GROUPS, rnd.randint(0, 4))
        e = []
        for n, g in enumerate(groups):
            for k in range(rnd.randint(1, 2)):
                e.append(ev(f"{g}{k}", self.KINDS[g], self.TRUST[g], g, supports=[("content_origin", "REGISTERED_REPOSITORY"), ("package_ownership", "OWNED_BY_PACKAGE")]))
        f = owned_finding("ev-db0") if rnd.random() < 0.8 else Finding("t")
        if rnd.random() < 0.5:
            f.integrity.append(ref(rnd.choice(["CODE_SIGNATURE", "RECORD_FILE_HASH"]), rnd.choice(["CRYPTOGRAPHIC_SIGNED", "CRYPTOGRAPHIC_UNSIGNED", "WEAK_HASH"]),
                                   rnd.choice(["MATCH", "MATCH", "MISMATCH"]), writable=rnd.random() < 0.5))
        return [f], e

    def conf(self, fs, e):
        return combiner.combine(fs, e, True)

    def test_adding_a_contradiction_never_raises_confidence_and_blocks_high(self):
        rnd = random.Random(20261022)
        for _ in range(400):
            fs, e = self.scenario(rnd)
            before = self.conf(fs, e)
            bad = ev("zz", "RECORD_HASH_MISMATCH", "MANAGER_DECLARED", "extra", contradicts=[("integrity_status", "VERIFIED_INTACT")])
            after = self.conf(fs, e + [bad])
            self.assertLessEqual(level(after), level(before))
            self.assertTrue(after["provenance_confidence"]["contradicted"])
            self.assertLessEqual(level(after), 2)

    def test_more_evidence_in_an_already_counted_group_never_raises_confidence(self):
        rnd = random.Random(7)
        for _ in range(400):
            fs, e = self.scenario(rnd)
            if not e:
                continue
            g = rnd.choice(e)
            dup = ev("dup", g["kind"], g["trust"], g["independence_group"], supports=g["supports"])
            self.assertEqual(level(self.conf(fs, e + [dup])), level(self.conf(fs, e)))

    def test_removing_supporting_evidence_never_strengthens_anything(self):
        rnd = random.Random(99)
        for _ in range(400):
            fs, e = self.scenario(rnd)
            if not e:
                continue
            smaller = list(e)
            smaller.pop(rnd.randrange(len(smaller)))
            self.assertLessEqual(level(self.conf(fs, smaller)), level(self.conf(fs, e)))

    def test_order_of_evidence_and_findings_does_not_matter(self):
        rnd = random.Random(5)
        for _ in range(200):
            fs, e = self.scenario(rnd)
            e2 = list(e)
            rnd.shuffle(e2)
            self.assertEqual(json.dumps(self.conf(fs, e), sort_keys=True), json.dumps(self.conf(fs, e2), sort_keys=True))

    def test_high_and_very_high_imply_not_contradicted_and_a_basis(self):
        rnd = random.Random(31)
        for _ in range(600):
            fs, e = self.scenario(rnd)
            if rnd.random() < 0.4:
                e.append(ev("gk", "GATEKEEPER_REJECTED", "SYSTEM_AUTHORITATIVE", "gk", contradicts=[("provenance_confidence", "HIGH")]))
            c = self.conf(fs, e)["provenance_confidence"]
            if c["value"] in ("HIGH", "VERY_HIGH"):
                self.assertFalse(c["contradicted"])
                self.assertNotIn("contradicted_by", c) if not c.get("contradicted_by") else self.fail("contradicted_by with HIGH")
            if c["value"] in ("MEDIUM", "HIGH", "VERY_HIGH"):
                self.assertTrue(c["basis"])
                self.assertGreaterEqual(c["independent_sources"], 1)

    def test_a_hash_without_a_reference_is_never_verified_intact(self):
        rnd = random.Random(3)
        for _ in range(200):
            fs, e = self.scenario(rnd)
            for f in fs:
                f.integrity = []
            self.assertEqual(self.conf(fs, e)["integrity_status"]["value"], "NO_REFERENCE")

    def test_path_and_name_collision_evidence_in_any_amount_changes_nothing(self):
        rnd = random.Random(11)
        for _ in range(200):
            fs, e = self.scenario(rnd)
            noise = [ev(f"n{i}", rnd.choice(["PATH_LOCATION", "NAME_COLLISION_NOTE", "HASH_ONLY", "TIMESTAMP_CORRELATION"]), "SYSTEM_AUTHORITATIVE", f"n{i}",
                        supports=[("content_origin", "REGISTERED_REPOSITORY"), ("package_ownership", "OWNED_BY_PACKAGE")]) for i in range(rnd.randint(1, 5))]
            self.assertEqual(json.dumps(self.conf(fs, e), sort_keys=True), json.dumps(self.conf(fs, e + noise), sort_keys=True))


# ======================================================================================================================
# (b) fixtures: the committed design fixtures still validate; collectors with an injected runner
# ======================================================================================================================
class SchemaFixtureTests(unittest.TestCase):
    def test_the_design_fixtures_validate_and_mutations_are_rejected(self):
        for fn in sorted(os.listdir(FIXTURES)):
            doc = json.load(open(os.path.join(FIXTURES, fn)))
            self.assertEqual(schema_validate(doc, SCHEMA), [], fn)
        doc = json.load(open(os.path.join(FIXTURES, "unowned-binary-hash-only.json")))
        doc["assessment"]["integrity_status"]["value"] = "VERIFIED_INTACT"
        self.assertTrue(schema_validate(doc, SCHEMA))
        doc = json.load(open(os.path.join(FIXTURES, "unowned-binary-hash-only.json")))
        doc["assessment"]["content_origin"]["value"] = "SAFE"
        self.assertTrue(schema_validate(doc, SCHEMA))


class HomebrewFormulaTests(TmpCase):
    def keg(self, receipt=None, name="jq", ver="1.8.2", files=None, raw_receipt=None):
        base = os.path.join(self.d, "prefix", "Cellar", name, ver)
        os.makedirs(os.path.join(base, "bin"))
        for rel, data in (files or {"COPYING": b"license text\n"}).items():
            p = os.path.join(base, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
        if raw_receipt is not None:
            open(os.path.join(base, "INSTALL_RECEIPT.json"), "wb").write(raw_receipt)
        elif receipt is not None:
            json.dump(receipt, open(os.path.join(base, "INSTALL_RECEIPT.json"), "w"))
        return base

    RECEIPT = {"homebrew_version": "6.0.2", "poured_from_bottle": True, "built_as_bottle": True, "installed_on_request": True, "time": 1784195541, "arch": "x86_64",
               "changed_files": ["lib/pkgconfig/libjq.pc"], "source": {"tap": "homebrew/core", "tap_git_head": None, "versions": {"stable": "1.8.2"}}}

    def test_receipt_gives_ownership_install_and_a_declared_origin_but_no_integrity_reference(self):
        k = self.keg(self.RECEIPT)
        doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "installation_method")["value"], "THIRD_PARTY_PACKAGE_MANAGER")
        self.assertEqual(A(doc, "installation_method")["manager"], "brew")
        self.assertEqual(A(doc, "installation_method")["installed_at"], "2026-07-16T09:52:21Z")
        self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("REGISTERED_REPOSITORY", "DECLARED_BY_MANAGER"))
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertEqual(doc["history"][0]["change"], "PACKAGE_INSTALLED")
        self.assertTrue([e for e in doc["evidence"] if e["kind"] == "PATH_LOCATION" and "supports" not in e])

    def test_a_cellar_path_without_a_receipt_proves_nothing(self):
        k = self.keg(None)
        doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "content_origin")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "installation_method")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "UNKNOWN")
        self.assertTrue([e for e in doc["evidence"] if e["kind"] == "MANAGER_INSTALL_RECEIPT" and not e["present"]])

    def test_a_directory_named_cellar_that_is_not_a_cellar_layout_is_ignored(self):
        p = self.mk("x/Cellar/foo.txt")
        doc = run_assess(p, mac_base(), os_family="macos")
        self.assertEqual(A(doc, "package_ownership")["value"], "NOT_OWNED")
        self.assertFalse([e for e in doc["evidence"] if e["kind"] == "PATH_LOCATION"])

    def test_unreadable_hostile_or_oversized_receipts_are_not_trusted(self):
        for label, raw in (("garbage", b"{not json"), ("array", b"[1,2,3]"), ("deep", b"[" * 200000 + b"]" * 200000), ("huge", b'{"a":"' + b"x" * (5 * 1024 * 1024) + b'"}')):
            with self.subTest(label):
                shutil.rmtree(os.path.join(self.d, "prefix"), True)
                k = self.keg(raw_receipt=raw)
                doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
                self.assertEqual(A(doc, "package_ownership")["value"], "UNKNOWN", label)

    def test_a_receipt_that_is_a_symlink_is_not_followed(self):
        k = self.keg(None)
        real = self.mk("elsewhere.json", json.dumps(self.RECEIPT))
        os.symlink(real, os.path.join(k, "INSTALL_RECEIPT.json"))
        doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
        self.assertEqual(A(doc, "package_ownership")["value"], "UNKNOWN")

    def test_third_party_tap_and_source_builds_are_not_called_official(self):
        r = json.loads(json.dumps(self.RECEIPT))
        r["source"]["tap"] = "someone/tools"
        k = self.keg(r)
        doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
        self.assertEqual(A(doc, "content_origin")["value"], "THIRD_PARTY_REPOSITORY")
        shutil.rmtree(os.path.join(self.d, "prefix"))
        r["source"]["tap"] = "homebrew/core"
        r["poured_from_bottle"] = False
        r["built_as_bottle"] = False
        k = self.keg(r)
        self.assertEqual(A(run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos"), "content_origin")["value"], "LOCAL_BUILD")

    def test_receipt_version_that_disagrees_with_the_keg_directory_is_a_contradiction(self):
        r = json.loads(json.dumps(self.RECEIPT))
        r["source"]["versions"]["stable"] = "9.9.9"
        k = self.keg(r)
        doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
        self.assertTrue(A(doc, "provenance_confidence")["contradicted"])
        self.assertIn("CAP-OWNER-VERSION-MISMATCH", A(doc, "provenance_confidence")["cap_rule_ids"])
        self.check_schema(doc)

    def test_revision_suffix_in_the_directory_is_not_a_mismatch(self):
        k = self.keg(self.RECEIPT, ver="1.8.2_1")
        doc = run_assess(os.path.join(k, "COPYING"), mac_base(), os_family="macos")
        self.assertFalse(A(doc, "provenance_confidence")["contradicted"])

    def test_same_named_package_but_the_file_was_modified_signature_mismatch(self):
        """A keg with a receipt owns the path, yet a failing signature makes the file MODIFIED and caps confidence."""
        k = self.keg(self.RECEIPT, files={"bin/jq": b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 64})
        fake = mac_base()
        fake.on("/usr/bin/codesign", "-dv", rc=0, err="Executable=x\nIdentifier=jq-abc\nFormat=Mach-O thin (x86_64)\nCodeDirectory v=20400 size=452 flags=0x2(adhoc) hashes=8+2 location=embedded\nSignature=adhoc\n")
        fake.on("/usr/bin/codesign", "--verify", rc=1, err="x: main executable failed strict validation")
        doc = run_assess(os.path.join(k, "bin", "jq"), fake, os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
        c = A(doc, "provenance_confidence")
        self.assertEqual(c["value"], "LOW")
        self.assertTrue(c["contradicted"])

    def test_ad_hoc_signature_valid_is_partial_not_intact(self):
        k = self.keg(self.RECEIPT, files={"bin/jq": b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 64})
        fake = mac_base()
        fake.on("/usr/bin/codesign", "-dv", rc=0, err="Identifier=jq-abc\nFormat=Mach-O thin (x86_64)\nCodeDirectory v=20400 size=452 flags=0x2(adhoc) hashes=8+2 location=embedded\n")
        fake.on("/usr/bin/codesign", "--verify", rc=0)
        doc = run_assess(os.path.join(k, "bin", "jq"), fake, os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED")
        self.assertTrue(A(doc, "integrity_status")["reference"]["reference_location_writable_by_attacker"])
        self.assertEqual(A(doc, "content_origin")["claim_basis"], "DECLARED_BY_MANAGER")      # an ad hoc signature names no signer


APP_DEV_ID = ("Executable=/x/Foo\nIdentifier=com.example.foo\nFormat=app bundle with Mach-O universal (x86_64 arm64)\nCodeDirectory v=20500 size=366689 flags=0x10000(runtime) hashes=11448+7 location=embedded\n"
              "Authority=Developer ID Application: EXAMPLE SOFTWARE LTD (AAAAAAAAAA)\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\n"
              "Notarization Ticket=stapled\nTeamIdentifier=AAAAAAAAAA\n")


class CaskAndMacTests(TmpCase):
    def make_app(self, receipt=True, listed=True, version="1.0"):
        apps = os.path.join(self.d, "Applications")
        exe = os.path.join(apps, "Foo.app", "Contents", "MacOS", "Foo")
        os.makedirs(os.path.dirname(exe))
        open(exe, "wb").write(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 32)
        plistlib.dump({"CFBundleExecutable": "Foo", "CFBundleIdentifier": "com.example.foo", "CFBundleShortVersionString": version}, open(os.path.join(apps, "Foo.app", "Contents", "Info.plist"), "wb"))
        room = os.path.join(self.d, "prefix", "Caskroom", "foo")
        os.makedirs(os.path.join(room, version))
        os.symlink(os.path.join(apps, "Foo.app"), os.path.join(room, version, "Foo.app"))
        if receipt:
            os.makedirs(os.path.join(room, ".metadata"))
            json.dump({"homebrew_version": "6.0.11", "time": 1784193716, "source": {"tap": "homebrew/cask", "tap_git_head": "abc", "version": version},
                       "uninstall_artifacts": [{"app": ["Foo.app" if listed else "Other.app"]}]}, open(os.path.join(room, ".metadata", "INSTALL_RECEIPT.json"), "w"))
        return os.path.join(apps, "Foo.app")

    def signed_runner(self, valid=True, spctl_ok=True, chain_ok=True):
        f = mac_base()
        f.on("/usr/bin/codesign", "-dv", rc=0, err=APP_DEV_ID)
        f.on("/usr/bin/codesign", "--verify", rc=0 if valid else 1, err="" if valid else "a sealed resource is missing or invalid")
        if not chain_ok:
            f.on("/usr/bin/codesign", "--verify", "--strict", rc=1, err="requirement not satisfied") if False else None
        f.on("/usr/sbin/spctl", rc=0 if spctl_ok else 3, err="/x: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: EXAMPLE SOFTWARE LTD (AAAAAAAAAA)\n" if spctl_ok else "/x: rejected\nsource=Unnotarized Developer ID\n")
        return f

    def test_cask_app_with_developer_id_signature_and_notarization(self):
        app = self.make_app()
        doc = run_assess(app, self.signed_runner(), os_family="macos", brew_prefixes=[os.path.join(self.d, "prefix")])
        self.check_schema(doc)
        self.assertEqual(doc["subject"]["kind"], "application")
        self.assertEqual(doc["subject"]["application"]["team_id"], "AAAAAAAAAA")
        self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("VENDOR_DIRECT", "VERIFIED_BINDING"))
        self.assertEqual(A(doc, "installation_method")["manager"], "brew-cask")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["value"], "VERIFIED_INTACT")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "VERY_HIGH")
        self.assertEqual(doc["attestations"][0]["availability"], "AVAILABLE_VERIFIED")
        self.assertEqual(doc["ownership_chain"][-1]["resolution"], "RESOLVED")

    def test_cask_app_whose_signature_no_longer_verifies_is_modified_low_and_contradicted(self):
        app = self.make_app()
        doc = run_assess(app, self.signed_runner(valid=False), os_family="macos", brew_prefixes=[os.path.join(self.d, "prefix")])
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")             # the cask still names it
        self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertTrue(A(doc, "provenance_confidence")["contradicted"])

    def test_gatekeeper_rejection_next_to_a_valid_signature_is_a_contradiction_not_a_pass(self):
        app = self.make_app()
        doc = run_assess(app, self.signed_runner(spctl_ok=False), os_family="macos", brew_prefixes=[os.path.join(self.d, "prefix")])
        self.check_schema(doc)
        c = A(doc, "provenance_confidence")
        self.assertTrue(c["contradicted"])
        self.assertLessEqual(LEVELS.index(c["value"]), 2)
        self.assertEqual(doc["attestations"][0]["availability"], "VERIFICATION_FAILED")

    def test_caskroom_link_without_a_listing_receipt_is_not_ownership(self):
        for kw in ({"receipt": False}, {"listed": False}):
            with self.subTest(kw):
                shutil.rmtree(self.d)
                os.makedirs(self.d)
                app = self.make_app(**kw)
                doc = run_assess(app, self.signed_runner(), os_family="macos", brew_prefixes=[os.path.join(self.d, "prefix")])
                self.assertEqual(A(doc, "package_ownership")["value"], "UNKNOWN")
                self.assertNotEqual(A(doc, "installation_method")["value"], "THIRD_PARTY_PACKAGE_MANAGER")

    def test_same_named_cask_in_the_catalog_but_app_not_installed_by_it(self):
        """A Caskroom exists and a cask named foo exists, but nothing links to this bundle: ownership is NOT_OWNED, never the cask."""
        app = self.make_app()
        os.unlink(os.path.join(self.d, "prefix", "Caskroom", "foo", "1.0", "Foo.app"))
        doc = run_assess(app, self.signed_runner(), os_family="macos", brew_prefixes=[os.path.join(self.d, "prefix")])
        self.assertEqual(A(doc, "package_ownership")["value"], "NOT_OWNED")
        self.assertEqual(A(doc, "installation_method")["value"], "UNKNOWN")

    def test_unsigned_mach_o_has_no_signature_to_compare(self):
        p = self.mk("tool", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 64)
        f = mac_base().on("/usr/bin/codesign", "-dv", rc=1, err="tool: code object is not signed at all").on("/usr/bin/codesign", "--verify", rc=1, err="tool: code object is not signed at all")
        doc = run_assess(p, f, os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        self.assertEqual(doc["subject"]["file"]["code_signature_summary"], {"present": False, "kind": "NONE"})

    def test_codesign_timeout_is_unknown_not_a_pass(self):
        p = self.mk("tool", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 64)
        f = mac_base().on("/usr/bin/codesign", rc=124, timed_out=True)
        doc = run_assess(p, f, os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "integrity_status")["value"], "UNKNOWN")

    def test_pkgutil_owner_gives_pkg_installer_and_metadata_only_reference(self):
        p = self.mk("usr/local/bin/foo", b"#!/bin/sh\n", mode=0o755)
        out = "volume: /\npath: x\n\npkgid: com.example.pkg.Tools\npkg-version: 3.1\ninstall-time: 1791589539\nuid: 501\ngid: 20\nmode: 100755\n"
        f = mac_base().on("/usr/sbin/pkgutil", "--file-info", out=out).on("/usr/sbin/pkgutil", "--pkg-info", out="package-id: com.example.pkg.Tools\nlocation: /\n")
        doc = run_assess(p, f, os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "installation_method")["value"], "PKG_INSTALLER")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["reference"]["kind"], "PACKAGE_DB_METADATA_ONLY")
        self.assertIn(A(doc, "integrity_status")["value"], ("PARTIALLY_VERIFIED",))               # metadata only: never intact
        self.assertEqual(A(doc, "provenance_confidence")["value"], "MEDIUM")                      # one system-authoritative record, no content reference
        self.assertEqual(doc["history"][0]["known_via"], "MANAGER_HISTORY_DB")

    def test_pkgutil_failure_is_not_owned_never(self):
        p = self.mk("a.bin")
        doc = run_assess(p, Fake().on("/usr/bin/xattr", "-s", out="").on("/usr/sbin/pkgutil", rc=1, err="boom"), os_family="macos")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNERSHIP_NOT_QUERYABLE")
        self.assertEqual(A(doc, "package_ownership")["unqueryable_managers"], ["pkgutil"])

    def test_sealed_system_path_with_no_receipt_is_unknown_not_not_owned(self):
        f = macos_mod.collect_pkgutil.__globals__["_is_sealed"]
        self.assertTrue(f("/bin/ls") and f("/usr/bin/git") and f("/System/Library/x") and not f("/usr/local/bin/x") and not f(self.d + "/x"))

    def quarantine_runner(self, with_wherefroms=True):
        q = b"0083;5f5e1000;Safari;12345678-1234-1234-1234-123456789ABC"
        w = plistlib.dumps(["https://downloads.example.com/app.dmg?token=SECRET123&x=1", "https://example.com/page?utm=zzz"], fmt=plistlib.FMT_BINARY)
        names = "com.apple.quarantine\ncom.apple.provenance\n" + ("com.apple.metadata:kMDItemWhereFroms\n" if with_wherefroms else "")
        f = mac_base().on("/usr/bin/xattr", "-s", out=names)
        f.on("/usr/bin/xattr", "-s", "-px", "com.apple.quarantine", out=hexdump(q))
        f.on("/usr/bin/xattr", "-s", "-px", "com.apple.metadata:kMDItemWhereFroms", out=hexdump(w))
        return f

    def test_quarantine_and_wherefroms_are_recorded_as_writable_low_trust_declarations(self):
        p = self.mk("dl/tool.bin")
        doc = run_assess(p, self.quarantine_runner(), os_family="macos")
        self.check_schema(doc)
        self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("USER_DOWNLOAD_RECORDED", "DECLARED_BY_WRITABLE_METADATA"))
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertEqual(A(doc, "provenance_confidence")["independent_sources"], 1)                # quarantine + WhereFroms share one writer
        self.assertEqual(A(doc, "installation_method")["value"], "MANUAL_COPY")
        q = ev_by_kind(doc, "QUARANTINE_XATTR")[0]
        self.assertEqual(q["trust"], "WRITABLE_METADATA")
        self.assertIn("Any process of the user can write or delete", q["summary"])
        self.assertEqual(A(doc, "content_origin")["source"]["url_host"], "downloads.example.com")

    def test_urls_lose_query_strings_by_default_and_redact_removes_everything_sensitive(self):
        p = self.mk("dl/tool.bin")
        doc = run_assess(p, self.quarantine_runner(), os_family="macos")
        default = json.dumps(doc)
        self.assertNotIn("SECRET123", default)
        self.assertNotIn("token=", default)
        self.assertIn("https://downloads.example.com/app.dmg", default)
        red_doc = run_assess(p, self.quarantine_runner(), os_family="macos", redact=True)
        red = json.dumps(red_doc)
        self.assertNotIn("downloads.example.com", red)
        self.assertNotIn("Safari", red)
        self.assertNotIn("12345678-1234", red)
        self.assertIn("sensitive details removed", red)
        self.assertNotIn("12345678-1234", default)                                                 # the event id is never recorded
        self.assertNotIn("_sensitive", default)
        self.check_schema(red_doc)

    def test_quarantine_forged_on_a_binary_with_a_real_apple_signature_does_not_override_it(self):
        p = self.mk("fake-ls", b"\xca\xfe\xba\xbe\x00\x00\x00\x01" + b"\x00" * 64)
        f = self.quarantine_runner(False)
        f.on("/usr/bin/codesign", "-dv", rc=0, err="Identifier=com.apple.ls\nFormat=Mach-O universal\nPlatform identifier=16\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\n")
        f.on("/usr/bin/codesign", "--verify", rc=0)
        doc = run_assess(p, f, os_family="macos")
        self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("OS_VENDOR", "VERIFIED_BINDING"))
        self.assertIn("USER_DOWNLOAD_RECORDED", " ".join(A(doc, "content_origin")["reasons"]))

    def test_stripped_quarantine_gives_no_inference_of_a_package_or_origin(self):
        p = self.mk("Downloads/tool.bin")
        doc = run_assess(p, mac_base(), os_family="macos")
        self.assertEqual(A(doc, "content_origin")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "installation_method")["value"], "UNKNOWN")
        self.assertNotEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertIn("no com.apple.quarantine", " ".join(A(doc, "content_origin")["missing"]))

    def test_xattr_failure_is_not_the_same_as_no_xattr(self):
        p = self.mk("a.bin")
        f = Fake().on("/usr/sbin/pkgutil", "--file-info", out="volume: /\npath: x\n").on("/usr/bin/xattr", rc=1, err="denied")
        doc = run_assess(p, f, os_family="macos")
        self.assertTrue([e for e in doc["evidence"] if e["kind"] == "QUARANTINE_XATTR" and "not obtainable" in e["summary"]])
        self.assertEqual(A(doc, "integrity_status")["value"], "UNKNOWN")

    def test_malformed_wherefroms_and_quarantine_do_not_crash(self):
        p = self.mk("a.bin")
        f = mac_base().on("/usr/bin/xattr", "-s", out="com.apple.quarantine\ncom.apple.metadata:kMDItemWhereFroms\n")
        f.on("/usr/bin/xattr", "-s", "-px", "com.apple.quarantine", out=hexdump(b"garbage"))
        f.on("/usr/bin/xattr", "-s", "-px", "com.apple.metadata:kMDItemWhereFroms", out=hexdump(b"not a plist"))
        doc = run_assess(p, f, os_family="macos")
        self.check_schema(doc)
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")


class PipTests(TmpCase):
    def site(self, entries, files=None, installer="pip", direct_url=None, name="demo", version="1.0"):
        site = os.path.join(self.d, "venv", "lib", "python3.9", "site-packages")
        dist = os.path.join(site, f"{name}-{version}.dist-info")
        os.makedirs(dist)
        for rel, data in (files or {}).items():
            p = os.path.join(site, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
        open(os.path.join(dist, "RECORD"), "w").write("".join(f"{a},{b},{c}\n" for a, b, c in entries))
        open(os.path.join(dist, "METADATA"), "w").write(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nbody\n")
        if installer:
            open(os.path.join(dist, "INSTALLER"), "w").write(installer + "\n")
        if direct_url:
            open(os.path.join(dist, "direct_url.json"), "w").write(json.dumps(direct_url))
        return site

    @staticmethod
    def rec(data):
        return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()

    def test_record_hash_match_is_partial_integrity_and_low_confidence_with_no_origin(self):
        data = b"print('hi')\n"
        site = self.site([("demo/mod.py", self.rec(data), str(len(data)))], {"demo/mod.py": data})
        doc = run_assess(os.path.join(site, "demo", "mod.py"), Fake(), os_family="linux")
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "installation_method")["value"], "LANGUAGE_PACKAGE_MANAGER")
        self.assertEqual(A(doc, "installation_method")["manager"], "pip")
        self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED")
        self.assertEqual(A(doc, "integrity_status")["reference"]["kind"], "RECORD_FILE_HASH")
        self.assertEqual(A(doc, "content_origin")["value"], "UNKNOWN")                             # a plain pip install records no index
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")

    def test_record_mismatch_is_modified_but_explained_as_an_installer_record_and_confidence_not_zero(self):
        data = b"print('hi')\n"
        site = self.site([("demo/mod.py", self.rec(b"original\n"), "9")], {"demo/mod.py": data})
        doc = run_assess(os.path.join(site, "demo", "mod.py"), Fake(), os_family="linux")
        self.check_schema(doc)
        self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
        self.assertIn("installer", " ".join(A(doc, "integrity_status")["reasons"]))
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertTrue(A(doc, "provenance_confidence")["contradicted"])
        self.assertIn("CAP-RECORD-HASH-MISMATCH", A(doc, "provenance_confidence")["cap_rule_ids"])
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")

    def test_entry_without_hash_gives_ownership_and_no_integrity_reference(self):
        site = self.site([("demo/__init__.py", "", "")], {"demo/__init__.py": b"x\n"})
        doc = run_assess(os.path.join(site, "demo", "__init__.py"), Fake(), os_family="linux")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")

    def test_file_not_listed_anywhere_is_not_owned_by_pip_and_pyc_is_the_usual_case(self):
        site = self.site([("demo/mod.py", "", "")], {"demo/mod.py": b"x\n", "demo/__pycache__/mod.cpython-39.pyc": b"\x00pyc"})
        doc = run_assess(os.path.join(site, "demo", "__pycache__", "mod.cpython-39.pyc"), Fake(), os_family="linux")
        self.assertEqual(A(doc, "package_ownership")["value"], "NOT_OWNED")
        self.assertEqual(A(doc, "package_ownership")["queried_managers"], ["pip"])

    def test_console_script_in_bin_is_found_through_record(self):
        data = b"#!/usr/bin/python\n"
        site = self.site([("../../../bin/demo-cli", self.rec(data), str(len(data)))], {})
        bindir = os.path.join(self.d, "venv", "bin")
        os.makedirs(bindir)
        open(os.path.join(bindir, "demo-cli"), "wb").write(data)
        doc = run_assess(os.path.join(bindir, "demo-cli"), Fake(), os_family="linux")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED")

    def test_direct_url_declares_a_writable_origin_and_secrets_in_the_url_are_dropped(self):
        data = b"x = 1\n"
        site = self.site([("demo/a.py", self.rec(data), "6")], {"demo/a.py": data},
                         direct_url={"url": "https://user:pw@git.example.org/org/demo.git?token=ABC", "vcs_info": {"vcs": "git", "commit_id": "deadbeef"}})
        doc = run_assess(os.path.join(site, "demo", "a.py"), Fake(), os_family="linux")
        self.check_schema(doc)
        self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("THIRD_PARTY_REPOSITORY", "DECLARED_BY_WRITABLE_METADATA"))
        out = json.dumps(doc)
        for leak in ("user:pw", "ABC", "token="):
            self.assertNotIn(leak, out)
        self.assertEqual(A(doc, "content_origin")["source"]["url_host"], "git.example.org")
        self.assertNotIn("git.example.org", json.dumps(run_assess(os.path.join(site, "demo", "a.py"), Fake(), os_family="linux", redact=True)))

    def test_local_directory_install_is_a_local_build_claim(self):
        data = b"x = 1\n"
        site = self.site([("demo/a.py", self.rec(data), "6")], {"demo/a.py": data}, direct_url={"url": "file:///src/demo", "dir_info": {"editable": True}})
        doc = run_assess(os.path.join(site, "demo", "a.py"), Fake(), os_family="linux")
        self.assertEqual(A(doc, "content_origin")["value"], "LOCAL_BUILD")

    def test_hostile_record_cannot_make_the_engine_read_outside_and_oversized_record_is_skipped(self):
        outside = self.mk("outside-secret.txt", b"TOP SECRET")
        data = b"x\n"
        site = self.site([("../../../../../outside-secret.txt", self.rec(b"TOP SECRET"), "10"), ("demo/a.py", self.rec(data), "2")], {"demo/a.py": data})
        doc = run_assess(os.path.join(site, "demo", "a.py"), Fake(), os_family="linux")
        self.assertNotIn("TOP SECRET", json.dumps(doc))
        self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED")
        big = os.path.join(site, "huge-1.0.dist-info")
        os.makedirs(big)
        open(os.path.join(big, "RECORD"), "wb").write(b"a,,\n" * (5 * 1024 * 1024))                # 20 MB > cap: skipped, not parsed
        doc = run_assess(os.path.join(site, "demo", "a.py"), Fake(), os_family="linux")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")

    def test_missing_installer_file_is_recorded_as_a_gap(self):
        data = b"x\n"
        site = self.site([("demo/a.py", self.rec(data), "2")], {"demo/a.py": data}, installer=None)
        doc = run_assess(os.path.join(site, "demo", "a.py"), Fake(), os_family="linux")
        self.assertIn("INSTALLER file missing", " ".join(A(doc, "installation_method")["missing"]))

    def test_record_digest_helper(self):
        h = hashlib.sha256(b"abc").hexdigest()
        self.assertTrue(pip_mod.record_digest_matches(self.rec(b"abc"), h, None))
        self.assertFalse(pip_mod.record_digest_matches(self.rec(b"abd"), h, None))
        self.assertIsNone(pip_mod.record_digest_matches("md5=AAAA", h, None))
        self.assertFalse(pip_mod.record_digest_matches("sha256=!!!", h, None))


class DpkgFixtureTests(TmpCase):
    """Recorded dpkg formats (dpkg-query -S, md5sums, status, history.log). The real-host run is PENDING: see RealLinuxDpkgPending."""

    def tree(self, content=b"#!/bin/sh\necho tool\n", md5_override=None, with_md5=True, pkg="tool", arch=None, conffile=False):
        root = os.path.join(self.d, "root")
        f = os.path.join(root, "usr", "bin", "tool")
        os.makedirs(os.path.dirname(f))
        open(f, "wb").write(content)
        info = os.path.join(root, "var", "lib", "dpkg", "info")
        os.makedirs(info)
        name = pkg + (":" + arch if arch else "")
        if with_md5:
            m = md5_override or hashlib.md5(b"#!/bin/sh\necho tool\n").hexdigest()
            open(os.path.join(info, name + ".md5sums"), "w").write(f"{m}  usr/bin/tool\n")
        status = f"Package: {pkg}\nStatus: install ok installed\nArchitecture: {arch or 'amd64'}\nVersion: 1.2-3\nDescription: x\n"
        if conffile:
            status += "Conffiles:\n /usr/bin/tool " + (md5_override or hashlib.md5(b"#!/bin/sh\necho tool\n").hexdigest()) + "\n"
        open(os.path.join(root, "var", "lib", "dpkg", "status"), "w").write("Package: other\nStatus: install ok installed\nArchitecture: amd64\nVersion: 9\n\n" + status + "\n")
        os.makedirs(os.path.join(root, "var", "log", "apt"))
        open(os.path.join(root, "var", "log", "apt", "history.log"), "w").write(
            "Start-Date: 2026-05-01  10:00:00\nCommandline: apt install tool\nRequested-By: alice (1000)\nInstall: tool:amd64 (1.2-3)\nEnd-Date: 2026-05-01  10:00:05\n\n")
        os.makedirs(os.path.join(root, "etc"))
        open(os.path.join(root, "etc", "os-release"), "w").write('ID=debian\nVERSION_ID="12"\n')
        return root, f

    def runner(self, owner="tool: /usr/bin/tool\n", rc=0, err="", policy=True):
        r = Fake().on("/usr/bin/dpkg-query", "-S", rc=rc, out=owner, err=err)
        if policy:
            r.on("/usr/bin/apt-cache", "policy", out="tool:\n  Installed: 1.2-3\n  Candidate: 2.0-1\n  Version table:\n     2.0-1 500\n        500 http://deb.example/debian bookworm/main amd64 Packages\n *** 1.2-3 100\n        100 /var/lib/dpkg/status\n")
        return r

    def test_owned_file_md5_match_is_partial_weak_hash_medium_and_origin_unknown(self):
        root, f = self.tree()
        doc = run_assess(f, self.runner(), os_family="linux", root=root)
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "package_ownership")["queried_managers"], ["dpkg"])
        self.assertEqual(A(doc, "installation_method")["value"], "SYSTEM_PACKAGE_MANAGER")
        self.assertEqual(A(doc, "installation_method")["manager"], "dpkg")
        i = A(doc, "integrity_status")
        self.assertEqual((i["value"], i["reference"]["kind"], i["reference"]["strength"]), ("PARTIALLY_VERIFIED", "PACKAGE_DB_CHECKSUM", "WEAK_HASH"))
        self.assertTrue(i["reference"]["reference_location_writable_by_attacker"])
        self.assertEqual(A(doc, "content_origin")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "MEDIUM")
        self.assertEqual(doc["coverage"]["state"], "DESIGNED")
        self.assertIn("PENDING", " ".join(doc["coverage"]["limits"]))
        self.assertEqual(doc["host"]["distro_id"], "debian")
        self.assertEqual(doc["history"][0]["known_via"], "PACKAGE_MANAGER_LOG")
        self.assertNotIn("alice", json.dumps(doc))                                                  # Requested-By is a person's name: not recorded
        self.assertEqual(doc["subject"]["file"]["file_type"], "script")

    def test_modified_file_at_an_owned_path_is_modified_contradicted_and_low(self):
        root, f = self.tree(md5_override="0" * 32)
        doc = run_assess(f, self.runner(), os_family="linux", root=root)
        self.check_schema(doc)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertTrue(A(doc, "provenance_confidence")["contradicted"])

    def test_apt_policy_today_is_a_name_collision_note_and_changes_nothing(self):
        root, f = self.tree()
        with_policy = run_assess(f, self.runner(policy=True), os_family="linux", root=root, nonce="a" * 16)
        without = run_assess(f, self.runner(policy=False), os_family="linux", root=root, nonce="a" * 16)
        self.assertTrue(ev_by_kind(with_policy, "NAME_COLLISION_NOTE"))
        self.assertEqual(with_policy["assessment"], without["assessment"])
        self.assertNotIn("deb.example", json.dumps(with_policy))

    def test_no_md5sums_file_means_no_reference(self):
        root, f = self.tree(with_md5=False)
        doc = run_assess(f, self.runner(), os_family="linux", root=root)
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")

    def test_conffile_uses_the_status_hash(self):
        root, f = self.tree(with_md5=False, conffile=True)
        doc = run_assess(f, self.runner(), os_family="linux", root=root)
        self.assertEqual(A(doc, "integrity_status")["reference"]["kind"], "PACKAGE_DB_CHECKSUM")
        self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED")

    def test_multiarch_package_reference_and_usr_merge_alias(self):
        root, f = self.tree(pkg="tool", arch="amd64")
        r = Fake().on("/usr/bin/dpkg-query", "-S", rc=1, err="dpkg-query: no path found matching pattern x")
        r.on("/usr/bin/dpkg-query", "-S", "/bin/tool", out="tool:amd64: /bin/tool\n")           # the DB lists the pre-merge path; the file sits at /usr/bin/tool
        doc = run_assess(f, r, os_family="linux", root=root)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(doc["ownership_chain"][1]["arch"], "amd64")

    def test_no_package_lists_the_path_is_not_owned_only_when_the_database_was_read(self):
        root, f = self.tree()
        r = Fake().on("/usr/bin/dpkg-query", "-S", rc=1, err="dpkg-query: no path found matching pattern /usr/bin/tool")
        doc = run_assess(f, r, os_family="linux", root=root)
        self.assertEqual(A(doc, "package_ownership")["value"], "NOT_OWNED")
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "UNKNOWN")
        self.check_schema(doc)

    def test_database_errors_are_not_queryable_never_not_owned(self):
        root, f = self.tree()
        for r in (Fake().on("/usr/bin/dpkg-query", "-S", rc=2, err="dpkg-query: error: cannot read"), Fake().on("/usr/bin/dpkg-query", "-S", rc=124, timed_out=True), Fake()):
            doc = run_assess(f, r, os_family="linux", root=root)
            self.assertEqual(A(doc, "package_ownership")["value"], "OWNERSHIP_NOT_QUERYABLE")
            self.assertEqual(A(doc, "package_ownership")["unqueryable_managers"], ["dpkg"])

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "root can read everything")
    def test_unreadable_status_file_is_not_queryable(self):
        root, f = self.tree()
        st = os.path.join(root, "var", "lib", "dpkg", "status")
        os.chmod(st, 0)
        self.addCleanup(os.chmod, st, 0o600)
        doc = run_assess(f, self.runner("tool: /usr/bin/tool\n"), os_family="linux", root=root)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNERSHIP_NOT_QUERYABLE")

    def test_glob_characters_in_the_path_are_escaped_for_dpkg_query(self):
        self.assertEqual(dpkg_mod.glob_escape("/usr/bin/a*b?[c]\\d"), "/usr/bin/a\\*b\\?\\[c]\\\\d")
        self.assertEqual(dpkg_mod.alt_paths("/bin/ls"), ["/bin/ls", "/usr/bin/ls"])
        self.assertEqual(dpkg_mod.parse_search("diversion by dash from: /bin/sh\ndash: /bin/sh\n", ["/bin/sh"]), (["dash"], ["diversion by dash from"]))
        self.assertEqual(dpkg_mod.parse_search("libc6:amd64, libc6-dev:amd64: /usr/lib/x\nother: /usr/lib/xy\n", ["/usr/lib/x"]), (["libc6:amd64", "libc6-dev:amd64"], []))

    def test_dpkg_collector_is_not_applicable_without_a_dpkg_database_or_on_macos(self):
        p = self.mk("a.bin")
        doc = run_assess(p, Fake(), os_family="linux", root=self.d)
        self.assertEqual(A(doc, "package_ownership")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")


class ManualFileTests(TmpCase):
    def test_plain_file_is_hash_only_with_everything_else_unknown(self):
        p = self.mk("manual.bin", b"\x7fELF" + b"\x00" * 60)
        doc = run_assess(p, mac_base(), os_family="macos")
        self.check_schema(doc)
        self.assertEqual(doc["subject"]["file"]["hashes"]["sha256"], hashlib.sha256(slurp(p)).hexdigest())
        self.assertEqual(doc["subject"]["file"]["hashes"]["sha512"], hashlib.sha512(slurp(p)).hexdigest())
        self.assertEqual(doc["subject"]["file"]["file_type"], "elf")
        self.assertEqual(A(doc, "content_origin")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "installation_method")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "detection_status")["value"], "NOT_SCANNED")
        self.assertTrue(A(doc, "content_origin")["missing"])
        self.assertEqual(doc["coverage"]["manager_or_method"], "manual-unowned")
        self.assertEqual(doc["coverage"]["historical_reconstruction"], "NONE")
        self.assertFalse(doc["history"])
        self.assertFalse(doc["engine"]["network_used"])
        self.assertIn("never", render.render_text(doc).lower() + "never")                         # text renders without error

    def test_unknown_is_never_rendered_as_safe(self):
        p = self.mk("m.bin")
        text = render.render_text(run_assess(p, mac_base(), os_family="macos"))
        facts = [ln for ln in text.splitlines() if re.match(r"^  [A-Z]+_[A-Z_]+ ", ln)]
        self.assertEqual(len(facts), 6)
        for ln in facts:
            for word in ("SAFE", "TRUSTED", "CLEAN", "OK"):
                self.assertNotIn(word, ln.split())
        self.assertIn("never 'safe'", text)

    def test_unsupported_os_family_raises_unavailable(self):
        p = self.mk("m.bin")
        with self.assertRaises(engine.Unavailable):
            run_assess(p, Fake(), os_family="other")


# ======================================================================================================================
# (c) negative tests: paths, symlinks, FIFO, TOCTOU, no network, no writes
# ======================================================================================================================
class PathAndSafetyTests(TmpCase):
    def test_bad_paths_are_rejected(self):
        for bad in ("", "   ", "a\x00b", "x" * 5000, os.path.join(self.d, "missing")):
            with self.assertRaises(fileid.PathError, msg=repr(bad)[:30]):
                run_assess(bad, mac_base(), os_family="macos")

    def test_directories_and_fifos_and_non_app_bundles_are_refused(self):
        with self.assertRaises(fileid.PathError):
            run_assess(self.d, mac_base(), os_family="macos")
        fifo = os.path.join(self.d, "pipe")
        os.mkfifo(fifo)
        with self.assertRaises(fileid.PathError):
            run_assess(fifo, mac_base(), os_family="macos")
        os.makedirs(os.path.join(self.d, "Foo.app"))
        with self.assertRaises(fileid.PathError):                                                  # an .app with no main executable
            run_assess(os.path.join(self.d, "Foo.app"), mac_base(), os_family="macos")

    def test_symlink_is_refused_by_default_and_both_paths_are_recorded_when_followed(self):
        target = self.mk("real/target.bin", b"payload")
        link = os.path.join(self.d, "link")
        os.symlink(target, link)
        with self.assertRaises(fileid.PathError) as cm:
            run_assess(link, mac_base(), os_family="macos")
        self.assertIn("symbolic link", str(cm.exception))
        doc = run_assess(link, mac_base(), os_family="macos", follow_symlinks=True)
        f = doc["subject"]["file"]
        self.assertTrue(f["path_was_symlink"])
        self.assertEqual(f["path"], link)
        self.assertEqual(f["resolved_path"], target)
        self.assertEqual(f["hashes"]["sha256"], hashlib.sha256(b"payload").hexdigest())
        self.check_schema(doc)

    def test_dangling_symlink_even_when_followed_is_refused(self):
        link = os.path.join(self.d, "dangling")
        os.symlink(os.path.join(self.d, "nope"), link)
        with self.assertRaises(fileid.PathError):
            run_assess(link, mac_base(), os_family="macos", follow_symlinks=True)

    def test_path_tricks_are_normalised_not_trusted(self):
        p = self.mk("a/b/file.bin", b"zz")
        tricky = os.path.join(self.d, "a", "c", "..", "b", ".", "file.bin")
        doc = run_assess(tricky, mac_base(), os_family="macos")
        self.assertEqual(doc["subject"]["file"]["path"], p)
        spaced = self.mk("odd dir/na me\n$(touch pwned)`id`;.bin", b"q")
        run_assess(spaced, mac_base(), os_family="macos")
        self.assertFalse(os.path.exists(os.path.join(self.d, "pwned")))
        self.assertFalse(os.path.exists("pwned"))

    def test_symlinked_parent_directories_and_dotdot_are_resolved_physically_and_both_paths_are_recorded(self):
        real = self.mk("real/dir/f.bin", b"abc")
        os.symlink(os.path.join(self.d, "real"), os.path.join(self.d, "alias"))
        doc = run_assess(os.path.join(self.d, "alias", "dir", "f.bin"), mac_base(), os_family="macos")
        f = doc["subject"]["file"]
        self.assertFalse(f["path_was_symlink"])                                                      # the file itself is not a link
        self.assertEqual((f["path"], f["resolved_path"]), (os.path.join(self.d, "alias", "dir", "f.bin"), real))
        os.makedirs(os.path.join(self.d, "deep", "sub"))
        x = self.mk("deep/x.bin", b"x")
        os.makedirs(os.path.join(self.d, "links"))
        os.symlink(os.path.join(self.d, "deep", "sub"), os.path.join(self.d, "links", "to_deep"))
        doc = run_assess(os.path.join(self.d, "links", "to_deep", "..", "x.bin"), mac_base(), os_family="macos")     # the kernel's '..', not the textual one
        self.assertEqual(doc["subject"]["file"]["hashes"]["sha256"], hashlib.sha256(b"x").hexdigest())
        self.assertEqual(doc["subject"]["file"]["resolved_path"], x)

    def test_a_path_that_looks_like_cellar_cannot_pass_through_a_symlinked_prefix(self):
        real = self.mk("elsewhere/data.txt", b"d")
        os.makedirs(os.path.join(self.d, "p", "Cellar", "x"))
        os.symlink(os.path.dirname(real), os.path.join(self.d, "p", "Cellar", "x", "1.0"))
        doc = run_assess(os.path.join(self.d, "p", "Cellar", "x", "1.0", "data.txt"), mac_base(), os_family="macos")
        self.assertEqual(A(doc, "package_ownership")["value"], "NOT_OWNED")                       # the keg directory is a link: not a keg

    def test_file_changed_during_hashing_is_flagged_and_gives_no_integrity_claim(self):
        p = self.mk("moving.bin", b"A" * (3 * 1024 * 1024))
        real_read = os.read
        state = {"n": 0}

        def sneaky(fd, n):
            state["n"] += 1
            if state["n"] in (3, 8):                                                                  # the 3rd read of each of the two attempts
                with open(p, "ab") as w:
                    w.write(b"B" * 1000)
            return real_read(fd, n)

        with mock.patch.object(fileid.os, "read", sneaky):
            ident = fileid.identify(p)
        self.assertFalse(ident["hashes"]["stable_during_read"])
        with mock.patch.object(fileid.os, "read", sneaky):
            state["n"] = 0
            doc = run_assess(p, mac_base(), os_family="macos")
        self.assertFalse(doc["subject"]["file"]["hashes"]["stable_during_read"])
        self.assertEqual(A(doc, "integrity_status")["value"], "UNKNOWN")
        self.assertLessEqual(LEVELS.index(A(doc, "provenance_confidence")["value"]), 1)
        self.check_schema(doc)

    def test_a_change_during_the_first_attempt_only_is_retried_once_and_reports_the_final_bytes(self):
        p = self.mk("moving2.bin", b"A" * (3 * 1024 * 1024))
        real_read = os.read
        state = {"n": 0}

        def sneaky(fd, n):
            state["n"] += 1
            if state["n"] == 3:
                with open(p, "ab") as w:
                    w.write(b"B" * 10)
            return real_read(fd, n)

        with mock.patch.object(fileid.os, "read", sneaky):
            ident = fileid.identify(p)
        self.assertTrue(ident["hashes"]["stable_during_read"])
        self.assertEqual(ident["hashes"]["sha256"], hashlib.sha256(slurp(p)).hexdigest())

    def test_file_swapped_for_a_symlink_after_validation_is_not_followed(self):
        p = self.mk("swap.bin", b"real")
        secret = self.mk("secret.txt", b"SECRET")
        sub = fileid.validate(p)
        os.unlink(p)
        os.symlink(secret, p)
        with self.assertRaises(fileid.PathError):
            fileid.identify(sub.resolved)

    def test_hash_limit_is_enforced_and_nothing_is_claimed(self):
        p = self.mk("big.bin", b"x" * 5000)
        with self.assertRaises(fileid.PathError):
            fileid.identify(p, max_bytes=1000)

    def test_no_network_is_used(self):
        p = self.mk("n.bin")

        def boom(*a, **k):
            raise AssertionError("network access attempted")

        with mock.patch.object(socket.socket, "connect", boom), mock.patch.object(socket, "create_connection", boom), mock.patch.object(socket, "getaddrinfo", boom):
            doc = run_assess(p, mac_base(), os_family="macos")
        self.assertFalse(doc["engine"]["network_used"])
        self.assertFalse(any(e["source"].get("needs_network") for e in doc["evidence"]))

    def test_the_engine_writes_nothing(self):
        p = self.mk("w.bin")
        before = sorted((r, d, f) for r, d, f in os.walk(self.d))
        st = os.stat(p)
        run_assess(p, mac_base(), os_family="macos")
        self.assertEqual(sorted((r, d, f) for r, d, f in os.walk(self.d)), before)
        self.assertEqual((os.stat(p).st_mtime_ns, os.stat(p).st_size), (st.st_mtime_ns, st.st_size))

    def test_only_fixed_argument_vectors_without_a_shell_reach_the_runner(self):
        p = self.mk("evil; rm -rf ~ $(id).bin", b"z")
        fake = mac_base()
        run_assess(p, fake, os_family="macos")
        for argv in fake.calls:
            self.assertIsInstance(argv, list)
            self.assertTrue(argv[0].startswith("/"), argv)

    def test_a_collector_crash_becomes_a_gap_not_a_pass(self):
        p = self.mk("c.bin")
        def collect_xattrs(ctx):
            raise RuntimeError("boom")

        with mock.patch.object(engine, "MACOS_COLLECTORS", (engine.macos.collect_pkgutil, collect_xattrs)):
            doc = run_assess(p, mac_base(), os_family="macos")
        self.assertEqual(A(doc, "integrity_status")["value"], "UNKNOWN")
        self.assertTrue([e for e in doc["evidence"] if e["id"].startswith("ev-collector-error") and not e["present"]])
        self.check_schema(doc)

    def test_runner_enforces_timeout_output_cap_and_never_uses_a_shell(self):
        from intel.provenance.runner import system_runner
        r = system_runner(["/bin/sleep", "5"], timeout=1)
        self.assertTrue(r.timed_out)
        r = system_runner(["/usr/bin/yes"], timeout=1, max_out=1000)
        self.assertLessEqual(len(r.out), 1000)
        r = system_runner(["/bin/echo", "$(id);`id`"], timeout=5)
        self.assertEqual(r.out.strip(), "$(id);`id`")
        self.assertTrue(system_runner(["/definitely/not/here"], timeout=1).missing)
        self.assertTrue(system_runner(["nothing-called-this"], timeout=1).missing)


# ======================================================================================================================
# (d) REAL tests on this machine
# ======================================================================================================================
def brew_env():
    return dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")


def brew_out(*args):
    b = shutil.which("brew") or "/usr/local/bin/brew"
    if not os.path.exists(b):
        return None
    try:
        r = subprocess.run([b] + list(args), capture_output=True, text=True, timeout=120, env=brew_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def has_tool(path):
    return os.path.exists(path)


@unittest.skipUnless(DARWIN and has_tool("/usr/bin/codesign") and has_tool("/usr/sbin/pkgutil") and has_tool("/usr/bin/xattr"), "needs macOS and its signing/receipt tools")
class RealMacTests(TmpCase):
    def real(self, path, **kw):
        doc = engine.assess(path, **kw)
        self.assertEqual(schema_validate(doc, SCHEMA), [])
        self.assertEqual(doc["host"]["os_family"], "macos")
        return doc

    def test_real_homebrew_formula_file_ownership_from_the_receipt_and_no_integrity_reference(self):
        prefix = (brew_out("--prefix") or "").strip()
        formulas = (brew_out("list", "--formula") or "").split()
        if not prefix or not formulas:
            self.skipTest("Homebrew has no formulae here")
        chosen = None
        for name in formulas[:200]:
            opt = os.path.join(prefix, "opt", name)
            keg = os.path.realpath(opt)
            if os.path.isfile(os.path.join(keg, "INSTALL_RECEIPT.json")):
                for cand in ("COPYING", "LICENSE", "LICENSE.md", "README.md", "README", "COPYING.txt", "LICENSE.txt"):
                    if os.path.isfile(os.path.join(keg, cand)):
                        chosen = (name, os.path.join(keg, cand), keg)
                        break
            if chosen:
                break
        if not chosen:
            self.skipTest("no installed formula with a receipt and a plain top-level text file")
        name, path, keg = chosen
        doc = self.real(path)
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "installation_method")["manager"], "brew")
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")              # Homebrew keeps no per-file hash: UNKNOWN reference, never intact
        self.assertNotEqual(A(doc, "provenance_confidence")["value"], "VERY_HIGH")
        self.assertLessEqual(LEVELS.index(A(doc, "provenance_confidence")["value"]), 1)
        self.assertEqual(doc["ownership_chain"][1]["name"], os.path.basename(os.path.dirname(keg)))
        # independent oracle for the receipt: parse it here
        rec = json.load(open(os.path.join(keg, "INSTALL_RECEIPT.json")))
        self.assertEqual(A(doc, "content_origin")["source"].get("repository_id"), rec["source"].get("tap"))

    def test_real_homebrew_mach_o_has_an_ad_hoc_or_signed_reference_but_is_never_called_verified_by_the_bottle(self):
        prefix = (brew_out("--prefix") or "").strip()
        formulas = (brew_out("list", "--formula") or "").split()
        for name in formulas[:200]:
            keg = os.path.realpath(os.path.join(prefix, "opt", name))
            bindir = os.path.join(keg, "bin")
            if os.path.isfile(os.path.join(keg, "INSTALL_RECEIPT.json")) and os.path.isdir(bindir):
                for fn in sorted(os.listdir(bindir)):
                    p = os.path.join(bindir, fn)
                    if os.path.isfile(p) and not os.path.islink(p) and open(p, "rb").read(4) in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                        doc = self.real(p)
                        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
                        self.assertIn(doc["subject"]["file"]["code_signature_summary"]["present"], (True, False))
                        self.assertNotEqual(A(doc, "integrity_status")["reference"]["kind"], "UPSTREAM_ARTIFACT_COMPARISON")
                        if doc["subject"]["file"]["code_signature_summary"].get("kind") == "ADHOC":
                            self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED")
                        return
        self.skipTest("no Homebrew Mach-O executable found")

    def test_real_homebrew_symlink_needs_follow_and_records_both_paths(self):
        prefix = (brew_out("--prefix") or "").strip()
        bindir = os.path.join(prefix, "bin")
        link = None
        for fn in sorted(os.listdir(bindir)) if os.path.isdir(bindir) else []:
            p = os.path.join(bindir, fn)
            if os.path.islink(p) and "/Cellar/" in os.path.realpath(p) and os.path.isfile(os.path.realpath(p)):
                link = p
                break
        if not link:
            self.skipTest("no symlink from <prefix>/bin into a Cellar")
        with self.assertRaises(fileid.PathError):
            engine.assess(link)
        doc = self.real(link, follow_symlinks=True)
        f = doc["subject"]["file"]
        self.assertTrue(f["path_was_symlink"])
        self.assertEqual(f["path"], link)
        self.assertEqual(f["resolved_path"], os.path.realpath(link))
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")           # ownership comes from the keg receipt at the resolved path, not from the link

    def test_real_cask_installed_app(self):
        casks = (brew_out("list", "--cask") or "").split()
        prefix = (brew_out("--prefix") or "").strip()
        if not casks:
            self.skipTest("no cask installed")
        for tok in casks:
            room = os.path.join(prefix, "Caskroom", tok)
            for root, dirs, files in os.walk(room):
                depth = root[len(room):].count(os.sep)
                for e in list(dirs) + files:
                    p = os.path.join(root, e)
                    if e.endswith(".app") and os.path.islink(p) and os.path.isdir(os.path.realpath(p)) and depth <= 2:
                        app = os.path.realpath(p)
                        doc = self.real(app)
                        self.assertEqual(doc["subject"]["kind"], "application")
                        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
                        self.assertEqual(A(doc, "installation_method")["manager"], "brew-cask")
                        oracle = subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app], capture_output=True)
                        if oracle.returncode == 0:
                            self.assertIn(A(doc, "integrity_status")["value"], ("VERIFIED_INTACT", "PARTIALLY_VERIFIED"))
                        else:
                            self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
                        return
                dirs[:] = [d for d in dirs if not d.endswith(".app")][:5]
        self.skipTest("no cask with an installed .app link")

    def test_real_pip_installed_file_matches_an_independent_record_check(self):
        import sysconfig
        site = sysconfig.get_paths()["purelib"]
        picked = None
        for dist in sorted(os.listdir(site)):
            if not dist.endswith(".dist-info"):
                continue
            rp = os.path.join(site, dist, "RECORD")
            if not os.path.isfile(rp):
                continue
            for line in open(rp, encoding="utf-8", errors="replace"):
                parts = line.rstrip("\n").split(",")
                if len(parts) == 3 and parts[1].startswith("sha256=") and parts[0].endswith(".py") and ".." not in parts[0]:
                    f = os.path.join(site, parts[0])
                    if os.path.isfile(f) and not os.path.islink(f):
                        picked = (f, parts[1], dist)
                        break
            if picked:
                break
        if not picked:
            self.skipTest("no dist-info with a hashed .py entry in this interpreter's site-packages")
        f, spec, dist = picked
        doc = self.real(f)
        want = base64.urlsafe_b64decode(spec.split("=", 1)[1] + "==").hex()
        matches = want == hashlib.sha256(slurp(f)).hexdigest()
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")
        self.assertEqual(A(doc, "integrity_status")["value"], "PARTIALLY_VERIFIED" if matches else "MODIFIED")
        self.assertEqual(A(doc, "integrity_status")["reference"]["kind"], "RECORD_FILE_HASH")
        self.assertEqual(A(doc, "installation_method")["value"], "LANGUAGE_PACKAGE_MANAGER")
        self.assertLessEqual(LEVELS.index(A(doc, "provenance_confidence")["value"]), 1)
        self.assertEqual(A(doc, "provenance_confidence")["contradicted"], not matches)

    def test_real_apple_system_binary_ownership_is_unknown_and_says_why_origin_comes_from_the_apple_signature(self):
        doc = self.real("/bin/ls")
        o = A(doc, "package_ownership")
        self.assertEqual(o["value"], "UNKNOWN")                                                  # not in any pkgutil receipt: expected, and not NOT_OWNED
        self.assertIn("receipt", " ".join(o["reasons"]))
        oracle = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple", "/bin/ls"], capture_output=True)
        if oracle.returncode == 0:
            self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("OS_VENDOR", "VERIFIED_BINDING"))
            self.assertEqual(A(doc, "integrity_status")["value"], "VERIFIED_INTACT")
        self.assertEqual(A(doc, "installation_method")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "detection_status")["value"], "NOT_SCANNED")

    def test_real_file_with_a_quarantine_attribute_that_the_test_wrote_is_low_trust(self):
        p = self.mk("dl/tool.sh", b"#!/bin/sh\necho hi\n", 0o755)
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "0083;5f5e1000;Safari;12345678-1234-1234-1234-123456789ABC", p], check=True)
        doc = self.real(p)
        self.assertEqual((A(doc, "content_origin")["value"], A(doc, "content_origin")["claim_basis"]), ("USER_DOWNLOAD_RECORDED", "DECLARED_BY_WRITABLE_METADATA"))
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertIn("flags=0083", ev_by_kind(doc, "QUARANTINE_XATTR")[0]["summary"])
        self.assertIn("agent=Safari", json.dumps(doc))
        self.assertNotIn("Safari", json.dumps(engine.assess(p, redact=True)))
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        # the same bytes without the attribute: the claim disappears; the engine never inferred anything beyond it
        subprocess.run(["/usr/bin/xattr", "-d", "com.apple.quarantine", p], check=True)
        self.assertEqual(A(self.real(p), "content_origin")["value"], "UNKNOWN")

    def test_real_forged_whereFroms_and_quarantine_on_a_copy_of_an_apple_binary_do_not_change_its_signed_origin(self):
        p = os.path.join(self.d, "ls-copy")
        shutil.copy("/bin/ls", p)
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "0081;5f5e1000;Chrome;ABCDEF", p], check=True)
        doc = self.real(p)
        oracle = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple", p], capture_output=True)
        if oracle.returncode == 0:
            self.assertEqual(A(doc, "content_origin")["value"], "OS_VENDOR")
        with open(p, "ab") as f:                                                                   # now modify it: the Apple signature no longer verifies
            f.write(b"\x00")
        doc = self.real(p)
        self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "LOW")
        self.assertTrue(A(doc, "provenance_confidence")["contradicted"])

    def test_real_plain_temp_file_has_hash_only(self):
        p = self.mk("plain.txt", b"just a note\n")
        doc = self.real(p)
        self.assertEqual(doc["subject"]["file"]["hashes"]["sha256"], hashlib.sha256(b"just a note\n").hexdigest())
        for name in ("content_origin", "installation_method"):
            self.assertEqual(A(doc, name)["value"], "UNKNOWN")
        self.assertEqual(A(doc, "integrity_status")["value"], "NO_REFERENCE")
        self.assertEqual(A(doc, "provenance_confidence")["value"], "UNKNOWN")
        self.assertEqual(A(doc, "package_ownership")["value"], "NOT_OWNED")                       # pkgutil was read successfully; says nothing about other managers
        self.assertEqual(A(doc, "package_ownership")["queried_managers"], ["pkgutil"])

    def test_real_unsigned_and_modified_mach_o_copies(self):
        p = os.path.join(self.d, "true-copy")
        shutil.copy("/usr/bin/true", p)
        with open(p, "ab") as f:
            f.write(b"\x00")
        doc = self.real(p)
        self.assertEqual(A(doc, "integrity_status")["value"], "MODIFIED")
        self.assertEqual(doc["subject"]["file"]["code_signature_summary"]["kind"], "APPLE_PLATFORM")

    def test_real_run_does_not_touch_xattrs_or_mtime(self):
        p = self.mk("t.txt")
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "0083;5f5e1000;Safari;X", p], check=True)
        before = (subprocess.run(["/usr/bin/xattr", "-l", p], capture_output=True, text=True).stdout, os.stat(p).st_mtime_ns)
        self.real(p)
        after = (subprocess.run(["/usr/bin/xattr", "-l", p], capture_output=True, text=True).stdout, os.stat(p).st_mtime_ns)
        self.assertEqual(before, after)


@unittest.skipUnless(sys.platform.startswith("linux") and os.path.exists("/usr/bin/dpkg-query"), "PENDING: the dpkg collector has only been tested against recorded fixtures; run this on a real Debian/Ubuntu host")
class RealLinuxDpkgPending(unittest.TestCase):
    def test_real_dpkg_owned_binary(self):
        doc = engine.assess("/bin/ls")
        self.assertEqual(schema_validate(doc, SCHEMA), [])
        self.assertEqual(A(doc, "package_ownership")["value"], "OWNED_BY_PACKAGE")


# ======================================================================================================================
# (e) the CLI and mgctl
# ======================================================================================================================
def run_cli(args, cwd=None):
    r = subprocess.run([sys.executable, "-m", "intel"] + args, capture_output=True, text=True, cwd=cwd or ROOT, timeout=120)
    return r.returncode, r.stdout, r.stderr


class CliTests(TmpCase):
    def test_exit_codes_and_json_document(self):
        p = self.mk("x.bin")
        code, out, err = run_cli(["provenance", "file", p, "--json"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(schema_validate(doc, SCHEMA), [])
        self.assertEqual(doc["subject"]["file"]["hashes"]["sha256"], hashlib.sha256(slurp(p)).hexdigest())
        self.assertEqual(run_cli(["provenance", "file", os.path.join(self.d, "missing")])[0], 3)
        self.assertEqual(run_cli(["provenance", "file", self.d])[0], 3)
        link = os.path.join(self.d, "l")
        os.symlink(p, link)
        self.assertEqual(run_cli(["provenance", "file", link])[0], 3)
        self.assertEqual(run_cli(["provenance", "file", link, "--follow-symlinks", "--json"])[0], 0)

    def test_home_directory_is_written_as_tilde_and_text_mode_works(self):
        home = os.path.expanduser("~")
        d = tempfile.mkdtemp(prefix="prov-home-", dir=home) if os.access(home, os.W_OK) else None
        if not d:
            self.skipTest("home is not writable")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "f.bin")
        open(p, "w").write("x")
        code, out, _e = run_cli(["provenance", "file", p, "--json"])
        self.assertEqual(code, 0)
        self.assertNotIn(home + "/", out)
        self.assertEqual(json.loads(out)["subject"]["file"]["path"], "~/" + os.path.relpath(p, home))
        code, out, _e = run_cli(["provenance", "file", p])
        self.assertIn("PACKAGE_OWNERSHIP", out)
        self.assertIn("UNKNOWN", out)

    def test_out_file_is_created_once_with_private_mode_and_never_overwritten(self):
        p = self.mk("x.bin")
        o = os.path.join(self.d, "out.json")
        self.assertEqual(run_cli(["provenance", "file", p, "--out", o])[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(o).st_mode), 0o600)
        self.assertEqual(schema_validate(json.load(open(o)), SCHEMA), [])
        before = slurp(o)
        self.assertEqual(run_cli(["provenance", "file", p, "--out", o])[0], 3)
        self.assertEqual(slurp(o), before)
        os.symlink(os.path.join(self.d, "elsewhere"), os.path.join(self.d, "lnk.json"))
        self.assertEqual(run_cli(["provenance", "file", p, "--out", os.path.join(self.d, "lnk.json")])[0], 3)
        self.assertFalse(os.path.exists(os.path.join(self.d, "elsewhere")))

    def test_timeout_argument_is_validated(self):
        p = self.mk("x.bin")
        self.assertEqual(run_cli(["provenance", "file", p, "--timeout", "0"])[0], 3)


class MgctlIntegrationTests(TmpCase):
    def mg(self, args):
        env = dict(os.environ, MGCTL_LANG="en", PYTHONPATH=ROOT)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "mgctl")] + args, capture_output=True, text=True, env=env, timeout=120)
        return r.returncode, r.stdout, r.stderr

    def test_provenance_file_is_experimental_and_delegates_to_the_intel_package(self):
        from mgctl.tree import BY_PATH
        self.assertEqual(BY_PATH[("provenance", "file")].status, "experimental")
        self.assertEqual(BY_PATH[("provenance",)].status, "planned")
        p = self.mk("x.bin")
        code, out, err = self.mg(["--json", "provenance", "file", p])
        self.assertEqual(code, 0, err)
        wrapper = json.loads(out)
        self.assertEqual((wrapper["command"], wrapper["exitCode"], wrapper["ok"]), ("provenance file", 0, True))
        self.assertEqual(schema_validate(wrapper["document"], SCHEMA), [])
        code, out, _e = self.mg(["provenance", "file", p])
        self.assertEqual(code, 0)
        self.assertIn("CONTENT_ORIGIN", out)

    def test_host_wide_scan_stays_planned_and_bad_paths_exit_3(self):
        code, _o, err = self.mg(["provenance", "--all"])
        self.assertEqual(code, 4)
        self.assertIn("planned", err)
        self.assertEqual(self.mg(["provenance", "file", os.path.join(self.d, "nope")])[0], 3)
        self.assertEqual(self.mg(["provenance", "file", self.d])[0], 3)
        link = os.path.join(self.d, "l")
        os.symlink(self.mk("t.bin"), link)
        self.assertEqual(self.mg(["provenance", "file", link])[0], 3)
        self.assertEqual(self.mg(["provenance", "file", link, "--follow-symlinks"])[0], 0)

    def test_output_dir_gets_one_private_never_overwritten_document(self):
        p = self.mk("x.bin")
        out_dir = os.path.join(self.d, "outdir")
        self.assertEqual(self.mg(["--output", out_dir, "provenance", "file", p])[0], 0)
        self.assertEqual(schema_validate(json.load(open(os.path.join(out_dir, "provenance.json"))), SCHEMA), [])
        self.assertEqual(self.mg(["--output", out_dir, "provenance", "file", p])[0], 3)

    def test_help_exists_in_both_languages(self):
        for lang in ("en", "es"):
            code, out, _e = self.mg(["--lang", lang, "help", "provenance", "file"])
            self.assertEqual(code, 0)
            self.assertIn("provenance file", out)
            self.assertIn("UNKNOWN", out)


if __name__ == "__main__":
    unittest.main()
