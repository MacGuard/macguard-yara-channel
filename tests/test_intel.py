"""Tests for the intel package (P0/P1): canonical JSON, IOC normalisation and validation, channel manifests, the global catalog and the
independent verifier, including real signatures made with a throwaway cosign key (skipped, and reported as skipped, if cosign is missing)."""
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from intel import canonical, catalog, channel, ioc, merkle, registry as reg, verify  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
COSIGN = shutil.which("cosign")


def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def test_registry(**over):
    """A registry in which 'feedA' and 'feedB' are cleared and 'blocked' is not (test double: real status is a human decision)."""
    def src(i, status, trust=50, ttl=30, **kw):
        d = {"id": i, "name": i, "upstream_url": "https://example.invalid/" + i, "license": {"name": "test"}, "redistribution_status": status, "trust": trust, "default_ttl_days": ttl,
             "access": {"credential_required": False}, "original_signature": {"kind": "none"}}
        d.update(kw)
        return d
    srcs = [src("feedA", "allowed", 80), src("feedB", "allowed-with-conditions", 50, 10), src("blocked", "pending-legal"), src("keyed", "allowed", access={"credential_required": True})]
    return {s["id"]: s for s in srcs}


class CanonicalTests(unittest.TestCase):
    def test_same_bytes_for_any_key_order_and_no_whitespace(self):
        a = {"b": 1, "a": {"y": [1, 2], "x": "é"}}
        b = {"a": {"x": "é", "y": [1, 2]}, "b": 1}
        self.assertEqual(canonical.canonical_bytes(a), canonical.canonical_bytes(b))
        self.assertEqual(canonical.canonical_bytes(a), '{"a":{"x":"é","y":[1,2]},"b":1}'.encode("utf-8"))

    def test_floats_and_odd_types_are_rejected(self):
        for bad in ({"x": 1.5}, {"x": float("nan")}, {1: 2}, {"x": {1, 2}}, {"x": b"b"}):
            with self.assertRaises(ValueError):
                canonical.canonical_bytes(bad)

    def test_hash_changes_with_any_change(self):
        self.assertNotEqual(canonical.doc_sha256({"a": 1}), canonical.doc_sha256({"a": 2}))


class NormalisationTests(unittest.TestCase):
    def ok(self, hint, raw, want):
        self.assertEqual(ioc.normalise(hint, raw), want, raw)

    def drop(self, hint, raw, reason):
        with self.assertRaises(ioc.Drop) as cm:
            ioc.normalise(hint, raw)
        self.assertEqual(str(cm.exception), reason, raw)

    def test_hashes(self):
        h = "A" * 31 + "B"
        self.ok(None, "44D88612FEA8A8F36DE82E1278ABB02F", ("md5", "44d88612fea8a8f36de82e1278abb02f"))
        self.ok("sha256", "e" + "f" * 7 + "0" * 55 + "1", ("sha256", "e" + "f" * 7 + "0" * 55 + "1"))
        self.ok("hash", " " + "ab" * 20 + " ", ("sha1", "ab" * 20))
        self.drop("sha256", "ab" * 20, "hash-type-mismatch")
        self.drop(None, "xyz", "invalid-domain")
        self.drop("hash", "zz" * 16, "invalid-hash")
        self.drop("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "non-indicator-hash")     # empty file
        self.drop("hash", "0" * 64, "non-indicator-hash")
        self.assertEqual(len(h), 32)

    def test_ip_addresses_must_be_global(self):
        self.ok(None, "1.2[.]3.4", ("ipv4", "1.2.3.4"))
        self.ok("ip", "2001:4860:4860:0:0:0:0:8888", ("ipv6", "2001:4860:4860::8888"))
        for bad in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.5", "::1", "fe80::1", "fc00::1"):
            self.drop("ip", bad, "non-global-ip")
        self.drop("ip", "999.1.1.1", "invalid-ip")

    def test_domains(self):
        self.ok(None, "Evil-Example[.]COM.", ("domain", "evil-example.com"))
        self.ok("domain", "münchen.example.org", ("domain", "xn--mnchen-3ya.example.org"))
        self.drop("domain", "localhost", "invalid-domain")
        self.drop("domain", "printer.local", "reserved-tld")
        self.drop("domain", "intranet.corp", "reserved-tld")
        self.drop("domain", "a..b.com", "invalid-domain")
        self.drop("domain", "-bad.example.com", "invalid-domain")
        self.drop("domain", "x" * 64 + ".com", "invalid-domain")
        self.drop("domain", "host.com/path", "invalid-domain")
        self.drop("domain", "1.2.3.4", "ip-as-domain")
        self.drop("domain", "site.123", "invalid-domain")

    def test_urls(self):
        self.ok(None, "hxxp://Bad.EXAMPLE.org:80/a%2fb?q=%7e#frag", ("url", "http://bad.example.org/a%2Fb?q=%7E"))
        self.ok("url", "https://bad.example.org:8443", ("url", "https://bad.example.org:8443/"))
        self.ok("url", "http://1.2.3.4/x", ("url", "http://1.2.3.4/x"))
        self.drop("url", "http://user:pw@bad.example.org/", "url-with-credentials")
        self.drop("url", "file:///etc/passwd", "unsupported-scheme")
        self.drop("url", "javascript:alert(1)", "unsupported-scheme")
        self.drop("url", "http://10.1.1.1/x", "non-global-ip")
        self.drop("url", "http://localhost/x", "invalid-domain")
        self.drop("url", "http://example.com/" + "a" * 2100, "url-too-long")
        self.drop("url", "http://[::1]/", "non-global-ip")

    def test_empty_and_garbage(self):
        self.drop(None, "   ", "empty")
        self.drop(None, "<>", "empty")


class BuildTests(unittest.TestCase):
    def build(self, items, reg_=None, allow=None, now=NOW):
        return ioc.build(items, reg_ or test_registry(), now, allow)

    def test_duplicates_merge_and_keep_every_source_and_confidence_rises(self):
        items = [("feedA", {"value": "1.2.3.4", "kind": "ip", "confidence": 90, "seen": "2026-10-20T00:00:00Z"}),
                 ("feedB", {"value": "1[.]2.3.4", "kind": None, "confidence": 60, "seen": "2026-10-21T00:00:00Z", "tags": ["c2"]}),
                 ("feedA", {"value": "1.2.3.4", "kind": "ip", "confidence": 70, "seen": "2026-10-22T00:00:00Z"})]
        recs, rep = self.build(items)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual([s["id"] for s in r["sources"]], ["feedA", "feedB"])
        a = r["sources"][0]
        self.assertEqual((a["first_seen"], a["last_seen"], a["confidence"]), ("2026-10-20T00:00:00Z", "2026-10-22T00:00:00Z", 90))
        self.assertEqual(r["confidence"], 72 + 10)            # max(90*80/100, 60*50/100) + 10 for the second source
        self.assertEqual(r["tags"], ["c2"])
        self.assertEqual(r["expires_at"], "2026-11-21T00:00:00Z")   # feedA last seen 22 Oct + 30 days (feedB: 21 Oct + 10 days is earlier)

    def test_ttl_expiry_removes_and_counts_the_indicator(self):
        recs, rep = self.build([("feedB", {"value": "5.6.7.8", "kind": "ip", "seen": "2026-10-01T00:00:00Z"}), ("feedA", {"value": "9.9.9.9", "kind": "ip", "seen": "2026-10-01T00:00:00Z"})])
        self.assertEqual([r["value"] for r in recs], ["9.9.9.9"])
        self.assertEqual(rep["expired"], 1)

    def test_drops_are_counted_by_reason_and_never_silent(self):
        items = [("feedA", {"value": v, "kind": None}) for v in ("10.0.0.1", "10.0.0.2", "foo", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "evil.example.com")]
        items.append(("feedA", {"value": "2.2.2.2", "kind": "ip", "seen": "not-a-date"}))
        items.append(("feedA", {"value": "3.3.3.3", "kind": "ip", "seen": "2030-01-01T00:00:00Z"}))
        recs, rep = self.build(items)
        self.assertEqual([r["value"] for r in recs], ["evil.example.com"])
        self.assertEqual(rep["dropped"], {"bad-timestamp": 1, "empty": 1, "future-timestamp": 1, "invalid-domain": 1, "non-global-ip": 2, "non-indicator-hash": 1})
        self.assertEqual(rep["input_items"], len(items))
        self.assertEqual(sum(rep["dropped"].values()) + rep["published"] + rep["expired"], len(items))

    def test_allowlist_removes_known_good_indicators(self):
        allow = {"entries": [{"type": "domain", "value": "Good.Example.com"}]}
        recs, rep = self.build([("feedA", {"value": "good.example.com", "kind": "domain"}), ("feedA", {"value": "bad.example.com", "kind": "domain"})], allow=allow)
        self.assertEqual([r["value"] for r in recs], ["bad.example.com"])
        self.assertEqual(rep["dropped"], {"allowlisted": 1})

    def test_output_is_deterministic_whatever_the_input_order(self):
        vals = [("feedA", {"value": f"{i}.{i}.{i}.{i}", "kind": "ip"}) for i in range(1, 40)] + [("feedB", {"value": f"d{i}.example.com", "kind": "domain"}) for i in range(30)]
        a = self.build(vals)[0]
        random.Random(7).shuffle(vals)
        b = self.build(vals)[0]
        self.assertEqual([canonical.canonical_bytes(r) for r in a], [canonical.canonical_bytes(r) for r in b])

    def test_unknown_source_gets_default_trust(self):
        recs, _ = self.build([("mystery", {"value": "1.1.1.1", "kind": "ip", "confidence": 100})])
        self.assertEqual(recs[0]["confidence"], 50)


class ReaderTests(unittest.TestCase):
    def test_readers_parse_local_files(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "a.txt")
        open(p, "w").write("# c\n1.2.3.4 extra\n\n; x\nbad.example.com\n")
        self.assertEqual([i["value"] for i in ioc.read_plain(p)], ["1.2.3.4", "bad.example.com"])
        c = os.path.join(d, "a.csv")
        open(c, "w").write("# header comment\nfirst_seen, url, conf\n2026-10-20T00:00:00Z, http://bad.example.com/x, 80\n")
        rows = list(ioc.read_csv(c, "url", "url", "first_seen", "conf"))
        self.assertEqual((rows[0]["value"], rows[0]["seen"], rows[0]["confidence"]), ("http://bad.example.com/x", "2026-10-20T00:00:00Z", 80))
        with self.assertRaises(ValueError):
            list(ioc.read_csv(c, "nope", None))
        j = os.path.join(d, "a.jsonl")
        open(j, "w").write('{"type":"domain","value":"x.example.com","confidence":70}\nnot json\n')
        got = list(ioc.read_jsonl(j))
        self.assertEqual(got[0]["value"], "x.example.com")
        self.assertIn("_error", got[1])


class RegistryTests(unittest.TestCase):
    def test_repo_registry_loads_and_nothing_is_cleared_without_a_decision(self):
        r = reg.load()
        self.assertIn("nextron", r)
        for sid, s in r.items():
            self.assertIn(s["redistribution_status"], reg.STATUSES)
        ok, why = reg.clearance(r, ["abusech-bulk"])
        self.assertFalse(ok)

    def test_clearance_rules(self):
        r = test_registry()
        self.assertEqual(reg.clearance(r, ["feedA", "feedB"]), (True, []))
        ok, why = reg.clearance(r, ["feedA", "blocked", "nope", "keyed"])
        self.assertFalse(ok)
        self.assertEqual(len(why), 3)

    def test_invalid_registries_are_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for body in ('{"schema":"x"}', '{"schema":"macguard.source-registry/1","sources":[{"id":"a","redistribution_status":"yes"}]}',
                     '{"schema":"macguard.source-registry/1","sources":[{"id":"a","redistribution_status":"allowed"},{"id":"a","redistribution_status":"allowed"}]}',
                     '{"schema":"macguard.source-registry/1","sources":[{"id":"a","redistribution_status":"allowed","trust":500}]}', "not json"):
            p = os.path.join(d, "r.json")
            open(p, "w").write(body)
            with self.assertRaises(reg.RegistryError):
                reg.load(p)


class Workspace(unittest.TestCase):
    """A catalog root with an IOC channel built from real code paths."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="intel-test-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.root = os.path.join(self.d, "root")
        self.registry = test_registry()

    def make_channel(self, version=1, state="approved", sources=("feedA",), previous=None, values=None):
        out = os.path.join(self.root, "ioc", str(version))
        os.makedirs(out, exist_ok=True)
        items = [(sources[0], {"value": v, "kind": None}) for v in (values or ["1.2.3.4", "bad.example.com", "http://bad.example.com/x", "44d88612fea8a8f36de82e1278abb02f"])]
        recs, rep = ioc.build(items, self.registry, NOW)
        for t in sorted({r["type"] for r in recs}):
            with open(os.path.join(out, f"ioc-{t}.jsonl"), "wb") as f:
                for r in [x for x in recs if x["type"] == t]:
                    f.write(canonical.canonical_bytes(r) + b"\n")
        m = channel.build_manifest("ioc", "ioc", version, out, list(sources), self.registry, "2026-10-22T12:00:00Z", previous=previous, stats=rep, approval_state=state)
        return out, m, channel.write_manifest(m, out)

    def make_catalog(self, refs, version=1, **kw):
        doc = catalog.build_catalog(version, "2026-10-22T12:30:00Z", refs, **kw)
        return catalog.write_catalog(doc, os.path.join(self.d, f"cat{version}")), doc


class ChannelTests(Workspace):
    def test_manifest_is_deterministic_and_lists_artifacts_with_origin(self):
        _o, m, p = self.make_channel()
        self.assertEqual(m["schema"], "macguard.channel-manifest/1")
        self.assertTrue(all(a["origin"] == "derived" and not a["original_signature"]["present"] for a in m["artifacts"]))
        self.assertEqual(slurp(p, "rb").rstrip(b"\n"), canonical.canonical_bytes(m))
        self.assertEqual(m["approval"], {"state": "approved", "publishable": True, "blocking_reasons": [], "approved_by": [], "approved_at": None})

    def test_artifacts_root_matches_the_legacy_channel_construction(self):
        files = [{"path": "b.txt", "sha256": "11" * 32}, {"path": "a.txt", "sha256": "22" * 32}]
        legacy = importlib_tlog()
        self.assertEqual(merkle.artifacts_root(files), legacy.rules_root(files))
        self.assertTrue(merkle.uses_shared_implementation())

    def test_an_uncleared_source_blocks_approval_and_publication(self):
        out = os.path.join(self.root, "ioc", "9")
        os.makedirs(out)
        open(os.path.join(out, "x.jsonl"), "w").write("{}\n")
        with self.assertRaises(channel.ChannelError):
            channel.build_manifest("ioc", "ioc", 1, out, ["blocked"], self.registry, "2026-10-22T00:00:00Z", approval_state="approved")
        m = channel.build_manifest("ioc", "ioc", 1, out, ["blocked", "keyed"], self.registry, "2026-10-22T00:00:00Z")
        self.assertEqual((m["approval"]["state"], m["approval"]["publishable"]), ("draft", False))
        self.assertEqual(len(m["approval"]["blocking_reasons"]), 2)

    def test_versions_only_increase_and_manifests_are_never_overwritten(self):
        _o, m1, _p = self.make_channel(1)
        with self.assertRaises(channel.ChannelError):
            self.make_channel(1, previous=m1)
        out2, m2, _ = self.make_channel(2, previous=m1)
        self.assertEqual(m2["previous"], {"version": 1, "manifest_sha256": canonical.doc_sha256(m1)})
        with self.assertRaises(channel.ChannelError):
            channel.write_manifest(m2, out2)

    def test_symlinks_empty_channels_and_unknown_families_are_refused(self):
        out = os.path.join(self.d, "c")
        os.makedirs(out)
        with self.assertRaises(channel.ChannelError):
            channel.build_manifest("x", "ioc", 1, out, ["feedA"], self.registry, "t")
        open(os.path.join(out, "a"), "w").write("a")
        os.symlink(os.path.join(out, "a"), os.path.join(out, "l"))
        with self.assertRaises(channel.ChannelError):
            channel.build_manifest("x", "ioc", 1, out, ["feedA"], self.registry, "t")
        os.unlink(os.path.join(out, "l"))
        with self.assertRaises(channel.ChannelError):
            channel.build_manifest("x", "nonsense", 1, out, ["feedA"], self.registry, "t")


def importlib_tlog():
    import importlib.util
    spec = importlib.util.spec_from_file_location("legacy_tlog", os.path.join(ROOT, "scripts", "tlog.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CatalogTests(Workspace):
    def test_draft_channels_are_left_out_unless_asked(self):
        _o, m, p = self.make_channel(1, state="draft")
        ref = catalog.channel_ref(p)
        self.assertEqual(catalog.build_catalog(1, "t", [ref])["channels"], [])
        self.assertEqual(len(catalog.build_catalog(1, "t", [ref], include_draft=True)["channels"]), 1)

    def test_combinations_must_match_the_pinned_versions_and_approved_channels(self):
        _o, m, p = self.make_channel(1)
        ref = catalog.channel_ref(p)
        good = {"id": "c1", "channels": {"ioc": 1}, "state": "approved"}
        self.assertEqual(catalog.build_catalog(1, "t", [ref], [good])["combinations"], [good])
        for bad in ({"id": "c", "channels": {"ioc": 2}}, {"id": "c", "channels": {"nope": 1}}):
            with self.assertRaises(catalog.CatalogError):
                catalog.build_catalog(1, "t", [ref], [bad])
        _o2, _m2, p2 = self.make_channel(5, state="draft")
        with self.assertRaises(catalog.CatalogError):
            catalog.build_catalog(1, "t", [catalog.channel_ref(p2)], [{"id": "c", "channels": {"ioc": 5}, "state": "approved"}], include_draft=True)

    def test_catalog_versions_increase_and_link(self):
        _o, m, p = self.make_channel(1)
        c1 = catalog.build_catalog(1, "t", [catalog.channel_ref(p)])
        c2 = catalog.build_catalog(2, "t", [catalog.channel_ref(p)], previous=c1)
        self.assertEqual(c2["previous"], {"version": 1, "catalog_sha256": canonical.doc_sha256(c1)})
        with self.assertRaises(catalog.CatalogError):
            catalog.build_catalog(2, "t", [catalog.channel_ref(p)], previous=c2)

    def test_the_legacy_yara_channel_is_referenced_not_changed(self):
        fx = os.path.join(ROOT, "tests", "fixtures", "intel")
        ref = catalog.legacy_yara_ref(os.path.join(fx, "legacy-manifest.json"), os.path.join(fx, "legacy-release.json"))
        self.assertEqual((ref["id"], ref["legacy"], ref["version"], ref["state"], ref["validation_engine"]), ("yara", True, "rules-FIXTURE", "approved", "yara"))
        self.assertEqual(ref["manifest"]["sha256"], canonical.sha256_hex(slurp(os.path.join(fx, "legacy-manifest.json"), "rb")))


class VerifyTests(Workspace):
    def setUp(self):
        super().setUp()
        self.out, self.m, self.mpath = self.make_channel(1)
        self.cpath, self.cdoc = self.make_catalog([catalog.channel_ref(self.mpath)], combinations=[{"id": "combo-1", "channels": {"ioc": 1}, "state": "approved"}])

    def run_verify(self, **kw):
        return verify.verify_catalog(self.cpath, self.root, **kw)

    def failing(self, res):
        return [c["check"] for c in res["checks"] if c["status"] == "FAIL"]

    def test_consistent_but_unsigned_is_exit_5_never_verified(self):
        res = self.run_verify()
        self.assertEqual((res["result"], res["exit_code"]), ("CONSISTENT, SIGNATURE NOT CHECKED", 5))
        self.assertEqual(self.failing(res), [])

    @unittest.skipUnless(COSIGN, "cosign is not installed: signature tests cannot run (a skipped test is not a pass)")
    def test_a_real_signature_is_verified_and_a_wrong_key_or_tampering_is_refused(self):
        kd = os.path.join(self.d, "keys")
        os.makedirs(kd)
        env = dict(os.environ, COSIGN_PASSWORD="")
        subprocess.run([COSIGN, "generate-key-pair"], cwd=kd, env=env, check=True, capture_output=True, timeout=60)
        sig = os.path.join(self.d, "catalog.bundle.json")
        subprocess.run([COSIGN, "sign-blob", "--key", os.path.join(kd, "cosign.key"), "--tlog-upload=false", "--use-signing-config=false", "--bundle", sig, self.cpath], env=env, check=True, capture_output=True, timeout=60)
        good = self.run_verify(key=os.path.join(kd, "cosign.pub"), signature_bundle=sig)
        self.assertEqual((good["result"], good["exit_code"]), ("VERIFIED", 0))
        kd2 = os.path.join(self.d, "keys2")
        os.makedirs(kd2)
        subprocess.run([COSIGN, "generate-key-pair"], cwd=kd2, env=env, check=True, capture_output=True, timeout=60)
        bad = self.run_verify(key=os.path.join(kd2, "cosign.pub"), signature_bundle=sig)
        self.assertEqual(bad["exit_code"], 2)
        with open(self.cpath, "ab") as f:                     # any byte changed after signing
            f.write(b" ")
        tampered = self.run_verify(key=os.path.join(kd, "cosign.pub"), signature_bundle=sig)
        self.assertIn("catalog signature", self.failing(tampered))          # the signature no longer matches the bytes
        self.assertIn(tampered["exit_code"], (1, 2))                         # (1 wins by precedence: the file is also no longer canonical)

    def test_signature_requested_but_cosign_missing_or_bad_arguments_fail_closed(self):
        res = self.run_verify(signature_bundle=os.path.join(self.d, "none.json"), cosign="/nonexistent/cosign")
        self.assertEqual(res["exit_code"], 2)
        res = self.run_verify(signature=os.path.join(self.d, "none.sig"))
        self.assertEqual(res["exit_code"], 2)

    def test_a_changed_artifact_is_an_integrity_failure(self):
        art = [f for f in os.listdir(self.out) if f.startswith("ioc-")][0]
        with open(os.path.join(self.out, art), "ab") as f:
            f.write(b"tampered\n")
        res = self.run_verify()
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("ioc@1: artifacts", self.failing(res))

    def test_a_changed_manifest_or_swapped_version_is_detected(self):
        m = json.loads(slurp(self.mpath))
        m["stats"]["published"] = 999
        with open(self.mpath, "wb") as f:
            f.write(canonical.canonical_bytes(m) + b"\n")
        res = self.run_verify()
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("ioc@1: manifest hash", self.failing(res))

    def test_missing_files_and_unlisted_files(self):
        art = [f for f in os.listdir(self.out) if f.startswith("ioc-")][0]
        extra = os.path.join(self.out, "extra.txt")
        open(extra, "w").write("x")
        res = self.run_verify()
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("ioc@1: no unlisted files", self.failing(res))
        os.unlink(extra)
        os.unlink(os.path.join(self.out, art))
        self.assertEqual(self.run_verify()["exit_code"], 1)
        shutil.rmtree(os.path.join(self.root, "ioc"))
        self.assertEqual(self.run_verify()["exit_code"], 4)

    def test_path_traversal_in_a_manifest_is_refused(self):
        m = json.loads(slurp(self.mpath))
        m["artifacts"][0]["path"] = "../../etc/passwd"
        with open(self.mpath, "wb") as f:
            f.write(canonical.canonical_bytes(m) + b"\n")
        res = self.run_verify()
        self.assertNotEqual(res["exit_code"], 0)
        self.assertTrue(any("unsafe path" in c["detail"] for c in res["checks"]))

    def test_revoked_channels_and_draft_channels_are_policy_refusals(self):
        rev = catalog.build_catalog(2, "t", [catalog.channel_ref(self.mpath)], revocations=[{"channel": "ioc", "version": 1, "reason": "test", "at": "2026-10-23T00:00:00Z"}])
        p = catalog.write_catalog(rev, os.path.join(self.d, "rev"))
        res = verify.verify_catalog(p, self.root)
        self.assertEqual(res["exit_code"], 3)
        out3, m3, mp3 = self.make_channel(3, state="draft")
        dr = catalog.build_catalog(3, "t", [catalog.channel_ref(mp3)], include_draft=True)
        p = catalog.write_catalog(dr, os.path.join(self.d, "dr"))
        self.assertEqual(verify.verify_catalog(p, self.root)["exit_code"], 3)
        self.assertEqual(verify.verify_catalog(p, self.root, allow_draft=True)["exit_code"], 5)

    def test_rollback_and_previous_chain(self):
        self.assertEqual(self.run_verify(min_catalog_version=2)["exit_code"], 3)
        self.assertEqual(self.run_verify(min_catalog_version=1)["exit_code"], 5)
        c2 = catalog.build_catalog(2, "t", [catalog.channel_ref(self.mpath)], previous=self.cdoc)
        p2 = catalog.write_catalog(c2, os.path.join(self.d, "cat2"))
        self.assertEqual(verify.verify_catalog(p2, self.root, previous_catalog=self.cpath)["exit_code"], 5)
        other = catalog.build_catalog(1, "t0", [], include_draft=True)
        po = catalog.write_catalog(other, os.path.join(self.d, "other"))
        self.assertEqual(verify.verify_catalog(p2, self.root, previous_catalog=po)["exit_code"], 1)

    def test_a_catalog_that_is_not_canonical_json_is_refused(self):
        with open(self.cpath, "w") as f:
            json.dump(self.cdoc, f, indent=2)
        res = self.run_verify()
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("catalog canonical form", self.failing(res))

    def test_garbage_catalogs_exit_4(self):
        p = os.path.join(self.d, "bad.json")
        for body in ("not json", '{"schema":"other/1"}'):
            open(p, "w").write(body)
            self.assertEqual(verify.verify_catalog(p, self.root)["exit_code"], 4)
        self.assertEqual(verify.verify_catalog(os.path.join(self.d, "absent.json"), self.root)["exit_code"], 4)

    def test_a_channel_edited_to_look_approved_is_caught_by_the_catalog(self):
        _o, m, p = self.make_channel(7, state="draft")
        ref = catalog.channel_ref(p)
        ref["state"] = "approved"                              # a catalog that lies about the manifest's state
        doc = catalog.build_catalog(9, "t", [ref], include_draft=True)
        cp = catalog.write_catalog(doc, os.path.join(self.d, "lie"))
        res = verify.verify_catalog(cp, self.root)
        self.assertEqual(res["exit_code"], 1)
        self.assertIn("ioc@7: approval state", self.failing(res))


class SchemaTests(Workspace):
    SCHEMAS = os.path.join(ROOT, "docs", "intelligence", "schemas")

    def test_every_schema_parses_and_cross_references_resolve(self):
        names = set(os.listdir(self.SCHEMAS))
        self.assertGreaterEqual(len(names), 16)
        for fn in names:
            text = slurp(os.path.join(self.SCHEMAS, fn))
            json.loads(text)
            for ref in re.findall(r'"\$ref"\s*:\s*"([^"#]+)', text):
                self.assertIn(ref, names, f"{fn} references {ref}")

    def test_generated_documents_carry_every_required_property_of_their_schema(self):
        _o, m, p = self.make_channel(1)
        cdoc = catalog.build_catalog(1, "t", [catalog.channel_ref(p)])
        rec = ioc.build([("feedA", {"value": "1.2.3.4", "kind": "ip"})], self.registry, NOW)[0][0]
        for doc, name in ((m, "channel-manifest"), (cdoc, "catalog"), (rec, "ioc-record")):
            schema = json.loads(slurp(os.path.join(self.SCHEMAS, f"{name}.schema.json")))
            self.assertEqual(sorted(set(schema["required"]) - set(doc)), [], name)
            self.assertEqual(schema["properties"]["schema"]["const"], doc["schema"])
        for a in m["artifacts"]:
            self.assertEqual(sorted(set(["path", "sha256", "bytes", "media_type", "origin", "original_signature"]) - set(a)), [])


class CliAndLegacyTests(Workspace):
    def run_cli(self, *argv):
        return subprocess.run([sys.executable, "-m", "intel"] + list(argv), cwd=ROOT, capture_output=True, text=True, timeout=120)

    def test_end_to_end_build_catalog_verify_through_the_cli(self):
        reg_path = os.path.join(self.d, "reg.json")
        json.dump({"schema": "macguard.source-registry/1", "sources": list(self.registry.values())}, open(reg_path, "w"))
        src = os.path.join(self.d, "in.txt")
        open(src, "w").write("1.2.3.4\nbad.example.com\n10.0.0.1\n")
        out = os.path.join(self.root, "ioc", "1")
        r = self.run_cli("ioc", "build", "--source", f"feedA:{src}", "--out", out, "--version", "1", "--now", "2026-10-22T12:00:00Z", "--registry", reg_path, "--state", "approved")
        self.assertEqual(r.returncode, 0, r.stderr)
        info = json.loads(r.stdout)
        self.assertEqual((info["published_indicators"], info["dropped"], info["publishable"]), (2, {"non-global-ip": 1}, True))
        r = self.run_cli("catalog", "build", "--channel", os.path.join(out, "manifest.json"), "--version", "1", "--out", os.path.join(self.d, "cat"), "--now", "2026-10-22T12:30:00Z")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_cli("catalog", "verify", os.path.join(self.d, "cat", "catalog.json"), "--root", self.root, "--json")
        self.assertEqual(r.returncode, 5)
        self.assertEqual(json.loads(r.stdout)["result"], "CONSISTENT, SIGNATURE NOT CHECKED")
        again = self.run_cli("ioc", "build", "--source", f"feedA:{src}", "--out", out, "--version", "1", "--registry", reg_path)
        self.assertEqual(again.returncode, 3)                    # manifest.json exists: a version is never overwritten

    def test_the_cli_refuses_unknown_sources_and_blocks_publication_of_uncleared_ones(self):
        src = os.path.join(self.d, "in.txt")
        open(src, "w").write("1.2.3.4\n")
        self.assertEqual(self.run_cli("ioc", "build", "--source", f"nosuch:{src}", "--out", os.path.join(self.d, "o"), "--version", "1").returncode, 3)
        r = self.run_cli("ioc", "build", "--source", f"abusech-bulk:{src}", "--out", os.path.join(self.d, "o2"), "--version", "1", "--state", "approved")
        self.assertEqual(r.returncode, 3)
        self.assertIn("cannot approve", r.stderr)

    def test_intel_never_touches_the_network_or_the_legacy_pipeline(self):
        banned = re.compile(r"\b(urlopen|http\.client|requests|socket|ftplib|smtplib)\b")
        for fn in os.listdir(os.path.join(ROOT, "intel")):
            if fn.endswith(".py"):
                self.assertIsNone(banned.search(slurp(os.path.join(ROOT, "intel", fn))), fn)
        for legacy in ("scripts/prepare.py", ".github/workflows/publish.yml", ".github/workflows/daily.yml"):
            self.assertNotIn("intel", slurp(os.path.join(ROOT, legacy)).lower().replace("intelligence", "").replace("intel_", ""), f"{legacy} must not depend on the new package yet")


if __name__ == "__main__":
    unittest.main()
