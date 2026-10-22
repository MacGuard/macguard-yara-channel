"""Writes filter-vectors.json: hand-written (filter, alert, expected answer) cases that BOTH the Python evaluator (alerts/filters.py) and the browser
one (web/alerts/filter.js) must pass. The expected values are written here by reasoning, not produced by running either implementation.
Run: python3 tests/fixtures/alerts/make_vectors.py"""
import copy, json, os

BASE = {
    "alert_id": "MGA-0001", "record_version": 1, "key": "CVE-2026-0001", "alert_type": "vulnerability",
    "ids": {"cve": ["CVE-2026-0001"], "euvd": ["EUVD-2026-0001"], "ghsa": ["GHSA-2g2v-9wf5-6m3g"]},
    "severity": {"score": "8.1", "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L", "band": "high", "rated_by": ["enisa-euvd"], "all": {"enisa-euvd": "8.1"}},
    "epss": {"by_source": {"enisa-euvd": "0.5"}}, "attack_vector": "network",
    "exploitation": {"status": "exploited", "asserted_by": ["cisa-kev"], "earliest_since": "2026-10-01", "independent_confirmation": "not-applicable",
                     "per_source": {"cisa-kev": {"asserted": True, "since": "2026-10-01", "basis": "kev"}, "enisa-euvd": {"asserted": False, "since": None, "basis": None}}},
    "affected": [{"vendor": "Microsoft", "product": "Windows Server 2012 R2", "vendor_slug": "microsoft", "product_slug": "windows server 2012 r2",
                  "versions": [{"raw": "6.3.9600.0 <6.3.9600.23470", "kind": "range", "introduced": "6.3.9600.0", "fixed_in": "6.3.9600.23470"}],
                  "sources": ["enisa-euvd"], "os": ["windows"], "categories": [], "services": [], "classification_basis": "curated-mapping:technology-map@1"},
                 {"vendor": "Cisco", "product": "IOS XE", "vendor_slug": "cisco", "product_slug": "ios xe",
                  "versions": [{"raw": "17.3 ≤17.3.5", "kind": "range", "introduced": "17.3", "last_affected": "17.3.5"}, {"raw": "16.12.1", "kind": "single", "version": "16.12.1"}],
                  "sources": ["cisa-kev"], "os": ["network-firmware"], "categories": ["network-device"], "services": [], "classification_basis": "curated-mapping:technology-map@1"}],
    "fix": {"available": True, "details": []}, "mitigations": [], "mitigation_basis": "none",
    "region_scope": [{"region": "EU", "basis": "source-scope", "source": "enisa-euvd"}, {"region": "country:US", "basis": "source-scope", "source": "cisa-kev"}],
    "sectors": [], "threat_families": [{"family": "ransomware", "source": "cisa-kev", "basis": "kev"}], "attack_techniques": [],
    "dates": {"published": "2026-09-20", "updated": "2026-10-20", "listed": {}}, "first_ingested_utc": "2026-10-20T10:00:00Z",
    "observations": {"enisa-euvd": {}, "cisa-kev": {}},
}
NOW = "2026-10-22T12:00:00Z"


def leaf(field, op, value, **extra):
    d = {"field": field, "op": op, "value": value}
    d.update(extra)
    return d


V = []


def case(name, expr, expect, over=None, stale=None, changes=None):
    V.append({"name": name, "expr": expr, "alert_overrides": over or {}, "stale": stale or [], "changes": changes, "expect": expect})


# region (a source scoped to ES also satisfies EU; EU never satisfies ES)
case("region EU matches an EU-scoped source", leaf("region", "in", ["EU"]), True)
case("region ES does not match an EU-scoped source", leaf("region", "in", ["ES"]), False)
case("region ES-scoped source satisfies EU", leaf("region", "in", ["EU"]), True, {"region_scope": [{"region": "ES", "basis": "source-scope", "source": "ccn"}]})
case("region ES-scoped source satisfies ES", leaf("region", "in", ["ES"]), True, {"region_scope": [{"region": "ES", "basis": "source-scope", "source": "ccn"}]})
case("region country:US matches", leaf("region", "in", ["country:US"]), True)
case("region OTHER matches a non-EU country", leaf("region", "in", ["OTHER"]), True)
case("region OTHER does not match EU/ES only", leaf("region", "in", ["OTHER"]), False, {"region_scope": [{"region": "EU", "basis": "source-scope", "source": "x"}]})
case("region GLOBAL needs a global scope", leaf("region", "in", ["GLOBAL"]), False)
case("region GLOBAL matches a global scope", leaf("region", "in", ["GLOBAL"]), True, {"region_scope": [{"region": "GLOBAL", "basis": "source-scope", "source": "osv"}]})
case("region with no scope never matches", leaf("region", "in", ["EU", "ES", "GLOBAL"]), False, {"region_scope": []})
# sector (nothing states a sector: no match unless the subscriber asks to include unknown)
case("sector without information does not match", leaf("sector", "in", ["health"]), False)
case("sector without information matches when included", leaf("sector", "in", ["health"], include_unknown=True), True)
case("sector stated matches", leaf("sector", "in", ["health"]), True, {"sectors": [{"sector": "health", "basis": "source-stated"}]})
case("sector stated but different does not match even if unknown included", leaf("sector", "in", ["energy"], include_unknown=True), False, {"sectors": [{"sector": "health", "basis": "source-stated"}]})
# technology
case("vendor exact", leaf("vendor", "in", ["Microsoft"]), True)
case("vendor is not a substring match", leaf("vendor", "in", ["micro"]), False)
case("product exact (slugged)", leaf("product", "in", ["windows server 2012 r2"]), True)
case("product is not a prefix match", leaf("product", "in", ["windows"]), False)
case("product_family is a word prefix", leaf("product_family", "in", ["windows"]), True)
case("product_family respects word boundaries", leaf("product_family", "in", ["win"]), False)
case("os windows", leaf("os", "in", ["windows"]), True)
case("os linux does not match", leaf("os", "in", ["linux"]), False)
case("os unknown vendor never matches", leaf("os", "in", ["linux"]), False, {"affected": []})
case("category network-device", leaf("technology_category", "in", ["network-device"]), True)
case("category cloud does not match", leaf("technology_category", "in", ["cloud"]), False)
case("service from the curated map", leaf("service", "in", ["ssh"]), True, {"affected": [{"vendor": "OpenBSD", "product": "OpenSSH", "vendor_slug": "openbsd", "product_slug": "openssh", "versions": [], "sources": ["x"], "os": [], "categories": ["service-protocol"], "services": ["ssh"], "classification_basis": "m"}]})
case("ecosystem is unknown without a source statement", leaf("ecosystem", "in", ["npm"]), False)
case("ecosystem stated by a source", leaf("ecosystem", "in", ["npm"]), True, {"affected": [{"vendor": "x", "product": "left-pad", "vendor_slug": "x", "product_slug": "left-pad", "versions": [], "sources": ["osv"], "os": [], "categories": [], "services": [], "ecosystems": ["npm"], "classification_basis": None}]})
# versions
case("version inside a fixed-in range", leaf("version", "affects", {"vendor": "Microsoft", "product": "Windows Server 2012 R2", "version": "6.3.9600.20000"}), True)
case("version equal to the fixed version is not affected", leaf("version", "affects", {"vendor": "Microsoft", "product": "Windows Server 2012 R2", "version": "6.3.9600.23470"}), False)
case("version below the range start is not affected", leaf("version", "affects", {"vendor": "Microsoft", "product": "Windows Server 2012 R2", "version": "6.3.9000"}), False)
case("version numeric, not text, order", leaf("version", "affects", {"vendor": "Cisco", "product": "IOS XE", "version": "17.3.10"}), False)
case("version at last_affected is inside", leaf("version", "affects", {"vendor": "Cisco", "product": "IOS XE", "version": "17.3.5"}), True)
case("single version is ambiguous: no match by default", leaf("version", "affects", {"vendor": "Cisco", "product": "IOS XE", "version": "16.12.1"}), False)
case("single version matches when ambiguity is accepted", leaf("version", "affects", {"vendor": "Cisco", "product": "IOS XE", "version": "16.12.1"}, include_ambiguous=True), True)
case("version of another product never matches", leaf("version", "affects", {"vendor": "Microsoft", "product": "Exchange", "version": "1.0"}), False)
# identifiers
case("id CVE any case", leaf("id", "in", ["cve-2026-0001"]), True)
case("id EUVD", leaf("id", "in", ["EUVD-2026-0001"]), True)
case("id GHSA any case", leaf("id", "in", ["ghsa-2G2V-9wf5-6m3g"]), True)
case("id other CVE does not match", leaf("id", "in", ["CVE-2026-0002"]), False)
# scores
case("cvss gte met", leaf("cvss", "gte", 8.0), True)
case("cvss gte not met", leaf("cvss", "gte", 8.2), False)
case("cvss lte", leaf("cvss", "lte", 8.1), True)
case("cvss unknown never matches", leaf("cvss", "gte", 0), False, {"severity": {"score": None, "version": None, "vector": None, "band": "unknown", "rated_by": [], "all": {}}})
case("epss gte met", leaf("epss", "gte", 0.4), True)
case("epss absent never matches", leaf("epss", "gte", 0), False, {"epss": None})
case("severity high satisfies high", leaf("severity", "gte", "high"), True)
case("severity high does not satisfy critical", leaf("severity", "gte", "critical"), False)
case("severity unknown satisfies nothing", leaf("severity", "gte", "low"), False, {"severity": {"score": None, "version": None, "vector": None, "band": "unknown", "rated_by": [], "all": {}}})
# exploitation
case("exploited true", leaf("exploited", "is", True), True)
case("exploited false does not match an exploited alert", leaf("exploited", "is", False), False)
case("exploited false matches an alert no source asserts", leaf("exploited", "is", False), True, {"exploitation": {"status": "not-asserted", "asserted_by": [], "earliest_since": None, "independent_confirmation": "not-applicable", "per_source": {}}})
case("exploited by a named source", leaf("exploited", "is", True, source="cisa-kev"), True)
case("exploited by another named source", leaf("exploited", "is", True, source="enisa-euvd-exploited"), False)
case("a stale source's exploitation is not counted", leaf("exploited", "is", True), False, stale=["cisa-kev"])
# dates
case("published gte", leaf("published", "gte", "2026-09-01"), True)
case("published lte before", leaf("published", "lte", "2026-09-01"), False)
case("updated gte", leaf("updated", "gte", "2026-10-20"), True)
case("updated missing never matches", leaf("updated", "gte", "2000-01-01"), False, {"dates": {"published": "2026-09-20", "updated": None, "listed": {}}})
case("ingested within 3 days", leaf("ingested_within_days", "lte", 3), True)
case("ingested within 1 day is too recent a window", leaf("ingested_within_days", "lte", 1), False)
# fixes, mitigations
case("has_fix true", leaf("has_fix", "is", True), True)
case("has_fix false when unknown", leaf("has_fix", "is", False), True, {"fix": {"available": None, "details": []}})
case("has_fix true when unknown does not match", leaf("has_fix", "is", True), False, {"fix": {"available": None, "details": []}})
case("has_mitigation false", leaf("has_mitigation", "is", False), True)
case("has_mitigation true", leaf("has_mitigation", "is", True), False)
# exposure (narrows by attack vector only)
case("internet exposure keeps network vulnerabilities", leaf("exposure", "in", ["internet"]), True)
case("internet exposure drops local vulnerabilities", leaf("exposure", "in", ["internet"]), False, {"attack_vector": "local"})
case("internet exposure keeps an unknown vector", leaf("exposure", "in", ["internet"]), True, {"attack_vector": "unknown"})
case("internal-service keeps local", leaf("exposure", "in", ["internal-service"]), True, {"attack_vector": "local"})
case("private-network drops physical", leaf("exposure", "in", ["private-network"]), False, {"attack_vector": "physical"})
case("exposure unknown keeps everything", leaf("exposure", "in", ["unknown"]), True, {"attack_vector": "physical"})
# source, family, technique, type, change
case("source observed", leaf("source", "in", ["cisa-kev"]), True)
case("source not observed", leaf("source", "in", ["osv"]), False)
case("threat family ransomware", leaf("threat_family", "in", ["ransomware"]), True)
case("technique absent", leaf("attack_technique", "in", ["T1190"]), False)
case("technique stated", leaf("attack_technique", "in", ["T1190"]), True, {"attack_techniques": ["T1190", "T1059.001"]})
case("alert type", leaf("alert_type", "in", ["vulnerability", "advisory"]), True)
case("alert type rule-release excluded", leaf("alert_type", "in", ["rule-release"]), False)
case("change without an event is not evaluated", leaf("change", "any", ["new"]), False)
case("change matches the event", leaf("change", "any", ["exploitation_added", "fix_available"]), True, changes=["exploitation_added"])
case("change does not match another event", leaf("change", "any", ["fix_available"]), False, changes=["new"])
# combinators
case("empty all matches everything", {"all": []}, True)
case("empty any matches nothing", {"any": []}, False)
case("all needs every branch", {"all": [leaf("os", "in", ["windows"]), leaf("severity", "gte", "critical")]}, False)
case("all of true branches", {"all": [leaf("os", "in", ["windows"]), leaf("severity", "gte", "high"), leaf("exploited", "is", True)]}, True)
case("any needs one branch", {"any": [leaf("os", "in", ["linux"]), leaf("severity", "gte", "high")]}, True)
case("any with no true branch", {"any": [leaf("os", "in", ["linux"]), leaf("severity", "gte", "critical")]}, False)
case("not inverts", {"not": leaf("os", "in", ["linux"])}, True)
case("not of a true leaf", {"not": leaf("os", "in", ["windows"])}, False)
case("nested and/or/not", {"all": [{"any": [leaf("region", "in", ["ES"]), leaf("region", "in", ["EU"])]}, {"not": leaf("alert_type", "in", ["rule-release"])}, leaf("cvss", "gte", 7)]}, True)
case("unknown data under not is still not a match of the inner leaf", {"not": leaf("cvss", "gte", 5)}, True, {"severity": {"score": None, "version": None, "vector": None, "band": "unknown", "rated_by": [], "all": {}}})

out = {"now": NOW, "base": BASE, "vectors": V}
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "filter-vectors.json")
open(path, "w", encoding="utf-8").write(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print(len(V), "vectors written")
