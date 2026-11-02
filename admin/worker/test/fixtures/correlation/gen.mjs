#!/usr/bin/env node
// Adversarial correlation corpus (docs/design/CORRELATION-ENGINE.md §8, C6). Writes <case>/case.json (description, input snapshot, HAND-WRITTEN expectations).
//   node test/fixtures/correlation/gen.mjs                    rewrite every case.json (inputs and hand-written expectations only)
//   node test/fixtures/correlation/gen.mjs --write-expected   ALSO rewrite <case>/expected.json from the engine. Review that diff by hand: the expected
//                                                             files are the exact-output oracle of test/intel_correlate.test.js.
// Data: synthetic, plus small excerpts of public data used as identifiers and locators only:
//   * CISA KEV catalogue 2026.10.30 (CC0 1.0; "Contains data from the CISA Known Exploited Vulnerabilities Catalog"): cve ids, CWE lists, dates of
//     CVE-2023-27351, CVE-2025-10035, CVE-2018-19943, CVE-2023-41061 from tests/fixtures/intel/kev-subset-2026.10.30.json (branch feat/hub-ingest),
//     whose SHA-256 is the upstream_sha256 below. Free-text fields are replaced by synthetic text.
//   * Signed YARA release rules-20261101-41271797671: rule ids, paths, file SHA-256, line numbers, meta keys and the identifier values of two rules
//     (no rule text).
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { correlate, serialize } from '../../../src/intel_correlate.js';

const HERE = new URL('.', import.meta.url);
const sha = (s) => createHash('sha256').update(s).digest('hex');
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REAL_TAG = 'rules-20261101-41271797671';

// ---- builders ------------------------------------------------------------------------------------------------------------------------------------------
function item(cve_id, cwes, extra = {}) {
  return { cve_id, vendor: 'ExampleVendor', product: 'ExampleProduct', name: `Synthetic entry for ${cve_id}`, date_added: '2026-01-01', short_description: 'Synthetic description.',
    required_action: 'Apply mitigations per vendor instructions.', due_date: '2026-01-22', known_ransomware_use: 'Unknown', notes: '', cwes, ...extra };
}
function kev({ source_id, origin = 'cisa-kev', version = '2026.10.30', date = '2026-10-30T17:02:45.366Z', upstream = sha(`kev ${origin} ${version}`), items }) {
  const document = { schema: 'macguard.intel-kev/1', source: { id: origin, url: KEV_URL, license: 'CC0-1.0', attribution: 'Contains data from the CISA Known Exploited Vulnerabilities Catalog (CC0 1.0)',
    catalog_version: version, date_released: date, retrieved_at: date, upstream_sha256: upstream }, count: items.length, items };
  return source_id ? { source_id, document } : { document };
}
/** rules: [{ path, name, source?, file?, meta: [[key, value, value_kind, match, line?]] }] -> one search-index wrapper */
function index({ tag = 'rules-20261102-1', source_id, rules, raw = [] }) {
  const entities = [], assertions = [];
  for (const r of rules) {
    const id = `yara:${r.path}#${r.name}`, file = r.file ?? sha(`file ${r.path}`);
    entities.push({ id, kind: 'rule', path: r.path, name: r.name, tags: [], modifiers: [], line: r.line ?? 1, file_sha256: file, source: r.source ?? 'community', meta: { uuid: null, author: null, date: null, references: [] } });
    let line = (r.line ?? 1) + 1;
    for (const [key, value, value_kind, match = 'whole_value', ln = line++] of r.meta ?? []) {
      const type = value_kind === 'cve' ? 'rule_meta_mentions_cve' : 'rule_meta_mentions_hash';
      assertions.push({ id: 'assert:' + sha(JSON.stringify([type, id, value, key, ln])), type, subject: id, value, value_kind, meta_key: key, match, status: 'asserted_by_rule_metadata',
        provenance: { release_tag: tag, path: r.path, file_sha256: file, line: ln } });
    }
  }
  assertions.push(...raw);
  const document = { schema: 'macguard.search-index/1', generator: 'scripts/rule_index.py', release: { tag, manifest_sha256: sha(`manifest ${tag} ${source_id ?? ''}`), rules_root: null, files: rules.length },
    note: 'synthetic', counts: {}, entities, assertions };
  return source_id ? { source_id, document } : { document };
}
const H = (s) => sha(`sample ${s}`);                     // synthetic SHA-256 sample
const rid = (path, name) => `rule:yara:${path}#${name}`;
const V = (c) => `vulnerability:cve:${c}`, W = (c) => `weakness:cwe:${c}`, S = (h) => `sample:sha256:${h}`;
const VHW = 'VULN_HAS_WEAKNESS', RRS = 'RULE_REFERENCES_SAMPLE', RAC = 'RULE_ASSOCIATED_WITH_CVE';

const cases = {};

// 01 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const realKev = kev({ upstream: '48070c5f103fb0dacd4cef83cf141cee60f22c75229e31e183f441b9be32fff9', items: [
    item('CVE-2023-27351', ['CWE-287'], { vendor: 'PaperCut', product: 'NG/MF', date_added: '2026-04-20' }),
    item('CVE-2025-10035', ['CWE-502', 'CWE-77'], { vendor: 'Fortra', product: 'GoAnywhere MFT', date_added: '2025-09-29' }),
    item('CVE-2018-19943', ['CWE-79', 'CWE-80'], { vendor: 'QNAP', product: 'Network Attached Storage (NAS)', date_added: '2022-05-24' }) ] });
  const dns = { path: 'rules/nextron/yara/apt_aa19_024a.yar', name: 'APT_MAL_DNS_Hijacking_Campaign_AA19_024A', source: 'nextron', line: 2, file: 'bdf26bde7835be3336f6ac237a4ad051d2f498ff9d3802b2008cbcfec93bf8b2',
    meta: [['hash1', '2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec', 'sha256', 'whole_value', 8]] };
  const citrix = { path: 'rules/nextron/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar', name: 'EXPL_Citrix_Netscaler_ADC_ForensicArtifacts_CVE_2023_3519_Jul23', source: 'nextron', line: 2,
    file: '857ea344a1d5bb7044dfb2b418b56438f3b77bc8a760bbffbbd4e36190c6ea80', meta: [['description', 'CVE-2023-3519', 'cve', 'embedded', 4], ['reference', 'CVE-2023-3519', 'cve', 'embedded', 6]] };
  const synth = { path: 'rules/community/synthetic/papercut.yar', name: 'SYNTH_PaperCut_Artefact', meta: [['cve', 'CVE-2023-27351', 'cve'], ['sha256', H('papercut'), 'sha256']] };
  cases['01_verified_relations'] = {
    description: 'Source-asserted relations that must come out asserted: real KEV CWE lists (CC0 excerpt), a real signed-release hash1 meta value, and a synthetic rule with whole-value cve/sha256 keys. The real Citrix rule mentions its CVE only inside description and reference text: candidate, not asserted.',
    input: { kev: [realKev], rule_indexes: [index({ tag: REAL_TAG, rules: [dns, citrix, synth] })] },
    expect: {
      asserted: [[VHW, V('CVE-2018-19943'), W('CWE-79')], [VHW, V('CVE-2018-19943'), W('CWE-80')], [VHW, V('CVE-2023-27351'), W('CWE-287')], [VHW, V('CVE-2025-10035'), W('CWE-502')], [VHW, V('CVE-2025-10035'), W('CWE-77')],
        [RRS, rid(dns.path, dns.name), S('2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec')], [RRS, rid(synth.path, synth.name), S(H('papercut'))], [RAC, rid(synth.path, synth.name), V('CVE-2023-27351')]],
      candidate: [[RAC, rid(citrix.path, citrix.name), V('CVE-2023-3519')]],
    },
  };
}
// 02 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const quiet = { path: 'rules/community/synthetic/quiet.yar', name: 'SYNTH_No_Identifiers' };
  const other = { path: 'rules/community/synthetic/other.yar', name: 'SYNTH_Other_Sample', meta: [['hash', H('other'), 'sha256']] };
  cases['02_unrelated_entities'] = {
    description: 'Entities that share nothing produce nothing: a rule without identifiers, a KEV entry without CWEs (real CVE-2023-41061 has an empty list), and a rule and a KEV entry that sit in the same snapshot but never name each other.',
    input: { kev: [kev({ items: [item('CVE-2023-41061', [], { vendor: 'Apple', product: 'iOS, iPadOS, and watchOS', date_added: '2023-09-11' }), item('CVE-2099-0001', ['CWE-79'])] })],
      rule_indexes: [index({ rules: [quiet, other] })] },
    expect: { asserted: [[VHW, V('CVE-2099-0001'), W('CWE-79')], [RRS, rid(other.path, other.name), S(H('other'))]], candidate: [],
      rejections: { no_assertions: 1, no_cwes: 1 } },
  };
}
// 03 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const trip = { path: 'rules/community/synthetic/triplet.yar', name: 'SYNTH_Hash_Triplet', meta: [['md5', 'a'.repeat(32), 'md5'], ['sha1', 'b'.repeat(40), 'sha1'], ['sha256', 'c'.repeat(64), 'sha256']] };
  const a = { path: 'rules/community/a/same.yar', name: 'SYNTH_Same_Name', meta: [['hash', H('only-in-a'), 'sha256']] };
  const b = { path: 'rules/community/b/same.yar', name: 'SYNTH_Same_Name' };
  const l1 = { path: 'rules/community/synthetic/log4j.yar', name: 'SYNTH_Log4j_A', meta: [['cve', 'CVE-2021-44228', 'cve']] };
  const l2 = { path: 'rules/community/synthetic/log4j.yar', name: 'SYNTH_Log4j_B', meta: [['cve', 'CVE-2021-45046', 'cve']] };
  cases['03_ambiguous_aliases'] = {
    description: 'No alias merge without a source record: md5/sha1/sha256 of "the same sample" are never joined (md5/sha1 have no canonical sample identity and are refused); two rules with the same name in different files are two rules; a GCVE-0 id is not silently turned into a CVE; two related CVEs are never aliases.',
    input: { kev: [kev({ items: [item('GCVE-0-2021-44228', ['CWE-917']), item('CVE-2021-44228', ['CWE-917'])] })], rule_indexes: [index({ rules: [trip, a, b, l1, l2] })] },
    expect: { asserted: [[VHW, V('CVE-2021-44228'), W('CWE-917')], [RRS, rid(trip.path, trip.name), S('c'.repeat(64))], [RRS, rid(a.path, a.name), S(H('only-in-a'))],
      [RAC, rid(l1.path, l1.name), V('CVE-2021-44228')], [RAC, rid(l2.path, l2.name), V('CVE-2021-45046')]], candidate: [],
      rejections: { no_canonical_sample_identity_for_md5_sha1: 2, malformed_identifier: 1, no_assertions: 1 } },
  };
}
// 04 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const h = H('similar'), near = h.slice(0, -1) + (h.at(-1) === '0' ? '1' : '0');
  const bad = [['63 hex', h.slice(0, 63)], ['65 hex', h + 'a'], ['non-hex', h.slice(0, 63) + 'g'], ['upper', h.toUpperCase()], ['fullwidth digit', '０' + h.slice(1)],
    ['arabic-indic digit', '٠' + h.slice(1)], ['prefixed', `sha256:${h}`], ['trailing space', h + ' '], ['empty', ''], ['zero-width', h.slice(0, 32) + '​' + h.slice(32)]];
  const r = { path: 'rules/community/synthetic/hashes.yar', name: 'SYNTH_Malformed_Hashes', meta: [['hash1', h, 'sha256'], ['hash2', near, 'sha256'], ...bad.map(([, v], i) => [`hash${i + 3}`, v, 'sha256']),
    ['hash20', h, 'md5'], ['cve', 'CVE-2024-01234', 'cve'], ['cve', 'CVE-٢٠٢٤-1234', 'cve'], ['cve', 'cve-2024-1234', 'cve'], ['cve', 'CVE-2024-123', 'cve']] };
  cases['04_malformed_identifiers'] = {
    description: 'Similar hashes stay separate (one character apart: two samples, no fuzzy merge). 63/65 hex, non-hex, upper case, Unicode digits, prefixes, whitespace and zero-width characters are not canonical SHA-256 values: no relation. A 64-hex value labelled md5 is a kind mismatch. Malformed or non-canonical CVE and CWE ids (leading zero, Arabic-Indic digits, lower case, CWE-0, NVD-CWE-noinfo, CWE-00079, fullwidth digits) produce no relation.',
    input: { kev: [kev({ items: [item('CVE-２０２１-0001', ['CWE-79']), item('CVE-2099-0002', ['CWE-0', 'NVD-CWE-noinfo', 'CWE-00079', 'cwe-79', 'CWE-７９', 'CWE-20'])] })],
      rule_indexes: [index({ rules: [r] })] },
    expect: { asserted: [[VHW, V('CVE-2099-0002'), W('CWE-20')], [RRS, rid(r.path, r.name), S(h)], [RRS, rid(r.path, r.name), S(near)]], candidate: [],
      rejections: { malformed_identifier: 21 } },
  };
}
// 05 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const r = { path: 'rules/community/synthetic/log4shell.yar', name: 'SYNTH_Log4Shell', meta: [['cve', 'CVE-2021-44228', 'cve'], ['hash', H('log4shell'), 'sha256']] };
  const prod = { path: 'rules/community/synthetic/log4j_generic.yar', name: 'SYNTH_Log4j_Product_Only', meta: [['sample', H('log4j-jar'), 'sha256']] };
  cases['05_cve_similar_products'] = {
    description: 'Two CVEs of the same vendor and product (and notes that mention each other) are not related to each other, and a rule that names only one of them is not associated with the other. Product, vendor and notes are never read; a rule about the product but naming no CVE gets no CVE.',
    input: { kev: [kev({ items: [item('CVE-2021-44228', ['CWE-20', 'CWE-917'], { vendor: 'Apache', product: 'Log4j2', notes: 'See also CVE-2021-45046; https://nvd.nist.gov/vuln/detail/CVE-2021-45046' }),
      item('CVE-2021-45046', ['CWE-917'], { vendor: 'Apache', product: 'Log4j2', notes: 'Incomplete fix for CVE-2021-44228' })] })], rule_indexes: [index({ rules: [r, prod] })] },
    expect: { asserted: [[VHW, V('CVE-2021-44228'), W('CWE-20')], [VHW, V('CVE-2021-44228'), W('CWE-917')], [VHW, V('CVE-2021-45046'), W('CWE-917')],
      [RAC, rid(r.path, r.name), V('CVE-2021-44228')], [RRS, rid(r.path, r.name), S(H('log4shell'))], [RRS, rid(prod.path, prod.name), S(H('log4j-jar'))]], candidate: [] },
  };
}
// 06 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const six = Array.from({ length: 6 }, (_, i) => `CVE-2099-${String(1000 + i)}`), five = Array.from({ length: 5 }, (_, i) => `CVE-2098-${String(1000 + i)}`);
  const many = Array.from({ length: 257 }, (_, i) => H(`generic ${i}`)), limit = Array.from({ length: 256 }, (_, i) => H(`limit ${i}`));
  const g1 = { path: 'rules/community/synthetic/generic.yar', name: 'SYNTH_Generic_Exploit_Kit', meta: six.map((c) => ['cve', c, 'cve']) };
  const g2 = { path: 'rules/community/synthetic/generic.yar', name: 'SYNTH_Five_CVEs', meta: five.map((c) => ['cves', c, 'cve']) };
  const g3 = { path: 'rules/community/synthetic/generic.yar', name: 'SYNTH_Hash_List_257', meta: many.map((x, i) => [`hash${i}`, x, 'sha256']) };
  const g4 = { path: 'rules/community/synthetic/generic.yar', name: 'SYNTH_Hash_List_256', meta: limit.map((x, i) => [`hash${i}`, x, 'sha256']) };
  cases['06_generic_rules'] = {
    description: 'Generic rules: more than 5 distinct CVEs or 256 distinct SHA-256 asserted by one rule lose the asserted state for all of them (candidate, generic_rule_fanout); exactly at the limit they stay asserted.',
    input: { rule_indexes: [index({ rules: [g1, g2, g3, g4] })] },
    expect: { asserted: [...five.map((c) => [RAC, rid(g2.path, g2.name), V(c)]), ...limit.map((x) => [RRS, rid(g4.path, g4.name), S(x)])],
      candidate: [...six.map((c) => [RAC, rid(g1.path, g1.name), V(c)]), ...many.map((x) => [RRS, rid(g3.path, g3.name), S(x)])] },
  };
}
// 07 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const r = { path: 'rules/community/synthetic/refs.yar', name: 'SYNTH_References', meta: [
    ['reference', 'CVE-2099-0101', 'cve', 'embedded'], ['reference', 'CVE-2099-0102', 'cve', 'whole_value'], ['description', 'CVE-2099-0103', 'cve', 'embedded'],
    ['cve_id', 'CVE-2099-0104', 'cve', 'whole_value'], ['id', 'CVE-2099-0105', 'cve', 'whole_value'], ['Vulnerability', 'CVE-2099-0106', 'cve', 'whole_value'], ['cve', 'CVE-2099-0107', 'cve', 'embedded'],
    ['imphash', H('imphash'), 'sha256', 'whole_value'], ['md5', H('mislabelled'), 'sha256', 'whole_value'], ['Hash1', H('casing'), 'sha256', 'whole_value'], ['reference', H('vt-link'), 'sha256', 'embedded'],
    ['hash2', H('in-list'), 'sha256', 'embedded'], ['sha1', H('sha1-key'), 'sha256', 'whole_value'], ['imphash', 'd'.repeat(32), 'md5', 'whole_value']] };
  cases['07_wrong_references'] = {
    description: 'Decision on references: a CVE that is the WHOLE value of an allow-listed key (cve, cves, vuln, vulnerability, reference; key compared case-insensitively) is asserted; a CVE inside a reference URL, a description or any other key is a candidate only. A hash is asserted only as the whole value of hash/hashN/sha256/sample/samples; imphash, a key naming another hash kind, a hash inside a URL or a list stay candidates. Evidence locators keep the original key case.',
    input: { kev: [kev({ items: [item('CVE-2099-0101', ['CWE-79'], { notes: 'https://example.org/CVE-2099-0102' })] })], rule_indexes: [index({ rules: [r] })] },
    expect: { asserted: [[VHW, V('CVE-2099-0101'), W('CWE-79')], [RAC, rid(r.path, r.name), V('CVE-2099-0102')], [RAC, rid(r.path, r.name), V('CVE-2099-0106')], [RRS, rid(r.path, r.name), S(H('casing'))]],
      candidate: [[RAC, rid(r.path, r.name), V('CVE-2099-0101')], [RAC, rid(r.path, r.name), V('CVE-2099-0103')], [RAC, rid(r.path, r.name), V('CVE-2099-0104')], [RAC, rid(r.path, r.name), V('CVE-2099-0105')],
        [RAC, rid(r.path, r.name), V('CVE-2099-0107')], [RRS, rid(r.path, r.name), S(H('imphash'))], [RRS, rid(r.path, r.name), S(H('mislabelled'))], [RRS, rid(r.path, r.name), S(H('vt-link'))],
        [RRS, rid(r.path, r.name), S(H('in-list'))], [RRS, rid(r.path, r.name), S(H('sha1-key'))]],
      rejections: { no_canonical_sample_identity_for_md5_sha1: 1 } },
  };
}
// 08 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  cases['08_contradicting_sources'] = {
    description: 'Contradicting sources: CISA KEV says CWE-79, an independent synthetic list says CWE-89 for the same CVE. Both statements stay asserted (each according to its source) and a conflict is reported; nothing is resolved or merged. A source that delivers two different documents under the same version is refused entirely; one catalogue that lists a CVE twice with different CWEs yields nothing for that CVE.',
    input: { kev: [kev({ items: [item('CVE-2099-0200', ['CWE-79']), item('CVE-2099-0202', ['CWE-20']), item('CVE-2099-0202', ['CWE-22'])] }), kev({ source_id: 'synthetic-list-b', origin: 'synthetic-list-b', items: [item('CVE-2099-0200', ['CWE-89'])] }),
      kev({ source_id: 'synthetic-list-c', origin: 'synthetic-list-c', upstream: sha('c1'), items: [item('CVE-2099-0201', ['CWE-20'])] }),
      kev({ source_id: 'synthetic-list-c', origin: 'synthetic-list-c', upstream: sha('c2'), items: [item('CVE-2099-0201', ['CWE-22'])] })] },
    expect: { asserted: [[VHW, V('CVE-2099-0200'), W('CWE-79')], [VHW, V('CVE-2099-0200'), W('CWE-89')]], candidate: [], conflicts: 1, refused_inputs: 1, rejections: { duplicate_item_in_snapshot: 1 } },
  };
}
// 09 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const r = { path: 'rules/community/synthetic/retract.yar', name: 'SYNTH_Retract' };
  cases['09_retracted_data'] = {
    description: 'Retracted data: a newer KEV catalogue drops CVE-2099-0301 (delisted) and changes the CWE of CVE-2099-0300; a newer signed release drops one hash from a rule. Only the latest snapshot yields relations; what only older snapshots stated is reported as retracted (history kept, never asserted). Inputs are given newest first on purpose.',
    input: { kev: [kev({ version: '2026.10.31', date: '2026-10-31T10:00:00.000Z', items: [item('CVE-2099-0300', ['CWE-89'])] }),
      kev({ version: '2026.10.30', items: [item('CVE-2099-0300', ['CWE-79']), item('CVE-2099-0301', ['CWE-20'])] })],
    rule_indexes: [index({ tag: 'rules-20261102-10', rules: [{ ...r, meta: [['hash1', H('kept'), 'sha256']] }] }), index({ tag: 'rules-20261102-9', rules: [{ ...r, meta: [['hash1', H('kept'), 'sha256'], ['hash2', H('dropped'), 'sha256']] }] })] },
    expect: { asserted: [[VHW, V('CVE-2099-0300'), W('CWE-89')], [RRS, rid(r.path, r.name), S(H('kept'))]], candidate: [],
      retracted: [[VHW, V('CVE-2099-0300'), W('CWE-79')], [VHW, V('CVE-2099-0301'), W('CWE-20')], [RRS, rid(r.path, r.name), S(H('dropped'))]] },
  };
}
// 10 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const base = { items: [item('CVE-2099-0400', ['CWE-79'])] };
  const r = { path: 'rules/community/synthetic/dup.yar', name: 'SYNTH_Duplicate', meta: [['hash1', H('dup'), 'sha256', 'whole_value', 5], ['sample', H('dup'), 'sha256', 'whole_value', 6]] };
  const ix = index({ rules: [r] });
  ix.document.assertions.push(structuredClone(ix.document.assertions[0]));   // the very same assertion twice
  cases['10_duplicate_evidence'] = {
    description: 'Duplicate evidence from one original source counts once: the same KEV document delivered twice is one evidence row; an aggregator republishing KEV (source_id enisa-euvd-exploited, original cisa-kev) adds an evidence row but NOT an independent source; a rule repeating one hash under two keys (and one assertion duplicated verbatim) is one relation with independent_sources = 1.',
    input: { kev: [kev(base), kev(base), kev({ source_id: 'enisa-euvd-exploited', upstream: sha('aggregator copy'), ...base })], rule_indexes: [ix] },
    expect: { asserted: [[VHW, V('CVE-2099-0400'), W('CWE-79')], [RRS, rid(r.path, r.name), S(H('dup'))]], candidate: [],
      evidence_rows: { [`${VHW} ${V('CVE-2099-0400')} ${W('CWE-79')}`]: 2, [`${RRS} ${rid(r.path, r.name)} ${S(H('dup'))}`]: 2 }, independent_sources_all: 1 },
  };
}
// 11 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const a = { path: 'rules/community/synthetic/trans.yar', name: 'SYNTH_A_Hash_Only', meta: [['hash', H('shared'), 'sha256']] };
  const b = { path: 'rules/community/synthetic/trans.yar', name: 'SYNTH_B_Hash_And_CVE', meta: [['hash', H('shared'), 'sha256'], ['cve', 'CVE-2099-0500', 'cve']] };
  cases['11_false_transitivity'] = {
    description: 'No transitivity: rule A mentions hash H; rule B mentions H and CVE C; KEV lists C with CWE-79. A is NOT associated with C, no rule gets a weakness, and the hash gets no CVE: every relation comes from one statement.',
    input: { kev: [kev({ items: [item('CVE-2099-0500', ['CWE-79'])] })], rule_indexes: [index({ rules: [a, b] })] },
    expect: { asserted: [[VHW, V('CVE-2099-0500'), W('CWE-79')], [RRS, rid(a.path, a.name), S(H('shared'))], [RRS, rid(b.path, b.name), S(H('shared'))], [RAC, rid(b.path, b.name), V('CVE-2099-0500')]], candidate: [],
      forbidden: [[RAC, rid(a.path, a.name), V('CVE-2099-0500')], [VHW, rid(a.path, a.name), W('CWE-79')], [VHW, rid(b.path, b.name), W('CWE-79')]] },
  };
}
// 12 ---------------------------------------------------------------------------------------------------------------------------------------------------
{
  const dir = 'rules/' + 'd'.repeat(99) + '/' + 'e'.repeat(99) + '/' + 'f'.repeat(99) + '/';
  const longPath = dir + 'g'.repeat(400 - dir.length - 4) + '.yar';            // 400 characters: the longest valid release path
  const fitPath = dir + 'g'.repeat(512 - 1 - 128 - dir.length - 4) + '.yar';  // key = path + '#' + 128-char name = 512 exactly
  const n128 = 'N' + 'x'.repeat(127);
  const big = { path: longPath, name: n128, meta: [['hash', H('too-long'), 'sha256']] };
  const fit = { path: fitPath, name: n128, meta: [['hash', H('fits'), 'sha256']] };
  const stray = { id: 'assert:' + sha('stray'), type: 'rule_meta_mentions_hash', subject: 'yara:rules/community/x/absent.yar#Absent', value: H('stray'), value_kind: 'sha256', meta_key: 'hash', match: 'whole_value', status: 'asserted_by_rule_metadata', provenance: { release_tag: 'rules-20261102-1', path: 'rules/community/x/absent.yar', file_sha256: sha('x'), line: 3 } };
  const ix = index({ rules: [big, fit], raw: [stray] });
  const forged = structuredClone(ix.document.assertions[1]); forged.provenance.file_sha256 = sha('forged'); forged.value = H('forged'); ix.document.assertions.push(forged);
  const otherStatus = structuredClone(ix.document.assertions[1]); otherStatus.status = 'correlated'; otherStatus.value = H('status'); ix.document.assertions.push(otherStatus);
  cases['12_identity_and_provenance'] = {
    description: 'A valid rule identity can be 529 characters but intel_entities.key holds 512: such a rule is refused (never truncated) and its assertions with it; a 512-character key is accepted. Assertions whose subject is not in the index, whose provenance does not match the rule (forged file hash) or whose status is not asserted_by_rule_metadata are refused.',
    input: { rule_indexes: [ix] },
    expect: { asserted: [[RRS, rid(fit.path, fit.name), S(H('fits'))]], candidate: [],
      rejections: { rule_key_exceeds_db_limit: 1, subject_rejected: 1, subject_not_in_index: 1, provenance_mismatch: 1, bad_status: 1 } },
  };
}

// 13/14 ------------------------------------------------------------------------------------------------------------------------------------------------
// Regression (Codex correlation-engine-c4 round 1, MEDIUM): the same source and version with different CONTENT but the same claimed upstream_sha256 must
// be refused in BOTH input orders (it was deduplicated by the claimed hash, so the first document won). The same class for rule indexes (same tag and
// manifest_sha256, different assertion), plus latest-snapshot selection between two versions released at the same instant.
{
  const original = cases['01_verified_relations'].input.kev[0], clone = structuredClone(original);
  clone.document.items[0].cwes = ['CWE-89'];
  const r = { path: 'rules/community/synthetic/conflict.yar', name: 'SYNTH_Conflict' };
  const ixA = index({ tag: 'rules-20261102-5', rules: [{ ...r, meta: [['hash', H('variant-a'), 'sha256']] }] }), ixB = index({ tag: 'rules-20261102-5', rules: [{ ...r, meta: [['hash', H('variant-b'), 'sha256']] }] });
  const sameAgain = structuredClone(ixA); sameAgain.document.entities.reverse(); sameAgain.document.assertions.reverse();   // identical content, other order
  const t1 = kev({ source_id: 'synthetic-list-t', origin: 'synthetic-list-t', version: '2026.10.30', items: [item('CVE-2099-0600', ['CWE-20'])] });
  const t2 = kev({ source_id: 'synthetic-list-t', origin: 'synthetic-list-t', version: '2026.10.30.1', items: [item('CVE-2099-0600', ['CWE-22'])] });
  const okIx = index({ source_id: 'synthetic-release-ok', tag: 'rules-20261102-7', rules: [{ ...r, meta: [['hash', H('ok'), 'sha256']] }] });
  const expect = { asserted: [[VHW, V('CVE-2099-0600'), W('CWE-22')], [RRS, rid(r.path, r.name), S(H('ok'))]], candidate: [],
    retracted: [[VHW, V('CVE-2099-0600'), W('CWE-20')]], refused_inputs: 2 };
  const description = (order) => `Regression, ${order}: one KEV catalogue version delivered twice with the same claimed upstream_sha256 but a different CWE list (cisa-kev) is refused whatever the input order; so is one release tag with the same manifest_sha256 but a different assertion; a reordered identical copy is deduplicated, not a conflict; between two versions released at the same instant the later version string wins.`;
  cases['13_snapshot_conflict_order_a'] = { description: description('original first'), input: { kev: [original, clone, t2, t1], rule_indexes: [ixA, ixB, sameAgain, okIx] }, expect };
  cases['14_snapshot_conflict_order_b'] = { description: description('clone first'), input: { kev: [clone, original, t1, t2], rule_indexes: [sameAgain, ixB, ixA, okIx].reverse() }, expect };
}

const writeExpected = process.argv.includes('--write-expected');
for (const [name, c] of Object.entries(cases)) {
  const dir = new URL(`${name}/`, HERE); mkdirSync(dir, { recursive: true });
  writeFileSync(new URL('case.json', dir), JSON.stringify(c, null, 1) + '\n');
  if (writeExpected) writeFileSync(new URL('expected.json', dir), serialize(correlate(c.input)));
}
console.log(`${Object.keys(cases).length} cases${writeExpected ? ' (expected outputs rewritten: review the diff)' : ''}`);
