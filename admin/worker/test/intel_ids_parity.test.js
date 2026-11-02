// Parity of src/intel_ids.js (the engine's identifier rules) with the reference scripts/intel_ids.py, run under `python3 -I` on the same inputs.
// Also DOCUMENTS (does not change) where intel_graph.js normalizeKey(), the database key normaliser, disagrees with intel_ids.py: the list is pinned so a
// new disagreement fails loudly. The engine never uses normalizeKey to decide a relation; it accepts only values that are canonical under intel_ids.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { normalize, tryNormalize, PY_WHITESPACE, KINDS } from '../src/intel_ids.js';
import { normalizeKey } from '../src/intel_graph.js';

const SCRIPTS = fileURLToPath(new URL('../../../scripts/', import.meta.url));
function python(code, input) {
  const r = spawnSync('python3', ['-I', '-c', code, SCRIPTS], { input, encoding: 'utf8', maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `python3 -I failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}
const PY_NORMALIZE = `import sys, json
sys.path.insert(0, sys.argv[1])
import intel_ids
out = []
for kind, text in json.load(sys.stdin):
    try: out.append(intel_ids.normalize(kind, text))
    except ValueError: out.append(None)
print(json.dumps(out))`;

function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const H64 = '3bbeb47c53c998f35aabb8bc739ba268c00e73b2e3a7a2cf9a4a5d0c1c3f7e21';
const SEEDS = {
  cve: ['CVE-2021-44228', 'cve-2021-44228', 'CVE_2021_44228', 'CVE 2021 44228', 'CVE-2021_44228', 'CVE-2024-01234', 'CVE-2024-0123', 'CVE-2024-1234567', 'CVE-2024-12345678', 'CVE-24-1234',
    'CVE-２０２１-44228', 'CVE-٢٠٢١-44228', ' CVE-2021-44228 ', ' CVE-2021-44228', '﻿CVE-2021-44228', '\u001cCVE-2021-44228', '\u0085CVE-2021-44228', 'CVE-2021-44228 ',
    'CVE-2021-44228\n', 'CVE‐2021‐44228', 'ＣVE-2021-44228', 'CVE-2021-44228x', 'GCVE-0-2021-44228', ''],
  cwe: ['CWE-79', 'cwe-79', 'CWE-0', 'CWE-00079', 'CWE-000079', 'CWE-99999', 'CWE-100000', 'NVD-CWE-noinfo', 'CWE-７９', 'CWE-٧٩', ' CWE-79', 'CWE79', 'CWE-'],
  sha256: [H64, H64.toUpperCase(), H64.slice(0, 63), H64 + 'a', `sha256:${H64}`, `SHA-256 = ${H64}`, `sha1:${H64}`, `sha256:${H64} `, `sha256: ${H64}`, `md5=${H64}`, '０' + H64.slice(1), H64.slice(0, 32) + '​' + H64.slice(32), ` ${H64}\t`, `\u0085${H64}`],
  sha1: [H64.slice(0, 40), H64.slice(0, 40).toUpperCase(), `sha1: ${H64.slice(0, 40)}`, `SHA-1=${H64.slice(0, 40)}`, `sha-1 :${H64.slice(0, 40)}`, H64.slice(0, 39), `sha256:${H64.slice(0, 40)}`],
  md5: [H64.slice(0, 32), `md5:${H64.slice(0, 32)}`, `MD5 = ${H64.slice(0, 32)}`, H64.slice(0, 31) + 'G', H64.slice(0, 33), `md5:${H64.slice(0, 32)} `],
  yara_rule: ['yara:rules/a/b.yar#Rule_1', 'yara:rules/a/b.YARA#Rule_1', 'rules/a/b.yar:Rule_1', 'yara:rules/a/../b.yar#R', 'yara:rules//b.yar#R', 'yara:rules/a/b.yar#rule', 'yara:rules/a/b.yar#1R',
    'yara:rules/a/b.txt#R', 'yara:rules/a b+(c)[d]@e.yar#R', `yara:${'p/'.repeat(199)}x.yar#R`, `yara:${'p'.repeat(396)}.yar#${'N'.repeat(128)}`, `yara:${'p'.repeat(397)}.yar#N`, `yara:rules/a.yar#${'N'.repeat(129)}`,
    'yara:rules/a.yar#Ｒ', 'yara:rules/ä.yar#R', 'yara:rules/a.yar#R#S', 'yara:rules/a#b.yar#R', 'yara:rules/a.yar:R', 'R'],
};
function corpus() {
  const r = rng(424242), out = [];
  const muts = [(s) => s, (s) => s.toLowerCase(), (s) => s.toUpperCase(), (s) => ` ${s}`, (s) => `${s}　`, (s) => s.replace(/[0-9]/, (d) => String.fromCharCode(0xff10 + +d)),
    (s) => s.replace(/-/, '_'), (s) => s.slice(1), (s) => s + s.at(-1), (s) => `\u001f${s}`, (s) => `${s}\u0085`, (s) => `﻿${s}`, (s) => s.replace(/[0-9]/, (d) => String.fromCharCode(0x0660 + +d))];
  for (const kind of KINDS) for (const s of SEEDS[kind]) { out.push([kind, s]); for (let i = 0; i < 6; i++) out.push([kind, muts[Math.floor(r() * muts.length)](s)]); }
  for (const kind of KINDS) for (const s of Object.values(SEEDS).flat().slice(0, 40)) out.push([kind, s]);   // cross-kind
  out.push(['cve', 'x'.repeat(2049)], ['cve', ' '.repeat(3000) + 'CVE-2021-44228'], ['md5', 5], ['md5', null]);
  return out;
}

test('parity: src/intel_ids.js normalize() equals scripts/intel_ids.py normalize() on an adversarial corpus', () => {
  const inputs = corpus(), py = python(PY_NORMALIZE, JSON.stringify(inputs));
  assert.equal(py.length, inputs.length);
  const diff = inputs.map(([k, t], i) => [k, t, tryNormalize(k, t), py[i]]).filter(([, , js, p]) => js !== p);
  assert.deepEqual(diff, [], 'JS and Python disagree');
  assert.ok(py.filter((x) => x !== null).length > 40 && py.filter((x) => x === null).length > 100, 'both accepting and refusing inputs are exercised');
  assert.throws(() => normalize('ipv4', '1.1.1.1'), /unknown kind/);
});

test('parity: the Python str.strip() whitespace set is exactly PY_WHITESPACE', () => {
  const py = python('import json\nprint(json.dumps([c for c in range(0x110000) if chr(c).isspace()]))', '');
  assert.deepEqual([...PY_WHITESPACE].map((c) => c.codePointAt(0)), py);
});

// intel_graph.js normalizeKey (database keys) vs intel_ids.py: DOCUMENTED disagreements (input for the contract review; intel_graph.js is not changed here).
const GRAPH_NS = { cve: ['vulnerability', 'cve'], cwe: ['weakness', 'cwe'], sha256: ['sample', 'sha256'], sha1: ['indicator', 'sha1'], md5: ['indicator', 'md5'] };
export const KNOWN_GRAPH_DISAGREEMENTS = [
  // [kind, input, intel_graph normalizeKey, intel_ids.py]
  ['cve', 'CVE-2024-01234', 'CVE-2024-01234', null],                 // 5+ digit sequence with a leading zero: graph accepts, intel_ids refuses
  ['cve', 'CVE-2024-12345678', 'CVE-2024-12345678', null],           // 8+ digits: graph has no upper bound, intel_ids caps at 7
  ['cve', 'CVE_2021_44228', null, 'CVE-2021-44228'],                 // separators: intel_ids accepts _ and space (confidence 'pattern'), graph refuses
  ['cve', 'CVE 2021 44228', null, 'CVE-2021-44228'],
  ['cwe', 'CWE-0', 'CWE-0', null],                                   // CWE-0: graph accepts, intel_ids refuses
  ['cwe', 'CWE-000079', 'CWE-79', null],                             // 6 digits: graph accepts 1-6, intel_ids 1-5
  ['cwe', 'CWE-100000', 'CWE-100000', null],
  ['sha256', `sha256:${H64}`, null, H64],                            // labelled hash: intel_ids strips the label, graph refuses
  ['sha256', 'AB:'.repeat(31) + 'AB', 'ab'.repeat(32), null],        // colon-separated hex: graph strips ':', intel_ids refuses
  ['sha256', '﻿' + H64, H64, null],                             // JS trim() strips U+FEFF; Python strip() does not
  ['sha256', '\u001c' + H64, null, H64],                             // Python strip() removes U+001C-U+001F; JS trim() does not
  ['sha1', `sha1: ${H64.slice(0, 40)}`, null, H64.slice(0, 40)],
  ['md5', `md5:${H64.slice(0, 32)}`, null, H64.slice(0, 32)],
];
test('documented: intel_graph.js normalizeKey vs intel_ids.py disagreements are exactly the pinned list', () => {
  const probe = [...corpus().filter(([k]) => GRAPH_NS[k]), ...KNOWN_GRAPH_DISAGREEMENTS.map(([k, t]) => [k, t])];
  const py = python(PY_NORMALIZE, JSON.stringify(probe));
  const g = (k, t) => { try { return normalizeKey(GRAPH_NS[k][0], GRAPH_NS[k][1], t); } catch { return null; } };
  const seen = new Map();
  probe.forEach(([k, t], i) => { const a = g(k, t); if (a !== py[i]) seen.set(JSON.stringify([k, t]), [k, t, a, py[i]]); });
  for (const d of KNOWN_GRAPH_DISAGREEMENTS) assert.deepEqual(seen.get(JSON.stringify([d[0], d[1]])), d, `pinned disagreement ${d[1]}`);
  const unpinned = [...seen.values()].filter(([k, t]) => !KNOWN_GRAPH_DISAGREEMENTS.some((d) => d[0] === k && d[1] === t));
  // every unpinned disagreement must belong to one of the pinned CLASSES above (labels, separators, leading zero, digit caps, CWE-0, BOM/U+001C-1F, colons)
  const classOf = ([k, t, a, p]) => (/^(sha-?256|sha-?1|md5)\s*[:=]/i.test(t.trim?.() ?? '') ? 'label' : /[﻿\u001c-\u001f\u0085]/.test(t) ? 'strip-set'
    : /CVE[_ ]/i.test(t) ? 'separator' : /^CVE-\d{4}-0\d{4,}$/i.test(t.trim()) ? 'leading-zero' : /CVE-\d{4}-\d{8,}/i.test(t) ? 'cve-cap' : /CWE-0+(?![0-9])|CWE-\d{6}/i.test(t) ? 'cwe' : 'other');
  const other = unpinned.filter((d) => classOf(d) === 'other');
  assert.deepEqual(other, [], 'a disagreement outside the documented classes');
});
