// JS port of the parts of scripts/intel_ids.py that the correlation engine needs: normalize(kind, text) for cve, cwe, sha256, sha1, md5 and yara_rule.
// scripts/intel_ids.py is the reference: test/intel_ids_parity.test.js runs both on the same adversarial inputs (python3 -I) and requires identical results.
// Every pattern is ASCII-only, as in Python (re.ASCII): fullwidth or Arabic-Indic digits, the Kelvin sign or the long s never become an identifier.
// This module is NOT intel_graph.js normalizeKey(): that one is the database key normaliser and disagrees with intel_ids.py on some inputs
// (listed by the parity test, not changed here).

export const MAX_INPUT = 2048;
export const MAX_RULE_NAME = 128;
export const MAX_YARA_PATH = 400;
export const KINDS = ['cve', 'cwe', 'sha256', 'sha1', 'md5', 'yara_rule'];

// Python str.strip() with no argument removes the characters for which str.isspace() is true. JS String.prototype.trim() uses a different set
// (it strips U+FEFF but not U+001C-U+001F or U+0085), so the Python set is spelled out here. The parity test checks this set against Python.
export const PY_WHITESPACE = '\t\n\u000b\u000c\r\u001c\u001d\u001e\u001f \u0085                 　';
const WS = new Set(PY_WHITESPACE);
export function pyStrip(s) {
  let a = 0, b = s.length;
  while (a < b && WS.has(s[a])) a++;
  while (b > a && WS.has(s[b - 1])) b--;
  return s.slice(a, b);
}
const CTRL = /[\x00-\x1f\x7f]/;
const ASCII_WS = '[ \\t\\n\\r\\f\\v]';   // Python's \s under re.ASCII

/** Trimmed text, or null when it is not a string, empty, longer than MAX_INPUT code points or carries a control character (intel_ids._clean). */
function clean(text) {
  if (typeof text !== 'string') return null;
  const t = pyStrip(text);
  if (!t || [...t].length > MAX_INPUT || CTRL.test(t)) return null;
  return t;
}

const RX_CVE = /^CVE([-_ ])([0-9]{4})\1([0-9]{4,7})$/i;
const RX_CWE = /^CWE-([0-9]{1,5})$/i;
const RX_HEX = /^[0-9a-fA-F]+$/;
const RX_HASH_PREFIX = new RegExp(`^(sha-?256|sha-?1|md5)${ASCII_WS}*[:=]${ASCII_WS}*([^\\n]+)$`, 'i');   // Python '.' = anything but \n
const HASH_LEN = { 64: 'sha256', 40: 'sha1', 32: 'md5' };
const RX_IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RX_YARA_PATH = /^[A-Za-z0-9._\-/ +@()[\]]+\.(?:yara|yar)$/i;
const YARA_KEYWORDS = new Set(`all and any ascii at base64 base64wide condition contains defined endswith entrypoint false filesize for fullword global
 icontains iendswith iequals import in include int16 int16be int32 int32be int8 int8be istartswith matches meta nocase none not of or private rule
 startswith strings them true uint16 uint16be uint32 uint32be uint8 uint8be wide xor`.split(/\s+/).filter(Boolean));

function cve(t) {
  const m = RX_CVE.exec(t);
  if (!m) return null;
  if (m[3].length > 4 && m[3][0] === '0') return null;   // CVE sequences of 5+ digits carry no leading zero
  return `CVE-${m[2]}-${m[3]}`;
}
function cwe(t) {
  const m = RX_CWE.exec(t);
  if (!m || Number(m[1]) === 0) return null;
  return `CWE-${Number(m[1])}`;
}
const hash = (kind) => (t) => {
  const m = RX_HASH_PREFIX.exec(t);
  if (m) {
    if (m[1].toLowerCase().replace(/-/g, '') !== kind) return null;
    t = pyStrip(m[2]);
  }
  return RX_HEX.test(t) && HASH_LEN[t.length] === kind ? t.toLowerCase() : null;
};
function yaraRule(t) {
  const body = t.startsWith('yara:') ? t.slice(5) : t;
  let path, name, i;
  if (t.startsWith('yara:') && body.includes('#')) { i = body.lastIndexOf('#'); path = body.slice(0, i); name = body.slice(i + 1); }
  else if (body.includes(':')) { i = body.lastIndexOf(':'); path = body.slice(0, i); name = body.slice(i + 1); }
  else return null;
  if (path.length > MAX_YARA_PATH || !RX_YARA_PATH.test(path) || path.split('/').some((s) => s === '' || s === '.' || s === '..')) return null;
  if (!RX_IDENT.test(name) || name.length > MAX_RULE_NAME || YARA_KEYWORDS.has(name)) return null;
  return `yara:${path}#${name}`;
}
const PARSERS = { cve, cwe, sha256: hash('sha256'), sha1: hash('sha1'), md5: hash('md5'), yara_rule: yaraRule };

/** Canonical form of `text` as `kind`, or throws (like intel_ids.normalize raises ValueError). */
export function normalize(kind, text) {
  if (!Object.hasOwn(PARSERS, kind)) throw new Error(`unknown kind ${kind}`);
  const t = clean(text);
  const r = t === null ? null : PARSERS[kind](t);
  if (r === null) throw new Error(`not a ${kind}`);
  return r;
}
/** normalize() or null, never throws. */
export function tryNormalize(kind, text) { try { return normalize(kind, text); } catch { return null; } }
/** True when `text` is already the canonical form of `kind` (the engine accepts only canonical identifiers from its inputs). */
export const isCanonical = (kind, text) => typeof text === 'string' && tryNormalize(kind, text) === text;
