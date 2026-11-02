#!/usr/bin/env python3
"""One deterministic identifier normaliser and classifier for the Threat Intelligence Hub (stdlib only).

classify(text) -> [Candidate(kind, normalized, confidence)]: every kind the WHOLE input could syntactically be, best first.
normalize(kind, text) -> canonical string, or ValueError when the text is not that kind.
extract_hashes(text) / extract_cves(text): identifiers embedded in free text (rule metadata), with the same normalisation.

Pure syntax: a candidate says what a string looks like, never that it is related to anything, known, malicious or present anywhere.
Confidence: 'exact' = the canonical form of that kind, nothing to guess; 'pattern' = well formed but a lenient spelling was accepted
(refanged IOC, prefix, separator, Unicode domain) or the syntax alone cannot prove the kind (a domain could be a file name);
'ambiguous' = another kind fits as well (a bare UUID may or may not be a Sigma id; a bare word may be a YARA rule name).

Kept consistent with web/common.js (CVE, EUVD, GCVE, GHSA, CWE, SHA256, SHA1, MD5, SID) and scripts/portal_hub.py (CVE 4-7 digits,
CWE 1-5 digits). Deliberate differences from common.js: a CVE sequence of 5+ digits may not start with 0 and is at most 7 digits; CWE-0 is
rejected. There is no MacGuard identifier namespace in the repository (the `mg-<hex>` event ids in contracts/v1 are operations events, not
intelligence ids), so no 'macguard' kind is invented here.
"""
import encodings.idna  # noqa: F401  (registers the 'idna' codec under -I as well)
import ipaddress, re, unicodedata
# Every pattern is compiled with re.ASCII: Python's \d, \s, \w and IGNORECASE are Unicode-aware by default, and fullwidth or Arabic-Indic
# digits, or the Kelvin sign and long s under IGNORECASE, must never become an identifier. The one Unicode-aware step is IDNA for domains.
from typing import NamedTuple
from urllib.parse import quote, urlsplit

MAX_INPUT = 2048          # longer input is never classified (URLs are the longest kind)
MAX_RULE_NAME = 128       # YARA identifier limit
MAX_YARA_PATH = 400       # tlog.check_inventory path limit
MAX_YARA_ID = len('yara:') + MAX_YARA_PATH + len('#') + MAX_RULE_NAME   # longest valid rule identity (534)
CONFIDENCE_ORDER = ('exact', 'pattern', 'ambiguous')
KINDS = ('cve', 'euvd', 'gcve', 'ghsa', 'cwe', 'sha256', 'sha1', 'md5', 'ipv4', 'ipv6', 'domain', 'url', 'cpe23', 'suricata_sid',
         'uuid', 'sigma_id', 'yara_rule', 'yara_rule_name')


class Candidate(NamedTuple):
    kind: str
    normalized: str
    confidence: str


_CTRL = re.compile(r'[\x00-\x1f\x7f]', re.A)
_CVE = re.compile(r'CVE([-_ ])(\d{4})\1(\d{4,7})', re.I | re.A)
_EUVD = re.compile(r'EUVD-(\d{4})-(\d+)', re.I | re.A)   # sequence length as web/common.js (bounded by MAX_INPUT)
_GCVE = re.compile(r'GCVE-(\d{1,9})-(\d{4})-(\d+)', re.I | re.A)
_GHSA = re.compile(r'GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}', re.I | re.A)
_CWE = re.compile(r'CWE-(\d{1,5})', re.I | re.A)
_HEX = re.compile(r'[0-9a-fA-F]+', re.A)
_HASH_PREFIX = re.compile(r'(sha-?256|sha-?1|md5)\s*[:=]\s*(.+)', re.I | re.A)
_HASH_LEN = {64: 'sha256', 40: 'sha1', 32: 'md5'}
_UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', re.A)
_SIGMA_PREFIX = re.compile(r'sigma\s*[: ]\s*(.+)', re.I | re.A)
_SID = (re.compile(r'sid\s*:\s*(\d{1,10})\s*;?', re.I | re.A), re.compile(r'sid\s+(\d{1,10})', re.I | re.A), re.compile(r'\d{1,3}:(\d{1,10})', re.A))
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', re.A)
_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*', re.A)
_YARA_PATH = re.compile(r'[A-Za-z0-9._\-/ +@()\[\]]+\.(?:yara|yar)', re.I | re.A)   # the release path charset (tlog.check_inventory); length checked against MAX_YARA_PATH
_YARA_KEYWORDS = frozenset('''all and any ascii at base64 base64wide condition contains defined endswith entrypoint false filesize for fullword global
 icontains iendswith iequals import in include int16 int16be int32 int32be int8 int8be istartswith matches meta nocase none not of or private rule
 startswith strings them true uint16 uint16be uint32 uint32be uint8 uint8be wide xor'''.split())
# Last labels that are also common file extensions: such a "domain" is as likely a file name (several are real TLDs: zip, py, sh, mov).
_FILE_EXT_TLDS = frozenset('yar yara exe dll sys bin json txt log zip rar gz tgz tar py sh js mov pdf doc docx xls xlsx ps1 bat vbs jar apk dmg pkg app plist conf cfg ini xml html htm php'.split())
_DEFANG = ((re.compile(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)', re.I | re.A), '.'), (re.compile(r'\[:\]', re.A), ':'), (re.compile(r'\[://\]', re.A), '://'),
           (re.compile(r'^hxxp', re.I | re.A), 'http'), (re.compile(r'^h\[tt\]p', re.I | re.A), 'http'))


def _clean(text):
    """Trimmed text, or None when it is empty, too long or carries control characters."""
    if not isinstance(text, str): return None
    t = text.strip()
    if not t or len(t) > MAX_INPUT or _CTRL.search(t): return None
    return t


def _refang(t):
    out = t
    for rx, rep in _DEFANG: out = rx.sub(rep, out)
    return out, out != t


# ---- one parser per kind: text (already cleaned) -> (normalized, confidence) or None ------------------------------------------------------
def _cve(t):
    m = _CVE.fullmatch(t)
    if not m: return None
    seq = m.group(3)
    if len(seq) > 4 and seq[0] == '0': return None   # CVE sequences of 5+ digits carry no leading zero
    return f'CVE-{m.group(2)}-{seq}', ('exact' if m.group(1) == '-' else 'pattern')


def _euvd(t):
    m = _EUVD.fullmatch(t)
    return (f'EUVD-{m.group(1)}-{m.group(2)}', 'exact') if m else None


def _gcve(t):
    m = _GCVE.fullmatch(t)
    return (f'GCVE-{m.group(1)}-{m.group(2)}-{m.group(3)}', 'exact') if m else None


def _ghsa(t):
    return ('GHSA' + t[4:].lower(), 'exact') if _GHSA.fullmatch(t) else None


def _cwe(t):
    m = _CWE.fullmatch(t)
    if not m or int(m.group(1)) == 0: return None
    return f'CWE-{int(m.group(1))}', 'exact'


def _hash(kind):
    def parse(t):
        conf = 'exact'
        m = _HASH_PREFIX.fullmatch(t)
        if m:
            if m.group(1).lower().replace('-', '') != kind: return None
            t, conf = m.group(2).strip(), 'pattern'
        if _HEX.fullmatch(t) and _HASH_LEN.get(len(t)) == kind: return t.lower(), conf
        return None
    return parse


def _ipv4(t):
    t, refanged = _refang(t)
    try: ip = ipaddress.IPv4Address(t)   # rejects leading zeros (octal ambiguity), out-of-range octals, short forms
    except ValueError: return None
    return str(ip), ('pattern' if refanged else 'exact')


def _ipv6(t):
    t, refanged = _refang(t)
    if t.startswith('[') and t.endswith(']'): t = t[1:-1]
    if '%' in t or ':' not in t: return None   # zone ids are host-local, never an indicator
    try: ip = ipaddress.IPv6Address(t)
    except ValueError: return None
    return ip.compressed, ('pattern' if refanged else 'exact')


def _scripts(label):
    """Unicode scripts of the letters of a label, approximated by the first word of each character name (LATIN, CYRILLIC, GREEK, ...)."""
    out = set()
    for ch in label:
        if ch.isalpha(): out.add(unicodedata.name(ch, 'UNKNOWN').split(' ')[0])
    return out


def _host(t):
    """ASCII lowercase host for a domain name: IDNA (2003, stdlib) to punycode, no trailing dot, at least two labels, valid LDH labels, a
    non-numeric last label. Returns (host, confidence) or None."""
    if not t or any(c in t for c in ' /\\@:?#[]'): return None
    conf = 'pattern'
    try:
        if not t.isascii():
            if any(len(_scripts(lbl)) > 1 for lbl in re.split(r'[.。．｡]', t)): conf = 'ambiguous'   # mixed-script label: homograph
            host = t.encode('idna').decode('ascii')
        else:
            host = t
    except (UnicodeError, ValueError):
        return None
    host = host.lower()
    if host.endswith('.'): host = host[:-1]
    labels = host.split('.')
    if len(host) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(lbl) for lbl in labels): return None
    tld = labels[-1]
    if tld.isdigit() or not (tld.isalpha() or tld.startswith('xn--')): return None
    if any(lbl[2:4] == '--' and not lbl.startswith('xn--') for lbl in labels): return None   # reserved R-LDH labels
    if tld in _FILE_EXT_TLDS: conf = 'ambiguous'
    return host, conf


def _domain(t):
    t, refanged = _refang(t)
    if _ipv4(t): return None
    r = _host(t)
    if not r: return None
    return r[0], ('ambiguous' if r[1] == 'ambiguous' else 'pattern')


def _url(t):
    t, refanged = _refang(t)
    if not re.match(r'https?://', t, re.I | re.A): return None
    try:
        s = urlsplit(t)
        port = s.port
    except ValueError:
        return None
    if port == 0: return None   # port 0 is not a destination
    hostname = s.hostname
    if not hostname: return None
    conf = 'pattern' if refanged else 'exact'
    if '[' in s.netloc:
        h = _ipv6(hostname)
        host = f'[{h[0]}]' if h else None
    else:
        h = _ipv4(hostname) or _host(hostname)
        host = h[0] if h else None
        if h and h[1] == 'ambiguous': conf = 'ambiguous'
    if not host: return None
    if '@' in s.netloc: conf = 'ambiguous'   # userinfo dropped: "http://bank.example@evil.example/" is evil.example
    scheme = s.scheme.lower()
    if port is not None and port != {'http': 80, 'https': 443}[scheme]: host += f':{port}'
    # ASCII output only: non-ASCII and spaces are percent-encoded (UTF-8); existing %XX escapes are kept as written (nothing is merged)
    path = quote(s.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = quote(s.query, safe="/%:@!$&'()*+,;=?-._~")
    if not hostname.isascii(): conf = 'pattern' if conf == 'exact' else conf   # IDNA ran: the punycode host is a display transformation
    return f'{scheme}://{host}{path}' + (f'?{query}' if query else ''), conf


# CPE 2.3 formatted string, the official grammar (NISTIR 7695 §6.2; the regex of the NVD CPE 2.3 dictionary schema): each attribute is
# '*', '-' or a value of [A-Za-z0-9._-] and backslash-escaped punctuation, with '*'/'?' wildcards only at the ends; language is a tag.
_CPE_AV = r'(?:(?:\?*|\*?)(?:[a-zA-Z0-9\-._]|\\[\\*?!"#$%&'"'"'()+,/:;<=>@\[\]^`{|}~])+(?:\?*|\*?)|[*\-])'
_CPE23 = re.compile(r'cpe:2\.3:[aho*\-](?::' + _CPE_AV + r'){5}(?::(?:[a-zA-Z]{2,3}(?:-(?:[a-zA-Z]{2}|[0-9]{3}))?|[*\-]))(?::' + _CPE_AV + r'){4}', re.ASCII)


def _cpe23(t):
    if not t.isascii() or not t.lower().startswith('cpe:2.3:'): return None   # a CPE 2.3 formatted string is printable ASCII
    if not _CPE23.fullmatch(t): return None   # unescaped space or punctuation, wrong arity, empty or misplaced wildcard: not a CPE
    # an identifier names a concrete part, vendor and product and has no wildcard inside any value; otherwise it is a matching PATTERN
    attrs = re.split(r'(?<!\\):', t, flags=re.A)[2:]
    concrete = lambda v: v not in ('*', '-') and not re.search(r'(?<!\\)[*?]', v, re.A)
    wild_inside = any(v not in ('*', '-') and re.search(r'(?<!\\)[*?]', v, re.A) for v in attrs)
    exact = attrs[0].lower() in ('a', 'o', 'h') and concrete(attrs[1]) and concrete(attrs[2]) and not wild_inside
    return t.lower(), 'exact' if exact else 'pattern'


def _sid(t):
    for i, rx in enumerate(_SID):
        m = rx.fullmatch(t)
        if m:
            n = int(m.group(1))
            if not 1 <= n <= 0xFFFFFFFF: return None
            return f'sid:{n}', ('exact' if i == 0 else 'pattern')
    return None


def _uuid_text(t):
    conf = 'exact'
    low = t.lower()
    if low.startswith('urn:uuid:'): t, conf = t[9:], 'pattern'
    elif t.startswith('{') and t.endswith('}'): t, conf = t[1:-1], 'pattern'
    return (t.lower(), conf) if _UUID.fullmatch(t) else None


def _uuid(t):
    return _uuid_text(t)


def _sigma(t):
    m = _SIGMA_PREFIX.fullmatch(t)
    if m:
        r = _uuid_text(m.group(1).strip())
        return (r[0], 'exact') if r else None
    r = _uuid_text(t)
    return (r[0], 'ambiguous') if r else None   # a bare UUID is a Sigma id only if the caller's context says so


def _yara_rule(t):
    body = t[5:] if t.startswith('yara:') else t
    if t.startswith('yara:') and '#' in body: path, _, name = body.rpartition('#')
    elif ':' in body: path, _, name = body.rpartition(':')
    else: return None
    if len(path) > MAX_YARA_PATH or not _YARA_PATH.fullmatch(path) or any(seg in ('', '.', '..') for seg in path.split('/')): return None
    if not _IDENT.fullmatch(name) or len(name) > MAX_RULE_NAME or name in _YARA_KEYWORDS: return None
    return f'yara:{path}#{name}', 'exact'


def _yara_rule_name(t):
    if len(t) < 2 or len(t) > MAX_RULE_NAME or not _IDENT.fullmatch(t) or t in _YARA_KEYWORDS: return None
    if _HEX.fullmatch(t) and len(t) in _HASH_LEN: return None   # a hash-shaped word is reported as the hash only
    return t, 'ambiguous'   # a rule name is not an identity: the same name exists in several files


_PARSERS = {'cve': _cve, 'euvd': _euvd, 'gcve': _gcve, 'ghsa': _ghsa, 'cwe': _cwe, 'sha256': _hash('sha256'), 'sha1': _hash('sha1'),
            'md5': _hash('md5'), 'ipv4': _ipv4, 'ipv6': _ipv6, 'domain': _domain, 'url': _url, 'cpe23': _cpe23, 'suricata_sid': _sid,
            'uuid': _uuid, 'sigma_id': _sigma, 'yara_rule': _yara_rule, 'yara_rule_name': _yara_rule_name}
assert tuple(_PARSERS) == KINDS
assert MAX_INPUT >= MAX_YARA_ID   # the global cap never cuts off a valid identity


def classify(text):
    """Every kind the whole input can be, as Candidates sorted by confidence (exact, pattern, ambiguous) then kind. [] for empty, overlong
    or control-character input, and for anything no kind accepts."""
    t = _clean(text)
    if t is None: return []
    out = []
    for kind, parse in _PARSERS.items():
        r = parse(t)
        if r: out.append(Candidate(kind, r[0], r[1]))
    return sorted(out, key=lambda c: (CONFIDENCE_ORDER.index(c.confidence), c.kind, c.normalized))


def normalize(kind, text):
    """Canonical form of `text` as `kind`. Raises ValueError for an unknown kind or text that is not that kind."""
    if kind not in _PARSERS: raise ValueError(f'unknown kind {kind!r}')
    t = _clean(text)
    r = _PARSERS[kind](t) if t is not None else None
    if not r: raise ValueError(f'not a {kind}')
    return r[0]


# ---- extraction from free text (rule metadata) ------------------------------------------------------------------------------------------
_HEX_RUN = re.compile(r'(?<![0-9A-Za-z])[0-9A-Fa-f]+(?![0-9A-Za-z])', re.A)
_CVE_RUN = re.compile(r'(?<![0-9A-Za-z])CVE-\d{4}-\d+(?![0-9A-Za-z])', re.I | re.A)


def extract_hashes(text):
    """[(kind, normalized, whole)] for every standalone 32/40/64 hex run in `text`, in order. `whole` is True when the run is the whole
    (trimmed) text. Runs of other lengths (63, 65, 128 ...) are never truncated into a hash."""
    if not isinstance(text, str): return []
    stripped = text.strip()
    out = []
    for m in _HEX_RUN.finditer(text):
        kind = _HASH_LEN.get(len(m.group(0)))
        if kind: out.append((kind, m.group(0).lower(), m.group(0) == stripped))
    return out


def hash_like_runs(text, lo=30, hi=130):
    """Standalone hex runs of lo..hi characters that are NOT a 32/40/64 hash (e.g. a 63-character truncated SHA-256)."""
    if not isinstance(text, str): return []
    return [m.group(0) for m in _HEX_RUN.finditer(text) if lo <= len(m.group(0)) <= hi and len(m.group(0)) not in _HASH_LEN]


def extract_cves(text):
    """[normalized CVE] for every well-formed hyphenated CVE id in `text`, in order (CVE-YYYY-NNNN.. with the classify() rules)."""
    if not isinstance(text, str): return []
    out = []
    for m in _CVE_RUN.finditer(text):
        r = _cve(m.group(0))
        if r: out.append(r[0])
    return out


if __name__ == '__main__':
    import json, sys
    for arg in sys.argv[1:]:
        print(json.dumps({'input': arg, 'candidates': [c._asdict() for c in classify(arg)]}, ensure_ascii=False))
