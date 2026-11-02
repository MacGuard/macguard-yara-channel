#!/usr/bin/env python3
"""Deterministic rule-level search index (macguard.search-index/1) from an UNPACKED YARA release.

usage: rule_index.py RELEASE_DIR --release-tag rules-YYYYMMDD-RUN [-o OUT.json]

RELEASE_DIR is the extracted rules-release.tar.gz (manifest.json + rules/). Before anything is read as YARA, every file the manifest lists
must exist as a regular file inside RELEASE_DIR (no symlink), match its size and SHA-256, the inventory must be safe (tlog.check_inventory),
no unlisted file may sit under rules/, and the manifest's rules_root and stats must match the list. Any mismatch refuses the whole release:
no partial index. This checks integrity against the manifest only; the manifest's signature and log inclusion are verify_release.py's job and
must have passed before this runs (the build wiring does that; this script never fetches anything).

Identity of a rule = (file path, rule name): `yara:<path>#<name>`. The same name in two files is two rules. Paths are exactly what
tlog.check_inventory accepts (letters, digits, . _ - / space + @ ( ) [ ], any case of .yar/.yara) and never contain '#', while a rule name
is a YARA identifier, so the id splits unambiguously on its last '#'. No escaping is applied.
Assertions are what a rule's OWN meta: block says, nothing more: `rule_meta_mentions_hash` and `rule_meta_mentions_cve`, status
`asserted_by_rule_metadata`. They do not mean the rule detects that sample or the exploitation of that CVE, and they are not correlations.
Output is sorted and byte-deterministic: no timestamps, no absolute paths, compact JSON with sorted keys.
"""
import argparse, hashlib, json, os, pathlib, re, stat, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import intel_ids, tlog

SCHEMA = 'macguard.search-index/1'
STATUS = 'asserted_by_rule_metadata'
TAG_RE = re.compile(r'rules-\d{8}-\d{1,20}', re.A)
MAX_FILE = 16 * 1024 * 1024       # a single rule file larger than this is refused
MAX_META_VALUE = 1024             # longer meta strings are not copied into the entity (assertions are still extracted from them)
HASHY_KEY = re.compile(r'(hash|sha|md5|sample)', re.I | re.A)
REF_KEY = re.compile(r'(reference|ref|url|link)\d*', re.I | re.A)
YARA_EXT = ('.yar', '.yara')


class RefusedRelease(Exception):
    pass


# ---- integrity ---------------------------------------------------------------------------------------------------------------------------
def _sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''): h.update(chunk)
    return h.hexdigest()


def verify_against_manifest(root):
    """Return (manifest, manifest_sha256) after checking every listed file; raise RefusedRelease otherwise."""
    root = pathlib.Path(root)
    mp = root / 'manifest.json'
    if mp.is_symlink() or not mp.is_file(): raise RefusedRelease('manifest.json missing')
    raw = mp.read_bytes()
    try: m = json.loads(raw)
    except ValueError as e: raise RefusedRelease(f'manifest.json is not JSON: {e}')
    if not isinstance(m, dict): raise RefusedRelease('manifest.json is not an object')
    files = m.get('files')
    bad = tlog.check_inventory(files)
    if bad: raise RefusedRelease(f'manifest inventory: {bad}')
    real_root = os.path.realpath(root)
    for f in files:
        rel = f['path']
        p = root / rel
        if os.path.realpath(p) != os.path.join(real_root, *rel.split('/')): raise RefusedRelease(f'{rel}: resolves outside the release (symlink)')
        try: st = os.lstat(p)
        except FileNotFoundError: raise RefusedRelease(f'{rel}: listed in the manifest but missing')
        if not stat.S_ISREG(st.st_mode): raise RefusedRelease(f'{rel}: not a regular file')
        if st.st_size > MAX_FILE: raise RefusedRelease(f'{rel}: larger than {MAX_FILE} bytes')
        if f.get('bytes') is not None and st.st_size != f['bytes']: raise RefusedRelease(f'{rel}: size differs from the manifest')
        if _sha256(p) != f['sha256']: raise RefusedRelease(f'{rel}: SHA-256 differs from the manifest')
    listed = {f['path'] for f in files}
    rules = root / 'rules'
    if rules.is_dir():
        for dirpath, dirnames, filenames in os.walk(rules):
            for name in dirnames + filenames:
                q = pathlib.Path(dirpath) / name
                rel = q.relative_to(root).as_posix()
                if q.is_symlink(): raise RefusedRelease(f'{rel}: symlink inside rules/')
                if name in filenames and rel not in listed: raise RefusedRelease(f'{rel}: present but not listed in the manifest')
    if m.get('rules_root') is not None and tlog.rules_root(files) != m['rules_root']: raise RefusedRelease('rules_root does not match the file list')
    st = m.get('stats') or {}
    if st.get('files') is not None and st['files'] != len(files): raise RefusedRelease('manifest stats.files does not match the file list')
    return m, hashlib.sha256(raw).hexdigest()


# ---- tolerant YARA scanner ---------------------------------------------------------------------------------------------------------------
_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*', re.A)
_NUM = re.compile(r'-?(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)(?:KB|MB)?', re.A)
_ESC = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}


class _Scanner:
    """Finds `[private] [global] rule NAME [: tags] {` headers and the key = value pairs of each meta: section. strings: and condition:
    are skipped with enough lexing (text strings, hex strings, regular expressions, comments) that braces and quotes inside them never end
    a rule early. Malformed input never raises: unknown characters are skipped."""

    def __init__(self, text):
        self.s, self.i, self.line, self.n = text, 0, 1, len(text)

    def _adv(self, k=1):
        seg = self.s[self.i:self.i + k]
        self.line += seg.count('\n'); self.i += len(seg)

    def _ws(self):
        s = self.s
        while self.i < self.n:
            c = s[self.i]
            if c in ' \t\r\n\f\v': self._adv()
            elif s.startswith('//', self.i):
                j = s.find('\n', self.i); self._adv((j if j >= 0 else self.n) - self.i)
            elif s.startswith('/*', self.i):
                j = s.find('*/', self.i + 2); self._adv((j + 2 if j >= 0 else self.n) - self.i)
            else: break

    def _ident(self):
        m = _IDENT.match(self.s, self.i)
        if not m: return None
        self._adv(m.end() - self.i); return m.group(0)

    def _string(self):
        """At a '"': consume a YARA text string, return its decoded value."""
        out, s = [], self.s
        self._adv()
        while self.i < self.n:
            c = s[self.i]
            if c == '"': self._adv(); return ''.join(out)
            if c == '\n': return ''.join(out)   # unterminated: stop at end of line
            if c == '\\' and self.i + 1 < self.n:
                e = s[self.i + 1]
                if e == 'x' and re.fullmatch(r'[0-9A-Fa-f]{2}', s[self.i + 2:self.i + 4], re.A):
                    out.append(chr(int(s[self.i + 2:self.i + 4], 16))); self._adv(4); continue
                out.append(_ESC.get(e, '\\' + e)); self._adv(2); continue
            out.append(c); self._adv()
        return ''.join(out)

    def _regex(self):
        """At a '/': consume /.../flags."""
        s = self.s
        self._adv(); in_class = False
        while self.i < self.n:
            c = s[self.i]
            if c == '\\': self._adv(2); continue
            if c == '\n': return
            if c == '[': in_class = True
            elif c == ']': in_class = False
            elif c == '/' and not in_class:
                self._adv()
                while self.i < self.n and s[self.i] in 'isg': self._adv()
                return
            self._adv()

    def _hex(self):
        """At a '{' that starts a hex string: consume to its closing '}'. Hex strings do not nest braces but may hold /* */ and // comments,
        and a '}' (or 'meta:', 'rule X {') inside such a comment must never end the hex string."""
        s = self.s
        self._adv()
        while self.i < self.n:
            if s.startswith('/*', self.i):
                j = s.find('*/', self.i + 2); self._adv((j + 2 if j >= 0 else self.n) - self.i); continue
            if s.startswith('//', self.i):
                j = s.find('\n', self.i); self._adv((j if j >= 0 else self.n) - self.i); continue
            c = s[self.i]; self._adv()
            if c == '}': return

    def rules(self):
        s = self.s
        while True:
            self._ws()
            if self.i >= self.n: return
            c = s[self.i]
            if c == '"': self._string(); continue
            word_line = self.line
            w = self._ident()
            if w is None: self._adv(); continue
            mods = []
            while w in ('private', 'global'):
                mods.append(w); self._ws(); w = self._ident()
            if w != 'rule': continue
            line = word_line
            self._ws()
            name = self._ident()
            if name is None: continue
            self._ws()
            tags = []
            if self.i < self.n and s[self.i] == ':':
                self._adv()
                while True:
                    self._ws()
                    t = self._ident()
                    if t is None: break
                    tags.append(t)
            self._ws()
            if self.i >= self.n or s[self.i] != '{': continue
            self._adv()
            meta, closed = self._body()
            yield {'name': name, 'modifiers': sorted(set(mods)), 'tags': tags, 'line': line, 'meta': meta, 'complete': closed}

    def _body(self):
        """Inside a rule body; returns (meta pairs [(key, value, line)], closed)."""
        s, meta, section, prev = self.s, [], None, ''
        while True:
            self._ws()
            if self.i >= self.n: return meta, False
            c = s[self.i]
            if c == '}': self._adv(); return meta, True
            if c == '"': self._string(); prev = 'str'; continue
            if c == '/' and prev in ('=', 'matches'): self._regex(); prev = 're'; continue
            if c == '{' and section == 'strings' and prev == '=': self._hex(); prev = 'hex'; continue
            if c == '$' or c == '#' or c == '@' or c == '!':
                self._adv(); self._ident(); prev = 'var'; continue
            w = self._ident()
            if w is not None:
                self._ws()
                if w in ('meta', 'strings', 'condition') and self.i < self.n and s[self.i] == ':':
                    self._adv(); section = w; prev = ':'; continue
                if section == 'meta' and self.i < self.n and s[self.i] == '=':
                    self._adv(); self._ws()
                    vline = self.line
                    if self.i < self.n and s[self.i] == '"':
                        meta.append((w, self._string(), vline))
                    else:
                        m = _NUM.match(s, self.i) or _IDENT.match(s, self.i)
                        if m: self._adv(m.end() - self.i); meta.append((w, m.group(0), vline))
                    prev = 'val'; continue
                prev = w; continue
            prev = c; self._adv()


def scan(text):
    return list(_Scanner(text).rules())


# ---- index -------------------------------------------------------------------------------------------------------------------------------
def _assertion(kind, rule_id, value, value_kind, key, line, match, prov):
    a = {'type': kind, 'subject': rule_id, 'value': value, 'value_kind': value_kind, 'meta_key': key, 'match': match, 'status': STATUS,
         'provenance': dict(prov, line=line)}
    a['id'] = 'assert:' + hashlib.sha256(json.dumps([kind, rule_id, value, key, line], separators=(',', ':')).encode()).hexdigest()
    return a


def build_index(release_dir, release_tag):
    if not isinstance(release_tag, str) or not TAG_RE.fullmatch(release_tag): raise RefusedRelease(f'bad release tag {release_tag!r}')
    root = pathlib.Path(release_dir)
    manifest, manifest_sha = verify_against_manifest(root)
    entities, assertions, seen = {}, [], set()
    c = {'files': len(manifest['files']), 'files_indexed': 0, 'files_skipped_not_yara': 0, 'files_decode_errors': 0, 'rules': 0,
         'rules_name_too_long_skipped': 0, 'rules_private': 0, 'rules_global': 0, 'rules_incomplete': 0, 'rules_duplicate_id_dropped': 0, 'rules_with_uuid': 0,
         'meta_values_not_copied_too_long': 0, 'hash_meta_without_valid_hash': 0, 'hash_like_runs_rejected': 0}
    for f in sorted(manifest['files'], key=lambda f: f['path']):
        path = f['path']
        if not path.lower().endswith(YARA_EXT): c['files_skipped_not_yara'] += 1; continue
        data = (root / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != f['sha256']: raise RefusedRelease(f'{path}: changed while indexing')
        try: text = data.decode('utf-8')
        except UnicodeDecodeError: text = data.decode('utf-8', errors='replace'); c['files_decode_errors'] += 1
        c['files_indexed'] += 1
        prov = {'release_tag': release_tag, 'path': path, 'file_sha256': f['sha256']}
        for r in scan(text):
            if len(r['name']) > intel_ids.MAX_RULE_NAME: c['rules_name_too_long_skipped'] += 1; continue   # YARA itself refuses these
            rid = f'yara:{path}#{r["name"]}'   # tlog.check_inventory paths never contain '#': split an id on its LAST '#'
            if rid in seen: c['rules_duplicate_id_dropped'] += 1; continue
            seen.add(rid)
            c['rules'] += 1
            c['rules_private'] += 'private' in r['modifiers']; c['rules_global'] += 'global' in r['modifiers']; c['rules_incomplete'] += not r['complete']
            info = {'uuid': None, 'author': None, 'date': None, 'references': []}
            for key, val, line in r['meta']:
                k = key.lower()
                if len(val) > MAX_META_VALUE:
                    c['meta_values_not_copied_too_long'] += 1
                elif k == 'id' and info['uuid'] is None:
                    try: info['uuid'] = intel_ids.normalize('uuid', val)
                    except ValueError: pass
                elif k == 'author' and info['author'] is None: info['author'] = val
                elif k == 'date' and info['date'] is None: info['date'] = val
                elif REF_KEY.fullmatch(k) and val not in info['references']: info['references'].append(val)
                hashes = intel_ids.extract_hashes(val)
                for hk, hv, whole in hashes:
                    assertions.append(_assertion('rule_meta_mentions_hash', rid, hv, hk, key, line, 'whole_value' if whole else 'embedded', prov))
                c['hash_like_runs_rejected'] += len(intel_ids.hash_like_runs(val))
                if not hashes and HASHY_KEY.search(k) and val.strip(): c['hash_meta_without_valid_hash'] += 1
                for cve in intel_ids.extract_cves(val):
                    assertions.append(_assertion('rule_meta_mentions_cve', rid, cve, 'cve', key, line, 'whole_value' if cve == val.strip().upper() else 'embedded', prov))
            c['rules_with_uuid'] += info['uuid'] is not None
            entities[rid] = {'id': rid, 'kind': 'rule', 'path': path, 'name': r['name'], 'tags': r['tags'], 'modifiers': r['modifiers'],
                             'line': r['line'], 'file_sha256': f['sha256'], 'source': f.get('source') if isinstance(f.get('source'), str) else None,
                             'meta': info}
    assertions = list({a['id']: a for a in assertions}.values())
    for x in [(e['id'], e['path'], e['name'], *e['tags'], e['meta']['uuid'] or '') for e in entities.values()] + \
             [(a['id'], a['subject'], a['value'], a['meta_key'], a['provenance']['path']) for a in assertions]:
        if not all(v.isascii() for v in x): raise RefusedRelease(f'internal: non-ASCII identifier {x[0][:80]!r}')   # the contract is ASCII-only
    assertions.sort(key=lambda a: (a['subject'], a['provenance']['line'], a['type'], a['meta_key'], a['value']))
    by_type = {}
    for a in assertions: by_type.setdefault(a['type'], []).append(a)
    hashes = by_type.get('rule_meta_mentions_hash', []); cves = by_type.get('rule_meta_mentions_cve', [])
    c['unique_rule_names'] = len({e['name'] for e in entities.values()})
    c['assertions'] = len(assertions)
    c['assertions_by_type'] = {k: len(v) for k, v in sorted(by_type.items())}
    c['hash_mentions_by_kind'] = {k: sum(1 for a in hashes if a['value_kind'] == k) for k in ('md5', 'sha1', 'sha256')}
    c['distinct_hashes_by_kind'] = {k: len({a['value'] for a in hashes if a['value_kind'] == k}) for k in ('md5', 'sha1', 'sha256')}
    c['distinct_cves'] = len({a['value'] for a in cves})
    c['rules_by_source'] = {}
    for e in entities.values(): c['rules_by_source'][e['source'] or 'unknown'] = c['rules_by_source'].get(e['source'] or 'unknown', 0) + 1
    return {'schema': SCHEMA, 'generator': 'scripts/rule_index.py',
            'release': {'tag': release_tag, 'manifest_sha256': manifest_sha, 'rules_root': manifest.get('rules_root'), 'files': len(manifest['files'])},
            'note': 'Assertions repeat what each rule\'s own metadata states. They are not detections, correlations or evidence of exploitation.',
            'counts': c, 'entities': [entities[k] for k in sorted(entities)], 'assertions': assertions}


def dumps(index):
    return (json.dumps(index, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('release_dir'); ap.add_argument('--release-tag', required=True); ap.add_argument('-o', '--out')
    a = ap.parse_args(argv)
    try: idx = build_index(a.release_dir, a.release_tag)
    except RefusedRelease as e:
        print(f'REFUSED: {e}', file=sys.stderr); return 2
    out = dumps(idx)
    if a.out:
        tmp = pathlib.Path(a.out + '.tmp'); tmp.write_bytes(out); os.replace(tmp, a.out)
    else:
        sys.stdout.buffer.write(out)
    print(f'indexed {idx["counts"]["rules"]} rules from {idx["counts"]["files_indexed"]} files, {idx["counts"]["assertions"]} assertions', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
