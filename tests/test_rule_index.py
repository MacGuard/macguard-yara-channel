"""scripts/rule_index.py: rule-level search index from an unpacked release. Integrity against the manifest first (tampered, missing, extra,
symlinked files refuse the whole release), the tolerant YARA scanner (comments, private/global, tags, braces and quotes in strings and
conditions), identity (path, name), assertions only from the rule's own meta, byte determinism, and the contract
(contracts/v1/search-index.schema.json + its example, checked by a small validator for the keywords the schema uses). Synthetic data only."""
import hashlib, json, os, pathlib, re, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rule_index, tlog

TAG = 'rules-20990101-1'
SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
MD5 = 'd41d8cd98f00b204e9800998ecf8427e'
UUID = '5b6e2a1c-1f0e-4b7b-9c7b-1a2b3c4d5e6f'
SCHEMA = json.loads((ROOT / 'contracts/v1/search-index.schema.json').read_text())
EXAMPLE = ROOT / 'contracts/v1/examples/search-index.json'

APT = f'''import "pe"
// rule Commented_Line {{ condition: true }}
/* rule Commented_Block {{
   meta: hash = "{SHA256}"
   condition: true }} */
rule Dup_Name : tag_one TagTwo
{{
    meta:
        author = "Synthetic Author"
        id = "{UUID.upper()}"
        date = "2099-01-01"
        hash = "{SHA256.upper()}"
        hash2 = "{SHA256[:63]}"
        description = "Mentions cve-2021-44228 and CVE-2023-01234; sample md5 {MD5} \\"quoted\\" rule Fake {{"
        reference = "https://example.invalid/CVE-2024-0001"
        score = 80
        active = true
    strings:
        $a = "rule NotARule {{ meta: hash = \\"{SHA1}\\" }}" ascii wide
        $h = {{ 6A 40 [2-4] 68 ?? }}
        $r = /rule\\s+x\\{{"[}}\\/]/ nocase
        $b = "x" base64("abc}}")
    condition:
        uint16(0) == 0x5a4d and filesize < 1MB and ($a or $h or $r or $b) and "a}}" contains "}}" and filesize / 2 > 1
}}

private rule Helper {{ condition: true }}
global private rule Gate : t {{ meta: md5 = "{MD5}" condition: filesize < 10MB }}
'''
OTHER = f'''rule Dup_Name {{
  meta:
    hash1 = "{SHA1}"
    md5 = "not a hash"
    Sample = "{MD5.upper()}"
  condition:
    true
}}
'''


def make_release(d, files=None, **mutate):
    d = pathlib.Path(d)
    files = files if files is not None else {'rules/community/apt/apt.yar': (APT, 'community'), 'rules/nextron/yara/other.yar': (OTHER, 'nextron'),
                                             'rules/nextron/README.txt': ('not yara', 'nextron')}
    inv = []
    for path, (text, src) in sorted(files.items()):
        p = d / path; p.parent.mkdir(parents=True, exist_ok=True); b = text.encode(); p.write_bytes(b)
        inv.append({'bytes': len(b), 'path': path, 'sha256': hashlib.sha256(b).hexdigest(), 'source': src})
    m = {'schema': 1, 'files': inv, 'rules_root': tlog.rules_root(inv), 'stats': {'files': len(inv)}}
    m.update(mutate)
    (d / 'manifest.json').write_text(json.dumps(m, sort_keys=True, indent=1))
    return d


def validate(inst, schema, root=SCHEMA, path='$'):
    """Errors for the JSON Schema keywords this contract uses ($ref to #/$defs, type, const, enum, pattern, required, properties,
    additionalProperties, items, minimum, maxLength)."""
    if '$ref' in schema: return validate(inst, root['$defs'][schema['$ref'].split('/')[-1]], root, path)
    errs, t = [], schema.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'null': type(None), 'boolean': bool}
    if t:
        ok = any((isinstance(inst, int) and not isinstance(inst, bool)) if x == 'integer' else isinstance(inst, types[x]) for x in (t if isinstance(t, list) else [t]))
        if not ok: return [f'{path}: type {type(inst).__name__} not {t}']
    if 'const' in schema and inst != schema['const']: errs.append(f'{path}: not const {schema["const"]!r}')
    if 'enum' in schema and inst not in schema['enum']: errs.append(f'{path}: {inst!r} not in enum')
    if isinstance(inst, str):
        if 'pattern' in schema and not re.search(schema['pattern'], inst): errs.append(f'{path}: {inst[:60]!r} !~ {schema["pattern"]}')
        if 'maxLength' in schema and len(inst) > schema['maxLength']: errs.append(f'{path}: too long')
    if isinstance(inst, int) and 'minimum' in schema and inst < schema['minimum']: errs.append(f'{path}: below minimum')
    if isinstance(inst, dict):
        for k in schema.get('required', []):
            if k not in inst: errs.append(f'{path}: missing {k}')
        props, extra = schema.get('properties', {}), schema.get('additionalProperties', True)
        for k, v in inst.items():
            if k in props: errs += validate(v, props[k], root, f'{path}.{k}')
            elif extra is False: errs.append(f'{path}: unexpected {k}')
            elif isinstance(extra, dict): errs += validate(v, extra, root, f'{path}.{k}')
    if isinstance(inst, list) and 'items' in schema:
        for i, v in enumerate(inst): errs += validate(v, schema['items'], root, f'{path}[{i}]')
    return errs


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.d = make_release(pathlib.Path(self.tmp.name) / 'rel')


class Integrity(Base):
    def refused(self, msg):
        with self.assertRaises(rule_index.RefusedRelease) as cm: rule_index.build_index(self.d, TAG)
        self.assertIn(msg, str(cm.exception))

    def test_tampered_file(self):
        p = self.d / 'rules/nextron/yara/other.yar'; b = bytearray(p.read_bytes()); b[0] ^= 1; p.write_bytes(bytes(b))   # same size
        self.refused('SHA-256 differs')

    def test_resized_missing_extra(self):
        (self.d / 'rules/nextron/yara/other.yar').write_text(OTHER + '\n'); self.refused('size differs')
        (self.d / 'rules/nextron/yara/other.yar').unlink(); self.refused('missing')

    def test_unlisted_file(self):
        (self.d / 'rules/nextron/yara/planted.yar').write_text('rule Planted { condition: true }'); self.refused('not listed')

    def test_symlink(self):
        target = pathlib.Path(self.tmp.name) / 'outside.yar'; target.write_text(OTHER)
        p = self.d / 'rules/nextron/yara/other.yar'; p.unlink(); p.symlink_to(target); self.refused('symlink')

    def test_manifest_inventory_and_root(self):
        make_release(self.d, rules_root='0' * 64); self.refused('rules_root')
        m = json.loads((self.d / 'manifest.json').read_text()); m['files'][0]['path'] = '../x.yar'; (self.d / 'manifest.json').write_text(json.dumps(m))
        self.refused('unsafe path')
        (self.d / 'manifest.json').write_text('{'); self.refused('not JSON')

    def test_bad_tag(self):
        for tag in ('', 'intel-x', 'rules-2099-1', 'rules-20990101-1/../x', None):
            with self.subTest(tag=tag), self.assertRaises(rule_index.RefusedRelease): rule_index.build_index(self.d, tag)

    def test_cli_refuses_without_output(self):
        out = pathlib.Path(self.tmp.name) / 'idx.json'
        (self.d / 'rules/nextron/yara/other.yar').write_text(OTHER.replace('true', 'TRUE'))
        r = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/rule_index.py'), str(self.d), '--release-tag', TAG, '-o', str(out)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2); self.assertIn('REFUSED', r.stderr); self.assertFalse(out.exists())


class Scanner(unittest.TestCase):
    def test_rules_and_comments(self):
        rs = rule_index.scan(APT)
        self.assertEqual([(r['name'], r['modifiers'], r['tags'], r['complete']) for r in rs],
                         [('Dup_Name', [], ['tag_one', 'TagTwo'], True), ('Helper', ['private'], [], True), ('Gate', ['global', 'private'], ['t'], True)])
        self.assertEqual(rs[0]['line'], 6)
        keys = [k for k, _, _ in rs[0]['meta']]
        self.assertEqual(keys, ['author', 'id', 'date', 'hash', 'hash2', 'description', 'reference', 'score', 'active'], 'strings: never leak into meta')
        self.assertIn('"quoted" rule Fake {', dict((k, v) for k, v, _ in rs[0]['meta'])['description'])
        self.assertEqual([(k, v) for k, v, _ in rs[2]['meta']], [('md5', MD5)])

    def test_tolerant(self):
        for junk in ('', 'rule', 'rule {', 'rule X', 'rule X {', '}}}} rule', '"unterminated', '/* never closed rule Y { }', 'rule X : { condition: true }',
                     'rule A { strings: $a = { 41 42 condition: true }', 'rule B { meta: a = condition: true }', '\x00rule C { condition: true }'):
            with self.subTest(junk=junk): rule_index.scan(junk)
        self.assertEqual([r['complete'] for r in rule_index.scan('rule X { meta: a = "b"')], [False])
        self.assertEqual([r['name'] for r in rule_index.scan('\x00rule C { condition: true }')], ['C'])


class Index(Base):
    def test_entities_and_assertions(self):
        idx = rule_index.build_index(self.d, TAG)
        ids = [e['id'] for e in idx['entities']]
        self.assertEqual(ids, ['yara:rules/community/apt/apt.yar#Dup_Name', 'yara:rules/community/apt/apt.yar#Gate', 'yara:rules/community/apt/apt.yar#Helper',
                               'yara:rules/nextron/yara/other.yar#Dup_Name'], 'same name in two files = two rules; commented rules are not rules')
        e = idx['entities'][0]
        self.assertEqual(e['meta'], {'uuid': UUID, 'author': 'Synthetic Author', 'date': '2099-01-01', 'references': ['https://example.invalid/CVE-2024-0001']})
        self.assertEqual((e['source'], e['tags'], e['file_sha256']), ('community', ['tag_one', 'TagTwo'], hashlib.sha256(APT.encode()).hexdigest()))
        c = idx['counts']
        self.assertEqual((c['files'], c['files_indexed'], c['files_skipped_not_yara'], c['rules'], c['unique_rule_names'], c['rules_private'], c['rules_global']),
                         (3, 2, 1, 4, 3, 2, 1))
        got = sorted((a['subject'].split('#')[1], a['type'].rsplit('_', 1)[1], a['value'], a['meta_key'], a['match'], a['provenance']['line']) for a in idx['assertions'])
        self.assertEqual(got, sorted([
            ('Dup_Name', 'hash', SHA256, 'hash', 'whole_value', 12), ('Dup_Name', 'hash', MD5, 'description', 'embedded', 14),
            ('Dup_Name', 'cve', 'CVE-2021-44228', 'description', 'embedded', 14), ('Dup_Name', 'cve', 'CVE-2024-0001', 'reference', 'embedded', 15),
            ('Gate', 'hash', MD5, 'md5', 'whole_value', 28),
            ('Dup_Name', 'hash', SHA1, 'hash1', 'whole_value', 3), ('Dup_Name', 'hash', MD5, 'Sample', 'whole_value', 5)]),
            'no hash from strings:, comments or a 63-hex value; CVE-2023-01234 is malformed')
        self.assertEqual((c['hash_like_runs_rejected'], c['hash_meta_without_valid_hash'], c['distinct_cves']), (1, 2, 2))
        self.assertEqual(c['distinct_hashes_by_kind'], {'md5': 1, 'sha1': 1, 'sha256': 1})
        for a in idx['assertions']:
            self.assertEqual(a['status'], 'asserted_by_rule_metadata')
            self.assertEqual(a['provenance']['release_tag'], TAG)
            self.assertIn(a['provenance']['path'], a['subject'])
        self.assertNotIn('detect', json.dumps(idx['assertions']).lower(), 'an assertion never claims detection')

    def test_deterministic_bytes(self):
        a = rule_index.dumps(rule_index.build_index(self.d, TAG))
        other = make_release(pathlib.Path(self.tmp.name) / 'elsewhere')
        os.utime(other / 'manifest.json', (1, 1))
        self.assertEqual(a, rule_index.dumps(rule_index.build_index(other, TAG)), 'same input, same bytes, wherever it is unpacked')
        self.assertNotIn(self.tmp.name.encode(), a)
        out = pathlib.Path(self.tmp.name) / 'cli.json'
        subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/rule_index.py'), str(self.d), '--release-tag', TAG, '-o', str(out)], check=True, capture_output=True)
        self.assertEqual(out.read_bytes(), a)

    def test_contract(self):
        idx = json.loads(rule_index.dumps(rule_index.build_index(self.d, TAG)))
        self.assertEqual(validate(idx, SCHEMA), [])
        bad = json.loads(json.dumps(idx)); bad['assertions'][0]['status'] = 'detects_exploitation'
        self.assertTrue(validate(bad, SCHEMA), 'the validator really checks')

    def test_example_is_the_fixture_output(self):
        example = json.loads(EXAMPLE.read_text())
        self.assertEqual(validate(example, SCHEMA), [])
        self.assertEqual(example, json.loads(rule_index.dumps(rule_index.build_index(self.d, TAG))), 'regenerate the example from this fixture')


if __name__ == '__main__':
    unittest.main()
