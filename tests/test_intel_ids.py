"""scripts/intel_ids.py: one identifier normaliser for the hub. Canonical forms, near misses that must NOT classify, defanged IOCs, IDNA
lookalikes, ambiguity flags, input caps, and parity with web/common.js MG.idKind for the kinds both know (node, skipped without it)."""
import json, pathlib, shutil, subprocess, sys, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import intel_ids
from intel_ids import classify, normalize

SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
MD5 = 'd41d8cd98f00b204e9800998ecf8427e'
UUID = '5b6e2a1c-1f0e-4b7b-9c7b-1a2b3c4d5e6f'


def kinds(text):
    return {c.kind: (c.normalized, c.confidence) for c in classify(text)}


class Canonical(unittest.TestCase):
    def test_vulnerability_ids(self):
        self.assertEqual(kinds('cve-2021-44228'), {'cve': ('CVE-2021-44228', 'exact')})
        self.assertEqual(kinds(' CVE-2024-1234567 ')['cve'], ('CVE-2024-1234567', 'exact'))
        self.assertEqual(kinds('CVE-2021-0001')['cve'], ('CVE-2021-0001', 'exact'), 'four-digit sequences keep their zeros')
        self.assertEqual(kinds('CVE_2021_44228')['cve'], ('CVE-2021-44228', 'pattern'))
        self.assertEqual(kinds('cwe-079'), {'cwe': ('CWE-79', 'exact')})
        self.assertEqual(kinds('ghsa-JFH8-C2JP-5V3Q'), {'ghsa': ('GHSA-jfh8-c2jp-5v3q', 'exact')})
        self.assertEqual(kinds('euvd-2024-12345'), {'euvd': ('EUVD-2024-12345', 'exact')})
        self.assertEqual(kinds('gcve-1-2024-7'), {'gcve': ('GCVE-1-2024-7', 'exact')})

    def test_hashes_lowercase_exact_length(self):
        self.assertEqual(kinds(SHA256.upper()), {'sha256': (SHA256, 'exact')})
        self.assertEqual(kinds(SHA1), {'sha1': (SHA1, 'exact')})
        self.assertEqual(kinds('D41D8cd98F00B204E9800998ECF8427E'), {'md5': (MD5, 'exact')}, 'mixed case; a hash-shaped word is not also a rule name')
        self.assertEqual(kinds('sha256:' + SHA256), {'sha256': (SHA256, 'pattern')})
        self.assertEqual(kinds('md5=' + MD5.upper()), {'md5': (MD5, 'pattern')})

    def test_network(self):
        self.assertEqual(kinds('192.0.2.1'), {'ipv4': ('192.0.2.1', 'exact')})
        self.assertEqual(kinds('192.0.2[.]1'), {'ipv4': ('192.0.2.1', 'pattern')})
        self.assertEqual(kinds('[2001:DB8:0:0::1]'), {'ipv6': ('2001:db8::1', 'exact')})
        self.assertEqual(kinds('Evil.Example.COM.'), {'domain': ('evil.example.com', 'pattern')})
        self.assertEqual(kinds('evil[.]example(.)com'), {'domain': ('evil.example.com', 'pattern')})
        self.assertEqual(kinds('hxxps://Evil.Example.COM:443/a/B?x=1#frag'), {'url': ('https://evil.example.com/a/B?x=1', 'pattern')})
        self.assertEqual(kinds('http://evil.example:8080'), {'url': ('http://evil.example:8080/', 'exact')})
        self.assertEqual(kinds('http://[2001:db8::1]/p'), {'url': ('http://[2001:db8::1]/p', 'exact')})
        self.assertEqual(kinds('http://bank.example@evil.example/')['url'], ('http://evil.example/', 'ambiguous'), 'userinfo is dropped and flagged')

    def test_detection_ids(self):
        self.assertEqual(kinds('cpe:2.3:a:Apache:Log4j:2.14.1:*:*:*:*:*:*:*'), {'cpe23': ('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', 'exact')})
        self.assertEqual(kinds('cpe:2.3:a:vendor:prod\\:x:1:*:*:*:*:*:*:*')['cpe23'][0], 'cpe:2.3:a:vendor:prod\\:x:1:*:*:*:*:*:*:*', 'escaped colon')
        self.assertEqual(kinds('sid:2000001;'), {'suricata_sid': ('sid:2000001', 'exact')})
        self.assertEqual(kinds('SID 2000001'), {'suricata_sid': ('sid:2000001', 'pattern')})
        self.assertEqual(kinds('1:2000001'), {'suricata_sid': ('sid:2000001', 'pattern')})
        self.assertEqual(kinds('sigma:' + UUID.upper()), {'sigma_id': (UUID, 'exact')})
        self.assertEqual(kinds(UUID), {'uuid': (UUID, 'exact'), 'sigma_id': (UUID, 'ambiguous')}, 'a bare UUID may or may not be a Sigma id')
        self.assertEqual(kinds('{' + UUID + '}')['uuid'], (UUID, 'pattern'))
        self.assertEqual(kinds('rules/nextron/apt.yar:APT_X'), {'yara_rule': ('yara:rules/nextron/apt.yar#APT_X', 'exact')})
        self.assertEqual(kinds('yara:rules/a/b.yara#R1'), {'yara_rule': ('yara:rules/a/b.yara#R1', 'exact')})
        self.assertEqual(kinds('Mal_Foo'), {'yara_rule_name': ('Mal_Foo', 'ambiguous')}, 'a rule name is never an identity')
        self.assertEqual(kinds('CVE_2021_44228')['yara_rule_name'], ('CVE_2021_44228', 'ambiguous'))

    def test_order_is_confidence_then_kind(self):
        c = classify('CVE_2021_44228')
        self.assertEqual([x.confidence for x in c], ['pattern', 'ambiguous'])
        self.assertEqual(classify(UUID)[0].kind, 'uuid')

    def test_normalize(self):
        self.assertEqual(normalize('cve', 'cve-2021-44228'), 'CVE-2021-44228')
        self.assertEqual(normalize('sigma_id', UUID.upper()), UUID)
        with self.assertRaises(ValueError): normalize('cve', 'CVE-2021-123')
        with self.assertRaises(ValueError): normalize('macguard', 'MG-1')
        with self.assertRaises(ValueError): normalize('sha256', '')
        self.assertNotIn('macguard', intel_ids.KINDS, 'no MacGuard id namespace exists; none is invented')


class NearMisses(unittest.TestCase):
    def test_reject(self):
        for bad in ['', '   ', 'a', 'CVE-2021-123', 'CVE-21-44228', 'CVE-2021-01234', 'CVE-2021-12345678', 'CVE-2021-44228x', 'CWE-0', 'CWE-123456',
                    SHA256[:63], SHA256 + 'a', SHA256[:63] + 'g', SHA1[:39], MD5[:31], MD5 + '0', 'sha1:' + SHA256,
                    '010.1.1.1', '192.168.001.1', '256.1.1.1', '1.2.3', '1.2.3.4.5', 'fe80::1%eth0',
                    'cpe:2.3:a:apache:log4j', 'cpe:2.3:a:apache:log4j:2:*:*:*:*:*:*:*:*', 'cpe:2.3:x:apache:log4j:2:*:*:*:*:*:*', 'cpe:2.3:a::log4j:2:*:*:*:*:*:*:*',
                    'sid:0', 'sid:99999999999', 'ftp://example.com/', 'http://', 'http://exa mple.com/', 'localhost', 'example', 'a..com', '-a.com', 'a-.com',
                    'example.123', 'ab--cd.com', 'x' * 64 + '.com', 'rules/../x.yar:R', '/abs/x.yar:R', 'x.yar:9bad', 'rule', 'condition', 'line\nbreak',
                    'tab\there', 'nul\x00', '12345678-1234-1234-1234-12345678901']:
            with self.subTest(bad=bad):
                got = kinds(bad)
                self.assertEqual(set(got) - {'yara_rule_name'}, set(), f'{bad!r} -> {got}')
        self.assertEqual(kinds('example'), {'yara_rule_name': ('example', 'ambiguous')})

    def test_hash_never_truncated(self):
        for n in (31, 33, 39, 41, 63, 65, 128):
            with self.subTest(n=n): self.assertEqual({c.kind for c in classify('a' * n)} & {'md5', 'sha1', 'sha256'}, set())
        self.assertEqual(intel_ids.extract_hashes('x ' + 'a' * 128 + ' y'), [], 'a SHA-512 is not a SHA-256')
        self.assertEqual(intel_ids.hash_like_runs('h=' + SHA256[:63]), [SHA256[:63]])

    def test_caps(self):
        self.assertEqual(classify('http://example.com/' + 'a' * intel_ids.MAX_INPUT), [], 'overlong input is not classified')
        self.assertEqual(classify(None), []); self.assertEqual(classify(42), [])
        self.assertEqual(kinds('A' * 129), {}, 'longer than a YARA identifier')

    def test_unicode_lookalikes(self):
        k = kinds('аpple.com')   # Cyrillic a + Latin pple
        self.assertEqual(k['domain'], ('xn--pple-43d.com', 'ambiguous'), 'mixed-script label: homograph, kept distinct from apple.com')
        self.assertEqual(kinds('xn--pple-43d.com')['domain'][0], 'xn--pple-43d.com')
        self.assertEqual(kinds('bücher.example')['domain'], ('xn--bcher-kva.example', 'pattern'))
        self.assertEqual(kinds('ＥＸＡＭＰＬＥ。com')['domain'][0], 'example.com', 'IDNA maps full-width forms')
        self.assertEqual(kinds('серсара.com')['domain'][0].startswith('xn--'), True)

    def test_file_like_domains_are_ambiguous(self):
        self.assertEqual(kinds('rules.yar')['domain'], ('rules.yar', 'ambiguous'))
        self.assertEqual(kinds('update.zip')['domain'], ('update.zip', 'ambiguous'))


class Extraction(unittest.TestCase):
    def test_hashes_in_text(self):
        t = f'see {SHA256.upper()}, {SHA1}; md5:{MD5} and {"b" * 63} and x{MD5}'
        self.assertEqual(intel_ids.extract_hashes(t), [('sha256', SHA256, False), ('sha1', SHA1, False), ('md5', MD5, False)])
        self.assertEqual(intel_ids.extract_hashes(f' {MD5} '), [('md5', MD5, True)])

    def test_cves_in_text(self):
        self.assertEqual(intel_ids.extract_cves('Exploits cve-2021-44228, CVE-2023-01234, CVE-2024-123456789 and xCVE-2020-1111 / CVE-2019-0708.'),
                         ['CVE-2021-44228', 'CVE-2019-0708'])


class Caps(unittest.TestCase):
    """Per-kind caps agree with the producers: the longest valid identity is accepted, one character more is not."""

    def test_yara_identity_boundary(self):
        import tlog
        name = 'R' * intel_ids.MAX_RULE_NAME
        for ext in ('.yar', '.YARA'):
            path = 'rules/' + 'a' * 190 + '/' + 'b' * (intel_ids.MAX_YARA_PATH - 197 - len(ext)) + ext
            with self.subTest(ext=ext):
                self.assertEqual(len(path), 400); self.assertIsNone(tlog.check_inventory([{'path': path, 'sha256': '0' * 64}]))
                ident = f'yara:{path}#{name}'
                self.assertEqual(len(ident), intel_ids.MAX_YARA_ID)
                self.assertEqual(classify(ident), [intel_ids.Candidate('yara_rule', ident, 'exact')])
                self.assertEqual(normalize('yara_rule', ident), ident)
                self.assertEqual(normalize('yara_rule', f'{path}:{name}'), ident)
                for bad in (f'yara:{path[:6]}c{path[6:]}#{name}', f'yara:{path}#{name}R'):   # path 401 / name 129: max + 1
                    self.assertEqual(len(bad), intel_ids.MAX_YARA_ID + 1)
                    self.assertEqual(classify(bad), [])
                    with self.assertRaises(ValueError): normalize('yara_rule', bad)
                self.assertTrue(tlog.check_inventory([{'path': path[:6] + 'c' + path[6:], 'sha256': '0' * 64}]), 'tlog refuses 401 too')
        self.assertGreaterEqual(intel_ids.MAX_INPUT, intel_ids.MAX_YARA_ID)

    def test_other_kind_caps(self):
        self.assertEqual(normalize('yara_rule_name', 'N' * 128), 'N' * 128); self.assertEqual(kinds('N' * 129), {})
        self.assertEqual(normalize('cve', 'CVE-2024-1234567'), 'CVE-2024-1234567')   # 7 digits: portal_hub / intel_package limit (documented)
        self.assertEqual(normalize('euvd', 'EUVD-2024-' + '9' * 12), 'EUVD-2024-' + '9' * 12, 'web/common.js has no EUVD length cap')
        self.assertEqual(normalize('gcve', 'GCVE-1-2024-' + '9' * 12), 'GCVE-1-2024-' + '9' * 12)
        self.assertEqual(normalize('suricata_sid', 'sid:4294967295'), 'sid:4294967295'); self.assertEqual(kinds('sid:4294967296'), {})
        self.assertEqual(normalize('cwe', 'CWE-99999'), 'CWE-99999'); self.assertEqual(kinds('CWE-100000'), {})
        label = 'a' * 63
        dom = '.'.join([label] * 3 + ['b' * 61])   # 253 characters
        self.assertEqual(len(dom), 253); self.assertEqual(normalize('domain', dom + '.'), dom)
        self.assertEqual(kinds('c' + dom), {}); self.assertEqual(kinds('a' * 64 + '.com'), {})
        url = 'https://example.com/' + 'p' * (intel_ids.MAX_INPUT - 20)
        self.assertEqual(len(url), intel_ids.MAX_INPUT); self.assertEqual(normalize('url', url), url); self.assertEqual(classify(url + 'p'), [])


FW = str.maketrans('0123456789', '\uff10\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18\uff19')        # fullwidth
AR = str.maketrans('0123456789', '\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669')        # Arabic-Indic
SUP = str.maketrans('0123456789', '\u2070\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079')       # superscript
HYPHENS = ('\u2010', '\u2011', '\u2212')


class UnicodeLookalikes(unittest.TestCase):
    """Codex: Python's \\d / \\s / IGNORECASE are Unicode-aware. No non-ASCII digit, hyphen or letter may become an identifier."""
    ASCII_KINDS = set(intel_ids.KINDS) - {'domain', 'url'}

    def assert_no_id(self, text):
        got = {c.kind for c in classify(text)} & self.ASCII_KINDS
        self.assertEqual(got, set(), f'{text!r} -> {classify(text)}')
        for c in classify(text): self.assertTrue(c.normalized.isascii(), c)

    def test_digits(self):
        base = ['CVE-2024-1234', 'CWE-79', 'sid:2000001', 'SID 5', '1:2000001', '192.0.2.1', '2001:db8::1', 'EUVD-2024-1', 'GCVE-1-2024-7',
                'CVE_2024_1234', SHA256, SHA1, MD5, UUID, 'sigma:' + UUID]
        for tr in (FW, AR, SUP):
            for b in base:
                v = b.translate(tr)
                if v == b: continue
                with self.subTest(v=v):
                    self.assert_no_id(v)
                    for kind in ('cve', 'cwe', 'suricata_sid', 'ipv4', 'ipv6', 'sha256', 'sha1', 'md5', 'uuid'):
                        with self.assertRaises(ValueError): normalize(kind, v)
        self.assertEqual(intel_ids.extract_cves('CVE-2024-1234'.translate(FW) + ' CVE-\uff12\uff10\uff12\uff14-1234 CVE-2024-' + '1234'.translate(AR)), [])
        self.assertEqual(intel_ids.extract_hashes(SHA256[:-1] + '\uff10'), [])

    def test_hyphens(self):
        for h in HYPHENS:
            for v in ('CVE-2024-1234', 'CWE-79', 'EUVD-2024-1', 'GCVE-1-2024-7', 'GHSA-jfh8-c2jp-5v3q', UUID, 'sha-256:' + SHA256):
                with self.subTest(v=v.replace('-', h)): self.assert_no_id(v.replace('-', h))
            self.assertEqual(intel_ids.extract_cves('CVE-2024-1234'.replace('-', h)), [])

    def test_casefold_lookalikes(self):
        # Kelvin sign and long s fold to k / s under Unicode IGNORECASE
        for v in ('\u017fid:5', '\u017fha256:' + SHA256, '\u017figma:' + UUID, 'CVE-2024-1234'.replace('E', '\u0395'),
                  'rules/\u212a.yar:R', 'cpe:2.3:a:\u212a:p:1:*:*:*:*:*:*:*', 'h\u0445\u0445p://example.com/'):
            with self.subTest(v=v): self.assert_no_id(v)
        self.assertEqual(kinds('\uff25\uff38\uff21\uff2d\uff30\uff2c\uff25\u3002com')['domain'][0], 'example.com', 'IDNA stays the one intended Unicode step')


VECTORS = ['cve-2021-44228', 'CVE-2021-0001', 'CWE-79', 'cwe-079', 'GHSA-jfh8-c2jp-5v3q', 'EUVD-2024-1', 'EUVD-2024-1234567890', 'GCVE-1-2024-7', 'GCVE-1-2024-1234567890', SHA256.upper(), SHA1, MD5,
           'sid:2000001', 'SID 5', '1:2000001', 'CVE-2021-123', SHA256[:63]]
PY_TO_JS = {'cve': 'CVE', 'euvd': 'EUVD', 'gcve': 'GCVE', 'ghsa': 'GHSA', 'cwe': 'CWE', 'sha256': 'SHA256', 'sha1': 'SHA1', 'md5': 'MD5', 'suricata_sid': 'SID'}


class ParityWithWeb(unittest.TestCase):
    """web/common.js MG.idKind and this module agree on every kind both implement (the first shared test of the five normalisers)."""

    def test_common_js(self):
        node = shutil.which('node')
        if not node: self.skipTest('node not installed')
        js = ("const fs=require('fs');global.window={MG:{}};global.document={querySelector:()=>null};const src=fs.readFileSync(process.argv[1],'utf8');"
              "const a=src.indexOf('/* Identifier detection');const b=src.indexOf('})(window.MG);',a)+'})(window.MG);'.length;eval(src.slice(a,b));"
              "const v=JSON.parse(process.argv[2]);console.log(JSON.stringify(v.map(x=>window.MG.idKind(x))))")
        r = subprocess.run([node, '-e', js, str(ROOT / 'web' / 'common.js'), json.dumps(VECTORS)], capture_output=True, text=True, timeout=30)
        if r.returncode != 0 or not r.stdout.strip(): self.skipTest(f'web/common.js identifier block not loadable: {r.stderr[-200:]}')
        for v, js_k in zip(VECTORS, json.loads(r.stdout)):
            with self.subTest(v=v):
                py = [c for c in classify(v) if c.kind in PY_TO_JS and c.confidence in ('exact', 'pattern')]
                if js_k is None or js_k['kind'] == 'TEXT': self.assertEqual(py, [], f'{v}: web says {js_k}'); continue
                self.assertTrue(py, f'{v}: web says {js_k}, python none')
                self.assertEqual((PY_TO_JS[py[0].kind], py[0].normalized), (js_k['kind'], js_k['id']))


if __name__ == '__main__':
    unittest.main()
