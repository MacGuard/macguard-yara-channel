"""Hostile and damaged YARA text against the static analyser: it must never raise, must flag damage as truncated/corrupt, and must stay
linear-ish on pathological input (the time bound is a resource limit for hostile input, not a pass criterion for ordinary files)."""
import json, pathlib, random, sys, time, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rulecheck as rc

POLICY = json.loads((ROOT / 'config/policy.json').read_text())
FILE = ('import "pe"\n// header { comment\n'
        'rule One : tag { meta: a = "}" strings: $a = "abc" $b = { 4D 5A ?? } $c = /ab+c/ nocase condition: any of them }\n'
        '/* block } comment */\nprivate rule Two { strings: $x = "q\\"}" condition: $x and One }\n'
        'rule Three { condition: for any i in (1..3) : ( uint8(i) == 0x4d ) }\n')

def analyse(text): return rc.analyse_text(text, POLICY)

class DamageTests(unittest.TestCase):
    def test_the_intact_file_has_no_findings(self): self.assertEqual(analyse(FILE)['findings'], [])

    def test_every_truncation_point_is_analysed_deterministically_and_damage_is_never_clean(self):
        # spans of the three rules in FILE: a cut strictly inside one (after its first character, before its closing brace) is damage and must yield a finding
        spans = []
        for start_marker, end_marker in (('rule One', 'any of them }'), ('private rule Two', 'and One }'), ('rule Three', '0x4d ) }')):
            st = FILE.index(start_marker); spans.append((st, FILE.index(end_marker) + len(end_marker)))
        for cut in range(len(FILE) + 1):
            part = FILE[:cut]; a = analyse(part); b = analyse(part)
            self.assertEqual(a, b, cut)
            if any(st < cut < en for st, en in spans):
                self.assertTrue({f['severity'] for f in a['findings']} & {'truncated', 'corrupt', 'reject'}, (cut, repr(part[-30:]), a['findings']))   # every one of these is blocking in decide.py

    def test_random_byte_damage_never_raises(self):
        rnd = random.Random(7); raw = FILE.encode()
        for _ in range(1500):
            b = bytearray(raw)
            for _ in range(rnd.randrange(1, 8)): b[rnd.randrange(len(b))] = rnd.randrange(256)
            if rnd.random() < 0.3: del b[rnd.randrange(len(b)):]
            analyse(b.decode('utf-8', 'replace'))

    def test_unicode_and_control_characters(self):
        for t in ('rule ‮ { condition: true }', 'rule A\u0000B { condition: true }', 'rule 😀 { condition: true }'.encode('utf-8', 'surrogatepass').decode('utf-8', 'replace'),
                  '﻿rule A { condition: true }', 'rule A { condition: true }\r\n' * 50, '\x00' * 1000, '', ' ', '\n' * 10000):
            analyse(t)


class ResourceTests(unittest.TestCase):
    def bounded(self, text, seconds=8):
        t0 = time.monotonic(); analyse(text); took = time.monotonic() - t0
        self.assertLess(took, seconds, f'{len(text)} bytes took {took:.1f}s')

    def test_pathological_inputs_stay_bounded(self):
        n = 1_000_000
        for name, text in (('one long line', 'a' * n), ('open braces', 'rule A {' * 50000), ('close braces', '}' * n), ('quotes', '"' * n), ('slashes', '/' * n), ('open comment', '/*' * 200000),
                           ('nested regex', 'rule A { strings: $a = /' + '(a+)+' * 20000 + '/ condition: $a }'), ('many rules', 'rule R%d { condition: true }\n' * 1 + ('rule R { condition: true }\n' * 40000)),
                           ('huge hex', 'rule A { strings: $a = { ' + '4D ' * 300000 + '} condition: $a }'), ('many loops', 'rule A { condition: ' + 'for all i in (1..10) : ( ' * 3000 + 'true' + ' )' * 3000 + ' }'),
                           ('long identifiers', 'rule ' + 'A' * n + ' { condition: true }')):
            with self.subTest(name): self.bounded(text)

if __name__ == '__main__': unittest.main()
