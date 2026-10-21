"""Archive P1: canonical form, monthly segments, seals, and verification of continuity from archived segments alone."""
import json, pathlib, subprocess, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from archive_support import ROOT, canon, make_rows, months, tmpdir
from archive import segment as seg
from archive.segment import SegmentError, build_segments, verify_archive, verify_seal_chain, verify_segment


def sealed(counts=None, **kw):
    rows = make_rows(months(counts or {'2026-07': 4, '2026-08': 3, '2026-09': 5}))
    segs = build_segments(rows, **kw); return rows, segs


def pairs(segs): return [(s['seal'], s['segment']) for s in segs]


class Canonical(unittest.TestCase):
    def test_canonical_rules_and_floats(self):
        self.assertEqual(canon.canonical({'b': 1, 'a': [True, None, 'é']}), '{"a":[true,null,"é"],"b":1}')
        with self.assertRaises(ValueError): canon.canonical({'x': 1.5})

    def test_node_and_python_agree_on_chain_hash_seal_digest_and_verification(self):
        rows, segs = sealed()
        d = tmpdir(self); (d / 'in.json').write_text(json.dumps({'rows': rows, 'seal': segs[0]['seal']}))
        (d / 'x.mjs').write_text("import {readFileSync} from 'node:fs'; import {verifyChain} from %r; import {sealSha256} from %r;\n"
            "const j=JSON.parse(readFileSync(process.argv[2],'utf8')); const v=await verifyChain(j.rows); console.log(JSON.stringify({ok:v.ok,head:v.head,seal:await sealSha256(j.seal)}));"
            % ((ROOT / 'admin/worker/src/core.js').as_uri(), (ROOT / 'admin/worker/src/anchor.js').as_uri()))
        out = json.loads(subprocess.run(['node', str(d / 'x.mjs'), str(d / 'in.json')], capture_output=True, text=True, check=True).stdout)
        self.assertTrue(out['ok']); self.assertEqual(out['head'], rows[-1]['hash']); self.assertEqual(out['seal'], canon.seal_sha256(segs[0]['seal']))


class Build(unittest.TestCase):
    def test_three_months_seal_and_verify(self):
        rows, segs = sealed()
        self.assertEqual([s['period'] for s in segs], ['2026-07', '2026-08', '2026-09'])
        self.assertEqual([s['seal']['count'] for s in segs], [4, 3, 5])
        self.assertEqual(segs[1]['seal']['first_prev_hash'], segs[0]['seal']['head_hash'])
        self.assertEqual(segs[1]['seal']['prev_seal_sha256'], canon.seal_sha256(segs[0]['seal']))
        r = verify_archive(pairs(segs), expected_head=rows[-1]['hash']); self.assertEqual((r['seals'], r['last_seq']), (3, 12))

    def test_idempotent_and_incremental(self):
        rows, a = sealed(); _, b = sealed()
        self.assertEqual([(s['segment'], canon.seal_bytes(s['seal'])) for s in a], [(s['segment'], canon.seal_bytes(s['seal'])) for s in b], 'same input, same bytes')
        first = build_segments(rows[:4]); rest = build_segments(rows[4:], first[0]['seal']['head_hash'], first[0]['seal'])
        self.assertEqual(canon.seal_bytes(rest[0]['seal']), canon.seal_bytes(a[1]['seal']), 'sealing month by month equals sealing all at once')

    def test_builder_refuses_bad_input(self):
        rows = make_rows(months({'2026-07': 3}))
        bad = [dict(r) for r in rows]; bad[1]['actor'] = 'mallory'
        with self.assertRaisesRegex(SegmentError, 'does not verify'): build_segments(bad)
        with self.assertRaisesRegex(SegmentError, 'does not verify'): build_segments(rows[1:])           # not starting at the stated start hash
        with self.assertRaisesRegex(SegmentError, 'does not verify'): build_segments([rows[0], rows[2]])  # a row missing
        with self.assertRaisesRegex(SegmentError, 'does not verify'): build_segments([rows[1], rows[0], rows[2]])
        back = make_rows(['2026-08-01T00:00:00.000Z', '2026-07-01T00:00:00.000Z'])
        with self.assertRaisesRegex(SegmentError, 'out of order'): build_segments(back)
        self.assertEqual(build_segments([]), [])

    def test_export_reader_accepts_any_key_order_and_rejects_extra_columns(self):
        rows = make_rows(months({'2026-07': 2})); d = tmpdir(self)
        (d / 'ok.jsonl').write_text('\n'.join(json.dumps(dict(reversed(list(r.items())))) for r in rows) + '\n')
        self.assertEqual(seg.read_export(d / 'ok.jsonl'), rows)
        (d / 'bad.jsonl').write_text(json.dumps({**rows[0], 'extra': 1}) + '\n')
        with self.assertRaises(SegmentError): seg.read_export(d / 'bad.jsonl')


class Negative(unittest.TestCase):
    def setUp(self): self.rows, self.segs = sealed(); self.p = pairs(self.segs)

    def test_tampered_segment_bytes(self):
        s, b = self.p[1]; t = b.replace(b'ada', b'bob')
        with self.assertRaisesRegex(SegmentError, 'segment_sha256'): verify_segment(s, t)

    def test_tampered_row_with_attacker_recomputed_seal_digest_still_fails_on_the_chain(self):
        s, b = self.p[1]; lines = b.decode().split('\n'); r = json.loads(lines[0]); r['actor'] = 'mallory'; lines[0] = canon.canonical(r); t = '\n'.join(lines).encode()
        forged = {**s, 'segment_sha256': canon.sha256_hex(t)}
        with self.assertRaisesRegex(SegmentError, 'altered'): verify_segment(forged, t)

    def test_reordered_rows(self):
        s, b = self.p[0]; lines = b.decode().split('\n'); lines[0], lines[1] = lines[1], lines[0]; t = '\n'.join(lines).encode()
        with self.assertRaises(SegmentError): verify_segment({**s, 'segment_sha256': canon.sha256_hex(t)}, t)

    def test_truncated_segment(self):
        s, b = self.p[0]; t = b'\n'.join(b.split(b'\n')[:2]) + b'\n'
        with self.assertRaises(SegmentError): verify_segment(s, t)
        with self.assertRaises(SegmentError): verify_segment({**s, 'segment_sha256': canon.sha256_hex(t)}, t)   # sha re-pointed: count/head still disagree

    def test_non_canonical_segment_is_refused(self):
        s, b = self.p[0]; first = json.loads(b.decode().split('\n')[0]); t = (json.dumps(first, indent=1) + '\n' + b.decode().split('\n', 1)[1]).encode()
        with self.assertRaises(SegmentError): verify_segment({**s, 'segment_sha256': canon.sha256_hex(t)}, t)

    def test_missing_segment_in_the_middle(self):
        with self.assertRaisesRegex(SegmentError, 'does not chain|does not continue'): verify_archive([self.p[0], self.p[2]])

    def test_seals_reordered_or_duplicated(self):
        with self.assertRaises(SegmentError): verify_seal_chain([self.p[1][0], self.p[0][0], self.p[2][0]])
        with self.assertRaises(SegmentError): verify_seal_chain([self.p[0][0], self.p[0][0]])

    def test_wrong_anchor_start(self):
        with self.assertRaisesRegex(SegmentError, 'anchor does not match'): verify_archive(self.p, start_hash='1' * 64)

    def test_truncated_chain_is_caught_against_the_live_head(self):
        verify_archive(self.p[:2])      # alone, a shorter chain is internally consistent ...
        with self.assertRaisesRegex(SegmentError, 'expected head'): verify_archive(self.p[:2], expected_head=self.rows[-1]['hash'])   # ... but not against the database head

    def test_seal_altered_after_the_fact(self):
        bad = {**self.p[0][0], 'count': 99}
        with self.assertRaises(SegmentError): verify_segment(bad, self.p[0][1])
        with self.assertRaisesRegex(SegmentError, 'does not chain'): verify_seal_chain([bad, self.p[1][0]])
        with self.assertRaises(SegmentError): verify_segment({**self.p[0][0], 'unexpected': 1}, self.p[0][1])

    def test_segment_with_rows_of_another_month(self):
        rows = make_rows(['2026-07-31T23:00:00.000Z', '2026-08-01T00:00:00.000Z']); data = ''.join(canon.row_line(r) for r in rows).encode()
        s = {'schema': seg.SEAL_SCHEMA, 'period': '2026-07', 'first_seq': 1, 'last_seq': 2, 'count': 2, 'first_prev_hash': canon.GENESIS, 'head_hash': rows[-1]['hash'], 'segment_sha256': canon.sha256_hex(data), 'prev_seal_sha256': None}
        with self.assertRaisesRegex(SegmentError, 'another month'): verify_segment(s, data)


if __name__ == '__main__': unittest.main()
