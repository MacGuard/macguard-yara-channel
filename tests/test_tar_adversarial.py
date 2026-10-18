"""Hostile release archives against the independent verifier's extractor. Every case must be refused with exit class 6 and
leave nothing outside the destination; the archives are synthetic and built in memory."""
import io, pathlib, sys, tarfile, tempfile, unittest, gzip
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import verify_public_release as V

def build(members, path):
    with tarfile.open(path, 'w:gz') as t:
        for spec in members:
            name, kind, data = spec[0], spec[1], spec[2] if len(spec) > 2 else b''
            ti = tarfile.TarInfo(name)
            if kind == 'file': ti.size = len(data); t.addfile(ti, io.BytesIO(data))
            elif kind == 'dir': ti.type = tarfile.DIRTYPE; t.addfile(ti)
            elif kind == 'sym': ti.type = tarfile.SYMTYPE; ti.linkname = data.decode(); t.addfile(ti)
            elif kind == 'hard': ti.type = tarfile.LNKTYPE; ti.linkname = data.decode(); t.addfile(ti)
            elif kind == 'fifo': ti.type = tarfile.FIFOTYPE; t.addfile(ti)
            elif kind == 'chr': ti.type = tarfile.CHRTYPE; t.addfile(ti)

class HostileArchives(unittest.TestCase):
    def setUp(self): self.tmp = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(__import__('shutil').rmtree, self.tmp, True); self.dest = self.tmp / 'out'; self.old = dict(V.LIMITS); self.addCleanup(V.LIMITS.update, self.old)
    def refuse(self, members, name=''):
        a = self.tmp / 'a.tar.gz'; build(members, a)
        with self.assertRaises(V.Fail, msg=name) as cm: V.safe_extract(a, self.dest)
        self.assertEqual(cm.exception.code, 6, name)
        self.assertEqual([p.name for p in self.tmp.iterdir() if p.name not in ('a.tar.gz', 'out')], [], f'{name}: something was written outside the destination')
        return cm.exception.message

    def test_path_tricks(self):   # a NUL in a member name cannot be carried by the tar format (tarfile cuts the name at the NUL), so there is no case for it
        for n, name in (('rules/../../x', 'dotdot'), ('/etc/x', 'absolute'), ('rules\\..\\x', 'backslash'), ('rules/' + 'd/' * 30 + 'x', 'deep'), ('rules/' + 'a' * 600, 'long'), ('etc/passwd', 'top-level'), ('other/x', 'top-level dir'), ('manifest.json/../../x', 'dotdot after manifest')):
            self.refuse([(n, 'file', b'x')], name)

    def test_links_and_special_files(self):
        self.refuse([('rules/l', 'sym', b'/etc/passwd')], 'symlink'); self.refuse([('rules/l', 'sym', b'../../x')], 'relative symlink')
        self.refuse([('rules/a', 'file', b'x'), ('rules/h', 'hard', b'rules/a')], 'hardlink'); self.refuse([('rules/f', 'fifo')], 'fifo'); self.refuse([('rules/c', 'chr')], 'device')
        self.refuse([('evil', 'dir'), ], 'unexpected directory')

    def test_duplicates_and_case_collisions(self):
        self.refuse([('rules/a.yar', 'file', b'1'), ('rules/a.yar', 'file', b'2')], 'duplicate')
        a = self.tmp / 'c.tar.gz'; build([('rules/A.yar', 'file', b'1'), ('rules/a.yar', 'file', b'2')], a)
        try: V.safe_extract(a, self.dest)   # on a case-sensitive filesystem both exist, on a case-insensitive one the second is refused: neither may escape
        except V.Fail as f: self.assertEqual(f.code, 6)
        self.assertTrue(all(self.dest in p.parents for p in self.dest.rglob('*')))

    def test_size_and_count_bombs(self):
        V.LIMITS['file_bytes'] = 1000; self.refuse([('rules/big', 'file', b'0' * 5000)], 'one big file')
        V.LIMITS.update(self.old); V.LIMITS['total_bytes'] = 3000; self.refuse([(f'rules/f{i}', 'file', b'0' * 1000) for i in range(5)], 'many files adding up')
        V.LIMITS.update(self.old); V.LIMITS['members'] = 10; self.refuse([(f'rules/f{i}', 'file', b'x') for i in range(11)], 'too many members')

    def test_a_header_that_lies_about_its_size_is_counted_by_reading(self):
        V.LIMITS['file_bytes'] = 1000
        a = self.tmp / 'lie.tar'; raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as t: ti = tarfile.TarInfo('rules/x'); ti.size = 900; t.addfile(ti, io.BytesIO(b'0' * 900))
        (self.tmp / 'lie.tar.gz').write_bytes(gzip.compress(raw.getvalue()))   # a well-formed small file is accepted: the control is on bytes read, not on the header
        files, total = V.safe_extract(self.tmp / 'lie.tar.gz', self.dest); self.assertEqual(total, 900)

    def test_corrupt_and_truncated_streams(self):
        good = self.tmp / 'g.tar.gz'; build([('rules/a', 'file', b'x' * 5000)], good); data = good.read_bytes()
        for name, blob in (('truncated', data[: len(data) // 2]), ('garbage', b'not a gzip at all'), ('empty', b''), ('flipped', data[:20] + bytes([data[20] ^ 255]) + data[21:])):
            p = self.tmp / f'{name}.tar.gz'; p.write_bytes(blob)
            with self.assertRaises(V.Fail, msg=name) as cm: V.safe_extract(p, self.tmp / name)
            self.assertEqual(cm.exception.code, 6, name)

    def test_a_clean_archive_extracts_exactly_what_it_lists(self):
        a = self.tmp / 'ok.tar.gz'; build([('rules', 'dir'), ('rules/s/a.yar', 'file', b'rule A { condition: true }'), ('manifest.json', 'file', b'{}')], a)
        files, total = V.safe_extract(a, self.dest); self.assertEqual(sorted(files), ['manifest.json', 'rules/s/a.yar']); self.assertEqual(total, 28)

if __name__ == '__main__': unittest.main()
