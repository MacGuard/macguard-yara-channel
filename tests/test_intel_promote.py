"""The promotion of local intelligence runs: integrity is checked before anything is promoted, every mutation of a channel is refused, secrets never reach the SQL, and the SQL loads into the real INTEL schema.
Synthetic channels only (no real data, no network)."""
import hashlib, io, json, os, pathlib, sqlite3, sys, tempfile, unittest, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import intel_promote as ip

SCHEMA = (ROOT / 'admin/worker/migrations-intel/0001_intel.sql').read_text()
sha = lambda b: hashlib.sha256(b).hexdigest()
NOW = '2026-10-26T00:00:00Z'
JWT_HEAD = 'eyJhbGciOi' + 'JIUzI1NiJ9'   # assembled so that no secret-shaped literal sits in the repository
BEARER_BODY = 'abcdefghijklmnop' + '1234567890'


def write(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def vuln_channel(root, n=3, **tweak):
    """A single-file KEV-like channel: raw file, retrieval record, build report, manifest, records, and the run summary that points at them."""
    raw = json.dumps({'vulnerabilities': [{'cveID': f'CVE-2024-{i:04d}'} for i in range(n)]}).encode()
    d = root / 'chan'
    write(d / 'raw.json', raw)
    retr = {'bytes': len(raw), 'etag': '"e"', 'file': 'raw.json', 'final_url': f'https://cdn.example/x?sig=SECRETSIG&jwt={JWT_HEAD}.AAAAAAAAAAAAAAAAAAAA.BBBB', 'last_modified': 'Fri, 23 Oct 2026 19:30:18 GMT', 'redistribution_status_at_retrieval': 'allowed-with-conditions',
            'retrieved_at': '2026-10-25T03:46:29Z', 'sha256': sha(raw), 'source_id': 'cisa-kev', 'status': 200, 'url': 'https://www.cisa.gov/feed.json'}
    retr.update(tweak.get('retrieval', {}))
    recs = [{'affected': [{'product': 'p', 'vendor': 'v', 'version': {'kind': 'unspecified', 'raw': None}}] * (tweak.get('affected', 1)), 'dates': {'listed': '2022-03-03', 'published': None, 'updated': None}, 'epss': None,
             'evidence': {'file': 'raw.json', 'file_sha256': tweak.get('evidence_sha', sha(raw)), 'item_sha256': 'a' * 64, 'locator': f'vulnerabilities[{i}]', 'retrieved_at': retr['retrieved_at']}, 'ids': {'cve': [f'CVE-2024-{i:04d}'], 'euvd': [], 'ghsa': []},
             'schema': 'macguard.vuln-record/1', 'severity': None, 'source': 'cisa-kev', 'source_record_id': f'CVE-2024-{i:04d}', 'summary': tweak.get('title', f"O'Brien \"quoted\" title {i}"), 'title': tweak.get('title', f"O'Brien \"quoted\" title {i}")} for i in range(n)]
    write(d / 'vuln-records.jsonl', '\n'.join(json.dumps(r) for r in recs) + '\n')
    report = {'accepted': n, 'rejected': 0, 'declared_count': n, 'catalog_version': '2026.10.23'}
    write(d / 'build-report.json', json.dumps(report))
    arts = [{'path': p, 'bytes': (d / p).stat().st_size, 'sha256': sha((d / p).read_bytes())} for p in ('raw.json', 'vuln-records.jsonl', 'build-report.json')]
    write(d / 'manifest.json', json.dumps({'artifacts': arts}))
    summary = {'blocking_reasons': tweak.get('blocking', ['cisa-kev: the owner has not confirmed the redistribution decision']), 'channel': 'vulns', 'dir': str(d), 'publishable': False, 'retrieval': retr, 'source': 'cisa-kev', 'stats': dict(report, accepted=tweak.get('accepted', n)), 'version': 1}
    return write(root / 'kev.json', json.dumps(summary)), d


def run_main(args):
    import contextlib
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = ip.main(args)
    return code, json.loads(out.getvalue())


def load_sql(outdir):
    db = sqlite3.connect(':memory:')
    db.executescript(SCHEMA)
    for f in sorted(pathlib.Path(outdir).glob('chunk-*.sql')):
        db.executescript(f.read_text(encoding='utf-8'))
    return db


class PromoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def promote(self, summary, extra=()):
        out = self.root / 'out'
        code, res = run_main(['--out', str(out), '--by', 'ada', '--adapter-ref', 'abc1234', '--now', NOW, '--run', str(summary), *extra])
        return code, res, out

    def test_a_verified_channel_loads_into_the_real_schema_with_exact_counts_and_hashes(self):
        summary, _ = vuln_channel(self.root, n=5)
        code, res, out = self.promote(summary)
        self.assertEqual(code, 0, res)
        self.assertEqual(res['records_by_family'], {'kev': 5})
        db = load_sql(out)
        self.assertEqual(db.execute('select count(*) from intel_records').fetchone()[0], 5)
        for doc, h in db.execute('select doc, doc_sha256 from intel_records'):
            self.assertEqual(sha(doc.encode()), h)
        run = db.execute('select state, accepted, publishable, http_status, content_sha256 is not null from intel_runs').fetchone()
        self.assertEqual(run, ('COMPLETE', 5, 0, 200, 1))
        self.assertTrue(db.execute("select count(*) from intel_sources where integration='BLOCKED' and status_reason='api_key_required'").fetchone()[0] >= 3, 'sources without a connector are stated with their reason')
        self.assertEqual(db.execute("select integration from intel_sources where id='cisa-kev'").fetchone()[0], 'CONNECTED')
        self.assertEqual(db.execute("select integration, status_reason from intel_sources where id='nvd'").fetchone(), ('NOT_INTEGRATED', 'no_promoted_run'), 'a source without a promoted run is not shown as connected')

    def test_the_title_with_quotes_is_stored_verbatim_and_nothing_executes(self):
        summary, _ = vuln_channel(self.root, n=1, title="x'); DROP TABLE intel_records; --")
        _, _, out = self.promote(summary)
        db = load_sql(out)
        self.assertEqual(db.execute('select title from intel_records').fetchone()[0], "x'); DROP TABLE intel_records; --")

    def test_signed_urls_and_token_shaped_text_never_reach_the_sql(self):
        tok = 'ghp_' + 'A' * 30
        summary, _ = vuln_channel(self.root, blocking=[f'blocked because Authorization: Bearer {BEARER_BODY} and {tok}'], title=f'see {tok} for details')
        _, _, out = self.promote(summary)
        blob = ''.join(p.read_text(encoding='utf-8') for p in out.glob('chunk-*.sql'))
        for forbidden in ('SECRETSIG', JWT_HEAD, 'final_url', tok, BEARER_BODY):
            self.assertNotIn(forbidden, blob)
        self.assertIn('[redacted]', blob)

    def test_every_mutation_of_a_channel_is_refused_and_nothing_of_it_is_promoted(self):
        cases = {
            'artifact bytes changed': lambda d, s: (d / 'vuln-records.jsonl').write_bytes((d / 'vuln-records.jsonl').read_bytes() + b'\n'),
            'artifact removed': lambda d, s: (d / 'build-report.json').unlink(),
            'raw file replaced': lambda d, s: (d / 'raw.json').write_bytes(b'{"vulnerabilities": []}'),
            'manifest removed': lambda d, s: (d / 'manifest.json').unlink(),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                with tempfile.TemporaryDirectory() as t:
                    r = pathlib.Path(t)
                    summary, d = vuln_channel(r)
                    mutate(d, summary)
                    code, res = run_main(['--out', str(r / 'o'), '--by', 'ada', '--adapter-ref', 'x', '--now', NOW, '--run', str(summary)])
                    self.assertEqual(code, 3, name)
                    self.assertEqual(res['runs'], [], name)
                    self.assertEqual(len(res['skipped']), 1, name)
                    self.assertEqual(res['records_by_family'], {}, name)

    def test_count_and_evidence_hash_disagreements_are_refused(self):
        for tweak, why in (({'accepted': 99}, 'channel accepted 99'), ({'evidence_sha': 'f' * 64}, 'file hash that is not the retrieved file')):
            with self.subTest(why):
                with tempfile.TemporaryDirectory() as t:
                    r = pathlib.Path(t)
                    summary, _ = vuln_channel(r, **tweak)
                    code, res = run_main(['--out', str(r / 'o'), '--by', 'ada', '--adapter-ref', 'x', '--now', NOW, '--run', str(summary)])
                    self.assertEqual(code, 3)
                    self.assertIn(why, res['skipped'][0]['reason'])

    def test_a_huge_affected_list_is_shrunk_under_the_statement_limit_and_says_so(self):
        summary, _ = vuln_channel(self.root, n=1, affected=6000)
        code, res, out = self.promote(summary)
        self.assertEqual(code, 0, res)
        for p in out.glob('chunk-*.sql'):
            for line in p.read_text(encoding='utf-8').splitlines():
                self.assertLess(len(line.encode()), ip.MAX_STATEMENT)
        doc = json.loads(load_sql(out).execute('select doc from intel_records').fetchone()[0])
        self.assertTrue(doc['affected_truncated'])
        self.assertEqual(doc['affected_total'], 6000)

    def test_events_are_structured_use_real_timestamps_and_the_vocabulary_of_levels(self):
        summary, _ = vuln_channel(self.root)
        _, _, out = self.promote(summary)
        db = load_sql(out)
        rows = db.execute('select ts, level, component, family, outcome from intel_events order by id').fetchall()
        self.assertEqual(rows[0][:3], ('2026-10-25T03:46:29Z', 'INFO', 'intel.fetch'))
        self.assertEqual({r[1] for r in rows} - {'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'}, set())
        self.assertTrue(any(r[2] == 'intel.quarantine' and r[1] == 'WARN' for r in rows), 'a retention by policy is a WARN event, not silence')
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute('delete from intel_events')

    def test_epss_keeps_only_cves_referenced_by_promoted_records_and_still_counts_the_whole_file(self):
        summary, _ = vuln_channel(self.root, n=3)
        raw = '\n'.join(json.dumps({'cve': f'CVE-2024-{i:04d}', 'epss': '0.5', 'percentile': '0.9', 'model_version': 'v1', 'score_date': '2026-10-24T12:00:00Z', 'schema': 'macguard.epss-record/1'}) for i in range(10)) + '\n'
        d = self.root / 'epss'
        write(d / 'epss.jsonl', raw)
        retr = {'bytes': len(raw), 'file': 'epss.jsonl', 'retrieved_at': '2026-10-25T04:00:00Z', 'sha256': sha(raw.encode()), 'status': 200, 'url': 'https://epss.example'}
        write(d / 'build-report.json', json.dumps({'accepted': 10}))
        write(d / 'manifest.json', json.dumps({'artifacts': [{'path': 'epss.jsonl', 'bytes': len(raw), 'sha256': sha(raw.encode())}, {'path': 'build-report.json', 'bytes': (d / 'build-report.json').stat().st_size, 'sha256': sha((d / 'build-report.json').read_bytes())}]}))
        es = write(self.root / 'epss.json', json.dumps({'dir': str(d), 'retrieval': retr, 'stats': {'accepted': 10}, 'publishable': False, 'blocking_reasons': [], 'source': 'first-epss'}))
        code, res, out = self.promote(summary, ['--epss', str(d / 'epss.jsonl'), '--epss-summary', str(es)])
        self.assertEqual(code, 0, res)
        db = load_sql(out)
        self.assertEqual(db.execute("select count(*) from intel_records where family='epss'").fetchone()[0], 3)
        self.assertEqual(db.execute("select accepted, retained from intel_runs where source_id='first-epss'").fetchone(), (10, 3))

    def test_suricata_rules_are_parsed_joined_to_their_verdicts_and_a_line_without_sid_gets_a_stable_id(self):
        rules = '# comment\nalert tcp any any -> any 80 (msg:"ET TEST \\"quoted\\""; sid:2000105; rev:3; classtype:trojan-activity;)\nalert udp any any -> any 53 (msg:"no sid here";)\nalert tcp any any -> any 80 (msg:"dup"; sid:2000105; rev:4;)\n'
        rp = write(self.root / 'etopen.rules', rules)
        line2 = rules.splitlines()[2].encode()
        lh = sha(line2)[:16]
        matrix = write(self.root / 'm.csv', 'run,source,family,engine,platform,rule,sha256,validated,functional,performance,held_back,quarantine_state,reason\n'
                       f'x,s,suricata,e,p,suricata:2000105,{"a" * 64},VALIDATED,NOT_RUN,INCONCLUSIVE,True,approved,\n' f'x,s,suricata,e,p,suricata:line:{lh},{"b" * 64},FAILED,NOT_RUN,NOT_RUN,True,quarantined,\n')
        out = self.root / 'o'
        code, res = run_main(['--out', str(out), '--by', 'ada', '--adapter-ref', 'x', '--now', NOW, '--suricata', str(rp), str(matrix), '--suricata-evidence-head', 'c' * 64])
        self.assertEqual(code, 0, res)
        db = load_sql(out)
        rows = {r[0]: r for r in db.execute("select id, title, validated, state, held_back, body from intel_records where family='suricata'")}
        self.assertEqual(set(rows), {'suricata:2000105', f'suricata:line:{lh}'}, 'the duplicate sid collapses to one record')
        self.assertEqual(rows['suricata:2000105'][1], 'ET TEST \\"quoted\\"')
        self.assertEqual((rows['suricata:2000105'][2], rows['suricata:2000105'][3], rows['suricata:2000105'][4]), ('VALIDATED', 'approved', 1), 'the quality verdict is the one of the matrix; held back stays 1')
        self.assertEqual(rows[f'suricata:line:{lh}'][2:4], ('FAILED', 'quarantined'))
        self.assertEqual(db.execute("select rejected from intel_runs where source_id='emerging-threats-open'").fetchone()[0], 1)

    def test_sigma_rule_text_must_match_its_hash(self):
        body = b'title: X\nlogsource: {product: windows}\ndetection: {condition: selection}\n'
        zp = self.root / 'sigma.zip'
        with zipfile.ZipFile(zp, 'w') as z:
            z.writestr('rules/win/x.yml', body)
        zsha = sha(zp.read_bytes())
        rec = {'id': 'u-1', 'title': 'X', 'path': 'rules/win/x.yml', 'rule_sha256': sha(body), 'level': 'high', 'status': 'test', 'tags': [], 'attack': [], 'logsource': {}, 'date': '2022-01-01', 'modified': None, 'author': 'a', 'deprecated': False}
        jl = write(self.root / 'sigma-rules.jsonl', json.dumps(rec) + '\n')
        matrix = write(self.root / 'm.csv', 'run,source,family,engine,platform,rule,sha256,validated,functional,performance,held_back,quarantine_state,reason\nr,sigmahq,sigma,e,p,sigma:u-1,' + 'a' * 64 + ',VALIDATED,NOT_RUN,N/A,True,approved,\n')
        live = write(self.root / 'live.json', json.dumps({'blocking_reasons': ['sigmahq: owner has not confirmed'], 'publishable': False, 'retrieval': {'sha256': zsha, 'bytes': 1, 'status': 200, 'retrieved_at': '2026-10-25T03:45:00Z', 'file': 'sigma_all_rules.zip', 'final_url': 'https://x?sig=ZZZ&jwt=YYY'}, 'stats': {'accepted': 1}}))
        code, res = run_main(['--out', str(self.root / 'o'), '--by', 'ada', '--adapter-ref', 'x', '--now', NOW, '--sigma', str(jl), str(zp), str(matrix), str(live)])
        self.assertEqual(code, 0, res)
        db = load_sql(self.root / 'o')
        self.assertEqual(db.execute("select body from intel_records where family='sigma'").fetchone()[0], body.decode())
        blob = ''.join(p.read_text(encoding='utf-8') for p in (self.root / 'o').glob('chunk-*.sql'))
        self.assertNotIn('jwt=YYY', blob)
        with zipfile.ZipFile(zp, 'w') as z:
            z.writestr('rules/win/x.yml', body + b'# tampered\n')
        live.write_text(json.dumps(dict(json.loads(live.read_text()), retrieval=dict(json.loads(live.read_text())['retrieval'], sha256=sha(zp.read_bytes())))))
        code, res = run_main(['--out', str(self.root / 'o2'), '--by', 'ada', '--adapter-ref', 'x', '--now', NOW, '--sigma', str(jl), str(zp), str(matrix), str(live)])
        self.assertEqual(code, 3)
        self.assertIn('does not match its SHA-256', res['skipped'][0]['reason'])


if __name__ == '__main__':
    unittest.main()
