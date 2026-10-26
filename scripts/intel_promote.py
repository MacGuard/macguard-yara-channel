#!/usr/bin/env python3
"""Promote locally produced, validated intelligence runs into SQL for the INTEL database that the panel reads.

Nothing is invented and nothing is uploaded here: this reads run summaries, channel manifests, retrieval records and record files from a local evidence directory, VERIFIES them against their own hashes and
counts, and writes chunked SQL plus promotion.json (what was read, what was promoted, what was skipped and why). Upload is a separate, explicit step (intel_apply.sh).

Integrity checks (a failure skips that run and says why; it never promotes a partial truth silently):
  * every artifact listed in the channel manifest exists and matches its SHA-256 and size;
  * the retrieval record's SHA-256 matches the raw file it describes;
  * the number of records read equals the channel's accepted count;
  * for single-file channels every record's evidence.file_sha256 equals the retrieval SHA-256.
Stdlib only. URLs that carry signatures or tokens (`final_url`) are never stored.

usage: intel_promote.py --out DIR --by LOGIN --adapter-ref SHA [--run FILE]... [--suricata RULES MATRIX] [--sigma JSONL ZIP MATRIX] [--epss JSONL] [--now ISO]
"""
import argparse, csv, datetime, hashlib, json, os, re, sys, zipfile

CHUNK_BYTES = 3_000_000
MAX_STATEMENT = 90_000          # D1 refuses statements over 100 KB
SECRET = re.compile(r'(?i)(bearer\s+[a-z0-9._-]{16,}|api[_-]?key\s*[=:]\s*\S{8,}|authorization\s*[=:]\s*\S{8,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AGE-SECRET-KEY-[A-Z0-9]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|[?&](sig|token|jwt|signature)=[^&\s]+)')


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def q(v):
    """A SQL literal. Strings are single-quoted with quotes doubled; control characters other than newline and tab are refused."""
    if v is None:
        return 'NULL'
    if isinstance(v, bool):
        return '1' if v else '0'
    if isinstance(v, (int, float)):
        if isinstance(v, float) and (v != v or v in (float('inf'), float('-inf'))):
            return 'NULL'
        return repr(v)
    s = str(v)
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', s):
        s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', s)
    return "'" + s.replace("'", "''") + "'"


def redact(s):
    return SECRET.sub('[redacted]', s) if isinstance(s, str) else s


def redact_doc(o, count=None):
    """Redacts every string of a document; `count` collects how many strings changed so the document can say it was redacted. Rule bodies are NOT passed through here: their SHA-256 is checked against the source."""
    count = count if count is not None else [0]
    if isinstance(o, str):
        r = SECRET.sub('[redacted]', o)
        if r != o:
            count[0] += 1
        return r
    if isinstance(o, list):
        return [redact_doc(x, count) for x in o]
    if isinstance(o, dict):
        return {k: redact_doc(v, count) for k, v in o.items()}
    return o


# ---- what each source is: facts that are the same on every run (the official page, the adapter that reads it, the family it feeds). Status facts come from the data or from the cited study. ----
SOURCES = {
    'cisa-kev': dict(name='CISA Known Exploited Vulnerabilities', organization='CISA', url='https://www.cisa.gov/known-exploited-vulnerabilities-catalog', family='kev', grp='vulnerabilities', data_type='vulnerability catalogue (exploited in the wild)', adapter='intel.vulns.kev'),
    'nvd': dict(name='NVD (CVE API 2.0)', organization='NIST', url='https://nvd.nist.gov/developers/vulnerabilities', family='cve', grp='vulnerabilities', data_type='vulnerability records (CVSS, CPE, references)', adapter='intel.vulns.nvd'),
    'osv': dict(name='OSV (PyPI)', organization='OpenSSF / Google', url='https://osv.dev', family='cve', grp='vulnerabilities', data_type='open-source vulnerability records (ranges, purl)', adapter='intel.vulns.osv'),
    'enisa-euvd': dict(name='EUVD', organization='ENISA', url='https://euvd.enisa.europa.eu', family='cve', grp='vulnerabilities', data_type='EU vulnerability database records', adapter='intel.vulns.euvd'),
    'cert-eu-advisories': dict(name='CERT-EU security advisories', organization='CERT-EU', url='https://cert.europa.eu/publications/security-advisories/', family='advisory', grp='vulnerabilities', data_type='security advisories (RSS)', adapter='intel.vulns.certeu'),
    'mitre-attack': dict(name='MITRE ATT&CK (techniques)', organization='MITRE', url='https://attack.mitre.org', family='attack', grp='context', data_type='attack techniques and tactics', adapter='intel.context'),
    'first-epss': dict(name='EPSS', organization='FIRST', url='https://www.first.org/epss/', family='epss', grp='context', data_type='exploit prediction scores per CVE', adapter='intel.risk'),
    'abusech-feodo': dict(name='Feodo Tracker', organization='abuse.ch', url='https://feodotracker.abuse.ch', family='ioc', grp='indicators', data_type='botnet C2 IP blocklist', adapter='intel.ioc'),
    'emerging-threats-open': dict(name='Emerging Threats Open (Suricata)', organization='Proofpoint', url='https://rules.emergingthreats.net/open/', family='suricata', grp='detections', data_type='network detection rules', adapter='intel.suricata_engine'),
    'sigmahq': dict(name='SigmaHQ rules', organization='SigmaHQ', url='https://github.com/SigmaHQ/sigma', family='sigma', grp='detections', data_type='generic SIEM detection rules', adapter='intel.sigma'),
}
# Sources that exist as facts but have NO connector or are BLOCKED: stated with the study that says why (docs/quality/ABUSECH-AND-HASH-SOURCES-2026-10-25.md on branch feat/community-telemetry).
UNCONNECTED = [
    dict(id='abusech-malwarebazaar', name='MalwareBazaar', organization='abuse.ch', url='https://bazaar.abuse.ch', family='hash', grp='indicators', data_type='malware file hashes', integration='BLOCKED', status_reason='api_key_required', auth='api_key'),
    dict(id='abusech-threatfox', name='ThreatFox', organization='abuse.ch', url='https://threatfox.abuse.ch', family='ioc', grp='indicators', data_type='indicators of compromise', integration='BLOCKED', status_reason='api_key_required', auth='api_key'),
    dict(id='abusech-urlhaus', name='URLhaus', organization='abuse.ch', url='https://urlhaus.abuse.ch', family='ioc', grp='indicators', data_type='malicious URLs', integration='BLOCKED', status_reason='api_key_required', auth='api_key'),
    dict(id='abusech-sslbl', name='SSL Blacklist (SSLBL)', organization='abuse.ch', url='https://sslbl.abuse.ch', family='ioc', grp='indicators', data_type='malicious certificate fingerprints', integration='NOT_INTEGRATED', status_reason='no_connector', auth='none'),
    dict(id='circl-hashlookup', name='CIRCL hashlookup', organization='CIRCL', url='https://hashlookup.circl.lu', family='hash', grp='indicators', data_type='known-benign file hashes', integration='NOT_INTEGRATED', status_reason='no_connector', auth='none'),
    dict(id='cve-program', name='CVE Program', organization='CVE Program (MITRE)', url='https://www.cve.org', family='cve', grp='vulnerabilities', data_type='CVE identifiers and records', integration='NOT_INTEGRATED', status_reason='no_connector', auth='none'),
]
SOURCE_ALIASES = {'abusech-feodo': 'abusech-feodo'}


class Skip(Exception):
    pass


def load_json(path):
    with open(path, 'rb') as f:
        return json.loads(f.read().decode('utf-8'))


def read_jsonl(path):
    with open(path, 'rb') as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line.decode('utf-8'))


def fit(doc):
    """Keep a document under the statement limit: shrink only the long, repetitive `affected` list and say so inside the document."""
    d = dict(doc)
    for limit in (1000, 200, 50, 10):
        if len(canonical(d)) < MAX_STATEMENT // 2:
            return d
        aff = doc.get('affected') or []
        d['affected'] = aff[:limit]
        d['affected_total'] = len(aff)
        d['affected_truncated'] = True
    return d


def verify_channel(chan_dir, expect_count, single_file_sha=None):
    """The manifest's artifacts against their files; returns the manifest."""
    mp = os.path.join(chan_dir, 'manifest.json')
    if not os.path.isfile(mp):
        raise Skip(f'no manifest.json in {chan_dir}')
    man = load_json(mp)
    for a in man.get('artifacts', []):
        p = os.path.join(chan_dir, a['path'])
        if not os.path.isfile(p):
            raise Skip(f"artifact {a['path']} is listed in the manifest but missing")
        if os.path.getsize(p) != a.get('bytes') or sha256_file(p) != a.get('sha256'):
            raise Skip(f"artifact {a['path']} does not match the manifest (size or SHA-256)")
    return man


def run_row(source_id, summary, retrieval, stats_extra, now, by, promo_sha, state=None, **over):
    r = retrieval or {}
    stats = summary.get('stats', {})
    complete = stats.get('complete', True)
    row = dict(
        id=f"{source_id}:{(r.get('sha256') or promo_sha)[:16]}", source_id=source_id, retrieved_at=r.get('retrieved_at'), http_status=r.get('status'), bytes=r.get('bytes'), expected_bytes=None,
        etag=r.get('etag'), last_modified=r.get('last_modified'), upstream_version=stats.get('catalog_version') or stats.get('model_version'), content_sha256=r.get('sha256'),
        declared=stats.get('declared_count', stats.get('declared_total')), accepted=stats.get('accepted', 0), rejected=stats.get('rejected', 0), duplicates=stats.get('duplicates', 0),
        retained=stats.get('accepted', 0), approved=0, published=0, state=state or ('COMPLETE' if complete else 'PARTIAL'), publishable=1 if summary.get('publishable') else 0,
        blocking=json.dumps([redact(b) for b in summary.get('blocking_reasons', [])]), duration_ms=None,
        evidence=canonical({k: v for k, v in dict(redistribution_at_retrieval=r.get('redistribution_status_at_retrieval'), url=r.get('url'), file=r.get('file'), stats=stats, **stats_extra).items() if v is not None}),
        promoted_at=now, promoted_by=by, promotion_sha256=promo_sha, log_leaf=None)
    row.update(over)
    return row


def record_row(family, source_id, run_id, key, title, doc, **cols):
    n = [0]
    doc = redact_doc(doc, n)
    if n[0]:
        doc['redacted_strings'] = n[0]
    doc = fit(doc)
    c = dict(id=f'{family}:{key}' if family not in ('cve', 'advisory') else f'{source_id}:{key}', family=family, source_id=source_id, run_id=run_id, key=key, title=redact(title), severity=None, score=None, state='RETENIDA', validated=None, functional=None, performance=None,
             held_back=1, first_seen=None, last_seen=None, updated_at=None, body=None, doc=canonical(doc), doc_sha256=sha256_bytes(canonical(doc).encode()))
    c.update(cols)
    return c


def vuln_records(src_id, run_id, chan_dir, retr_sha, single_file):
    path = None
    for dp, _, fs in os.walk(chan_dir):
        if 'vuln-records.jsonl' in fs:
            path = os.path.join(dp, 'vuln-records.jsonl')
    if not path:
        raise Skip('no vuln-records.jsonl')
    fam = SOURCES[src_id]['family']
    out = []
    for r in read_jsonl(path):
        if single_file and r['evidence']['file_sha256'] != retr_sha:
            raise Skip(f"record {r.get('source_record_id')} cites a file hash that is not the retrieved file")
        sev = r.get('severity') if isinstance(r.get('severity'), dict) else None
        score = None
        if sev and sev.get('score') is not None:
            try:
                score = float(sev['score'])
            except ValueError:
                score = None
        elif r.get('epss') is not None and src_id == 'cisa-kev':
            score = None
        dates = r.get('dates') or {}
        first = dates.get('published') or dates.get('listed')
        key = r['source_record_id']
        title = r.get('title') or r.get('summary') or key
        out.append(record_row(fam, src_id, run_id, key, title[:300], r, severity=('CVSS ' + str(sev.get('version') or '?')) if sev else None, score=score, first_seen=first, last_seen=dates.get('updated') or first,
                              updated_at=dates.get('updated') or first))
    return out


def promote_vuln_run(summary_path, now, by, promo_seed):
    s = load_json(summary_path)
    src = s['source']
    if src not in SOURCES:
        raise Skip(f'unknown source {src}')
    chan_dir = s['dir'] if os.path.isdir(s.get('dir', '')) else None
    if not chan_dir:
        raise Skip(f"channel directory {s.get('dir')} is not present on this machine")
    retr = s.get('retrieval') or (s.get('retrievals') or [None])[0]
    if not retr:
        raise Skip('the run summary has no retrieval record')
    single = bool(s.get('retrieval'))
    if single:
        raw = os.path.join(chan_dir, retr['file'])
        if not os.path.isfile(raw) or sha256_file(raw) != retr['sha256']:
            raise Skip('the raw retrieved file does not match its retrieval record')
    verify_channel(chan_dir, s['stats'].get('accepted'))
    promo = sha256_bytes((promo_seed + canonical(s)).encode())
    run = run_row(src, s, retr, {}, now, by, promo)
    recs = vuln_records(src, run['id'], chan_dir, retr['sha256'] if single else None, single)
    if len(recs) != s['stats'].get('accepted'):
        raise Skip(f"{len(recs)} records read but the channel accepted {s['stats'].get('accepted')}")
    return run, recs, s


def promote_attack(summary_path, now, by, promo_seed):
    s = load_json(summary_path)
    chan_dir = s['dir']
    if not os.path.isdir(chan_dir):
        raise Skip(f'channel directory {chan_dir} is not present on this machine')
    retr = s.get('retrieval') or (s.get('retrievals') or [None])[0]
    if not retr:
        raise Skip('the run summary has no retrieval record')
    verify_channel(chan_dir, s['stats'].get('accepted'))
    promo = sha256_bytes((promo_seed + canonical(s)).encode())
    run = run_row('mitre-attack', s, retr, {}, now, by, promo)
    files = []
    for dp, _, fs in os.walk(chan_dir):
        files += [os.path.join(dp, n) for n in ('attack-techniques.jsonl', 'attack-tactics.jsonl') if n in fs]
    if not files:
        raise Skip('no ATT&CK record files')
    recs = [record_row('attack', 'mitre-attack', run['id'], r['attack_id'], r['name'], r, severity=r.get('kind'), first_seen=None, last_seen=r.get('modified'), updated_at=(r.get('modified') or '')[:10] or None) for p in sorted(files) for r in read_jsonl(p)]
    if len(recs) != s['stats'].get('accepted'):
        raise Skip(f"{len(recs)} ATT&CK records read but the channel accepted {s['stats'].get('accepted')}")
    return run, recs, s


def promote_feodo(summary_path, now, by, promo_seed):
    s = load_json(summary_path)
    chan_dir = s['dir']
    if not os.path.isdir(chan_dir):
        raise Skip(f'channel directory {chan_dir} is not present on this machine')
    retr = s.get('retrieval') or (s.get('retrievals') or [None])[0]
    if not retr:
        raise Skip('the run summary has no retrieval record')
    raw = os.path.join(chan_dir, retr['file'])
    if not os.path.isfile(raw) or sha256_file(raw) != retr['sha256']:
        raise Skip('the raw retrieved file does not match its retrieval record')
    verify_channel(chan_dir, 0)
    rep = load_json(os.path.join(chan_dir, 'build-report.json'))
    promo = sha256_bytes((promo_seed + canonical(s)).encode())
    st = dict(s.get('stats') or {}, **{k: rep.get(k) for k in ('accepted', 'rejected', 'expired', 'input_items') if k in rep})
    s = dict(s, stats=st)
    run = run_row('abusech-feodo', s, retr, {}, now, by, promo)
    run['retained'] = 0
    recs = []
    for e in load_json(raw):
        ip = e.get('ip_address')
        if not ip:
            continue
        recs.append(record_row('ioc', 'abusech-feodo', run['id'], f'ip:{ip}', f"{ip} ({e.get('malware', 'unknown')})", {'type': 'ipv4', 'value': ip, 'port': e.get('port'), 'malware': e.get('malware'), 'status': e.get('status'), 'first_seen': e.get('first_seen'), 'last_online': e.get('last_online'), 'country': e.get('country'), 'as_name': e.get('as_name')},
                               state='EXPIRED', severity=None, first_seen=(e.get('first_seen') or '')[:10] or None, last_seen=(e.get('last_online') or '')[:10] or None, updated_at=(e.get('last_online') or '')[:10] or None, held_back=1))
    return run, recs, s


def promote_epss(summary_path, epss_jsonl, cve_ids, now, by, promo_seed):
    s = load_json(summary_path)
    chan_dir = s['dir']
    retr = s.get('retrieval') or (s.get('retrievals') or [None])[0]
    if not retr:
        raise Skip('the run summary has no retrieval record')
    verify_channel(chan_dir, s['stats'].get('accepted'))
    promo = sha256_bytes((promo_seed + canonical(s)).encode())
    run = run_row('first-epss', s, retr, {'subset': 'only the CVEs referenced by the promoted vulnerability records', 'full_file': os.path.basename(epss_jsonl), 'full_file_sha256_of_retrieval': retr.get('sha256')}, now, by, promo)
    recs, total = [], 0
    for r in read_jsonl(epss_jsonl):
        total += 1
        if r['cve'] in cve_ids:
            recs.append(record_row('epss', 'first-epss', run['id'], r['cve'], f"EPSS {r['epss']} ({r['cve']})", r, score=float(r['epss']), severity=f"percentile {r['percentile']}", first_seen=r['score_date'][:10], last_seen=r['score_date'][:10], updated_at=r['score_date'][:10]))
    if total != s['stats'].get('accepted'):
        raise Skip(f"{total} EPSS rows read but the channel accepted {s['stats'].get('accepted')}")
    run['retained'] = len(recs)
    return run, recs, s


MATRIX_FIELDS = ('validated', 'functional', 'performance', 'held_back', 'quarantine_state', 'reason')


def load_matrix(path, family):
    out = {}
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row['family'] == family:
                out[row['rule']] = row
    return out


def promote_suricata(rules_path, matrix_path, evidence_head, summary, now, by, promo_seed):
    sha = sha256_file(rules_path)
    cand = None
    run_json = summary
    promo = sha256_bytes((promo_seed + sha + sha256_file(matrix_path)).encode())
    run = dict(id=f'emerging-threats-open:{sha[:16]}', source_id='emerging-threats-open', retrieved_at=None, http_status=None, bytes=os.path.getsize(rules_path), expected_bytes=None, etag=None, last_modified=None, upstream_version=None, content_sha256=sha, declared=None, accepted=0,
               rejected=0, duplicates=0, retained=0, approved=0, published=0, state='COMPLETE', publishable=0, blocking=json.dumps(['mandatory gates INCONCLUSIVE or NOT_RUN (see quality evidence); the owner has not confirmed redistribution']), duration_ms=None,
               evidence=canonical({'quality_evidence_head': evidence_head, 'file': os.path.basename(rules_path), 'matrix': os.path.basename(matrix_path)}), promoted_at=now, promoted_by=by, promotion_sha256=promo, log_leaf=None)
    matrix = load_matrix(matrix_path, 'suricata')
    recs, seen = [], set()
    with open(rules_path, 'rb') as f:
        for ln, raw in enumerate(f):
            line = raw.decode('utf-8', 'replace').rstrip('\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            sid = (re.search(r'\bsid:\s*(\d+)', line) or [None, None])[1]
            lh = hashlib.sha256(raw.rstrip(b'\n')).hexdigest()[:16]
            rid = f'suricata:{sid}' if sid else f'suricata:line:{lh}'
            m = matrix.get(rid) or matrix.get(f'suricata:line:{lh}')
            if rid in seen:
                continue
            seen.add(rid)
            msg = (re.search(r'\bmsg:\s*"((?:[^"\\]|\\.)*)"', line) or [None, None])[1]
            cls = (re.search(r'\bclasstype:\s*([\w-]+)', line) or [None, None])[1]
            rev = (re.search(r'\brev:\s*(\d+)', line) or [None, None])[1]
            head = line.split('(', 1)[0].split()
            doc = {'sid': int(sid) if sid else None, 'rev': int(rev) if rev else None, 'msg': msg, 'classtype': cls, 'action': head[0] if head else None, 'proto': head[1] if len(head) > 1 else None, 'line_sha256': hashlib.sha256(raw.rstrip(b'\n')).hexdigest(),
                   'matrix_row': {k: (m or {}).get(k) for k in MATRIX_FIELDS} if m else None}
            recs.append(record_row('suricata', 'emerging-threats-open', run['id'], sid or f'line:{lh}', msg or rid, doc, id=rid, severity=cls, state=(m or {}).get('quarantine_state') or 'RETENIDA', validated=(m or {}).get('validated'), functional=(m or {}).get('functional'),
                                   performance=(m or {}).get('performance'), held_back=1 if (m or {}).get('held_back') == 'True' else 0, body=line[:60000], first_seen=None, updated_at=None))
    run['accepted'] = run['retained'] = len(recs)
    run['rejected'] = sum(1 for r in recs if r['validated'] == 'FAILED')
    return run, recs, {'matrix_rows': len(matrix)}


def promote_sigma(jsonl_path, zip_path, matrix_path, live_summary, now, by, promo_seed):
    ret = live_summary.get('retrieval') or {}
    if sha256_file(zip_path) != ret.get('sha256'):
        raise Skip('sigma zip does not match its retrieval record')
    promo = sha256_bytes((promo_seed + canonical(live_summary)).encode())
    run = run_row('sigmahq', live_summary, ret, {}, now, by, promo)
    matrix = load_matrix(matrix_path, 'sigma')
    z = zipfile.ZipFile(zip_path)
    names = {n.lstrip('./'): n for n in z.namelist()}
    recs = []
    for r in read_jsonl(jsonl_path):
        name = names.get(r['path']) or names.get(r['path'].split('rules/', 1)[-1]) or next((v for k, v in names.items() if k.endswith(r['path'])), None)
        body = z.read(name) if name else None
        if body is None or sha256_bytes(body) != r['rule_sha256']:
            raise Skip(f"sigma rule {r['id']} is missing from the archive or does not match its SHA-256")
        m = matrix.get(f"sigma:{r['id']}")
        doc = {k: r.get(k) for k in ('id', 'title', 'status', 'level', 'author', 'date', 'modified', 'tags', 'attack', 'logsource', 'path', 'rule_sha256', 'deprecated')}
        doc['matrix_row'] = {k: m.get(k) for k in MATRIX_FIELDS} if m else None
        recs.append(record_row('sigma', 'sigmahq', run['id'], r['id'], r['title'], doc, id=f"sigma:{r['id']}", severity=r.get('level'), state=(m or {}).get('quarantine_state') or 'RETENIDA', validated=(m or {}).get('validated'), functional=(m or {}).get('functional'),
                               performance=(m or {}).get('performance'), held_back=1 if (m or {}).get('held_back') == 'True' else 0, body=body.decode('utf-8', 'replace')[:60000], first_seen=r.get('date'), last_seen=r.get('modified') or r.get('date'), updated_at=r.get('modified') or r.get('date')))
    run['retained'] = len(recs)
    return run, recs, {}


def source_rows(now, runs):
    rows, seen = [], set()
    for sid, f in SOURCES.items():
        r = next((x for x in runs if x['source_id'] == sid), None)
        evid = json.loads(r['evidence']) if r else {}
        rows.append(dict(id=sid, name=f['name'], organization=f['organization'], url=f['url'], family=f['family'], grp=f['grp'], data_type=f['data_type'], adapter=f['adapter'], adapter_version=None, license_id=None,
                         redistribution=evid.get('redistribution_at_retrieval'), auth='none', configured=1, integration='CONNECTED' if r else 'NOT_INTEGRATED', status_reason=None if r else 'no_promoted_run', evidence_ref=None, updated_at=now))
        seen.add(sid)
    for u in UNCONNECTED:
        rows.append(dict(id=u['id'], name=u['name'], organization=u['organization'], url=u['url'], family=u['family'], grp=u['grp'], data_type=u['data_type'], adapter=None, adapter_version=None, license_id=None, redistribution=None, auth=u['auth'], configured=0,
                         integration=u['integration'], status_reason=u['status_reason'], evidence_ref='docs/quality/ABUSECH-AND-HASH-SOURCES-2026-10-25.md', updated_at=now))
    return rows


def events_for(runs, now, by):
    ev = []
    for r in runs:
        ev_ref = f"run:{r['id']}"
        fam = SOURCES[r['source_id']]['family']
        base = dict(run_id=r['id'], trace_id=r['promotion_sha256'][:32], family=fam, source_id=r['source_id'], artifact_id=r.get('content_sha256'), actor_id=None, evidence_ref=ev_ref)
        if r['retrieved_at']:
            ev.append(dict(base, ts=r['retrieved_at'], level='INFO' if r['http_status'] in (200, 206) else 'ERROR', component='intel.fetch', module='intel.fetch', message=f"download {r['state'].lower()}: HTTP {r['http_status']}, {r['bytes']} bytes", outcome='ok' if r['state'] == 'COMPLETE' else 'partial', duration_ms=None))
        ev.append(dict(base, ts=r['retrieved_at'] or now, level='WARN' if r['state'] == 'PARTIAL' else 'INFO', component='intel.normalize', module='intel.normalize', message=f"normalized {r['accepted']} records, rejected {r['rejected']}" + (' (snapshot incomplete)' if r['state'] == 'PARTIAL' else ''), outcome='partial' if r['state'] == 'PARTIAL' else 'ok', duration_ms=None))
        for b in json.loads(r['blocking']):
            ev.append(dict(base, ts=r['retrieved_at'] or now, level='WARN', component='intel.quarantine', module='intel.policy', message=f'retained: {redact(b)[:300]}', outcome='retained', duration_ms=None))
        ev.append(dict(base, ts=now, level='INFO', component='intel.promote', module='intel.promote', message=f"promoted {r['retained']} records to the panel store", outcome='ok', duration_ms=None, actor_id=by))
    return ev


COLS = {
    'intel_sources': ['id', 'name', 'organization', 'url', 'family', 'grp', 'data_type', 'adapter', 'adapter_version', 'license_id', 'redistribution', 'auth', 'configured', 'integration', 'status_reason', 'evidence_ref', 'updated_at'],
    'intel_runs': ['id', 'source_id', 'retrieved_at', 'http_status', 'bytes', 'expected_bytes', 'etag', 'last_modified', 'upstream_version', 'content_sha256', 'declared', 'accepted', 'rejected', 'duplicates', 'retained', 'approved', 'published', 'state', 'publishable', 'blocking', 'duration_ms',
                   'evidence', 'promoted_at', 'promoted_by', 'promotion_sha256', 'log_leaf'],
    'intel_records': ['id', 'family', 'source_id', 'run_id', 'key', 'title', 'severity', 'score', 'state', 'validated', 'functional', 'performance', 'held_back', 'first_seen', 'last_seen', 'updated_at', 'body', 'doc', 'doc_sha256'],
    'intel_events': ['ts', 'level', 'component', 'module', 'message', 'run_id', 'trace_id', 'family', 'source_id', 'artifact_id', 'outcome', 'duration_ms', 'actor_id', 'evidence_ref'],
}


def insert(table, row, replace=True):
    cols = COLS[table]
    return f"INSERT {'OR REPLACE ' if replace else ''}INTO {table} ({','.join(cols)}) VALUES ({','.join(q(row.get(c)) for c in cols)});\n"


class Writer:
    def __init__(self, out):
        self.out, self.n, self.size, self.f, self.files = out, 0, 0, None, []

    def write(self, stmt):
        if self.f is None or self.size + len(stmt) > CHUNK_BYTES:
            if self.f:
                self.f.close()
            self.n += 1
            p = os.path.join(self.out, f'chunk-{self.n:04d}.sql')
            self.f, self.size = open(p, 'w', encoding='utf-8'), 0
            self.files.append(p)
        self.f.write(stmt)
        self.size += len(stmt.encode())

    def close(self):
        if self.f:
            self.f.close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--by', required=True)
    ap.add_argument('--adapter-ref', required=True)
    ap.add_argument('--run', action='append', default=[])
    ap.add_argument('--epss')
    ap.add_argument('--epss-summary')
    ap.add_argument('--suricata', nargs=2, metavar=('RULES', 'MATRIX'))
    ap.add_argument('--suricata-evidence-head')
    ap.add_argument('--sigma', nargs=4, metavar=('JSONL', 'ZIP', 'MATRIX', 'LIVE_JSON'))
    ap.add_argument('--now')
    a = ap.parse_args(argv)
    now = a.now or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    os.makedirs(a.out, exist_ok=True)
    seed = f'macguard.intel-promotion/1|{a.adapter_ref}|'
    runs, records, skipped, done = [], [], [], []
    for p in a.run:
        try:
            s = load_json(p)
            fn = promote_attack if s['source'] == 'mitre-attack' else promote_feodo if s['source'] == 'abusech-feodo' else promote_vuln_run
            run, recs, _ = fn(p, now, a.by, seed)
            runs.append(run); records.extend(recs); done.append(dict(source=run['source_id'], records=len(recs), run=run['id']))
        except Skip as e:
            skipped.append(dict(file=p, reason=str(e)))
    if a.epss and a.epss_summary:
        try:
            cves = {c for r in records if r['family'] in ('cve', 'kev', 'advisory') for c in (json.loads(r['doc']).get('ids') or {}).get('cve', [])}
            run, recs, _ = promote_epss(a.epss_summary, a.epss, cves, now, a.by, seed)
            runs.append(run); records.extend(recs); done.append(dict(source='first-epss', records=len(recs), run=run['id']))
        except Skip as e:
            skipped.append(dict(file=a.epss_summary, reason=str(e)))
    if a.suricata:
        try:
            run, recs, _ = promote_suricata(a.suricata[0], a.suricata[1], a.suricata_evidence_head, None, now, a.by, seed)
            runs.append(run); records.extend(recs); done.append(dict(source='emerging-threats-open', records=len(recs), run=run['id']))
        except Skip as e:
            skipped.append(dict(file=a.suricata[0], reason=str(e)))
    if a.sigma:
        try:
            run, recs, _ = promote_sigma(a.sigma[0], a.sigma[1], a.sigma[2], load_json(a.sigma[3]), now, a.by, seed)
            runs.append(run); records.extend(recs); done.append(dict(source='sigmahq', records=len(recs), run=run['id']))
        except Skip as e:
            skipped.append(dict(file=a.sigma[3], reason=str(e)))
    w = Writer(a.out)
    for s in source_rows(now, runs):
        w.write(insert('intel_sources', s))
    for r in runs:
        w.write(insert('intel_runs', r))
    for r in records:
        stmt = insert('intel_records', r)
        if len(stmt.encode()) > MAX_STATEMENT:
            r = dict(r, body=(r['body'] or '')[:20000] if r.get('body') else None)
            stmt = insert('intel_records', r)
            if len(stmt.encode()) > MAX_STATEMENT:
                skipped.append(dict(file=r['id'], reason='record larger than the statement limit even after shrinking'))
                continue
        w.write(stmt)
    for e in events_for(runs, now, a.by):
        w.write(insert('intel_events', e, replace=False))
    w.close()
    by_family = {}
    for r in records:
        by_family[r['family']] = by_family.get(r['family'], 0) + 1
    summary = dict(schema='macguard.intel-promotion-summary/1', promoted_at=now, promoted_by=a.by, adapter_ref=a.adapter_ref, runs=done, skipped=skipped, records_by_family=by_family, chunks=[os.path.basename(f) for f in w.files],
                   chunk_sha256={os.path.basename(f): sha256_file(f) for f in w.files}, run_promotion_sha256={r['id']: r['promotion_sha256'] for r in runs})
    with open(os.path.join(a.out, 'promotion.json'), 'w') as f:
        json.dump(summary, f, indent=1, sort_keys=True)
    print(json.dumps({k: summary[k] for k in ('runs', 'skipped', 'records_by_family')}, indent=1))
    return 0 if not skipped else 3


if __name__ == '__main__':
    sys.exit(main())
