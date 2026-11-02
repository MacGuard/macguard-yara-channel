#!/usr/bin/env python3
"""Build, seal and verify an intelligence-family package (data, not detection rules) with the SAME trust chain as the YARA channel.

The YARA release is untouched. An intelligence package is a separate, independently verifiable artifact:
  intel-<family>-<version>.tar.gz              deterministic tarball of the dataset files only (no manifest inside)
  intel-<family>-<version>.manifest.json       canonical JSON, contract macguard.package-manifest/1 (contracts/v1/package-manifest.schema.json)
  intel-<family>-<version>.manifest.sigstore.json   keyless Sigstore bundle of the manifest (publish.yml identity), made by the workflow
  intel-<family>-<version>.inclusion-proof.json     the package's `intel.package.accepted` entry inside the signed transparency-log checkpoint
  intel-<family>-<version>.sha256              `sha256sum` line of the tarball (the tarball digest cannot live in a manifest it does not contain)

Commands (no network; the workflow runs cosign and tlog.py around them, exactly like the YARA release):
  build   --family cisa-kev --dataset DIR --version V --out OUT      -> tarball + <name>.candidate.json (status UNSIGNED_CANDIDATE, outside the contract)
  accept  --candidate C --run-id R [--logs logs]                     -> appends the `intel.package.accepted` event (details: package, rules_root, items)
  seal    --candidate C --out M [--logs logs] [--run-id R] [--tag T] [--previous PREV_MANIFEST]
                                                                     -> manifest.json, status PUBLISHED, log head of the latest checkpoint
  proof   --manifest M --run-id R --out P [--logs logs]              -> inclusion proof of the accepted event in the checkpoint the manifest names
  verify  --package T --manifest M [--sha256-file S] [--proof P --checkpoint CK [--checkpoint-bundle CKB]] [--bundle B --identity I --repo R]
          Exit 0 only when EVERYTHING was checked (content, manifest signature, checkpoint signature, inclusion proof).
          Exit 3 = content verified but some signature/proof was NOT checked (printed as SIGNATURE_NOT_CHECKED / PROOF_NOT_CHECKED, never as OK).
          Exit 1 = verification failed.

Family policy: each family lists the exact files it may contain, their formats and limits. Nothing executable, no archives, no PoC/exploit material:
a dataset that does not match the policy is refused before anything is written."""
import argparse, gzip, hashlib, io, json, os, pathlib, re, stat, sys, tarfile
from datetime import datetime, timezone
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tlog

ROOT = pathlib.Path(__file__).resolve().parents[1]
IDENTITY = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main'
REPO = 'MacGuard/macguard-yara-channel'
ACCEPT_EVENT = 'intel.package.accepted'
MAX_MEMBERS = 16
CVE = re.compile(r'CVE-\d{4}-\d{4,7}')
VERSION = re.compile(r'[A-Za-z0-9._+-]{1,64}')
# Bytes that mean "this is a program or an archive", whatever the file is called.
EXEC_MAGIC = (b'\x7fELF', b'MZ', b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'#!', b'PK\x03\x04', b'\x1f\x8b', b'Rar!', b'7z\xbc\xaf')
POC_NAME = re.compile(r'(poc|exploit|payload|shellcode)', re.I)

class PackageError(Exception): pass

def _kev_items(files):
    """macguard.intel-kev/1 (contracts/v1/intel-kev.schema.json): kev.json {schema, source, count, items:[{cve_id,...}]} and kev.csv (header + one RECORD per item; fields may contain quoted newlines)."""
    try: doc = json.loads(files['kev.json'])
    except ValueError as e: raise PackageError(f'kev.json is not JSON ({e})')
    if not isinstance(doc, dict) or doc.get('schema') != 'macguard.intel-kev/1': raise PackageError('kev.json is not macguard.intel-kev/1')
    vulns = doc.get('items')
    if not isinstance(vulns, list) or not vulns: raise PackageError('kev.json has no items list')
    if doc.get('count') != len(vulns): raise PackageError(f"kev.json count {doc.get('count')} != {len(vulns)} items")
    ids = []
    for v in vulns:
        cid = v.get('cve_id') if isinstance(v, dict) else None
        if not isinstance(cid, str) or not CVE.fullmatch(cid): raise PackageError(f'kev.json entry without a valid CVE id: {str(cid)[:40]!r}')
        ids.append(cid)
    if len(set(ids)) != len(ids): raise PackageError('kev.json lists a CVE twice')
    try: text = files['kev.csv'].decode('utf-8')
    except UnicodeDecodeError: raise PackageError('kev.csv is not UTF-8')
    import csv, io
    try: rows = [r for r in csv.reader(io.StringIO(text, newline='')) if r]
    except csv.Error as e: raise PackageError(f'kev.csv is not valid CSV ({e})')
    if len(rows) - 1 != len(vulns): raise PackageError(f'kev.csv has {len(rows) - 1} records, kev.json {len(vulns)}')
    if [r[0] for r in rows[1:]] != ids: raise PackageError('kev.csv records do not match kev.json items (first column must be cve_id, same order)')
    return len(vulns), sorted(ids)

FAMILIES = {
    'cisa-kev': {
        'family': 'vulnerability-data', 'name': 'cisa-kev', 'tier': 'community', 'format': 'json+csv', 'schema': 'macguard.intel-kev/1',
        'files': {'kev.json': 64 << 20, 'kev.csv': 32 << 20, 'LICENSE-NOTICE.txt': 64 << 10},   # exact allow-list with a size limit each
        'source': {'id': 'cisa-kev', 'licence': 'CC0-1.0', 'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'},
        'items': _kev_items,
    },
}

# ---- detection and indicator families: PREPARED, NOT APPROVED (their sources are RETAINED in config/intel/sources.registry.json, and publish.yml
# accepts only cisa-kev). build() refuses an unapproved family; tests build them with allow_unapproved=True. Engine-real formats only:
# Sigma YAML rules, Suricata .rules, ClamAV text databases, normalised IOC JSON+CSV. File names are constrained (rule id, category), never free text.
def _family(module):
    def run(files):
        from families import sigma, suricata, clamav, ioc   # scripts/families: validators (data only, nothing executed)
        try: return {'sigma': sigma, 'suricata': suricata, 'clamav': clamav, 'ioc': ioc}[module].validate(files)
        except ValueError as e: raise PackageError(str(e))
    return run

LICENCE = {'LICENSE-NOTICE.txt': 64 << 10}
FAMILIES.update({
    'sigma': {'family': 'sigma', 'name': 'sigmahq', 'tier': 'premium', 'format': 'sigma-yaml', 'schema': 'sigma-rule',
              'engine': {'name': 'sigma', 'min_version': None, 'syntax_version': 'sigma-spec-2'},
              'files': dict(LICENCE), 'patterns': [(re.compile(r'rules/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.yml'), 256 << 10)],
              'dirs': ('rules',), 'max_members': 20000, 'source': {'id': 'sigmahq', 'licence': 'DRL-1.1', 'url': 'https://github.com/SigmaHQ/sigma'}, 'validate': _family('sigma')},
    'suricata': {'family': 'suricata', 'name': 'et-open', 'tier': 'premium', 'format': 'suricata-rules', 'schema': 'suricata-rule',
                 'engine': {'name': 'suricata', 'min_version': None, 'syntax_version': None},
                 'files': dict(LICENCE), 'patterns': [(re.compile(r'rules/[a-z0-9][a-z0-9_-]{0,63}\.rules'), 64 << 20)],
                 'dirs': ('rules',), 'max_members': 128, 'source': {'id': 'et-open', 'licence': 'GPL-2.0-only', 'url': 'https://rules.emergingthreats.net/'}, 'validate': _family('suricata')},
    'clamav': {'family': 'clamav', 'name': 'clamav-text', 'tier': 'premium', 'format': 'clamav-text-db', 'schema': 'clamav-db',
               'engine': {'name': 'clamav', 'min_version': None, 'syntax_version': None},
               'files': dict(LICENCE), 'patterns': [(re.compile(r'db/[a-z0-9][a-z0-9_-]{0,63}\.(ndb|hdb|hsb|ldb)'), 64 << 20)],
               'dirs': ('db',), 'max_members': 64, 'source': {'id': 'clamav-cvd', 'licence': 'unknown', 'url': 'https://www.clamav.net/'}, 'validate': _family('clamav')},
    'ioc': {'family': 'ioc', 'name': 'abusech-feodo', 'tier': 'premium', 'format': 'json+csv', 'schema': 'macguard.intel-ioc/1',
            'files': {'indicators.json': 64 << 20, 'indicators.csv': 32 << 20, **LICENCE},
            'source': {'id': 'abusech-feodo', 'licence': 'CC0-1.0', 'url': 'https://feodotracker.abuse.ch/'}, 'validate': _family('ioc')},
})
CONTAINERS = re.compile(r'.*\.(cvd|cld|cud)')   # ClamAV binary containers: only acceptable after sigtool verification (not available here)

def approved(family):
    """A family may be built for publication only when the owner approved its source in config/intel/sources.registry.json."""
    try: reg = json.loads((ROOT / 'config' / 'intel' / 'sources.registry.json').read_text())
    except (OSError, ValueError): return False
    src = FAMILIES[family]['source']['id']
    return any(x.get('id') == src and x.get('approval_state') in ('APPROVED_PUBLIC', 'APPROVED_PREMIUM') and x.get('owner_confirmed') is True for x in reg.get('sources', []))

def _limit(pol, name):
    if name in pol['files']: return pol['files'][name]
    for rx, lim in pol.get('patterns', ()):
        if rx.fullmatch(name): return lim
    return None
MAX_EXPANDED = 128 << 20

def _canonical(doc): return json.dumps(doc, sort_keys=True, separators=(',', ':')).encode()
def _sha(b): return hashlib.sha256(b).hexdigest()
def names(family, version):
    base = f'intel-{family}-{version}'
    return {k: f'{base}{s}' for k, s in (('tarball', '.tar.gz'), ('candidate', '.candidate.json'), ('manifest', '.manifest.json'), ('bundle', '.manifest.sigstore.json'),
                                         ('proof', '.inclusion-proof.json'), ('sha256', '.sha256'))}

def check_policy(family, files: dict):
    """files: {name: bytes}. Refuses anything the family does not allow; returns (items, related CVE ids)."""
    pol = FAMILIES.get(family)
    if not pol: raise PackageError(f'unknown family {family!r}')
    for n in files:
        if POC_NAME.search(n): raise PackageError(f'{n}: PoC/exploit material is never part of a package')
    if not pol.get('patterns'):
        if set(files) != set(pol['files']): raise PackageError(f"files {sorted(files)} != allowed {sorted(pol['files'])}")
    else:
        if not set(pol['files']) <= set(files): raise PackageError(f"required files missing: {sorted(set(pol['files']) - set(files))}")
        if len(files) > pol.get('max_members', MAX_MEMBERS): raise PackageError('too many files for this family')
        for n in files:
            if CONTAINERS.fullmatch(n): raise PackageError(f'{n}: BLOCKED, a binary ClamAV container needs sigtool verification, which is not available')
            if _limit(pol, n) is None: raise PackageError(f'{n} is not allowed in a {family} package')
    total = 0
    for n, b in files.items():
        if not b: raise PackageError(f'{n} is empty')
        if len(b) > _limit(pol, n): raise PackageError(f'{n} exceeds {_limit(pol, n)} bytes')
        if b.startswith(EXEC_MAGIC): raise PackageError(f'{n} looks like a program or an archive')
        if b'\x00' in b: raise PackageError(f'{n} contains NUL bytes: not a text dataset')
        total += len(b)
    if total > MAX_EXPANDED: raise PackageError('dataset too large')
    if 'validate' in pol: return pol['validate'](files)[:2]
    return pol['items'](files)

def read_dataset(family, folder: pathlib.Path):
    pol = FAMILIES.get(family)
    if not pol: raise PackageError(f'unknown family {family!r}')
    folder = folder.resolve(); out = {}
    def walk(d, prefix, depth):
        for entry in sorted(os.listdir(d)):
            p = d / entry; st = os.lstat(p); name = prefix + entry
            if POC_NAME.search(entry): raise PackageError(f'{name}: PoC/exploit material is never part of a package')
            if stat.S_ISLNK(st.st_mode): raise PackageError(f'{name} is a symlink')
            if stat.S_ISDIR(st.st_mode) and depth == 0 and entry in pol.get('dirs', ()): walk(p, name + '/', 1); continue
            if not stat.S_ISREG(st.st_mode): raise PackageError(f'{name} is not a regular file')
            if st.st_mode & 0o111: raise PackageError(f'{name} is executable')
            if CONTAINERS.fullmatch(name): raise PackageError(f'{name}: BLOCKED, a binary ClamAV container needs sigtool verification, which is not available')
            lim = _limit(pol, name)
            if lim is None: raise PackageError(f'{name} is not allowed in a {family} package')
            if st.st_size > lim: raise PackageError(f'{name} exceeds its size limit')
            if len(out) >= pol.get('max_members', MAX_MEMBERS): raise PackageError('too many files for this family')
            out[name] = p.read_bytes()
    walk(folder, '', 0)
    return out

def _tarball(files: dict, mtime: int) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as t:
        for n in sorted(files):
            ti = tarfile.TarInfo(n); ti.size = len(files[n]); ti.mtime = mtime; ti.mode = 0o644; ti.uid = ti.gid = 0; ti.uname = ti.gname = ''; ti.type = tarfile.REGTYPE
            t.addfile(ti, io.BytesIO(files[n]))
    out = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=out, compresslevel=9, mtime=0) as g: g.write(raw.getvalue())
    return out.getvalue()

def build(family, dataset: pathlib.Path, version, out: pathlib.Path, created_at=None, allow_unapproved=False):
    if not VERSION.fullmatch(version): raise PackageError('version must match [A-Za-z0-9._+-]{1,64}')
    if family in FAMILIES and not allow_unapproved and not approved(family):
        raise PackageError(f'family {family} is not approved for publication: its source {FAMILIES[family]["source"]["id"]} is not APPROVED in config/intel/sources.registry.json')
    files = read_dataset(family, dataset); items, related = check_policy(family, files)
    pol = FAMILIES[family]
    vstate, vengine = (pol['validate'](files)[2:] if 'validate' in pol else ('SYNTAX_CHECKED', f"{pol['schema']} schema + item count (data package: no detection engine)"))
    if created_at is None and 'validate' in pol: raise PackageError('created_at is required for this family')
    if created_at is None:
        doc = json.loads(files[next(iter(k for k in files if k.endswith('.json')))])
        created_at = doc.get('generated_at') or doc.get('date_released') or '1970-01-01T00:00:00Z'
    ts = datetime.strptime(created_at[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc) if 'T' in created_at else datetime.strptime(created_at, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    created_at = ts.strftime('%Y-%m-%dT%H:%M:%SZ')
    pol = FAMILIES[family]; n = names(family, version)
    inv = [{'path': k, 'sha256': _sha(files[k]), 'bytes': len(files[k]), 'source': pol['source']['id'], 'licence': pol['source']['licence']} for k in sorted(files)]
    bad = tlog.check_inventory(inv)
    if bad: raise PackageError(bad)
    tgz = _tarball(files, int(ts.timestamp()))
    cand = {'status': 'UNSIGNED_CANDIDATE', 'family_key': family, 'tarball': {'name': n['tarball'], 'sha256': _sha(tgz), 'bytes': len(tgz)},
            'manifest': {'schema': 'macguard.package-manifest/1',
                         'package': {'id': f"package:{pol['family']}:{pol['name']}@{version}", 'family': pol['family'], 'tier': pol['tier'], 'name': pol['name'], 'version': version,
                                     'created_at': created_at, 'release_tag': None, 'engine': pol.get('engine') or {'name': 'none', 'min_version': None, 'syntax_version': pol['schema']},
                                     'format': pol['format'], 'platforms': [], 'previous': None},
                         'files': inv, 'rules_root': tlog.rules_root(inv),
                         'validation': {'state': vstate, 'engine': vengine, 'checked': items},
                         'sources': [dict(pol['source'])], 'stats': {'files': len(inv), 'items': items, 'expanded_bytes': sum(f['bytes'] for f in inv)},
                         'related_vulnerabilities': related[:10000]}}
    out.mkdir(parents=True, exist_ok=True)
    (out / n['tarball']).write_bytes(tgz)
    (out / n['sha256']).write_text(f"{_sha(tgz)}  {n['tarball']}\n")
    (out / n['candidate']).write_bytes(_canonical(cand))
    return cand

def accept(candidate: dict, run_id: str, log: tlog.Log, time=''):
    m = candidate['manifest']
    log.append(tlog.event('INFO', ACCEPT_EVENT, f"Intelligence package {m['package']['id']} ({m['stats']['items']} items) was accepted for signing.", run_id, time,
                          package=m['package']['id'], rules_root=m['rules_root'], items=m['stats']['items'], tarball_sha256=candidate['tarball']['sha256']))

def seal(candidate: dict, log_folder: pathlib.Path, run_id='', tag=None, previous=None, run_url='', workflow_sha=''):
    if candidate.get('status') != 'UNSIGNED_CANDIDATE': raise PackageError('not an unsigned candidate')
    head = log_folder / 'checkpoint.txt'
    if not head.exists(): raise PackageError('no log checkpoint: run tlog.py checkpoint before sealing')
    size, root = tlog.Log.parse_checkpoint(head.read_bytes())
    m = json.loads(json.dumps(candidate['manifest']))
    if tlog.rules_root(m['files']) != m['rules_root']: raise PackageError('candidate rules_root does not match its files')
    m['log'] = {'origin': tlog.ORIGIN, 'size': size, 'root': root.hex()}
    m['status'] = 'PUBLISHED'; m['package']['release_tag'] = tag
    if previous: m['package']['previous'] = {'version': previous['package']['version'], 'manifest_sha256': _sha(_canonical(previous))}
    m['evidence'] = {'candidate_run_id': run_id, 'candidate_workflow_sha': workflow_sha, 'publish_run_url': run_url}
    return m

def release_proof(log: tlog.Log, run_id, manifest):
    size = manifest['log']['size']; lines = log.lines(); leaves = log.leaves()[:size]
    for i, line in enumerate(lines[:size]):
        e = json.loads(line); d = e.get('details', {})
        if e.get('event') == ACCEPT_EVENT and e.get('run_id') == run_id and d.get('rules_root') == manifest['rules_root'] and d.get('package') == manifest['package']['id']:
            proof = tlog.inclusion_proof(i, leaves); root = tlog.mth(leaves)
            if root.hex() != manifest['log']['root']: raise PackageError('the log head does not match the manifest')
            if not tlog.verify_inclusion(i, size, leaves[i], proof, root): raise PackageError('inclusion proof does not verify')
            return {'schema': 1, 'origin': tlog.ORIGIN, 'index': i, 'size': size, 'root': root.hex(), 'entry': line.decode(), 'proof': [h.hex() for h in proof]}
    raise PackageError(f'no {ACCEPT_EVENT} entry for run {run_id} and {manifest["package"]["id"]} inside the checkpoint')

def check_proof(doc, checkpoint_body: bytes, manifest):
    try:
        size, root = tlog.Log.parse_checkpoint(checkpoint_body)
        if doc['size'] != size or bytes.fromhex(doc['root']) != root: return 'proof is for a different checkpoint'
        if manifest['log']['size'] != size or manifest['log']['root'] != root.hex(): return 'manifest log head differs from the checkpoint'
        e = json.loads(doc['entry']); d = e.get('details', {})
        if e.get('event') != ACCEPT_EVENT or d.get('rules_root') != manifest['rules_root'] or d.get('package') != manifest['package']['id']: return 'logged entry does not match the manifest'
        if not tlog.verify_inclusion(doc['index'], size, tlog.leaf_hash(doc['entry'].encode()), [bytes.fromhex(h) for h in doc['proof']], root): return 'inclusion proof does not verify'
    except (KeyError, ValueError, TypeError) as e: return f'malformed proof ({type(e).__name__})'
    return None

REQUIRED = ('schema', 'package', 'files', 'rules_root', 'log', 'status', 'validation', 'sources', 'stats')
def check_manifest_shape(m):
    if not isinstance(m, dict) or any(k not in m for k in REQUIRED): return 'manifest misses required fields'
    if m['schema'] != 'macguard.package-manifest/1' or m['status'] != 'PUBLISHED': return 'not a published macguard.package-manifest/1'
    if m['validation'].get('state') not in ('SYNTAX_CHECKED', 'ENGINE_COMPILED', 'ENGINE_TESTED'): return 'unknown validation state'
    p = m['package']
    if not re.fullmatch(r'package:(yara|sigma|suricata|clamav|ioc|vulnerability-data):[a-z0-9][a-z0-9._-]{0,63}@[A-Za-z0-9._+-]{1,64}', str(p.get('id'))): return 'bad package id'
    if p['id'] != f"package:{p.get('family')}:{p.get('name')}@{p.get('version')}": return 'package id does not match family/name/version'
    return None

def _read_tar(tgz: bytes, limit, max_members=MAX_MEMBERS):
    """Read every member with hard limits; refuses links, devices, directories, unsafe or duplicate names, and expansion bombs."""
    out, expanded = {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz), mode='r:gz') as t:
            for i, mi in enumerate(t):
                if i >= max_members: raise PackageError('too many members')
                if not mi.isreg(): raise PackageError(f'{mi.name}: only regular files are allowed')
                if mi.name.startswith('/') or any(s in ('', '.', '..') for s in mi.name.split('/')) or '\\' in mi.name: raise PackageError(f'{mi.name}: unsafe path')
                if mi.name in out: raise PackageError(f'{mi.name}: duplicate member')
                if mi.size > limit: raise PackageError(f'{mi.name}: declared size over the limit')
                f = t.extractfile(mi); data = f.read(limit + 1)
                if len(data) > limit or len(data) != mi.size: raise PackageError(f'{mi.name}: size over the limit or inconsistent')
                expanded += len(data)
                if expanded > MAX_EXPANDED: raise PackageError('expanded size over the limit')
                out[mi.name] = data
    except (tarfile.TarError, OSError, EOFError) as e: raise PackageError(f'not a valid tar.gz ({type(e).__name__})')
    return out

def verify(tgz: bytes, manifest_bytes: bytes, *, family_key=None, sha256_line=None, proof=None, checkpoint=None, checkpoint_verify=None, manifest_verify=None):
    """Returns (status, messages). status: VERIFIED | CONTENT_VERIFIED (some signature/proof not checked) | FAILED."""
    msgs = []
    try:
        m = json.loads(manifest_bytes)
        if manifest_bytes != _canonical(m): raise PackageError('manifest is not canonical JSON (it was re-serialised or edited)')
        bad = check_manifest_shape(m)
        if bad: raise PackageError(bad)
        fam = family_key or next((k for k, p in FAMILIES.items() if p['family'] == m['package']['family'] and p['name'] == m['package']['name']), None)
        if fam not in FAMILIES or FAMILIES[fam]['family'] != m['package']['family'] or FAMILIES[fam]['name'] != m['package']['name']: raise PackageError('package family does not match the expected family')
        if sha256_line is not None:
            want = sha256_line.split()[0] if sha256_line.split() else ''
            if want != _sha(tgz): raise PackageError('tarball SHA-256 differs from the published .sha256')
            msgs.append(f'tarball SHA-256 {want[:16]}... matches')
        pol = FAMILIES[fam]
        files = _read_tar(tgz, max([*pol['files'].values(), *(lim for _, lim in pol.get('patterns', ()))]), pol.get('max_members', MAX_MEMBERS))
        bad = tlog.check_inventory(m['files'])
        if bad: raise PackageError(f'manifest inventory: {bad}')
        listed = {f['path']: f for f in m['files']}
        if set(files) != set(listed): raise PackageError(f'tar members {sorted(files)} != manifest files {sorted(listed)}')
        for n, b in files.items():
            if _sha(b) != listed[n]['sha256'] or len(b) != listed[n]['bytes']: raise PackageError(f'{n} does not match the manifest')
        if tlog.rules_root(m['files']) != m['rules_root']: raise PackageError('rules_root does not match the file list')
        items, related = check_policy(fam, files)
        st = m['stats']
        if st.get('files') != len(files) or st.get('items') != items or st.get('expanded_bytes') != sum(len(b) for b in files.values()) or m['validation'].get('checked') != items:
            raise PackageError('manifest stats/validation do not match the content')
        if m.get('related_vulnerabilities', []) != related[:10000]: raise PackageError('related_vulnerabilities do not match the content')
        msgs.append(f"content OK: {len(files)} files, {items} items, rules_root {m['rules_root'][:16]}...")
        complete = True
        if manifest_verify is None: msgs.append('SIGNATURE_NOT_CHECKED: no manifest Sigstore bundle was given'); complete = False
        else:
            err = manifest_verify()
            if err: raise PackageError(f'manifest signature: {err}')
            msgs.append('manifest signature OK (publish.yml identity, GitHub OIDC issuer)')
        if proof is None or checkpoint is None: msgs.append('PROOF_NOT_CHECKED: no inclusion proof or checkpoint was given'); complete = False
        else:
            if checkpoint_verify is None: msgs.append('SIGNATURE_NOT_CHECKED: checkpoint signature not checked'); complete = False
            else:
                err = checkpoint_verify()
                if err: raise PackageError(f'checkpoint signature: {err}')
                msgs.append('checkpoint signature OK')
            err = check_proof(proof, checkpoint, m)
            if err: raise PackageError(err)
            msgs.append(f"included in the transparency log ({m['log']['size']} entries)")
        return ('VERIFIED' if complete else 'CONTENT_VERIFIED'), msgs
    except (PackageError, ValueError, KeyError, TypeError) as e:
        return 'FAILED', msgs + [f'VERIFY FAILED: {e}']

def verify_files(tarball: pathlib.Path, manifest: pathlib.Path, *, sha256_file=None, proof=None, checkpoint=None, checkpoint_bundle=None, bundle=None, identity=IDENTITY, repo=REPO, family_key=None):
    cos = tlog.cosign_verifier(identity, repo)
    return verify(tarball.read_bytes(), manifest.read_bytes(), family_key=family_key,
                  sha256_line=sha256_file.read_text() if sha256_file else None,
                  proof=json.loads(proof.read_text()) if proof else None, checkpoint=checkpoint.read_bytes() if checkpoint else None,
                  checkpoint_verify=(lambda: cos(checkpoint, checkpoint_bundle)) if (checkpoint and checkpoint_bundle) else None,
                  manifest_verify=(lambda: cos(manifest, bundle)) if bundle else None)

def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or '').splitlines()[0]); sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('build'); s.add_argument('--family', required=True, choices=sorted(FAMILIES)); s.add_argument('--dataset', required=True); s.add_argument('--version', required=True); s.add_argument('--out', required=True); s.add_argument('--created-at')
    s = sub.add_parser('accept'); s.add_argument('--candidate', required=True); s.add_argument('--run-id', required=True); s.add_argument('--logs', default=str(ROOT / 'logs'))
    s = sub.add_parser('seal'); s.add_argument('--candidate', required=True); s.add_argument('--out', required=True); s.add_argument('--logs', default=str(ROOT / 'logs')); s.add_argument('--run-id', default=''); s.add_argument('--tag'); s.add_argument('--previous')
    s = sub.add_parser('proof'); s.add_argument('--manifest', required=True); s.add_argument('--run-id', required=True); s.add_argument('--out', required=True); s.add_argument('--logs', default=str(ROOT / 'logs'))
    s = sub.add_parser('verify')
    for k in ('package', 'manifest'): s.add_argument('--' + k, required=True)
    for k in ('sha256-file', 'proof', 'checkpoint', 'checkpoint-bundle', 'bundle', 'family'): s.add_argument('--' + k)
    s.add_argument('--identity', default=IDENTITY); s.add_argument('--repo', default=REPO)
    a = ap.parse_args(argv); P = pathlib.Path
    try:
        if a.cmd == 'build':
            c = build(a.family, P(a.dataset), a.version, P(a.out), a.created_at)
            print(f"candidate {c['manifest']['package']['id']}: {c['manifest']['stats']['items']} items, tarball {c['tarball']['sha256'][:16]}... (UNSIGNED_CANDIDATE)")
        elif a.cmd == 'accept':
            accept(json.loads(P(a.candidate).read_text()), a.run_id, tlog.Log(P(a.logs))); print(f'appended {ACCEPT_EVENT}')
        elif a.cmd == 'seal':
            m = seal(json.loads(P(a.candidate).read_text()), P(a.logs), a.run_id, a.tag, json.loads(P(a.previous).read_text()) if a.previous and P(a.previous).exists() else None,
                     os.environ.get('RUN_URL', ''), os.environ.get('GITHUB_SHA', ''))
            P(a.out).write_bytes(_canonical(m)); print('manifest written (PUBLISHED); it must now be signed with cosign')
        elif a.cmd == 'proof':
            doc = release_proof(tlog.Log(P(a.logs)), a.run_id, json.loads(P(a.manifest).read_text()))
            P(a.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + '\n'); print(f"inclusion proof written (entry {doc['index']} of {doc['size']})")
        elif a.cmd == 'verify':
            st, msgs = verify_files(P(a.package), P(a.manifest), sha256_file=P(a.sha256_file) if a.sha256_file else None, proof=P(a.proof) if a.proof else None,
                                    checkpoint=P(a.checkpoint) if a.checkpoint else None, checkpoint_bundle=P(a.checkpoint_bundle) if a.checkpoint_bundle else None,
                                    bundle=P(a.bundle) if a.bundle else None, identity=a.identity, repo=a.repo, family_key=a.family)
            for line in msgs: print(line)
            print(st); sys.exit({'VERIFIED': 0, 'CONTENT_VERIFIED': 3}.get(st, 1))
    except PackageError as e: sys.exit(f'REFUSED: {e}')

if __name__ == '__main__': main()
