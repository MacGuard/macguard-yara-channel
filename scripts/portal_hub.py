#!/usr/bin/env python3
"""Build-time data of the Threat Intelligence Hub (portada, explorador, biblioteca): hub.json, sources.json, kev/ static index, and the verified
intel packages added to packages.json and families.json.

Intel packages (BUNDLES team) arrive in <root>/intel-release/<dir>/ (or $MG_INTEL_RELEASES), like the YARA release in <root>/release/:
manifest.json (macguard.package-manifest/1), manifest.sigstore.json, exactly one package tarball and an optional meta.json {tag, published_at, url}.
A package is used by the site ONLY when, in this same build,
  1) `scripts/intel_package.py verify <dir>` exits 0 (signature, signing identity, transparency: owned by BUNDLES), and
  2) the content checks here pass: the manifest inside the tarball is byte-identical to the published one, the tarball holds exactly the files
     the manifest lists, every SHA-256 and size matches, and the dataset is well formed.
Without the verifier, or if anything fails, the package is NOT used and the site says the family is unavailable (the reason is kept in
packages.json `intel_refused`). Nothing unverified is ever shown as data.

The KEV static index is the fallback search while no lookup API is configured: one JSON shard per CVE year (never one file per CVE), each at most
MAX_SHARD bytes, plus kev/index.json. It is labelled as the CISA KEV catalogue only: it never claims NVD, EUVD or GCVE coverage."""
import hashlib, json, os, pathlib, re, subprocess, sys, tarfile

SCHEMA_KEV, SCHEMA_KEV_INDEX, SCHEMA_KEV_SHARD = 'macguard.intel-kev/1', 'macguard.portal-kev-index/1', 'macguard.portal-kev-shard/1'
SCHEMA_HUB, SCHEMA_SOURCES = 'macguard.portal-hub/1', 'macguard.portal-sources/1'
MAX_TAR, MAX_MEMBER, MAX_EXPANDED, MAX_SHARD, MAX_ITEMS, MAX_FIELD = 64 * 2**20, 32 * 2**20, 256 * 2**20, 512 * 1024, 100000, 4000
CVE_RE, CWE_RE = re.compile(r'^CVE-(\d{4})-(\d{4,7})$'), re.compile(r'^CWE-\d{1,5}$')
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
KEV_FIELDS = ('cve_id', 'vendor', 'product', 'name', 'date_added', 'short_description', 'required_action', 'due_date', 'known_ransomware_use', 'notes', 'cwes')
KEV_TEXT = ('vendor', 'product', 'name', 'short_description', 'required_action', 'notes', 'known_ransomware_use')


class PackageError(Exception):
    pass


def package_files(d: pathlib.Path) -> dict:
    """The files of one intel release directory. Two layouts are accepted:
    - the assets publish.yml attaches (BUNDLES): <P>.tar.gz, <P>.manifest.json, <P>.manifest.sigstore.json, <P>.inclusion-proof.json, <P>.sha256,
      checkpoint.txt, checkpoint.sigstore.json (P = intel-<family>-<version>);
    - the generic one: manifest.json, manifest.sigstore.json and one tarball."""
    tars = sorted(d.glob('*.tar.gz'))
    if len(tars) != 1: raise PackageError('expected exactly one package tarball')
    P = tars[0].name[:-len('.tar.gz')]
    pick = lambda *names: next((d / n for n in names if (d / n).is_file()), None)
    return {'tarball': tars[0], 'manifest': pick(f'{P}.manifest.json', 'manifest.json'), 'bundle': pick(f'{P}.manifest.sigstore.json', 'manifest.sigstore.json'),
            'proof': pick(f'{P}.inclusion-proof.json'), 'sha256': pick(f'{P}.sha256'), 'checkpoint': pick('checkpoint.txt'), 'checkpoint_bundle': pick('checkpoint.sigstore.json')}


def read_package(d: pathlib.Path) -> tuple[dict, dict, pathlib.Path]:
    """(manifest, {path: bytes}, tarball) after checking the tarball against the published manifest. Raises PackageError."""
    man_file = package_files(d)['manifest']
    if not man_file: raise PackageError('no package manifest')
    man_bytes = man_file.read_bytes()
    try: man = json.loads(man_bytes)
    except ValueError as e: raise PackageError(f'manifest is not JSON: {e}') from None
    if man.get('schema') != 'macguard.package-manifest/1' or man.get('status') != 'PUBLISHED': raise PackageError('not a published macguard.package-manifest/1')
    tars = [package_files(d)['tarball']]
    if tars[0].stat().st_size > MAX_TAR: raise PackageError('package too large')
    members, total = {}, 0
    try:
        with tarfile.open(tars[0], 'r:gz') as t:
            for m in t.getmembers():
                if m.isdir(): continue
                if not m.isfile() or m.name.startswith('/') or '..' in m.name.split('/') or m.name in members: raise PackageError(f'unsafe or duplicate member {m.name!r}')
                total += m.size
                if m.size > MAX_MEMBER or total > MAX_EXPANDED: raise PackageError('decompressed size limit exceeded')
                members[m.name] = t.extractfile(m).read()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise PackageError(f'unreadable tarball: {e}') from None
    # BUNDLES' tarball carries only the data files (the manifest is signed and published next to it); a manifest INSIDE the tarball must be identical
    if 'manifest.json' in members and members['manifest.json'] != man_bytes: raise PackageError('the manifest inside the package differs from the published one')
    listed = {f['path']: f for f in man.get('files', [])}
    if not listed or set(listed) != set(members) - {'manifest.json'}: raise PackageError('package contents differ from the manifest')
    for p, f in listed.items():
        b = members[p]
        if len(b) != f.get('bytes') or hashlib.sha256(b).hexdigest() != f.get('sha256'): raise PackageError(f'hash or size mismatch: {p}')
    return man, members, tars[0]


def verify_package(d: pathlib.Path, root: pathlib.Path) -> tuple[bool, str]:
    """(ok, reason). The BUNDLES verifier AND the local content checks must both pass."""
    verifier = root / 'scripts' / 'intel_package.py'
    if not verifier.is_file(): return False, 'no intel package verifier in this build (scripts/intel_package.py): package not used'
    try:
        f = package_files(d)
        if not f['manifest'] or not f['bundle']: return False, 'manifest or its Sigstore bundle missing: package not used'
        args = ['verify', '--package', str(f['tarball']), '--manifest', str(f['manifest']), '--bundle', str(f['bundle'])]
        for k, opt in (('proof', '--proof'), ('checkpoint', '--checkpoint'), ('checkpoint_bundle', '--checkpoint-bundle'), ('sha256', '--sha256-file')):
            if f[k]: args += [opt, str(f[k])]
        r = subprocess.run([sys.executable, '-I', str(verifier), *args], capture_output=True, text=True, timeout=300)
    except PackageError as e:
        return False, f'content check failed: {e}'
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f'verifier did not run: {type(e).__name__}'
    if r.returncode != 0: return False, f'verifier refused the package (exit {r.returncode})'
    try: read_package(d)
    except PackageError as e: return False, f'content check failed: {e}'
    return True, 'signature verified by scripts/intel_package.py; manifest, hashes and sizes verified by the site build'


def kev_dataset(members: dict) -> dict:
    """The macguard.intel-kev/1 dataset inside a verified package, validated field by field. Raises PackageError."""
    cands = [p for p in members if p.endswith('kev.json')]
    if len(cands) != 1: raise PackageError('expected exactly one kev.json in the package')
    try: doc = json.loads(members[cands[0]])
    except ValueError as e: raise PackageError(f'kev.json is not JSON: {e}') from None
    if doc.get('schema') != SCHEMA_KEV or not isinstance(doc.get('items'), list): raise PackageError('not a macguard.intel-kev/1 dataset')
    src = doc.get('source') or {}
    if src.get('license') != 'CC0-1.0': raise PackageError('KEV dataset licence is not CC0-1.0')
    items = doc['items']
    if len(items) > MAX_ITEMS or doc.get('count') != len(items) or not items: raise PackageError('count does not match the items')
    prev = ''
    for it in items:
        if not isinstance(it, dict) or not CVE_RE.match(str(it.get('cve_id', ''))): raise PackageError(f'bad cve_id {it.get("cve_id") if isinstance(it, dict) else it!r}')
        if it['cve_id'] <= prev: raise PackageError('items are not sorted by cve_id or are duplicated')
        prev = it['cve_id']
        for k in KEV_TEXT:
            v = it.get(k)
            if v is not None and (not isinstance(v, str) or len(v) > MAX_FIELD): raise PackageError(f'{it["cve_id"]}: bad field {k}')
        for k in ('date_added', 'due_date'):
            v = it.get(k)
            if v is not None and not (isinstance(v, str) and DATE_RE.match(v)): raise PackageError(f'{it["cve_id"]}: bad date {k}')
        cw = it.get('cwes', [])
        if not isinstance(cw, list) or any(not CWE_RE.match(str(c)) for c in cw): raise PackageError(f'{it["cve_id"]}: bad cwes')
    return doc


def kev_shards(doc: dict, package: dict) -> tuple[dict, dict]:
    """(index, {relative file: shard}) for the static KEV search. A year is split only if its shard would exceed MAX_SHARD bytes."""
    by_year: dict = {}
    for it in doc['items']:
        by_year.setdefault(CVE_RE.match(it['cve_id']).group(1), []).append({k: it.get(k) for k in KEV_FIELDS})
    shards, entries = {}, []
    enc = lambda o: json.dumps(o, separators=(',', ':'), sort_keys=True).encode()
    for y in sorted(by_year):
        chunks, cur = [], []
        for r in by_year[y]:
            cur.append(r)
            if len(enc({'schema': SCHEMA_KEV_SHARD, 'year': y, 'items': cur})) > MAX_SHARD:
                if len(cur) == 1: raise PackageError(f'{r["cve_id"]}: a single record exceeds the shard limit')
                cur.pop(); chunks.append(cur); cur = [r]
        chunks.append(cur)
        for i, c in enumerate(chunks):
            name = f'kev/{y}.json' if len(chunks) == 1 else f'kev/{y}-{i}.json'
            body = {'schema': SCHEMA_KEV_SHARD, 'year': y, 'items': c}
            shards[name] = body
            entries.append({'year': y, 'file': name, 'first': c[0]['cve_id'], 'last': c[-1]['cve_id'], 'sha256': hashlib.sha256(enc(body) + b'\n').hexdigest(),
                            'count': {'value': len(c), 'source': 'verified KEV package'}})
    src = doc['source']
    index = {'schema': SCHEMA_KEV_INDEX, 'label': 'CISA KEV catalogue, static search (KEV only: not NVD, not EUVD, not GCVE)',
             'source': {'id': src.get('id', 'cisa-kev'), 'url': src.get('url'), 'license': 'CC0-1.0', 'attribution': src.get('attribution'),
                        'catalog_version': src.get('catalog_version'), 'date_released': src.get('date_released'), 'retrieved_at': src.get('retrieved_at'),
                        'upstream_sha256': src.get('upstream_sha256')},
             'count': {'value': len(doc['items']), 'source': 'verified KEV package'}, 'package': package, 'shards': entries}
    return index, shards


def intel_packages(root: pathlib.Path) -> list:
    base = pathlib.Path(os.environ.get('MG_INTEL_RELEASES') or root / 'intel-release')
    out = []
    for d in (sorted(p for p in base.iterdir() if p.is_dir()) if base.is_dir() else []):
        ok, why = verify_package(d, root)
        try: meta = json.loads((d / 'meta.json').read_text()) if (d / 'meta.json').is_file() else {}
        except ValueError: meta = {}
        out.append({'dir': d, 'ok': ok, 'reason': why, 'meta': meta if isinstance(meta, dict) else {}})
    return out


def sources(root: pathlib.Path) -> dict:
    """What the portal says about each intelligence source: id, name, approval state, licence and attribution. Nothing else leaves the registry."""
    f = root / 'config' / 'intel' / 'sources.registry.json'
    reg = json.loads(f.read_text()) if f.is_file() else {'sources': []}
    rows = []
    for s in reg.get('sources', []):
        lic = s.get('licence') or {}
        rows.append({'id': s['id'], 'name': s.get('name'), 'approval_state': s.get('approval_state') or 'RETAINED', 'licence': lic.get('spdx') or lic.get('name'),
                     'attribution': lic.get('attribution_text')})
    return {'schema': SCHEMA_SOURCES, 'as_of': reg.get('as_of'), 'source': 'config/intel/sources.registry.json', 'sources': rows}


API_PAGES = ('index.html', 'vulnerabilities.html', 'vuln.html')


def inject_api(site: pathlib.Path, base: str) -> str:
    """Writes <meta name="mg-vuln-api" content=base> into the hub pages when the build configures an API (validated by csp.api_base). Returns base."""
    if not base: return ''
    tag = f'<meta name="mg-vuln-api" content="{base}">'
    for n in API_PAGES:
        p = site / n
        if not p.is_file(): continue
        s = re.sub(r'<meta name="mg-vuln-api"[^>]*>', '', p.read_text(encoding='utf-8'))
        m = re.search(r'<meta charset="[^"]*">', s, re.I)
        if not m: raise SystemExit(f'{p}: no <meta charset>')
        p.write_text(s[:m.end()] + tag + s[m.end():], encoding='utf-8')
    return base


def write(site: pathlib.Path, root: pathlib.Path, rows: list) -> dict:
    """Writes sources.json, kev/ (only from a verified package) and hub.json; extends packages.json and families.json. Returns hub.json."""
    latest = json.loads((site / 'latest.json').read_text()) if (site / 'latest.json').exists() else None
    (site / 'sources.json').write_text(json.dumps(sources(root), indent=1, sort_keys=True) + '\n')
    pkgs, refused, kev_index = [], [], None
    for p in intel_packages(root):
        if not p['ok']:
            refused.append({'dir': p['dir'].name, 'reason': p['reason']}); continue
        man, members, tb = read_package(p['dir'])
        pk = man['package']; tb_bytes = tb.read_bytes()
        kev = None
        if pk.get('family') == 'vulnerability-data' and any(n.endswith('kev.json') for n in members):
            try: kev = kev_dataset(members)
            except PackageError as e: refused.append({'dir': p['dir'].name, 'reason': f'KEV dataset refused: {e}'}); continue
        entry = {'family': pk['family'], 'id': pk['id'], 'name': pk['name'], 'tier': str(pk.get('tier', '')).upper() or None, 'format': pk.get('format'), 'version': pk.get('version'),
                 'tag': p['meta'].get('tag') or pk.get('release_tag') or pk.get('version'), 'published_at': p['meta'].get('published_at') or pk.get('created_at'), 'url': p['meta'].get('url'),
                 'size': {'package_bytes': len(tb_bytes), 'source': 'package tarball verified by the site build'},
                 'items': {'items': man['stats']['items'], 'files': man['stats']['files'], 'source': 'signed package manifest'},
                 'package_sha256': hashlib.sha256(tb_bytes).hexdigest(), 'manifest_sha256': hashlib.sha256(package_files(p['dir'])['manifest'].read_bytes()).hexdigest(),
                 'licences': sorted({str(s.get('licence')) for s in man.get('sources', [])}), 'validation': {**man['validation'], 'source': 'signed package manifest'} if isinstance(man.get('validation'), dict) else None,
                 'verification': {'checked': True, 'manifest_signature': 'valid', 'by': p['reason']},
                 'assets': {v.name: f'intel/{p["dir"].name}/{v.name}' for v in package_files(p['dir']).values() if v}}
        out_dir = site / 'intel' / p['dir'].name
        out_dir.mkdir(parents=True, exist_ok=True)
        for n in entry['assets']: (out_dir / n).write_bytes((p['dir'] / n).read_bytes())
        pkgs.append(entry)
        if kev is not None and kev_index is None:
            kev_index, shards = kev_shards(kev, {'tag': entry['tag'], 'package_sha256': entry['package_sha256'], 'manifest_sha256': entry['manifest_sha256'], 'url': entry['url'],
                                                 'assets': entry['assets']})
            for name, body in shards.items():
                (site / name).parent.mkdir(parents=True, exist_ok=True)
                (site / name).write_text(json.dumps(body, separators=(',', ':'), sort_keys=True) + '\n')
            (site / 'kev' / 'index.json').write_text(json.dumps(kev_index, indent=1, sort_keys=True) + '\n')
    pj_file = site / 'packages.json'
    pj = json.loads(pj_file.read_text()) if pj_file.exists() else {'packages': []}
    pj['intel'] = pkgs; pj['intel_refused'] = refused
    pj_file.write_text(json.dumps(pj, indent=1, sort_keys=True) + '\n')
    fj_file = site / 'families.json'
    if fj_file.exists():
        fj = json.loads(fj_file.read_text())
        for f in fj['families']:
            if f['id'] == 'cisa_kev' and kev_index:
                f['state'] = 'PUBLISHED'
                f['package'] = {'records': kev_index['count']['value'], 'tag': kev_index['package']['tag'], 'manifest_sha256': kev_index['package']['manifest_sha256'],
                                'source': 'verified intel package (kev/index.json)'}
        fj_file.write_text(json.dumps(fj, indent=1, sort_keys=True) + '\n')
    recent = [{'family': 'yara_community', 'tag': r['tag'], 'published_at': r['published_at'], 'url': r['url'],
               'signature': (r.get('verification') or {}).get('manifest_signature') if (r.get('verification') or {}).get('checked') else 'not_checked'} for r in list(reversed(rows))[:5]]
    recent += [{'family': p['family'], 'tag': p['tag'], 'published_at': p['published_at'], 'url': p['url'], 'signature': 'valid'} for p in pkgs]
    recent.sort(key=lambda r: str(r['published_at'] or ''), reverse=True)
    stats = {}
    if latest and latest.get('stats'):
        s = latest['stats']
        stats['yara'] = {'files': s.get('files'), 'yara_rules': s.get('yara_rules'), 'source': 'latest.json (counted by the site build from the verified release)'}
    if kev_index:
        stats['kev'] = {'records': kev_index['count']['value'], 'catalog_version': kev_index['source'].get('catalog_version'), 'source': 'verified KEV package (kev/index.json)'}
    last = (rows[-1].get('verification') or {}) if rows else {}
    hub = {'schema': SCHEMA_HUB, 'source': 'latest.json, releases.json, consistency.json and verified intel packages of this build', 'stats': stats, 'recent': recent[:8],
           'integrity': {'latest_tag': rows[-1]['tag'] if rows else None, 'latest_manifest_sha256': latest.get('manifest_sha256') if latest else None,
                         'latest_signature': last.get('manifest_signature') if last.get('checked') else 'not_checked', 'consistency_proof': (site / 'consistency.json').exists(),
                         'intel_packages_verified': len(pkgs), 'intel_packages_refused': len(refused), 'source': 'this site build'},
           'kev_static': bool(kev_index)}
    if not kev_index:   # an explicit "unavailable" index, so the pages never request a missing file (no 404 in the console) and say why
        (site / 'kev').mkdir(parents=True, exist_ok=True)
        (site / 'kev' / 'index.json').write_text(json.dumps({'schema': SCHEMA_KEV_INDEX, 'available': False, 'shards': [], 'reason': 'no verified CISA KEV package in this build'}, indent=1, sort_keys=True) + '\n')
    (site / 'hub.json').write_text(json.dumps(hub, indent=1, sort_keys=True) + '\n')
    return hub
