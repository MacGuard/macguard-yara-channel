#!/usr/bin/env python3
"""Generates the static data of the MacGuard Security Intelligence pages: web/api/v1/*.json.

Standard library only, no network. Every number and every status in the output traces to a file of this repository:
  intel/status.py                           channel families and their status (the single source of truth for badges)
  config/intel/sources.registry.json        sources, licences, redistribution status (clearance computed by intel/registry.py)
  docs/intelligence/LICENSE-MATRIX.md       licence verdict table (evidence, not legal advice)
  docs/intelligence/ROADMAP.md              roadmap rows (no dates, no percentages)
  docs/intelligence/PROVENANCE-DESIGN.md    rules, the six facts, coverage matrix (designed vs exercised)
  docs/intelligence/live-evidence/2026-10-22/<channel>-<version>/   MacGuard-generated metadata of a real build of CISA KEV and the
                                            abuse.ch Feodo Tracker feed (manifest, build report, retrieval record; byte copies). The third-party
                                            data files are NOT copied.
  logs/log.jsonl, logs/checkpoint.txt       the legacy YARA channel's own transparency log
  tests/test_*.py                           test files cited by the cards (function counts are counted, not typed)

usage: gen_intel_web.py [--write] [--check] [--generated-at ISO]
  (default / --write)  rewrite web/api/v1
  --check              regenerate in memory and compare with the committed files, ignoring only generated_at; exit 1 on a difference"""
import argparse, datetime, hashlib, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from intel import registry as reg, status as chstatus   # noqa: E402

API = ROOT / 'web' / 'api' / 'v1'
EVIDENCE = ROOT / 'docs' / 'intelligence' / 'live-evidence' / '2026-10-22'
SCHEMA = 'macguard.web-data/1'
ORDER = {'operational': 0, 'experimental': 1, 'planned': 2}
KIND = {'yara': 'detection rules', 'yara-x': 'detection rules', 'sigma': 'detection rules', 'ioc': 'indicators', 'vulns': 'vulnerability catalog',
        'clamav': 'antivirus signatures', 'heuristics': 'heuristics', 'behavior': 'behaviour detections', 'ml': 'ML models', 'sandbox': 'sandbox profiles'}
# card id -> (channel directory under live-evidence, retrieval record file name)
LIVE_CARDS = {'ioc-1': ('ioc-1', 'feodo-ipblocklist.json.retrieval.json'), 'vulns-1': ('vulns-1', 'known_exploited_vulnerabilities.json.retrieval.json'),
              'vulns-euvd-1': ('vulns-euvd-1', 'euvd-page-0000.json.retrieval.json'), 'vulns-eukev-1': ('vulns-eukev-1', 'euvd-page-0000.json.retrieval.json'),
              'vulns-certeu-1': ('vulns-certeu-1', 'security-advisories.rss.xml.retrieval.json')}
GROUPS = {'4.1': 'Linux system package managers', '4.2': 'Linux self-contained formats', '4.3': 'macOS', '4.4': 'Language ecosystems', '4.5': 'Other methods'}
FEED_TESTS = ('tests/test_intel.py', 'tests/test_intel_live.py', 'tests/test_vulns_eu.py')


def rel(p):
    return pathlib.Path(p).relative_to(ROOT).as_posix()


def jload(p):
    return json.loads(pathlib.Path(p).read_text(encoding='utf-8'))


def sha256_file(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def count_tests(path):
    """Number of test functions in a test file, counted from the file."""
    return len(re.findall(r'^\s+def test_', (ROOT / path).read_text(encoding='utf-8'), re.M))


def test_doc(path):
    """First sentence of the module docstring of a test file (what the tests say they cover)."""
    m = re.match(r'\s*(?:#.*\n)*\s*"""(.*?)"""', (ROOT / path).read_text(encoding='utf-8'), re.S)
    if not m:
        return None
    return ' '.join(m.group(1).split()).split('. ')[0].rstrip('.') + '.'


def cells(line):
    parts = re.split(r'(?<!\\)\|', line.strip())
    return [c.strip().replace('\\|', '|') for c in parts[1:-1]]


def table_rows(lines):
    return [cells(l) for l in lines if l.strip().startswith('|') and not re.match(r'^\|[\s:|-]+\|$', l.strip())][1:]


def section(text, start, end=None):
    """Lines between a heading starting with `start` and the next heading that starts with `end` (or any '## ' heading)."""
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith(start))
    j = len(lines)
    for n in range(i + 1, len(lines)):
        if (end and lines[n].startswith(end)) or (not end and lines[n].startswith('## ')):
            j = n
            break
    return lines[i + 1:j]


def clean(s):
    return re.sub(r'\*\*|`', '', s)


def meta(generated_at, origin, real):
    return {'schema': SCHEMA, 'generated_at': generated_at, 'generated_by': 'scripts/gen_intel_web.py', 'data_origin': origin, 'what_is_real': real}


def license_key(src):
    lic = src.get('license', {})
    return lic.get('spdx') or 'no-spdx-terms-text'


# ---------------------------------------------------------------- live evidence (MacGuard-generated metadata only)
def live_cards_data():
    out = {}
    for cid, (d, retr_name) in LIVE_CARDS.items():
        base = EVIDENCE / d
        if not base.is_dir():
            continue
        out[cid] = {'dir': rel(base), 'manifest': jload(base / 'manifest.json'), 'report': jload(base / 'build-report.json'), 'retrieval': jload(base / retr_name),
                    'files': {n: sha256_file(base / n) for n in ('manifest.json', 'build-report.json', retr_name)}}
    return out


def tests_cited(paths):
    return [{'file': p, 'test_functions': count_tests(p), 'what_it_says': test_doc(p)} for p in paths if (ROOT / p).exists()]


def feed_card(cid, live, registry, generated_at):
    man, rep, ret = live['manifest'], live['report'], live['retrieval']
    ch = man['channel']
    st = {c['id']: c for c in chstatus.CHANNELS}[ch['id']]
    sid = man['sources'][0]['id']
    approval = man['approval']
    arts = []
    for a in man['artifacts']:
        third_party = a['origin'] == 'original'
        meta_file = a['path'] in ('build-report.json', ret['file'] + '.retrieval.json')
        arts.append({'path': a['path'], 'sha256': a['sha256'], 'bytes': a['bytes'], 'media_type': a['media_type'], 'origin': a['origin'],
                     'original_signature_present': a['original_signature']['present'], 'hosted_on_this_site': False, 'metadata_embedded_in_card': meta_file,
                     'role': 'original third-party file, kept byte for byte' if third_party else 'MacGuard-generated metadata, embedded in this card' if meta_file
                     else 'MacGuard-generated, derived from third-party content; not hosted'})
    s = registry[sid]
    ok, why = reg.clearance(registry, [sid])
    assert not ok or approval['publishable'], 'registry and manifest disagree about publication'
    key_numbers = {'input_items': rep['input_items'], 'accepted': rep['accepted'], 'rejected': rep['rejected']}
    if 'expired' in rep:
        key_numbers.update(expired=rep['expired'], published=rep['published'])
    if 'declared_count' in rep:
        key_numbers.update(declared_count=rep['declared_count'], count_matches_declared=rep['count_matches_declared'])
    return {
        **meta(generated_at, f"{live['dir']}/ (byte copies of the manifest, build report and retrieval record of a real build made on {ret['retrieved_at'][:10]}), "
               'intel/status.py, config/intel/sources.registry.json, tests/', 'A real download and build of one upstream feed. Every number below is copied from the build report or manifest. Nothing here is published: see approval and download.'),
        'id': cid, 'kind': 'channel-artifact-set', 'channel': ch['id'], 'family': ch['family'], 'version': ch['version'],
        'status': st['status'], 'status_source': 'intel/status.py', 'status_detail': st['detail'],
        'identity': {'channel_manifest_schema': man['schema'], 'created_at': ch['created_at'], 'artifacts_root': man['artifacts_root'],
                     'compatibility': man['compatibility'], 'previous_version': man['previous']['version']},
        'artifacts': arts,
        'source': {'id': sid, 'name': s['name'], 'upstream_url': s['upstream_url'], 'license': s['license'], 'redistribution_status': s['redistribution_status'],
                   'owner_confirmed': s.get('owner_confirmed', False), 'attribution': s['attribution'], 'registry_status_note': s.get('status_note'),
                   'registry_clearance_blocking_reasons': why},
        'retrieval': dict(ret, **({'pages': rep['pages'], 'note': f"this is the first of {rep['pages']} paged requests; every page is an original file listed in the artifacts"} if rep.get('pages', 1) > 1 else {})),
        'build': {'report': rep, 'key_numbers': key_numbers},
        'approval': {'state': approval['state'], 'publishable': approval['publishable'], 'approved_by': approval['approved_by'], 'approved_at': approval['approved_at'],
                     'blocking_reasons': approval['blocking_reasons']},
        'signature': {'status': 'not_signed', 'text': 'not signed: no signing workflow exists', 'original_signature': 'none (the upstream provides none; MacGuard never re-signs a third-party file)'},
        'attestation': {'status': 'none', 'text': 'none: not produced', 'validation_gates': man['validation']['gates'], 'validation_attestation': man['validation']['attestation']},
        'tests': tests_cited(FEED_TESTS),
        'tests_note': 'Tests run against local test doubles; the live download was done once by hand. No test result is attested.',
        'download': {'published': False, 'text': 'not published: publication is blocked', 'reason': approval['blocking_reasons'],
                     'third_party_data_hosted': False,
                     'metadata_offered': [f'api/v1/cards/{cid}.json'],
                     'upstream_data_url': ret['url'], 'upstream_note': 'To compare, fetch the upstream file yourself and hash it. The upstream changes: a different hash later does not mean tampering.'},
        'verify_independently': [
            {'step': 'Rebuild the channel from the upstream feed (needs the network; writes only under ROOT)', 'command': f'python3 -m intel vulns build {sid} --out ROOT --version {ch["version"]}'},
            {'step': 'Compare the sha256 of the retrieved file with the card', 'command': f'shasum -a 256 ROOT/{ch["id"]}/{ch["version"]}/{ret["file"]}', 'expect': ret['sha256'], 'caveat': 'equal only if the upstream file did not change since the retrieval'},
            {'step': 'Build a catalog that pins the channel (drafts are included only on request)', 'command': f'python3 -m intel catalog build --channel ROOT/{ch["id"]}/{ch["version"]}/manifest.json --version 1 --out OUT --include-draft --rel-to ROOT'},
            {'step': 'Verify hashes, Merkle root, state and unlisted files', 'command': 'python3 -m intel catalog verify OUT/catalog.json --root ROOT --allow-draft', 'expect': 'exit 5 = CONSISTENT, SIGNATURE NOT CHECKED (there is no signature to check)'},
            {'step': 'Same check through the CLI front end', 'command': 'mgctl intelligence catalog verify OUT/catalog.json --root ROOT --allow-draft'}],
        'metadata_files_sha256': live['files'],
    }


def legacy_card(registry, generated_at):
    log = [json.loads(l) for l in (ROOT / 'logs' / 'log.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    rel_pub = [e for e in log if e['event'] == 'release.published'][-1]
    tag = re.search(r'release (rules-[0-9]{8}-[0-9]+)', rel_pub['message']).group(1)
    acc = [e for e in log if e['event'] == 'candidate.accepted'][-1]
    unch = [e for e in log if e['event'] == 'candidate.unchanged']
    cp = (ROOT / 'logs' / 'checkpoint.txt').read_text(encoding='utf-8').splitlines()
    st = {c['id']: c for c in chstatus.CHANNELS}['yara']
    srcs = [registry[i] for i in ('nextron', 'community')]
    rep = 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/' + tag
    return {
        **meta(generated_at, 'logs/log.jsonl, logs/checkpoint.txt, logs/checkpoint.sigstore.json (the legacy channel\'s own transparency log), intel/status.py, config/intel/sources.registry.json',
               'The legacy YARA channel is published by its own pipeline. Numbers come from its transparency log in this repository; the release files themselves live on GitHub Releases and the built site, not here.'),
        'id': 'yara-legacy', 'kind': 'legacy-channel', 'channel': 'yara', 'family': 'yara', 'version': tag,
        'status': st['status'], 'status_source': 'intel/status.py', 'status_detail': st['detail'],
        'identity': {'latest_release_tag': tag, 'release_published_at': rel_pub['time'], 'log_seq_of_release_event': rel_pub['seq'],
                     'engine': st['engine'], 'log_checkpoint_size': int(cp[1]), 'log_checkpoint_root': cp[2], 'log_format': cp[0]},
        'artifacts': [{'path': n, 'sha256': None, 'bytes': None, 'origin': 'derived', 'hosted_on_this_site': 'built site only', 'role': r}
                      for n, r in (('rules-release.tar.gz', 'the rule files of the release'), ('manifest.json', 'signed manifest: the SHA-256 and size of every file are inside it'),
                                   ('manifest.sigstore.json', 'Sigstore bundle of the manifest'), ('inclusion-proof.json', 'Merkle inclusion proof of the release in the log'))],
        'artifacts_note': 'Hashes are not copied here: the authoritative values are in the signed manifest.json of the release. The repository does not store them.',
        'latest_candidate': {'file_count': acc['details']['file_count'], 'examined': acc['details']['examined'], 'quarantined': acc['details']['quarantined'],
                             'rejected': acc['details']['rejected'], 'deprecated': acc['details']['deprecated'], 'rules_root': acc['details']['rules_root'],
                             'evaluated_at': acc['time'], 'log_seq': acc['seq'],
                             'identical_to_latest_release_per_log': bool(unch) and unch[-1]['seq'] > acc['seq']},
        'sources': [{'id': s['id'], 'name': s['name'], 'upstream_url': s['upstream_url'], 'license': s['license'], 'redistribution_status': s['redistribution_status'],
                     'attribution': s['attribution'], 'status_note': s.get('status_note')} for s in srcs],
        'approval': {'state': 'published (release.published event in the log)', 'publishable': True, 'blocking_reasons': [],
                     'open_item': 'Redistribution notices of the third-party rules are pending legal review (docs/intelligence/CHANNELS.md); both sources are pending-legal in the registry.'},
        'signature': {'status': 'signed_sigstore', 'text': 'Sigstore keyless signature of manifest.json and of the log checkpoint (bundles manifest.sigstore.json and logs/checkpoint.sigstore.json). Verify it yourself: the browser pages do not verify signatures.',
                      'evidence_files': ['logs/checkpoint.sigstore.json'], 'workflow_identity': '.github/workflows/publish.yml@refs/heads/main'},
        'attestation': {'status': 'none', 'text': 'none: not produced (no GitHub/SLSA attestation and no signed test attestation exist; docs/intelligence/VALIDATION-PLAN.md)'},
        'tests': tests_cited(('tests/test_verify_public_release.py', 'tests/test_tlog.py', 'tests/test_rulecheck.py')),
        'tests_note': 'test_verify_public_release.py needs the network and cosign; tests are not attested.',
        'download': {'published': True, 'text': 'published by the legacy pipeline: use the release assets', 'release_url': rep,
                     'site_files': ['latest.json', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json', 'rules-release.tar.gz', 'catalog.json', 'releases.json', 'logs/checkpoint.txt', 'logs/checkpoint.sigstore.json', 'verify_public_release.py'],
                     'site_files_note': 'These files are produced by scripts/build_site.py in the deployed site; they are not part of this static data.'},
        'verify_independently': [
            {'step': 'Verify the latest release end to end (signature, hashes, log inclusion)', 'command': 'mgctl evidence verify --latest', 'expect': 'needs the network and cosign'},
            {'step': 'Verify a downloaded release folder offline', 'command': 'mgctl evidence verify --directory ./release --offline'},
            {'step': 'Without mgctl', 'command': 'python3 verify_public_release.py', 'expect': 'script published on the site next to its .sha256; a same-origin copy is a convenience, not a root of trust'}],
    }


# ---------------------------------------------------------------- channels, sources, licences
def build_channels(registry, cards, generated_at):
    out = []
    for c in chstatus.CHANNELS:
        srcs = sorted(c['sources']) if 'sources' in c else sorted(sid for sid, s in registry.items() if c['family'] in s.get('families', []))
        lic = sorted({license_key(registry[i]) for i in srcs})
        mycards = sorted(k for k, v in cards.items() if v['channel'] == c['id'])
        oses = set()
        for k in mycards:
            if 'identity' in cards[k] and 'compatibility' in cards[k]['identity']:
                oses.update(cards[k]['identity']['compatibility']['platforms'])
        if c['status'] == 'operational':
            pub = {'published': True, 'text': 'published by the legacy YARA pipeline (see card yara-legacy)'}
        elif mycards:
            reasons = sorted({r for k in mycards for r in cards[k]['approval']['blocking_reasons']})
            pub = {'published': False, 'text': 'not published: publication is blocked', 'blocking_reasons': reasons}
        else:
            pub = {'published': False, 'text': 'not published: no artifact exists' if c['status'] == 'planned' else 'not published'}
        ev = [x.strip() for x in re.split(r'[;,]', c['evidence']) if (ROOT / x.strip()).exists()]
        if c['status'] != 'planned' and not ev:
            raise SystemExit(f"{c['id']}: status '{c['status']}' without evidence: none of {c['evidence']!r} is a file of this repository")
        row = {'id': c['id'], 'family': c['family'], 'status': c['status'], 'status_source': 'intel/status.py', 'kind': KIND.get(c['id']) or KIND[c['family']], 'detail': c['detail'], 'evidence': c['evidence'], 'evidence_files_found': ev,
               'sources': srcs, 'licenses': lic, 'os': sorted(oses), 'os_basis': ('compatibility.platforms in the channel manifests' if oses else 'not stated in the data'),
               'cards': mycards, 'publication': pub}
        if 'engine' in c:
            row['engine'] = c['engine']
        out.append(row)
    counts = {s: sum(1 for r in out if r['status'] == s) for s in ORDER}
    return {**meta(generated_at, 'intel/status.py (CHANNELS), config/intel/sources.registry.json, cards/*.json',
                   'Status of each family exactly as intel/status.py declares it; a badge is never set anywhere else.'), 'counts_by_status': counts, 'channels': out}


def build_sources(registry, cards, generated_at):
    rows = []
    for sid, s in sorted(registry.items()):
        ok, why = reg.clearance(registry, [sid])
        rows.append({'id': sid, 'name': s['name'], 'families': s['families'], 'upstream_url': s['upstream_url'], 'license': s['license'], 'license_key': license_key(s),
                     'redistribution_status': s['redistribution_status'], 'owner_confirmed': s.get('owner_confirmed', False), 'attribution': s['attribution'],
                     'access': s['access'], 'trust': s.get('trust'), 'default_ttl_days': s.get('default_ttl_days'), 'original_signature': s['original_signature'],
                     'status_note': s.get('status_note'), 'clearance': {'publishable': ok, 'blocking_reasons': why},
                     'real_retrieval_cards': sorted(k for k, v in cards.items() if v.get('source', {}).get('id') == sid)})
    return {**meta(generated_at, 'config/intel/sources.registry.json, clearance computed by intel/registry.py',
                   'Redistribution status is a human decision recorded in the registry; the code never decides a licence question.'), 'sources': rows}


def build_licenses(registry, generated_at):
    text = (ROOT / 'docs/intelligence/LICENSE-MATRIX.md').read_text(encoding='utf-8')
    rows = []
    for c in table_rows(section(text, '## 1. Verdict table')):
        verdicts = [v for v in ('ALLOWED-WITH-CONDITIONS', 'PENDING-LEGAL', 'BLOCKED', 'NOT-VERIFIED') if v in c[3]]
        rows.append({'n': int(c[0]), 'source': clean(c[1]), 'license_as_stated': clean(c[2]), 'verdict': clean(c[3]), 'verdict_classes': verdicts})
    classes = {}
    for r in rows:
        for v in r['verdict_classes']:
            classes[v] = classes.get(v, 0) + 1
    status_line = re.search(r'^Status: (.*)$', text, re.M).group(1)
    return {**meta(generated_at, 'docs/intelligence/LICENSE-MATRIX.md (verdict table), config/intel/sources.registry.json',
                   'Evidence read on 2026-10-22, not legal advice and not an authorisation to publish. MacGuard does not own or relicense any third-party content.'),
            'matrix_status': status_line, 'verdict_legend': ['ALLOWED-WITH-CONDITIONS', 'PENDING-LEGAL', 'BLOCKED', 'NOT-VERIFIED'], 'rows_by_verdict_class': classes, 'matrix': rows,
            'registry': [{'id': i, 'name': s['name'], 'spdx': s['license'].get('spdx'), 'license_name': s['license']['name'], 'redistribution_status': s['redistribution_status'],
                          'owner_confirmed': s.get('owner_confirmed', False)} for i, s in sorted(registry.items())]}


# ---------------------------------------------------------------- vulnerability sources (US / EU / ES), built from the registry and the real builds
VULN_RULES = [
    {'id': 'V1', 'rule': 'Exploitation is what a source asserts in a structured field. A critical score, a high EPSS value or the word "critical" is severity and never makes a vulnerability "exploited".'},
    {'id': 'V2', 'rule': 'Each source keeps its own statement. Two sources asserting exploitation are not called independent confirmation unless the registry says they are independent.'},
    {'id': 'V3', 'rule': 'A Linux package is never called vulnerable from upstream version ranges: a distribution backports fixes. Only a distribution advisory for that release and package can say so; otherwise the verdict is NOT_ASSESSED.'},
    {'id': 'V4', 'rule': 'Identifiers (CVE, EUVD, GHSA) join records only when a source declares them as its own. Text mentions, reference URLs and similar product names never join records.'},
    {'id': 'V5', 'rule': 'Nothing is redistributed until the registry says the licence allows it AND the owner confirmed it. Today no vulnerability source passes both.'}]


def build_vulns(registry, cards, generated_at):
    rows = []
    for sid, s in sorted(registry.items()):
        if 'vulns' not in s.get('families', []):
            continue
        ok, why = reg.clearance(registry, [sid])
        mine = sorted(k for k, v in cards.items() if v.get('source', {}).get('id') == sid)
        integ = 'built-and-run' if mine else 'blocked-no-adapter' if s['redistribution_status'] == 'blocked' else 'registered-only'
        rows.append({'id': sid, 'name': s['name'], 'region': s.get('region', 'unknown'), 'upstream_url': s['upstream_url'], 'license_name': s['license']['name'], 'license_key': license_key(s),
                     'redistribution_status': s['redistribution_status'], 'owner_confirmed': s.get('owner_confirmed', False), 'publishable': ok, 'blocking_reasons': why,
                     'exploitation_field': s.get('exploitation_field', 'unknown'), 'max_snapshot_age_days': s.get('max_snapshot_age_days'), 'integration': integ,
                     'cards': mine, 'status_note': s.get('status_note')})
    observed = []
    for cid, c in sorted(cards.items()):
        if c.get('family') != 'vulns':
            continue
        r = c['build']['report']
        observed.append({'card': cid, 'channel': c['channel'], 'source': c['source']['id'], 'retrieved_at': c['retrieval']['retrieved_at'], 'accepted': r['accepted'], 'rejected': r['rejected'],
                         'pages': r.get('pages', 1), 'complete': r.get('complete', True), 'exploitation_asserted': r.get('exploitation_asserted'), 'publishable': c['approval']['publishable']})
    mpath = EVIDENCE / 'vulns-merged-1.json'
    merge = jload(mpath) if mpath.exists() else None
    cards_dir = API / 'vulns'
    published = sorted(p.stem for p in cards_dir.glob('*.json') if p.name != 'index.json') if cards_dir.is_dir() else []
    return {**meta(generated_at, 'config/intel/sources.registry.json (sources, regions, clearance), the cards of the real builds, docs/intelligence/live-evidence/2026-10-22/vulns-merged-1.json',
                   'Which vulnerability sources exist, which were really downloaded and validated on 2026-10-22, and why none is published. Counts only: no third-party vulnerability record is hosted.'),
            'regions': {'US': 'United States', 'EU': 'European Union', 'ES': 'Spain', 'global': 'Global', 'unknown': 'Not stated'}, 'sources': rows, 'observed': observed, 'merge': merge,
            'rules': VULN_RULES, 'cards': {'published': len(published), 'ids': published, 'reason': 'no vulnerability card is published: no source is both cleared by the registry and confirmed by the owner' if not published else None,
                                          'card_schema': 'docs/intelligence/schemas/vuln-card.schema.json', 'generator': 'scripts/gen_intel_vulns.py'}}


# ---------------------------------------------------------------- provenance engine (derived from the repository, never typed)
MANAGER_COLLECTOR = {'Homebrew formula': 'collect_formula', 'Homebrew cask': 'collect_cask', 'PKG installer': 'collect_pkgutil', 'Quarantine xattr': 'collect_xattrs',
                     'kMDItemWhereFroms': 'collect_xattrs', 'Code signature, notarization, Gatekeeper': 'collect_codesign', 'pip / pipx / uv / Poetry': 'collect_pip',
                     'APT / aptitude / DPKG, ownership': 'collect_dpkg', 'DPKG integrity': 'collect_dpkg'}


def provenance_engine():
    """experimental only if intel/provenance/ exists AND tests/test_provenance.py exists AND the mgctl command snapshot lists 'provenance file' as experimental."""
    pdir, tfile, snap_file = ROOT / 'intel/provenance', ROOT / 'tests/test_provenance.py', ROOT / 'tests/fixtures/mgctl/command-tree.json'
    snap = jload(snap_file)['commands'] if snap_file.exists() else {}
    collectors = {}
    for f in sorted((pdir / 'collectors').glob('*.py')) if pdir.is_dir() else []:
        fn = re.findall(r'^def (collect_\w+)\(', f.read_text(encoding='utf-8'), re.M)
        if fn:
            collectors[rel(f)] = fn
    ttext = tfile.read_text(encoding='utf-8') if tfile.exists() else ''
    real_mac = bool(re.search(r'^class RealMacTests', ttext, re.M))
    dpkg_pending = bool(re.search(r'^class RealLinuxDpkgPending', ttext, re.M))
    ok = pdir.is_dir() and tfile.exists() and snap.get('provenance file') == 'experimental'
    return {'status': 'experimental' if ok else 'planned', 'collectors': collectors, 'tests': count_tests('tests/test_provenance.py') if tfile.exists() else 0,
            'real_mac_tests_exist': real_mac, 'dpkg_real_host_pending': dpkg_pending, 'snapshot': {k: snap.get(k) for k in ('provenance', 'provenance file')}, 'ok': ok}


# ---------------------------------------------------------------- roadmap
def build_roadmap(generated_at):
    text = (ROOT / 'docs/intelligence/ROADMAP.md').read_text(encoding='utf-8')
    chs = {c['id']: c['status'] for c in chstatus.CHANNELS}
    rules = {'P0': ('files', ['intel/channel.py', 'intel/catalog.py', 'intel/verify.py', 'tests/test_intel.py']), 'P1': ('channels', ['ioc', 'vulns']), 'P2': ('provenance', []),
             'EU-Vuln': ('channels', ['vulns-euvd', 'vulns-eukev', 'vulns-certeu', 'vulns-merged']), 'Alerts': ('files', ['alerts/engine.py', 'alerts/api.py', 'web/intelligence/alerts/index.html', 'docs/alerts/ARCHITECTURE.md']),
             'P3': ('channels', ['sigma']), 'P4': ('channels', ['clamav']), 'P5': ('channels', ['heuristics', 'behavior']), 'P6': ('channels', ['sandbox', 'ml']),
             'Web': ('files', ['web/intelligence/index.html', 'scripts/gen_intel_web.py']), 'Cloud': ('files', ['cloud']), 'Install': ('files', ['docs/cli/mgctl-install.md', 'bin/mgctl'])}
    rows = []
    for c in table_rows(text.splitlines()):
        key = clean(c[0])
        kind, refs = rules[key]
        if kind == 'provenance':
            pe = provenance_engine()
            st = pe['status']
            basis = ('intel/provenance/ and tests/test_provenance.py exist and tests/fixtures/mgctl/command-tree.json lists "provenance file" as experimental' if pe['ok']
                     else 'the engine, its tests or the experimental command in the snapshot are missing')
        elif kind == 'channels':
            st = min((chs[i] for i in refs), key=lambda s: ORDER[s])
            basis = 'best status of ' + ', '.join(refs) + ' in intel/status.py'
        else:
            present = [p for p in refs if (ROOT / p).exists()]
            st = 'experimental' if len(present) == len(refs) else 'planned'
            basis = ('all these files exist: ' if st == 'experimental' else 'missing: ' + ', '.join(p for p in refs if p not in present) + '; ') + ', '.join(refs)
        rows.append({'phase': key, 'scope': clean(c[1]), 'done': clean(c[2]), 'missing': clean(c[3]), 'status': st, 'status_basis': basis})
    byk = {r['phase']: r for r in rows}
    prov = (ROOT / 'docs/intelligence/PROVENANCE-DESIGN.md').read_text(encoding='utf-8')
    p1b = next(c for c in table_rows(section(prov, '## 11.')) if c[0].startswith('P1b'))
    tracks = [
        {'id': 'macguard-intelligence', 'name': 'MacGuard Intelligence', 'source': 'docs/intelligence/ROADMAP.md', 'items': [r['phase'] for r in rows if r['phase'] not in ('Cloud', 'Install')]},
        {'id': 'linux-intelligence-guard', 'name': 'Linux Intelligence Guard', 'source': 'docs/intelligence/ROADMAP.md rows P2 and Install; docs/intelligence/PROVENANCE-DESIGN.md section 11 (P1b)',
         'items': ['P2', 'Install'], 'status': 'planned',
         'note': 'ROADMAP.md has no section with this name. The Linux work it lists is: provenance for Linux package managers (P2: the dpkg collector exists but is fixture-only, no real Linux host test; rpm and pacman are not implemented), Linux packages of mgctl (Install, templates only). Nothing runs on Linux as a product.',
         'linux_provenance_phase': {'phase': 'P1b (Linux)', 'scope': clean(p1b[1]), 'justification': clean(p1b[2])}},
        {'id': 'cloud', 'name': 'MacGuard Cloud', 'source': 'docs/intelligence/ROADMAP.md, docs/intelligence/CLOUD-CONTRACTS.md', 'items': ['Cloud'], 'status': byk['Cloud']['status'],
         'note': 'Draft contracts only; no service, agent or schema is published.'}]
    return {**meta(generated_at, 'docs/intelligence/ROADMAP.md, intel/status.py, existence of the files named in each status_basis',
                   'No dates and no percentages. A status other than planned means the named files exist or intel/status.py says so; nothing in the roadmap is deployed.'),
            'tracks': tracks, 'rows': rows}


# ---------------------------------------------------------------- provenance (design doc, parsed)
def build_provenance(generated_at):
    text = (ROOT / 'docs/intelligence/PROVENANCE-DESIGN.md').read_text(encoding='utf-8')
    rules = [{'id': clean(c[0]), 'rule': clean(c[1]), 'consequence': clean(c[2])} for c in table_rows(section(text, '## 1.'))]
    facts = [{'field': clean(c[0]), 'question': clean(c[1]), 'values': clean(c[2])} for c in table_rows(section(text, '## 2.'))]
    managers = []
    for sub in ('### 4.1', '### 4.2', '### 4.3', '### 4.4', '### 4.5'):
        for c in table_rows(section(text, sub, '### ')):
            raw = clean(c[-1])
            kind = ('exercised-in-survey' if raw.startswith('implemented') else 'designed' if raw.startswith('designed') else 'not-possible' if raw.startswith('NOT_POSSIBLE')
                    else 'recorded-only' if raw.startswith('recorded') else 'other')
            managers.append({'group': GROUPS[sub[4:7]], 'name': clean(c[0]), 'coverage': kind, 'coverage_raw': raw})
    counts = {}
    for m in managers:
        counts[m['coverage']] = counts.get(m['coverage'], 0) + 1
    limits = [clean(l[2:]) for l in section(text, '## 12.') if l.startswith('- ')]
    pe = provenance_engine()
    for m in managers:
        fn = MANAGER_COLLECTOR.get(m['name'])
        have = fn and any(fn in v for v in pe['collectors'].values())
        m['collector'] = fn if have else None
        m['engine'] = ('none' if not have else 'fixture-only' if fn == 'collect_dpkg' and pe['dpkg_real_host_pending'] else 'experimental-real-mac-tested' if pe['real_mac_tests_exist'] else 'experimental')
    engine_counts = {}
    for m in managers:
        engine_counts[m['engine']] = engine_counts.get(m['engine'], 0) + 1
    roadmap_missing = next(clean(c[3]) for c in table_rows((ROOT / 'docs/intelligence/ROADMAP.md').read_text(encoding='utf-8').splitlines()) if clean(c[0]) == 'P2')
    snap = pe['snapshot']
    if pe['ok']:
        real = ('A design plus a first EXPERIMENTAL engine. The collectors listed under engine_collectors exist and are tested; macOS collectors were also run against a real Mac '
                'by the tests, the dpkg collector is fixture-only (real Linux host test pending). Host-wide scanning and online checks are not implemented. '
                'Per-manager `engine` says what the code covers; `coverage` is the design survey, which is a different thing.')
        basis = ('intel/provenance/ and tests/test_provenance.py exist and tests/fixtures/mgctl/command-tree.json lists "provenance file" as experimental; '
                 f'{pe["tests"]} test functions counted in tests/test_provenance.py')
        mg = f'mgctl provenance file is {snap["provenance file"]}; mgctl provenance (host-wide, --all) is {snap["provenance"]} (tests/fixtures/mgctl/command-tree.json)'
    else:
        real = 'This is a DESIGN. The engine, its tests or the experimental command are not all present; the coverage column records design survey results only.'
        basis = 'one of intel/provenance/, tests/test_provenance.py or the experimental "provenance file" entry in the command snapshot is missing'
        mg = f'mgctl provenance file is {snap["provenance file"]}; mgctl provenance is {snap["provenance"]} (tests/fixtures/mgctl/command-tree.json)'
    still = [f'mgctl provenance (host-wide) is {snap["provenance"]} in the command snapshot'] + (['real Linux dpkg host test is PENDING (class RealLinuxDpkgPending in tests/test_provenance.py)'] if pe['dpkg_real_host_pending'] else []) + ['roadmap P2 missing: ' + roadmap_missing]
    return {**meta(generated_at, 'docs/intelligence/PROVENANCE-DESIGN.md (sections 1, 2, 4, 12), intel/provenance/collectors/*.py, tests/test_provenance.py, tests/fixtures/mgctl/command-tree.json, docs/intelligence/ROADMAP.md', real),
            'status': pe['status'], 'status_basis': basis, 'engine_collectors': pe['collectors'], 'engine_test_functions': pe['tests'], 'still_planned': still,
            'mgctl_command': mg, 'hard_rules': rules, 'six_facts': facts,
            'coverage': {'meaning': {'exercised-in-survey': 'the mechanism was run by hand on one Mac during the design survey (the design document); whether code exists is the separate `engine` field',
                                     'designed': 'specified in the design document, not exercised in the survey', 'not-possible': 'the act leaves no evidence',
                                     'recorded-only': 'recorded but supports no claim', 'other': 'see coverage_raw'},
                         'engine_meaning': {'experimental-real-mac-tested': 'a collector exists and tests ran it against a real Mac', 'experimental': 'a collector exists with tests', 'fixture-only': 'a collector exists, tested only on recorded fixtures (no real-host run)',
                                            'none': 'no collector code exists for this manager'},
                         'counts': counts, 'engine_counts': engine_counts, 'managers': managers}, 'limits': limits}


# ---------------------------------------------------------------- assembly
def build(generated_at):
    registry = reg.load()
    live = live_cards_data()
    cards = {cid: feed_card(cid, v, registry, generated_at) for cid, v in live.items()}
    cards['yara-legacy'] = legacy_card(registry, generated_at)
    files = {'channels.json': build_channels(registry, cards, generated_at), 'sources.json': build_sources(registry, cards, generated_at),
             'licenses.json': build_licenses(registry, generated_at), 'roadmap.json': build_roadmap(generated_at), 'provenance.json': build_provenance(generated_at),
             'vulns.json': build_vulns(registry, cards, generated_at)}
    for cid, c in cards.items():
        files[f'cards/{cid}.json'] = c
    desc = {'channels.json': 'status of every channel family (intel/status.py)', 'sources.json': 'source registry with clearance', 'licenses.json': 'licence verdicts (evidence, not legal advice)',
            'roadmap.json': 'roadmap rows and tracks', 'provenance.json': 'software provenance design, rules and coverage', 'vulns.json': 'vulnerability sources by region, real builds, merge counts and rules'}
    idx = {**meta(generated_at, 'the files listed here', 'An index of the static data files with their SHA-256. There is no server: these are plain files.'),
           'files': [{'path': p, 'sha256': hashlib.sha256(serialise(d).encode()).hexdigest(), 'description': desc.get(p, 'artifact card ' + p[6:-5])} for p, d in sorted(files.items())]}
    files['index.json'] = idx
    return files


def serialise(d):
    return json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False) + '\n'


def committed_generated_at():
    p = API / 'index.json'
    return jload(p)['generated_at'] if p.exists() else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--write', action='store_true'); ap.add_argument('--check', action='store_true'); ap.add_argument('--generated-at')
    a = ap.parse_args(argv)
    if a.check:
        files = build(a.generated_at or committed_generated_at() or '1970-01-01T00:00:00Z')
        bad = [p for p, d in sorted(files.items()) if not (API / p).exists() or (API / p).read_text(encoding='utf-8') != serialise(d)]
        extra = sorted(p.relative_to(API).as_posix() for p in API.rglob('*.json') if p.relative_to(API).as_posix() not in files) if API.exists() else []
        for p in bad:
            print('DIFFERS', p)
        for p in extra:
            print('EXTRA', p)
        print('gen_intel_web: committed data', 'differs' if bad or extra else 'matches the sources')
        return 1 if bad or extra else 0
    now = a.generated_at or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    files = build(now)
    for p, d in files.items():
        (API / p).parent.mkdir(parents=True, exist_ok=True)
        (API / p).write_text(serialise(d), encoding='utf-8')
    print(f'wrote {len(files)} files under {rel(API)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
