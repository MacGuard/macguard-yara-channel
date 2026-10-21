#!/usr/bin/env python3
"""Pipeline side of the private quarantine service. Authenticates with the workflow's GitHub OIDC token (no stored secret).

The service no longer has to be reachable for the pipeline to RUN, but publication is fail safe with respect to it (owner decision, spec section 15): when it cannot
be reached, `decisions` and `policy-check` fall back to the last verified policy snapshot, and without one nothing may be ADDED or MODIFIED, only removed (see
scripts/policy_snapshot.py). Commands that only report (submit, released, failed) still print 'unavailable' and exit 0. The exits that are NOT 0 on purpose:
`policy-check`, `urgent` and `urgent-assert`.

usage: quarantine_client.py submit    --decision dist/decision.json --dist dist --run-id ID [--run-url URL] [--dynamic dist/dynamic.json]
       quarantine_client.py decisions --out dist/decisions.json [--snapshot-dir policy-snapshot] [--logs logs]   (also writes rejected.json, policies.json next to it)
       quarantine_client.py released  --tag TAG --hashes-file approved.json   (publish workflow)
       quarantine_client.py failed    --hashes-file hashes.json --reason TEXT
       quarantine_client.py policy-check --candidate dist/candidate.json [--previous previous/manifest.json]   (publish workflow, before signing)
       quarantine_client.py urgent --policy-id ID --out urgent-policy.json   |   urgent-assert --policy urgent-policy.json --approved dist/approved.json"""
import argparse, base64, json, os, pathlib, re, sys, urllib.error, urllib.parse, urllib.request
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import policy_snapshot as ps

CHUNK = 40   # 40 items of at most 1 MB each stay under the service's 64 MB request cap

def base_url(): return (os.environ.get('QUARANTINE_URL') or '').rstrip('/')

def insecure(url):
    """The bearer token is only ever sent over HTTPS (plain HTTP only to the local test server)."""
    u = urllib.parse.urlsplit(url)
    return not (u.scheme == 'https' or (u.scheme == 'http' and u.hostname in ('127.0.0.1', 'localhost', '::1')))

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None   # a redirect would re-send the Authorization header to another host
OPENER = urllib.request.build_opener(_NoRedirect)

def oidc_token(audience):
    url, tok = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL'), os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    if not url or not tok: raise RuntimeError('this is not a GitHub Actions job with id-token: write')
    req = urllib.request.Request(url + ('&' if '?' in url else '?') + urllib.parse.urlencode({'audience': audience}), headers={'Authorization': f'bearer {tok}', 'Accept': 'application/json'})
    with OPENER.open(req, timeout=20) as r: return json.load(r)['value']

def call(method, path, body=None):
    """Returns (status, json). status 0 means the service could not be reached."""
    base = base_url()
    if not base: return 0, {'error': 'QUARANTINE_URL is not configured'}
    if insecure(base): return 0, {'error': 'QUARANTINE_URL must be https; the token is not sent'}
    try:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, method=method, headers={'Authorization': f'Bearer {oidc_token(os.environ.get("QUARANTINE_AUDIENCE") or base)}', 'Content-Type': 'application/json', 'User-Agent': 'macguard-pipeline'})
        with OPENER.open(req, timeout=60) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try: return e.code, json.load(e)
        except Exception: return e.code, {'error': str(e)}
    except Exception as e: return 0, {'error': f'service unreachable: {e}'}

def build_submissions(decision, dist, dynamic=None):
    per_file = (dynamic or {}).get('per_file', {})
    out = []
    for s in decision.get('submissions', []):
        root = pathlib.Path(dist).resolve(); p = (root / s['path']).resolve()
        if root != p and root not in p.parents: raise ValueError(f"submission path escapes the candidate folder: {s['path']!r}")
        item = {'sha256': s['sha256'], 'path': s['path'], 'source': s['source'], 'bytes': s['bytes'], 'reasons': s['reasons'], 'depends_on': s.get('depends_on', []), 'metrics': per_file.get(s['path'], {}), 'findings_schema': 1, 'findings': s.get('findings', [])}
        if (dynamic or {}).get('engine'): item['engine'] = str((dynamic or {})['engine'])[:80]
        if p.exists() and p.stat().st_size <= 1_000_000: item['content_b64'] = base64.b64encode(p.read_bytes()).decode()
        out.append(item)
    return out

def policy_view(snapshot_dir, logs_dir, verifier=None, now=None):
    """What this run knows about prohibitions and persistent rejections: (policies document, live view to keep as the next snapshot or None).
    An older Worker without the endpoint answers 404, which is 'unknown', never 'no policies'."""
    st, data = call('GET', '/api/pipeline/policy-snapshot')
    if verifier is None:
        repo = os.environ.get('GITHUB_REPOSITORY', '')
        def verifier(path, bundle):
            if not repo: return 'GITHUB_REPOSITORY is not set'
            try: return ps.cosign_verifier(repo)(path, bundle)
            except OSError as e: return f'cosign is not available: {e}'
    return ps.resolve(st, data, snapshot_dir, logs_dir, now, verifier)

def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('submit'); s.add_argument('--decision', default='dist/decision.json'); s.add_argument('--dist', default='dist'); s.add_argument('--run-id', default=os.environ.get('GITHUB_RUN_ID', '')); s.add_argument('--run-url', default=''); s.add_argument('--dynamic'); s.add_argument('--commit', action='append', default=[])
    d = sub.add_parser('decisions'); d.add_argument('--out', default='dist/decisions.json'); d.add_argument('--snapshot-dir', default='policy-snapshot'); d.add_argument('--logs', default='logs')
    pc = sub.add_parser('policy-check'); pc.add_argument('--candidate', default='dist/candidate.json'); pc.add_argument('--previous', default='previous/manifest.json'); pc.add_argument('--snapshot-dir', default='policy-snapshot'); pc.add_argument('--logs', default='logs')
    ug = sub.add_parser('urgent'); ug.add_argument('--policy-id', required=True); ug.add_argument('--out', default='urgent-policy.json'); ug.add_argument('--run-url', default='')
    ua = sub.add_parser('urgent-assert'); ua.add_argument('--policy', default='urgent-policy.json'); ua.add_argument('--approved', default='dist/approved.json')
    r = sub.add_parser('released'); r.add_argument('--tag', required=True); r.add_argument('--hashes-file', required=True); r.add_argument('--run-url', default='')
    f = sub.add_parser('failed'); f.add_argument('--hashes-file', required=True); f.add_argument('--reason', default='failed the technical checks'); f.add_argument('--run-url', default='')
    a = ap.parse_args()
    if a.cmd == 'submit':
        dec = json.loads(pathlib.Path(a.decision).read_text()); dyn = json.loads(pathlib.Path(a.dynamic).read_text()) if a.dynamic and pathlib.Path(a.dynamic).exists() else None
        items = build_submissions(dec, a.dist, dyn)
        if not items: print('nothing to quarantine'); return
        retested = []
        status_file = pathlib.Path(a.dist) / 'decisions.json.status'
        if status_file.exists():
            try: retested = [r['id'] for r in json.loads(status_file.read_text()).get('retest', [])]
            except Exception: retested = []
        results, st, data = [], 200, {}
        for i in range(0, len(items), CHUNK):   # one request per CHUNK candidates: the service caps body size and each item carries its content
            st, data = call('POST', '/api/pipeline/submit', {'run_id': a.run_id, 'run_url': a.run_url, 'candidates': items[i:i + CHUNK], 'retested': retested if i == 0 else []})
            if st != 200: break
            results += data['results']
        if st == 200: print(f"quarantine: {sum(1 for x in results if x['status'] == 'created')} new, {sum(1 for x in results if x['status'] != 'created')} already known")
        else: print(f"quarantine UNAVAILABLE (status {st}): {data.get('error')}. {len(items) - len(results)} of {len(items)} candidates were not recorded; they stay out of the release and will be seen again on the next run.")
    elif a.cmd == 'decisions':
        st, data = call('GET', '/api/pipeline/decisions')
        out = {'available': st == 200, 'decisions': data.get('decisions', {}) if st == 200 else {}, 'retest': data.get('retest', []) if st == 200 else []}
        if st != 200: print(f"quarantine decisions UNAVAILABLE (status {st}): {data.get('error')}; no approval is known (nothing quarantined is published)")
        pathlib.Path(a.out).write_text(json.dumps(out['decisions'])); pathlib.Path(a.out + '.status').write_text(json.dumps({k: out[k] for k in ('available', 'retest')}))
        doc, keep = policy_view(a.snapshot_dir, a.logs); folder = pathlib.Path(a.out).parent   # always written, so a missing file can only mean a broken step, never "no prohibitions"
        (folder / 'policies.json').write_text(json.dumps(doc, indent=1) + '\n'); (folder / 'rejected.json').write_text(json.dumps(doc['rejected']) + '\n')
        cand = folder / 'policy-snapshot.candidate.json'
        if keep is not None: cand.write_text(json.dumps(keep))
        elif cand.exists(): cand.unlink()
        print(f"policy view: mode={doc['mode']} ({doc['reason']}); {len(doc['policies'])} prohibitions, {len(doc['rejected'])} rejected hashes" + (f"; regressions: {doc['regressions']}" if doc['regressions'] else ''))
    elif a.cmd == 'policy-check':
        cand = json.loads(pathlib.Path(a.candidate).read_text())['files']; pm = pathlib.Path(a.previous)
        prev = json.loads(pm.read_text()).get('files', []) if pm.is_file() else []
        doc, _ = policy_view(a.snapshot_dir, a.logs); problems = ps.check_candidate(cand, doc, prev)
        print(f"policy-check: mode={doc['mode']} ({doc['reason']}); {len(cand)} files checked against {len(doc['policies'])} prohibitions and {len(doc['rejected'])} rejected hashes")
        if problems:
            for p in problems[:20]: print(f'  BLOCKED: {p}')
            sys.exit(1)   # the one deliberate exception to "always exits 0": nothing is signed on a candidate the policy forbids or cannot vouch for
    elif a.cmd == 'urgent':
        if not re.fullmatch(r'[0-9a-f-]{8,64}', a.policy_id): sys.exit('urgent_policy_id is not a policy id')
        st, res = call('POST', '/api/pipeline/urgent-run', {'policy_id': a.policy_id, 'run_url': a.run_url})
        if st != 200: sys.exit(f"urgent withdrawal refused (status {st}): {res.get('error')}")
        pathlib.Path(a.out).write_text(json.dumps(res['policy'])); print(f"urgent withdrawal accepted for policy {a.policy_id}")
    elif a.cmd == 'urgent-assert':
        pol = json.loads(pathlib.Path(a.policy).read_text()); approved = json.loads(pathlib.Path(a.approved).read_text())['files']
        still = [f['path'] for f in approved if ps.matches(pol, f)]
        if still: sys.exit(f"urgent withdrawal not effective: the prohibited scope is still in the approved set ({len(still)} file(s)); nothing will be requested")
        print('urgent withdrawal effective: the prohibited scope is absent from the approved set')
    else:
        data = json.loads(pathlib.Path(a.hashes_file).read_text()); hashes = [x['sha256'] if isinstance(x, dict) else x for x in (data['files'] if isinstance(data, dict) else data)]
        path, body = ('/api/pipeline/released', {'tag': a.tag, 'hashes': hashes, 'run_url': a.run_url}) if a.cmd == 'released' else ('/api/pipeline/revalidation-failed', {'hashes': hashes, 'reason': a.reason, 'run_url': a.run_url})
        st, res = call('POST', path, body); print(f"quarantine {a.cmd}: status {st} {json.dumps(res)[:200]}")

if __name__ == '__main__': main()
