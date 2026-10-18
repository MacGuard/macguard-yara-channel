#!/usr/bin/env python3
"""Pipeline side of the private quarantine service. Authenticates with the workflow's GitHub OIDC token (no stored secret).

The service is optional by design: when QUARANTINE_URL is unset or unreachable every command reports 'unavailable' and exits 0,
because publication must never depend on it. Without it nothing quarantined can be reviewed, and nothing unreviewed is published.

usage: quarantine_client.py submit    --decision dist/decision.json --dist dist --run-id ID [--run-url URL] [--dynamic dist/dynamic.json]
       quarantine_client.py decisions --out dist/decisions.json
       quarantine_client.py released  --tag TAG --hashes-file approved.json   (publish workflow)
       quarantine_client.py failed    --hashes-file hashes.json --reason TEXT"""
import argparse, base64, json, os, pathlib, sys, urllib.error, urllib.parse, urllib.request

CHUNK = 100

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
        item = {'sha256': s['sha256'], 'path': s['path'], 'source': s['source'], 'bytes': s['bytes'], 'reasons': s['reasons'], 'depends_on': s.get('depends_on', []), 'metrics': per_file.get(s['path'], {})}
        if p.exists() and p.stat().st_size <= 1_000_000: item['content_b64'] = base64.b64encode(p.read_bytes()).decode()
        out.append(item)
    return out

def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('submit'); s.add_argument('--decision', default='dist/decision.json'); s.add_argument('--dist', default='dist'); s.add_argument('--run-id', default=os.environ.get('GITHUB_RUN_ID', '')); s.add_argument('--run-url', default=''); s.add_argument('--dynamic'); s.add_argument('--commit', action='append', default=[])
    d = sub.add_parser('decisions'); d.add_argument('--out', default='dist/decisions.json')
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
        if st != 200: print(f"quarantine decisions UNAVAILABLE (status {st}): {data.get('error')}; the safe default applies (nothing quarantined is published)")
        pathlib.Path(a.out).write_text(json.dumps(out['decisions'])); pathlib.Path(a.out + '.status').write_text(json.dumps({k: out[k] for k in ('available', 'retest')}))
    else:
        data = json.loads(pathlib.Path(a.hashes_file).read_text()); hashes = [x['sha256'] if isinstance(x, dict) else x for x in (data['files'] if isinstance(data, dict) else data)]
        path, body = ('/api/pipeline/released', {'tag': a.tag, 'hashes': hashes, 'run_url': a.run_url}) if a.cmd == 'released' else ('/api/pipeline/revalidation-failed', {'hashes': hashes, 'reason': a.reason, 'run_url': a.run_url})
        st, res = call('POST', path, body); print(f"quarantine {a.cmd}: status {st} {json.dumps(res)[:200]}")

if __name__ == '__main__': main()
