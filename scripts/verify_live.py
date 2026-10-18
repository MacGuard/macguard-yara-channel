#!/usr/bin/env python3
"""Check a PUBLISHED site the way a stranger would, over the network, and fail on anything that does not hold.

usage: verify_live.py BASE_URL --identity WORKFLOW_IDENTITY --repo OWNER/NAME [--external]

1. downloads the package, manifest, bundles, proof and checkpoint from BASE_URL and runs the full release verification
   (Sigstore signatures, every file hash, rules_root, checkpoint, inclusion proof) on those bytes;
2. downloads every individual rule file served by the site and compares it with the signed manifest;
3. requests every same-site link of the pages (site and documentation) and every release asset link (--external) and requires HTTP 200.
Nothing here trusts a local build: only the bytes the public URL returns are used."""
import argparse, concurrent.futures, hashlib, html.parser, io, json, pathlib, subprocess, sys, tarfile, tempfile, urllib.error, urllib.parse, urllib.request

PAGES = ['index.html', 'rules.html', 'releases.html', 'transparency.html', 'docs.html', 'docs/index.html', 'docs/es/overview.html', 'docs/en/overview.html', 'docs/es/verification.html', 'docs/en/verification.html']

def get(url, limit=200_000_000, attempts=4):
    """GET with a few retries for transient CDN errors (5xx, timeouts); a wrong answer is never retried into a pass: bytes are still compared by the caller."""
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'macguard-verify-live/1', 'Cache-Control': 'no-cache'})
            with urllib.request.urlopen(req, timeout=40) as r:
                data = r.read(limit + 1)
                if len(data) > limit: raise RuntimeError(f'{url} exceeds {limit} bytes')
                return r.status, data
        except urllib.error.HTTPError as e:
            if e.code < 500: raise
            last = e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e: last = e
        import time; time.sleep(1 + i)
    raise last

def status(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'macguard-verify-live/1'}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception: return 0

class Links(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.urls = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ('href', 'src'):
            if a.get(k): self.urls.append(a[k])

def same_site_links(page_html: str, page_url: str, base: str) -> list:
    p = Links(); p.feed(page_html); out = []
    for u in p.urls:
        if u.startswith(('#', 'mailto:', 'javascript:', 'data:')): continue
        full = urllib.parse.urljoin(page_url, u).split('#')[0]
        if full.startswith(base) and full not in out: out.append(full)
    return out

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('base'); ap.add_argument('--identity', required=True); ap.add_argument('--repo', required=True); ap.add_argument('--external', action='store_true')
    a = ap.parse_args(); base = a.base.rstrip('/') + '/'; problems = []
    def bad(msg): problems.append(msg); print('FAIL', msg)
    def ok(msg): print('PASS', msg)
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td) / 'release'; (d / 'logs').mkdir(parents=True)
        latest = json.loads(get(base + 'latest.json')[1])
        for name, dest in (('manifest.json', 'manifest.json'), ('manifest.sigstore.json', 'manifest.sigstore.json'), ('inclusion-proof.json', 'inclusion-proof.json'),
                           ('logs/checkpoint.txt', 'logs/checkpoint.txt'), ('logs/checkpoint.sigstore.json', 'logs/checkpoint.sigstore.json')):
            (d / dest).write_bytes(get(base + name)[1])
        pkg = get(base + latest['package'])[1]
        if hashlib.sha256(pkg).hexdigest() != latest['package_sha256'] or len(pkg) != latest['package_bytes']: bad('package bytes differ from latest.json')
        else: ok(f"package {len(pkg)} bytes, SHA-256 matches latest.json")
        if hashlib.sha256((d / 'manifest.json').read_bytes()).hexdigest() != latest['manifest_sha256']: bad('manifest differs from latest.json')
        with tarfile.open(fileobj=io.BytesIO(pkg), mode='r:gz') as t: t.extractall(d, filter='data')
        r = subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('verify_release.py')), str(d), '--identity', a.identity, '--repo', a.repo], capture_output=True, text=True)
        (ok if r.returncode == 0 else bad)(('full release verification on the downloaded bytes: ' + r.stdout.strip()) if r.returncode == 0 else ('release verification: ' + (r.stderr or r.stdout).strip()))
        manifest = json.loads((d / 'manifest.json').read_text())
        tar_manifest = None
        with tarfile.open(fileobj=io.BytesIO(pkg), mode='r:gz') as t: tar_manifest = t.extractfile('manifest.json').read()
        if tar_manifest != (d / 'manifest.json').read_bytes(): bad('the package manifest is not the manifest the site publishes')
        # every rule file the site serves must be byte-identical to the signed manifest
        def check(f):
            try:
                code, body = get(base + urllib.parse.quote(f['path']))
                return None if code == 200 and hashlib.sha256(body).hexdigest() == f['sha256'] and len(body) == f['bytes'] else f"{f['path']}: served bytes differ (HTTP {code})"
            except Exception as e: return f"{f['path']}: {e}"
        with concurrent.futures.ThreadPoolExecutor(16) as ex: errs = [e for e in ex.map(check, manifest['files']) if e]
        for e in errs[:10]: bad(e)
        if not errs: ok(f"all {len(manifest['files'])} rule files served by the site match the manifest")
        catalog = json.loads(get(base + 'catalog.json')[1])
        if sorted((f['path'], f['sha256']) for f in catalog['files']) != sorted((f['path'], f['sha256']) for f in manifest['files']): bad('catalog.json is not exactly the manifest file list')
        else: ok(f"catalog.json lists exactly the {catalog['count']} manifest files")
        # share preview: every page names an absolute og:image on THIS host, and that image is a real 1200x630 PNG
        import re, base64
        img = get(base + 'img/yara-rules.png')[1]
        if img[:8] == b'\x89PNG\r\n\x1a\n' and (int.from_bytes(img[16:20], 'big'), int.from_bytes(img[20:24], 'big')) == (1200, 630): ok('og image is a 1200x630 PNG')
        else: bad('img/yara-rules.png is not a 1200x630 PNG')
        for pg in PAGES:
            try: page = get(base + pg)[1].decode('utf-8', 'replace')
            except Exception as e: bad(f'{pg}: {e}'); continue
            m = re.search(r'property="og:image" content="([^"]+)"', page); t = re.search(r'name="twitter:card" content="([^"]+)"', page)
            if not m or m.group(1) != base + 'img/yara-rules.png' or not t or t.group(1) != 'summary_large_image': bad(f'{pg}: Open Graph / Twitter tags missing or pointing elsewhere ({m.group(1) if m else None})')
        ok('Open Graph and Twitter tags checked on ' + str(len(PAGES)) + ' pages')
        # documentation: the vendored Mermaid is served unchanged (SRI) and the verifier copy matches its published hash
        dpage = get(base + 'docs/en/verification.html')[1].decode('utf-8', 'replace'); sm = re.search(r'<script src="([^"]*mermaid[^"]*)" integrity="sha256-([^"]+)"', dpage)
        if not sm: bad('docs: the diagram script with its integrity attribute is missing')
        else:
            code, body = get(urllib.parse.urljoin(base + 'docs/en/verification.html', sm.group(1)))
            if code == 200 and base64.b64encode(hashlib.sha256(body).digest()).decode() == sm.group(2): ok('docs: Mermaid is served byte for byte as its integrity attribute says')
            else: bad('docs: Mermaid bytes differ from the integrity attribute')
        vsrc = get(base + 'verify_public_release.py')[1]; vsum = get(base + 'verify_public_release.py.sha256')[1].decode().split()[0]
        if hashlib.sha256(vsrc).hexdigest() == vsum and b'verify-blob' in vsrc: ok('verifier copy matches its published SHA-256')
        else: bad('verify_public_release.py differs from its .sha256')
        # links
        urls = []
        for p in PAGES:
            code, body = get(base + p); 
            if code != 200: bad(f'{p}: HTTP {code}'); continue
            urls += [u for u in same_site_links(body.decode('utf-8', 'replace'), base + p, base) if u not in urls]
        urls += [base + n for n in ('stats.json', 'releases.json', 'catalog.json', 'logs/log.jsonl', 'logs/LOG.md', 'rules-list.html') if base + n not in urls]
        with concurrent.futures.ThreadPoolExecutor(12) as ex: codes = list(ex.map(status, urls))
        dead = [(u, c) for u, c in zip(urls, codes) if c != 200]
        for u, c in dead[:15]: bad(f'link {u} -> {c}')
        if not dead: ok(f'{len(urls)} same-site links answer 200')
        if a.external:
            rel = json.loads(get(base + 'releases.json')[1])['releases']; ext = [u for r in rel for u in r['assets'].values()] + [r['url'] for r in rel]
            with concurrent.futures.ThreadPoolExecutor(8) as ex: codes = list(ex.map(status, ext))
            dead = [(u, c) for u, c in zip(ext, codes) if c != 200]
            for u, c in dead[:15]: bad(f'release link {u} -> {c}')
            if not dead: ok(f'{len(ext)} release links answer 200')
    if problems: sys.exit(f'{len(problems)} problem(s)')
    print('LIVE VERIFICATION PASSED')

if __name__ == '__main__': main()
