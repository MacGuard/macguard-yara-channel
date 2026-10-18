#!/usr/bin/env python3
"""Independent verifier for a MacGuard YARA release. Standard library only; needs `cosign` for the Sigstore checks.

  python3 verify_public_release.py --latest
  python3 verify_public_release.py --tag rules-20261018-39150886414
  python3 verify_public_release.py --directory ./release-files
  python3 verify_public_release.py --latest --json

It resolves the release ONCE and downloads every artifact from that exact tag (if `latest` moves while you verify, you still verify
the release you started with), then checks, in this order and without trusting any command's text output (only return codes and
parsed data):

  artifacts      the six mandatory artifacts exist, have the size GitHub reports and parse
  manifest sig   cosign verify-blob of manifest.json with the expected workflow identity and OIDC issuer
  checkpoint sig the same for the log checkpoint
  package        the archive is read with limits (no links, no traversal, bounded size and count) and its manifest.json is the signed one
  files          every file's SHA-256 equals the signed manifest; no missing, extra or duplicated file
  rules_root     recomputed Merkle root over the files equals the signed one
  counts         files / expanded bytes / individual YARA rules equal what the signed manifest declares
  checkpoint     size and root equal the log head inside the signed manifest
  inclusion      the Merkle proof carries the release's log entry to the checkpoint root, and the entry names this rules_root
  consistency    (optional) this checkpoint extends the previous one you trust: --previous-checkpoint FILE or --trust-state FILE

Exit codes   0 all mandatory checks done and passed   1 integrity   2 signature or identity   3 Merkle / inclusion / consistency
             4 download incomplete or network error   5 missing dependency (cosign)   6 invalid format or incomplete set
Several failures: the report lists them all; the exit code is the first by precedence 5, 4, 6, 2, 1, 3.

Trust: this script is code you run. Read it (about 500 lines) or compare it with the signed copy attached to a release
(docs: Verification page). Downloading it from the same site that hosts the rules is not an independent root of trust."""
import argparse, base64, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tarfile, tempfile, time, urllib.error, urllib.parse, urllib.request

VERSION = '1.0.0'
SCHEMA = 1
DEFAULT_REPO = 'MacGuard/macguard-yara-channel'
DEFAULT_IDENTITY = 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main'
DEFAULT_ISSUER = 'https://token.actions.githubusercontent.com'
ORIGIN = 'macguard-rules-log v1'
REQUIRED = ['rules-release.tar.gz', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json', 'checkpoint.txt', 'checkpoint.sigstore.json']
OPTIONAL = ['consistency.json', 'release.json', 'changes.json', 'CHANGELOG.md']
LIMITS = {'members': 20000, 'total_bytes': 512 * 1024 * 1024, 'file_bytes': 25 * 1024 * 1024, 'depth': 24, 'name_bytes': 512, 'manifest_bytes': 10 * 1024 * 1024}
RULE_RE = re.compile(r'^\s*(?:(?:global|private)\s+)*rule\s+\w+', re.M)
PRECEDENCE = [5, 4, 6, 2, 1, 3]          # which failure decides the exit code when several happen

class Fail(Exception):
    def __init__(self, code, message): super().__init__(message); self.code, self.message = code, message

# ---- Merkle (RFC 6962 hashing, RFC 9162 proofs) ------------------------------------------------------------
def leaf_hash(data: bytes) -> bytes: return hashlib.sha256(b'\x00' + data).digest()
def node_hash(l: bytes, r: bytes) -> bytes: return hashlib.sha256(b'\x01' + l + r).digest()
def mth(leaves):
    n = len(leaves)
    if n == 0: return hashlib.sha256(b'').digest()
    if n == 1: return leaves[0]
    k = 1
    while k * 2 < n: k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))
def rules_root(files) -> str:
    """Leaves are `path NUL sha256-hex` encoded as UTF-8, ordered by path (UTF-8 byte order), hashed as leaves, combined with mth()."""
    ordered = sorted(files, key=lambda f: f['path'].encode('utf-8'))
    return mth([leaf_hash(f"{f['path']}\0{f['sha256']}".encode('utf-8')) for f in ordered]).hex()
def verify_inclusion(index, size, leaf, proof, root) -> bool:
    if not 0 <= index < size: return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else: r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root
def verify_consistency(first, second, first_root, second_root, proof) -> bool:
    if first > second or first < 0: return False
    if first == second: return not proof and first_root == second_root
    if first == 0: return not proof
    proof = list(proof)
    if first & (first - 1) == 0: proof.insert(0, first_root)
    if not proof: return False
    fn, sn = first - 1, second - 1
    while fn & 1: fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else: sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root

def parse_checkpoint(text: str):
    lines = text.split('\n')
    if len(lines) != 4 or lines[3] != '' or lines[0] != ORIGIN: raise Fail(6, f'checkpoint is not in the "{ORIGIN}" format')
    try: size, root = int(lines[1]), base64.b64decode(lines[2], validate=True)
    except Exception: raise Fail(6, 'checkpoint size or root is malformed')
    if size < 0 or len(root) != 32: raise Fail(6, 'checkpoint root is not a 32-byte hash')
    return size, root

# ---- network ------------------------------------------------------------------------------------------------
class RateLimited(Fail):
    """GitHub answered 403/429 because the request quota is used up (not because anything is forbidden)."""

def _rate_limit_info(e):
    h = e.headers or {}
    remaining, reset, retry = h.get('X-RateLimit-Remaining'), h.get('X-RateLimit-Reset'), h.get('Retry-After')
    limited = e.code == 429 or remaining == '0' or retry is not None
    when = ''
    if reset and reset.isdigit(): when = ' resets at ' + time.strftime('%H:%M:%S UTC', time.gmtime(int(reset)))
    elif retry and retry.isdigit(): when = f' retry in {retry} s'
    return limited, when

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

class Net:
    def __init__(self, api_url, token=None, timeout=40, retries=3):
        self.api, self.timeout, self.retries = api_url.rstrip('/'), timeout, retries
        self.headers = {'User-Agent': f'macguard-verify/{VERSION}', 'Accept': 'application/vnd.github+json', **({'Authorization': f'Bearer {token}'} if token else {})}
    def _open(self, url, headers=None):
        last = None
        for i in range(self.retries):
            try: return urllib.request.urlopen(urllib.request.Request(url, headers={**self.headers, **(headers or {})}), timeout=self.timeout)
            except urllib.error.HTTPError as e:
                limited, when = _rate_limit_info(e)
                if e.code in (403, 429) and limited:
                    raise RateLimited(4, f'{url}: GitHub rate limit reached (HTTP {e.code}; anonymous requests are limited per IP address);{when}. Pass --token or set GITHUB_TOKEN to raise the limit')
                if e.code == 403: raise Fail(4, f'{url}: HTTP 403 forbidden, and it is not rate limiting (no quota exhausted): a proxy, firewall or access rule is refusing the request')
                if e.code == 404: raise Fail(4, f'{url}: HTTP 404 not found (check the tag and the repository name; the release must be public)')
                if e.code < 500: raise Fail(4, f'{url}: HTTP {e.code}')
                last = e
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e: last = e
            time.sleep(1 + i)
        raise Fail(4, f'{url}: {last}')
    def final_location(self, url):
        """Where a github.com URL redirects to (no API request, so no API quota is used)."""
        op = urllib.request.build_opener(_NoRedirect)
        try: op.open(urllib.request.Request(url, headers={'User-Agent': self.headers['User-Agent']}), timeout=self.timeout)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get('Location'): return urllib.parse.urljoin(url, e.headers['Location'])
            raise Fail(4, f'{url}: HTTP {e.code}')
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e: raise Fail(4, f'{url}: {e}')
        raise Fail(4, f'{url}: expected a redirect to the latest release')
    def json(self, url):
        with self._open(url) as r: return json.load(r)
    def download(self, url, dest: pathlib.Path, expected_size=None):
        got = 0
        with self._open(url, {'Accept': 'application/octet-stream'}) as r, open(dest, 'wb') as out:
            declared = r.headers.get('Content-Length')
            while True:
                chunk = r.read(1 << 20)
                if not chunk: break
                got += len(chunk); out.write(chunk)
                if got > LIMITS['total_bytes']: raise Fail(4, f'{url}: larger than the {LIMITS["total_bytes"]} byte limit')
        for want, what in ((expected_size, 'size GitHub reports'), (int(declared) if declared is not None else None, 'Content-Length')):
            if want is not None and want != got: raise Fail(4, f'{dest.name}: incomplete download ({got} bytes, {what} {want})')
        return got

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''): h.update(chunk)
    return h.hexdigest()

# ---- cosign -----------------------------------------------------------------------------------------------
def find_cosign(explicit):
    c = explicit or shutil.which('cosign')
    if not c or not os.access(c, os.X_OK): raise Fail(5, 'cosign was not found. Install it (https://docs.sigstore.dev/cosign/system_config/installation/) or pass --cosign PATH. Without it no Sigstore check can be made.')
    return c
def cosign_verify(cosign, blob: pathlib.Path, bundle: pathlib.Path, identity, issuer, repo):
    cmd = [cosign, 'verify-blob', str(blob), '--bundle', str(bundle), '--certificate-identity', identity, '--certificate-oidc-issuer', issuer]
    if repo: cmd += ['--certificate-github-workflow-repository', repo]
    try: r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    except FileNotFoundError: raise Fail(5, 'cosign could not be started')
    except subprocess.TimeoutExpired: raise Fail(4, 'cosign timed out (it may need the network to fetch the Sigstore trust root)')
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()
        raise Fail(2, (msg[-1] if msg else 'cosign verification failed')[:300])
    return ' '.join(cmd[:2]) + ' ok'

# ---- safe extraction --------------------------------------------------------------------------------------
def safe_extract(archive: pathlib.Path, dest: pathlib.Path):
    """Reads the tar.gz member by member. Only regular files and directories under `rules/` plus `manifest.json`; no links, devices,
    absolute paths, `..`, odd names, duplicates; bounded count, depth, size per file and in total. Sizes are counted while reading, not trusted."""
    files, total, seen = {}, 0, set()
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, 'r:gz') as t:
            for n, m in enumerate(t, 1):
                if n > LIMITS['members']: raise Fail(6, f'more than {LIMITS["members"]} archive members')
                name = m.name
                if name.startswith('./'): name = name[2:]
                parts = [p for p in name.split('/') if p not in ('', '.')]
                if m.name.startswith('/') or '..' in parts or '\\' in name or '\0' in name: raise Fail(6, f'unsafe path in the archive: {name[:80]!r}')
                if len(name.encode()) > LIMITS['name_bytes'] or len(parts) > LIMITS['depth']: raise Fail(6, f'path too long or too deep: {name[:80]!r}')
                if m.issym() or m.islnk(): raise Fail(6, f'the archive contains a link ({name[:80]!r}); releases never do')
                if m.isdir():
                    if parts and parts[0] != 'rules': raise Fail(6, f'unexpected directory {name!r}')
                    continue
                if not m.isreg(): raise Fail(6, f'the archive contains a non-regular member ({name[:80]!r})')
                if not (name == 'manifest.json' or (parts and parts[0] == 'rules')): raise Fail(6, f'unexpected top-level entry {name!r}')
                if name in seen: raise Fail(6, f'duplicate archive entry {name!r}')
                seen.add(name)
                if m.size > LIMITS['file_bytes']: raise Fail(6, f'{name!r} is larger than {LIMITS["file_bytes"]} bytes')
                target = dest.joinpath(*parts); target.parent.mkdir(parents=True, exist_ok=True)
                src = t.extractfile(m)
                if src is None: raise Fail(6, f'cannot read archive member {name[:80]!r}')
                h, size = hashlib.sha256(), 0
                with open(target, 'xb') as out:
                    for chunk in iter(lambda: src.read(1 << 16), b''):
                        size += len(chunk); total += len(chunk)
                        if size > LIMITS['file_bytes'] or total > LIMITS['total_bytes']: raise Fail(6, 'the archive expands beyond the allowed size')
                        h.update(chunk); out.write(chunk)
                files[name] = {'sha256': h.hexdigest(), 'bytes': size}
    except (tarfile.TarError, EOFError, OSError) as e:
        raise Fail(6, f'the package is not a readable tar.gz ({e})')
    return files, total

# ---- the checks --------------------------------------------------------------------------------------------
class Report:
    def __init__(self): self.checks, self.summary = [], {}
    def add(self, cid, status, detail, category=None, mandatory=True): self.checks.append({'id': cid, 'status': status, 'mandatory': mandatory, 'category': category, 'detail': detail})

def run_check(rep, cid, fn, category, mandatory=True):
    try: detail = fn(); rep.add(cid, 'pass', detail or '', category, mandatory); return True
    except Fail as f: rep.add(cid, 'fail', f.message, f.code, mandatory); return False
    except Exception as e:   # a verifier that crashes must still fail loudly and explain itself, never end silently
        rep.add(cid, 'fail', f'unexpected error while checking: {type(e).__name__}: {str(e)[:200]}', 6, mandatory); return False

def load_json(path: pathlib.Path, limit=LIMITS['manifest_bytes']):
    if path.stat().st_size > limit: raise Fail(6, f'{path.name} is larger than {limit} bytes')
    try: return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e: raise Fail(6, f'{path.name} is not valid JSON ({e})')

def resolve_and_download(a, net, work: pathlib.Path, rep):
    """Returns (release info dict, directory with the artifacts)."""
    if a.directory:
        d = pathlib.Path(a.directory)
        if not d.is_dir(): raise Fail(4, f'{d} is not a directory')
        return {'tag': a.tag or d.name, 'resolved_from': 'directory', 'url': None, 'published_at': None, 'latest_moved': False}, d
    d = work / 'release'; d.mkdir()
    try: return resolve_via_api(a, net, d)
    except RateLimited as rl:
        # Anonymous API quota used up. Public releases do not need the API: github.com resolves `latest` with a redirect and serves the assets.
        for x in d.iterdir(): x.unlink()
        info, d = resolve_via_web(a, net, d)
        info['note'] = (info.get('note') + '; ' if info.get('note') else '') + f'GitHub API rate limit reached, so the release was resolved through github.com instead (no API sizes/digests; Content-Length is checked): {rl.message[:160]}'
        return info, d

def resolve_via_web(a, net, d: pathlib.Path):
    web = a.web_url.rstrip('/')
    if a.latest:
        loc = net.final_location(f'{web}/{a.repo}/releases/latest'); m = re.search(r'/releases/tag/([^/?#]+)$', loc)
        if not m: raise Fail(4, f'{web}/{a.repo}/releases/latest did not redirect to a release tag ({loc[:120]})')
        tag = urllib.parse.unquote(m.group(1))
    else: tag = a.tag
    dl = f'{web}/{a.repo}/releases/download/{urllib.parse.quote(tag)}/'
    note = None
    for name in REQUIRED:
        try: net.download(dl + name, d / name)
        except Fail as f:
            if name not in ('checkpoint.txt', 'checkpoint.sigstore.json') or not (d / 'manifest.json').exists(): raise Fail(f.code, f'{f.message} (mandatory artifact {name})')
            size = load_json(d / 'manifest.json')['log']['size']; raw = a.raw_url.rstrip('/') + f'/{a.repo}/main/logs/checkpoints/{size:08d}'
            net.download(raw + ('.txt' if name.endswith('.txt') else '.sigstore.json'), d / name); note = f'checkpoint taken from the repository (logs/checkpoints/{size:08d}.*): this release predates attaching it'
    for name in OPTIONAL:
        try: net.download(dl + name, d / name)
        except Fail:
            (d / name).unlink(missing_ok=True)
    moved = False
    try:
        if a.latest:
            loc = net.final_location(f'{web}/{a.repo}/releases/latest'); mm = re.search(r'/releases/tag/([^/?#]+)$', loc); moved = bool(mm) and urllib.parse.unquote(mm.group(1)) != tag
    except Fail: pass
    return {'tag': tag, 'resolved_from': ('latest' if a.latest else 'tag') + ' via github.com', 'url': f'{web}/{a.repo}/releases/tag/{urllib.parse.quote(tag)}', 'published_at': None, 'latest_moved': moved, 'note': note}, d

def resolve_via_api(a, net, d: pathlib.Path):
    base = f'{net.api}/repos/{a.repo}'
    first = net.json(f'{base}/releases/latest') if a.latest else net.json(f'{base}/releases/tags/{a.tag}')
    tag = first['tag_name']
    if first.get('draft'): raise Fail(6, f'{tag} is a draft, not a published release')
    pinned = net.json(f'{base}/releases/tags/{tag}')                           # everything below comes from this exact tag
    assets = {x['name']: x for x in pinned.get('assets', [])}
    missing = [n for n in REQUIRED if n not in assets]
    fallback_note = None
    if missing and set(missing) <= {'checkpoint.txt', 'checkpoint.sigstore.json'} and 'manifest.json' in assets:
        # releases made before checkpoints were attached: the signed checkpoint of that log size lives in the repository
        net.download(assets['manifest.json']['browser_download_url'], d / 'manifest.json', assets['manifest.json'].get('size'))
        size = load_json(d / 'manifest.json')['log']['size']
        raw = a.raw_url.rstrip('/') + f'/{a.repo}/main/logs/checkpoints/{size:08d}'
        net.download(raw + '.txt', d / 'checkpoint.txt'); net.download(raw + '.sigstore.json', d / 'checkpoint.sigstore.json')
        fallback_note = f'checkpoint taken from the repository (logs/checkpoints/{size:08d}.*): this release predates attaching it'
        missing = [n for n in missing if n not in ('checkpoint.txt', 'checkpoint.sigstore.json')]
    if missing: raise Fail(6, 'incomplete release: missing ' + ', '.join(missing))
    for name in REQUIRED + [n for n in OPTIONAL if n in assets]:
        if (d / name).exists(): continue
        x = assets[name]; net.download(x['browser_download_url'], d / name, x.get('size'))
        digest = (x.get('digest') or '')
        if digest.startswith('sha256:') and digest[7:] != sha256_file(d / name): raise Fail(4, f'{name}: SHA-256 differs from the digest GitHub recorded for the asset')
    moved = False
    try:
        if a.latest: moved = net.json(f'{base}/releases/latest')['tag_name'] != tag
    except Fail: pass
    info = {'tag': tag, 'resolved_from': 'latest' if a.latest else 'tag', 'url': pinned.get('html_url'), 'published_at': pinned.get('published_at'), 'latest_moved': moved, 'note': fallback_note}
    return info, d

def verify(a):
    rep = Report(); net = Net(a.api_url, a.token or os.environ.get('GITHUB_TOKEN')); tmp = pathlib.Path(tempfile.mkdtemp(prefix='macguard-verify-'))
    keep = pathlib.Path(a.output_dir) if a.output_dir else None
    release, d = {}, None
    try:
        try: cosign = find_cosign(a.cosign); rep.add('dependency.cosign', 'pass', cosign, None)
        except Fail as f: rep.add('dependency.cosign', 'fail', f.message, f.code); return finish(rep, release, a)
        try: release, d = resolve_and_download(a, net, tmp, rep); rep.add('release.resolve', 'pass', f"{release['tag']} (from {release['resolved_from']})" + ('; `latest` moved while verifying, the pinned tag was verified' if release.get('latest_moved') else ''), None)
        except Fail as f: rep.add('release.resolve', 'fail', f.message, f.code); return finish(rep, release, a)
        if keep:
            keep.mkdir(parents=True, exist_ok=True)
            for n in REQUIRED + OPTIONAL:
                if (d / n).exists(): shutil.copy2(d / n, keep / n)
        ctx = {}
        def artifacts():
            miss = [n for n in REQUIRED if not (d / n).is_file()]
            if miss: raise Fail(6, 'missing: ' + ', '.join(miss))
            ctx['manifest'] = load_json(d / 'manifest.json'); ctx['proof'] = load_json(d / 'inclusion-proof.json'); load_json(d / 'manifest.sigstore.json'); load_json(d / 'checkpoint.sigstore.json')
            m = ctx['manifest']
            if not isinstance(m.get('files'), list) or not m['files'] or not m.get('rules_root') or not isinstance(m.get('log'), dict): raise Fail(6, 'manifest.json lacks files, rules_root or log')
            for f in m['files']:
                if not (isinstance(f.get('path'), str) and re.fullmatch(r'[0-9a-f]{64}', str(f.get('sha256', ''))) and isinstance(f.get('bytes'), int)): raise Fail(6, f"malformed manifest entry: {str(f)[:80]}")
            ctx['size'], ctx['root'] = parse_checkpoint((d / 'checkpoint.txt').read_text(encoding='utf-8'))
            return f"{len(m['files'])} files declared; " + ', '.join(n for n in OPTIONAL if (d / n).exists()) + ' present'
        ok = run_check(rep, 'artifacts', artifacts, 6)
        if not ok: return finish(rep, release, a)
        m = ctx['manifest']
        run_check(rep, 'signature.manifest', lambda: cosign_verify(cosign, d / 'manifest.json', d / 'manifest.sigstore.json', a.identity, a.issuer, a.workflow_repo), 2)
        run_check(rep, 'signature.checkpoint', lambda: cosign_verify(cosign, d / 'checkpoint.txt', d / 'checkpoint.sigstore.json', a.identity, a.issuer, a.workflow_repo), 2)
        # package
        out = tmp / 'extracted'
        def package():
            files, total = safe_extract(d / 'rules-release.tar.gz', out); ctx['files'] = files; ctx['expanded'] = total
            tar_manifest = (out / 'manifest.json').read_bytes() if (out / 'manifest.json').exists() else None
            if tar_manifest is None: raise Fail(6, 'the package has no manifest.json')
            if tar_manifest != (d / 'manifest.json').read_bytes(): raise Fail(1, 'the manifest inside the package is not the signed manifest.json')
            return f'{len(files) - 1} rule files, {total} bytes expanded, no links, no traversal'
        pkg_ok = run_check(rep, 'package.extract', package, None)
        if not pkg_ok:
            rep.checks[-1]['category'] = rep.checks[-1].get('category') if isinstance(rep.checks[-1].get('category'), int) else 6
        def hashes():
            declared = {}
            for f in m['files']:
                if f['path'] in declared: raise Fail(1, f"duplicate manifest entry {f['path']}")
                declared[f['path']] = f
            present = {k: v for k, v in ctx['files'].items() if k != 'manifest.json'}
            missing = sorted(set(declared) - set(present)); extra = sorted(set(present) - set(declared))
            if missing: raise Fail(1, f'{len(missing)} file(s) in the manifest are missing from the package, e.g. {missing[0]}')
            if extra: raise Fail(1, f'{len(extra)} file(s) in the package are not in the manifest, e.g. {extra[0]}')
            for p, f in declared.items():
                if present[p]['sha256'] != f['sha256']: raise Fail(1, f'{p}: SHA-256 {present[p]["sha256"][:16]}… does not match the manifest {f["sha256"][:16]}…')
                if present[p]['bytes'] != f['bytes']: raise Fail(1, f'{p}: size {present[p]["bytes"]} does not match the manifest {f["bytes"]}')
            return f'{len(declared)} files match the signed manifest byte for byte'
        if pkg_ok: run_check(rep, 'files.sha256', hashes, 1)
        def root():
            calc = rules_root(m['files'])
            if calc != m['rules_root']: raise Fail(3, f'recomputed rules_root {calc[:16]}… differs from the signed {m["rules_root"][:16]}…')
            return calc
        run_check(rep, 'merkle.rules_root', root, 3)
        def counts():
            st = m.get('stats')
            files = m['files']; expanded = sum(f['bytes'] for f in files)
            if st is None: return 'the manifest declares no stats (older release): counted from the files only'
            if st.get('files') != len(files): raise Fail(1, f"stats.files {st.get('files')} != {len(files)} files listed")
            if st.get('expanded_bytes') != expanded: raise Fail(1, f"stats.expanded_bytes {st.get('expanded_bytes')} != {expanded}")
            if pkg_ok:
                n = sum(len(RULE_RE.findall((out / f['path']).read_text(errors='replace'))) for f in files if (out / f['path']).exists())
                if any(not (out / f['path']).exists() for f in files): raise Fail(1, 'cannot recount the YARA rules: some files of the manifest are missing from the package')
                if st.get('yara_rules') != n: raise Fail(1, f"stats.yara_rules {st.get('yara_rules')} != {n} rule declarations counted")
                ctx['yara_rules'] = n
            return f"{len(files)} files, {expanded} bytes, {st.get('yara_rules')} individual YARA rules"
        run_check(rep, 'counts', counts, 1)
        def checkpoint():
            lg = m['log']
            if lg.get('origin') != ORIGIN or lg.get('size') != ctx['size'] or lg.get('root') != ctx['root'].hex(): raise Fail(3, 'the log head in the signed manifest differs from the signed checkpoint')
            return f"log size {ctx['size']}, root {ctx['root'].hex()[:16]}…"
        run_check(rep, 'checkpoint.matches_manifest', checkpoint, 3)
        def inclusion():
            p = ctx['proof']
            try: index, size, proof, entry = int(p['index']), int(p['size']), [bytes.fromhex(h) for h in p['proof']], p['entry']; proot = bytes.fromhex(p['root'])
            except Exception: raise Fail(6, 'inclusion-proof.json is malformed')
            if size != ctx['size'] or proot != ctx['root']: raise Fail(3, 'the inclusion proof is for a different checkpoint')
            if not verify_inclusion(index, size, leaf_hash(entry.encode('utf-8')), proof, ctx['root']): raise Fail(3, 'the inclusion proof does not lead to the checkpoint root')
            try: e = json.loads(entry)
            except Exception: raise Fail(6, 'the logged entry is not JSON')
            if e.get('event') != 'candidate.accepted' or (e.get('details') or {}).get('rules_root') != m['rules_root']: raise Fail(3, 'the logged entry does not name this release\'s rules_root')
            return f'entry {index} of {size} is in the checkpoint and names rules_root {m["rules_root"][:16]}…'
        run_check(rep, 'merkle.inclusion', inclusion, 3)
        # consistency / rollback
        prev = None
        if a.previous_checkpoint:
            try: prev = parse_checkpoint(pathlib.Path(a.previous_checkpoint).read_text(encoding='utf-8'))
            except Fail as f: rep.add('consistency', 'fail', 'previous checkpoint: ' + f.message, 6); prev = None
            except OSError as e: rep.add('consistency', 'fail', f'cannot read the previous checkpoint: {e}', 6)
        elif a.trust_state and pathlib.Path(a.trust_state).exists():
            try: ts = json.loads(pathlib.Path(a.trust_state).read_text()); prev = (int(ts['size']), bytes.fromhex(ts['root']))
            except Exception as e: rep.add('consistency', 'fail', f'the trust state file is damaged: {e}', 6)
        def consistency():
            size, root_ = ctx['size'], ctx['root']; psize, proot = prev
            if size < psize: raise Fail(3, f'ROLLBACK: this checkpoint has {size} entries, the one you trust has {psize}')
            if size == psize:
                if root_ != proot: raise Fail(3, f'FORK: a different root at the same size {size}')
                return f'same checkpoint as the trusted one ({size} entries)'
            c = d / 'consistency.json'
            if not c.exists(): raise Fail(3, f'the log grew from {psize} to {size} entries but the release has no consistency.json to prove it extends the trusted one')
            doc = load_json(c)
            try: f_size, s_size, f_root, s_root, proof = int(doc['first_size']), int(doc['second_size']), bytes.fromhex(doc['first_root']), bytes.fromhex(doc['second_root']), [bytes.fromhex(x) for x in doc['proof']]
            except Exception: raise Fail(6, 'consistency.json is malformed')
            if (f_size, f_root) != (psize, proot): raise Fail(3, f'consistency.json starts from size {f_size}, not from the trusted checkpoint ({psize}); a chain of proofs from an older release is needed')
            if (s_size, s_root) != (size, root_): raise Fail(3, 'consistency.json ends at a different checkpoint than this release')
            if not verify_consistency(f_size, s_size, f_root, s_root, proof): raise Fail(3, 'the consistency proof does not verify')
            return f'the trusted checkpoint ({psize}) is a prefix of this one ({size}): consistency proof verifies'
        if prev: run_check(rep, 'consistency', consistency, 3)
        elif not any(c['id'] == 'consistency' for c in rep.checks):
            rep.add('consistency', 'not_requested', 'no previous checkpoint was given (--previous-checkpoint or --trust-state): this is a first verification, so rollback protection is NOT established by this run', None, mandatory=False)
        rep.summary = {'files': len(m['files']), 'yara_rules': ctx.get('yara_rules', (m.get('stats') or {}).get('yara_rules')), 'expanded_bytes': sum(f['bytes'] for f in m['files']),
                       'package_bytes': (d / 'rules-release.tar.gz').stat().st_size, 'package_sha256': sha256_file(d / 'rules-release.tar.gz'), 'manifest_sha256': sha256_file(d / 'manifest.json'),
                       'rules_root': m['rules_root'], 'log_size': ctx['size'], 'log_root': ctx['root'].hex(), 'checkpoint': (d / 'checkpoint.txt').read_text().strip().replace('\n', ' | ')}
        # optional, unsigned cross-checks
        rj = d / 'release.json'
        if rj.exists():
            try:
                r = json.loads(rj.read_text())
                bad = [k for k, v in (('package_sha256', rep.summary['package_sha256']), ('rules_root', m['rules_root']), ('files', len(m['files']))) if r.get(k) != v]
                rep.add('metadata.release_json', 'fail' if bad else 'pass', ('release.json (unsigned) disagrees on: ' + ', '.join(bad)) if bad else 'release.json (unsigned convenience metadata) agrees with the verified values', 6 if bad else None, mandatory=False)
            except Exception as e: rep.add('metadata.release_json', 'fail', f'release.json unreadable: {e}', 6, mandatory=False)
        # trust state update only after a fully passing verification
        if a.trust_state and all(c['status'] != 'fail' for c in rep.checks if c['mandatory']):
            pathlib.Path(a.trust_state).write_text(json.dumps({'size': ctx['size'], 'root': ctx['root'].hex(), 'rules_root': m['rules_root'], 'tag': release.get('tag'), 'verified_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, indent=1) + '\n')
            rep.add('trust_state', 'pass', f'{a.trust_state} now holds the checkpoint of {ctx["size"]} entries', None, mandatory=False)
        return finish(rep, release, a)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def finish(rep, release, a):
    failed = [c for c in rep.checks if c['status'] == 'fail' and c['mandatory']]
    mandatory_missing = [c for c in rep.checks if c['mandatory'] and c['status'] not in ('pass', 'fail')]
    codes = {c['category'] for c in failed if isinstance(c['category'], int)}
    code = next((p for p in PRECEDENCE if p in codes), 0)
    if not code and (failed or mandatory_missing): code = 6
    if not code and not any(c['id'] == 'merkle.inclusion' for c in rep.checks): code = 6           # a run that never reached the mandatory checks is not a pass
    return {'schemaVersion': SCHEMA, 'tool': 'verify_public_release.py', 'version': VERSION, 'result': 'PASS' if code == 0 else 'FAIL', 'exit_code': code, 'release': release,
            'expected': {'identity': a.identity, 'issuer': a.issuer, 'repository': a.workflow_repo}, 'summary': rep.summary, 'checks': rep.checks,
            'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}

def render(r) -> str:
    s, rel = r['summary'], r['release']
    lines = [f"MacGuard release verification — {r['result']} (exit {r['exit_code']})", '']
    if rel: lines.append(f"Release        {rel.get('tag')}  ({rel.get('resolved_from')})" + (f"  {rel.get('url')}" if rel.get('url') else '') + (f"\n               note: {rel['note']}" if rel.get('note') else ''))
    if s:
        lines += [f"Files          {s['files']}   individual YARA rules: {s['yara_rules']}   expanded {s['expanded_bytes']} bytes   package {s['package_bytes']} bytes",
                  f"Package SHA256 {s['package_sha256']}", f"Manifest SHA256 {s['manifest_sha256']}", f"rules_root     {s['rules_root']}", f"Checkpoint     {s['checkpoint']}"]
    lines.append(f"Identity       {r['expected']['identity']}\nIssuer         {r['expected']['issuer']}\n")
    mark = {'pass': 'PASS', 'fail': 'FAIL', 'not_requested': 'n/a '}
    for c in r['checks']: lines.append(f"  [{mark.get(c['status'], c['status'])}] {c['id']}: {c['detail']}")
    lines += ['', 'A valid signature and matching hashes prove WHO published exactly THESE bytes. They do not prove the rules are good or that scanned files are safe.']
    return '\n'.join(lines)

def main(argv=None):
    ap = argparse.ArgumentParser(description='Verify a MacGuard YARA release independently.', epilog=(__doc__ or '').split('Exit codes')[-1].split('Trust:')[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--latest', action='store_true', help='the newest published release (resolved once, then pinned)'); g.add_argument('--tag', help='a specific release tag'); g.add_argument('--directory', help='a folder that already holds the release artifacts')
    ap.add_argument('--json', action='store_true', help='print the structured report only'); ap.add_argument('--repo', default=DEFAULT_REPO); ap.add_argument('--identity', default=DEFAULT_IDENTITY); ap.add_argument('--issuer', default=DEFAULT_ISSUER)
    ap.add_argument('--workflow-repo', default=DEFAULT_REPO, help='source repository the certificate must name (empty to skip)'); ap.add_argument('--cosign'); ap.add_argument('--output-dir', help='keep the downloaded artifacts here')
    ap.add_argument('--previous-checkpoint', help='a checkpoint.txt you already trust: prove this release extends it'); ap.add_argument('--trust-state', help='JSON file holding the newest verified checkpoint; read for rollback protection, updated after a full pass')
    ap.add_argument('--api-url', default='https://api.github.com'); ap.add_argument('--web-url', default='https://github.com', help='used when the API quota is exhausted'); ap.add_argument('--raw-url', default='https://raw.githubusercontent.com'); ap.add_argument('--token', help='GitHub token (only to lift the anonymous rate limit)'); ap.add_argument('--tag-for-directory', dest='tag_dir')
    a = ap.parse_args(argv)
    if a.directory and a.tag is None: a.tag = None
    try: rep = verify(a)
    except Exception as e:
        f = e if isinstance(e, Fail) else Fail(6, f'unexpected error: {type(e).__name__}: {str(e)[:200]}')
        rep = {'schemaVersion': SCHEMA, 'tool': 'verify_public_release.py', 'version': VERSION, 'result': 'FAIL', 'exit_code': f.code, 'release': {}, 'expected': {'identity': a.identity, 'issuer': a.issuer, 'repository': a.workflow_repo}, 'summary': {}, 'checks': [{'id': 'run', 'status': 'fail', 'mandatory': True, 'category': f.code, 'detail': f.message}], 'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    print(json.dumps(rep, indent=1) if a.json else render(rep))
    return rep['exit_code']

if __name__ == '__main__': sys.exit(main())
