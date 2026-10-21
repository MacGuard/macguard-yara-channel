#!/usr/bin/env python3
"""Turn an authorized source proposal into a reviewed pull request, and judge such pull requests. Code the workflow runs; it trusts NOTHING the Worker says.

The private service hands the workflow `{id, version, payload, payload_sha256}` for proposals an ADMIN authorized. This script re-validates every field from scratch
(the Worker's own checks are a convenience), re-asks GitHub for the licence, and edits exactly four tracked files with fixed templates, writing no free text:
    config/sources.json                one new line, the rest of the file byte-identical
    config/policy.json                 one licence entry (with the SHA-256 of the licence text: a later edit becomes `license-changed`, which nobody can waive)
    docs-src/es/sources.md, docs-src/en/sources.md   one table row each (tests/test_docs.py requires every source to be documented)
plus one note, docs/source-proposals/<id>.md. The proposer's free-text reason never leaves the private service.

usage: source_proposal.py list    --out FILE                       GET /api/pipeline/source-proposals (OIDC) and keep the validated ids
       source_proposal.py prepare --file FILE --id ID --out DIR    validate, re-verify with GitHub, edit the files, write DIR/{branch,title,body.md,note}
       source_proposal.py report  --file FILE --id ID --pr N --head-sha SHA     POST .../pr
       source_proposal.py sync    --prs FILE                       POST .../sync for merged / closed pull requests (FILE: gh pr list --json number,state,mergedAt,headRefName)
       source_proposal.py gate    --base REF                       the required check `source-proposal-gate`"""
import argparse, base64, hashlib, json, os, pathlib, re, subprocess, sys, urllib.parse, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
ROOT = pathlib.Path(__file__).resolve().parents[1]

ID = re.compile(r'[a-z0-9][a-z0-9-]{1,31}')
OWNER = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?')
REPO = re.compile(r'[A-Za-z0-9._-]{1,100}')
PATH = re.compile(r'[A-Za-z0-9._][A-Za-z0-9._/-]{0,99}')
HEX64, HEX40, SPDX = re.compile(r'[0-9a-f]{64}'), re.compile(r'[0-9a-f]{40}'), re.compile(r'[A-Za-z0-9.+-]{1,40}')
BRANCH = re.compile(r'proposal/[a-z0-9][a-z0-9-]{1,31}-[0-9a-f]{8}')
ALLOWED_SPDX = {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'CC0-1.0'}   # same list as admin/worker/src/proposals.js; anything else is a legal decision, never automatic
KEYS = {'admission', 'id', 'kind', 'license', 'paths', 'repo', 'verified_commit'}
FILES = ('config/sources.json', 'config/policy.json', 'docs-src/en/sources.md', 'docs-src/es/sources.md')


class Invalid(ValueError):
    pass


def digest(payload):
    """SHA-256 of the canonical form: keys sorted, no whitespace, ASCII only. admin/worker/src/proposals.js computes the same."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def no_duplicate_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise Invalid(f'duplicate key {k!r}')
        d[k] = v
    return d


def loads(text): return json.loads(text, object_pairs_hook=no_duplicate_keys)


def _str(v, rx, what):
    if not isinstance(v, str) or not rx.fullmatch(v): raise Invalid(f'{what} is not valid')
    return v


def validate(item, existing_sources=()):
    """Returns the payload, or raises Invalid. `existing_sources`: the entries of config/sources.json."""
    if not isinstance(item, dict) or set(item) - {'id', 'version', 'payload', 'payload_sha256'}: raise Invalid('unexpected shape')
    p = item.get('payload')
    if not isinstance(p, dict) or set(p) != KEYS: raise Invalid('payload keys differ from the contract')
    _str(item.get('payload_sha256'), HEX64, 'payload_sha256')
    if digest(p) != item['payload_sha256']: raise Invalid('payload_sha256 does not match the payload')
    _str(p['id'], ID, 'id')
    if p['id'] == 'synthetic-test' or p['id'].endswith('-'): raise Invalid('reserved id')
    if p['kind'] != 'rules' or p['admission'] != 'probation': raise Invalid('only rules sources on probation can be proposed')
    owner, _, name = str(p['repo']).partition('/')
    _str(owner, OWNER, 'repo owner'); _str(name, REPO, 'repo name')
    if '--' in owner or name in ('.', '..') or name.endswith('.git'): raise Invalid('repo is not valid')
    paths = p['paths']
    if not isinstance(paths, list) or not 1 <= len(paths) <= 20 or len(set(paths)) != len(paths): raise Invalid('paths')
    for x in paths:
        _str(x, PATH, 'path')
        if x.endswith('/') or '//' in x or any(s in ('.', '..') for s in x.split('/')): raise Invalid('path')
    lic = p['license']
    if not isinstance(lic, dict) or set(lic) != {'sha256', 'spdx'}: raise Invalid('license keys')
    _str(lic['sha256'], HEX64, 'license sha256'); _str(lic['spdx'], SPDX, 'license spdx')
    if lic['spdx'] not in ALLOWED_SPDX: raise Invalid(f"licence {lic['spdx']} needs a legal decision: add it by hand, not through the workflow")
    _str(p['verified_commit'], HEX40, 'verified_commit')
    for s in existing_sources:
        if s.get('id') == p['id']: raise Invalid('id already in config/sources.json')
        if str(s.get('repo', '')).lower() == p['repo'].lower(): raise Invalid('repository already in config/sources.json')
    return p


def reverify(payload, get):
    """Ask GitHub again (read only, api.github.com): the repository must still be public and unchanged in the way that matters. `get(path)` returns parsed JSON."""
    r = get(f"/repos/{payload['repo']}")
    if r.get('private') or r.get('fork') or r.get('archived') or r.get('disabled'): raise Invalid('the repository is private, a fork, archived or disabled now')
    if (r.get('license') or {}).get('spdx_id') != payload['license']['spdx']: raise Invalid('GitHub reports another licence now')
    l = get(f"/repos/{payload['repo']}/license")
    text = base64.b64decode(l.get('content', '')).decode('utf-8', 'replace')
    if hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest() != payload['license']['sha256']: raise Invalid('the licence text changed since it was verified')
    if (l.get('license') or {}).get('spdx_id') != payload['license']['spdx']: raise Invalid('the licence file reports another licence now')


# ---- the four edits, all from fixed templates ----
def entry_line(p):
    e = {'id': p['id'], 'repo': p['repo'], 'kind': 'rules', 'paths': p['paths'], 'admission': 'probation'}
    return '    ' + json.dumps(e, separators=(',', ':'))


def apply_sources(text, p):
    lines = text.split('\n'); close = [i for i, l in enumerate(lines) if l == '  ]']
    if len(close) != 1: raise Invalid('config/sources.json is not in the expected layout')
    i = close[0]; last = i - 1
    if not lines[last].rstrip().endswith('}'): raise Invalid('config/sources.json is not in the expected layout')
    out = lines[:last] + [lines[last] + ','] + [entry_line(p)] + lines[i:]
    new = '\n'.join(out); before, after = json.loads(text)['sources'], json.loads(new)['sources']
    if after[:-1] != before or after[-1]['id'] != p['id'] or len(after) != len(before) + 1: raise Invalid('the edit would change more than one source')
    return new


def apply_policy(text, p):
    obj = json.loads(text)
    if json.dumps(obj, indent=2) + '\n' != text: raise Invalid('config/policy.json is not in the canonical layout')
    lic = obj.setdefault('licenses', {})
    if p['repo'] in lic: raise Invalid('a licence policy already exists for this repository')
    lic[p['repo']] = {'expected_spdx': p['license']['spdx'], 'spdx': p['license']['spdx'], 'redistribution': 'allowed-with-license-notice', 'sha256': p['license']['sha256']}
    return json.dumps(obj, indent=2) + '\n'


DOC_ROW = {
    'es': '| {repo} (propuesta autorizada, en prueba) | `{repo}` | **Fuente de reglas en prueba.** Su primera ejecución queda en cuarentena hasta que un administrador autorice sus reglas. Rutas: {paths}. |',
    'en': '| {repo} (authorized proposal, on probation) | `{repo}` | **Rules source on probation.** Its first run stays in quarantine until an administrator authorizes its rules. Paths: {paths}. |',
}


def apply_docs(text, lang, p):
    lines = text.split('\n'); sep = [i for i, l in enumerate(lines) if re.fullmatch(r'\|[-| ]+\|', l)]
    if not sep: raise Invalid('docs table not found')
    i = sep[0] + 1
    while i < len(lines) and lines[i].startswith('|'): i += 1
    row = DOC_ROW[lang].format(repo=p['repo'], paths=', '.join(f'`{x}`' for x in p['paths']))
    return '\n'.join(lines[:i] + [row] + lines[i:])


def note(p, item):
    return (f"# Source proposal: {p['id']}\n\nGenerated by `scripts/source_proposal.py` from a proposal an administrator authorized in the private panel. Review the diff of `config/sources.json`,\n"
            f"`config/policy.json` and `docs-src/*/sources.md`; nothing else is changed. The source starts on probation: its first run is held in quarantine.\n\n"
            f"| Field | Value |\n|---|---|\n| id | `{p['id']}` |\n| repository | `{p['repo']}` |\n| paths | {', '.join('`' + x + '`' for x in p['paths'])} |\n| licence (SPDX) | `{p['license']['spdx']}` |\n"
            f"| licence text SHA-256 | `{p['license']['sha256']}` |\n| commit verified | `{p['verified_commit']}` |\n| payload SHA-256 | `{item['payload_sha256']}` |\n| proposal | `{item['id']}` |\n")


def pr_texts(p, item):
    return f"Add rules source {p['id']} ({p['repo']})", (
        f"Authorized in the private panel by an administrator; opened by `source-proposals.yml` with the per-run token.\n\n"
        f"* repository `{p['repo']}`, paths {', '.join('`' + x + '`' for x in p['paths'])}, licence `{p['license']['spdx']}`\n* payload SHA-256 `{item['payload_sha256']}`\n\n"
        "Before approving: read the licence of the repository yourself, check the diff touches only the files listed in the note, and wait for the required checks. "
        "Merging does not publish anything: the source starts on probation and its rules are held in quarantine until an administrator authorizes them.\n")


def branch_of(p, item): return f"proposal/{p['id']}-{item['payload_sha256'][:8]}"


def prepare(item, root, out, get):
    root, out = pathlib.Path(root), pathlib.Path(out)
    src = json.loads((root / 'config/sources.json').read_text())['sources']
    p = validate(item, src); reverify(p, get)
    (root / 'config/sources.json').write_text(apply_sources((root / 'config/sources.json').read_text(), p))
    (root / 'config/policy.json').write_text(apply_policy((root / 'config/policy.json').read_text(), p))
    for lang in ('es', 'en'):
        f = root / f'docs-src/{lang}/sources.md'; f.write_text(apply_docs(f.read_text(), lang, p))
    nf = root / 'docs' / 'source-proposals' / f"{p['id']}.md"; nf.parent.mkdir(parents=True, exist_ok=True); nf.write_text(note(p, item))
    out.mkdir(parents=True, exist_ok=True); title, body = pr_texts(p, item)
    (out / 'branch').write_text(branch_of(p, item)); (out / 'title').write_text(title); (out / 'body.md').write_text(body); (out / 'note').write_text(f"docs/source-proposals/{p['id']}.md")
    return p


# ---- the required check ----
def gate(changed, base, head, head_ref=''):
    """Problems of a pull request. `changed`: paths; `base`/`head`: {path: text} for config/sources.json and config/policy.json. [] means the check passes."""
    probs = []; changed = set(changed)
    if head_ref.startswith('proposal/'):
        if not BRANCH.fullmatch(head_ref): probs.append('the branch name is not proposal/<id>-<8 hex>')
        notes = {c for c in changed if c.startswith('docs/source-proposals/')}
        extra = changed - set(FILES) - notes
        if extra: probs.append(f"a proposal pull request may only change the four template files and its note, not: {', '.join(sorted(extra))}")
        if len(notes) != 1 or not all(re.fullmatch(r'docs/source-proposals/[a-z0-9][a-z0-9-]{1,31}\.md', n) for n in notes): probs.append('exactly one proposal note is required')
        if not {'config/sources.json', 'config/policy.json'} <= changed: probs.append('a proposal changes both config/sources.json and config/policy.json')
    if not ({'config/sources.json', 'config/policy.json'} & changed): return probs
    b = {s['id']: s for s in json.loads(base['config/sources.json'])['sources']}; h = {s['id']: s for s in json.loads(head['config/sources.json'])['sources']}
    added, removed = sorted(set(h) - set(b)), sorted(set(b) - set(h)); modified = sorted(i for i in set(h) & set(b) if h[i] != b[i])
    if len(added) + len(removed) + len(modified) > 1: probs.append(f'one source per pull request (added {added}, removed {removed}, modified {modified})')
    policy = json.loads(head['config/policy.json']); lic = policy.get('licenses', {})
    for i in added:
        e = h[i]
        if set(e) != {'id', 'repo', 'kind', 'paths', 'admission'} and not (e.get('kind') == 'engine'): probs.append(f'{i}: the entry must have exactly id, repo, kind, paths, admission')
        if e.get('kind') == 'rules':
            if e.get('admission') != 'probation': probs.append(f'{i}: a new rules source must carry "admission": "probation"')
            try: _str(e.get('id'), ID, 'id'); owner, _, name = str(e.get('repo')).partition('/'); _str(owner, OWNER, 'owner'); _str(name, REPO, 'name'); [_str(x, PATH, 'path') for x in e['paths']]
            except (Invalid, KeyError, TypeError) as x: probs.append(f'{i}: {x}')
            l = lic.get(e.get('repo'))
            if not isinstance(l, dict) or not HEX64.fullmatch(str(l.get('sha256', ''))) or not (l.get('expected_spdx') or l.get('expected_marker')): probs.append(f"{i}: config/policy.json needs a licence entry for {e.get('repo')} with the SHA-256 of the licence text")
    new_lic = set(lic) - set(json.loads(base['config/policy.json']).get('licenses', {}))
    if new_lic - {h[i].get('repo') for i in added}: probs.append('a licence entry was added that belongs to no added source')
    return probs


# ---- command line ----
def _github_get(path):
    if not path.startswith('/repos/'): raise Invalid('refused path')
    req = urllib.request.Request('https://api.github.com' + path, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'macguard-source-proposals', **({'Authorization': f"Bearer {os.environ['GITHUB_TOKEN']}"} if os.environ.get('GITHUB_TOKEN') else {})})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    with urllib.request.build_opener(NoRedirect).open(req, timeout=25) as r: return json.load(r)


def _git(*a): return subprocess.run(['git', *a], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0]); sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('list'); s.add_argument('--out', required=True)
    s = sub.add_parser('prepare'); s.add_argument('--file', required=True); s.add_argument('--id', required=True); s.add_argument('--out', required=True); s.add_argument('--root', default=str(ROOT))
    s = sub.add_parser('report'); s.add_argument('--file', required=True); s.add_argument('--id', required=True); s.add_argument('--pr', type=int, required=True); s.add_argument('--head-sha', required=True)
    s = sub.add_parser('sync'); s.add_argument('--prs', required=True)
    s = sub.add_parser('gate'); s.add_argument('--base', required=True); s.add_argument('--head-ref', default=os.environ.get('HEAD_REF', ''))
    a = ap.parse_args(argv)
    import quarantine_client as qc
    if a.cmd == 'list':
        st, data = qc.call('GET', '/api/pipeline/source-proposals')
        if st != 200: print(f'service unavailable or refused (status {st}); nothing to do', file=sys.stderr); pathlib.Path(a.out).write_text('{"proposals":[]}'); return 0
        items = [x for x in data.get('proposals', []) if isinstance(x, dict) and re.fullmatch(r'[0-9a-f-]{8,64}', str(x.get('id', '')))]
        pathlib.Path(a.out).write_text(json.dumps({'proposals': items})); print('\n'.join(x['id'] for x in items)); return 0
    if a.cmd in ('prepare', 'report'):
        items = loads(pathlib.Path(a.file).read_text())['proposals']; item = next((x for x in items if x.get('id') == a.id), None)
        if not item: print('unknown proposal id', file=sys.stderr); return 2
    if a.cmd == 'prepare':
        try: p = prepare(item, a.root, a.out, _github_get)
        except Invalid as e: print(f'REFUSED {a.id}: {e}', file=sys.stderr); return 3
        print(f"prepared {p['id']}"); return 0
    if a.cmd == 'report':
        p = validate(item, []); st, data = qc.call('POST', f"/api/pipeline/source-proposals/{a.id}/pr", {'pr_number': a.pr, 'pr_url': f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/pull/{a.pr}", 'branch': branch_of(p, item), 'head_sha': a.head_sha, 'payload_sha256': item['payload_sha256']})
        print(f'report: status {st}'); return 0 if st == 200 else 1
    if a.cmd == 'sync':
        rc = 0
        for pr in json.loads(pathlib.Path(a.prs).read_text()):
            br = str(pr.get('headRefName', ''))
            if not BRANCH.fullmatch(br): continue
            outcome = 'merged' if pr.get('mergedAt') else 'closed_unmerged' if pr.get('state') == 'CLOSED' else None
            if outcome:
                st, _ = qc.call('POST', '/api/pipeline/source-proposals/sync', {'branch': br, 'outcome': outcome}); print(f'sync {br} {outcome}: status {st}'); rc = rc or (0 if st in (200, 404) else 1)
        return rc
    if a.cmd == 'gate':
        if not a.base or a.base.endswith('/'): print('no base branch (not a pull request): nothing to check'); return 0
        changed = _git('diff', '--name-only', f'{a.base}...HEAD').split()
        read = lambda ref, f: (lambda r: r.stdout if r.returncode == 0 else '{"sources":[],"licenses":{}}')(subprocess.run(['git', 'show', f'{ref}:{f}'], cwd=ROOT, capture_output=True, text=True))
        files = ('config/sources.json', 'config/policy.json')
        probs = gate(changed, {f: read(a.base, f) for f in files}, {f: (ROOT / f).read_text() for f in files}, a.head_ref)
        for x in probs: print('PROBLEM', x)
        print('source-proposal-gate:', 'FAILED' if probs else 'ok'); return 1 if probs else 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
