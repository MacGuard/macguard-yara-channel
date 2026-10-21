#!/usr/bin/env python3
"""Offline checks of the repository guarantees that keep an unreviewed source out of config/sources.json.

Parses (never calls GitHub) a ruleset JSON, the live ruleset objects `gh api repos/R/rulesets/<id>` returns, and CODEOWNERS, and reports every way they
fail to say what docs/audit/source-proposals-spec.md section 9 requires:
  * the default branch has NO bypass actor of type Integration (the GitHub Actions app) and no bypass in mode "always";
  * pull requests need at least one approving review, from a code owner, on the last push, with stale reviews dismissed;
  * deletion and force-push are refused; the required checks are present;
  * the `logs` branch is writable only by the log bot, with no history rewrite;
  * CODEOWNERS covers config/sources.json, config/policy.json, .github/workflows/** and scripts/** with a syntactically valid owner.

scripts/ruleset_probe.sh runs these against the sandbox repository and then proves the same thing with real pushes. CLI:
  ruleset_check.py main FILE | logs FILE | codeowners FILE [--root DIR]      (exit 1 and one problem per line when something is wrong)
"""
import fnmatch, json, pathlib, re, sys

ACTIONS_APP_ID = 15368
REQUIRED_CHECKS = ('python-tests', 'quarantine-service', 'source-proposal-gate')
MUST_BE_OWNED = ('config/sources.json', 'config/policy.json', '.github/CODEOWNERS', '.github/workflows/daily.yml', '.github/workflows/publish.yml', '.github/workflows/source-proposals.yml',
                 '.github/workflows/new-future-workflow.yml', '.github/workflows/nested/dir/x.yml', 'scripts/decide.py', 'scripts/prepare.py', 'scripts/a/b/future.sh')
OWNER = re.compile(r'^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9._-]+)?$|^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$')


def _rules(rs, kind):
    return [r for r in rs.get('rules', []) if r.get('type') == kind]


def _bypass(rs, allow):
    """allow: a set of (actor_type, actor_id, mode) that may bypass; anything else is a problem."""
    out = []
    for b in rs.get('bypass_actors') or []:
        key = (b.get('actor_type'), b.get('actor_id'), b.get('bypass_mode'))
        if key not in allow:
            out.append(f"bypass actor {b.get('actor_type')} {b.get('actor_id')} ({b.get('bypass_mode')}) is not allowed")
    return out


def check_main_ruleset(rs, extra_checks=()):
    """Problems of a ruleset meant for the default branch ([] when it is what the spec requires)."""
    p = []
    if rs.get('target') != 'branch': p.append('target must be branch')
    if rs.get('enforcement') != 'active': p.append('enforcement must be active')
    if (rs.get('conditions') or {}).get('ref_name', {}).get('include') != ['~DEFAULT_BRANCH']: p.append('must target ~DEFAULT_BRANCH only')
    if any(b.get('actor_type') == 'Integration' for b in rs.get('bypass_actors') or []): p.append('the GitHub Actions app (an Integration) must not bypass the default branch')
    p += _bypass(rs, {('RepositoryRole', 5, 'pull_request')})   # the owner may merge their own reviewed PR; nothing may push straight to main
    for kind in ('deletion', 'non_fast_forward'):
        if not _rules(rs, kind): p.append(f'rule {kind} is missing')
    pr = _rules(rs, 'pull_request')
    if len(pr) != 1: p.append('exactly one pull_request rule is required')
    else:
        a = pr[0].get('parameters') or {}
        if not isinstance(a.get('required_approving_review_count'), int) or a['required_approving_review_count'] < 1: p.append('required_approving_review_count must be at least 1')
        for k in ('require_code_owner_review', 'dismiss_stale_reviews_on_push', 'require_last_push_approval', 'required_review_thread_resolution'):
            if a.get(k) is not True: p.append(f'{k} must be true')
    sc = _rules(rs, 'required_status_checks')
    names = {c.get('context') for r in sc for c in (r.get('parameters') or {}).get('required_status_checks', [])}
    for need in (*REQUIRED_CHECKS, *extra_checks):
        if need not in names: p.append(f'required status check {need} is missing')
    for r in rs.get('rules', []):
        if r.get('type') in ('update', 'creation'): p.append(f"rule {r['type']} would block the pull request flow on the default branch")
    return p


def check_logs_ruleset(rs):
    p = []
    if rs.get('target') != 'branch': p.append('target must be branch')
    if rs.get('enforcement') != 'active': p.append('enforcement must be active')
    if (rs.get('conditions') or {}).get('ref_name', {}).get('include') != ['refs/heads/logs']: p.append('must target refs/heads/logs only')
    if (rs.get('conditions') or {}).get('ref_name', {}).get('exclude'): p.append('no exclusions')
    p += _bypass(rs, {('Integration', ACTIONS_APP_ID, 'always')})
    if not (rs.get('bypass_actors') or []): p.append('the log bot (GitHub Actions app) must be the bypass actor, otherwise nobody can write the log')
    for kind in ('update', 'deletion', 'non_fast_forward'):
        if not _rules(rs, kind): p.append(f'rule {kind} is missing')
    return p


def parse_codeowners(text):
    rules = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.split('#', 1)[0].strip()
        if not s: continue
        parts = s.split()
        rules.append((parts[0], parts[1:], n))
    return rules


def _match(pattern, path):
    """The subset of CODEOWNERS syntax this repository uses: anchored paths, directories (trailing /), * and **."""
    anchored = pattern.startswith('/'); pat = pattern.lstrip('/')
    if pat.endswith('/'):
        d = pat.rstrip('/')
        return path.startswith(d + '/') if anchored else (('/' + path).find('/' + d + '/') >= 0)
    if '*' in pat: return fnmatch.fnmatchcase(path, pat) if anchored else fnmatch.fnmatchcase(path.split('/')[-1], pat)
    return path == pat if anchored else (path == pat or path.endswith('/' + pat))


def owners_of(rules, path):
    """Last matching pattern wins, as on GitHub."""
    found = []
    for pattern, owners, _ in rules:
        if _match(pattern, path): found = owners
    return found


def check_codeowners(text, paths=MUST_BE_OWNED, root=None):
    p = []; rules = parse_codeowners(text)
    if '<OWNER>' in text: p.append('the <OWNER> placeholder is still there')
    for pattern, owners, n in rules:
        if not owners: p.append(f'line {n}: {pattern} has no owner (it would un-own the path)')
        for o in owners:
            if not OWNER.match(o): p.append(f'line {n}: {o!r} is not a valid owner')
        if root is not None and not any(True for _ in pathlib.Path(root).glob(pattern.lstrip('/').rstrip('/') or '*')): p.append(f'line {n}: {pattern} matches nothing in the repository')
    for path in paths:
        if not owners_of(rules, path): p.append(f'{path} has no code owner')
    return p


def check_live(rulesets, extra_checks=()):
    """`rulesets`: the list of full ruleset objects (gh api repos/R/rulesets/<id>) that are active. Problems of the effective protection of the default branch."""
    main = [r for r in rulesets if r.get('target') == 'branch' and (r.get('conditions') or {}).get('ref_name', {}).get('include') == ['~DEFAULT_BRANCH']]
    if not main: return ['no active ruleset targets the default branch']
    out = []
    for r in main: out += [f"{r.get('name')}: {x}" for x in check_main_ruleset(r, extra_checks)]
    return out


def main(argv):
    if len(argv) < 3 or argv[1] not in ('main', 'logs', 'codeowners', 'live'):
        print(__doc__); return 2
    kind, path = argv[1], argv[2]
    text = pathlib.Path(path).read_text()
    if kind == 'codeowners':
        root = argv[argv.index('--root') + 1] if '--root' in argv else None
        problems = check_codeowners(text, root=root)
    else:
        data = json.loads(text)
        problems = check_main_ruleset(data) if kind == 'main' else check_logs_ruleset(data) if kind == 'logs' else check_live(data if isinstance(data, list) else [data])
    for x in problems: print('PROBLEM', x)
    if not problems: print('OK')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
