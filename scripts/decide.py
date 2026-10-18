#!/usr/bin/env python3
"""Turn static classification, dynamic results and human decisions into the set that may be published.

Rules that cannot be bent
  * a human approval never skips a technical control: it can waive only judgement findings (WAIVABLE); compile errors,
    truncation, corruption, crashes/timeouts, a changed licence or an identical previously-rejected file stay blocked;
  * content rejected before stays rejected while the bytes are the same; changed bytes are a new candidate (linked by path);
  * a previously published file that now fails is not published again without a documented resolution;
  * the dynamic result must belong to exactly the final set, otherwise nothing is publishable;
  * nothing here depends on the private quarantine store being reachable: without decisions the safe default applies.
"""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import catalog, tlog
VALIDATED, QUARANTINED, REJECTED, DEPRECATED = 'VALIDATED', 'QUARANTINED', 'REJECTED', 'DEPRECATED'
WAIVABLE = {'costly-regex', 'filesize-loop', 'many-loops', 'unknown-module', 'include', 'license-unchecked', 'matches-benign-corpus', 'dependency-not-validated'}
APPROVING = {'APPROVED_PENDING_VALIDATION', 'RELEASED'}

def set_root(files): return tlog.rules_root([{'path': f['path'], 'sha256': f['sha256']} for f in files])

def decide(classified, previous=None, decisions=None, dynamic=None, benign_hits=None, dynamic_required=True, hit_rate_limit=0.05, corpus_size=0, previously_rejected=None):
    previous = previous or {}; decisions = decisions or {}; previously_rejected = set(previously_rejected or [])
    prev_files = {f['path']: f['sha256'] for f in previous.get('files', [])}
    dyn_bad = set((dynamic or {}).get('culprits', []))
    res = {'approved': [], 'excluded': [], 'submissions': [], 'new_rejected_hashes': [], 'retired': [], 'previously_published_failing': [], 'reasons': []}
    by_path = {c['path']: c for c in classified}
    generic = set()   # a rule file that matches many clean files is too generic to trust
    if benign_hits and corpus_size >= 50:
        generic = {p for p, n in benign_hits.items() if n / corpus_size > hit_rate_limit}
    included = {}
    for c in classified:
        reasons = [dict(r) for r in c['reasons']]; state = c['state']
        if c['path'] in generic and state == VALIDATED:
            reasons.append({'code': 'matches-benign-corpus', 'severity': 'review', 'detail': 'matches more than the allowed share of the clean corpus'}); state = QUARANTINED
        if c['path'] in dyn_bad and state != REJECTED:
            reasons.append({'code': 'dynamic-failure', 'severity': 'block', 'detail': 'caused a crash, timeout or regression in the dynamic tests'}); state = QUARANTINED
        if c['sha256'] in previously_rejected and state != REJECTED:
            reasons.append({'code': 'previously-rejected', 'severity': 'reject', 'detail': 'identical content was rejected before'}); state = REJECTED
        d = decisions.get(c['sha256'])
        if d and d.get('state') == 'REJECTED':
            reasons.append({'code': 'rejected-by-reviewer', 'severity': 'reject', 'detail': d.get('reason', '')}); state = REJECTED
        if state == QUARANTINED and d and d.get('state') in APPROVING:
            blocking = [r for r in reasons if r['severity'] in ('truncated', 'corrupt', 'reject', 'block') or (r['severity'] == 'review' and r['code'] not in WAIVABLE)]
            if not blocking:
                state = VALIDATED; reasons.append({'code': 'waived-by-review', 'severity': 'info', 'detail': f"approved by {d.get('by', 'a reviewer')}; technical checks still passed"})
        c2 = {**c, 'state': state, 'reasons': reasons}
        if state == VALIDATED: included[c['path']] = c2
        else: res['excluded'].append(c2)
    changed = True   # a file needing something excluded cannot ship (transitive, after approvals were applied)
    while changed:
        changed = False
        for p, c in list(included.items()):
            missing = [d for d in c.get('depends_on', []) if d not in included]
            if missing:
                c['state'] = QUARANTINED; c['reasons'].append({'code': 'dependency-not-validated', 'severity': 'review', 'detail': f'needs {missing[0]} which is not part of the release'})
                res['excluded'].append(included.pop(p)); changed = True
    res['approved'] = [included[p] for p in sorted(included)]
    excluded_by_path = {e['path']: e for e in res['excluded']}
    for p, h in prev_files.items():
        if p in excluded_by_path:
            res['previously_published_failing'].append({'path': p, 'was': h, 'now': by_path[p]['sha256'], 'state': excluded_by_path[p]['state']})
        elif p not in by_path:
            res['retired'].append({'path': p, 'sha256': h, 'reason': 'no longer present upstream'})
    for e in res['excluded']:
        if e['state'] == QUARANTINED:
            res['submissions'].append({'path': e['path'], 'sha256': e['sha256'], 'bytes': e['bytes'], 'source': e['source'], 'reasons': [r['code'] for r in e['reasons'] if r['severity'] != 'info'], 'depends_on': e.get('depends_on', [])})
        if e['state'] == REJECTED and 'rejected-by-reviewer' not in [r['code'] for r in e['reasons']]: res['new_rejected_hashes'].append(e['sha256'])
    res['approved'] = [c for c in res['approved'] if c['state'] != DEPRECATED]
    final_root = set_root(res['approved'])
    changes = catalog.diff(previous, {'files': res['approved']}) if previous else {'added': [x['path'] for x in res['approved']], 'modified': [], 'removed': []}
    res['changes'] = {k: len(v) for k, v in changes.items()}; res['rules_root'] = final_root
    why = []
    if not res['approved']: why.append('the approved set is empty')
    if previous and not (changes['added'] or changes['modified'] or changes['removed']): why.append('no effective change against the latest release')
    if dynamic_required:
        if not dynamic: why.append('dynamic validation did not run')
        elif dynamic.get('set_root') != final_root: why.append('the dynamic result belongs to a different set than the one to publish')
        elif dynamic.get('verdict') not in ('ok', 'no-baseline'): why.append(f"dynamic validation verdict is {dynamic.get('verdict')}")
        elif dynamic.get('canaries_detected', 0) < dynamic.get('canaries_expected', 1): why.append('the engine did not detect the canary files: detection is not demonstrably working')
    res['publishable'] = not why; res['blockers'] = why
    counts = {s: 0 for s in (VALIDATED, QUARANTINED, REJECTED, DEPRECATED)}
    for e in res['excluded']: counts[e['state']] += 1
    res['public_stats'] = {'examined': len(classified), 'accepted': len(res['approved']), 'quarantined': counts[QUARANTINED], 'rejected': counts[REJECTED], 'retired': len(res['retired']), 'previously_published_failing': len(res['previously_published_failing'])}
    return res

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--classification', default='dist/classification.json'); ap.add_argument('--previous'); ap.add_argument('--decisions'); ap.add_argument('--dynamic')
    ap.add_argument('--rejected'); ap.add_argument('--out', default='dist/decision.json'); ap.add_argument('--approved-out', default='dist/approved.json'); ap.add_argument('--no-dynamic', action='store_true')
    a = ap.parse_args()
    cls = json.loads(pathlib.Path(a.classification).read_text())['files']
    load = lambda p: json.loads(pathlib.Path(p).read_text()) if p and pathlib.Path(p).exists() else None
    dyn = load(a.dynamic); hits = (dyn or {}).get('benign_hits_by_file'); corpus = ((dyn or {}).get('corpus') or {}).get('clean_files', 0)
    res = decide(cls, load(a.previous), load(a.decisions), dyn, hits, not a.no_dynamic, corpus_size=corpus, previously_rejected=load(a.rejected))
    pathlib.Path(a.out).write_text(json.dumps(res, indent=1) + '\n')
    pathlib.Path(a.approved_out).write_text(json.dumps({'files': res['approved'], 'rules_root': res['rules_root']}, indent=1) + '\n')
    print(f"publishable={'true' if res['publishable'] else 'false'}"); print(json.dumps(res['public_stats']) + ' blockers=' + json.dumps(res['blockers']), file=sys.stderr)
