#!/usr/bin/env python3
"""Refreshes docs/wiki/roadmap-data.json from the real GitHub data of the repository (milestones, releases, pull requests).

Read-only public endpoints only; no secret is needed (an authenticated `gh` just raises the rate limit). The output is a file you review in a pull request: nothing
publishes it. Counts are what GitHub reports, with the date they were measured; no percentages and no dates of delivery are derived from them.
usage: wiki_roadmap.py [--repo OWNER/NAME] [--out FILE] [--date YYYY-MM-DD]"""
import argparse, datetime, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = 'MacGuard/macguard-yara-channel'


def gh(args):
    r = subprocess.run(['gh', 'api'] + args, capture_output=True, text=True, timeout=60)
    if r.returncode: raise RuntimeError(f'gh api {" ".join(args)[:80]} failed: {r.stderr.strip()[:200]}')
    return json.loads(r.stdout)


def collect(repo, date, call=gh):
    since = (datetime.date.fromisoformat(date) - datetime.timedelta(days=30)).isoformat()
    ms = call([f'repos/{repo}/milestones?state=all&per_page=100'])
    rel = call([f'repos/{repo}/releases?per_page=3'])
    opened = call([f'search/issues?q=repo:{repo}+type:pr+state:open&per_page=1'])
    merged = call([f'search/issues?q=repo:{repo}+type:pr+is:merged+merged:>={since}&per_page=1'])
    return {'schema': 1, 'repo': repo, 'measured_on': date,
            'milestones': [{'title': m['title'], 'url': m['html_url'], 'open': m['open_issues'], 'closed': m['closed_issues']} for m in sorted(ms, key=lambda m: m['number'])],
            'releases': [{'tag': r['tag_name'], 'url': r['html_url'], 'published_at': r['published_at']} for r in rel if not r.get('draft')],
            'open_prs': opened['total_count'], 'merged_last_30_days': merged['total_count']}


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or '').split('\n')[0])
    ap.add_argument('--repo', default=REPO); ap.add_argument('--out', default=str(ROOT / 'docs' / 'wiki' / 'roadmap-data.json'))
    ap.add_argument('--date', default=datetime.datetime.now(datetime.timezone.utc).date().isoformat())
    a = ap.parse_args(argv)
    try: data = collect(a.repo, a.date)
    except (RuntimeError, KeyError, ValueError, subprocess.TimeoutExpired) as e: print(f'wiki_roadmap: {e}', file=sys.stderr); return 1
    pathlib.Path(a.out).write_text(json.dumps(data, ensure_ascii=False, indent=1) + '\n')
    print(f'wiki_roadmap: {len(data["milestones"])} milestones, {len(data["releases"])} releases, {data["open_prs"]} open PRs -> {a.out}'); return 0


if __name__ == '__main__': sys.exit(main())
