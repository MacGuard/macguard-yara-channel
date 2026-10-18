#!/usr/bin/env python3
"""Daily rule counts for the site chart, derived from the transparency log and the release history.

Per UTC day, from the last candidate the pipeline evaluated that day:
  examined  rule files the run looked at (file_count of the candidate)       - NOT downloads by users
  rejected  files the YARA compiler refused;  accepted = examined - rejected
  new / modified / removed  from the releases published that day, compared manifest to manifest (null when no release)
A day with no run is `observed: false` with every count null: absence of observation, not a run that found zero rules.
Only the last WINDOW days are shown; the log itself is never rewritten."""
import json, pathlib
from datetime import date, datetime, timedelta, timezone
WINDOW = 30

def daily(entries, today: date, window: int = WINDOW, releases=None):
    runs = {}   # run_id -> {day, time, examined, rejected}
    for e in entries:
        rid, kind, d = e.get('run_id'), e.get('event'), e.get('details', {})
        if not rid or not e.get('time'): continue
        if kind in ('candidate.accepted', 'candidate.rejected'):
            r = runs.setdefault(rid, {'rejected': 0})
            r.update(day=e['time'][:10], time=e['time'], examined=int(d.get('file_count', 0)))
        elif kind == 'rule.rejected':
            runs.setdefault(rid, {'rejected': 0})['rejected'] += 1
    last = {}
    for r in runs.values():
        if 'day' not in r: continue
        if r['day'] not in last or r['time'] >= last[r['day']]['time']: last[r['day']] = r
    changes = {}   # day -> [new, modified, removed] summed over that day's releases
    for rel in releases or []:
        c = changes.setdefault(rel['published_at'][:10], [0, 0, 0])
        c[0] += rel['added']; c[1] += rel['modified']; c[2] += rel['removed']
    days = []
    for i in range(window - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat(); r = last.get(day); c = changes.get(day)
        if not r:
            days.append({'date': day, 'observed': False, 'examined': None, 'accepted': None, 'rejected': None, 'new': c[0] if c else None, 'modified': c[1] if c else None, 'removed': c[2] if c else None})
            continue
        rejected = min(r['rejected'], r['examined'])
        days.append({'date': day, 'observed': True, 'examined': r['examined'], 'accepted': r['examined'] - rejected, 'rejected': rejected,
                     'new': c[0] if c else None, 'modified': c[1] if c else None, 'removed': c[2] if c else None})
    return days

def build(log_file: pathlib.Path, out: pathlib.Path, now: datetime = None, releases=None):
    now = now or datetime.now(timezone.utc)
    entries = [json.loads(l) for l in log_file.read_text().splitlines() if l] if log_file.exists() else []
    doc = {'schema': 1, 'generated_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'window_days': WINDOW, 'days': daily(entries, now.date(), releases=releases),
           'definitions': {'examined': 'rule files the pipeline looked at in the last run of the day', 'accepted': 'examined minus rejected', 'rejected': 'files refused by the YARA compiler',
                           'new_modified_removed': 'from comparing the manifests of releases published that day', 'observed': 'false = no pipeline run that day (not zero rules)',
                           'downloads': 'not measured: this site has no download telemetry'}}
    out.write_text(json.dumps(doc, indent=1) + '\n')
    return doc

if __name__ == '__main__':
    root = pathlib.Path(__file__).resolve().parents[1]
    build(root / 'logs' / 'log.jsonl', root / 'site' / 'stats.json')
