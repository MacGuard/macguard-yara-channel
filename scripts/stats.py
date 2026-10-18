#!/usr/bin/env python3
"""Daily rule counts for the site chart, derived from the transparency log and the release history.

Per UTC day, from the last candidate the pipeline evaluated that day:
  examined  rule files the run looked at (file_count of the candidate)       - NOT downloads by users
  rejected  files the YARA compiler refused;  accepted = examined - rejected
  new / modified / removed  from the releases published that day, compared manifest to manifest (null when no release)
A day with no run is `observed: false` with every count null: absence of observation, not a run that found zero rules.
Only the last WINDOW days are shown; the log itself is never rewritten."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import accounting
from datetime import date, datetime, timedelta, timezone
WINDOW = 30

def daily(entries, today: date, window: int = WINDOW, releases=None):
    runs = {}   # run_id -> {day, time, examined, rejected}
    for e in entries:
        rid, kind, d = e.get('run_id'), e.get('event'), e.get('details', {})
        if not rid or not e.get('time'): continue
        if kind in ('candidate.accepted', 'candidate.rejected'):
            r = runs.setdefault(rid, {'rejected': 0})
            r.update(day=e['time'][:10], time=e['time'], examined=int(d.get('examined', d.get('file_count', 0))))
            if 'quarantined' in d or 'rejected' in d:   # autonomous flow: the event carries the full breakdown
                r.update(accepted=int(d.get('file_count', 0)), quarantined=int(d.get('quarantined', 0)), hard_rejected=int(d.get('rejected', 0)), deprecated=int(d.get('deprecated', 0)))
        elif kind == 'candidate.classified':
            r = runs.setdefault(rid, {'rejected': 0}); r['performance'] = {k: d[k] for k in ('classify_seconds', 'gate_seconds', 'scan_p95_s', 'compile_rss_mb', 'scan_rss_peak_mb', 'engine') if k in d}
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
            days.append({'date': day, 'observed': False, 'examined': None, 'accepted': None, 'quarantined': None, 'rejected': None, 'deprecated': None, 'accounting_ok': None, 'performance': None, 'new': c[0] if c else None, 'modified': c[1] if c else None, 'removed': c[2] if c else None})
            continue
        if 'quarantined' in r:
            accepted, quarantined, rejected, deprecated = r['accepted'], r['quarantined'], r['hard_rejected'], r.get('deprecated', 0)
            ok = not accounting.violations({'examined': r['examined'], 'accepted': accepted, 'quarantined': quarantined, 'rejected': rejected, 'deprecated': deprecated})
        else:   # earlier runs did not separate quarantine from rejection: no breakdown, so no invariant to check
            rejected = min(r['rejected'], r['examined']); accepted, quarantined, deprecated, ok = r['examined'] - rejected, None, None, None
        days.append({'date': day, 'observed': True, 'examined': r['examined'], 'accepted': accepted, 'quarantined': quarantined, 'rejected': rejected, 'deprecated': deprecated, 'accounting_ok': ok, 'performance': r.get('performance'),
                     'new': c[0] if c else None, 'modified': c[1] if c else None, 'removed': c[2] if c else None})
    return days

def build(log_file: pathlib.Path, out: pathlib.Path, now: datetime = None, releases=None):
    now = now or datetime.now(timezone.utc)
    entries = [json.loads(l) for l in log_file.read_text().splitlines() if l] if log_file.exists() else []
    days_ = daily(entries, now.date(), releases=releases)
    broken = [(d['date'], accounting.violations(d)) for d in days_ if d['accounting_ok'] is False]
    if broken: raise ValueError('refusing to publish statistics that violate examined = accepted + quarantined + rejected + deprecated: ' + json.dumps(broken))
    doc = {'schema': 1, 'generated_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'window_days': WINDOW, 'days': days_, 'unit': 'rule files examined by one analysis run; one run per day is shown (the last), never a mix of runs',
           'definitions': {'examined': 'rule files the pipeline looked at in the last run of the day', 'accepted': 'files that passed every check and are in the candidate', 'quarantined': 'files held for human review (null for runs before the quarantine existed)', 'rejected': 'files refused outright (hard criteria)', 'performance': 'durations and engine measurements of that run, aggregate only',
                           'new_modified_removed': 'from comparing the manifests of releases published that day', 'observed': 'false = no pipeline run that day (not zero rules)',
                           'downloads': 'not measured: this site has no download telemetry'}}
    out.write_text(json.dumps(doc, indent=1) + '\n')
    return doc

if __name__ == '__main__':
    root = pathlib.Path(__file__).resolve().parents[1]
    build(root / 'logs' / 'log.jsonl', root / 'site' / 'stats.json')
