#!/usr/bin/env python3
"""Daily rule counts for the site chart, derived from the transparency log.

Per UTC day: the last candidate of that day decides `downloaded` (rule files fetched), `rejected`
(files the compiler refused) and `accepted` (downloaded - rejected). Only the last WINDOW days are kept."""
import json, pathlib
from datetime import date, datetime, timedelta, timezone
WINDOW = 30

def daily(entries, today: date, window: int = WINDOW):
    runs = {}   # run_id -> {day, time, downloaded, rejected}
    for e in entries:
        rid, kind, d = e.get('run_id'), e.get('event'), e.get('details', {})
        if not rid or not e.get('time'): continue
        if kind in ('candidate.accepted', 'candidate.rejected'):
            r = runs.setdefault(rid, {'rejected': 0})
            r.update(day=e['time'][:10], time=e['time'], downloaded=int(d.get('file_count', 0)))
        elif kind == 'rule.rejected':
            runs.setdefault(rid, {'rejected': 0})['rejected'] += 1
    last = {}
    for r in runs.values():
        if 'day' not in r: continue
        if r['day'] not in last or r['time'] >= last[r['day']]['time']: last[r['day']] = r
    days = []
    for i in range(window - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat(); r = last.get(day)
        downloaded = r['downloaded'] if r else 0; rejected = min(r['rejected'], downloaded) if r else 0
        days.append({'date': day, 'downloaded': downloaded, 'accepted': downloaded - rejected, 'rejected': rejected})
    return days

def build(log_file: pathlib.Path, out: pathlib.Path, now: datetime = None):
    now = now or datetime.now(timezone.utc)
    entries = [json.loads(l) for l in log_file.read_text().splitlines() if l] if log_file.exists() else []
    doc = {'schema': 1, 'generated_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'window_days': WINDOW, 'days': daily(entries, now.date())}
    out.write_text(json.dumps(doc, indent=1) + '\n')
    return doc

if __name__ == '__main__':
    root = pathlib.Path(__file__).resolve().parents[1]
    build(root / 'logs' / 'log.jsonl', root / 'site' / 'stats.json')
