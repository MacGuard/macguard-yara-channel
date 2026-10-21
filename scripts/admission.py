#!/usr/bin/env python3
"""First run of a new rules source: held in quarantine until an ADMIN authorizes it (docs/audit/source-proposals-spec.md, section 10.2).

decide.decide() calls held_sources() and quarantines every file of a held source with the finding `new-source`, which is waivable only by an ADMIN
decision in the private panel (the Worker refuses the approval of a `new-source` candidate from any other role). A held source adds nothing to the release,
so the anomaly gate does not move. Two independent conditions, either one holds a source:

  1. `admission: "probation"` in config/sources.json: stateless, lives in Git, also holds files the source adds later and survives a partial approval.
     Every source a proposal adds carries it; ending probation is a reviewed pull request that removes the key.
  2. fail-safe for a source added by hand without the key: none of its files is in the previous release. It needs a non-empty previous release
     (daily.yml runs with an empty one when the download fails, and holding every source on a transient failure would flood the panel).

The hook is inert (nothing is held) unless the caller passes the source records, so decide.decide() keeps its previous behaviour for every existing caller.
Sources without files (kind engine) never reach the classification, so they are never held.
"""
import json, pathlib

NEW_SOURCE = 'new-source'


def load_sources(path='config/sources.json'):
    """id -> source record, from the file the pipeline already reads."""
    cfg = json.loads(pathlib.Path(path).read_text())
    return {s['id']: s for s in cfg.get('sources', [])}


def held_sources(classified, previous_files, sources):
    """Source ids whose files may not enter the release without an ADMIN decision.

    classified: the classification entries (each has 'source'); previous_files: paths of the previous release (rules/<source id>/...);
    sources: id -> record from config/sources.json, or None to leave the hook off."""
    if sources is None:
        return set()
    previous_files = list(previous_files or [])
    held = set()
    for sid in {c['source'] for c in classified}:
        probation = (sources.get(sid) or {}).get('admission') == 'probation'
        never_released = bool(previous_files) and not any(p.startswith(f'rules/{sid}/') for p in previous_files)
        if probation or never_released:
            held.add(sid)
    return held
