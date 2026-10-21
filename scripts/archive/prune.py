"""Prune READINESS dry run. This module can only READ and REPORT; deleting audit rows from D1 is deliberately not implemented anywhere in the repository
(it needs a controlled migration, a separate credential and the owner's authorization). `executed` is always False.

A period is ready only when ALL of: (a) its seal verifies against the segment; (b) the sealed objects are in all three providers and verified by read-back;
(c) a restore rehearsal for this very seal passed; (d) a later seal exists that continues from it; (e) the live database already holds the anchor for it;
(f) the owner's written authorization for this seal is present; and it is never the newest period."""
import json

from .canon import seal_sha256
from .providers import ProviderError
from .segment import SegmentError, verify_segment, verify_seal_chain
from .store import ArchiveError, read_unit


def check_period(providers, period, rehearsal: dict, d1_anchors: list, authorization: dict = None, all_periods: list = None) -> dict:
    checks, seal = {}, None
    def rec(name, ok, detail=''): checks[name] = {'pass': bool(ok), 'detail': detail}
    names = sorted(all_periods or [])
    try:
        copies = []
        for p in providers:
            idx, files = read_unit(p, 'audit', period)
            copies.append((p.name, json.loads(files['seal.json']), idx))
        seal = copies[0][1]
        same = all(s == seal for _, s, _ in copies) and len({json.dumps(i['files'], sort_keys=True) for _, _, i in copies}) == 1
        rec('a_b_three_verified_copies', len(copies) == 3 and same, f'{len(copies)} providers read back; identical={same}')
    except (ProviderError, ArchiveError, ValueError, KeyError) as e:
        rec('a_b_three_verified_copies', False, f'{type(e).__name__}: {str(e)[:200]}')
    if seal:
        s = seal_sha256(seal)
        rec('c_restore_rehearsed', bool(rehearsal and rehearsal.get('ok') and rehearsal.get('seal_sha256') == s and rehearsal.get('segment_sha256') == seal['segment_sha256']), 'rehearsal report must name this seal')
        later = []
        try:
            for n in names:
                if n > period:
                    later.append(json.loads(read_unit(providers[0], 'audit', n)[1]['seal.json']))
            ok = bool(later)
            if ok: verify_seal_chain([seal, later[0]], seal['first_prev_hash'])
            rec('d_next_seal_continues', ok, f'{len(later)} later seals')
        except (ProviderError, ArchiveError, SegmentError, ValueError, KeyError) as e:
            rec('d_next_seal_continues', False, str(e)[:200])
        rec('e_anchor_in_database', any(a.get('seq') == seal['last_seq'] and a.get('hash') == seal['head_hash'] and a.get('seal_sha256') == s for a in d1_anchors or []), 'anchor row must equal the seal')
        rec('f_owner_authorization', bool(authorization and authorization.get('seal_sha256') == s and authorization.get('approver') and authorization.get('approved') is True), 'written authorization naming this seal')
        rec('not_newest_period', bool(names) and period != names[-1], 'the newest period is never pruned')
    else:
        for k in ('c_restore_rehearsed', 'd_next_seal_continues', 'e_anchor_in_database', 'f_owner_authorization', 'not_newest_period'): rec(k, False, 'no seal')
    ready = all(c['pass'] for c in checks.values())
    return {'period': period, 'ready': ready, 'executed': False, 'checks': checks,
            'would_prune': {'first_seq': seal['first_seq'], 'last_seq': seal['last_seq'], 'rows': seal['count']} if seal else None,
            'note': 'dry run only: no deletion exists in this tool'}
