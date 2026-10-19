import json,sys,collections
f=sys.argv[1]
r=json.load(open(f))
viol=collections.defaultdict(lambda: collections.defaultdict(list))
for k,v in r.items():
    if v.get('error'): print('ERR',k,v['error'])
    if v.get('console') or v.get('pageerrors') or v.get('failed') or v.get('bad'): print('CONSOLE/NET',k,v['console'][:3],v['pageerrors'][:2],v['failed'][:2],v['bad'][:3])
    ext=[o for o in v['origins'] if 'macguard' not in o]
    if ext: print('EXTERNAL',k,ext)
    if k.endswith('d1280') or k.endswith('m390'):
        for a in v['axe']['violations']:
            viol[a['id']][a['impact']].append((k,a['n'],a['sample'][0]['t'] if a['sample'] else '',a['sample'][0]['s'][:200] if a['sample'] else ''))
    o=v.get('overflow')
    if o and o['sw']>o['cw']+1: print('HSCROLL',k,o,v.get('clipped'))
    if v.get('clipped') and not k.endswith('d1280'): print('CLIPPED',k,v['clipped'][:4])
    if 'tab' in v: print('TAB',k,'count',v['tabCount'],'unique',v['tabUnique'],'noIndicator',v['tabNoIndicator'][:5])
for i,d in viol.items():
    print('\nAXE',i)
    for imp,l in d.items():
        for x in l[:20]: print('  ',imp,x)
for k,v in r.items():
    if k.endswith('d1280') and 'cf' in k[:2]: pass
print('\nINCOMPLETE (sample)')
inc=collections.defaultdict(set)
for k,v in r.items():
    if 'axe' in v:
        for a in v['axe']['incomplete']: inc[a['id']].add(k)
for i,s in inc.items(): print(i,len(s))
