#!/usr/bin/env python3
"""Static admission checks for YARA rule files. Classifies every candidate file and never executes anything from it.

States
  VALIDATED    passed every mandatory check
  QUARANTINED  needs a human or a retest: truncated, corrupt, does not compile for a fixable reason, unknown license,
               risky regex/condition, forbidden or unknown module, depends on something that is not VALIDATED
  REJECTED     can never be valid for us: binary, empty, no rules, oversized, license not redistributable
  DEPRECATED   marked deprecated by its own metadata, or no longer present upstream (set by decide.py, not here)

Judgement calls (risky regex, slow condition) only ever quarantine. Only hard criteria reject.
The real cost of a rule is decided by the dynamic benchmark (bench.py), not by these heuristics."""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile

VALIDATED, QUARANTINED, REJECTED, DEPRECATED = 'VALIDATED', 'QUARANTINED', 'REJECTED', 'DEPRECATED'
EXTERNALS = ['-d', 'filepath=', '-d', 'filename=', '-d', 'extension=', '-d', 'filetype=', '-d', 'owner=', '-d', 'md5=']
RULE_HEAD = re.compile(r'^[ \t]*((?:(?:private|global)[ \t]+)*)rule[ \t]+(\w+)([^{]*)\{', re.M)
KEYWORDS = set('all and any ascii at base64 base64wide condition contains endswith entrypoint false filesize for fullword global icontains iendswith import in include int16 int16be int32 int32be int8 int8be istartswith matches meta nocase none not of or private rule startswith strings them true uint16 uint16be uint32 uint32be uint8 uint8be wide xor defined'.split())

def sha256(b: bytes) -> str: return hashlib.sha256(b).hexdigest()

def finding(code, severity, detail, **measured):
    """`measured` (observed, threshold, unit) is set only where the check really measures something; a finding that is a yes/no test carries just its detail."""
    return {'code': code, 'severity': severity, 'detail': detail, **measured}

# ---- lexical pass --------------------------------------------------------------------------
def strip(text: str):
    """Return (code, problems, regexes): text with comments and string/regex contents blanked, plus lexical problems."""
    out, problems, regexes = [], [], []
    i, n, line = 0, len(text), 1
    def blank(s): return ''.join('\n' if c == '\n' else ' ' for c in s)
    while i < n:
        c = text[i]
        if c == '/' and text.startswith('//', i):
            j = text.find('\n', i); j = n if j < 0 else j; out.append(blank(text[i:j])); i = j
        elif c == '/' and text.startswith('/*', i):
            j = text.find('*/', i + 2)
            if j < 0: problems.append(finding('unterminated-comment', 'truncated', f'block comment opened at line {line} never closes')); out.append(blank(text[i:])); i = n
            else: out.append(blank(text[i:j + 2])); line += text[i:j + 2].count('\n'); i = j + 2
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            if j >= n or text[j] != '"': problems.append(finding('unterminated-string', 'truncated', f'string starting at line {line} is not closed')); out.append(blank(text[i:j])); i = j
            else: out.append('"' + blank(text[i + 1:j]) + '"'); i = j + 1
        elif c == '/' and re.search(r'(?:=|matches|\()\s*$', text[max(0, i - 12):i]):
            j = i + 1
            while j < n and text[j] != '/' and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            if j >= n or text[j] != '/': problems.append(finding('unterminated-regex', 'truncated', f'regular expression at line {line} is not closed')); out.append(blank(text[i:j])); i = j
            else: regexes.append(text[i + 1:j]); out.append('/' + blank(text[i + 1:j]) + '/'); i = j + 1
        else:
            if c == '\n': line += 1
            out.append(c); i += 1
    return ''.join(out), problems, regexes

def rule_blocks(code: str):
    """[(name, modifiers, start, end, body)] with brace matching on comment/string-free code. end is -1 for an unclosed rule."""
    blocks = []
    for m in RULE_HEAD.finditer(code):
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += (code[j] == '{') - (code[j] == '}'); j += 1
        blocks.append((m.group(2), m.group(1).split(), m.start(), j if depth == 0 else -1, code[m.end():j - 1] if depth == 0 else code[m.end():]))
    return blocks

def regex_risk(rx: str, policy: dict) -> (int, list):
    score, why = 0, []
    if re.search(r'\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]|\((?:[^()\\]|\\.)*[+*]\)\{\d+,\d*\}', rx): score += 9; why.append('nested quantifier')
    unbounded = len(re.findall(r'\.[*+]', rx))
    if unbounded >= 2: score += 3; why.append(f'{unbounded} unbounded .* / .+ runs')
    elif unbounded == 1 and rx.startswith('.*'): score += 2; why.append('leading .*')
    for lo, hi in re.findall(r'\{(\d*),(\d+)\}', rx):
        if int(hi) >= policy['regex']['wide_gap']: score += 4; why.append(f'gap up to {hi}')
    if re.search(r'\{\d+,\}', rx): score += 3; why.append('open-ended repetition')
    return score, why

def analyse_text(text: str, policy: dict) -> dict:
    """Pure analysis of one file's source. No compiler involved."""
    f = []
    code, problems, regexes = strip(text)
    f += problems
    # only code outside strings and comments counts: raw control bytes inside a string literal are unusual but valid YARA
    if '\ufffd' in code or re.search(r'[\x00-\x08\x0e-\x1f]', code): f.append(finding('corrupt-encoding', 'corrupt', 'replacement or control characters in the code itself: the file looks damaged'))
    blocks = rule_blocks(code)
    if not blocks and not problems: f.append(finding('no-rules', 'reject', 'no rule declaration found'))
    for name, mods, start, end, body in blocks:
        if end < 0: f.append(finding('unclosed-rule', 'truncated', f'rule {name} is not closed: the file ends inside it'))
        elif not re.search(r'\bcondition\s*:', body): f.append(finding('no-condition', 'corrupt', f'rule {name} has no condition section'))
    opens, closes = code.count('{'), code.count('}')
    if opens != closes and not any(x['code'] == 'unclosed-rule' for x in f): f.append(finding('unbalanced-braces', 'truncated', f'{opens} opening and {closes} closing braces'))
    tail = code.rstrip()
    if blocks and not tail.endswith('}') and not any(x['code'] in ('unclosed-rule', 'unterminated-string', 'unterminated-comment') for x in f): f.append(finding('ends-mid-file', 'truncated', 'the file does not end with a closed rule'))
    imports = sorted(set(re.findall(r'^\s*import\s+"(\w+)"', text, re.M)))
    includes = sorted(set(re.findall(r'^\s*include\s+"([^"]+)"', text, re.M)))
    for mod in imports:
        if mod in policy['blocked_modules']: f.append(finding('blocked-module', 'review', f'module "{mod}" needs external libraries and is not allowed', observed=mod, unit='module'))
        elif mod not in policy['allowed_modules']: f.append(finding('unknown-module', 'review', f'module "{mod}" is not on the allowed list', observed=mod, unit='module'))
    for inc in includes: f.append(finding('include', 'review', f'include "{inc}" pulls in another file'))
    worst = 0
    for rx in regexes:
        s, why = regex_risk(rx, policy); worst = max(worst, s)
        if s >= policy['regex']['max_risk_score']: f.append(finding('costly-regex', 'review', f'regex /{rx[:80]}/ risk {s}: {", ".join(why)}', observed=s, threshold=policy['regex']['max_risk_score'], unit='risk score'))
    loops = 0
    for name, mods, start, end, body in blocks:
        cond = body.split('condition', 1)[1] if 'condition' in body else ''
        loops = max(loops, len(re.findall(r'\bfor\b', cond)))
        if policy['condition']['forbid_filesize_loops'] and re.search(r'\bin\s*\(\s*[\w\d]+\s*\.\.\s*(?:filesize|#\w+|\w+\s*-\s*\d+)\s*\)', cond) and 'filesize' in cond: f.append(finding('filesize-loop', 'review', f'rule {name} iterates over the whole file in its condition'))
        if len(re.findall(r'\bfor\b', cond)) > policy['condition']['max_for_loops']: f.append(finding('many-loops', 'review', f'rule {name} has {len(re.findall(r"\bfor\b", cond))} loops', observed=len(re.findall(r'\bfor\b', cond)), threshold=policy['condition']['max_for_loops'], unit='for loops'))
    names = [b[0] for b in blocks]
    deprecated = bool(re.search(r'\b(?:deprecated|status)\s*=\s*(?:true|"deprecated")', text, re.I))
    if len(blocks) > policy['limits']['max_rules_per_file']: f.append(finding('too-many-rules', 'reject', f'{len(blocks)} rules in one file'))
    return {'findings': f, 'rules': names, 'imports': imports, 'includes': includes, 'deprecated': deprecated,
            'metrics': {'rules': len(blocks), 'regexes': len(regexes), 'worst_regex_risk': worst, 'max_for_loops': loops},
            'conditions': {n: sorted(set(re.findall(r'\b[A-Za-z_]\w*\b', (b.split('condition', 1)[1] if 'condition' in b else '')))) for n, _, _, _, b in blocks}}

# ---- compiler ------------------------------------------------------------------------------
def engine_version(binary: str) -> str:
    try: return subprocess.run([binary.replace('yarac', 'yara'), '--version'], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception: return ''

def compile_file(engine: str, files: list, defines: dict, root: pathlib.Path, timeout: int = 20):
    """Compile `files[-1]` together with the files that define rules it needs. Returns (ok, stderr, used_files)."""
    paths = list(files)
    for _ in range(6):
        cp = subprocess.run([engine, '-w', *EXTERNALS, *[str(root / p) for p in paths], os.devnull], capture_output=True, text=True, timeout=timeout)
        missing = re.findall(r'undefined identifier "(\w+)"', cp.stderr)
        extra = [defines[m] for m in dict.fromkeys(missing) if m in defines and defines[m] not in paths]
        if cp.returncode and extra: paths = extra + paths; continue
        return cp.returncode == 0, cp.stderr[-600:], paths
    return False, cp.stderr[-600:], paths

def classify(entries: list, root: pathlib.Path, policy: dict, engines: list, sources: dict = None, rejected_hashes: set = None, previous: dict = None) -> list:
    """entries: [{'path','source','sha256','bytes'}]; returns the same dicts extended with state, reasons and analysis."""
    sources = sources or {}; rejected_hashes = rejected_hashes or set(); previous = previous or {}
    texts, out = {}, []
    for e in entries:
        raw = (root / e['path']).read_bytes()
        texts[e['path']] = raw.decode('utf-8', 'replace')
    analysis = {e['path']: analyse_text(texts[e['path']], policy) for e in entries}
    defines = {}
    for p, a in analysis.items():
        for n in a['rules']: defines.setdefault(n, p)
    all_names = set(defines)
    for e in entries:
        a = analysis[e['path']]; reasons = list(a['findings']); raw_len = e['bytes']
        if raw_len > policy['limits']['max_file_bytes']: reasons.append(finding('oversized', 'reject', f'{raw_len} bytes'))
        if b'\x00' in (root / e['path']).read_bytes(): reasons.append(finding('binary', 'reject', 'NUL bytes: not a text rule file'))
        lic = sources.get(e['source'], {}).get('license_check')
        if lic and not lic.get('ok'): reasons.append(finding('license-changed', 'review', lic.get('detail', 'license could not be confirmed')))
        elif e['source'] in policy['licenses'] and not lic and sources: reasons.append(finding('license-unchecked', 'review', 'no license evidence recorded for the source'))
        if e['sha256'] in rejected_hashes: reasons.append(finding('previously-rejected', 'reject', 'identical content was rejected before and nothing changed'))
        # dependencies: other files whose rules this one references
        deps = sorted({defines[n] for r_, idents in a['conditions'].items() for n in idents if n in all_names and defines[n] != e['path'] and n not in a['rules']})
        e_deps = deps
        # compile under every configured engine
        compiled = {}
        if not any(r['severity'] in ('truncated', 'corrupt', 'reject') for r in reasons):
            for eng in engines:
                try: ok, err, used = compile_file(eng['binary'], [e['path']], defines, root)
                except subprocess.TimeoutExpired: ok, err, used = False, 'compile timeout', [e['path']]
                compiled[eng['name']] = {'ok': ok, 'version': eng.get('version', ''), 'used': [u for u in used if u != e['path']]}
                if not ok:
                    code = 'compile-dependency' if re.search(r'undefined identifier|unknown module|could not open file', err) else 'compile-error'
                    reasons.append(finding(code, 'review' if code == 'compile-dependency' else 'corrupt', f"{eng['name']} {eng.get('version','')}: {err.strip().splitlines()[-1] if err.strip() else 'failed'}"))
                for u in used:
                    if u != e['path'] and u not in e_deps: e_deps = sorted(set(e_deps) | {u})
        if not engines: reasons.append(finding('no-engine', 'review', 'no YARA compiler available: the file was not compiled'))
        sev = {r['severity'] for r in reasons}
        state = REJECTED if 'reject' in sev else QUARANTINED if sev & {'truncated', 'corrupt', 'review'} else VALIDATED
        if state == VALIDATED and a['deprecated']: state = DEPRECATED
        out.append({**e, 'state': state, 'reasons': reasons, 'rules': a['rules'], 'imports': a['imports'], 'depends_on': e_deps, 'metrics': a['metrics'], 'compiled': compiled})
    # a file that needs a non-validated file cannot be validated (transitive)
    by = {o['path']: o for o in out}
    changed = True
    while changed:
        changed = False
        for o in out:
            if o['state'] == VALIDATED and any(by[d]['state'] != VALIDATED for d in o['depends_on'] if d in by):
                bad = [d for d in o['depends_on'] if d in by and by[d]['state'] != VALIDATED]
                o['state'] = QUARANTINED; o['reasons'].append(finding('dependency-not-validated', 'review', f'depends on {bad[0]} which is {by[bad[0]]["state"]}')); changed = True
    return out

def infer_deps(root: pathlib.Path, paths: list, policy: dict) -> dict:
    """File -> files defining rules it references, from the sources alone (no compiler). Used for a set that was not classified now,
    e.g. the previous release used as the performance baseline."""
    analysis = {p: analyse_text((root / p).read_text(errors='replace'), policy) for p in paths}
    defines = {}
    for p, a in analysis.items():
        for n in a['rules']: defines.setdefault(n, p)
    return {p: sorted({defines[n] for idents in a['conditions'].values() for n in idents if n in defines and defines[n] != p and n not in a['rules']}) for p, a in analysis.items()}

def summary(classified: list) -> dict:
    c = {s: 0 for s in (VALIDATED, QUARANTINED, REJECTED, DEPRECATED)}
    for o in classified: c[o['state']] += 1
    return c

def find_engines(paths: list) -> list:
    res = []
    for p in paths:
        b = shutil.which(p) or (p if os.path.isfile(p) else None)
        if b: res.append({'name': 'yara', 'binary': b, 'version': engine_version(b)})
    return res

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--dist', default='dist'); ap.add_argument('--policy', default='config/policy.json'); ap.add_argument('--engine', action='append', default=['yarac'])
    ap.add_argument('--out'); ap.add_argument('--rejected', help='JSON list of rejected content hashes'); ap.add_argument('--sources')
    a = ap.parse_args(); dist = pathlib.Path(a.dist)
    cand = json.loads((dist / 'candidate.json').read_text()); policy = json.loads(pathlib.Path(a.policy).read_text())
    rej = set(json.loads(pathlib.Path(a.rejected).read_text())) if a.rejected and os.path.exists(a.rejected) else set()
    engines = find_engines(a.engine)
    res = classify(cand['files'], dist, policy, engines, {s['id']: s for s in cand.get('sources', [])}, rej)
    doc = {'schema': 1, 'engines': [{k: e[k] for k in ('name', 'version')} for e in engines], 'summary': summary(res), 'files': res}
    pathlib.Path(a.out or dist / 'classification.json').write_text(json.dumps(doc, indent=1) + '\n')
    print(json.dumps(doc['summary']), file=sys.stderr)
