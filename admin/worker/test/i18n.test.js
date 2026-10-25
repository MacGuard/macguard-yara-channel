// The two languages stay complete and in step: same keys, same placeholders, and every key the UI code asks for exists.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

globalThis.document = { documentElement: {} }; globalThis.localStorage = { getItem: () => null, setItem() {} }; Object.defineProperty(globalThis, 'navigator', { value: { language: 'es' }, configurable: true });
const { DICT } = await import('../public/i18n.js');
const ph = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');

test('Spanish and English have exactly the same keys and placeholders', () => {
  const es = Object.keys(DICT.es), en = Object.keys(DICT.en);
  assert.deepEqual(es.filter((k) => !(k in DICT.en)), [], 'missing in English'); assert.deepEqual(en.filter((k) => !(k in DICT.es)), [], 'missing in Spanish');
  for (const k of es) assert.equal(ph(DICT.es[k]), ph(DICT.en[k]), `placeholders of ${k}`);
  for (const l of ['es', 'en']) for (const k of Object.keys(DICT[l])) assert.ok(String(DICT[l][k]).trim().length > 0, `${l}.${k} is empty`);
});

test('every translation key used by the screens exists, including the dynamic families', () => {
  const dir = new URL('../public/', import.meta.url), files = [...readdirSync(dir).filter((f) => f.endsWith('.js')).map((f) => new URL(f, dir)), ...readdirSync(new URL('views/', dir)).map((f) => new URL(`views/${f}`, dir))];
  const src = files.map((f) => readFileSync(f, 'utf8')).join('\n'); const used = new Set([...src.matchAll(/\bt\('([A-Za-z0-9_]+)'/g)].map((m) => m[1]));
  const families = { st_: ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION', 'REJECTED', 'RELEASED'], st_short_: ['PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION', 'REJECTED', 'RELEASED'], role_: ['ADMIN', 'REVIEWER', 'VIEWER', 'NONE'], rh_: ['ADMIN', 'REVIEWER', 'VIEWER'],
    ds_: ['OK', 'WARNING', 'FAIL', 'CANCELLED', 'RUNNING', 'NO_RUN', 'PENDING', 'BEFORE'], dsd_: ['OK', 'WARNING', 'FAIL', 'CANCELLED', 'RUNNING', 'NO_RUN', 'PENDING'], cc_: ['success', 'failure', 'cancelled', 'timed_out', 'skipped', 'neutral', 'action_required', 'startup_failure', 'stale'],
    act_: ['approve', 'reject', 'hold', 'retest'], act_approve_: ['h', 'p'], f_: ['all', 'decision', 'access', 'session', 'member', 'pipeline', 'retest'], ms_: ['all', 'authorized', 'unauthorized', 'revoked', 'unbound'], ms_state_: ['authorized', 'unauthorized', 'revoked', 'unbound'], org_: ['repo', 'manual', 'both', 'none'], sk_: ['rules', 'engine'],
    src_: ['runs', 'publish_runs', 'releases', 'stats', 'log', 'sources'], why_src_: ['rate_limited', 'unreachable', 'malformed', 'too_large'], mx_src_: ['VIEWER', 'REVIEWER', 'ADMIN'], rs_: ['withheld', 'accounting'], ev_: ['session_login', 'access_view', 'decision_approve', 'decision_reject', 'decision_hold', 'decision_review', 'decision_release_review', 'retest_requested', 'member_set', 'pipeline_submit', 'pipeline_released', 'pipeline_revalidation_failed', 'other'] };
  for (const [p, vs] of Object.entries(families)) for (const v of vs) used.add(p === 'act_approve_' ? `act_approve_${v}` : `${p}${v}`);
  for (const a of ['approve', 'reject', 'hold']) { used.add(`act_${a}_h`); used.add(`act_${a}_p`); }
  const missing = [...used].filter((k) => !(k in DICT.es) || !(k in DICT.en)).filter((k) => !/_$/.test(k)); assert.deepEqual(missing, []);
  const reasons = ['blocked-module', 'compile-dependency', 'compile-error', 'corrupt-encoding', 'costly-regex', 'dependency-not-validated', 'dynamic-failure', 'ends-mid-file', 'filesize-loop', 'license-changed', 'license-unchecked', 'many-loops', 'matches-benign-corpus', 'no-baseline', 'no-condition', 'previously-rejected', 'rejected-by-reviewer', 'waived-by-review', 'too-many-rules', 'unbalanced-braces', 'unclosed-rule', 'unknown-module', 'unterminated-comment', 'unterminated-regex', 'unterminated-string'];
  assert.deepEqual(reasons.map((r) => `why_${r.replace(/-/g, '_')}`).filter((k) => !(k in DICT.es) || !(k in DICT.en)), [], 'every reason code the pipeline emits is translated');
});

test('no key is defined twice inside one language: a later duplicate silently replaces the earlier text (it once turned the sign-in title into "Inteligencia")', () => {
  const src = readFileSync(new URL('../public/i18n.js', import.meta.url), 'utf8'), parts = src.split(/\n  (?:es|en): \{/).slice(1), KNOWN = new Set(['confirm']);   // 'confirm' is two real keys that predate this check, kept visible rather than hidden
  parts.forEach((p, i) => { const seen = new Map(); for (const m of p.matchAll(/(?:^|[\s,{])([a-z][A-Za-z0-9_]*):\s*['"`]/g)) seen.set(m[1], (seen.get(m[1]) || 0) + 1); const dup = [...seen].filter(([k, n]) => n > 1 && !KNOWN.has(k)).map(([k]) => k); assert.deepEqual(dup, [], `duplicate keys in language block ${i + 1}`); });
});
