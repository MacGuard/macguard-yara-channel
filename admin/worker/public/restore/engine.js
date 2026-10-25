// The logic that turns the recovery procedures into safe commands and checks: no runbook content lives here, so this file may be public. It is created over the data that the panel receives after sign-in
// (GET /api/restore/procedures) and over the same data in the tests and in the offline guide. Nothing here executes anything.

const SAFE_BARE = /^[A-Za-z0-9._\/@:=+~-]+$/;
export const shellQuote = (v) => (SAFE_BARE.test(v) ? v : `'${String(v).replace(/'/g, `'\\''`)}'`);
export const placeholdersOf = (template) => [...new Set([...template.matchAll(/\{([A-Za-z][A-Za-z0-9]*)\}/g)].map((m) => m[1]))];

/** `{source, flags}` pairs coming from JSON become RegExp objects again; RegExp objects pass through. */
export function reviveParams(params) { return Object.fromEntries(Object.entries(params).map(([k, p]) => [k, { ...p, re: p.re instanceof RegExp ? p.re : new RegExp(p.re.source, p.re.flags || '') }])); }

export function createEngine({ PARAMS, STEPS, PROCEDURES }) {
  /** Validates a map of values against PARAMS; returns {ok, errors}. Unknown names are errors. */
  function validateValues(values, names = null) {
    const errors = {};
    for (const [k, v] of Object.entries(values)) {
      const p = PARAMS[k]; if (!p) { errors[k] = 'unknown parameter'; continue; }
      if (typeof v !== 'string' || v.length === 0 || v.length > 300 || /[\r\n\0]/.test(v) || !p.re.test(v)) errors[k] = 'invalid';
    }
    for (const n of names || []) if (!(n in values)) errors[n] = 'missing';
    return { ok: Object.keys(errors).length === 0, errors };
  }
  /** Fills a template. Every {name} needs a declared, valid value; anything else throws. The result is built from tokens, never from free text. */
  function renderCommand(template, values) {
    return template.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (_, name) => {
      const p = PARAMS[name]; if (!p) throw new Error(`placeholder {${name}} has no declared parameter`);
      const v = values[name]; if (typeof v !== 'string' || !p.re.test(v) || /[\r\n\0]/.test(v)) throw new Error(`parameter ${name} is missing or invalid`);
      return shellQuote(v);
    });
  }
  const stepsOf = (procId) => PROCEDURES[procId].steps.map((id) => ({ id, ...STEPS[id] }));
  /** Does the pasted output satisfy the step? Never true for a step without a pattern: those need an attestation. */
  function checkOutput(step, text) {
    if (!step || !step.expected || !step.expected.pattern) return { ok: false, reason: 'no_pattern' };
    if (typeof text !== 'string' || !text.trim()) return { ok: false, reason: 'empty' };
    if (/AGE-SECRET-KEY-|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[ps]_[A-Za-z0-9]{20,}|github_pat_/.test(text)) return { ok: false, reason: 'secret_in_output' };      // a pasted secret is refused and never kept
    let re; try { re = new RegExp(step.expected.pattern); } catch { return { ok: false, reason: 'bad_pattern' }; }
    return re.test(text.trim()) ? { ok: true } : { ok: false, reason: 'mismatch' };
  }
  /** The prerequisites of this step that belong to the procedure and are not done yet. */
  function blockedBy(procId, stepId, done) {
    const ids = PROCEDURES[procId].steps, need = (STEPS[stepId].prereq || []).filter((p) => ids.includes(p));
    const ok = (p) => (done[p] && done[p].state === 'done') || (STEPS[p].alt || []).some((a) => done[a] && done[a].state === 'done');       // an alternative path (e.g. download from the run instead of from the provider) satisfies the step
    return need.filter((p) => !ok(p));
  }
  return { validateValues, renderCommand, placeholdersOf, checkOutput, blockedBy, stepsOf, shellQuote };
}
