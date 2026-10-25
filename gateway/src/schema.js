// A small JSON Schema subset validator (type, properties, required, additionalProperties, pattern, length/size bounds, enum, items, integer bounds). Enough for the tool inputs
// declared here; anything it does not understand is a validation error, never silently accepted.
const KNOWN = new Set(['const', 'oneOf', 'type', 'properties', 'required', 'additionalProperties', 'pattern', 'minLength', 'maxLength', 'minItems', 'maxItems', 'items', 'enum', 'minimum', 'maximum', 'description', 'title', 'default', 'examples', '$schema']);
export function validate(schema, v, path = 'arguments') {
  const bad = Object.keys(schema).filter((k) => !KNOWN.has(k)); if (bad.length) return [`${path}: unsupported schema keyword ${bad[0]}`];
  const e = [], kind = v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v;
  const types = schema.type === undefined ? null : [].concat(schema.type);
  if (types && !types.some((t) => t === kind || (t === 'number' && kind === 'integer'))) return [`${path}: expected ${types.join(' or ')}`];
  if ('const' in schema && schema.const !== v) return [`${path}: must equal ${JSON.stringify(schema.const)}`];
  if (schema.oneOf) { const ok = schema.oneOf.filter((sub) => validate(sub, v, path).length === 0).length; if (ok !== 1) return [`${path}: must match exactly one alternative (matched ${ok})`]; }
  if (schema.enum && !schema.enum.includes(v)) e.push(`${path}: not one of the allowed values`);
  if (kind === 'string') { if (schema.minLength !== undefined && v.length < schema.minLength) e.push(`${path}: too short`); if (schema.maxLength !== undefined && v.length > schema.maxLength) e.push(`${path}: too long`); if (schema.pattern && !new RegExp(schema.pattern).test(v)) e.push(`${path}: does not match the expected format`); }
  if (kind === 'integer') { if (schema.minimum !== undefined && v < schema.minimum) e.push(`${path}: below the minimum`); if (schema.maximum !== undefined && v > schema.maximum) e.push(`${path}: above the maximum`); }
  if (kind === 'array') { if (schema.minItems !== undefined && v.length < schema.minItems) e.push(`${path}: too few items`); if (schema.maxItems !== undefined && v.length > schema.maxItems) e.push(`${path}: too many items`); if (schema.items) v.forEach((x, i) => e.push(...validate(schema.items, x, `${path}[${i}]`))); }
  if (kind === 'object') {
    for (const r of schema.required || []) if (!(r in v)) e.push(`${path}.${r}: required`);
    for (const [k, x] of Object.entries(v)) { if (schema.properties?.[k]) e.push(...validate(schema.properties[k], x, `${path}.${k}`)); else if (schema.additionalProperties === false) e.push(`${path}.${k}: not allowed`); }
  }
  return e;
}
