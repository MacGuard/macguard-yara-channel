// Writes gateway/openapi.json from the operation catalog and the input schemas, so the specification cannot drift from the code. `--check` compares with the committed file.
import { readFileSync, writeFileSync } from 'node:fs';
import { OPS } from '../src/plans.js';
import { INPUT } from '../src/ops.js';

const ERR = { description: 'Error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } };
const codes = (op) => ({ 200: { description: 'OK' }, 400: ERR, ...(OPS[op].auth === false ? {} : { 401: ERR, 403: ERR }), 429: { ...ERR, headers: { 'Retry-After': { schema: { type: 'integer' } } } }, ...(OPS[op].class === 'metered' ? { 402: ERR } : {}), 502: ERR });
const paths = {};
const add = (route, item) => { const [m, p] = route.split(' '); (paths[p] ??= {})[m.toLowerCase()] = item; };
for (const [op, o] of Object.entries(OPS)) {
  const params = [...(o.route.match(/\{(\w+)\}/g) || [])].map((n) => ({ name: n.slice(1, -1), in: 'path', required: true, schema: { type: 'string' } }));
  const hasBody = o.route.startsWith('POST') && INPUT[op];
  add(o.route, { operationId: op, summary: o.title, tags: [op.split('.')[0]], security: o.auth === false ? [] : [{ ApiKey: [] }], 'x-macguard-class': o.class, 'x-macguard-scope': o.scope ?? null, 'x-macguard-feature': o.feature ?? null,
    parameters: [...params, ...(o.class === 'metered' ? [{ name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string' }, description: 'Required: a retry with the same key is never counted twice.' }] : []), ...(op === 'premium.download' ? [{ name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string' } }] : [])],
    ...(hasBody ? { requestBody: { required: true, content: { 'application/json': { schema: INPUT[op] } } } } : {}), responses: codes(op) });
}
const key = [{ ApiKey: [] }];
add('GET /v1/dl/{token}', { operationId: 'premium.transfer', summary: 'Transfer an authorised Premium file (same API key that asked for it; supports Range)', security: key, parameters: [{ name: 'token', in: 'path', required: true, schema: { type: 'string' } }, { name: 'Range', in: 'header', schema: { type: 'string' } }], responses: { 200: { description: 'file' }, 206: { description: 'partial content' }, 403: ERR, 404: ERR, 410: ERR, 416: ERR, 429: ERR, 503: ERR } });
add('GET /v1/account/commercial', { operationId: 'account.commercial', summary: 'Current commercial mode, pricing, notice of changes and terms status', security: key, responses: { 200: { description: 'OK' }, 401: ERR } });
add('POST /v1/account/commercial/accept', { operationId: 'account.accept', summary: 'Accept a pricing and terms version (required before anything can be charged)', security: key, requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['pricing_version', 'terms_version'], properties: { pricing_version: { type: 'string' }, terms_version: { type: 'string' } }, additionalProperties: false } } } }, responses: { 200: { description: 'OK' }, 409: ERR } });
add('POST /v1/account/checkout', { operationId: 'account.checkout', summary: 'Start a Stripe Checkout session (409 while paid plans are not open)', security: key, responses: { 200: { description: 'OK' }, 409: ERR } });
add('POST /stripe/webhook', { operationId: 'stripe.webhook', summary: 'Stripe events (signature verified, deduplicated by event id)', security: [], responses: { 200: { description: 'received' }, 400: ERR, 503: ERR } });
add('POST /mcp', { operationId: 'mcp', summary: 'MCP endpoint, Streamable HTTP, protocol revision 2026-07-28 (earlier revisions accepted without sessions)', security: key, responses: { 200: { description: 'JSON-RPC response' }, 202: { description: 'notification accepted' }, 400: { description: 'protocol error' }, 401: ERR, 403: { description: 'origin not allowed' } } });
add('GET /v1/health', { operationId: 'health', summary: 'Liveness', security: [], responses: { 200: { description: 'OK' } } });
const spec = { openapi: '3.1.0', info: { title: 'MacGuard gateway API', version: '1.0.0-draft', description: 'Premium, Intelligence API and MCP. Draft: nothing is deployed. Community files are NOT served by this API.' },
  servers: [{ url: 'https://REPLACE-WITH-GATEWAY-HOST' }], paths: Object.fromEntries(Object.entries(paths).sort(([a], [b]) => a.localeCompare(b))),
  components: { securitySchemes: { ApiKey: { type: 'http', scheme: 'bearer', bearerFormat: 'mgk_<id>_<secret>' } }, schemas: { Error: { type: 'object', required: ['error'], properties: { error: { type: 'object', required: ['code', 'message', 'request_id'], properties: { code: { type: 'string' }, message: { type: 'string' }, request_id: { type: 'string' } }, additionalProperties: true } } } } } };
const text = JSON.stringify(spec, null, 1) + '\n', file = new URL('../openapi.json', import.meta.url);
if (process.argv.includes('--check')) { const same = readFileSync(file, 'utf8') === text; console.log(same ? 'openapi.json matches the code' : 'openapi.json DIFFERS from the code'); process.exit(same ? 0 : 1); }
writeFileSync(file, text); console.log('wrote openapi.json');
