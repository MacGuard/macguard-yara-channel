// MCP server over Streamable HTTP, protocol revision 2026-07-28 (stateless: every request carries its protocol version and capabilities in _meta; no sessions, no initialize,
// no GET stream) as read from the specification on 2026-10-23. Clients of the earlier revisions (2025-03-26 .. 2025-11-25) are accepted without a session: this server keeps
// no state between requests, so an `initialize` is answered and nothing more. Authentication is an API key as a Bearer token (the MCP authorization framework, OAuth 2.1, is NOT
// implemented): every tool call goes through the same execute() as the REST routes.
import { OPS } from './plans.js';
import { INPUT, execute } from './ops.js';
import { track } from './analytics.js';
import { effective, productOf } from './policy.js';
import { PUBLIC, loadGrants, principalOf, resolve } from './entitlements.js';
import { buildContext } from './context.js';
import { HttpError, jsonResponse, randomHex, readBounded } from './util.js';

export const MODERN = '2026-07-28', LEGACY = ['2025-03-26', '2025-06-18', '2025-11-25'];
const NS = 'io.github.macguard/';                                          // vendor prefix for our _meta keys (reverse DNS of the project's GitHub host)
const rpcErr = (id, code, message, data) => ({ jsonrpc: '2.0', id: id ?? undefined, error: { code, message, ...(data ? { data } : {}) } });
const send = (status, body, headers = {}) => jsonResponse(status, body, headers);

export function tools() {
  return Object.entries(OPS).filter(([, o]) => o.tool).map(([op, o]) => ({
    name: o.tool, title: o.title,
    description: `${o.title}. ${o.class === 'metered' ? 'Billed per unit when charging is active; send an idempotency key.' : o.class === 'included' ? 'Included in the access; counts against quotas.' : 'Free; counts against the rate limit.'} Requires scope ${o.scope ?? 'none'}.`,
    inputSchema: INPUT[op], annotations: { readOnlyHint: op !== 'premium.download', openWorldHint: false, idempotentHint: true },
    _meta: { [NS + 'operation']: op, [NS + 'scope']: o.scope ?? null, [NS + 'billing']: { class: o.class, unit: o.unit ?? null, prices_in: 'commercial policy (see usage.estimate)' },
      [NS + 'result']: op === 'premium.download' ? 'returns a short-lived authorisation; download the file with the same API key' : 'returned directly in structuredContent' },
  })).sort((a, b) => a.name.localeCompare(b.name));
}
const byName = () => Object.fromEntries(tools().map((t) => [t.name, t]));

const MAX_MCP_BODY = 256 * 1024;
export async function handleMcp(request, env, db, clock, defer = () => {}) {
  const requestId = 'mcp_' + randomHex(8);
  const origin = request.headers.get('origin');
  if (origin && !(env.MCP_ALLOWED_ORIGINS || '').split(',').map((x) => x.trim()).filter(Boolean).includes(origin)) return send(403, rpcErr(null, -32600, 'Origin not allowed.'));       // DNS-rebinding protection
  if (request.method !== 'POST') return send(405, rpcErr(null, -32600, 'Use POST.'), { allow: 'POST' });
  let body; try { body = JSON.parse(await readBounded(request, MAX_MCP_BODY)); } catch (e) { if (e instanceof HttpError && e.status === 413) return send(413, rpcErr(null, -32600, 'The request body is too large.')); return send(400, rpcErr(null, -32700, 'Parse error.')); }
  if (!body || Array.isArray(body) || body.jsonrpc !== '2.0' || typeof body.method !== 'string') return send(400, rpcErr(body?.id, -32600, 'Send one JSON-RPC 2.0 request.'));
  const { id, method } = body, params = body.params ?? {}, meta = params._meta ?? {};
  const hv = request.headers.get('mcp-protocol-version'), mv = meta['io.modelcontextprotocol/protocolVersion'];
  const legacy = method === 'initialize' || (mv === undefined && (hv === null || LEGACY.includes(hv)));
  if (!legacy) {
    if (mv !== MODERN || typeof meta['io.modelcontextprotocol/clientCapabilities'] !== 'object' || meta['io.modelcontextprotocol/clientCapabilities'] === null) {
      if (mv !== undefined && mv !== MODERN) return send(400, rpcErr(id, -32022, 'Unsupported protocol version.', { supported: [MODERN] }));
      return send(400, rpcErr(id, -32602, 'Every request must carry _meta protocolVersion and clientCapabilities.'));
    }
    if (hv !== mv) return send(400, rpcErr(id, -32020, 'MCP-Protocol-Version does not match the request body.'));
    if (request.headers.get('mcp-method') !== method) return send(400, rpcErr(id, -32020, 'Mcp-Method does not match the request body.'));
    if (method === 'tools/call' && request.headers.get('mcp-name') !== params.name) return send(400, rpcErr(id, -32020, 'Mcp-Name does not match the request body.'));
  }
  if (id === undefined) return new Response(null, { status: 202 });                                                     // a notification: accepted, nothing to answer
  if (method === 'initialize') {                                                                                         // earlier-era handshake, stateless: nothing is remembered
    const want = params.protocolVersion; return send(200, { jsonrpc: '2.0', id, result: { protocolVersion: LEGACY.includes(want) ? want : LEGACY[LEGACY.length - 1], capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'macguard-gateway', version: '1' } } });
  }
  if (method === 'ping') return send(200, { jsonrpc: '2.0', id, result: {} });
  let ctx; try { ctx = await buildContext(request, env, db, clock); } catch (e) { if (e instanceof HttpError) return send(e.status, rpcErr(id, -32001, e.message), e.headers || {}); throw e; }
  const res = (result) => send(200, { jsonrpc: '2.0', id, result: legacy ? result : { resultType: 'complete', ...result } });
  // The same decision as pipeline.authorize (scope -> capability -> feature when ENFORCED), so a listed tool is one the caller may run.
  const mine = async () => { const t = byName(), now = clock().getTime(), grants = await loadGrants(db, ctx.tenant.id); return Object.values(t).filter((x) => { const op = x._meta[NS + 'operation'], o = OPS[op], eff = effective(ctx.policy.doc, ctx.tenant, productOf(op), now, ctx.acceptance), ent = resolve(principalOf(ctx, eff, grants), now);
    return (!o.scope || ctx.scopes.has(o.scope)) && (!o.capability || ent.caps.has(o.capability)) && (ent.accessMode === 'OPEN_PREMIUM_PREVIEW' || !o.feature || !PUBLIC.includes(o.capability) || eff.features.has(o.feature)); }); };
  if (method === 'tools/list') return res({ tools: await mine(), ttlMs: 60000, cacheScope: 'private' });
  if (method === 'tools/call') {
    const tool = byName()[params.name]; if (!tool) return send(200, rpcErr(id, -32602, `Unknown tool: ${String(params.name).slice(0, 64)}`));
    const op = tool._meta[NS + 'operation'], t0 = Date.now();
    const rec = (extra) => ({ tenantId: ctx.tenant.id, keyId: ctx.key.id, actorKind: ctx.key.actorKind, channel: 'mcp', product: productOf(op), operation: op, durationMs: Date.now() - t0, commercialMode: ctx.policy.doc.mode, ...extra });
    try {
      const out = await execute({ env, db, clock }, ctx, op, params.arguments ?? {}, { idemKey: meta[NS + 'idempotencyKey'] ?? request.headers.get('idempotency-key'), requestId });
      defer(track(env, db, clock, rec({ httpStatus: 200, commercialMode: out.eff.mode, units: out.units, billable: out.billable, theoretical: out.theoretical, replayed: out.replayed })));
      return res({ content: [{ type: 'text', text: JSON.stringify(out.result) }], structuredContent: out.result, isError: false, _meta: { [NS + 'usage_event_id']: out.usage_event_id ?? null, [NS + 'replayed']: !!out.replayed, [NS + 'commercial_mode']: out.eff.mode } });
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;                                                                             // unexpected errors become a generic 500 upstream, never a stack
      defer(track(env, db, clock, rec({ httpStatus: e.status, toolError: true })));
      const err = { code: e.code, message: e.message, ...e.extra };
      return res({ content: [{ type: 'text', text: JSON.stringify({ error: err }) }], structuredContent: { error: err }, isError: true });       // business errors (quota, budget, entitlement, input) are results the model can act on
    }
  }
  return send(404, rpcErr(id, -32601, 'Method not found.'));
}
