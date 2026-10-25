// Basic CRM: only what an administrator (or an authorised form) records. No lead is ever created from traffic, an IP, a download or an API key.
import { HttpError, iso, randomHex } from './util.js';
import { audit } from './audit.js';

export const STATES = ['NEW_LEAD', 'CONTACTED', 'QUALIFIED', 'DEMO_REQUESTED', 'PILOT', 'PROPOSAL', 'NEGOTIATION', 'WON', 'LOST'];
const NEXT = { NEW_LEAD: ['CONTACTED', 'QUALIFIED', 'LOST'], CONTACTED: ['QUALIFIED', 'DEMO_REQUESTED', 'LOST'], QUALIFIED: ['DEMO_REQUESTED', 'PILOT', 'PROPOSAL', 'LOST'], DEMO_REQUESTED: ['PILOT', 'PROPOSAL', 'LOST'],
  PILOT: ['PROPOSAL', 'NEGOTIATION', 'LOST'], PROPOSAL: ['NEGOTIATION', 'WON', 'LOST'], NEGOTIATION: ['WON', 'LOST'], WON: [], LOST: ['NEW_LEAD'] };       // WON is final; a LOST lead may be reopened
const clip = (s, n) => (s == null ? null : String(s).slice(0, n));

export async function createLead(db, clock, admin, { org_name, source = 'manual', contact = null, notes = null, tenant_id = null }) {
  if (!org_name || String(org_name).trim().length < 2) throw new HttpError(400, 'invalid_input', 'org_name is required.'); if (!['manual', 'form'].includes(source)) throw new HttpError(400, 'invalid_input', 'source must be manual or form.');
  if (tenant_id && !(await db.prepare('SELECT 1 x FROM tenants WHERE id = ?').bind(tenant_id).first())) throw new HttpError(404, 'not_found', 'Unknown tenant.');
  const id = 'ld_' + randomHex(8), at = iso(clock());
  await db.batch([db.prepare("INSERT INTO leads(lead_id,org_name,tenant_id,state,source,contact,notes,created_at,updated_at,created_by) VALUES (?,?,?,'NEW_LEAD',?,?,?,?,?,?)").bind(id, clip(org_name, 120), tenant_id, source, clip(contact, 160), clip(notes, 1000), at, at, admin.id),
    db.prepare("INSERT INTO lead_events(lead_id,at,from_state,to_state,by_admin) VALUES (?,?,NULL,'NEW_LEAD',?)").bind(id, at, admin.id)]);
  await audit(db, clock, null, 'crm.lead_created', { lead_id: id, admin_id: admin.id }); return { lead_id: id, state: 'NEW_LEAD' };
}
export async function moveLead(db, clock, admin, leadId, to) {
  const l = await db.prepare('SELECT state FROM leads WHERE lead_id = ?').bind(leadId).first(); if (!l) throw new HttpError(404, 'not_found', 'Unknown lead.');
  if (!STATES.includes(to) || !NEXT[l.state].includes(to)) throw new HttpError(409, 'invalid_transition', `${l.state} cannot move to ${String(to).slice(0, 20)}.`, { allowed: NEXT[l.state] });
  const at = iso(clock()), r = await db.prepare('UPDATE leads SET state = ?, updated_at = ? WHERE lead_id = ? AND state = ?').bind(to, at, leadId, l.state).run();
  if (r.meta.changes !== 1) throw new HttpError(409, 'conflict', 'The lead changed meanwhile; read it again.');
  await db.prepare('INSERT INTO lead_events(lead_id,at,from_state,to_state,by_admin) VALUES (?,?,?,?,?)').bind(leadId, at, l.state, to, admin.id).run();
  await audit(db, clock, null, 'crm.lead_moved', { lead_id: leadId, from: l.state, to, admin_id: admin.id }); return { lead_id: leadId, from: l.state, state: to };
}
export async function listLeads(db, { state = null, limit = 50, cursor = null }) {
  limit = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const rows = (await db.prepare('SELECT lead_id, org_name, tenant_id, state, source, created_at, updated_at FROM leads WHERE (? IS NULL OR state = ?) AND (? IS NULL OR lead_id > ?) ORDER BY lead_id LIMIT ?').bind(state, state, cursor, cursor, limit + 1).all()).results;
  return { leads: rows.slice(0, limit), next_cursor: rows.length > limit ? rows[limit - 1].lead_id : null };       // contact and notes are never listed in bulk
}
// "Reached" counts leads that ever had the state (from lead_events), so a lead that went on to PILOT still counts as having requested a demo.
export async function crmSummary(db) {
  const now = Object.fromEntries(STATES.map((s) => [s, 0])), ever = { ...now };
  for (const r of (await db.prepare('SELECT state, COUNT(*) n FROM leads GROUP BY state').all()).results) now[r.state] = r.n;
  for (const r of (await db.prepare('SELECT to_state s, COUNT(DISTINCT lead_id) n FROM lead_events GROUP BY to_state').all()).results) ever[r.s] = r.n;
  const total = Object.values(now).reduce((a, b) => a + b, 0);
  return { state: total ? 'REAL_VERIFIED' : 'NO_DATA', total, current: now, ever_reached: ever, win_rate: ever.WON + ever.LOST ? ever.WON / (ever.WON + ever.LOST) : null,
    note: 'Leads are recorded by people or authorised forms only; a download, an IP or an API key is not a lead.' };
}
