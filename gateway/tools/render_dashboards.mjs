// Renders the dashboards (and the daily/weekly/monthly reports) from a local SQLite file into static HTML + JSON + CSV. Offline and read-only: no network, nothing is sent anywhere.
// Usage: node tools/render_dashboards.mjs --db FILE --out DIR [--tenant ID] [--now ISO] [--backup-root DIR]  (--backup-root adds the real backup/off-machine/drill state to the cas_backups dashboard; read-only)
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openDb } from './sqlite_d1.mjs';
import { dashboard, report, toHtml, toCsv, DASHBOARDS, panel } from '../src/dashboards.js';
import { existsSync, readFileSync } from 'node:fs';
import { check } from './backup_flow.mjs';
import { custodyCheck } from './backup_offsite.mjs';
import { objstoreCheck, PROVIDERS } from './backup_objstore.mjs';

const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const dbPath = arg('--db'), out = arg('--out'), tenantId = arg('--tenant'), fixed = arg('--now');
if (!dbPath || !out) { console.error('usage: render_dashboards.mjs --db FILE --out DIR [--tenant ID] [--now ISO]'); process.exit(2); }
const need = new DatabaseSync(dbPath, { readOnly: true }); const has = need.prepare("SELECT 1 x FROM sqlite_master WHERE name = 'analytics_daily'").get(); need.close();
if (!has) { console.error('The database lacks the analytics tables: apply gateway/schema.sql first.'); process.exit(1); }
const db = openDb(dbPath), clock = fixed ? () => new Date(fixed) : () => new Date(), opts = { tenantId }, backupRoot = arg('--backup-root');
// Backups run on the owner machine, so only an offline render can show them. Alerts come from the same functions the alarms use.
function backupPanels(root) {
  const st = existsSync(`${root}/status.json`) ? JSON.parse(readFileSync(`${root}/status.json`, 'utf8')) : null, alerts = [...check({ root, clock }), ...custodyCheck({ root, clock }), ...objstoreCheck({ root, clock })];
  const drills = existsSync(`${root}/drills.json`) ? JSON.parse(readFileSync(`${root}/drills.json`, 'utf8')) : null;
  // One row per provider: the last verified copy and the last restore that really passed come from objstore.json, written only by backup_objstore after reading the objects back.
  const os = existsSync(`${root}/objstore.json`) ? JSON.parse(readFileSync(`${root}/objstore.json`, 'utf8')).destinations ?? {} : null, osAlerts = objstoreCheck({ root, clock }), by = Object.fromEntries(osAlerts.map((a) => [a.rule_id, a]));
  const rows = PROVIDERS.map((n) => ({ provider: n, last_verified_copy_at: os?.[n]?.last_verified_at ?? null, newest_backup: os?.[n]?.verified ?? null, last_passing_restore_at: os?.[n]?.last_drill_ok_at ?? null, copy_alarm: by[`backup.${n}.copy_stale`].state, restore_alarm: by[`backup.${n}.drill_stale`].state, last_restore_failed: by[`backup.${n}.drill_failed`].state === 'FIRING' }));
  return [panel('backup_providers', 'Encrypted backup copies per provider (Backblaze B2, Scaleway, Cloudflare R2)', 'table', os ? 'REAL_VERIFIED' : 'NO_DATA', 'objstore.json', rows, { accuracy: 'EXACT', reason: os ? null : 'no copy to any object store has ever been recorded' }),
    panel('backup_three_copies', 'Independent destinations with a recently verified copy', 'value', os ? 'REAL_VERIFIED' : 'NO_DATA', 'backup_objstore', os && { destinations_ok: by['backup.three_copies'].value, required: PROVIDERS.length, alarm: by['backup.three_copies'].state }, { accuracy: 'EXACT', reason: os ? null : 'no copy to any object store has ever been recorded' }),
    panel('backup_status', 'D1 backup status', 'value', st ? 'REAL_VERIFIED' : 'NO_DATA', 'status.json', st && { last_success_at: st.last_success_at, last_status: st.last_status, encrypted: st.encrypted, last_error: st.last_error }, { accuracy: 'EXACT', reason: st ? null : 'no status.json in the backup root' }),
    panel('backup_alarms', 'Backup, off-machine copy and restore-drill alarms', 'list', 'REAL_VERIFIED', 'backup_check + backup_offsite', alerts.map((a) => ({ rule_id: a.rule_id, state: a.state, message: a.message })), { accuracy: 'EXACT' }),
    panel('restore_drills', 'Restore drills from an off-machine copy', 'table', drills ? 'REAL_VERIFIED' : 'NO_DATA', 'drills.json', drills?.history ?? null, { accuracy: 'EXACT', reason: drills ? null : 'no restore drill has ever been recorded' })];
}
mkdirSync(out, { recursive: true });
const links = [];
for (const id of DASHBOARDS) { const d = await dashboard(db, clock, id, id === 'cas_backups' && backupRoot ? { ...opts, extraPanels: backupPanels(backupRoot) } : opts); writeFileSync(join(out, `dashboard-${id}.html`), toHtml(d)); writeFileSync(join(out, `dashboard-${id}.json`), JSON.stringify(d, null, 1)); writeFileSync(join(out, `dashboard-${id}.csv`), toCsv(d)); links.push(`<li><a href="dashboard-${id}.html">${id}</a></li>`); }
for (const kind of ['daily', 'weekly', 'monthly']) { const r = await report(db, clock, kind, opts); writeFileSync(join(out, `report-${kind}.html`), toHtml(r)); writeFileSync(join(out, `report-${kind}.json`), JSON.stringify(r, null, 1)); writeFileSync(join(out, `report-${kind}.csv`), toCsv(r)); links.push(`<li><a href="report-${kind}.html">report: ${kind}</a></li>`); }
writeFileSync(join(out, 'index.html'), `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MacGuard analytics</title><style>:root{--bg:#fff;--fg:#1a1a1a}@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee}}body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui;margin:16px}a{color:inherit}</style></head><body><h1>MacGuard analytics</h1><p>Generated ${new Date(clock()).toISOString()} from a local database. Static snapshot: re-render to refresh.</p><ul>${links.join('')}</ul></body></html>`);
db.close(); console.log(`wrote ${links.length} pages to ${out}`);
