// Prints the backup alarms as macguard.alert/1 JSON and exits 1 if any is FIRING. Run it from the same scheduler as the backup (or from a different one). Usage: node tools/backup_check.mjs [--root DIR] [--max-age-hours 30] [--custody]  (--custody adds the off-machine copy and restore-drill alarms; opt-in until a destination is configured)
import { check, ROOT_DEFAULT } from './backup_flow.mjs';
import { custodyCheck } from './backup_offsite.mjs';
import { objstoreCheck } from './backup_objstore.mjs';
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const alerts = check({ root: arg('--root', ROOT_DEFAULT), maxAgeHours: Number(arg('--max-age-hours', 30)) }); if (process.argv.includes('--custody')) alerts.push(...custodyCheck({ root: arg('--root', ROOT_DEFAULT) }));
if (process.argv.includes('--objstore')) alerts.push(...objstoreCheck({ root: arg('--root', ROOT_DEFAULT) }));   // Backblaze B2 / Scaleway / R2, one set of alarms per provider
console.log(JSON.stringify(alerts, null, 1)); const firing = alerts.filter((a) => a.state === 'FIRING'); for (const a of firing) console.error(`FIRING ${a.rule_id}: ${a.message}`); process.exit(firing.length ? 1 : 0);
