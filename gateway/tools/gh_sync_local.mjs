// Runs the REAL collector once against the public GitHub API (read-only, unauthenticated unless GITHUB_TOKEN is set) and keeps the observations in a local SQLite file.
// Usage: node tools/gh_sync_local.mjs --db FILE [--repo OWNER/NAME] [--json]
import { openDb } from './sqlite_d1.mjs';
import { downloadSummary, sync } from '../src/gh_collector.js';
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const db = openDb(arg('--db', ':memory:')), repo = arg('--repo', 'MacGuard/macguard-yara-channel'), clock = () => new Date();
const r = await sync(db, clock, fetch, { repo, token: process.env.GITHUB_TOKEN || null });
const s = await downloadSummary(db, clock);
if (process.argv.includes('--json')) console.log(JSON.stringify({ sync: r, summary: s }, null, 1));
else { console.log('sync:', JSON.stringify(r)); for (const x of s.releases) console.log(`${x.tag}  published ${x.published_at}  bundle downloads (cumulative) ${x.bundle_downloads_cumulative}  observed growth ${x.bundle_downloads_observed}`); console.log('by kind:', JSON.stringify(s.by_asset_kind)); console.log('coverage of 30-day window:', s.coverage_of_window, '| first observation:', s.collector_first_success_at); }
db.close();
