// The reproducible release sequence: backup -> D1 migrations -> deploy -> smoke -> security -> rollback, rehearsed on STAGING first. This tool NEVER executes a step: it prints the plan (the same
// text lives in docs/analytics/STAGING-SEQUENCE.md, generated from it and drift-tested) and `--check` verifies the invariants that keep the rehearsal away from production.
//   node tools/staging_sequence.mjs            human-readable plan
//   node tools/staging_sequence.mjs --markdown the text of STAGING-SEQUENCE.md
//   node tools/staging_sequence.mjs --check    invariants (exit 1 if one fails)
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)), GW = join(HERE, '..');
const ACC = 'CLOUDFLARE_ACCOUNT_ID=9e96e19f6dc0ccdd53e02f7c3b5cacab', W = 'npx wrangler@4.149.0';
// scope: local | remote-read | remote-write. Every remote-write step needs the owner's go-ahead for that environment; staging and production are authorised separately.
export const STEPS = [
  { id: 'S0', title: 'Freeze and verify the candidate', scope: 'local', cmd: ['cd gateway && node --test test/*.test.js', 'node test/runtime/runtime.test.mjs', 'python3.13 -m unittest discover -s tests', 'node tools/gen_openapi.mjs --check && node tools/gen_kpi_catalog.mjs --check && node tools/route_inventory.mjs --check', 'git rev-parse HEAD   # the SHA that will be deployed; write it in the report'],
    verify: 'all suites green; the SHA is a commit that exists on a pushed branch (tested tree = published tree)', rollback: 'nothing changed' },
  { id: 'S1', title: 'Record production as it is now (read-only)', scope: 'remote-read', cmd: [`${ACC} ${W} deployments list --name macguard-gateway`, `${ACC} ${W} d1 migrations list macguard-gateway --remote --config environments/production.wrangler.toml`],
    verify: 'live version id noted (today 2920e0d5-d7df-4c0d-a078-48764b461dd6); the migrations list shows which of 0001-0003 are pending', rollback: 'nothing changed' },
  { id: 'S2', title: 'Backup of production (read-only export, encrypted, restore-verified)', scope: 'remote-read', cmd: ['cd gateway && node tools/d1_backup.mjs   # exports, restores in isolation, verifies, encrypts with age, writes status.json', 'node tools/backup_check.mjs   # exits non-zero if the newest backup is missing, stale or unverified'],
    verify: 'status.json says verified:true for a backup newer than this sequence; the encrypted copy exists off the Mac (docs/analytics/KEY-CUSTODY.md)', rollback: 'nothing changed (an export does not modify the database)' },
  { id: 'S3', title: 'Create the staging database', scope: 'remote-write (staging only)', cmd: [`${ACC} ${W} d1 create macguard-gateway-staging`, '# put the returned database_id in environments/staging.wrangler.toml (a tracked file: identifier only)'],
    verify: 'the database is listed; it is empty', rollback: `${ACC} ${W} d1 delete macguard-gateway-staging   # staging only; the name is checked by restore_to_staging.mjs` },
  { id: 'S4', title: 'Restore the production backup into staging (rehearses recovery on real D1)', scope: 'remote-write (staging only)', cmd: ['cd gateway && node tools/restore_to_staging.mjs --export <backup>/d1-export.sql.age --identity <age identity file> --staging macguard-gateway-staging --env environments/staging.wrangler.toml   # dry run', '... the same command with --apply --confirm-database macguard-gateway-staging'],
    verify: 'tools print PASS for every restore check; row counts of staging equal the manifest; the tool refuses any name that is not *-staging / *-restore-test / *-scratch', rollback: 'delete and recreate the staging database (S3); production is never a target' },
  { id: 'S5', title: 'Apply the pending D1 migrations to staging', scope: 'remote-write (staging only)', cmd: [`${ACC} ${W} d1 migrations apply macguard-gateway-staging --remote --config environments/staging.wrangler.toml`],
    verify: 'migrations 0001-0003 listed as applied; a second run applies nothing; row counts from S4 unchanged (additive migrations)', rollback: 'restore S4 again into a fresh staging database; migrations are additive and are never reversed in place' },
  { id: 'S6', title: 'Deploy the candidate to the staging Worker', scope: 'remote-write (staging only)', cmd: ['# staging secrets are NEW random values, never the production ones:', 'export KEY_PEPPER=$(openssl rand -base64 36) ADMIN_PEPPER=$(openssl rand -base64 36) TOTP_SEAL_KEY=$(openssl rand -base64 36)   # fresh values, kept only in this shell', 'for n in KEY_PEPPER ADMIN_PEPPER TOTP_SEAL_KEY; do printf %s "${(P)n}" | node tools/set_worker_secret.mjs --env environments/staging.wrangler.toml --name $n; done   # the tool refuses these names on any Worker not ending in -staging', 'node tools/bootstrap_remote.mjs --admin-only --out /tmp/staging-admin.sql --secret-out ~/macguard-evidence/staging-admin.json   # a staging administrator under the NEW peppers (the restored production administrators cannot sign in); then wrangler d1 execute macguard-gateway-staging --remote --file /tmp/staging-admin.sql', `${ACC} ${W} deploy --config environments/staging.wrangler.toml --keep-vars`],
    verify: '/v1/health answers on the workers.dev URL; the deployed version id is noted', rollback: `${ACC} ${W} rollback --name macguard-gateway-staging   # or delete the staging Worker` },
  { id: 'S7', title: 'Smoke and security checks against staging', scope: 'remote-read (HTTP GETs and refused anonymous calls)', cmd: ['cd gateway && node tools/smoke.mjs --base-url https://macguard-gateway-staging.<account>.workers.dev'],
    verify: 'every check PASS (SKIP is listed, never counted as a pass); then, with the staging admin credentials, a real analytics read and a collector run: node tools/check_collector.mjs', rollback: 'if anything FAILs, stop: do not continue to production; fix, return to S0' },
  { id: 'S8', title: 'Rollback rehearsal on staging', scope: 'remote-write (staging only)', cmd: [`${ACC} ${W} deployments list --name macguard-gateway-staging`, `${ACC} ${W} rollback --name macguard-gateway-staging <previous version id>`, 'node tools/smoke.mjs --base-url <staging url>'],
    verify: 'after the rollback the smoke test still passes and the version id is the previous one', rollback: 'redeploy S6' },
  { id: 'P1', title: 'PRODUCTION (only after S0-S8 passed and the owner approves each line)', scope: 'remote-write (production)', cmd: ['node tools/d1_backup.mjs   # a fresh backup immediately before', `${ACC} ${W} d1 migrations apply macguard-gateway --remote --config environments/production.wrangler.toml`, `${ACC} ${W} deploy --config environments/production.wrangler.toml --keep-vars`, 'node tools/smoke.mjs --base-url https://quarantine-api.mac-guard.com --production', 'node tools/check_collector.mjs'],
    verify: 'smoke OK; /readyz-equivalent health OK; analytics rows keep arriving; Community download unchanged; panel and rules untouched', rollback: `${ACC} ${W} rollback --name macguard-gateway <version id noted in S1>   # code only. The migrations are additive and stay (additive-only is tested in test/migrations.test.js); that the PREVIOUS code (4d9b1ff) runs on the migrated schema is proven LOCALLY by test/staging_rehearsal.test.js (health, admin refusal, collector write); on real D1 it is still only proven by S8 on staging` },
];

export function invariants() {
  const read = (p) => readFileSync(join(GW, p), 'utf8'), stg = read('environments/staging.wrangler.toml'), prod = read('environments/production.wrangler.toml');
  const val = (t, k) => (t.match(new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, 'm')) ?? [])[1];
  const checks = [
    ['staging Worker name differs from production', val(stg, 'name') !== val(prod, 'name') && /-staging$/.test(val(stg, 'name'))],
    ['staging database name differs from production and ends in -staging', val(stg, 'database_name') !== val(prod, 'database_name') && /-staging$/.test(val(stg, 'database_name'))],
    ['staging never reuses the production database id', val(stg, 'database_id') !== val(prod, 'database_id')],
    ['staging has no route and no Custom Domain (no DNS is touched)', !/^\s*routes\s*=/m.test(stg) && !/custom_domain/.test(stg.replace(/#.*$/gm, ''))],
    ['staging has no R2 binding (never reads the private Premium bucket)', !/^\[\[r2_buckets\]\]/m.test(stg)],
    ['staging has no cron trigger (does not spend the production collector\'s GitHub allowance)', !/^\[triggers\]/m.test(stg)],
    ['staging holds no secret-shaped value', !/(sk_(live|test)_|whsec_|AGE-SECRET-KEY|-----BEGIN)/.test(stg)],
    ['every remote-write step before P1 is scoped to staging', STEPS.filter((s) => s.scope.startsWith('remote-write') && s.id !== 'P1').every((s) => /staging only/.test(s.scope))],
    ['no staging step names the production database as a target', STEPS.filter((s) => s.id !== 'P1' && s.id !== 'S1' && s.id !== 'S2').every((s) => !s.cmd.join('\n').match(/(d1 (create|delete|execute|migrations apply)) macguard-gateway( |$)/m))],
    ['every step has a verification and a rollback statement', STEPS.every((s) => s.verify && s.rollback)],
  ];
  return checks.map(([name, ok]) => ({ name, ok: !!ok }));
}

export function markdown() {
  const L = ['# Staging release sequence (prepared; NOT executed anywhere)', '', 'Generated by `gateway/tools/staging_sequence.mjs --markdown` and drift-tested: edit the tool, not this file. Order: **backup → D1 migrations → deploy → smoke → security → rollback**, rehearsed on a separate staging Worker and database first. Staging has no Custom Domain, no route, no R2 and no cron, so it touches no DNS, no production hostname and no production data.', '',
    'Scope legend: `local` runs on this machine only; `remote-read` reads from Cloudflare/HTTP without changing anything; `remote-write (staging only)` changes the staging resources and needs the owner\'s go-ahead for staging; `remote-write (production)` needs a separate go-ahead for each command.', ''];
  for (const s of STEPS) { L.push(`## ${s.id} · ${s.title}`, `**Scope:** ${s.scope}`, '', '```', ...s.cmd, '```', `**Verify:** ${s.verify}`, '', `**Rollback:** ${s.rollback}`, ''); }
  L.push('## Invariants checked by `--check` and by `test/staging.test.js`', '', ...invariants().map((c) => `- ${c.name}`), '', '## What this does not prove', 'A staging pass proves the code, the migrations and the restore path on real D1 and real workerd. It does not prove the production edge (Custom Domain TLS, WAF), the production secrets, the GitHub collector from production egress addresses, or any GuardOps receiver. Those stay marked UNKNOWN until observed in the environment itself.', '');
  return L.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes('--markdown')) process.stdout.write(markdown());
  else if (process.argv.includes('--check')) { const r = invariants(); for (const c of r) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}`); process.exit(r.every((c) => c.ok) ? 0 : 1); }
  else for (const s of STEPS) console.log(`${s.id}  ${s.title}  [${s.scope}]\n  ${s.cmd.join('\n  ')}\n  verify:   ${s.verify}\n  rollback: ${s.rollback}\n`);
}
