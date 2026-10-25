#!/bin/sh
# Migration trial on an ISOLATED copy: a temporary D1 database of our own, loaded from the last verified encrypted panel backup, receives 0003 -> 0004 -> 0005, is checked, rolled back
# 0005 -> 0004 -> 0003 and rolled forward again; then the temporary database is deleted. Production (macguard-quarantine) is never touched. Prints verdicts and counts only: no row content.
set -u
umask 077
# Usage: sh tools/migration_trial.sh <verified panel backup dir with panel-d1-export.sql.age and manifest.json>   (needs wrangler logged in with D1 write, age, and the age identity in the Keychain)
W=$(cd "$(dirname "$0")/.." && pwd); BK=${1:?backup dir}
export CLOUDFLARE_ACCOUNT_ID=$(sed -n 's/^account_id *= *"\([0-9a-f]\{32\}\)".*/\1/p' "$W/../../gateway/environments/panel-d1.wrangler.toml" | head -1)
T=$(mktemp -d "${TMPDIR:-/tmp}/mig-trial.XXXXXX"); DB=macguard-quarantine-migration-trial
cleanup() { rm -rf "$T"; }
trap cleanup EXIT
WR="npx --yes wrangler@4.149.0"
q() { ( cd "$W" && timeout 120 $WR d1 execute "$DB" --remote --json --command "$1" 2>"$T/err" ) | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const r=JSON.parse(s)[0].results;console.log(JSON.stringify(r))}catch(e){console.log('ERR')}})"; }
f() { ( cd "$W" && timeout 180 $WR d1 execute "$DB" --remote --file "$1" >"$T/out" 2>"$T/err" ) && echo ok || { sed "s/\x1b\[[0-9;]*m//g" "$T/err" "$T/out" | grep -iE "error|fail" | head -3 | cut -c1-200; echo FAILED; }; }
tables() { q "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).map(r=>r.name).join(','))}catch{console.log('ERR')}})"; }
counts() { q "SELECT (SELECT COUNT(*) FROM candidates) c,(SELECT COUNT(*) FROM decisions) d,(SELECT COUNT(*) FROM audit) a,(SELECT COUNT(*) FROM members) m,(SELECT COUNT(*) FROM sessions) s"; }

echo "[1] decrypt the verified backup in memory-only form into the trial dir (identity from the Keychain through stdin, never on disk)"
security find-generic-password -s macguard-gateway-prod -a BACKUP_AGE_IDENTITY -w 2>/dev/null | age -d -i - "$BK/panel-d1-export.sql.age" > "$T/panel.sql" || { echo "BLOCKED: could not decrypt (identity unavailable)"; exit 1; }
[ "$(shasum -a 256 "$T/panel.sql" | cut -d' ' -f1)" = "$(node -e "console.log(JSON.parse(require('fs').readFileSync('$BK/manifest.json','utf8')).plaintext_sha256)")" ] && echo "    plaintext hash matches the manifest" || { echo "HASH MISMATCH"; exit 1; }
echo "[2] create the isolated trial database"
( cd "$W" && timeout 120 $WR d1 create "$DB" >"$T/create.log" 2>&1 ) || { sed "s/\x1b\[[0-9;]*m//g" "$T/create.log" | grep -iE "error|already" | head -3 | cut -c1-200; echo "CREATE FAILED"; exit 1; }
echo "    created $DB"
echo "[3] load the production copy"; r=$(f "$T/panel.sql"); echo "    import: $r"; [ "$r" = ok ] || { echo ABORT; exit 1; }
BASE_TABLES=$(tables); echo "    tables: $BASE_TABLES"; BASE_COUNTS=$(counts); echo "    counts: $BASE_COUNTS"
echo "[4] apply 0003, 0004, 0005 in order"
for m in 0003_policies 0004_audit_anchor 0005_source_proposals; do echo "    $m: $(f "$W/migrations/$m.sql")"; done
AFTER_TABLES=$(tables); echo "    tables now: $AFTER_TABLES"; echo "    counts unchanged: $([ "$(counts)" = "$BASE_COUNTS" ] && echo yes || echo NO)"
echo "    integrity: $(q 'PRAGMA integrity_check')"
echo "    triggers: $(q "SELECT group_concat(name) n FROM sqlite_master WHERE type='trigger' AND name IN ('audit_anchor_no_update','audit_anchor_no_delete','audit_anchor_matches_audit','spe_no_update','spe_no_delete')")"
echo "    idempotent re-apply of 0003-0005: $(f "$W/migrations/0003_policies.sql") $(f "$W/migrations/0004_audit_anchor.sql") $(f "$W/migrations/0005_source_proposals.sql")"
echo "    append-only anchors: insert then update must be refused"
q "INSERT INTO audit_anchor (seq, hash, rows, seal_sha256, created_at, author) SELECT seq, hash, 1, '$(printf 'a%.0s' $(seq 1 64))', '2026-10-26T00:00:00Z', 'trial' FROM audit ORDER BY seq LIMIT 1" >/dev/null; echo "    inserted: $(q 'SELECT COUNT(*) n FROM audit_anchor')"
q "UPDATE audit_anchor SET author='x'" >/dev/null; echo "    update refused (author still 'trial'): $(q 'SELECT author FROM audit_anchor')"
echo "[5] rollback 0005, 0004, 0003 and compare with the original"
for m in 0005_rollback 0004_rollback 0003_rollback; do echo "    $m: $(f "$W/migrations/$m.sql")"; done
echo "    tables after rollback equal the original: $([ "$(tables)" = "$BASE_TABLES" ] && echo yes || echo "NO: $(tables)")"; echo "    counts unchanged: $([ "$(counts)" = "$BASE_COUNTS" ] && echo yes || echo NO)"
echo "[6] roll forward again"; for m in 0003_policies 0004_audit_anchor 0005_source_proposals; do echo "    $m: $(f "$W/migrations/$m.sql")"; done; echo "    tables: $(tables)"
echo "[7] export the migrated copy and verify audit chain and schema with the Worker's own code"
sleep 65; ( cd "$W" && timeout 180 $WR d1 export "$DB" --remote --output "$T/migrated.sql" >/dev/null 2>"$T/err" ) && echo "    exported $(wc -c < "$T/migrated.sql" | tr -d ' ') bytes" || echo "    EXPORT FAILED"
node --no-warnings --input-type=module -e "
import { readFileSync } from 'node:fs';
import { newDb } from '$W/test/d1shim.js';
import { verifyAuditChain } from '$W/src/anchor.js';
const db = newDb(); db.raw.exec('PRAGMA foreign_keys=OFF'); for (const ty of ['trigger','view','table']) for (const r of db.raw.prepare(\"SELECT name FROM sqlite_master WHERE type='\"+ty+\"' AND name NOT LIKE 'sqlite_%'\").all()) db.raw.exec('DROP '+ty.toUpperCase()+' IF EXISTS \"'+r.name+'\"');
db.raw.exec(readFileSync('$T/migrated.sql','utf8'));
console.log('    integrity:', JSON.stringify(db.raw.prepare('PRAGMA integrity_check').get()));
const c = await verifyAuditChain(db); console.log('    audit chain:', JSON.stringify(c).slice(0,160));
const t = db.raw.prepare(\"SELECT name FROM sqlite_master WHERE type='table' AND name IN ('policies','policy_lifts','policy_events','audit_anchor','source_proposals','source_proposal_events') ORDER BY name\").all().map(r=>r.name); console.log('    new tables present:', t.join(','));
" || echo "    VERIFY FAILED"
echo "[8] delete the temporary database"
( cd "$W" && timeout 120 $WR d1 delete "$DB" -y >"$T/del.log" 2>&1 ) && echo "    deleted $DB" || { echo "    DELETE FAILED (delete $DB by hand)"; }
echo "TRIAL DONE"
