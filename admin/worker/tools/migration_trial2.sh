#!/bin/sh
# Trial of panel 0006 + 0007 and INTEL 0002 + 0003 on ISOLATED temporary D1 databases: the panel from a verified local backup, INTEL from a deterministic FIXTURE (tools/intel_trial_fixture.mjs, ~1,500 rows).
# It never exports or imports the productive INTEL (75,148 rows: doing that exhausted the free D1 quota on 2026-10-26). Every run is budget-checked first (tools/d1_budget.mjs) and its real cost is recorded.
# Heavy checks belong to local SQLite (test/migration_compat.test.js, test/d1_budget.test.js); this trial only proves what needs a real D1: the migrations through `wrangler d1 execute --file`. Prints verdicts and counts only: no row content.
# Usage: sh tools/migration_trial2.sh <verified panel backup dir> [panel|intel|both]   (needs the operator's wrangler login with D1 write, age, and the age identity in the Keychain)
set -u
umask 077
W=$(cd "$(dirname "$0")/.." && pwd); BK=${1:?backup dir}; WHAT=${2:-both}
export CLOUDFLARE_ACCOUNT_ID=$(sed -n 's/^account_id *= *"\([0-9a-f]\{32\}\)".*/\1/p' "$W/../../gateway/environments/panel-d1.wrangler.toml" | head -1)
T=$(mktemp -d "${TMPDIR:-/tmp}/mig-trial2.XXXXXX"); WR="npx --yes wrangler@4.149.0"; TRIALS=""
cleanup() { for d in $TRIALS; do ( cd "$W" && timeout 120 $WR d1 delete "$d" -y >/dev/null 2>&1 ) && echo "    deleted $d" || echo "    DELETE FAILED: delete $d by hand"; done; rm -rf "$T"; }
trap cleanup EXIT
BUDGET="node $W/tools/d1_budget.mjs"; BEFORE="$T/budget-before.json"
if [ "$WHAT" = panel ] || [ "$WHAT" = both ]; then
  security find-generic-password -s macguard-gateway-prod -a BACKUP_AGE_IDENTITY -w 2>/dev/null | age -d -i - "$BK/panel-d1-export.sql.age" > "$T/panel.sql" || { echo "BLOCKED: identity unavailable"; exit 1; }
  PW=$($BUDGET estimate-file "$T/panel.sql" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).writes))"); else PW=0; fi
if [ "$WHAT" = intel ] || [ "$WHAT" = both ]; then node --no-warnings "$W/tools/intel_trial_fixture.mjs" 1500 > "$T/intel-fixture.sql" 2>/dev/null; IW=$($BUDGET estimate-file "$T/intel-fixture.sql" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).writes))"); else IW=0; fi
$BUDGET preflight --reads 150000 --writes $((PW + IW + 3000)) --label "migration-trial2 $WHAT" --before "$BEFORE" || { echo "ABORTED BEFORE TOUCHING D1: the budget does not allow this run today"; exit 3; }
q() { db=$1; shift; ( cd "$W" && timeout 120 $WR d1 execute "$db" --remote --json --command "$1" 2>"$T/err" ) | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const r=JSON.parse(s)[0].results;console.log(JSON.stringify(r.length===1?r[0]:r))}catch(e){console.log('ERR')}})"; }
f() { db=$1; ( cd "$W" && timeout 600 $WR d1 execute "$db" --remote --file "$2" >"$T/out" 2>"$T/err" ) && echo ok || { sed "s/\x1b\[[0-9;]*m//g" "$T/err" "$T/out" | grep -iE "error|fail|constraint" | head -2 | cut -c1-160; echo FAILED; }; }
mk() { ( cd "$W" && timeout 120 $WR d1 create "$1" >"$T/create.log" 2>&1 ) || { echo "CREATE FAILED"; exit 1; }; TRIALS="$TRIALS $1"; echo "    created $1"; }
names() { q "$1" "SELECT group_concat(type||':'||name) n FROM (SELECT type,name FROM sqlite_master WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY type,name)" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(require('crypto').createHash('sha256').update(JSON.parse(s).n||'').digest('hex').slice(0,16)+' '+(JSON.parse(s).n||'').split(',').length+' objects')}catch(e){console.log('ERR')}})"; }

if [ "$WHAT" = panel ] || [ "$WHAT" = both ]; then
  P=macguard-quarantine-trial2; echo "== PANEL: 0006 + 0007 on a copy of the verified backup"
  echo "[p1] decrypt the verified backup (identity from the Keychain through stdin) and check its hash against the manifest"
  [ "$(shasum -a 256 "$T/panel.sql" | cut -d' ' -f1)" = "$(node -e "console.log(JSON.parse(require('fs').readFileSync('$BK/manifest.json','utf8')).plaintext_sha256)")" ] && echo "    plaintext hash matches the manifest" || { echo "    HASH MISMATCH"; exit 1; }
  echo "[p2] create and load the isolated copy"; mk $P; echo "    import: $(f $P "$T/panel.sql")"
  BASE=$(names $P); BC=$(q $P "SELECT (SELECT COUNT(*) FROM candidates) c,(SELECT COUNT(*) FROM decisions) d,(SELECT COUNT(*) FROM audit) a,(SELECT COUNT(*) FROM members) m,(SELECT COUNT(*) FROM policies) p"); echo "    objects: $BASE"; echo "    counts: $BC"
  echo "[p3] apply 0006 then 0007"; echo "    0006: $(f $P "$W/migrations/0006_five_roles.sql")"; echo "    0007: $(f $P "$W/migrations/0007_source_requests.sql")"; AFTER=$(names $P); echo "    objects now: $AFTER"
  echo "    counts unchanged: $([ "$(q $P "SELECT (SELECT COUNT(*) FROM candidates) c,(SELECT COUNT(*) FROM decisions) d,(SELECT COUNT(*) FROM audit) a,(SELECT COUNT(*) FROM members) m,(SELECT COUNT(*) FROM policies) p")" = "$BC" ] && echo yes || echo NO)"; echo "    integrity: $(q $P 'PRAGMA integrity_check')"
  echo "[p4] idempotence: 0007 applied again"; echo "    0007 again: $(f $P "$W/migrations/0007_source_requests.sql")  objects equal: $([ "$(names $P)" = "$AFTER" ] && echo yes || echo NO)"
  echo "[p5] constraints and concurrency on source_requests"
  ROW="INSERT INTO source_requests (id, request_id, kind, family, name, url, format, auth, reason, requested_by, requested_by_id, requested_at)"
  echo "$ROW VALUES ('a1','req-trial-0000000001','ADD','ioc','Trial A','https://trial.example.org/a','csv','none','trial row for the migration test','trial',1,'2026-10-26T00:00:00Z');" > "$T/c1.sql"
  echo "$ROW VALUES ('a2','req-trial-0000000002','ADD','ioc','Trial B','https://trial.example.org/a','csv','none','same open url, second writer','trial',2,'2026-10-26T00:00:01Z');" > "$T/c2.sql"
  ( f $P "$T/c1.sql" > "$T/r1" ) & ( f $P "$T/c2.sql" > "$T/r2" ) & wait; echo "    two parallel writers on the same open URL: $(cat "$T/r1" | tail -1) / $(cat "$T/r2" | tail -1) (exactly one must be ok); rows: $(q $P 'SELECT COUNT(*) n FROM source_requests')"
  q $P "UPDATE source_requests SET url = 'https://evil.example.org/x'" >/dev/null; echo "    identity frozen (url unchanged): $(q $P "SELECT url FROM source_requests LIMIT 1")"
  q $P "DELETE FROM source_requests" >/dev/null; echo "    delete refused (rows still there): $(q $P 'SELECT COUNT(*) n FROM source_requests')"
  echo "[p6] failure in the middle of a file: nothing of it may stay"; printf "CREATE TABLE trial_atomic (x INTEGER);\nINSERT INTO trial_atomic VALUES (1);\nINSERT INTO no_such_table VALUES (1);\n" > "$T/bad.sql"; echo "    bad file: $(f $P "$T/bad.sql")  trial_atomic left behind: $(q $P "SELECT COUNT(*) n FROM sqlite_master WHERE name = 'trial_atomic'")"
  echo "[p7] rollback 0007 and 0006 (requests exported first: they are dropped), compare with the original, roll forward again"
  q $P "DELETE FROM source_requests" >/dev/null 2>&1
  echo "    0007_rollback: $(f $P "$W/migrations/0007_rollback.sql")"; echo "    0006_rollback: $(f $P "$W/migrations/0006_rollback.sql")"; echo "    objects equal the original: $([ "$(names $P)" = "$BASE" ] && echo yes || echo "NO: $(names $P)")"; echo "    counts unchanged: $([ "$(q $P "SELECT (SELECT COUNT(*) FROM candidates) c,(SELECT COUNT(*) FROM decisions) d,(SELECT COUNT(*) FROM audit) a,(SELECT COUNT(*) FROM members) m,(SELECT COUNT(*) FROM policies) p")" = "$BC" ] && echo yes || echo NO)"
  echo "    forward again: $(f $P "$W/migrations/0006_five_roles.sql") $(f $P "$W/migrations/0007_source_requests.sql")  equal to the first application: $([ "$(names $P)" = "$AFTER" ] && echo yes || echo NO)"
  echo "[p8] export the migrated copy and verify integrity and the audit chain with the Worker's own code"; sleep 65
  ( cd "$W" && timeout 240 $WR d1 export $P --remote --output "$T/migrated.sql" >/dev/null 2>"$T/err" ) && echo "    exported $(wc -c < "$T/migrated.sql" | tr -d ' ') bytes" || echo "    EXPORT FAILED"
  node --no-warnings --input-type=module -e "
import { readFileSync } from 'node:fs'; import { newDb } from '$W/test/d1shim.js'; import { verifyAuditChain } from '$W/src/anchor.js';
const db = newDb(); db.raw.exec('PRAGMA foreign_keys=OFF'); for (const ty of ['trigger','view','table']) for (const r of db.raw.prepare(\"SELECT name FROM sqlite_master WHERE type='\"+ty+\"' AND name NOT LIKE 'sqlite_%'\").all()) db.raw.exec('DROP '+ty.toUpperCase()+' IF EXISTS \"'+r.name+'\"');
db.raw.exec(readFileSync('$T/migrated.sql','utf8')); const c = await verifyAuditChain(db);
console.log('    integrity:', db.raw.prepare('PRAGMA integrity_check').get().integrity_check, '| audit chain:', c.ok ? 'ok, '+c.entries+' entries' : 'BROKEN');" || echo "    VERIFY FAILED"
fi

if [ "$WHAT" = intel ] || [ "$WHAT" = both ]; then
  I=macguard-intel-trial2; echo "== INTEL: 0002 + 0003 on a deterministic fixture (production INTEL is NOT read)"
  echo "[i1] create the isolated database with migration 0001 and load the fixture"; mk $I; echo "    0001: $(f $I "$W/migrations-intel/0001_intel.sql")"; echo "    fixture: $(f $I "$T/intel-fixture.sql")"
  IC="SELECT (SELECT COUNT(*) FROM intel_records) r,(SELECT COUNT(*) FROM intel_runs) u,(SELECT COUNT(*) FROM intel_sources) s,(SELECT COUNT(*) FROM intel_events) e,(SELECT group_concat(family||':'||c) FROM (SELECT family, COUNT(*) c FROM intel_records GROUP BY family ORDER BY family)) f"
  IH="SELECT COUNT(*) n, MIN(id) a, MAX(id) b, SUM(LENGTH(doc_sha256)) s FROM intel_records"
  IBC=$(q $I "$IC"); IBN=$(names $I); IFP=$(q $I "$IH"); echo "    counts: $IBC"; echo "    objects: $IBN"
  echo "[i2] apply 0002 then 0003 (0003 only adds two small tables and a trigger: idempotent, and it rewrites nothing in intel_records)"; echo "    0002: $(f $I "$W/migrations-intel/0002_decisions.sql")"
  echo "    0003: $(f $I "$W/migrations-intel/0003_effective_state.sql")"
  IAN=$(names $I); echo "    objects now: $IAN"; echo "    counts unchanged: $([ "$(q $I "$IC")" = "$IBC" ] && echo yes || echo NO)  records fingerprint unchanged: $([ "$(q $I "$IH")" = "$IFP" ] && echo yes || echo NO)"
  echo "[i3] decisions on real-shaped records: the trigger fills intel_decided, history and uniqueness hold, append-only holds"
  REC=$(q $I "SELECT id FROM intel_records WHERE family='suricata' LIMIT 1" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{console.log(JSON.parse(s).id)}catch(e){console.log('')}})")
  q $I "INSERT INTO intel_decisions (record_id, family, action, from_state, to_state, reason, actor, actor_id, at, request_id) SELECT id, family, 'quarantine', state, 'QUARANTINED', 'trial decision on a copy', 'trial', 1, '2026-10-26T00:00:00Z', 'req-trial-000000000001' FROM intel_records WHERE id = '$REC'" >/dev/null
  echo "    decided state of that record: $(q $I "SELECT d.state decided, r.state imported FROM intel_decided d JOIN intel_records r ON r.id = d.record_id WHERE d.record_id = '$REC'")  rows in intel_decided: $(q $I "SELECT COUNT(*) n FROM intel_decided")"
  q $I "INSERT INTO intel_decisions (record_id, family, action, from_state, to_state, reason, actor, actor_id, at, request_id) SELECT id, family, 'reject', 'x', 'REJECTED', 'duplicate request id must fail', 'trial', 1, '2026-10-26T00:00:01Z', 'req-trial-000000000001' FROM intel_records WHERE id = '$REC'" >/dev/null; echo "    duplicate (request id, record) refused (rows=1): $(q $I 'SELECT COUNT(*) n FROM intel_decisions')"
  q $I "UPDATE intel_decisions SET reason = 'edited reason'" >/dev/null; q $I "DELETE FROM intel_decisions" >/dev/null; echo "    edit and delete refused (row intact): $(q $I "SELECT reason FROM intel_decisions")"
  echo "    a re-import (INSERT OR REPLACE of that record) keeps its decision: $(q $I "INSERT OR REPLACE INTO intel_records (id, family, source_id, run_id, key, title, state, doc, doc_sha256) SELECT id, family, source_id, run_id, key, title, state, doc, doc_sha256 FROM intel_records WHERE id = '$REC'" >/dev/null; q $I "SELECT state d FROM intel_decided WHERE record_id = '$REC'")"
  echo "[i4] idempotence of 0002 and 0003: $(f $I "$W/migrations-intel/0002_decisions.sql") $(f $I "$W/migrations-intel/0003_effective_state.sql")  objects equal: $([ "$(names $I)" = "$IAN" ] && echo yes || echo NO)"
  echo "[i5] rollback 0003 then 0002 (the trial decisions are dropped with them: export first in production), compare with the original, roll forward"
  echo "    0003_rollback: $(f $I "$W/migrations-intel/0003_rollback.sql")  0002_rollback: $(f $I "$W/migrations-intel/0002_rollback.sql")  objects equal the original: $([ "$(names $I)" = "$IBN" ] && echo yes || echo NO)  counts unchanged: $([ "$(q $I "$IC")" = "$IBC" ] && echo yes || echo NO)  fingerprint unchanged: $([ "$(q $I "$IH")" = "$IFP" ] && echo yes || echo NO)"
  echo "    forward again: $(f $I "$W/migrations-intel/0002_decisions.sql") $(f $I "$W/migrations-intel/0003_effective_state.sql")  equal to the first application: $([ "$(names $I)" = "$IAN" ] && echo yes || echo NO)"
fi
$BUDGET record --label "migration-trial2 $WHAT" --before "$BEFORE" 2>&1 | tail -1
echo "TRIAL DONE"
