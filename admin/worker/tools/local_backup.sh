#!/bin/sh
# Local, verified, encrypted backup of the PANEL D1 (macguard-quarantine) before a schema change. It is a LOCAL backup made with the operator's own wrangler login: it is NOT the cloud pipeline
# (B2 + Scaleway + R2 with Sigstore) and proves nothing about those copies. Steps: export (read-only), load the export into a scratch SQLite and check integrity and the audit hash chain with the
# Worker's own code, encrypt with the age recipient of gateway/environments/backup-trust.json, write manifest + SHA256SUMS, then read the ciphertext back with the identity from the Keychain and compare hashes.
# Prints verdicts and counts only: never row content, never a key.   Usage: sh tools/local_backup.sh [OUT_ROOT=~/macguard-backups/panel]
set -u
umask 077
W=$(cd "$(dirname "$0")/.." && pwd); ROOT=${1:-$HOME/macguard-backups/panel}; STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT="$ROOT/$STAMP"; T=$(mktemp -d "${TMPDIR:-/tmp}/panel-bk.XXXXXX")
trap 'rm -rf "$T"' EXIT
export CLOUDFLARE_ACCOUNT_ID=$(sed -n 's/^account_id *= *"\([0-9a-f]\{32\}\)".*/\1/p' "$W/../../gateway/environments/panel-d1.wrangler.toml" | head -1)
REC=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$W/../../gateway/environments/backup-trust.json','utf8')).age_recipient)")
BUDGET="node $W/tools/d1_budget.mjs"; $BUDGET preflight --reads 20000 --writes 0 --label "local-backup panel" --before "$T/budget-before.json" || { echo "ABORTED BEFORE TOUCHING D1: the budget does not allow this run today"; exit 3; }
echo "[1] export (read-only) of macguard-quarantine"
( cd "$W/../../gateway/environments" && timeout 240 npx --yes wrangler@4.149.0 d1 export macguard-quarantine --remote -c panel-d1.wrangler.toml --output "$T/panel.sql" >"$T/exp.log" 2>&1 ) || { sed "s/\x1b\[[0-9;]*m//g" "$T/exp.log" | grep -iE "error|authentication|permission" | head -3 | cut -c1-200; echo "EXPORT FAILED"; exit 1; }
BYTES=$(wc -c < "$T/panel.sql" | tr -d ' '); SHA=$(shasum -a 256 "$T/panel.sql" | cut -d' ' -f1); echo "    $BYTES bytes, sha256 ${SHA%????????????????????????????????????????????????????????}…"
echo "[2] load into a scratch SQLite, check integrity and the audit chain with the Worker's own code"
node --no-warnings --input-type=module -e "
import { readFileSync } from 'node:fs';
import { newDb } from '$W/test/d1shim.js';
import { verifyAuditChain } from '$W/src/anchor.js';
const db = newDb(); db.raw.exec('PRAGMA foreign_keys=OFF'); for (const ty of ['trigger','view','table']) for (const r of db.raw.prepare(\"SELECT name FROM sqlite_master WHERE type='\"+ty+\"' AND name NOT LIKE 'sqlite_%'\").all()) db.raw.exec('DROP '+ty.toUpperCase()+' IF EXISTS \"'+r.name+'\"');
db.raw.exec(readFileSync('$T/panel.sql','utf8'));
const n = (t) => { try { return db.raw.prepare('SELECT COUNT(*) AS n FROM '+t).get().n; } catch { return null; } };
const c = await verifyAuditChain(db);
console.log('    integrity:', db.raw.prepare('PRAGMA integrity_check').get().integrity_check);
console.log('    audit chain:', c.ok ? 'ok, '+c.entries+' entries' : 'BROKEN '+JSON.stringify(c).slice(0,120));
console.log('    counts:', JSON.stringify({ candidates: n('candidates'), decisions: n('decisions'), audit: n('audit'), members: n('members'), policies: n('policies'), policy_lifts: n('policy_lifts'), sessions: n('sessions') }));
process.exit(c.ok ? 0 : 3);
" || { echo "VERIFY FAILED: nothing was kept"; exit 1; }
echo "[3] encrypt with the recipient of backup-trust.json"
mkdir -p "$OUT" && age -r "$REC" -o "$OUT/panel-d1-export.sql.age" "$T/panel.sql" || { echo "ENCRYPT FAILED"; exit 1; }
printf '{"database":"macguard-quarantine","at":"%s","plaintext_sha256":"%s","bytes":%s,"kind":"local-operator-backup"}\n' "$STAMP" "$SHA" "$BYTES" > "$OUT/manifest.json"
( cd "$OUT" && shasum -a 256 manifest.json panel-d1-export.sql.age > SHA256SUMS )
echo "[4] read the ciphertext back with the identity from the Keychain and compare"
BACK=$(security find-generic-password -s macguard-gateway-prod -a BACKUP_AGE_IDENTITY -w 2>/dev/null | age -d -i - "$OUT/panel-d1-export.sql.age" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
[ "$BACK" = "$SHA" ] && echo "    read-back hash matches the export: VERIFIED" || { echo "    READ-BACK MISMATCH or identity unavailable: the copy is NOT verified"; exit 2; }
$BUDGET record --label "local-backup panel" --before "$T/budget-before.json" 2>&1 | tail -1
echo "BACKUP DONE: $OUT"
