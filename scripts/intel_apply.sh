#!/bin/sh
# Applies a promotion directory (chunk-*.sql + promotion.json from intel_promote.py) to the INTEL database, in order, resumable.
# Every chunk's SHA-256 is checked against promotion.json before it is sent; a failure stops at that chunk (the SQL is INSERT OR REPLACE, so a rerun resumes safely). Prints counts and verdicts only.
# usage: scripts/intel_apply.sh PROMOTION_DIR [DB_NAME=macguard-intel] [WRANGLER_CONFIG]
set -u
D=${1:?promotion directory}; DB=${2:-macguard-intel}; CFG=${3:-}
[ -f "$D/promotion.json" ] || { echo "no promotion.json in $D"; exit 2; }
DONE="$D/applied.txt"; touch "$DONE"
for f in $(ls "$D"/chunk-*.sql | sort); do
  b=$(basename "$f"); grep -qx "$b" "$DONE" && { echo "skip $b (already applied)"; continue; }
  want=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$D/promotion.json','utf8')).chunk_sha256['$b']||'')"); got=$(shasum -a 256 "$f" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "REFUSED $b: hash differs from promotion.json"; exit 3; }
  out=$(timeout 900 npx --yes wrangler@4.149.0 d1 execute "$DB" --remote --file "$f" ${CFG:+--config "$CFG"} 2>&1 | sed "s/\x1b\[[0-9;]*m//g")
  if echo "$out" | grep -q '"success": true'; then echo "$b ok: $(echo "$out" | grep -o 'Executed [0-9]* queries[^"]*' | head -1)"; echo "$b" >> "$DONE"; else echo "$b FAILED: $(echo "$out" | grep -iE 'error|quota|limit' | head -2 | cut -c1-200)"; exit 4; fi
done
echo "APPLIED ALL"
