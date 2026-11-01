#!/bin/sh
# Builds the FIRST commit of the evidence branch in an empty directory: the records of the existing log copied VERBATIM (nothing is rewritten, so every reference to a run or a restore stays valid),
# the hash chain for them, and a README with the integrity policy. It does not push: creating the branch on the remote is a separate, authorised step (docs/operations/EVIDENCE-MIGRATION.md).
#   evidence_seed.sh DIR SOURCE.jsonl
# Refuses a non-empty DIR. The source file is never modified, and main keeps its copy: nothing is removed from where it is today.
set -eu
DIR=${1:?usage: evidence_seed.sh DIR SOURCE.jsonl}; SRC=${2:?usage: evidence_seed.sh DIR SOURCE.jsonl}
TOOLS=$(cd "$(dirname "$0")" && pwd)
[ -f "$SRC" ] || { echo "no such source file: $SRC" >&2; exit 1; }
if [ -e "$DIR" ] && [ -n "$(ls -A "$DIR")" ]; then echo "refused: $DIR is not empty" >&2; exit 1; fi
mkdir -p "$DIR/evidence"; cp "$SRC" "$DIR/evidence/backups.jsonl"
cat > "$DIR/README.md" <<'EOT'
# Evidence branch

`evidence/backups.jsonl` is the append-only record of backups and restorations (one JSON object per line). `evidence/backups.chain` is its hash chain (`<n> <sha256>`): each value commits to the previous one
and to the record, so changing, removing or reordering any record breaks every later line. A checkpoint (`macguard.evidence-checkpoint/1`: count + head) is signed with Sigstore and logged in Rekor, outside this
repository, by `.github/workflows/evidence-checkpoint.yml`; `node gateway/tools/evidence_chain.mjs verify --checkpoint FILE` proves the log still contains exactly what was signed.

This branch is NOT write-once storage: whoever can push here could rewrite it. The protection against that is (1) no force-push and no deletion on this branch, (2) the chain and the external checkpoints, which
make a rewrite detectable, and (3) the copies of each backup's own signed statement in the three object stores. The branch holds no code and no secrets; CI workflows only ever append to the two files above.
EOT
git -C "$DIR" init -q -b evidence
node "$TOOLS/evidence_chain.mjs" update --dir "$DIR/evidence"
git -C "$DIR" config user.name 'macguard-evidence[bot]'; git -C "$DIR" config user.email 'macguard-evidence@users.noreply.github.com'
git -C "$DIR" add README.md evidence/backups.jsonl evidence/backups.chain
git -C "$DIR" commit -q -m "evidence: seed from main ($(grep -c . "$SRC") records, copied verbatim, chain started)"
node "$TOOLS/evidence_chain.mjs" verify --dir "$DIR/evidence"
