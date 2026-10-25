#!/bin/sh
# Independent verification (and optional decryption) of ONE downloaded MacGuard backup, with nothing from this repository: only ssh-keygen, age, a SHA-256 tool and python3 (for JSON).
# It is meant to be copied into the recovery kit and run on a clean machine after the Mac is lost.
#
#   recover_verify.sh BACKUP_DIR PUBLIC_KEY MIN_SEQUENCE [IDENTITY_FILE OUTPUT_SQL]
#
#   BACKUP_DIR    a directory holding the five downloaded files: d1-export.sql.age manifest.json SHA256SUMS ANCHOR.json ANCHOR.json.sig
#   PUBLIC_KEY    the trusted signing key: either a file whose first line is "ssh-ed25519 AAAA..." or that line itself (from the recovery kit, NOT from the bucket)
#   MIN_SEQUENCE  the newest sequence number you know from the kit (0 if you know none): an older backup is refused as a rollback
#   IDENTITY_FILE the age identity FILE (never typed or printed here); with it, the ciphertext is decrypted to OUTPUT_SQL (mode 600) and its SHA-256 compared with the manifest
#   MG_CHECKPOINT_DIRS  (REQUIRED unless MG_ALLOW_NO_CHECKPOINT=1) colon-separated directories, each holding one external copy of CHECKPOINT.json and CHECKPOINT.json.sig. Each is verified with the same key under its own
#                       namespace; the newest authentic one counts, and a backup older than it (or at the same sequence with another head) is refused: this is what catches every provider serving an old coherent copy.
#   MG_ALLOW_NO_CHECKPOINT=1  explicit opt-out for a rehearsal: without a trusted checkpoint a rollback of every copy cannot be excluded, and the output says so.
#   MG_SIGSTORE_IDENTITY, MG_SIGSTORE_REPO, MG_ED25519_MAX_SEQUENCE  (all three together, from the kit; needs `cosign`) accept Sigstore keyless bundles (ANCHOR.json.sigstore.json, CHECKPOINT.json.sigstore.json) for every
#                       sequence ABOVE the Ed25519 freeze point, for the exact workflow identity only. Above that point an Ed25519 signature is refused (no downgrade); at or below it the Ed25519 key is used. MG_TRUSTED_ROOT optionally
#                       names a Sigstore trusted_root.json so verification needs no network.
# Exit: 0 verified (and decrypted when asked), 1 refused (nothing is decrypted), 2 usage or tool missing. It prints no secret.
set -u
umask 077
die() { echo "REFUSED: $1" >&2; exit 1; }
[ $# -ge 3 ] || { echo "usage: $0 BACKUP_DIR PUBLIC_KEY MIN_SEQUENCE [IDENTITY_FILE OUTPUT_SQL]" >&2; exit 2; }
DIR=$1; KEYARG=$2; MINSEQ=$3; IDENT=${4:-}; OUT=${5:-}
for t in ssh-keygen python3; do command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }; done
if [ -n "$IDENT" ]; then command -v age >/dev/null 2>&1 || { echo "missing tool: age" >&2; exit 2; }; [ -n "$OUT" ] || { echo "OUTPUT_SQL is required with an identity" >&2; exit 2; }; fi
case $MINSEQ in ''|*[!0-9]*) echo "MIN_SEQUENCE must be a number" >&2; exit 2;; esac
for f in d1-export.sql.age manifest.json SHA256SUMS ANCHOR.json; do [ -f "$DIR/$f" ] || die "$f is missing: this backup carries no signed anchor"; done
if [ -f "$KEYARG" ]; then KEY=$(head -n 1 "$KEYARG"); else KEY=$KEYARG; fi
printf '%s' "$KEY" | python3 -c 'import re,sys; s=sys.stdin.read(); sys.exit(0 if re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{43,}={0,2}( [^\r\n]*)?", s) else 1)' || die "the trusted key is not a single ssh-ed25519 line"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/mg-recover.XXXXXX") || exit 2
trap 'rm -rf "$TMP"' EXIT INT TERM
printf 'macguard-backup namespaces="macguard-backup/1" %s\n' "$(printf '%s' "$KEY" | cut -d' ' -f1,2)" > "$TMP/allowed"
seq_of() { python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["sequence"]))' "$1" 2>/dev/null; }
sigstore_verify() { cosign verify-blob --bundle "$2" --certificate-identity "$MG_SIGSTORE_IDENTITY" --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-github-workflow-repository "$MG_SIGSTORE_REPO" ${MG_TRUSTED_ROOT:+--trusted-root "$MG_TRUSTED_ROOT"} "$1" >/dev/null 2>&1; }
SIGSTORE=0
if [ -n "${MG_SIGSTORE_IDENTITY:-}${MG_SIGSTORE_REPO:-}${MG_ED25519_MAX_SEQUENCE:-}" ]; then
  [ -n "${MG_SIGSTORE_IDENTITY:-}" ] && [ -n "${MG_SIGSTORE_REPO:-}" ] && [ -n "${MG_ED25519_MAX_SEQUENCE:-}" ] || die "MG_SIGSTORE_IDENTITY, MG_SIGSTORE_REPO and MG_ED25519_MAX_SEQUENCE must be given together"
  case $MG_ED25519_MAX_SEQUENCE in ''|*[!0-9]*) die "MG_ED25519_MAX_SEQUENCE must be a number";; esac
  printf '%s' "$MG_SIGSTORE_IDENTITY" | python3 -c 'import re,sys; s=sys.stdin.read(); sys.exit(0 if re.fullmatch(r"https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/\.github/workflows/[A-Za-z0-9._-]+\.ya?ml@refs/heads/[A-Za-z0-9._/-]+", s) else 1)' || die "the Sigstore identity must be one exact GitHub workflow identity (a pattern is never accepted)"
  printf '%s' "$MG_SIGSTORE_REPO" | python3 -c 'import re,sys; sys.exit(0 if re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", sys.stdin.read()) else 1)' || die "MG_SIGSTORE_REPO must be OWNER/REPO"
  command -v cosign >/dev/null 2>&1 || { echo "missing tool: cosign" >&2; exit 2; }
  SIGSTORE=1
fi
ASEQ=$(seq_of "$DIR/ANCHOR.json") || die "the signed statement is not valid JSON or has no sequence"
SCHEME=ed25519
if [ $SIGSTORE = 1 ] && [ "$ASEQ" -gt "$MG_ED25519_MAX_SEQUENCE" ]; then
  [ -f "$DIR/ANCHOR.json.sigstore.json" ] || die "sequence $ASEQ must be signed with Sigstore keyless (Ed25519 is frozen at $MG_ED25519_MAX_SEQUENCE): no downgrade"
  sigstore_verify "$DIR/ANCHOR.json" "$DIR/ANCHOR.json.sigstore.json" || die "the Sigstore bundle does not verify for the pinned workflow identity"
  SCHEME=sigstore
else
  [ -f "$DIR/ANCHOR.json.sig" ] || die "ANCHOR.json.sig is missing: this backup carries no signed anchor"
  ssh-keygen -Y verify -f "$TMP/allowed" -I macguard-backup -n macguard-backup/1 -s "$DIR/ANCHOR.json.sig" < "$DIR/ANCHOR.json" >/dev/null 2>&1 || die "the signature does not verify with the trusted key"
fi
export MG_SCHEME=$SCHEME
N=0
[ -n "${MG_CHECKPOINT_DIRS:-}" ] || [ "${MG_ALLOW_NO_CHECKPOINT:-}" = 1 ] || die "no trusted checkpoint was given (MG_CHECKPOINT_DIRS): without one a rollback of every copy cannot be excluded. Nothing was decrypted."
if [ -n "${MG_CHECKPOINT_DIRS:-}" ]; then
  printf 'macguard-backup namespaces="macguard-backup-checkpoint/1" %s\n' "$(printf '%s' "$KEY" | cut -d' ' -f1,2)" > "$TMP/allowed-cp"
  OLDIFS=$IFS; IFS=:; for CD in $MG_CHECKPOINT_DIRS; do
    IFS=$OLDIFS; N=$((N+1))
    OK=0
    if [ -f "$CD/CHECKPOINT.json" ]; then
      CSEQ=$(seq_of "$CD/CHECKPOINT.json") || CSEQ=
      if [ -n "$CSEQ" ] && [ $SIGSTORE = 1 ] && [ "$CSEQ" -gt "$MG_ED25519_MAX_SEQUENCE" ]; then [ -f "$CD/CHECKPOINT.json.sigstore.json" ] && sigstore_verify "$CD/CHECKPOINT.json" "$CD/CHECKPOINT.json.sigstore.json" && OK=1
      elif [ -n "$CSEQ" ] && [ -f "$CD/CHECKPOINT.json.sig" ] && ssh-keygen -Y verify -f "$TMP/allowed-cp" -I macguard-backup -n macguard-backup-checkpoint/1 -s "$CD/CHECKPOINT.json.sig" < "$CD/CHECKPOINT.json" >/dev/null 2>&1; then OK=1; fi
    fi
    if [ $OK = 1 ]; then cp "$CD/CHECKPOINT.json" "$TMP/cp-$N.json"; else echo "note: checkpoint copy $N is missing or not authentic and is ignored" >&2; fi
    IFS=:
  done; IFS=$OLDIFS
  ls "$TMP"/cp-*.json >/dev/null 2>&1 || die "MG_CHECKPOINT_DIRS was given but no authentic checkpoint copy was found: a rollback cannot be excluded"
fi
export MG_TMP_DIR="$TMP"
python3 - "$DIR" "$MINSEQ" <<'PY' || exit 1
import hashlib, json, sys
d, minseq = sys.argv[1], int(sys.argv[2])
raw = open(f"{d}/ANCHOR.json", "rb").read(); a = json.loads(raw)
canon = (json.dumps({k: (dict(sorted(v.items())) if isinstance(v, dict) else v) for k, v in sorted(a.items())}, separators=(",", ":")) + "\n").encode()
def no(m): print("REFUSED: " + m, file=sys.stderr); sys.exit(1)
if raw != canon: no("the signed statement is not in canonical form")
if a.get("schema") != "macguard.backup-anchor/1": no("unknown statement schema")
for f, h in sorted(a["files"].items()):
    if hashlib.sha256(open(f"{d}/{f}", "rb").read()).hexdigest() != h: no(f"{f} does not match the signed statement")
if not isinstance(a["sequence"], int) or a["sequence"] < minseq: no(f"rollback: sequence {a['sequence']} is older than the newest known ({minseq})")
import glob, os
cps = []
for f in sorted(glob.glob(os.environ.get("MG_TMP_DIR", "") + "/cp-*.json")):
    c = json.load(open(f))
    canon_c = (json.dumps({k: c[k] for k in sorted(c)}, separators=(",", ":")) + "\n").encode()
    if open(f, "rb").read() != canon_c or c.get("schema") != "macguard.backup-checkpoint/1": no("a checkpoint is not in canonical form")
    cps.append(c)
if cps:
    top = max(c["sequence"] for c in cps); heads = {c["head_sha256"] for c in cps if c["sequence"] == top}
    if len(heads) > 1: no(f"two authentic checkpoints name different heads for sequence {top} (equivocation)")
    mine = hashlib.sha256(raw).hexdigest()
    if a["sequence"] < top: no(f"rollback or loss: this backup is sequence {a['sequence']} but sequence {top} was confirmed")
    if a["sequence"] == top and mine not in heads: no(f"fork: sequence {top} is signed but its head differs from the confirmed one")
print(f"ANCHORED OK stamp={a['stamp']} sequence={a['sequence']} head_sha256={hashlib.sha256(raw).hexdigest()} scheme={os.environ.get('MG_SCHEME','ed25519')}" + (f" checkpoint_sequence={max(c['sequence'] for c in cps)}" if cps else " checkpoint=none NOT-PROTECTED-AGAINST-ROLLBACK"))
PY
[ -n "$IDENT" ] || exit 0
[ -f "$IDENT" ] || die "the identity file does not exist"
age -d -i "$IDENT" -o "$OUT" "$DIR/d1-export.sql.age" 2>/dev/null || { rm -f "$OUT"; die "age could not decrypt with this identity"; }
python3 - "$DIR" "$OUT" <<'PY' || { rm -f "$OUT"; exit 1; }
import hashlib, json, sys
m = json.load(open(f"{sys.argv[1]}/manifest.json")); h = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
if h != m.get("plaintext_sha256"): print("REFUSED: the decrypted bytes do not match the manifest", file=sys.stderr); sys.exit(1)
print("DECRYPTED OK plaintext_sha256=" + h)
PY
