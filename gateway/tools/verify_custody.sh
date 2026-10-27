#!/bin/sh
# Checks that PRIVATE copies you hold (restored from the password manager, from paper, from a second location) correspond to the PUBLIC facts in the recovery kit, without printing, copying or logging any secret.
#
#   verify_custody.sh KIT_FILE [--age-identity FILE] [--signing-key FILE]
#
# For the age identity it derives the public recipient (`age-keygen -y`) and compares it with the kit; for the signing key it derives the public line (`ssh-keygen -y`; a passphrase-protected key will ask for the
# passphrase on the terminal) and compares it with the kit. It also refuses a custody mistake: a private file with permissions open to group or others, or one that sits inside a git working tree.
# Output is only OK / MISMATCH / WARNING lines. Exit 0 = every given file matches and has no custody warning; 1 = a mismatch or a warning; 2 = usage or a missing tool.
set -u
[ $# -ge 1 ] || { echo "usage: $0 KIT_FILE [--age-identity FILE] [--signing-key FILE]" >&2; exit 2; }
KIT=$1; shift; AGE_ID=; SIGN_KEY=
while [ $# -gt 0 ]; do case $1 in --age-identity) AGE_ID=${2:-}; shift 2;; --signing-key) SIGN_KEY=${2:-}; shift 2;; *) echo "unknown option" >&2; exit 2;; esac; done
[ -f "$KIT" ] || { echo "the kit file does not exist" >&2; exit 2; }
BAD=0
kit_after() { awk -v h="$1" 'index($0,h)==1 {getline; print; exit}' "$KIT"; }
KIT_PUB=$(kit_after "TRUSTED SIGNING PUBLIC KEY" | cut -d' ' -f1,2); KIT_REC=$(kit_after "AGE RECIPIENT" | tr -d ' ')
# GNU stat first: on Linux 'stat -f FORMAT FILE' is the FILESYSTEM status and prints several lines, which made every key look world-readable.
mode_ok() { m=$(stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null); case $m in ?00) return 0;; *) return 1;; esac; }
in_git() { d=$(dirname "$1"); git -C "$d" rev-parse --is-inside-work-tree >/dev/null 2>&1; }
custody() { f=$1; label=$2; mode_ok "$f" || { echo "WARNING: $label has permissions open to group or others (run chmod 600)"; BAD=1; }; in_git "$f" && { echo "WARNING: $label is inside a git working tree: move it out of any repository"; BAD=1; }; return 0; }
if [ -n "$AGE_ID" ]; then
  command -v age-keygen >/dev/null 2>&1 || { echo "missing tool: age-keygen" >&2; exit 2; }
  [ -f "$AGE_ID" ] || { echo "the age identity file does not exist" >&2; exit 2; }
  custody "$AGE_ID" "the age identity"
  DER=$(age-keygen -y "$AGE_ID" 2>/dev/null | tr -d ' ')
  if [ -n "$DER" ] && [ "$DER" = "$KIT_REC" ]; then echo "OK: the age identity matches the recipient in the kit"; else echo "MISMATCH: the age identity does not match the recipient in the kit"; BAD=1; fi
fi
if [ -n "$SIGN_KEY" ]; then
  command -v ssh-keygen >/dev/null 2>&1 || { echo "missing tool: ssh-keygen" >&2; exit 2; }
  [ -f "$SIGN_KEY" ] || { echo "the signing key file does not exist" >&2; exit 2; }
  custody "$SIGN_KEY" "the signing key"
  DER=$(ssh-keygen -y -f "$SIGN_KEY" 2>/dev/null | cut -d' ' -f1,2)
  if [ -n "$DER" ] && [ "$DER" = "$KIT_PUB" ]; then echo "OK: the signing key matches the public key in the kit"; else echo "MISMATCH: the signing key does not match the public key in the kit"; BAD=1; fi
fi
[ -n "$AGE_ID$SIGN_KEY" ] || echo "nothing to check: give --age-identity and/or --signing-key"
exit $BAD
