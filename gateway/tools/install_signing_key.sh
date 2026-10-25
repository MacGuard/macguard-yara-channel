#!/bin/sh
# Installs the backup SIGNING private key from stdin into KEY_FILE without ever leaving a truncated file there, and only if it matches the public key next to it.
#
#   bw get notes "<item>" | install_signing_key.sh KEY_FILE          (KEY_FILE.pub must already exist; the secret travels only through the pipe)
#
# The old shape `bw get notes … > KEY_FILE` truncates KEY_FILE before bw has produced anything, so a locked vault, a wrong item name or an interrupted run leaves a 0-byte key. Here the key is written to a private
# temp file in the same directory, checked (non-empty, a valid private key, derives exactly the public line of KEY_FILE.pub), and only then moved into place atomically with mode 400.
# An existing non-empty KEY_FILE is never replaced. Prints OK / REFUSED lines only. Exit 0 = installed, 1 = refused, 2 = usage.
set -u
[ $# -eq 1 ] || { echo "usage: bw get notes ITEM | $0 KEY_FILE" >&2; exit 2; }
KEY=$1; PUB=$KEY.pub
[ -f "$PUB" ] || { echo "REFUSED: $PUB does not exist"; exit 1; }
if [ -s "$KEY" ]; then echo "REFUSED: $KEY already exists and is not empty; it is never replaced"; exit 1; fi
umask 077
T=$(mktemp "$(dirname "$KEY")/.install.XXXXXX") || exit 1
trap 'rm -f "$T"' EXIT INT TERM
cat > "$T"
[ -s "$T" ] || { echo "REFUSED: nothing came in on stdin (locked vault or wrong item?); $KEY was not touched"; exit 1; }
chmod 600 "$T"
GOT=$(ssh-keygen -y -f "$T" </dev/null 2>/dev/null | cut -d' ' -f1,2); WANT=$(cut -d' ' -f1,2 "$PUB")
[ -n "$GOT" ] || { echo "REFUSED: stdin is not a usable private key (or it is passphrase-protected: run ssh-keygen -y -f on it interactively); $KEY was not touched"; exit 1; }
[ "$GOT" = "$WANT" ] || { echo "REFUSED: the key does not match $PUB; $KEY was not touched"; exit 1; }
mv "$T" "$KEY" && chmod 400 "$KEY" && trap - EXIT INT TERM && echo "OK: installed, matches the public key, mode 400"
