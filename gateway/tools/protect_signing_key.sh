#!/bin/sh
# OWNER PROCEDURE: adds a passphrase to the backup signing key WITHOUT changing the key pair, updates the existing Bitwarden entry, stores the passphrase in a separate Bitwarden item, proves that the stored copy and the
# stored passphrase unlock a key with the SAME public key, and only then replaces the local file (atomically). Run it yourself, in a terminal, with the vault unlocked (export BW_SESSION="$(bw unlock --raw)").
#
#   protect_signing_key.sh KEY_FILE KEY_ITEM PASSPHRASE_ITEM        KEY_FILE.pub must exist; KEY_ITEM is the EXISTING secure note; PASSPHRASE_ITEM is created (a login) or updated
#
# The passphrase is typed twice on the terminal (no echo) or read from two lines of stdin; it never appears in an argument, an environment variable or the output. It lives only in mode-600 files inside a private
# temporary directory, handed to ssh-keygen through an askpass helper, and that directory is removed on exit. Nothing is replaced until every check has passed; if the Bitwarden check fails after the note was edited,
# the note is put back from the untouched local key and the local file is left as it was. Output: OK / FAILED lines only. Exit 0 = done, 1 = refused or failed, 2 = usage / missing tool.
set -u
[ $# -eq 3 ] || { echo "usage: $0 KEY_FILE KEY_ITEM PASSPHRASE_ITEM" >&2; exit 2; }
KEY=$1; KITEM=$2; PITEM=$3; PUB=$KEY.pub
for t in ssh-keygen bw jq; do command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }; done
[ -n "${BW_SESSION:-}" ] || { echo "FAILED: the vault is locked (export BW_SESSION=\"\$(bw unlock --raw)\" first)"; exit 1; }
[ -s "$KEY" ] && [ -f "$PUB" ] || { echo "FAILED: $KEY is missing or empty, or $PUB does not exist"; exit 1; }
umask 077
W=$(mktemp -d "${TMPDIR:-/tmp}/mg-protect.XXXXXX") || exit 1
trap 'rm -rf "$W"' EXIT INT TERM
WANT=$(cut -d' ' -f1,2 "$PUB")
derive() { ssh-keygen -y -f "$1" </dev/null 2>/dev/null | cut -d' ' -f1,2; }
[ "$(ssh-keygen -y -P '' -f "$KEY" </dev/null 2>/dev/null | cut -d' ' -f1,2)" = "$WANT" ] || { echo "FAILED: $KEY is not an UNPROTECTED key matching $PUB (already protected, or a different key): nothing was changed"; exit 1; }
if [ -t 0 ]; then printf 'New passphrase: ' >&2; stty -echo 2>/dev/null; IFS= read -r P1; printf '\nAgain: ' >&2; IFS= read -r P2; stty echo 2>/dev/null; printf '\n' >&2; else IFS= read -r P1; IFS= read -r P2; fi
[ -n "$P1" ] && [ "$P1" = "${P2:-}" ] || { echo "FAILED: empty passphrase or the two entries differ: nothing was changed"; exit 1; }
printf '%s' "$P1" > "$W/pp"; unset P1 P2
printf '#!/bin/sh\ncat "%s/pp"\n' "$W" > "$W/ask_local"; chmod 700 "$W/ask_local"
# 1. protect a COPY; the key pair must not change
cp "$KEY" "$W/k" && chmod 600 "$W/k"
SSH_ASKPASS="$W/ask_local" SSH_ASKPASS_REQUIRE=force DISPLAY=none ssh-keygen -q -p -f "$W/k" </dev/null >/dev/null 2>&1 || { echo "FAILED: ssh-keygen could not protect the copy: nothing was changed"; exit 1; }
[ "$(SSH_ASKPASS="$W/ask_local" SSH_ASKPASS_REQUIRE=force DISPLAY=none ssh-keygen -y -f "$W/k" </dev/null 2>/dev/null | cut -d' ' -f1,2)" = "$WANT" ] || { echo "FAILED: the protected copy does not derive the public key: nothing was changed"; exit 1; }
[ -z "$(ssh-keygen -y -P '' -f "$W/k" </dev/null 2>/dev/null)" ] || { echo "FAILED: the copy is still unprotected: nothing was changed"; exit 1; }
echo "OK: the copy is passphrase-protected and derives the same public key"
# 2. Bitwarden: keep the old note aside (it is the untouched local key), edit the note, store the passphrase
bw sync >/dev/null 2>&1
bw get item "$KITEM" > "$W/item.json" 2>/dev/null && [ -s "$W/item.json" ] || { echo "FAILED: the Bitwarden item '$KITEM' could not be read: nothing was changed"; exit 1; }
KID=$(jq -r '.id' "$W/item.json")
jq --rawfile k "$W/k" '.notes=$k' "$W/item.json" | bw encode | bw edit item "$KID" >/dev/null 2>&1 || { echo "FAILED: the note could not be updated"; exit 1; }
revert() { jq --rawfile k "$KEY" '.notes=$k' "$W/item.json" | bw encode | bw edit item "$KID" >/dev/null 2>&1 && echo "REVERTED: the note holds the previous key again" || echo "WARNING: the note could NOT be reverted: it holds the protected key, which is still valid; do not delete the local file"; }
if bw get item "$PITEM" > "$W/pitem.json" 2>/dev/null && [ -s "$W/pitem.json" ]; then PID=$(jq -r '.id' "$W/pitem.json"); jq --rawfile p "$W/pp" '.login.password=$p' "$W/pitem.json" | bw encode | bw edit item "$PID" >/dev/null 2>&1 || { revert; echo "FAILED: the passphrase item could not be updated"; exit 1; }
else bw get template item | jq --rawfile p "$W/pp" --arg n "$PITEM" '.type=1 | .name=$n | .login={username:"backup-signing-passphrase", password:$p}' | bw encode | bw create item >/dev/null 2>&1 || { revert; echo "FAILED: the passphrase item could not be created"; exit 1; }; fi
# 3. prove it from Bitwarden alone: the stored note, unlocked with the stored passphrase, must derive the public key
printf '#!/bin/sh\nbw get password "%s"\n' "$PITEM" > "$W/ask_bw"; chmod 700 "$W/ask_bw"
bw get notes "$KITEM" > "$W/rk" 2>/dev/null; chmod 600 "$W/rk"
if [ -s "$W/rk" ] && [ "$(SSH_ASKPASS="$W/ask_bw" SSH_ASKPASS_REQUIRE=force DISPLAY=none ssh-keygen -y -f "$W/rk" </dev/null 2>/dev/null | cut -d' ' -f1,2)" = "$WANT" ]; then echo "OK: the key recovered from Bitwarden, unlocked with the stored passphrase, matches the public key"; else revert; echo "FAILED: the Bitwarden copy and passphrase do NOT unlock the expected key; the local file was not replaced"; exit 1; fi
[ -z "$(ssh-keygen -y -P '' -f "$W/rk" </dev/null 2>/dev/null)" ] || { revert; echo "FAILED: the stored note is not passphrase-protected"; exit 1; }
# 4. replace the local file atomically, only now
cp "$W/k" "$(dirname "$KEY")/.protect.$$" && chmod 400 "$(dirname "$KEY")/.protect.$$" && mv "$(dirname "$KEY")/.protect.$$" "$KEY" && echo "OK: local key replaced atomically (mode 400); same fingerprint: $(ssh-keygen -l -f "$PUB" | cut -d' ' -f2)" || { echo "FAILED: the local file could not be replaced; Bitwarden holds the protected key, the local file is the old one"; exit 1; }
echo "DONE: temporary files are removed on exit; delete any other unprotected copy you made yourself"
