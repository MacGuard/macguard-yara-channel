#!/bin/sh
# Prints KEY=VALUE lines (for $GITHUB_ENV) for one protected database: where its statements live (prefix), the trust policy that applies to it, the age recipient and the database name. Public values only.
#   ci_profile.sh gateway|panel
set -eu
R=${1:-}; MODE=${2:-env}; P=gateway/environments/backup-resources.json; T=gateway/environments/backup-trust.json
jq -e --arg r "$R" '.resources[$r]' "$P" >/dev/null 2>&1 || { echo "unknown resource: $R" >&2; exit 2; }
out() { if [ "$MODE" = --shell ]; then printf "%s='%s'\n" "$1" "$2"; else printf "%s=%s\n" "$1" "$2"; fi; }
out PREFIX "$(jq -r --arg r "$R" '.resources[$r].prefix' $P)"
out DBNAME "$(jq -r --arg r "$R" '.resources[$r].database' $P)"
out GENESIS "$(jq -r --arg r "$R" '.resources[$r].genesis // empty' $P)"
out ED_PUB "$(jq -r .ed25519.public_key $T)"
out ED_MAX "$(jq -r --arg r "$R" '.resources[$r].ed25519_max_sequence // .ed25519.max_sequence' $T)"
out SIG_ID "$(jq -r .sigstore.identity $T)"
out SIG_REPO "$(jq -r .sigstore.repository $T)"
out RECIPIENT "$(jq -r .age_recipient $T)"
