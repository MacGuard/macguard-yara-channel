#!/usr/bin/env bash
# Serves a built site on localhost and runs the in-browser checks (tests/web/e2e.html) with headless Chrome.
# usage: web_check.sh [site-dir] [mode]      mode: empty or "tamper"
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; site="${1:-$here/site}"; mode="${2:-}"
chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
port=$((20000 + RANDOM % 20000)); tmp="$(mktemp -d)"; trap 'kill $srv 2>/dev/null; rm -rf "$tmp"' EXIT
cp -R "$site/." "$tmp/"; cp "$here/tests/web/e2e.html" "$tmp/__e2e.html"
if [ "$mode" = tamper ]; then python3 - "$tmp/logs/log.jsonl" <<'PY'
import sys; p=sys.argv[1]; l=open(p).read().split('\n'); l[3]=l[3].replace('"event"','"evenT"',1); open(p,'w').write('\n'.join(l))
PY
fi
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$tmp" >/dev/null 2>&1 & srv=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$port/index.html" >/dev/null && break; sleep 0.2; done
url="http://127.0.0.1:$port/__e2e.html"; [ "$mode" = tamper ] && url="$url?mode=tamper"
"$chrome" --headless=new --disable-gpu --no-sandbox --virtual-time-budget=60000 --dump-dom "$url" 2>/dev/null | python3 -c "
import sys,re,html
d=sys.stdin.read(); m=re.search(r'<pre id=\"result\">(.*?)</pre>',d,re.S); t=html.unescape(m.group(1)) if m else d[-500:]
print(t); sys.exit(0 if 'DONE' in t and 'FAIL' not in t else 1)"
