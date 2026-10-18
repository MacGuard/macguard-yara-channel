#!/usr/bin/env bash
# Starts the real worker handler with seeded data and drives the admin UI in headless Chrome.
set -euo pipefail
cd "$(dirname "$0")/.."; port=$((20000 + RANDOM % 20000)); chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
node test/devserver.js "$port" >/tmp/mg-dev.log 2>&1 & srv=$!; trap 'kill $srv 2>/dev/null' EXIT
for _ in $(seq 50); do grep -q ready /tmp/mg-dev.log 2>/dev/null && break; sleep 0.2; done
"$chrome" --headless=new --disable-gpu --no-sandbox --virtual-time-budget=60000 --dump-dom "http://127.0.0.1:$port/__e2e.html" 2>/dev/null | python3 -c "
import sys,re,html
d=sys.stdin.read(); m=re.search(r'<pre id=\"result\">(.*?)</pre>',d,re.S); t=html.unescape(m.group(1)) if m else d[-400:]
print(t); sys.exit(0 if 'DONE' in t and 'FAIL' not in t else 1)"
