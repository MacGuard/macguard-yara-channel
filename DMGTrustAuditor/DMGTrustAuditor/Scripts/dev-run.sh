#!/usr/bin/env bash
# One command to build and run the current MacGuard from this repository.
#   Scripts/dev-run.sh            build engine (first time only), generate the Xcode project, build GUI + CLI, open the GUI
#   Scripts/dev-run.sh --xcode    same, but open the project in Xcode instead of launching the app
#   Scripts/dev-run.sh --no-open  build only
# Needs: Xcode, `brew install xcodegen autoconf automake libtool`.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; repo="$(cd "$here/../.." && pwd)"; engine="$repo/build/engine"
cd "$here"
if [ ! -f "$engine/yara" ]; then echo "Building the YARA engine (about 10 minutes, once)…"; Scripts/build-yara-engine.sh "$engine"; fi
xcodegen generate >/dev/null
if [ "${1:-}" = "--xcode" ]; then open DMGTrustAuditor.xcodeproj; echo "In Xcode: scheme DMGTrustAuditor → Product ▸ Run (⌘R). If it asks for signing, choose 'Sign to Run Locally'."; exit 0; fi
for scheme in DMGTrustAuditor macguard-audit; do
  xcodebuild -project DMGTrustAuditor.xcodeproj -scheme "$scheme" -configuration Debug CODE_SIGNING_ALLOWED=NO CODE_SIGN_IDENTITY=- -derivedDataPath "$repo/build/derived" build | tail -1
done
app="$repo/build/derived/Build/Products/Debug/DMGTrustAuditor.app"; cli="$repo/build/derived/Build/Products/Debug/macguard-audit"
echo "GUI: $app"; echo "CLI/TUI: $cli   (try: $cli engine-status ; $cli tui ~/Downloads)"
[ "${1:-}" = "--no-open" ] || open "$app"
