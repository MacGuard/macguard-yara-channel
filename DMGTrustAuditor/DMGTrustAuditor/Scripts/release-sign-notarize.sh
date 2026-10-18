#!/bin/bash
set -euo pipefail
# Release-only bundling. Developer supplies a locally built, audited universal YARA CLI.
: "${TEAM_ID:?Set Apple Developer Team ID}"
: "${BUNDLE_ID:?Set registered Bundle ID}"
: "${SIGNING_IDENTITY:?Set exact Developer ID Application identity}"
: "${NOTARY_PROFILE:?Set notarytool keychain profile}"
: "${YARA_BINARY:?Set path to reviewed, locally built universal yara executable}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -f "$YARA_BINARY" && -x "$YARA_BINARY" ]] || { echo 'Missing executable YARA_BINARY' >&2; exit 2; }
file "$YARA_BINARY"
ARCHS="$(lipo -archs "$YARA_BINARY")"
for arch in x86_64 arm64; do
  [[ " $ARCHS " == *" $arch "* ]] || { echo "Missing $arch in YARA_BINARY" >&2; exit 2; }
done
command -v xcodegen >/dev/null || { echo 'xcodegen is required for developer release' >&2; exit 2; }
OUT="${OUTPUT_DIR:-$ROOT/release-output}"
mkdir -p "$OUT"
xcodegen generate
# Build unsigned so nested helper can be added before final signing.
xcodebuild -project DMGTrustAuditor.xcodeproj -scheme DMGTrustAuditor -configuration Release -destination 'generic/platform=macOS' -derivedDataPath "$OUT/DerivedData" PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID" CODE_SIGNING_ALLOWED=NO build
APP="$OUT/DerivedData/Build/Products/Release/DMGTrustAuditor.app"
HELPERS="$APP/Contents/Helpers"
mkdir -p "$HELPERS"
cp "$YARA_BINARY" "$HELPERS/yara"
chmod 755 "$HELPERS/yara"
# Nested code must be signed before its parent. No --deep signing.
codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$HELPERS/yara"
codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$APP"
codesign --verify --strict --verbose=2 "$HELPERS/yara"
codesign --verify --strict --verbose=2 "$APP"
codesign -dv --verbose=4 "$APP" 2>&1 | grep -E 'TeamIdentifier=|Identifier=|flags=|Authority='
ditto -c -k --keepParent "$APP" "$OUT/DMGTrustAuditor-notarization.zip"
xcrun notarytool submit "$OUT/DMGTrustAuditor-notarization.zip" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=4 "$APP"
echo "Signed and notarized app: $APP"
