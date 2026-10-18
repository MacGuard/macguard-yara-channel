#!/usr/bin/env bash
# Builds the YARA engine that ships with MacGuard: universal (arm64 + x86_64), static OpenSSL so the `hash` and `pe` modules
# (signatures) work, no magic/cuckoo modules (they need external libraries), minimum macOS 13.0, ad-hoc signed with the hardened runtime.
# Developer ID signing and notarization are a release step that needs Apple credentials: see docs/ENGINE.md.
#
# usage: Scripts/build-yara-engine.sh OUT_DIR       (macOS with Xcode command line tools, autoconf, automake, libtool, curl)
# Every source is pinned by SHA-256; a mismatch stops the build.
set -euo pipefail
out="$1"; mkdir -p "$out"; out="$(cd "$out" && pwd)"
YARA_VERSION=4.5.8
YARA_URL="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
YARA_SHA256=c322414975ff6f701149856613afdcd92a7e6939c284c798ae3c85618197efaa
OPENSSL_VERSION=3.5.9
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
MINOS=13.0
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
fetch() { curl -sSL --retry 3 -o "$work/$1" "$2"; got="$(shasum -a 256 "$work/$1" | cut -d' ' -f1)"; [ "$got" = "$3" ] || { echo "$1: SHA-256 $got does not match the pin $3" >&2; exit 1; }; }
fetch yara.tgz "$YARA_URL" "$YARA_SHA256"; fetch openssl.tgz "$OPENSSL_URL" "$OPENSSL_SHA256"

build_arch() {
  local arch="$1" target host
  case "$arch" in arm64) target=darwin64-arm64-cc; host=aarch64-apple-darwin ;; x86_64) target=darwin64-x86_64-cc; host=x86_64-apple-darwin ;; *) exit 2 ;; esac
  local prefix="$work/ossl-$arch"; mkdir -p "$work/o-$arch" "$work/y-$arch"
  tar -xzf "$work/openssl.tgz" -C "$work/o-$arch" --strip-components=1
  ( cd "$work/o-$arch" && ./Configure "$target" no-shared no-tests no-docs no-apps --prefix="$prefix" -mmacosx-version-min=$MINOS >/dev/null && make -j"$(sysctl -n hw.ncpu)" build_libs >/dev/null && make install_dev >/dev/null )
  tar -xzf "$work/yara.tgz" -C "$work/y-$arch" --strip-components=1
  ( cd "$work/y-$arch" && ./bootstrap.sh >/dev/null 2>&1 \
    && ./configure --host="$host" --disable-shared --enable-static --with-crypto --disable-magic --disable-cuckoo --disable-dex --disable-debug \
         CFLAGS="-arch $arch -mmacosx-version-min=$MINOS -O2" LDFLAGS="-arch $arch -mmacosx-version-min=$MINOS -L$prefix/lib" CPPFLAGS="-I$prefix/include" >/dev/null \
    && make -j"$(sysctl -n hw.ncpu)" yara yarac >/dev/null )
  cp "$work/y-$arch/yara" "$work/yara-$arch"; cp "$work/y-$arch/yarac" "$work/yarac-$arch"
}
for a in arm64 x86_64; do echo "building $a"; build_arch "$a"; done
for t in yara yarac; do lipo -create "$work/$t-arm64" "$work/$t-x86_64" -output "$out/$t"; strip -x "$out/$t"; codesign --force --sign - --options runtime --identifier "com.macguard.$t" "$out/$t"; done
archs="$(lipo -archs "$out/yara")"
cat > "$out/engine-manifest.json" <<JSON
{
  "schema": 1,
  "engine": "yara",
  "version": "$YARA_VERSION",
  "source_sha256": "$YARA_SHA256",
  "openssl": "$OPENSSL_VERSION",
  "openssl_source_sha256": "$OPENSSL_SHA256",
  "architectures": "$archs",
  "minimum_macos": "$MINOS",
  "modules_disabled": ["magic", "cuckoo", "dex"],
  "signature": "ad-hoc with hardened runtime; Developer ID signing and notarization pending credentials",
  "yara_sha256": "$(shasum -a 256 "$out/yara" | cut -d' ' -f1)",
  "yarac_sha256": "$(shasum -a 256 "$out/yarac" | cut -d' ' -f1)"
}
JSON
echo "engine built: $archs"; "$out/yara" --version
