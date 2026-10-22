#!/bin/sh
# Installs or removes mgctl under a prefix you own. No root needed for the default prefix. Never creates 'mg'.
#
#   ./install.sh install   [--prefix DIR]     (default prefix: $HOME/.local)
#   ./install.sh uninstall [--prefix DIR]
#
# Verify the archive first: sha256sum -c SHA256SUMS   (macOS: shasum -a 256 -c SHA256SUMS)
set -eu

ACTION="${1:-}"
[ $# -gt 0 ] && shift
PREFIX="${HOME}/.local"
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || { echo "install.sh: --prefix needs a directory" >&2; exit 3; }; PREFIX="$2"; shift 2 ;;
    *) echo "install.sh: unknown option: $1" >&2; exit 3 ;;
  esac
done
case "$PREFIX" in /*) ;; *) echo "install.sh: the prefix must be an absolute path" >&2; exit 3 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$PREFIX/lib/mgctl"
BIN="$PREFIX/bin"
LINK="$BIN/mgctl"

case "$ACTION" in
  install)
    command -v python3 >/dev/null 2>&1 || { echo "install.sh: python3 (3.9 or newer) is required" >&2; exit 4; }
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "install.sh: python3 3.9 or newer is required" >&2; exit 4; }
    if [ -e "$LINK" ] || [ -L "$LINK" ]; then
      case "$(readlink "$LINK" 2>/dev/null || true)" in
        "$LIB/bin/mgctl") ;;                                    # our own earlier install: upgrade in place
        *) echo "install.sh: $LINK already exists and is not an mgctl installation; not touching it" >&2; exit 4 ;;
      esac
    fi
    mkdir -p "$LIB/bin" "$BIN"
    rm -rf "$LIB/mgctl"
    cp -R "$HERE/mgctl" "$LIB/mgctl"
    cp "$HERE/bin/mgctl" "$LIB/bin/mgctl"
    chmod 755 "$LIB/bin/mgctl"
    ln -sfn "$LIB/bin/mgctl" "$LINK"
    echo "installed: $LINK"
    echo "check it with: $LINK --version"
    echo "the optional short alias is NOT created; see: mgctl alias --help"
    ;;
  uninstall)
    if [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$LIB/bin/mgctl" ]; then rm -f "$LINK"; fi
    rm -rf "$LIB"
    rmdir "$PREFIX/lib" 2>/dev/null || true
    echo "removed mgctl from $PREFIX (an 'mg' alias you enabled is separate: mgctl alias disable)"
    ;;
  *)
    echo "usage: install.sh install|uninstall [--prefix DIR]" >&2
    exit 3
    ;;
esac
