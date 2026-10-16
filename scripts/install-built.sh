#!/bin/bash
set -euo pipefail
MODE="${1:?installation mode required}"
shift
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ "$MODE" != per-user ] && [ "$MODE" != system-wide ]; then
    echo 'Invalid installation mode' >&2
    exit 1
fi
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --migrate-legacy ]; }; then
    echo 'Only --migrate-legacy is supported' >&2
    exit 1
fi
# Re-enter without privilege before running the package build backend.
if [ "$(id -u)" -eq 0 ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        exec runuser -u "$SUDO_USER" -- bash "$SCRIPT_DIR/install-built.sh" "$MODE" "$@"
    fi
    echo 'Run this installer as a regular user; system installation requests sudo after building.' >&2
    exit 1
fi
STAGE="$(mktemp -d)"
ROOT_HELPER=''
cleanup() {
    rm -rf -- "$STAGE"
    if [ -n "$ROOT_HELPER" ]; then sudo rm -f -- "$ROOT_HELPER"; fi
}
trap cleanup EXIT
python3 -m pip wheel --wheel-dir "$STAGE/wheels" "$PROJECT_DIR"
if [ "$MODE" = per-user ]; then
    python3 "$SCRIPT_DIR/install-runtime.py" --mode per-user --wheelhouse "$STAGE/wheels" \
        --prefix "$HOME/.local/share/curlguard" "$@"
else
    sudo install -d -o root -g root -m 755 /opt/curlguard
    ROOT_HELPER="$(sudo mktemp /opt/curlguard/.installer-XXXXXXXX.py)"
    sudo install -o root -g root -m 600 "$SCRIPT_DIR/install-runtime.py" "$ROOT_HELPER"
    sudo python3 "$ROOT_HELPER" --mode system-wide --wheelhouse "$STAGE/wheels" \
        --prefix /opt/curlguard "$@"
fi
printf '\nInstallation complete. Ensure the wrapper directory precedes /usr/bin in PATH.\n'
if [ "$MODE" = per-user ]; then
    printf 'Add this to your shell startup file: export PATH="$HOME/.local/bin:$PATH"\n'
fi
printf 'Run: curlguard doctor --json\n'
