#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_ROOT="/opt/curlguard"
VENV_DIR="$INSTALL_ROOT/venv"
LAUNCHER="/usr/local/bin/curlguard"
WITH_SHIM=false

if [ "${1:-}" = "--with-curl-shim" ]; then
    WITH_SHIM=true
elif [ "$#" -ne 0 ]; then
    printf 'Usage: %s [--with-curl-shim]\n' "$0" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    printf 'ERROR: Run this installer as root (for example with sudo).\n' >&2
    exit 1
fi
if [ -f /usr/bin/curl.real ] && grep -q 'exec curlguard' /usr/bin/curl 2>/dev/null; then
    printf 'ERROR: A legacy curlguard replacement is active at /usr/bin/curl.\n' >&2
    printf 'Restore the OS-owned curl with your package manager before installing this version.\n' >&2
    exit 1
fi
command -v python3 >/dev/null 2>&1 || {
    printf 'ERROR: Python 3.10 or newer is required.\n' >&2
    exit 1
}
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || {
    printf 'ERROR: Python 3.10 or newer is required.\n' >&2
    exit 1
}

printf '[1/3] Creating isolated environment at %s\n' "$VENV_DIR"
mkdir -p "$INSTALL_ROOT"
python3 -m venv "$VENV_DIR" || {
    printf 'ERROR: Python venv support is required; install it using your OS package manager.\n' >&2
    exit 1
}

printf '[2/3] Installing curlguard without modifying system Python\n'
if ! "$VENV_DIR/bin/python" -m pip install "$PROJECT_DIR[tui]"; then
    printf 'WARNING: TUI dependencies were unavailable; installing console-only curlguard.\n' >&2
    "$VENV_DIR/bin/python" -m pip install "$PROJECT_DIR"
fi

if [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; then
    if [ ! -L "$LAUNCHER" ] || [ "$(readlink "$LAUNCHER")" != "$VENV_DIR/bin/curlguard" ]; then
        printf 'ERROR: Refusing to replace unmanaged file: %s\n' "$LAUNCHER" >&2
        exit 1
    fi
fi
ln -sfn "$VENV_DIR/bin/curlguard" "$LAUNCHER"

printf '[3/3] Finalizing installation\n'
if [ "$WITH_SHIM" = true ]; then
    "$VENV_DIR/bin/python" -c 'from curlguard.curl_manager import CurlManager; CurlManager("system-wide").install()'
    printf 'Optional shim installed at /usr/local/libexec/curlguard/bin/curl.\n'
    printf 'Administrators may opt selected interactive shells into that directory via PATH.\n'
else
    printf 'No curl shim was installed. /usr/bin/curl was not modified.\n'
fi

printf '\nInstallation complete: %s\n' "$LAUNCHER"
