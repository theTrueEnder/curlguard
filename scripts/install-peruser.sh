#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
VENV_DIR="$DATA_HOME/curlguard/venv"
BIN_DIR="$HOME/.local/bin"
WITH_SHIM=false

if [ "${1:-}" = "--with-curl-shim" ]; then
    WITH_SHIM=true
elif [ "$#" -ne 0 ]; then
    printf 'Usage: %s [--with-curl-shim]\n' "$0" >&2
    exit 2
fi

command -v python3 >/dev/null 2>&1 || {
    printf 'ERROR: Python 3.10 or newer is required.\n' >&2
    exit 1
}
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || {
    printf 'ERROR: Python 3.10 or newer is required.\n' >&2
    exit 1
}

LEGACY_SHIM="$HOME/.local/bin/curl"
if [ -f "$LEGACY_SHIM" ] && grep -q 'CURLGUARD_REAL_CURL_PATH=' "$LEGACY_SHIM" \
   && grep -q 'exec curlguard' "$LEGACY_SHIM"; then
    LEGACY_BACKUP="$LEGACY_SHIM.curlguard-legacy"
    if [ -e "$LEGACY_BACKUP" ]; then
        printf 'ERROR: Legacy backup already exists: %s\n' "$LEGACY_BACKUP" >&2
        exit 1
    fi
    mv "$LEGACY_SHIM" "$LEGACY_BACKUP"
    printf 'Disabled legacy PATH-wide curl shim; backup: %s\n' "$LEGACY_BACKUP"
fi

printf '[1/3] Creating isolated environment at %s\n' "$VENV_DIR"
python3 -m venv "$VENV_DIR" || {
    printf 'ERROR: Python venv support is required; install it using your OS package manager.\n' >&2
    exit 1
}

printf '[2/3] Installing curlguard without modifying system Python\n'
if ! "$VENV_DIR/bin/python" -m pip install "$PROJECT_DIR[tui]"; then
    printf 'WARNING: TUI dependencies were unavailable; installing console-only curlguard.\n' >&2
    "$VENV_DIR/bin/python" -m pip install "$PROJECT_DIR"
fi

mkdir -p "$BIN_DIR"
LAUNCHER="$BIN_DIR/curlguard"
if [ -e "$LAUNCHER" ] || [ -L "$LAUNCHER" ]; then
    if [ ! -L "$LAUNCHER" ] || [ "$(readlink "$LAUNCHER")" != "$VENV_DIR/bin/curlguard" ]; then
        printf 'ERROR: Refusing to replace unmanaged file: %s\n' "$LAUNCHER" >&2
        exit 1
    fi
fi
ln -sfn "$VENV_DIR/bin/curlguard" "$LAUNCHER"

printf '[3/3] Finalizing installation\n'
if [ "$WITH_SHIM" = true ]; then
    "$VENV_DIR/bin/python" -c 'from curlguard.curl_manager import CurlManager; CurlManager("per-user").install()'
    printf 'Optional curl shim installed at ~/.local/libexec/curlguard/bin/curl\n'
    printf 'Activate it only in an interactive shell with:\n'
    printf '  export PATH="$HOME/.local/libexec/curlguard/bin:$PATH"\n'
else
    printf 'No curl shim was installed; package managers and automation are unaffected.\n'
fi

printf '\nInstallation complete. Ensure ~/.local/bin is on PATH, then run:\n'
printf '  curlguard --version\n'
printf '  curlguard https://example.com/install.sh\n'
