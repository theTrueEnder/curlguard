#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CURLGUARD_DIR="$HOME/.curlguard"

step() {
    printf '\n[%s] %s\n' "$1" "$2"
}

info() {
    printf '  - %s\n' "$1"
}

warn() {
    printf 'WARNING: %s\n' "$1" >&2
}

die() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

pick_shell_rc() {
    if [ -f "$HOME/.bashrc" ]; then
        printf '%s\n' "$HOME/.bashrc"
        return
    fi
    if [ -f "$HOME/.zshrc" ]; then
        printf '%s\n' "$HOME/.zshrc"
        return
    fi
}

install_textual() {
    python3 -m pip install --user 'textual>=0.50.0' 2>/dev/null && return 0
    python3 -m pip install --user --break-system-packages 'textual>=0.50.0' 2>/dev/null && return 0
    python3 -m pip install --break-system-packages 'textual>=0.50.0' 2>/dev/null && return 0
    return 1
}

install_project() {
    python3 -m pip install --user -e "$PROJECT_DIR" 2>/dev/null && return 0
    python3 -m pip install --user --break-system-packages -e "$PROJECT_DIR" 2>/dev/null && return 0
    python3 -m pip install --break-system-packages -e "$PROJECT_DIR" 2>/dev/null && return 0
    return 1
}

command -v python3 >/dev/null 2>&1 || die "Python 3 is required."

step "1/5" "Preparing curlguard directories"
mkdir -p "$CURLGUARD_DIR/rules" "$CURLGUARD_DIR/quarantine"
if [ -d "$PROJECT_DIR/src/curlguard/rules" ]; then
    cp "$PROJECT_DIR"/src/curlguard/rules/*.yar "$CURLGUARD_DIR/rules/" 2>/dev/null || true
fi
info "Rules directory: $CURLGUARD_DIR/rules"
info "Quarantine directory: $CURLGUARD_DIR/quarantine"

step "2/5" "Installing Python dependencies"
if command -v apt-get >/dev/null 2>&1; then
    info "Attempting distro packages for yara-python, requests, and httpx"
    sudo apt-get install -y python3-yara python3-requests python3-httpx 2>/dev/null || \
        apt-get install -y python3-yara python3-requests python3-httpx 2>/dev/null || \
        warn "Could not install python3-yara/python3-requests/python3-httpx with apt-get."
else
    warn "apt-get not found; continuing without distro dependency installation."
fi

info "Installing Textual via pip"
install_textual || die "Could not install Textual. Try: python3 -m pip install --user --break-system-packages 'textual>=0.50.0'"

step "3/5" "Installing the curlguard package"
install_project || die "Could not install curlguard. Try: python3 -m pip install --user --break-system-packages -e '$PROJECT_DIR'"

step "4/5" "Installing the curl wrapper"
python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
from curlguard.curl_manager import CurlManager
CurlManager('per-user').install()
print('Installed wrapper at ~/.local/bin/curl')
"

step "5/5" "Updating shell configuration"
SHELL_RC="$(pick_shell_rc || true)"
RELOAD_TARGET="${SHELL_RC:-your shell startup file}"
if [ -n "${SHELL_RC:-}" ]; then
    if ! grep -q 'CURLGUARD_MODE=per-user' "$SHELL_RC" 2>/dev/null; then
        {
            echo
            echo '# curlguard'
            echo 'export CURLGUARD_MODE=per-user'
            echo 'export PATH="$HOME/.local/bin:$PATH"'
        } >> "$SHELL_RC"
        info "Updated $SHELL_RC"
    else
        info "$SHELL_RC already contains curlguard settings"
    fi
else
    warn "No shell startup file was detected. Add ~/.local/bin to PATH and export CURLGUARD_MODE=per-user manually."
fi

cat <<EOF

curlguard per-user installation complete.

Next steps:
  1. Reload your shell:
       source $RELOAD_TARGET
  2. Verify that the wrapper is active:
       which curl
       curlguard --help

Recommended checks:
  - Suspicious sample:
      python3 examples/true_positive/start_server.py
      curl http://127.0.0.1:8888/test.sh | bash
    Expected result: curlguard opens an interactive review prompt.

  - Clean sample:
      python3 examples/true_negative/start_server.py
      curl http://127.0.0.1:8889/install.sh -o /tmp/curlguard-demo.sh
    Expected result: the file downloads without a malware prompt.
EOF
