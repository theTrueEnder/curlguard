#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURLGUARD_DIR="$HOME/.curlguard"

echo "Installing curlguard (per-user)..."

python3 --version > /dev/null 2>&1 || { echo "Python 3 required but not found"; exit 1; }

mkdir -p "$CURLGUARD_DIR/rules"
mkdir -p "$CURLGUARD_DIR/quarantine"

if [ -d "$SCRIPT_DIR/src/curlguard/rules" ]; then
    cp -r "$SCRIPT_DIR/src/curlguard/rules/"*.yar "$CURLGUARD_DIR/rules/" 2>/dev/null || true
fi

pip install -e "$SCRIPT_DIR" 2>/dev/null || pip3 install -e "$SCRIPT_DIR"

python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR/src')
from curlguard.curl_manager import CurlManager
CurlManager('per-user').install()
print('curl wrapper installed to ~/.local/bin/')
"

if [ -n "\$BASH_VERSION" ]; then
    if [ -f "\$HOME/.bashrc" ] && ! grep -q 'CURLGUARD_MODE' "\$HOME/.bashrc" 2>/dev/null; then
        echo 'export CURLGUARD_MODE=per-user' >> "$HOME/.bashrc"
        echo 'export PATH="\$HOME/.local/bin:\$PATH"' >> "$HOME/.bashrc"
    fi
fi

if [ -n "\$ZSH_VERSION" ]; then
    if [ -f "\$HOME/.zshrc" ] && ! grep -q 'CURLGUARD_MODE' "\$HOME/.zshrc" 2>/dev/null; then
        echo 'export CURLGUARD_MODE=per-user' >> "$HOME/.zshrc"
        echo 'export PATH="\$HOME/.local/bin:\$PATH"' >> "$HOME/.zshrc"
    fi
fi

if [ -n "\$FISH_VERSION" ]; then
    mkdir -p "\$HOME/.config/fish"
    if ! grep -q 'CURLGUARD_MODE' "\$HOME/.config/fish/config.fish" 2>/dev/null; then
        echo 'set -gx CURLGUARD_MODE per-user' >> "$HOME/.config/fish/config.fish"
        echo 'set -gx PATH $HOME/.local/bin $PATH' >> "$HOME/.config/fish/config.fish"
    fi
fi

echo "=========================================="
echo "curlguard per-user install complete!"
echo ""
echo "Restart your shell or run: source ~/.bashrc"
echo "Verify: which curl  (should be ~/.local/bin/curl)"
echo "=========================================="