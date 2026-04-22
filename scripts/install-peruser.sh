#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CURLGUARD_DIR="$HOME/.curlguard"

echo "Installing curlguard (per-user)..."

python3 --version > /dev/null 2>&1 || { echo "Python 3 required but not found"; exit 1; }

mkdir -p "$CURLGUARD_DIR/rules"
mkdir -p "$CURLGUARD_DIR/quarantine"

if [ -d "$SCRIPT_DIR/src/curlguard/rules" ]; then
    cp -r "$PROJECT_DIR/src/curlguard/rules/"*.yar "$CURLGUARD_DIR/rules/" 2>/dev/null || true
fi

echo "Installing dependencies..."

if command -v apt-get > /dev/null 2>&1; then
    echo "  Using apt for yara, requests, httpx..."
    sudo apt-get install -y python3-yara python3-requests python3-httpx 2>/dev/null || \
    apt-get install -y python3-yara python3-requests python3-httpx 2>/dev/null || \
    { echo "  Warning: could not install python3-yara via apt, will try pip"; }
fi

echo "  Using pip for textual (system-managed)..."
pip install --user --break-system-packages 'textual>=0.50.0' 2>/dev/null || \
pip install --break-system-packages 'textual>=0.50.0' 2>/dev/null || \
{ echo "ERROR: Could not install textual. Try: pip install --user --break-system-packages 'textual>=0.50.0'"; exit 1; }

pip install --user -e "$PROJECT_DIR" 2>/dev/null || \
pip install --user --break-system-packages -e "$PROJECT_DIR" 2>/dev/null || \
pip install --break-system-packages -e "$PROJECT_DIR" 2>/dev/null || \
{ echo "ERROR: Could not install curlguard package. Try: pip install --user --break-system-packages -e $PROJECT_DIR"; exit 1; }

python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
from curlguard.curl_manager import CurlManager
CurlManager('per-user').install()
print('curl wrapper installed to ~/.local/bin/')
"

if [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -n "$ZSH_VERSION" ] && [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q 'CURLGUARD_MODE' "$SHELL_RC" 2>/dev/null; then
        echo '' >> "$SHELL_RC"
        echo '# curlguard' >> "$SHELL_RC"
        echo 'export CURLGUARD_MODE=per-user' >> "$SHELL_RC"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
        echo "Updated $SHELL_RC with CURLGUARD_MODE and PATH"
    fi
fi

if [ -n "$FISH_VERSION" ]; then
    mkdir -p "$HOME/.config/fish"
    if ! grep -q 'CURLGUARD_MODE' "$HOME/.config/fish/config.fish" 2>/dev/null; then
        echo '' >> "$HOME/.config/fish/config.fish"
        echo '# curlguard' >> "$HOME/.config/fish/config.fish"
        echo 'set -gx CURLGUARD_MODE per-user' >> "$HOME/.config/fish/config.fish"
        echo 'set -gx PATH $HOME/.local/bin $PATH' >> "$HOME/.config/fish/config.fish"
        echo "Updated fish config with CURLGUARD_MODE and PATH"
    fi
fi

echo ""
echo "  ████ █  █ ████ █    █████ █  █  ██  ████ ████  "
echo "  █    █  █ █  █ █    █     █  █ █  █ █  █ █  █ "
echo "  █    █  █ ████ █    █  ██ █  █ █████ ████ █  █ "
echo "  █    █  █ ███  █    █   █ █  █ █  █ ███  █  █ "
echo "  ████ ████ █ █  ████ █████ ████ █  █ █ █  ████  "
echo ""
echo "  Per-user install complete!"
echo ""
echo "  Restart your shell:  source ~/.bashrc  (or open a new terminal)"
echo "  Verify install:      which curl  → should show ~/.local/bin/curl"
echo "  Run curlguard:       curlguard --help"
echo ""
echo "  TEST MALWARE DETECTION (true positive):"
echo "  bash examples/true_positive/test_detection.sh"
echo ""
echo "  TEST CLEAN SCRIPT (false positive):"
echo "  curl -s http://127.0.0.1:8000/clean.sh | bash"
echo "  (run 'python3 -m http.server 8000' in another terminal first)"