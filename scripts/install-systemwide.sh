#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo > /dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "ERROR: curlguard system-wide install requires root."
        echo "       Run with sudo:  sudo bash $0"
        echo "       Or use per-user install instead."
        exit 1
    fi
fi

echo "Installing curlguard (system-wide)..."

$SUDO mkdir -p /var/lib/curlguard/rules
$SUDO mkdir -p /var/lib/curlguard/quarantine
$SUDO mkdir -p /var/log/curlguard

if [ -d "$SCRIPT_DIR/src/curlguard/rules" ]; then
    $SUDO cp -r "$SCRIPT_DIR/src/curlguard/rules/"*.yar /var/lib/curlguard/rules/ 2>/dev/null || true
fi

$SUDO pip install -e "$SCRIPT_DIR" --break-system-packages 2>/dev/null || \
$SUDO pip3 install -e "$SCRIPT_DIR" --break-system-packages 2>/dev/null || \
{ echo "ERROR: Could not install curlguard. Try manually: sudo pip install --break-system-packages -e $SCRIPT_DIR"; exit 1; }

$SUDO python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR/src')
from curlguard.curl_manager import CurlManager
CurlManager('system-wide').install()
print('curl wrapper installed to /usr/bin/')
"

PROFILE_FILE="/etc/profile.d/curlguard.sh"
if [ ! -f "$PROFILE_FILE" ]; then
    $SUDO tee "$PROFILE_FILE" > /dev/null << 'PROFILE'
export CURLGUARD_MODE=system-wide
PROFILE
    echo "Created $PROFILE_FILE"
fi

echo ""
echo "  ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗██╗      █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗"
echo "  ██████╗ ██╔════╝████╗  ██║██║██╔════╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██║   ██║██╔════╝"
echo "  ██╔══██╗█████╗  ██╔██╗ ██║██║███████╗███████╗██║     ███████║██████╔╝██║   ██║██║   ██║█████╗  "
echo "  ██║  ██║██╔══╝  ██║╚██╗██║██║╚════██║╚════██║██║     ██╔══██║██╔══██╗██║   ██║██║   ██║██╔══╝  "
echo "  ██████╔╝███████╗██║ ╚████║██║███████║███████║███████╗██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║     "
echo "  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     "
echo ""
echo "  System-wide install complete!"
echo ""
echo "  Audit log:   /var/log/curlguard/audit.log"
echo "  Rules dir:   /var/lib/curlguard/rules/"
echo "  Quarantine:  /var/lib/curlguard/quarantine/"
echo ""
echo "  Verify:      which curl  → should show /usr/bin/curl"
echo "  Run:         curlguard --help"
echo ""