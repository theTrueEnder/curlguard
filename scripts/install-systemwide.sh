#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo > /dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "ERROR: curlguard system-wide install requires root. Run with sudo or use per-user install."
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

$SUDO pip install . 2>/dev/null || $SUDO pip3 install . 2>/dev/null

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
fi

echo "=========================================="
echo "curlguard system-wide install complete!"
echo ""
echo "Audit log: /var/log/curlguard/audit.log"
echo "Rules: /var/lib/curlguard/rules/"
echo "Installed: /usr/bin/curl -> curlguard -> /usr/bin/curl.real"
echo "=========================================="