#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
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

if [ -d "$PROJECT_DIR/src/curlguard/rules" ]; then
    $SUDO cp -r "$PROJECT_DIR/src/curlguard/rules/"*.yar /var/lib/curlguard/rules/ 2>/dev/null || true
fi

echo "Installing dependencies..."

echo "  Using apt for yara, requests, httpx..."
$SUDO apt-get install -y python3-yara python3-requests python3-httpx 2>/dev/null || \
{ echo "  Warning: could not install python3-yara via apt, will try pip"; }

echo "  Using pip for textual (system-managed)..."
$SUDO pip install --break-system-packages 'textual>=0.50.0' 2>/dev/null || \
$SUDO pip3 install --break-system-packages 'textual>=0.50.0' 2>/dev/null || \
{ echo "ERROR: Could not install textual. Try manually: sudo pip install --break-system-packages 'textual>=0.50.0'"; exit 1; }

$SUDO pip install --break-system-packages -e "$PROJECT_DIR" 2>/dev/null || \
$SUDO pip3 install --break-system-packages -e "$PROJECT_DIR" 2>/dev/null || \
{ echo "ERROR: Could not install curlguard. Try manually: sudo pip install --break-system-packages -e $PROJECT_DIR"; exit 1; }

$SUDO python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
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

cat <<'ART'
  +++   ++      +++  +++++++  +++     +++  +++++++
  + ++  +     +  ++     +    +  +    +  +     +
  +  + ++     ++++      +    +++     +++      +
  +   + +     +  +      +    +  +    +  +     +
  +++   +++   +  +   ++++++  +++     +++      +
ART

  System-wide install complete!
echo ""
echo "  Audit log:   /var/log/curlguard/audit.log"
echo "  Rules dir:   /var/lib/curlguard/rules/"
echo "  Quarantine:  /var/lib/curlguard/quarantine/"
echo ""
echo "  Verify:      which curl  → should show /usr/bin/curl"
echo "  Run:         curlguard --help"
echo ""
echo "  TEST MALWARE DETECTION (true positive):"
echo "  Terminal 1: python3 examples/true_positive/start_server.py"
echo "  Terminal 2: curl http://127.0.0.1:8888/test.sh | bash"
echo "  curlguard will intercept, detect malware, and show the TUI."
echo "  (server auto-expires after 60s)"
echo ""
echo "  TEST CLEAN SCRIPT (false positive):"
echo "  python3 -m http.server 8888 --directory examples/true_positive"
echo "  curl http://127.0.0.1:8888/start_server.py | bash  # clean content"