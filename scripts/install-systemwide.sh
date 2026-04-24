#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

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

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    die "System-wide installation requires root or sudo."
fi

command -v python3 >/dev/null 2>&1 || die "Python 3 is required."

step "1/5" "Preparing system directories"
$SUDO mkdir -p /var/lib/curlguard/rules /var/lib/curlguard/quarantine /var/log/curlguard
if [ -d "$PROJECT_DIR/src/curlguard/rules" ]; then
    $SUDO cp "$PROJECT_DIR"/src/curlguard/rules/*.yar /var/lib/curlguard/rules/ 2>/dev/null || true
fi
info "Rules directory: /var/lib/curlguard/rules"
info "Quarantine directory: /var/lib/curlguard/quarantine"
info "Audit log directory: /var/log/curlguard"

step "2/5" "Installing Python dependencies"
if command -v apt-get >/dev/null 2>&1; then
    info "Attempting distro packages for yara-python, requests, and httpx"
    $SUDO apt-get install -y python3-yara python3-requests python3-httpx 2>/dev/null || \
        warn "Could not install python3-yara/python3-requests/python3-httpx with apt-get."
else
    warn "apt-get not found; continuing without distro dependency installation."
fi

info "Installing Textual via pip"
$SUDO python3 -m pip install --break-system-packages 'textual>=0.50.0' 2>/dev/null || \
    $SUDO python3 -m pip install 'textual>=0.50.0' 2>/dev/null || \
    die "Could not install Textual. Try: sudo python3 -m pip install --break-system-packages 'textual>=0.50.0'"

step "3/5" "Installing the curlguard package"
$SUDO python3 -m pip install --break-system-packages -e "$PROJECT_DIR" 2>/dev/null || \
    $SUDO python3 -m pip install -e "$PROJECT_DIR" 2>/dev/null || \
    die "Could not install curlguard. Try: sudo python3 -m pip install --break-system-packages -e '$PROJECT_DIR'"

step "4/5" "Installing the curl wrapper"
$SUDO python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
from curlguard.curl_manager import CurlManager
CurlManager('system-wide').install()
print('Installed wrapper at /usr/bin/curl')
"

step "5/5" "Writing environment configuration"
PROFILE_FILE="/etc/profile.d/curlguard.sh"
if [ ! -f "$PROFILE_FILE" ]; then
    $SUDO tee "$PROFILE_FILE" > /dev/null <<'PROFILE'
export CURLGUARD_MODE=system-wide
PROFILE
    info "Created $PROFILE_FILE"
else
    info "$PROFILE_FILE already exists"
fi

cat <<EOF

curlguard system-wide installation complete.

Runtime locations:
  - Audit log:   /var/log/curlguard/audit.log
  - Rules:       /var/lib/curlguard/rules
  - Quarantine:  /var/lib/curlguard/quarantine

Next steps:
  1. Start a new shell or run:
       source /etc/profile
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
