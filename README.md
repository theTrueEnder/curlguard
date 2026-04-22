# ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗██╗      █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
# ██████╗ ██╔════╝████╗  ██║██║██╔════╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██║   ██║██╔════╝
# ██╔══██╗█████╗  ██╔██╗ ██║██║███████╗███████╗██║     ███████║██████╔╝██║   ██║██║   ██║█████╗
# ██║  ██║██╔══╝  ██║╚██╗██║██║╚════██║╚════██║██║     ██╔══██║██╔══██╗██║   ██║██║   ██║██╔══╝
# ██████╔╝███████╗██║ ╚████║██║███████║███████║███████╗██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║
# ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝

**Secure curl wrapper with YARA malware scanning** — protects Linux from `curl ... | bash` supply chain attacks.

---

## The Problem

```bash
# You: "Let me just quickly install this tool..."
curl https://example.com/install.sh | bash
#                           ↑
#             You just ran arbitrary code from the internet
#             with zero inspection. What could go wrong?
```

Every day, thousands of users run `curl ... | bash` from unknown sources — npm packages, developer install scripts, "quick setup" commands. You're trusting that the server hasn't been compromised, the CDN isn't injecting malware, and the maintainer hasn't been bought.

**curlguard scans the content first. You decide what happens next.**

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         curlguard flow                              │
└─────────────────────────────────────────────────────────────────────┘

  $ curl https://example.com/install.sh | bash
              │
              ▼
    ┌──────────────────┐
    │  curlguard wraps │
    │   your curl cmd  │
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐
    │  Downloads via   │
    │  real curl.real  │
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐
    │  YARA scanner    │◄──── foundation.yar (built-in)
    │  checks content  │◄──── ~/.curlguard/rules/ (your rules)
    │                  │◄──── auto-updated rules (daily)
    └────────┬─────────┘
             │
       ┌─────┴─────┐
       │  CLEAN    │     ┌────────────────┐
       │           │     │  MALWARE       │
       │ Pass thru │     │                │
       │ silently  │     │ TUI prompt:    │
       │           │     │ [B] Block      │
       │           │     │ [Q] Quarantine │
       │           │     │ [A] Allow      │
       └───────────┘     └───────┬────────┘
                                 │
                       You decide what to do
```

---

## Quick Start

**1. Download and install**

*Per-user* (no sudo needed):
```bash
git clone https://github.com/YOUR_USER/curlguard.git
cd curlguard
bash scripts/install-peruser.sh
source ~/.bashrc
```

*System-wide* (requires sudo):
```bash
git clone https://github.com/YOUR_USER/curlguard.git
cd curlguard
sudo bash scripts/install-systemwide.sh
```

The installer uses `apt` for `python3-yara`, `python3-requests`, and `python3-httpx` (system-managed, no PEP 668 issues) and `pip` for `textual` (needs modern version not in apt).

**2. Verify**
```bash
curlguard --help
which curl        # should show ~/.local/bin/curl (per-user) or /usr/bin/curl (system-wide)
```

**3. Done.** Your `curl` is now protected.

---

## TUI: When Malware is Detected

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗██╗      █████╗ ║
║     ██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝██║     ██╔══██╗║
║     ██████╔╝█████╗  ██╔██╗ ██║██║███████╗███████╗██║     ███████║║
║     ██╔══██╗██╔══╝  ██║╚██╗██║██║╚════██║╚════██║██║     ██╔══██║║
║     ██████╔╝███████╗██║ ╚████║██║███████║███████║███████╗██║  ██║║
║     ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝║
║                                                                  ║
║                     M A L W A R E   D E T E C T E D              ║
║                                                                  ║
║   URL:  https://evil.com/payload.sh                              ║
║   Rule: suspicious_pipe_bash (severity: critical)                ║
║                                                                  ║
║   [B] Block this download    (ctrl+c)                            ║
║   [Q] Quarantine & block     (moves to ~/.curlguard/quarantine/) ║
║   [A] Allow anyway           (not recommended)                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

- **Block** — abort, exit code 1
- **Quarantine** — move to quarantine dir, exit 1
- **Allow** — deliver the file, you're on your own

---

## SSL Bypass Detection

curlguard warns when you use insecure TLS:

```
$ curl -k https://example.com/file.sh
WARNING: SSL bypass detected --insecure flag used. Connection is not encrypted.
```

Blocked flags: `--insecure`, `-k`, `--sslv3`, `--tlsv1.0`, `--tlsv1.1`, and URLs starting with `http://` (not `https://`).

---

## YARA Rules

Three sources, checked in order:

| Priority | Source | Location |
|----------|--------|----------|
| 1 | Built-in | `src/curlguard/rules/foundation.yar` |
| 2 | User rules | `~/.curlguard/rules/` (per-user) or `/var/lib/curlguard/rules/` (system-wide) |
| 3 | Auto-update | Downloaded daily from `CURLGUARD_UPDATE_URL` |

**Built-in rules detect:**

| Rule | What it catches |
|------|-----------------|
| `suspicious_pipe_bash` | `curl ... \| bash` — the classic supply chain attack |
| `base64_encoded_shell` | Base64-encoded payloads that decode and execute |
| `obfuscated_download` | Eval/exec tricks to hide malicious activity |
| `known_malware_header` | Scripts with malware/TROJAN comments or crypto pool IOCs |
| `network_ioc` | Connections to known-bad TLDs or Tor exits |

**Add your own rules:**
```bash
cp my_custom_rule.yar ~/.curlguard/rules/
curlguard ...   # rules reload automatically
```

**Test detection locally:**
```bash
bash examples/true_positive/test_detection.sh
```

---

## Audit Logging

Every curl invocation is logged in JSON Lines format:

```json
{"timestamp":"2024-01-01T12:00:00","url":"https://example.com/file.sh","scan_result":"clean","duration_ms":150.0,"exit_code":0}
{"timestamp":"2024-01-01T12:01:00","url":"https://evil.com/payload.sh","scan_result":"flagged","rules_triggered":["suspicious_pipe_bash"],"user_decision":"block"}
```

Log locations:
- **Per-user**: `~/.curlguard/audit.log`
- **System-wide**: `/var/log/curlguard/audit.log`

Logs rotate at 10MB (up to 5 backups), thread-safe, one event per line.

---

## Configuration

All via environment variables:

| Variable | Default | Description |
|---|---|---|
| `CURLGUARD_MODE` | auto-detect | `per-user` or `system-wide` |
| `CURLGUARD_LOG_PATH` | auto | Audit log path |
| `CURLGUARD_RULES_DIR` | auto | Colon-separated rule dirs |
| `CURLGUARD_QUARANTINE` | auto | Quarantine directory |
| `CURLGUARD_UPDATE_URL` | none | Daily rule auto-update URL |
| `CURLGUARD_UPDATE_INTERVAL_HOURS` | 24 | Auto-update frequency |
| `CURLGUARD_SSL_WARN_ONLY` | `true` | SSL bypass: warn only (not block) |

---

## Uninstall

**Per-user:**
```bash
python3 -c "import sys; sys.path.insert(0,'src'); from curlguard.curl_manager import CurlManager; CurlManager('per-user').uninstall()"
rm -rf ~/.curlguard ~/.local/bin/curl ~/.local/bin/curl.real
```

**System-wide:**
```bash
sudo python3 -c "import sys; sys.path.insert(0,'src'); from curlguard.curl_manager import CurlManager; CurlManager('system-wide').uninstall()"
sudo rm -rf /var/lib/curlguard /var/log/curlguard /etc/profile.d/curlguard.sh
sudo pip uninstall curlguard
```

---

## Dependencies

| Package | Why it's needed |
|---------|----------------|
| Python ≥ 3.10 | Runtime |
| [yara-python](https://github.com/VirusTotal/yara-python) | YARA rule matching |
| [textual](https://github.com/Textualize/textual) | Interactive TUI |
| requests / httpx | Rule auto-update downloads |

---

## Testing the Detection

A synthetic true-positive sample is included:

```bash
bash examples/true_positive/test_detection.sh
```

This creates a file that triggers the `suspicious_pipe_bash` rule and verifies detection.

> Without `yara-python` installed, the scanner gracefully falls back to `clean=True`. Install with: `pip install yara-python` (requires libyara-dev and C compiler).