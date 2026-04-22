# curlguard

**Secure curl wrapper with YARA malware scanning** — protects Linux users from supply chain attacks via `curl ... | bash`.

## What it does

curlguard intercepts all curl downloads, scans file contents with YARA rules, and alerts you via an interactive TUI when malware is detected. Clean files pass through normally. You decide: Block, Quarantine, or Allow.

## Threat Model

```
Attack: `curl https://example.com/install.sh | bash`
Problem: You have no way to inspect the script before execution
Solution: curlguard scans it first with YARA rules
```

## Quick Start

### Per-User Install
```bash
bash scripts/install-peruser.sh
source ~/.bashrc
```

### System-Wide Install (requires sudo)
```bash
sudo bash scripts/install-systemwide.sh
```

### Verify
```bash
curlguard --help
which curl  # should show ~/.local/bin/curl or /usr/bin/curl
```

## How It Works

```
curl https://example.com/script.sh | bash
         ↓
    curlguard (wrapper in PATH)
         ↓
    Real curl (curl.real) downloads file
         ↓
    YARA scanner checks file content
         ↓
    [CLEAN]  → file passes through, executes normally
    [MALWARE] → TUI prompt: Block / Quarantine / Allow
    [SSL BYPASS] → warning printed to stderr, download proceeds
```

## YARA Rules

Rules are loaded from three sources (checked in order):
1. Built-in rules: `src/curlguard/rules/foundation.yar`
2. User rules: `~/.curlguard/rules/` (per-user) or `/var/lib/curlguard/rules/` (system-wide)
3. Auto-updated rules: downloaded daily from configured URL

### Adding Custom Rules
```bash
cp my_custom_rule.yar ~/.curlguard/rules/
curlguard ...  # rules reload automatically
```

## TUI Prompt

When malware is detected, an interactive TUI appears:

```
╔══════════════════════════════════════════╗
║ curlguard -- MALWARE DETECTED            ║
║ URL: https://evil.com/payload.sh         ║
║ Matched: suspicious_pipe_bash            ║
║                                          ║
║ [B] Block   [Q] Quarantine   [A] Allow   ║
╚══════════════════════════════════════════╝
```

- **Block**: abort download, exit code 1
- **Quarantine**: move file to quarantine dir, exit 1
- **Allow**: let the file pass through

Keyboard shortcuts: `B`, `Q`, `A`

## SSL Bypass Detection

curlguard warns when you use insecure TLS:

```bash
curl -k https://example.com/file.sh  # prints WARNING: SSL bypass detected
```

Blocked flags: `--insecure`, `-k`, `--sslv3`, `--tlsv1.0`, `--tlsv1.1`

## Audit Logging

Every curl invocation is logged:

```json
{"timestamp": "2024-01-01T12:00:00", "url": "https://example.com/file.sh", "scan_result": "clean", "duration_ms": 150.0, "exit_code": 0}
{"timestamp": "2024-01-01T12:01:00", "url": "https://evil.com/payload.sh", "scan_result": "flagged", "rules_triggered": ["suspicious_pipe_bash"], "user_decision": "block"}
```

Log locations:
- Per-user: `~/.curlguard/audit.log`
- System-wide: `/var/log/curlguard/audit.log`

## Configuration

All settings via environment variables:

| Variable | Default | Description |
|---|---|---|
| `CURLGUARD_MODE` | auto-detect | `per-user` or `system-wide` |
| `CURLGUARD_LOG_PATH` | auto | Path to audit log |
| `CURLGUARD_RULES_DIR` | auto | Colon-separated rule directories |
| `CURLGUARD_QUARANTINE` | auto | Quarantine directory |
| `CURLGUARD_UPDATE_URL` | none | URL to fetch auto-update rules |
| `CURLGUARD_UPDATE_INTERVAL_HOURS` | 24 | How often to check for rule updates |
| `CURLGUARD_SSL_WARN_ONLY` | true | SSL bypass: `true`=warn only, `false`=block |

## Uninstall

Per-user:
```bash
python3 -c "import sys; sys.path.insert(0,'src'); from curlguard.curl_manager import CurlManager; CurlManager('per-user').uninstall()"
rm -rf ~/.curlguard ~/.local/bin/curl ~/.local/bin/curl.real
```

System-wide:
```bash
sudo python3 -c "import sys; sys.path.insert(0,'src'); from curlguard.curl_manager import CurlManager; CurlManager('system-wide').uninstall()"
sudo rm -rf /var/lib/curlguard /var/log/curlguard /etc/profile.d/curlguard.sh
pip uninstall curlguard
```

## Testing the Detection

A synthetic true-positive sample is included:

```bash
bash examples/known_malware/test_detection.sh
```

This should detect the `suspicious_pipe_bash` YARA rule.

## Dependencies

- Python >= 3.10
- yara-python (for YARA rule matching)
- textual (for the TUI prompt)
- requests / httpx (for rule auto-update)