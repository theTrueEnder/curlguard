# curlguard

`curlguard` is a Linux-focused safety wrapper for `curl` that scans downloaded content before it reaches `bash`, a file on disk, or another consumer.

It is built for the habit a lot of us have picked up:

```bash
curl https://somewhere/install.sh | bash
```

That command is convenient, but it also means “download remote code and execute it immediately.” `curlguard` inserts a review point into that flow:

- download with the real system `curl`
- scan the content with YARA rules
- warn about insecure TLS usage
- prompt you when content looks suspicious
- log what happened for later review

## What it does today

- Intercepts the common single-URL installer flow on Linux
- Downloads to a temporary file first, then scans before delivery
- Supports built-in, user-supplied, and auto-updated YARA rule sources
- Shows a Textual prompt for flagged content: block, quarantine, or allow
- Writes JSON Lines audit logs for intercepted and pass-through invocations
- Lets you choose how scan failures behave: warn-and-deliver or fail closed

## What it does not do yet

`curlguard` currently prioritizes installer-style commands over perfect parity with every `curl` feature.

The wrapper intentionally falls back to the real `curl` for requests it does not safely intercept yet, including flows that use flags like:

- `-I`, `--head`
- `-T`, `--upload-file`
- `-F`, `--form`
- `-d`, `--data`, `--data-raw`, `--data-binary`, `--data-urlencode`
- `--next`
- `-O`, `--remote-name`
- `-J`, `--remote-header-name`
- multi-URL invocations

That means the sweet spot right now is:

```bash
curl -fsSL https://example.com/install.sh | bash
curl -fsSL https://example.com/install.sh -o install.sh
```

## Why use it

`curlguard` is meant to reduce risk around watering-hole and supply-chain style attacks where:

- an install script is replaced on the origin server
- a CDN or redirect target serves malicious content
- a trusted project briefly ships a poisoned installer
- a “quick install” command uses insecure transport or weakened TLS settings

It does **not** guarantee a script is safe. It gives you a scanning and decision point before the content is delivered.

## How the flow works

```text
curl command
   │
   ├─ unsupported curl mode? ──> pass through to real curl, log as skipped
   │
   └─ supported single-URL mode
         │
         ├─ detect insecure TLS flags / http:// usage
         │
         ├─ download with the real system curl to a temp file
         │
         ├─ scan with YARA
         │     ├─ clean        -> deliver
         │     ├─ flagged      -> prompt block / quarantine / allow
         │     └─ unavailable  -> warn or block based on config
         │
         └─ write audit log entry
```

## Quick start

### Per-user install

```bash
git clone https://github.com/YOUR_USER/curlguard.git
cd curlguard
bash scripts/install-peruser.sh
source ~/.bashrc
```

This creates a wrapper at `~/.local/bin/curl` and points it at the real system `curl`.

### System-wide install

```bash
git clone https://github.com/YOUR_USER/curlguard.git
cd curlguard
sudo bash scripts/install-systemwide.sh
```

This replaces `/usr/bin/curl` with the wrapper and stores the original binary as `/usr/bin/curl.real`.

### Verify

```bash
curlguard --help
which curl
```

Expected results:

- per-user install: `~/.local/bin/curl`
- system-wide install: `/usr/bin/curl`

## Dependencies

The project currently expects:

- Python 3.10+
- `yara-python`
- `textual`
- `requests`
- `httpx`

The install scripts try to use distro packages for `python3-yara`, `python3-requests`, and `python3-httpx`, and `pip` for `textual`.

## Detection behavior

### Built-in rule sources

Rules are loaded from these locations, in this order:

1. built-in rules in `src/curlguard/rules/foundation.yar`
2. user rules in `~/.curlguard/rules/` or `/var/lib/curlguard/rules/`
3. auto-updated rules fetched from `CURLGUARD_UPDATE_URL`

### Built-in detection themes

The default rules look for patterns such as:

- `suspicious_pipe_bash`
- base64-decoded shell payloads
- obfuscated shell execution
- malware-style headers and crypto pool indicators
- network IOCs

### If malware is detected

For flagged content, `curlguard` opens a TUI prompt and lets you:

- `Block` — abort delivery and exit non-zero
- `Quarantine` — move the payload into the quarantine directory and exit non-zero
- `Allow` — deliver the content anyway

### If scanning is unavailable

This now has an explicit policy:

- default: warn and deliver
- optional: block the download

Control it with `CURLGUARD_SCAN_FAILURE_MODE`.

## TLS / transport warnings

`curlguard` checks for insecure transport and downgraded TLS usage.

Examples it detects:

- `--insecure`
- `-k`
- `--sslv3`
- `--tlsv1.0`
- `--tlsv1.1`
- `http://...` URLs

By default, SSL bypass findings warn. You can configure blocking for `severity=block` cases by setting:

```bash
export CURLGUARD_SSL_WARN_ONLY=false
```

## Audit logging

Every invocation handled by the wrapper is logged as JSON Lines.

Default log paths:

- per-user: `~/.curlguard/audit.log`
- system-wide: `/var/log/curlguard/audit.log`

Example entries:

```json
{"timestamp":"2024-01-01T12:00:00+00:00","url":"https://example.com/install.sh","scan_result":"clean","duration_ms":150.0,"exit_code":0}
{"timestamp":"2024-01-01T12:01:00+00:00","url":"https://evil.example/payload.sh","scan_result":"flagged","rules_triggered":["suspicious_pipe_bash"],"user_decision":"block","exit_code":1}
{"timestamp":"2024-01-01T12:02:00+00:00","url":"https://example.com/install.sh","scan_result":"unavailable","user_decision":"allow","exit_code":0}
```

Possible `scan_result` values currently include:

- `clean`
- `flagged`
- `unavailable`
- `error`
- `skipped`

## Configuration

All current runtime configuration is environment-variable based.

| Variable | Default | Description |
|---|---|---|
| `CURLGUARD_MODE` | auto-detect | `per-user` or `system-wide` |
| `CURLGUARD_LOG_PATH` | mode-specific | Override audit log path |
| `CURLGUARD_RULES_DIR` | mode-specific | Colon-separated rule directories |
| `CURLGUARD_QUARANTINE` | mode-specific | Override quarantine directory |
| `CURLGUARD_REAL_CURL_PATH` | auto-detect | Override the real curl binary path |
| `CURLGUARD_UPDATE_URL` | unset | URL used for auto-updated rules |
| `CURLGUARD_UPDATE_INTERVAL_HOURS` | `24` | Rule update interval |
| `CURLGUARD_SSL_WARN_ONLY` | `true` | Warn on TLS bypass unless a blocking severity is configured and this is `false` |
| `CURLGUARD_SCAN_FAILURE_MODE` | `warn` | `warn` to deliver with warning, `block` to fail closed when scanning is unavailable |

## Testing

### True positive

The repo includes a synthetic malicious sample:

```bash
python3 examples/true_positive/start_server.py
curl http://127.0.0.1:8888/test.sh | bash
```

There is also a direct sample file at `examples/known_malware/sample.sh`.

### True negative

A simple benign shell installer should scan clean. One example:

```bash
python3 - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "src")
from curlguard.scanner import YaraScanner

scanner = YaraScanner([Path("src/curlguard/rules")])
result = scanner.scan(b"#!/bin/sh\necho safe install\ncurl https://example.com/file.txt -o /tmp/file.txt\n")
print(result.clean, result.status, result.rules_triggered)
PY
```

### Automated tests

```bash
pytest -v
```

The integration tests cover:

- true positives
- true negatives
- scan-unavailable behavior
- quarantine flow
- SSL-blocking behavior
- wrapper temp-file download handling

## Uninstall

### Per-user

```bash
python3 -c "import sys; sys.path.insert(0, 'src'); from curlguard.curl_manager import CurlManager; CurlManager('per-user').uninstall()"
rm -rf ~/.curlguard ~/.local/bin/curl
```

### System-wide

```bash
sudo python3 -c "import sys; sys.path.insert(0, 'src'); from curlguard.curl_manager import CurlManager; CurlManager('system-wide').uninstall()"
sudo rm -rf /var/lib/curlguard /var/log/curlguard /etc/profile.d/curlguard.sh
sudo pip uninstall curlguard
```

## Current status

The repository is in a much better place than before, but it is still a focused early-stage tool, not a drop-in replacement for every `curl` workflow.

Today’s strongest path is:

- Linux
- single-URL downloads
- installer-style commands
- YARA-backed pre-delivery scanning

If you are evaluating or extending it, that is the path to test first.
