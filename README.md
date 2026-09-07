# curlguard

`curlguard` is a Linux-first safety wrapper for `curl` that puts a scan-and-review step in front of risky installer commands.

Instead of streaming remote content directly into `bash`, `curlguard` downloads supported requests with the real system `curl`, scans the payload with YARA rules, warns on insecure transport, and lets you decide what to do when content looks suspicious.

## Why it exists

Commands like this are convenient:

```bash
curl -fsSL https://example.com/install.sh | bash
```

They are also a natural target for watering-hole and supply-chain attacks:

- a trusted install script is replaced at the source
- a CDN or redirect target serves a poisoned payload
- an upstream compromise turns a previously safe one-liner into remote code execution
- insecure TLS options weaken the fetch path

`curlguard` is designed to reduce that risk by inserting a review point before delivery.

## What the tool does today

- intercepts supported single-URL download flows
- downloads to a temporary file before delivery
- scans content with built-in, user, and auto-updated YARA rules
- warns on insecure transport and downgraded TLS options
- opens an interactive terminal review prompt for flagged content
- installs without replacing the operating system's `curl`
- scans supported non-interactive downloads and blocks flagged content when no review terminal exists
- logs activity to JSON Lines audit logs
- supports configurable behavior when scanning is unavailable

## Current scope

Best-supported path:

- Linux
- interactive and unattended supported downloads
- single-URL downloads
- installer-style commands
- `curl ... | bash`
- `curl ... -o file`

Requests outside that path are passed through unchanged. Known package-manager ancestors are also passed through when the optional curl shim is active. Non-interactive supported downloads are still scanned.

### Known pass-through cases

The wrapper currently defers to the real `curl` for flows such as:

- `-I`, `--head`
- `-T`, `--upload-file`
- `-F`, `--form`
- `-d`, `--data`, `--data-raw`, `--data-binary`, `--data-urlencode`
- `--next`
- `-J`, `--remote-header-name`
- multi-URL invocations
- known package-manager and unattended-upgrade ancestors such as `apt`, `apt-get`, `dnf`, `yum`, `pacman`, `snap`, and `cloud-init`

## How it works

```text
curl command
   |
   +-- unsupported request shape?
   |      |
   |      +-- package-manager / unattended automation context?
   |      |      |
   |      |      +-- pass through to the real curl
   |      |      +-- write audit log entry with scan_result=skipped
   |      |
   |      +-- pass through to the real curl
   |      +-- write audit log entry with scan_result=skipped
   |
   +-- supported single-URL request
          |
          +-- detect insecure transport / TLS settings
          +-- download with the real curl to a temp file
          +-- scan with YARA
                 |
                 +-- clean        -> deliver
                 +-- flagged      -> interactive review prompt
                 +-- unavailable  -> warn or block, depending on policy
                 +-- error        -> warn or block, depending on policy
```

## Interactive review

When suspicious content is detected, `curlguard` opens an interactive terminal prompt and offers three actions:

- `Block`
- `Quarantine`
- `Allow`

The default review experience is the Textual TUI. If you want a simpler fallback that behaves like a classic console prompt, set:

```bash
export CURLGUARD_REVIEW_INTERFACE=console
```

In console mode, `curlguard` shows the flagged URL and matched rules, then waits for a decision such as `B`, `Q`, or `A`.

If `textual` is not installed, `curlguard` automatically falls back to the console prompt instead of failing closed at import time.

If no interactive terminal is available, `curlguard` blocks the download instead of hanging.

## Installation

### Per-user install

```bash
git clone https://github.com/thetrueender/curlguard.git
cd curlguard
bash scripts/install-peruser.sh
```

This creates an isolated virtual environment and installs `curlguard` at `~/.local/bin/curlguard`. It does not replace or shadow `curl`.

To install an optional `curl` shim, use:

```bash
bash scripts/install-peruser.sh --with-curl-shim
export PATH="$HOME/.local/libexec/curlguard/bin:$PATH"
```

Only add the shim directory to interactive shell sessions where interception is wanted. Package managers continue to use `/usr/bin/curl`.

### System-wide install

```bash
git clone https://github.com/thetrueender/curlguard.git
cd curlguard
sudo bash scripts/install-systemwide.sh
```

This installs an isolated environment under `/opt/curlguard` and exposes `/usr/local/bin/curlguard`. It never modifies `/usr/bin/curl` or the system Python environment.

Administrators can add `--with-curl-shim` to create an optional shim under `/usr/local/libexec/curlguard/bin`. That directory is deliberately not added to the global `PATH`.

When upgrading from an older per-user installation, the installer disables a recognized `~/.local/bin/curl` legacy shim and preserves it as `curl.curlguard-legacy`. If an older installation replaced `/usr/bin/curl`, restore the distro-owned package first; the modern system installer refuses to proceed while that legacy replacement is active.

### Verify

```bash
command -v curlguard
curlguard --help
```

Expected result:

- per-user install: `~/.local/bin/curlguard`
- system-wide install: `/usr/local/bin/curlguard`
- `/usr/bin/curl` remains owned and managed by the operating system


## Testing

### True positive: end-to-end prompt flow

Start the synthetic suspicious sample server:

```bash
python3 examples/true_positive/start_server.py
```

In another terminal:

```bash
curlguard http://127.0.0.1:8888/test.sh | bash
```

Expected behavior:

- `curlguard` reports suspicious content
- an interactive review prompt opens
- choosing `Block` or `Quarantine` prevents the script from reaching `bash`

If you are running from the repository without installing first, use `PYTHONPATH=src python3 -m curlguard http://127.0.0.1:8888/test.sh | bash`. If you explicitly activated the optional curl shim, the equivalent `curl ... | bash` command also exercises curlguard.

This project is Linux-first. For Windows development, run these flows in WSL or another Linux shell rather than PowerShell-native `curl`.

### True negative: clean content should pass

Start the clean sample server:

```bash
python3 examples/true_negative/start_server.py
```

In another terminal:

```bash
curlguard http://127.0.0.1:8889/install.sh -o /tmp/curlguard-demo.sh
```

Expected behavior:

- the file downloads without opening the review prompt
- no suspicious rules are triggered

### Scanner-only sample

The repository includes a synthetic suspicious sample at `examples/known_malware/sample.sh`.

You can validate it directly with:

```bash
bash examples/known_malware/test_detection.sh
```

### Automated tests

```bash
pytest -v
```

The automated suite currently covers:

- true positives
- true negatives
- scan-unavailable behavior
- quarantine flow
- SSL blocking behavior
- temp-file download handling
- TUI decision-path behavior

## Dependencies

`curlguard` currently expects:

- Python 3.10+
- `yara-python`
- `textual` for the optional TUI; the console review interface remains available without it

The install scripts use a dedicated virtual environment. They never invoke `apt`, install into system Python, or use `--break-system-packages`. Install Python venv support through your OS package manager before running the script if it is unavailable.

## Detection sources

Rules are loaded independently from these locations, so one invalid optional rule file cannot disable the bundled rules:

1. built-in rules in `src/curlguard/rules/foundation.yar`
2. user rules in `~/.curlguard/rules/` or `/var/lib/curlguard/rules/`
3. auto-updated rules fetched from `CURLGUARD_UPDATE_URL`

The built-in rules currently look for patterns such as:

- suspicious `curl ... | bash`
- base64-decoded shell payloads
- obfuscated shell execution
- malware-style headers and cryptominer indicators
- suspicious network IOCs

## TLS and transport checks

`curlguard` currently detects and warns on transport issues such as:

- `--insecure`
- `-k`
- `--sslv3`
- `--tlsv1.0`
- `--tlsv1.1`
- `http://...` URLs

Blocking can be enabled for blocking-severity cases with:

```bash
export CURLGUARD_SSL_WARN_ONLY=false
```

## Scan failure policy

If scanning is unavailable or errors out, `curlguard` can either:

- warn and deliver
- block the download

Control this with:

```bash
export CURLGUARD_SCAN_FAILURE_MODE=warn
export CURLGUARD_SCAN_FAILURE_MODE=block
```

The default is `block`. Set `warn` explicitly only when availability is more important than enforcing a completed scan.

## Audit logging

Every invocation handled by the wrapper is written as JSON Lines.

Default log locations:

- per-user: `~/.curlguard/audit.log`
- system-wide: `/var/log/curlguard/audit.log`

Example entries:

```json
{"timestamp":"2024-01-01T12:00:00+00:00","url":"https://example.com/install.sh","scan_result":"clean","duration_ms":150.0,"exit_code":0}
{"timestamp":"2024-01-01T12:01:00+00:00","url":"https://evil.example/payload.sh","scan_result":"flagged","rules_triggered":["suspicious_pipe_bash"],"user_decision":"block","exit_code":1}
{"timestamp":"2024-01-01T12:02:00+00:00","url":"https://example.com/install.sh","scan_result":"unavailable","user_decision":"allow","exit_code":0}
```

Current `scan_result` values include:

- `clean`
- `flagged`
- `unavailable`
- `error`
- `skipped`

## Configuration

All runtime configuration is currently environment-variable based.

| Variable | Default | Description |
|---|---|---|
| `CURLGUARD_MODE` | `per-user` | `per-user` or an explicitly administered `system-wide` state layout |
| `CURLGUARD_LOG_PATH` | mode-specific | Override audit log path |
| `CURLGUARD_RULES_DIR` | mode-specific | Colon-separated rule directories |
| `CURLGUARD_QUARANTINE` | mode-specific | Override quarantine directory |
| `CURLGUARD_REAL_CURL_PATH` | auto-detect | Override the real curl binary path |
| `CURLGUARD_REVIEW_INTERFACE` | `tui` | Review UI for flagged content: `tui` or `console` |
| `CURLGUARD_UPDATE_URL` | unset | URL used for auto-updated rules |
| `CURLGUARD_UPDATE_SHA256` | unset | Optional lowercase SHA-256 pin for the downloaded rule file |
| `CURLGUARD_UPDATE_INTERVAL_HOURS` | `24` | Rule update interval |
| `CURLGUARD_SSL_WARN_ONLY` | `true` | Warn on TLS bypass unless a blocking-severity case is configured and this is `false` |
| `CURLGUARD_SCAN_FAILURE_MODE` | `block` | `warn` to deliver with warning, `block` to fail closed when scanning is unavailable |
| `CURLGUARD_CONTEXT_AWARE_BYPASS` | `true` | Pass through known package-manager ancestors when a curl shim is active |
| `CURLGUARD_FORCE_INTERCEPT` | `false` | Override context-aware bypass for the current process and force interception |
| `CURLGUARD_PASSTHROUGH_PROCESSES` | built-in list | Colon- or comma-separated parent process names that should bypass interception |
| `CURLGUARD_MAX_DOWNLOAD_BYTES` | `104857600` | Maximum guarded response size in bytes |
| `CURLGUARD_SCAN_TIMEOUT_SECONDS` | `10` | YARA timeout per loaded rule file |

## Uninstall

### Per-user

```bash
rm ~/.local/bin/curlguard
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/curlguard"
# If the optional shim was installed:
rm -rf ~/.local/libexec/curlguard
```

### System-wide

```bash
sudo rm /usr/local/bin/curlguard
sudo rm -rf /opt/curlguard
# If the optional shim was installed:
sudo rm -rf /usr/local/libexec/curlguard
```

## Status

`curlguard` is functional for its primary Linux installer-defense path, but it is still an early-stage security tool rather than a drop-in replacement for every `curl` workflow. The default behavior is intentionally biased toward interactive shell use rather than system package-management plumbing.

If you are evaluating or extending it, start with:

- Linux
- single-URL downloads
- installer-style commands
- YARA-backed pre-delivery scanning
- the included true-positive and true-negative example servers
