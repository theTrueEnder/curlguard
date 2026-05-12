# curlguard

`curlguard` is a Linux-first safety wrapper for `curl` that grows toward a safer day-to-day `curl` experience without trying to replace the real tool.

Instead of streaming remote content directly into `bash`, `curlguard` downloads supported requests with the real system `curl`, scans the payload with YARA rules, warns on insecure transport, applies lightweight trust policy, and quarantines suspicious content by default.

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
- supports configurable flagged-content policy: `quarantine`, `prompt`, `block`, or `allow`
- supports lightweight trust decisions with trusted hosts and trusted SHA-256 checksums
- writes quarantine metadata alongside quarantined payloads
- logs activity to JSON Lines audit logs
- supports configurable behavior when scanning is unavailable

## Current scope

Best-supported path:

- Linux
- single-URL downloads
- installer-style commands
- `curl ... | bash`
- `curl ... -o file`
- `curl ... -O`

Requests outside that path are passed through to the real `curl`.

### Known pass-through cases

The wrapper currently defers to the real `curl` for flows such as:

- `-I`, `--head`
- `-T`, `--upload-file`
- `-F`, `--form`
- `-d`, `--data`, `--data-raw`, `--data-binary`, `--data-urlencode`
- `--next`
- `-J`, `--remote-header-name`
- multi-URL invocations

## How it works

```text
curl command
   |
   +-- unsupported request shape?
   |      |
   |      +-- pass through to the real curl
   |      +-- write audit log entry with scan_result=skipped
   |
   +-- supported single-URL request
          |
          +-- detect insecure transport / TLS settings
          +-- download with the real curl to a temp file
          +-- scan with YARA
          +-- check lightweight trust policy
                 |
                 +-- clean        -> deliver
                 +-- flagged      -> quarantine / prompt / block / allow
                 +-- unavailable  -> warn or block, depending on policy
                 +-- error        -> warn or block, depending on policy
```

## Flagged content handling

By default, suspicious content is quarantined and not delivered.

You can choose one of four flagged-content policies:

- `quarantine` — store the file locally and stop delivery
- `prompt` — open the interactive terminal review prompt
- `block` — refuse delivery and discard the temporary file
- `allow` — deliver the file with a warning

Set it with:

```bash
export CURLGUARD_MATCH_POLICY=quarantine
```

When `prompt` is enabled, `curlguard` opens an interactive terminal prompt and offers three actions:

- `Block`
- `Quarantine`
- `Allow`

If no interactive terminal is available, `curlguard` blocks the download instead of hanging.

## Trust controls

`curlguard` stays lightweight by keeping trust configuration file- and env-based.

It can auto-allow flagged content when either of these matches:

- the payload SHA-256 is in the trusted checksum list
- the request host is in the trusted host list

Environment-based trust:

```bash
export CURLGUARD_TRUSTED_HOSTS=downloads.example.com,artifacts.example.com
export CURLGUARD_TRUSTED_SHA256=0123...,abcd...
```

File-based trust:

```json
{
  "hosts": ["downloads.example.com"],
  "sha256": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
}
```

Save that file as:

- per-user: `~/.curlguard/trust.json`
- system-wide: `/var/lib/curlguard/trust.json`

Or point to a custom location:

```bash
export CURLGUARD_TRUST_FILE=/path/to/trust.json
```

## Quarantine inspection

Quarantined payloads stay file-based and easy to inspect.

List everything currently in quarantine:

```bash
curlguard quarantine list
```

Inspect one payload by name, prefix, or metadata path:

```bash
curlguard quarantine inspect 1713900000_payload.download
```

Each quarantined payload keeps a JSON sidecar with:

- capture time
- source URL
- matched rules
- SHA-256
- payload size

## Installation

### Per-user install

```bash
git clone https://github.com/thetrueender/curlguard.git
cd curlguard
bash scripts/install-peruser.sh
source ~/.bashrc
```

This installs the wrapper at `~/.local/bin/curl` and keeps the real system `curl` in place.

### System-wide install

```bash
git clone https://github.com/thetrueender/curlguard.git
cd curlguard
sudo bash scripts/install-systemwide.sh
```

This replaces `/usr/bin/curl` with the wrapper and stores the original binary as `/usr/bin/curl.real`.

### Verify

```bash
which curl
curlguard --help
```

Expected result:

- per-user install: `~/.local/bin/curl`
- system-wide install: `/usr/bin/curl`


## Testing

### True positive: end-to-end prompt flow

Start the synthetic suspicious sample server:

```bash
python3 examples/true_positive/start_server.py
```

In another terminal:

```bash
curl http://127.0.0.1:8888/test.sh | bash
```

Expected behavior:

- `curlguard` reports suspicious content
- with the default policy, the payload is quarantined
- with `CURLGUARD_MATCH_POLICY=prompt`, an interactive review prompt opens
- choosing `Block` or `Quarantine` prevents the script from reaching `bash`

### True negative: clean content should pass

Start the clean sample server:

```bash
python3 examples/true_negative/start_server.py
```

In another terminal:

```bash
curl http://127.0.0.1:8889/install.sh -o /tmp/curlguard-demo.sh
```

Expected behavior:

- the file downloads without opening the review prompt
- `curlguard` prints where it saved the file, along with its size and SHA-256
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
- `textual`
- `requests`
- `httpx`

The install scripts try to use distro packages for `python3-yara`, `python3-requests`, and `python3-httpx`, and `pip` for `textual`.

## Detection sources

Rules are loaded from these locations, in this order:

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

The default is `warn`.

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

Audit events also include the delivered or quarantined file checksum, size, and decision reason.

## Configuration

All runtime configuration is currently environment-variable based.

| Variable | Default | Description |
|---|---|---|
| `CURLGUARD_MODE` | auto-detect | `per-user` or `system-wide` |
| `CURLGUARD_LOG_PATH` | mode-specific | Override audit log path |
| `CURLGUARD_RULES_DIR` | mode-specific | Colon-separated rule directories |
| `CURLGUARD_QUARANTINE` | mode-specific | Override quarantine directory |
| `CURLGUARD_REAL_CURL_PATH` | auto-detect | Override the real curl binary path |
| `CURLGUARD_UPDATE_URL` | unset | URL used for auto-updated rules |
| `CURLGUARD_UPDATE_INTERVAL_HOURS` | `24` | Rule update interval |
| `CURLGUARD_SSL_WARN_ONLY` | `true` | Warn on TLS bypass unless a blocking-severity case is configured and this is `false` |
| `CURLGUARD_MATCH_POLICY` | `quarantine` | `quarantine`, `prompt`, `block`, or `allow` when suspicious content is detected |
| `CURLGUARD_SCAN_FAILURE_MODE` | `warn` | `warn` to deliver with warning, `block` to fail closed when scanning is unavailable |
| `CURLGUARD_TRUST_FILE` | mode-specific | Optional JSON trust file with `hosts` and `sha256` arrays |
| `CURLGUARD_TRUSTED_HOSTS` | unset | Comma-separated trusted hosts that can auto-allow flagged content |
| `CURLGUARD_TRUSTED_SHA256` | unset | Comma-separated trusted SHA-256 checksums that can auto-allow flagged content |

## Exit codes

`curlguard` uses stable exit codes for its own policy decisions:

- `0` — delivered or allowed
- `10` — blocked due to suspicious content
- `11` — quarantined due to suspicious content
- `12` — blocked by SSL/TLS policy
- `13` — blocked because scanning failed and fail-closed mode is enabled

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

## Status

`curlguard` is functional for its primary Linux safe-download path, but it is still an early-stage security tool rather than a drop-in replacement for every `curl` workflow.

If you are evaluating or extending it, start with:

- Linux
- single-URL downloads
- installer-style and artifact-download commands
- YARA-backed pre-delivery scanning
- quarantine-first handling with file/env-based trust controls
- the included true-positive and true-negative example servers
