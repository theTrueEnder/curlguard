# Update compatibility and failure handling

curlguard scans supported HTTP/HTTPS GET downloads before publishing payload bytes. stdout is buffered until scanning finishes. This intentionally prevents streaming execution of an unreviewed installer.

## Command compatibility

The `curl` wrapper accepts curl options in either order, including clusters (`-fsSL`), attached values (`-ofile`), `--output=file`, `--url`, and `--`. Native curl help/version requests remain native; `curlguard --help`, `curlguard --version`, and `curlguard quarantine ...` manage curlguard itself.

Supported downloads include stdout, `-o`, `-O`, redirects, compression, timeouts/retries, automatic and explicit resume to regular files, time conditions, ETag comparisons/saves, and common status/timing write-out variables. Existing files are staged beside their destination and replaced atomically after scanning. Resume scans the complete staged file, including its existing prefix. Invalid or inconsistent Content-Range responses fail without replacing the destination. HTTP 304 preserves the payload; an empty HTTP 200 replaces it with an empty file.

Write-out formatting is performed by real curl. Supported fields include response/http code, transfer times, byte counts, speed, redirect count, TLS verification status, HTTP version, and local/remote addresses. File-dependent fields, `%{json}`, external format files, and write-out output-switching directives are unsupported. Body output precedes write-out stdout. Diagnostics are on stderr; successful delivery summaries respect `-s`.

Downloads require curl 7.70 or newer for private JSON transfer metadata. Older versions follow the unsupported-request policy; native help/version still work.

Unknown options and unmodeled request shapes are never rewritten. Examples include uploads, request bodies, multiple transfers, URL globbing, arbitrary range requests, streaming modes, custom config files, special output files, symlinks, hardlinks, and outputs with foreign ownership or insufficient write permission. An active implicit curl config also makes the request unsupported unless curl's first-argument `-q` behavior disables it.

`CURLGUARD_UNSUPPORTED_POLICY=passthrough` (default) runs the original command unchanged and audits the request as **skipped**, with a reason. `block` exits 14 before network activity. Pass-through payloads are not scanned. This setting is independent of scan-failure policy.

## Scanning and rules

Bundled rules always participate, even if user rule directories are empty. File scanning and hashing avoid loading entire payloads into Python memory. Defaults:

| Setting | Default |
|---|---|
| `CURLGUARD_SCAN_TIMEOUT_SECONDS` | `10` |
| `CURLGUARD_MAX_SCAN_BYTES` | `268435456` (256 MiB) |
| `CURLGUARD_SCAN_FAILURE_MODE` | `warn` |

Numeric settings must be positive integers. Missing YARA, invalid initial rules, oversized payloads, and scan timeouts produce unsuccessful scan statuses. `warn` delivers with a warning; `block` exits 13. Neither failure nor skipped scanning is described as verification. Flagged content still defaults to quarantine; scanning a file is not a guarantee that the file is safe.

The base64 rule requires decoding connected to shell execution. Official rustup, uv, and nvm installer snapshots are pinned with source URLs and SHA-256 values under `tests/fixtures/installers`; tests scan these fixtures without executing them. Trusted checksum exceptions remain available. Trusted-host exceptions require both the requested URL and final redirect URL to be trusted.

Rule updates require HTTPS through every redirect, use a 30-second request timeout, and accept at most 5 MiB. Updates compile the entire candidate ruleset before atomic activation. Failure retains active rules and the previous success timestamp; retries back off for five minutes. A cross-process lock prevents concurrent activation. YARA includes are disabled for all sources, a stricter policy than restricting remote includes to their staging directory.

## Installation and migration

Per-user wrappers live at `~/.local/bin/curl`. System wrappers live at `/usr/local/bin/curl`; `/usr/bin/curl` stays package-owned. The wrapper invokes its absolute Python interpreter and real curl path. Absolute `/usr/bin/curl` calls bypass scanning. Both install and uninstall refuse unrelated executables and reject wrapper recursion.

For a legacy installation containing `/usr/bin/curl.real`, run:

```bash
sudo bash scripts/install-systemwide.sh --migrate-legacy
```

Migration backs up both executables, reinstalls the current distro curl package using APT, verifies package ownership and the installed executable against the package's checksum metadata, then installs the PATH wrapper. It never restores a saved `curl.real` over a newer package. Interrupted or failed migrations retain backups under `/var/lib/curlguard/legacy-backup-*`; rerunning migration can recover. Automatic migration requires Debian/Ubuntu and root. Uninstall refuses unresolved legacy installations.

System-wrapper invocations by regular users keep audit, trust, quarantine, and update state under `~/.curlguard` and also load system rules. Root uses `/var/log/curlguard` and `/var/lib/curlguard`. Explicit environment overrides take precedence. This avoids making shared system state writable by every user.

## Failure reporting and limits

| Exit | Meaning |
|---|---|
| 10–13 | Existing content, quarantine, TLS, and scan-failure policies |
| 14 | Unsupported request blocked |
| 15 | Invalid configuration |
| 16 | Internal/preparation/validation/delivery failure |
| Other curl codes | Preserved from the real curl process |
| 128 + signal | Interrupted process |

Audit records include processing stage, error category, interception reason, effective URL, and ruleset identity. URL credentials and query values are redacted. No raw command lines or authorization headers are logged. Log append and rotation are process-locked. Logging failure warns without overriding a transfer result. Quarantine payloads and metadata have private permissions; inability to quarantine never permits delivery.

Failed supported transfers preserve existing destinations rather than publishing partial output. Signals are forwarded to curl's process group, child processes are reaped, and temporary files are removed. SIGKILL and power loss cannot execute cleanup. A payload replacement is atomic; payload and ETag files cannot be replaced as one filesystem transaction. Catchable delivery failures roll back staged ETag changes, but process death between the two replacements can require revalidation. There is no retry after payload delivery starts.

## Validation

Linux CI covers Python 3.10/curl 7.81 on Ubuntu 22.04 and Python 3.12/curl 8.5 on Ubuntu 24.04 with real YARA. The mandatory suite uses local HTTP/HTTPS fixtures and compares real curl's payloads, write-out output, error codes, and requests. It injects filesystem, logging, scanning, rule-update, cancellation, and installation failures. Supported-flow buffering, security diagnostics, pre-delivery policy decisions, and preservation of existing files on failure are intentional differences from native curl.

Optional WSL validation is available as `python scripts/validate-wsl-updates.py --output /tmp/curlguard-validation`. It uses private APT lists/download directories, simulates upgrades, compares package hashes, and unpacks a curl package into an isolated wrapper layout. It does not install system packages or execute downloaded installers.
