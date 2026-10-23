# curlguard

curlguard is a Linux-first curl wrapper and explicit download tool. It stages
supported HTTP/HTTPS downloads, scans their bytes with YARA, evaluates transport
and artifact policy, and publishes only after those checks finish.

A scan with no matches is not proof that an artifact is safe. SHA-256 verification
checks expected bytes; it does not authenticate a publisher. Pinned lockfiles can
require offline Sigstore publisher verification independently of malware scanning.

## Editions

The current branch is **codex/security-users**. The maintained general variant is
**codex/general-users**. They share the download/scanner/policy implementation;
`edition.py` selects shipped defaults. Merge shared fixes from general into security.

| Setting | General users | Security users |
|---|---|---|
| Unsupported curl request | Warn and pass through unchanged | Block |
| Unavailable/failed scan | Warn and deliver | Block |
| Unsuppressed finding | Quarantine | Quarantine |
| Initial HTTP / certificate bypass | Warn | Block |
| Minimum enforced TLS | Native curl behavior | 1.2 |
| Redirect protocols | Native curl behavior | HTTPS |
| Expected SHA-256 | Optional | Required |
| Configured remote rule feed | Warn if unavailable/expired | Require an accepted, unexpired generation |

Settings are deliberately changeable. For example, the security edition can allow
unpinned downloads with `CURLGUARD_REQUIRE_SHA256=false`; supplied hashes still
must match. Resolved settings and edition appear in help, health and download audit.
These are voluntary user-space PATH wrappers. Absolute `/usr/bin/curl` calls,
other download clients and secondary installer downloads remain outside coverage.

## Commands

```bash
curlguard fetch https://example.com/tool.sh -o tool.sh --sha256 <64-hex-digest>
curlguard doctor --json
curlguard rules status --json
curlguard rules update
curlguard quarantine list
curlguard quarantine inspect <identifier>
curlguard scan ./artifact --json
curlguard quarantine rescan <identifier> --json
curlguard quarantine export <identifier> ./new-file --json
curlguard fetch --lock artifact.lock.json --report fetch.json -o artifact
curlguard bootstrap manifest.json --output-dir new-downloads --json
```

`fetch` supports one URL or a pinned lock, optional output, expected hash and JSON
report; unknown options are errors. It blocks scan failures and would-be prompts.
It follows permitted redirects and never executes content. Do not take
a checksum supplied by the same compromised download as an independent trust anchor.

See [investigation and CI workflows](docs/investigation-and-ci.md) for schemas,
offline publisher verification, independent transfer budgets and fetch-only examples.
The [administrator threat model](docs/organizational-enforcement.md) describes
enforcement boundaries; the wrapper remains voluntary.

The installed `curl` wrapper accepts the supported native argument shapes, including
`-fsSL`, `-o`, `-O`, resume, conditional/ETag requests and common write-out fields.
stdout is buffered until policy permits delivery. Uploads, request bodies, multiple
URLs, streaming, custom/implicit curl configs and other unmodeled features are
unsupported; general users get a warning and unchanged native invocation. Required
or explicit hashes, or any configured artifact pins, force unsupported commands
to block rather than bypass verification.

## Installation

Use Linux/WSL, Python 3.10+, pip/venv, and curl 7.70+. Wheel building may require
native build tools/libyara development headers when compatible binary dependencies
are unavailable. Install these prerequisites separately; the installers do not
repair system packages.

```bash
git clone https://github.com/thetrueender/curlguard.git
cd curlguard
git checkout codex/general-users  # or codex/security-users
bash scripts/install-peruser.sh
export PATH="$HOME/.local/bin:$PATH"
curlguard doctor --json
```

For a system wrapper, run `bash scripts/install-systemwide.sh` as your regular user.
The script builds without privilege, then requests sudo to install a privately
staged, root-owned runtime under `/opt/curlguard`. A sudo invocation with a normal
`SUDO_USER` re-enters the build as that user; direct root-only builds are refused.

Per-user runtimes live under `~/.local/share/curlguard`. Both installers use built
wheels and versioned virtual environments. They validate a candidate before
replacing the owned `curl` and `curlguard` wrappers. System wrappers live under
`/usr/local/bin`; the package-owned `/usr/bin/curl` remains untouched. An unrelated
wrapper/CLI executable is never silently replaced. Keep previous runtimes until
you decide they are no longer needed.

Installation prepares rollback backups before changing either wrapper and
serializes install, uninstall, and recovery. If publication fails, the candidate
runtime is retained whenever a wrapper might reference it. An unresolved
transaction blocks further installation or uninstall. Use the retained runtime's
absolute Python path and the transaction path printed by the installer:

```bash
/path/to/retained/runtime/bin/python -I -m curlguard.cli recover-install /path/to/bin/.curlguard-transaction
```

Recovery restores the previous wrappers, or removes this transaction's wrappers
after a failed fresh install. A committed installation awaiting cleanup keeps its
new wrappers. Recovery refuses unknown edits; preserve the journal, backups, and
runtimes for investigation if it cannot complete. Run system recovery as root.
Never delete a runtime while either live wrapper references it. The persistent
`.curlguard-install.lock` file is intentional and should not be removed while
installation or recovery may be running.

Production installation does not use editable packages or global pip modifications.
For old editable installations, remove their old console entry point only after
checking its ownership and retaining the previous runtime. See
[migration and policy](docs/update-reliability.md).

## Policies and hashes

Set `CURLGUARD_POLICY_FILE` to a schema-1 JSON file, or use the default mode-specific
`policy.json`. A minimal artifact record is:

```json
{
  "schema_version": 1,
  "artifacts": [{
    "id": "tool-release",
    "url": "https://example.com/tool.sh",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }],
  "exceptions": []
}
```

The default permitted final origin is the source origin. Add
`allowed_final_origins` for explicit alternatives. Matching normalizes scheme,
host and default port while preserving path and query semantics. Wildcards and
implicit subdomain trust are not supported. Query strings are redacted in audit.

`CURLGUARD_EXPECTED_SHA256` provides a hash for wrapper invocations. Conflicts
between command/environment and policy hashes fail before network activity.
A matching hash never automatically suppresses a malware finding. Detection
exceptions additionally require exact content/source, specific rules, an expiry
and an explanation; see the policy documentation.

## Signed rule updates

Bundled/local rules always participate. Remote updates require signed, versioned
Ed25519 bundles with locally provisioned public keys. Raw remote YARA files are
rejected. Configure `CURLGUARD_UPDATE_URL`, `CURLGUARD_UPDATE_FEED_ID` and
`CURLGUARD_UPDATE_KEYS_FILE`, then run `curlguard rules update` explicitly.
Ordinary downloads never fetch rule updates. See
[signed-feed publishing](docs/update-reliability.md#signed-rule-feeds).

## Configuration

| Variable | Purpose |
|---|---|
| `CURLGUARD_MODE` | `per-user` or `system-wide`; installed wrappers set it |
| `CURLGUARD_REAL_CURL_PATH` | Absolute real curl executable |
| `CURLGUARD_LOG_PATH` | JSONL audit path |
| `CURLGUARD_RULES_DIR` | Colon-separated local rule directories |
| `CURLGUARD_QUARANTINE` | Quarantine path; its parent also holds signed-feed state |
| `CURLGUARD_POLICY_FILE` | Artifact/exception policy file |
| `CURLGUARD_EXPECTED_SHA256` | Invocation's expected hash |
| `CURLGUARD_REQUIRE_SHA256` | Require a hash before supported downloads |
| `CURLGUARD_MATCH_POLICY` | `quarantine`, `block`, `prompt`, or `allow` |
| `CURLGUARD_SEVERITY_THRESHOLD` | Lowest actionable severity; defaults to `low` (all findings) |
| `CURLGUARD_SCAN_FAILURE_MODE` | `warn` or `block` |
| `CURLGUARD_UNSUPPORTED_POLICY` | `passthrough` or `block` |
| `CURLGUARD_REQUIRE_HTTPS` | Block initial HTTP and restrict initial protocols |
| `CURLGUARD_VERIFY_CERTIFICATES` | Reject `--insecure` |
| `CURLGUARD_MIN_TLS` | `none`, `1.0`, `1.1`, `1.2`, `1.3` |
| `CURLGUARD_REDIRECT_PROTOCOLS` | Allowed redirect protocols, comma-separated `http`/`https`; empty means native |
| `CURLGUARD_REQUIRE_FRESH_RULES` | Require an unexpired configured remote feed |
| `CURLGUARD_UPDATE_URL` | Signed bundle HTTPS endpoint |
| `CURLGUARD_UPDATE_FEED_ID` | Expected signed feed identity |
| `CURLGUARD_UPDATE_KEYS_FILE` | Locally provisioned Ed25519 public-key file |
| `CURLGUARD_SCAN_TIMEOUT_SECONDS` | YARA match timeout, default 10 |
| `CURLGUARD_MAX_STAGED_BYTES` | Maximum staged file size, default 1073741824; independent of scan size |
| `CURLGUARD_TRANSFER_TIMEOUT_SECONDS` | Total staged transfer deadline, default 300 seconds |
| `CURLGUARD_COSIGN_PATH` | Cosign v3.1.3 for offline publisher verification, default `/usr/local/bin/cosign` |
| `CURLGUARD_MAX_SCAN_BYTES` | Scan-size limit, default 256 MiB; not a download/disk budget |

Booleans accept `true`/`false`; numeric limits must be positive. Legacy broad trust
settings are rejected. `CURLGUARD_SSL_WARN_ONLY` is deprecated; conflicting legacy
and new transport settings are rejected. The old update interval variable no
longer schedules network checks; use an explicit scheduler for `rules update`.

## Exit status and audit

Codes 10/11 indicate suspicious content blocked/quarantined; 12 transport policy;
13 unsuccessful required scanning/rules; 14 unsupported request; 15 configuration;
16 internal/delivery failure; 17 missing required or mismatched expected hash.
Real curl failures and conventional signal statuses are preserved.

Audit preserves legacy scan statuses and adds schema-1 detection, integrity,
authenticity, findings, decision, settings and edition evidence. Match excerpts
are shown only in review, not logged or stored in quarantine sidecars. Audit is
best effort and redacts URL credentials/query values; it is not tamper-resistant.

## Uninstall and development

Run the installed runtime's Python with the appropriate mode:

```bash
/path/to/runtime/bin/python -c "from curlguard.curl_manager import CurlManager; CurlManager('per-user').uninstall()"
```

For system wrappers use the root-owned runtime and `CurlManager('system-wide')`
with sudo. This removes only owned wrappers; it preserves runtimes/state and distro
curl. Remove specifically selected old runtime/state directories separately when
no longer needed. Legacy `/usr/bin/curl.real` installations require explicit
migration, never stale-binary restoration.

See [development](docs/development.md), [behavior/migration](docs/update-reliability.md),
[implementation plan](docs/plans/security-redesign.md), and the separate
[underserved-use-case plan](docs/plans/underserved-use-cases.md). Scan synthetic
samples and pinned installer fixtures as data only; never execute them.
