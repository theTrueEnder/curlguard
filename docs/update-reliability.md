# Download reliability, policy and migration

## Supported transfer contract

The wrapper scans supported HTTP/HTTPS single-URL GET bodies before publishing
bytes. Native curl performs transfers and supported write-out formatting. Supported
features include `-fsSL`, attached/long option values, stdout/`-o`/`-O`, redirects,
compression, timeout/retry options, resume, conditional requests, ETags and common
status/timing write-out variables. curl 7.70+ JSON metadata is required.

Resume scans the complete staged file including the retained prefix. Content-Range
is validated. Empty HTTP 200 can replace an existing file with an empty file;
HTTP 304 preserves the destination but revalidates retained bytes before accepting
an applicable hash. Hash-required 304 without a retained file blocks. Output and
ETag files remain unchanged on verification failures. A catchable publication
failure rolls back a changed ETag; two files cannot form one crash-proof filesystem
transaction. No retry occurs after delivery begins.

Unknown curl options, upload/body requests, multiple URLs, arbitrary range headers,
streaming, external configuration/write-out sources, globbing and special/foreign/
hardlinked output destinations are unsupported. Active implicit curl configuration
also makes a request unsupported unless curl's first-argument `-q` disables it.
General defaults warn and pass the original invocation unchanged; security defaults
block before network activity. An explicit/required invocation hash or any configured artifact pins also block
unsupported requests, since those bytes cannot be verified by the wrapper.
The explicit `fetch` command always blocks unsupported shapes and never silently
falls back to an unscanned transfer.

Existing destinations are staged beside their final paths and replaced atomically.
Signals are forwarded, children reaped and temporary files cleaned on catchable
failures. SIGKILL/power loss cannot run cleanup. Logging failure does not change
a transfer result. Quarantine failure never permits delivery.

Supported transfers also have independent staged-byte and total elapsed budgets.
See [investigation and CI workflows](investigation-and-ci.md) for their exact
bounds, JSON report/lock schemas, offline publisher verification, local inspection
and deliberate quarantine export. These do not execute payloads or extend
protection to undeclared secondary downloads.

## Artifact policies and trust migration

Default policy paths are `~/.curlguard/policy.json` for regular users and
`/var/lib/curlguard/policy.json` for root in system mode. An explicitly selected
`CURLGUARD_POLICY_FILE` must exist. Schema 1 contains `artifacts` and `exceptions`
arrays. IDs must be unique across both arrays; artifact source URLs must be unique.

Artifact records contain `id`, `url`, `sha256`, and optional
`allowed_final_origins`. Exceptions contain those fields plus `rules`,
`expires_at` (timezone-aware ISO-8601), and `reason`. Example exception:

```json
{
  "schema_version": 1,
  "exceptions": [{
    "id": "reviewed-release-rule-exception",
    "url": "https://example.com/tool.sh",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "rules": ["builtin:suspicious_pipe_bash"],
    "expires_at": "2027-01-01T00:00:00Z",
    "reason": "Specific release reviewed by the local policy owner"
  }]
}
```

Match URLs exactly after scheme/hostname/default-port normalization. Paths and
queries retain meaning. Policy URLs forbid credentials/fragments. Permitted final
origins include scheme/host/port and default to the source origin. These checks
happen before delivery and do not provide network isolation. No wildcard or
implicit subdomain allowances exist. Rule identifiers can be simple rule names
or namespace-qualified names; namespace-qualified names are preferable.

An exception only suppresses listed findings on those exact bytes, source and
permitted final origin before expiration. Additional findings remain actionable.
A matching expected hash alone never suppresses detection. Scan results remain
flagged even if scoped exceptions permit delivery.

Remove nonempty `CURLGUARD_TRUSTED_HOSTS`, `CURLGUARD_TRUSTED_SHA256`, and legacy
`trust.json` allowances before upgrading. They produce migration errors. Broad
host entries cannot be safely converted automatically. For a reviewed artifact,
obtain an independently trusted hash and create an exact artifact record; create
a separate time-limited rule exception only when needed. Legacy global hashes
also need source/rule scope before becoming exceptions.

Expected hashes come from `fetch --sha256`, `CURLGUARD_EXPECTED_SHA256`, or an exact
artifact record. Conflicts are rejected before fetching. Security defaults require
a hash; `CURLGUARD_REQUIRE_SHA256=false` relaxes absence only. Mismatches always
block. A scan with no matches proves neither publisher authenticity nor safety.

## Transport and findings

Independent settings control HTTPS, certificate verification, minimum TLS and
redirect protocols. Security defaults reject initial HTTP and `--insecure`, enforce
TLS 1.2+, and configure real curl to forbid non-HTTPS redirects before following
them. Explicit policy overrides are permitted and recorded in resolved settings.
Requested low TLS minimums are distinguished from low TLS maximums and actual
negotiated versions; unknown negotiated versions remain unknown.

`CURLGUARD_SSL_WARN_ONLY` is deprecated. A legacy false setting maps to strict
transport defaults; conflicting legacy and new transport settings are errors.
Use the independent settings in the [README](../README.md#configuration).

Findings preserve namespace, description, severity, confidence, category, ruleset
identity and bounded locations. Interactive review additionally receives bounded,
escaped excerpts with markup disabled. Excerpts are excluded from audit/sidecars.
Malformed optional metadata defaults conservatively to high severity/unknown
confidence. `CURLGUARD_SEVERITY_THRESHOLD=low` makes all findings actionable;
raising it explicitly permits lower-severity findings with a warning. Default
content policy is quarantine in both editions. Review without a terminal blocks.

## Signed rule feeds

Bundled/local rules always participate. Remote updates require HTTPS at every
redirect and a locally provisioned public-key file:

```json
{"keys": {"publisher-2026": "BASE64_RAW_32_BYTE_ED25519_PUBLIC_KEY"}}
```

Set `CURLGUARD_UPDATE_KEYS_FILE`, `CURLGUARD_UPDATE_FEED_ID`, and
`CURLGUARD_UPDATE_URL`. No key is implicitly trusted because it arrived from a
feed. The endpoint returns a schema-1 envelope with `key_id`, `manifest` (base64
of exact JSON bytes), and `signature` (base64 Ed25519 signature over those bytes).
The signed manifest contains `schema_version`, `feed_id`, positive integer
`sequence`, `published_at`, `expires_at`, `rules_sha256`, and `rules` (base64 UTF-8).

Generate/manage signing keys outside runtime installations. Publish with:

```bash
python -m curlguard.sign_rules rules.yar bundle.json \
  --private-key /secure/offline/publisher.pem --key-id publisher-2026 \
  --feed-id your-feed --sequence 1 \
  --published-at 2026-10-16T00:00:00Z --expires-at 2026-11-16T00:00:00Z
```

Advance sequence for every changed bundle. The signing utility reads an existing
Ed25519 PEM private key; it never installs keys. Deliver the corresponding raw
public key through an independently trusted channel. Tests generate ephemeral keys.

Run `curlguard rules update` explicitly, then `curlguard rules status --json`.
Ordinary downloads never perform update HTTP requests. A scheduler can run:

```cron
0 */6 * * * /absolute/path/to/curlguard rules update
```

This is an example only; no scheduler is installed automatically. The old update
interval setting does not schedule updates. Failed attempts back off for five
minutes. The status includes the last failure; skipped concurrent/backoff updates
return failure rather than claiming a new update succeeded.

Envelopes are limited to 8 MiB and decoded rule source to 5 MiB; nested base64 means
the encoded-envelope limit can be reached before the decoded-source limit.
Unsigned, unknown-key, altered, expired, future-published and rollback bundles are
rejected. Equal sequence requires identical envelope bytes. Complete candidate
rulesets compile with includes disabled under 30s wall/20s CPU/512 MiB limits.
A process lock serializes updates; a single atomic active-generation pointer binds
accepted source, sequence, signed bytes and configured trust. Failed compilation
retains the active generation. Local rules also use isolated compilation.

State resides under the quarantine directory's parent in `feeds/`. Active bytes
are verified again on load. The binding includes feed URL and the complete key-set
identity. Changing either requires deliberate state migration: retain a private
backup of `feeds/`, provision/verify the new trust, move the old `feeds/` aside,
then explicitly update. This deliberately resets rollback history; obtain a known
current sequence through a trusted channel before migration. Do not fetch keys or
reset state automatically to bypass a signature failure.

General defaults warn and use usable cached/bundled/local rules if a configured
feed is unavailable/expired. Security defaults require an accepted, unexpired
configured feed. Without a remote feed, bundled/local rules suffice. This is
protection against remote replay, not local privileged state rollback.

## Runtime installation and legacy migration

The installers build wheels unprivileged and install offline from a privately
staged wheelhouse into a versioned virtual environment. System runtime contents
and helper code are root-owned before pip/package execution. Candidate health
checks run outside the checkout with Python source/user-site injection removed.
Both managed wrappers are preflighted and rolled back on catchable publication
failure. Old environments remain for deliberate rollback/removal. Two wrapper
replacements are not one power-loss-proof transaction.

If an old pip-generated `curlguard` console script remains, the installer refuses
to overwrite it as unrelated. Inspect that script and its package ownership,
retain the old environment, then remove that specific old entry point manually
before retrying. Do not remove unrelated executables or delete a shared Python
environment. Reconfigure shell PATH; installers do not rewrite shell startup files.

Legacy `/usr/bin/curl.real` migration remains explicit:

```bash
bash scripts/install-systemwide.sh --migrate-legacy
```

Only that mode may repair the current Debian/Ubuntu curl package after backup and
ownership/checksum checks. Ordinary verification uses isolated paths/mocks and
never runs package repair. Uninstall refuses unresolved legacy layouts and never
restores stale curl.real. System wrappers remain in `/usr/local/bin`, leaving
`/usr/bin/curl` package-owned. Regular users retain private state in `~/.curlguard`;
root system mode uses `/var/lib/curlguard` and `/var/log/curlguard`.

## Evidence, failure and verification

Audit retains legacy `scan_result` (`clean`, `flagged`, `unavailable`, `error`,
`skipped`) and adds schema-1 `evidence`: detection (`no_matches`, `flagged`,
`unavailable`, `error`, `skipped`), integrity (`matched`, `mismatched`,
`missing_required`, `unspecified`), authenticity (`unverified`), transport,
findings and a stable decision reason. Edition and effective settings are recorded.
URL credentials/query values are redacted; no raw argv or authorization headers
are logged. Audit is best effort, not an enforcement boundary.

Exit 17 means missing required/mismatched hashes; 12 is transport policy; 13 required
scanner/feed failure; 14 unsupported; 15 configuration; 16 internal/delivery.
Other native curl failures and signal statuses retain their conventional meanings.
`doctor` needs no artifact hash and returns 0 when required capabilities are ready,
13 for scanner/required-feed problems, or 15 for runtime/configuration/curl problems.

Linux CI tests the supported Python 3.10/curl 7.81 and Python 3.12/curl 8.5 matrix,
including real YARA, local HTTP/HTTPS, signed-feed failure injection, built wheel/
sdist imports outside the checkout and isolated installation failure tests.
See [development](development.md) and [redesign validation](redesign-validation.md).
