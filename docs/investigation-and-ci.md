# Local investigation, reproducible fetches and transfer budgets

All payloads are handled as data. None of these commands execute, expand archives
or approve future downloads. Scan findings and publisher signatures are independent
evidence; no matches do not establish safety.

## Existing files

```bash
curlguard scan ./artifact --json
curlguard quarantine inspect IDENTIFIER --json
curlguard quarantine rescan IDENTIFIER --json
curlguard quarantine export IDENTIFIER ./new-file --json
```

`scan` accepts one regular file, refuses symlinks/directories/devices/FIFOs, and
never accesses the network. It takes a bounded private snapshot and checks the
source's inode, size, timestamps and mode before reporting its hash. Content,
ownership and permissions are unchanged. Access time can change. Configured signed
rules are loaded from the verified local cache only. Required unavailable rules
remain an unavailable result. HTTP requirements, URL exceptions and invocation
hash requirements do not apply to a local file. Content severity and match policy
are evaluated and reported without prompting, remediation or input mutation.

Local scan codes: 0 no matches; 10 findings (even if policy allows them);
13 oversized/unreadable/special input or scanner unavailable/error;
17 changed input. JSON never reports a content hash for changed input. A report
includes schema version, ruleset identity, independent evidence and policy decision.

Quarantine JSON inspect verifies current bytes against the captured digest;
tampering exits 17, missing/unreadable bytes exit 13, and absent/ambiguous IDs exit 1.
Historic sidecars without a digest remain inspectable with `integrity=unspecified`.
The older human-readable inspect view retains its metadata display semantics.
Rescans retain the original capture fields and append timestamped results in
`rescans` with each selected ruleset identity. Historical findings are never
rewritten to imply they came from current rules. Tampering is recorded independently
of the scan result. A missing payload is recorded as an unreadable rescan.

Export requires a captured digest, rechecks it and current content policy on the
same private snapshot, then publishes mode 0600 to a **new** name using an atomic
no-clobber operation. Existing regular files, symlinks and destination races block;
scanner failure always blocks export, regardless of warn-mode downloads. Flagged
content exports only when content policy explicitly allows it (including below
threshold); prompt/quarantine/block decisions do not release it. Local URL-scoped
exceptions do not authorize export. Export does not delete quarantine records.

## Fetch reports and lockfiles

```bash
curlguard fetch https://example.com/artifact --sha256 "$EXPECTED_SHA256" \
  -o artifact --report fetch.json --write-lock artifact.lock.json
curlguard fetch --lock artifact.lock.json -o artifact --report replay.json
```

Explicit fetch is noninteractive, blocks scanner failures, and blocks a would-be
prompt. File reports and generated lockfiles must be new and separate from the
payload, input lock and audit path. They are reserved before network activity.
`--report -` emits JSON to stderr; stdout remains payload bytes. Other diagnostic
lines may also appear on stderr; a dedicated report file is preferable for CI.
Reports include the exit code, source/effective URL (query values redacted), hash,
size, ruleset identity, settings and evidence. Always check the command's exit code;
an interrupted/failed command may leave an empty reserved report/lock, which is
not valid evidence. Report-write failures can occur after payload publication.

Schema 1 locks declare exact source URL, expected hash and required scanning:

```json
{
  "schema_version": 1,
  "kind": "artifact_lock",
  "source": "https://example.com/artifact",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "verification": {"scan_required": true}
}
```

Unknown lock fields/versions are errors, conflicting pins block before requesting
bytes, and source/byte changes block before publication. Scanning uses current
rules and current content/transport policy; a lock does not freeze those settings.
Locks retain full source query values to preserve exact identity; keep secrets
out of URLs and protect lockfiles. Credentials/fragments are refused. A generated
hash records observed bytes; establish the initial pin through a trusted channel.
See the [schemas](schemas/artifact-lock.schema.json),
[fetch report](schemas/fetch-report.schema.json),
[scan report](schemas/scan-report.schema.json), and
[quarantine report](schemas/quarantine-report.schema.json).

## Offline publisher verification and trust updates

Schema 1 `verification.publisher` requires all six fields:

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "identity": "https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/v1",
  "bundle": "artifact.sigstore.json",
  "bundle_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "trusted_root": "trusted-root.json",
  "trusted_root_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Paths resolve relative to the lock/manifest. Bundle/root bytes are hash-pinned and
copied into bounded private snapshots. Only Sigstore v0.3 bundles with media type
`application/vnd.dev.sigstore.bundle.v0.3+json` are accepted. Install separately
the supported verifier **Cosign v3.1.3**, selected via `CURLGUARD_COSIGN_PATH`
(default `/usr/local/bin/cosign`); runtime checks its exact version. The CI Linux
amd64 binary is pinned to SHA-256
`4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`.

The adapter uses exact issuer/identity flags, an offline bundle and an explicit
local trusted root with a private HOME. It never disables transparency/SCT checks,
discovers signers, refreshes trust or falls back to online verification. Missing,
invalid or incomplete evidence exits 17 before publication. Malware evidence is
still required after a signature succeeds. The upstream interfaces are documented
in [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/) and
[the pinned command reference](https://github.com/sigstore/cosign/blob/v3.1.3/doc/cosign_verify-blob.md).

Policy owners must independently authenticate root material and verifier binaries,
review upstream security advisories, and change pins/identities by explicit review.
Update bundles/roots and affected locks together; run valid, wrong-identity,
tampered-byte and incomplete-proof tests before promoting a new verifier/root.
Retain previous pins and evidence for investigation. Offline verification cannot
discover subsequent revocation or compromise; establish an organization-specific
trust review cadence. A root supplied by the artifact publisher is not an independent
trust anchor. No newly observed signer is automatically accepted.

`CURLGUARD_TEST_COSIGN=/absolute/path/to/cosign python -m pytest tests/test_workflows.py`
runs the real offline positive/negative cases using pinned inert fixtures. CI
provides this binary; developer runs without it explicitly skip those cases.

## Independent transfer limits

`CURLGUARD_MAX_STAGED_BYTES` defaults to 1 GiB and
`CURLGUARD_TRANSFER_TIMEOUT_SECONDS` to 300 seconds. Both require positive integers
and are independent of `CURLGUARD_MAX_SCAN_BYTES`/`CURLGUARD_SCAN_TIMEOUT_SECONDS`.
These limits apply to supported staged transfers, never unscanned pass-through.

A Linux worker sets `RLIMIT_FSIZE` before replacing itself with curl: staged file
size has **zero-byte overshoot**, including decompression, resumed prefixes and
retry output. It also caps each curl-written header/ETag file, so very large
headers can fail even with a small body. It bounds simultaneous file sizes, not
cumulative network bytes written across retries or filesystem block allocation.
Retained prefixes and HTTP 304 copies use bounded copying. A supervisor checks
the elapsed deadline at most every 50 ms, kills the transfer group and reaps it;
budget exhaustion exits 18. Time tests allow 1.5 seconds beyond the one-second
transfer limit for CLI initialization, scheduling and reaping; this is a measured
test allowance, not a hard real-time guarantee under a stalled kernel or filesystem.
Byte/time failures and disk exhaustion preserve existing payload/ETag outputs.
Disk errors use native curl/delivery failure codes when no budget was exhausted.
The suite verifies real disk exhaustion on a tiny private tmpfs where user/mount
namespaces are supported; otherwise that case explicitly skips while injected
disk-error checks still run.

## Fetch-only bootstrap manifests and examples

```bash
curlguard bootstrap manifest.json --output-dir new-downloads --json
python examples/fetch-only.py
python examples/enforcement-boundaries.py
```

A [bootstrap manifest](schemas/bootstrap-manifest.schema.json) has schema version 1,
kind `bootstrap_manifest`, and a nonempty `artifacts` array. Each entry has a unique
filename `id`, role `bootstrap` or `secondary`, and an embedded artifact `lock`
with the schema above. At least one bootstrap is required. All declarations are
validated before fetching; output directories must be new. Artifacts are verified
independently and published mode 0600 without overwriting. Stop on the first
failure; already verified artifacts remain available. This is not a multi-file
transaction. A [bootstrap report](schemas/bootstrap-report.schema.json) lists the
attempted artifacts and explicitly marks undeclared secondary downloads outside
coverage. Approving a bootstrap script never approves its future downloads.

`examples/fetch-only.py` runs a local loopback server with fixed inert payloads,
declares and pins bootstrap/secondary files, verifies both and replays a lock with
a separate JSON report. No external network or fixture execution is required.
It runs in a prebuilt Linux CI/container environment with curl and curlguard
installed. For container isolation, run the example in that image with
`docker run --rm --network none IMAGE python /work/examples/fetch-only.py` (copy
this repository to `/work` when building the image). Image construction and
dependency provisioning are separate from artifact verification.
The example was also verified in a fresh WSL user/mount/network namespace with
only its loopback link enabled; it requires no access outside that namespace.

The [administrator design](organizational-enforcement.md) explains enforced network
boundaries, administrator-owned policy and independently acknowledged audit.
