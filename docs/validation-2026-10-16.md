# Update reliability validation — October 16, 2026

Implemented against restored source from commit `37235d2`. The change is organized into command compatibility, staged download delivery, scanner/rule-update resilience, and package-safe installation. No real system upgrade or system-wide wrapper installation was performed during validation.

## Deterministic tests

| Runtime in WSL Ubuntu 24.04.5 | Result |
|---|---|
| Python 3.10.22, source-built curl 7.81.0, YARA 4.5.4 | **147 passed**, 35.88 seconds |
| Python 3.12.3, distro curl 8.5.0, YARA 4.5.0 | **147 passed**, 35.85 seconds |

Both runs used the complete test suite, local HTTP/HTTPS servers, and real YARA. The old curl binary was built in `/tmp` and selected through `CURLGUARD_TEST_CURL`; the system executable was left untouched. Linux CI additionally defines the corresponding native Ubuntu 22.04 and 24.04 jobs. Those hosted CI jobs have not been run from this local session.

Confirmed regressions now tested: option-first commands, installer false positives, lost write-out output, explicit-offset resume corruption, conditional-response truncation, system wrapper replacement during package unpack, and stale-binary restoration during uninstall.

Additional scenarios cover argument ambiguity, configuration files, TLS errors, compression, redirects, retries, truncation, malformed Content-Range, missing ETags, timeouts, signals, broken pipes, scan failures/limits, destination changes, disk/permission failures, quarantine failures, log rotation and redaction, failed/concurrent rule updates, and successful/interrupted legacy migration with mocked package repair.

curl 7.81 and 8.5 differ when a resumed file is already complete: the old version can return error 22 for HTTP 416 while the newer version accepts it. Tests require curlguard to preserve the selected curl's result. A separate successful-resume test verifies that malicious retained prefixes are scanned.

## Live APT and package-layout validation

Executed `scripts/validate-wsl-updates.py` under WSL with private APT list, cache, log, and download directories for each comparison:

- Both fresh metadata refreshes succeeded.
- Both upgrade simulations succeeded and produced identical plans.
- Downloaded `hello` and `curl` packages matched by filename and SHA-256.
- A real curl package unpack into an isolated file tree preserved `/usr/local/bin/curl` and replaced only the package-owned `/usr/bin/curl`.
- Removing the isolated wrapper preserved the newly unpacked packaged binary.
- APT produced no curlguard audit events, consistent with these APT paths not invoking command-line curl.

Full APT stdout, commands, and checks were retained outside the repository at the session artifact directory `curlguard-update-test-fixed`. Legacy APT repair is covered through isolated mocks; actual root migration and arbitrary third-party maintainer scripts were not executed.

## Other checks and limits

`ruff check`, `ruff format --check`, both installer shell syntax checks, and `git diff --check` passed.

Unsupported requests pass through and are audited by default; scan failures warn and deliver by default. Strict modes are configurable. PATH wrappers do not intercept absolute `/usr/bin/curl` calls. Payload replacement is atomic, but payload and ETag replacement cannot form a single crash-proof transaction across files. YARA includes are disabled. See [the behavior and migration documentation](update-reliability.md) for these supported boundaries.
