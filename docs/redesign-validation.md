# Security redesign validation — October 16, 2026

## Automated checks

Both maintained editions were verified in WSL Ubuntu with Python 3.12.3,
real curl 8.5.0 and real YARA 4.5.0:

| Branch | Complete test suite | Lint | Formatting | Installer shell syntax |
|---|---|---|---|---|
| `codex/general-users` | 199 passed | Passed | Passed | Passed |
| `codex/security-users` | 199 passed | Passed | Passed | Passed |

Focused tests preceded the complete checks. Added coverage includes pins and
conflicts before payload/ETag publication, complete resumed hashes, conditional
retained-file revalidation, scoped/expired exceptions, unsupported bypass
prevention, explicit-fetch boundaries, strict redirect protocols, observed downgrade
warnings in compatibility mode, shipped defaults,
relaxations, signed-feed replay/tampering/expiry/limits/locking, isolated compilation
limits and worker reaping. The existing differential curl and filesystem failure
coverage remains active.

Distribution tests build wheel and sdist from an isolated source copy; the wheel
is built from the sdist. They inspect bundled YARA inclusion and import an installed
wheel outside the checkout without source injection. Positive/negative inert scans
work; removing the packaged rules produces unavailable scanning. Candidate-install
failure tests preserve the previous environment, restore the caller's umask and
verify offline wheel installation arguments. Wrapper-pair rollback is tested in
an isolated system-layout tree.

## Installed-runtime smoke checks

Actual offline wheel installations used temporary HOME, runtime-prefix and distro
curl layouts. No live wrapper installation or package repair was performed.

- General-user per-user install and upgrade both succeeded. Health returned 0,
  the earlier versioned environment remained, and uninstall removed both managed
  wrappers without modifying the isolated distro curl.
- An untrusted working directory containing a shadow `curlguard` package and a
  poisoned `PYTHONPATH` did not affect the installed isolated wrapper or doctor.
- A root-owned system-layout installation under `/tmp` succeeded with doctor 0;
  the isolated packaged curl remained byte-identical. A separate `umask 077`
  installation confirmed root-owned, publicly readable/non-writable runtime
  contents and a 0755 runtime prefix.
- The installed security-user runtime reported the strict defaults and doctor 0.
  A missing hash returned 17 with zero server requests. A correct pin fetched the
  exact inert payload over locally verified HTTPS. Explicitly disabling required
  hashes allowed an unpinned download while recording that relaxation and the
  security edition in audit.

WSL artifact directories retained for inspection:

- `/tmp/curlguard-redesign-validation` — built wheelhouses and build logs.
- `/tmp/curlguard-final-runtime-gmof2slv` — general install/upgrade/uninstall checks.
- `/tmp/curlguard-root-isolated-rm40dp6o` — isolated root-owned system-layout check.
- `/tmp/curlguard-root-umask-j2lr278l` — restrictive-umask system-layout check.
- `/tmp/curlguard-security-smoke-39h6uad2` — security-runtime install and HTTPS checks.

## Boundaries and repository state

Sample payloads and pinned installer fixtures were scanned as data only. No
installer sample was executed, no system package was repaired, and no branch was
deleted, force-pushed or published. Existing branches retain their previous tips.
The original `codex/safe-curl-lightweight` remains at
`8e8786214087f3d8374308b61d485b160f74c8e9`.

CI retains the Python 3.10/curl 7.81 and Python 3.12/curl 8.5 runtime jobs, adds a
shipped-edition check, and includes installed-distribution tests and installer
helper linting. Hosted CI has not been run from this local implementation session;
this report describes local WSL results.

Artifact authenticity remains unverified. Large-transfer budgets, publisher
signatures, secondary-download coverage and organizational enforcement remain
explicit follow-on work in [the separate plan](plans/underserved-use-cases.md).
