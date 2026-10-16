# Security redesign and reliable distribution

## Objective and branch strategy

Implement the six architecture/policy improvements and fix missing packaged rules
and editable production installation. Broader use cases are tracked separately in
[underserved-use-cases.md](underserved-use-cases.md).

Both branches originate at `8e8786214087f3d8374308b61d485b160f74c8e9`:

| Branch | Defaults |
|---|---|
| `codex/general-users` | Warn on unscanned pass-through, scan failure and insecure transport; quarantine unsuppressed findings |
| `codex/security-users` | Block unsupported downloads and unsuccessful scans; require verified HTTPS, TLS 1.2+, HTTPS redirects, current configured feeds, and artifact SHA-256 pins |

Share all transfer/scanner/policy code. Maintain branch defaults in `edition.py`.
Merge common fixes from general into security; keep security-only wiring separate.
Do not delete, replace or publish existing refs as part of this work.

## Implementation stages

1. Include YARA package resources in wheel and sdist. Add installed-artifact tests
   outside the checkout, and read-only scanner/runtime health diagnostics.
2. Introduce typed request, evidence, finding and decision records. Separate
   preparation, transfer, evidence, evaluation and publication. Preserve legacy
   audit fields, adding versioned independent evidence and resolved settings.
3. Replace host/global-checksum bypasses with exact artifact records and expiring,
   hash-bound rule exceptions. Implement required hashes, conflict rejection,
   conditional-file revalidation and `fetch`. Supplied hashes never become optional.
4. Preserve rule metadata and bounded match evidence for review. Disable markup
   and escape terminal controls. Enforce independent transport settings before
   forbidden activity; distinguish requested TLS limits from observed negotiation.
5. Replace raw remote rules with locally trusted Ed25519-signed, versioned bundles.
   Reject rollback, stale/invalid bundles and changed feed bindings. Compile in
   a subprocess with 30s wall, 20s CPU and 512 MiB address-space limits. Activate
   complete generations through one atomic reference. Updates are explicit.
6. Install wheels and dependencies into owned, versioned virtual environments.
   Build unprivileged; stage system inputs privately under root ownership.
   Validate the candidate before publishing both managed wrappers; restore prior
   wrappers on a catchable publication failure. Update migration docs and CI.

## Public contracts

- `fetch URL [-o PATH] [--sha256 HEX]`, `doctor [--json]`,
  `rules status [--json]`, `rules update`.
- Hash checks return 17 for missing required hashes/mismatches. Existing transport,
  scanner/rules, unsupported, configuration and delivery codes remain 12–16.
- Security hash requirements can be explicitly relaxed with
  `CURLGUARD_REQUIRE_SHA256=false`; scan/transport rules still apply.
- `policy.json` schema 1 holds artifact pins and scoped exceptions. Matching is
  exact after scheme/host/default-port normalization; queries and paths retain
  their semantics. Defaults never grant implicit subdomain or wildcard trust.
- Findings are distinct from integrity and authenticity. No rule matches means
  no matches, not proof of safety. Artifact authenticity stays `unverified`.
- Both editions are voluntary PATH wrappers; absolute curl and other download
  clients remain outside their interception boundary.

## Acceptance checklist

- [x] Existing payload parity, resume, cancellation, ETag rollback and preservation
  tests pass without executing sample payloads.
- [x] Missing, conflicting, mismatching, resumed and conditional hashes behave
  before output/ETag publication; missing required pins make no network request.
- [x] Wrong/expired exceptions and additional findings do not bypass policy;
  nonempty legacy trust produces migration errors.
- [x] Shipped defaults, explicit relaxations and branch audit identity are tested.
- [x] Strict transport prevents HTTP/downgrade requests and rejects certificate
  bypass or incompatible TLS maximums.
- [x] Tampering, replay, invalid metadata/signatures, oversized bundles, expiry,
  locking and worker failure preserve the last accepted generation.
- [x] Real compiler timeout reaps its worker; worker resource limits are checked.
- [x] Wheel, sdist-built wheel and installed scanner work outside the source tree;
  removing packaged rules is detected as unavailable scanning.
- [x] Isolated candidate-install, failed-upgrade, wrapper rollback and uninstall
  tests preserve unrelated executables and the current distro curl.
- [x] Both branches pass `ruff check`, `ruff format --check` and complete Linux/WSL
  pytest runs; supported CI runtime jobs include distribution tests.

Acceptance results are recorded in [redesign-validation.md](../redesign-validation.md).
No live install, package repair, fixture execution or automatic scheduler setup
is part of verification.
